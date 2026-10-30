"""Encrypted personal State API on an existing transactional AuthorizationStore.

No SQL, local database, credentials fallback, automatic retry or runtime wiring.
Approval methods (including set_draft_consent) are TRUSTED UI/host APIs, never
LLM tools. The supplied store must provide durable, serializable transactions
across instances, including absent keys. Fernet alone cannot prevent a trusted
storage administrator from restoring an old backup; do not roll back this ledger
without reconciliation with the external financial service.

Public State methods are supported, not its SQLite-specific db/_lock internals.
close() closes this facade only, never the shared store. Records are bounded to
1 MiB of plaintext; history/claims are never silently pruned to make space.
"""

import contextlib
import hashlib
import json
import math
import re
import time
import uuid

from cryptography.fernet import Fernet

from .state import ExpenseError, OutcomeUnknownError, digest, _memory_values, _memory_entry, _check_memory


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                      separators=(",", ":"))


def _copy(value):
    return json.loads(_json(value))


class DurableState:
    MAX_PLAINTEXT_BYTES = 1024 * 1024
    _COLLECTIONS = ("previews", "facts", "settings", "receipt_claims",
                    "external_approval_events", "source_receipts")

    def __init__(self, store, encryption_key, owner, namespace, clock=time.time):
        if (not isinstance(owner, str) or not owner.strip() or len(owner) > 512
                or not isinstance(namespace, str) or not namespace.strip() or len(namespace) > 512
                or not callable(getattr(store, "transaction", None)) or not callable(clock)):
            raise ValueError("Explicit personal owner, namespace, store and clock required")
        try:
            self._cipher = Fernet(encryption_key)
        except Exception:
            raise ValueError("Explicit durable state encryption key required") from None
        self.owner, self.clock = owner, clock
        self._store, self._closed = store, False
        self._binding = ["expense-durable-state/v1", namespace, owner]
        self._key = "expense-durable-state-v1:" + hashlib.sha256(_json(self._binding).encode()).hexdigest()

    @contextlib.contextmanager
    def _record(self):
        if self._closed:
            raise ExpenseError("状態の接続は閉じられています。")
        try:
            with self._store.transaction() as records:
                row = records.get(self._key)
                if row is None:
                    data = {name: {} for name in self._COLLECTIONS}
                else:
                    if (not isinstance(row, dict) or set(row) != {"ciphertext"}
                            or not isinstance(row["ciphertext"], str)
                            or len(row["ciphertext"]) > 2 * self.MAX_PLAINTEXT_BYTES):
                        raise ValueError
                    raw = self._cipher.decrypt(row["ciphertext"].encode("ascii"))
                    if len(raw) > self.MAX_PLAINTEXT_BYTES:
                        raise ValueError
                    payload = json.loads(raw)
                    if (set(payload) != {"binding", "data"} or payload["binding"] != self._binding
                            or not isinstance(payload["data"], dict)
                            or set(payload["data"]) != set(self._COLLECTIONS)
                            or any(not isinstance(v, dict) for v in payload["data"].values())):
                        raise ValueError
                    data = payload["data"]
                before = _json(data)
                yield data
                if _json(data) != before:
                    raw = _json({"binding": self._binding, "data": data}).encode()
                    if len(raw) > self.MAX_PLAINTEXT_BYTES:
                        raise ExpenseError("永続状態の容量上限に達しました。履歴を削除せず管理者へ確認してください。")
                    records.put(self._key, {"ciphertext": self._cipher.encrypt(raw).decode("ascii")})
        except ExpenseError:
            raise
        except Exception:
            raise ExpenseError("本人の永続状態を安全に読み書きできません。") from None

    def _details(self, data, identifier):
        row = data["previews"].get(identifier)
        if row is None:
            raise ExpenseError("本人の確認対象が見つかりません。")
        if digest({"owner": self.owner, "action": row["action"], "office": row["office"],
                   "snapshot": row["snapshot"]}) != row["hash"]:
            raise ExpenseError("本人の確認内容の整合性を確認できません。")
        return row

    def preview(self, action, office, snapshot, *, lifetime=600):
        if (type(lifetime) not in (int, float) or not math.isfinite(lifetime)
                or not 0 < lifetime <= 3600 or not isinstance(snapshot, dict)):
            raise ExpenseError("プレビューの内容・有効期限が不正です。")
        identifier = uuid.uuid4().hex
        hashed = digest({"owner": self.owner, "action": action, "office": office, "snapshot": snapshot})
        expires = self.clock() + lifetime
        with self._record() as data:
            data["previews"][identifier] = {
                "action": action, "office": office, "snapshot": _copy(snapshot), "hash": hashed,
                "expires": expires, "status": "preview", "approved": False, "result": None,
            }
        return {"preview_id": identifier, "preview_digest": hashed, "expires_at": expires, "approved": False}

    def _approve(self, data, identifier, expected_digest):
        row = self._details(data, identifier)
        if row["hash"] != expected_digest or row["expires"] <= self.clock() or row["status"] != "preview":
            raise ExpenseError("プレビューの内容・期限・状態を再確認してください。")
        row["approved"] = True

    def approve(self, identifier, expected_digest):
        """Trusted authenticated human UI only; NEVER expose as an LLM tool."""
        with self._record() as data:
            self._approve(data, identifier, expected_digest)

    def preview_details(self, identifier):
        with self._record() as data:
            row = self._details(data, identifier)
            return _copy({"preview_id": identifier, "preview_digest": row["hash"],
                          "expires_at": row["expires"], **{k: row[k] for k in
                          ("action", "office", "snapshot", "status", "result")}})

    def approve_external(self, source, event_id, identifier, expected_digest, evidence):
        """Trusted verifier only; immutable source event plus approval atomically."""
        key = _json([source, event_id])
        expected = {"preview_id": identifier, "digest": expected_digest, "evidence": _copy(evidence)}
        with self._record() as data:
            existing = data["external_approval_events"].get(key)
            if existing is not None and _json(existing) != _json(expected):
                raise ExpenseError("本人承認イベントが別の対象・内容に使われています。")
            self._approve(data, identifier, expected_digest)
            data["external_approval_events"][key] = expected

    def bind_source_receipt(self, source, scope_digest, reference, metadata):
        key, value = _json([source, scope_digest, reference]), _copy(metadata)
        with self._record() as data:
            if key in data["source_receipts"] and _json(data["source_receipts"][key]) != _json(value):
                raise ExpenseError("領収書の取得元の対応が変わっています。")
            data["source_receipts"][key] = value

    def source_receipt(self, source, scope_digest, reference):
        with self._record() as data:
            return _copy(data["source_receipts"].get(_json([source, scope_digest, reference])))

    def withdraw_unused_approval(self, identifier):
        with self._record() as data:
            row = data["previews"].get(identifier)
            if row and row["status"] == "preview":
                row["approved"] = False

    def set_draft_consent(self, office_ids, consent_id, *, active=True):
        """Trusted first-consent UI only; no identity or approval inferred here."""
        if (type(active) is not bool or not isinstance(consent_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", consent_id)
                or not isinstance(office_ids, list) or len(office_ids) > 50
                or (active and not office_ids)
                or any(not isinstance(x, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", x)
                       for x in office_ids) or len(office_ids) != len(set(office_ids))):
            raise ExpenseError("本人の初回許可と会社範囲を確認してください。")
        with self._record() as data:
            data["settings"]["draft_creation_consent"] = {
                "owner": self.owner, "consent_id": consent_id, "office_ids": sorted(office_ids),
                "active": active, "actions": ["create", "upload"],
            }

    def draft_consent(self, office):
        with self._record() as data:
            row = data["settings"].get("draft_creation_consent", {})
            if (row.get("owner") != self.owner or row.get("active") is not True
                    or office not in row.get("office_ids", []) or row.get("actions") != ["create", "upload"]):
                raise ExpenseError("この会社の未申請明細作成を初回の連携画面で許可してください。")
            return _copy(row)

    def execute(self, identifier, action, office, snapshot, write):
        hashed = digest({"owner": self.owner, "action": action, "office": office, "snapshot": snapshot})
        if not callable(write):
            raise ExpenseError("書き込み処理を確認してください。")
        with self._record() as data:
            row = self._details(data, identifier)
            if row["hash"] != hashed:
                raise ExpenseError("承認した本人・会社・対象・内容と一致しません。")
            if row["status"] == "done":
                return _copy(row["result"])
            if row["status"] != "preview":
                raise OutcomeUnknownError("前回の書き込み結果を照合してください。自動再送はしません。")
            if row["expires"] <= self.clock() or row["approved"] is not True:
                raise ExpenseError("本人の有効な承認がありません。")
            fingerprint = row["snapshot"].get("receipt_fingerprint")
            expense_claim = fingerprint is None
            if expense_claim:
                fingerprint = row["snapshot"].get("expense_fingerprint")
            if fingerprint is not None:
                if action not in {"create", "upload"} or not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
                    raise ExpenseError("領収書の照合情報を確認してください。")
                if expense_claim:
                    fingerprint = "expense:" + fingerprint
                prior = data["receipt_claims"].get(fingerprint)
                if prior is not None:
                    if data["previews"].get(prior, {}).get("status") == "done":
                        raise ExpenseError("同じ領収書または経費候補は処理済みです。新しいプレビューでも二重登録しません。")
                    raise OutcomeUnknownError("同じ領収書または経費候補の処理中または結果不明です。自動再送しません。")
                data["receipt_claims"][fingerprint] = identifier
            row["status"] = "executing"
        # The transaction (including commit) MUST finish before external I/O.
        # No store transaction/lock survives across this callback.
        write_returned = False
        try:
            result = write()
            write_returned = True
            result = _copy(result)
            with self._record() as data:
                row = self._details(data, identifier)
                if row["status"] != "executing" or row["hash"] != hashed:
                    raise OutcomeUnknownError("実行結果の保存状態を照合してください。")
                row.update(status="done", result=result)
            return result
        except BaseException:
            try:
                with self._record() as data:
                    row = self._details(data, identifier)
                    # A commit can succeed before its acknowledgement is lost.
                    # Do not overwrite a durably recorded success with unknown.
                    if row["status"] == "executing":
                        row["status"] = "unknown"
            except BaseException:
                # Even when recovery persistence fails, executing remains a
                # durable fence; NEVER put the preview back into preview status.
                raise OutcomeUnknownError("書き込み結果の保存を確認できません。照合するまで自動再送しません。") from None
            if write_returned:
                raise OutcomeUnknownError("書き込み後の結果保存を確認できません。照合するまで自動再送しません。") from None
            raise

    def completed(self, identifier, action, office, intent):
        with self._record() as data:
            row = data["previews"].get(identifier)
            if row and row["status"] in {"done", "executing", "unknown"}:
                row = self._details(data, identifier)
                if row["action"] != action or row["office"] != office or row["snapshot"].get("intent") != intent:
                    raise ExpenseError("完了した操作の本人・会社・内容と一致しません。")
                if row["status"] != "done":
                    raise OutcomeUnknownError("前回の書き込み結果を照合してください。自動再送はしません。")
                return _copy(row["result"])
        return None

    def propose_fact(self, kind, content, due_date=""):
        values = _memory_values(kind, content, due_date)
        identifier = uuid.uuid4().hex
        row = {"id": identifier, "kind": kind, "content": content, "status": "proposed",
               "created": self.clock(), "due_date": values["due_date"]}
        with self._record() as data:
            data["facts"][identifier] = row
        return {k: row[k] for k in ("id", "kind", "content", "status")}

    def accept_fact(self, identifier):
        """Trusted human confirmation only."""
        with self._record() as data:
            row = data["facts"].get(identifier)
            if not row or row["status"] != "proposed":
                raise ExpenseError("記憶の確認対象が見つかりません。")
            row["status"] = "active"

    def facts(self):
        with self._record() as data:
            return [{k: row[k] for k in ("id", "kind", "content", "status", "due_date")}
                    for row in sorted((r for r in data["facts"].values() if r["status"] != "deleted"),
                                      key=lambda r: (r["created"], r["id"]))]

    def memory_entries(self):
        """Trusted GUI host only; deleted entries are not listed."""
        return [_memory_entry(row, self._binding) for row in self.facts()]

    def _change_memory(self, identifier, expected_digest, action, values=None):
        # The supplied store transaction must be serializable across instances.
        # No digest check happens before the transaction or after mutation.
        with self._record() as data:
            row = data["facts"].get(identifier)
            allowed = {"proposed"} if action == "confirm" else {"active"} if action == "update" else {
                "proposed", "active", "retired", "done"}
            _check_memory(row, expected_digest, self._binding, allowed)
            if action == "delete":
                result = {"id": identifier, "status": "deleted"}
                data["facts"][identifier] = dict(result)
            else:
                if action == "confirm":
                    row["status"] = "active"
                else:
                    row.update(values)
                result = _memory_entry(row, self._binding)
        return result

    def confirm_memory(self, identifier, expected_digest):
        """Trusted GUI only. CAS-confirm a proposed item; never an LLM tool."""
        return self._change_memory(identifier, expected_digest, "confirm")

    def update_memory(self, identifier, expected_digest, kind, content, due_date=""):
        """Trusted GUI only. Edit an active item in place using its exact digest."""
        return self._change_memory(identifier, expected_digest, "update", _memory_values(kind, content, due_date))

    def delete_memory(self, identifier, expected_digest):
        """Trusted GUI only. CAS-remove content; a deleted ID cannot be revived."""
        return self._change_memory(identifier, expected_digest, "delete")

    def active_facts(self):
        """Conversation input: approved active facts only, never GUI digests."""
        return [row for row in self.facts() if row["status"] == "active"]

    def due_pending(self, today):
        return [row for row in self.active_facts() if row["kind"] == "pending" and row["status"] == "active"
                and row["due_date"] and row["due_date"] <= today.isoformat()]

    def retire_fact(self, identifier):
        with self._record() as data:
            if identifier in data["facts"] and data["facts"][identifier]["status"] != "deleted":
                data["facts"][identifier]["status"] = "retired"

    def complete_pending(self, identifier):
        with self._record() as data:
            row = data["facts"].get(identifier)
            if row and row["status"] == "active" and row["kind"] == "pending":
                row["status"] = "done"

    def suggestion_due(self, *, heartbeat=False, urgent=False, failed=False):
        if heartbeat or urgent or failed:
            return False
        with self._record() as data:
            last = data["settings"].get("last_suggestion")
            return last is None or self.clock() - float(last) >= 7 * 86400

    def mark_suggestion(self):
        with self._record() as data:
            data["settings"]["last_suggestion"] = self.clock()

    def close(self):
        self._closed = True
