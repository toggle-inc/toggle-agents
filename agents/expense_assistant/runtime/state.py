"""Private state and approval ledger. Approvals are issued by a trusted UI, not tools."""

import datetime as dt
import functools
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path


class ExpenseError(RuntimeError):
    """A safe, user-visible refusal with no secret-bearing response bodies."""


class OutcomeUnknownError(ExpenseError):
    """A write may have happened; readback is required before any retry."""


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _memory_values(kind, content, due_date=""):
    """Shared proposal/GUI validation; never relax the existing privacy filter."""
    if (not isinstance(kind, str)
            or kind not in {"commuter_pass", "base_location", "formatting", "pending", "preference"}
            or not isinstance(content, str) or not 1 <= len(content) <= 1000):
        raise ExpenseError("記憶の種類または長さが不正です。")
    if due_date is not None and not isinstance(due_date, str):
        raise ExpenseError("確認予定日の形式が不正です。")
    if kind == "pending":
        try:
            due_date = dt.date.fromisoformat(due_date).isoformat()
        except (TypeError, ValueError):
            raise ExpenseError("保留には確認予定日が必要です。") from None
    elif due_date:
        raise ExpenseError("確認予定日は保留にだけ指定できます。")
    if re.search(r"(?i)token|password|secret|認可コード|パスワード|口座|秘密|sk-[\w-]+|"
                 r"https?://|[\w.+-]+@[\w.-]+|\b\d{10,}\b", content):
        raise ExpenseError("秘密・口座・個人情報を記憶できません。一般的な決まりに言い換えてください。")
    return {"kind": kind, "content": content, "due_date": due_date or None}


def _memory_entry(row, scope):
    """Host-only, detached GUI view. Digest is opaque and includes private scope."""
    entry = {key: row[key] for key in ("id", "kind", "content", "status", "due_date")}
    return {**entry, "digest": digest({"scope": scope, "entry": entry})}


def _remember_identifier(values, scope):
    # Content-derived personal ID is a durable replay fence. GUI edits keep
    # this ID; deletion retains only the ID and cannot be undone by retry.
    return digest({"domain": "expense-remember/v1", "scope": scope, "values": values})[:32]


def _remember_result(row, values):
    if (row["status"] != "active"
            or any(row.get(key) != value for key, value in values.items())):
        raise ExpenseError("この記憶は変更・無効化・削除されています。再保存せず記憶管理画面で確認してください。")
    return {key: row[key] for key in ("id", "kind", "content", "status", "due_date")}


def _memory_claim_key(values, scope):
    # No plaintext is retained in replay metadata, including after GUI deletion.
    return "memory_content_claim:" + _remember_identifier(values, scope)


def _check_memory(row, expected_digest, scope, allowed_statuses):
    if (not row or row["status"] not in allowed_statuses
            or not isinstance(expected_digest, str)
            or _memory_entry(row, scope)["digest"] != expected_digest):
        raise ExpenseError("記憶の内容・状態が変わりました。最新の一覧を確認してください。")


def synchronized(function):
    @functools.wraps(function)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            return function(self, *args, **kwargs)

    return wrapped


class State:
    def __init__(self, path, owner, *, clock=time.time):
        if not isinstance(owner, str) or not owner.strip():
            raise ExpenseError("認証済みの本人が設定されていません。")
        self.owner, self.clock = owner, clock
        self._lock = threading.RLock()
        path = Path(path)
        if path.is_symlink():
            raise ExpenseError("状態ファイルにシンボリックリンクは使えません。")
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        os.chmod(path, 0o600)
        self.db = sqlite3.connect(path, isolation_level=None, timeout=15, check_same_thread=False)
        self._memory_scope = ["expense-sqlite-memory/v1", str(path.resolve()), owner]
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA secure_delete=ON")
        self.db.execute("CREATE TABLE IF NOT EXISTS binding (owner TEXT NOT NULL)")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            bound = self.db.execute("SELECT owner FROM binding").fetchone()
            if bound and bound[0] != owner:
                raise ExpenseError("別の本人の状態ファイルは利用できません。")
            if not bound:
                self.db.execute("INSERT INTO binding VALUES (?)", (owner,))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            self.db.close()
            raise
        self.db.execute("""CREATE TABLE IF NOT EXISTS previews (
            id TEXT PRIMARY KEY, action TEXT NOT NULL, office TEXT NOT NULL,
            snapshot TEXT NOT NULL, hash TEXT NOT NULL, expires REAL NOT NULL,
            status TEXT NOT NULL, approved INTEGER NOT NULL DEFAULT 0, result TEXT)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS facts (
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, content TEXT NOT NULL,
            status TEXT NOT NULL, created REAL NOT NULL, due_date TEXT)""")
        if "due_date" not in {row[1] for row in self.db.execute("PRAGMA table_info(facts)")}:
            self.db.execute("ALTER TABLE facts ADD COLUMN due_date TEXT")
        self.db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        # One receipt must not create multiple expenses through new previews,
        # another company or switching between direct create and MF OCR upload.
        # This DB is already bound to one verified human. Never auto-release an
        # uncertain or completed claim, even after restart or preview expiry.
        self.db.execute("""CREATE TABLE IF NOT EXISTS receipt_claims (
            fingerprint TEXT PRIMARY KEY, preview_id TEXT NOT NULL UNIQUE)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS external_approval_events (
            source TEXT NOT NULL, event_id TEXT NOT NULL, preview_id TEXT NOT NULL,
            digest TEXT NOT NULL, evidence TEXT NOT NULL, PRIMARY KEY(source,event_id))""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS source_receipts (
            source TEXT NOT NULL, scope_digest TEXT NOT NULL, reference TEXT NOT NULL,
            metadata TEXT NOT NULL, PRIMARY KEY(source,scope_digest,reference))""")

    @synchronized
    def preview(self, action, office, snapshot, *, lifetime=600):
        if not 0 < lifetime <= 3600:
            raise ExpenseError("プレビューの有効期限が不正です。")
        identifier = uuid.uuid4().hex
        hashed = digest(
            {"owner": self.owner, "action": action, "office": office, "snapshot": snapshot}
        )
        self.db.execute(
            "INSERT INTO previews VALUES (?,?,?,?,?,?,?,0,NULL)",
            (
                identifier,
                action,
                office,
                json.dumps(snapshot, ensure_ascii=False),
                hashed,
                self.clock() + lifetime,
                "preview",
            ),
        )
        return {
            "preview_id": identifier,
            "preview_digest": hashed,
            "expires_at": self.clock() + lifetime,
            "approved": False,
        }

    @synchronized
    def approve(self, identifier, expected_digest):
        """Trusted adapter/admin only. NEVER register this method as an LLM tool.

        The adapter must authenticate the human and show the exact snapshot first.
        This API cannot establish human identity on behalf of an untrusted caller.
        """
        changed = self.db.execute(
            "UPDATE previews SET approved=1 WHERE id=? AND hash=? "
            "AND expires>? AND status='preview'",
            (identifier, expected_digest, self.clock()),
        ).rowcount
        if not changed:
            raise ExpenseError("プレビューの内容・期限・状態を再確認してください。")

    @synchronized
    def preview_details(self, identifier):
        """Trusted host only: exact private snapshot, never an LLM tool/resource."""
        row = self.db.execute(
            "SELECT action,office,snapshot,hash,expires,status,result FROM previews WHERE id=?",
            (identifier,),
        ).fetchone()
        if not row:
            raise ExpenseError("本人の確認対象が見つかりません。")
        action, office, raw, hashed, expires, status, result = row
        snapshot = json.loads(raw)
        if (
            digest({"owner": self.owner, "action": action, "office": office, "snapshot": snapshot})
            != hashed
        ):
            raise ExpenseError("本人の確認内容の整合性を確認できません。")
        return {
            "preview_id": identifier,
            "preview_digest": hashed,
            "expires_at": expires,
            "action": action,
            "office": office,
            "snapshot": snapshot,
            "status": status,
            "result": json.loads(result) if result else None,
        }

    @synchronized
    def approve_external(self, source, event_id, identifier, expected_digest, evidence):
        """Trusted verifier only; persist immutable source-event evidence with approval."""
        encoded = json.dumps(evidence, ensure_ascii=False, sort_keys=True, allow_nan=False)
        expected = (identifier, expected_digest, encoded)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            existing = self.db.execute(
                "SELECT preview_id,digest,evidence FROM external_approval_events "
                "WHERE source=? AND event_id=?",
                (source, event_id),
            ).fetchone()
            if existing is not None and existing != expected:
                raise ExpenseError("本人承認イベントが別の対象・内容に使われています。")
            if existing is None:
                self.db.execute(
                    "INSERT INTO external_approval_events VALUES (?,?,?,?,?)",
                    (source, event_id, *expected),
                )
            self.approve(identifier, expected_digest)
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    @synchronized
    def bind_source_receipt(self, source, scope_digest, reference, metadata):
        """Trusted attachment importer only; immutable origin/receipt evidence."""
        encoded = json.dumps(metadata, ensure_ascii=False, sort_keys=True, allow_nan=False)
        self.db.execute(
            "INSERT OR IGNORE INTO source_receipts VALUES (?,?,?,?)",
            (source, scope_digest, reference, encoded),
        )
        row = self.db.execute(
            "SELECT metadata FROM source_receipts "
            "WHERE source=? AND scope_digest=? AND reference=?",
            (source, scope_digest, reference),
        ).fetchone()
        if row is None or row[0] != encoded:
            raise ExpenseError("領収書の取得元の対応が変わっています。")

    @synchronized
    def source_receipt(self, source, scope_digest, reference):
        """Trusted host only. A different run/origin cannot reuse this evidence."""
        row = self.db.execute(
            "SELECT metadata FROM source_receipts "
            "WHERE source=? AND scope_digest=? AND reference=?",
            (source, scope_digest, reference),
        ).fetchone()
        return json.loads(row[0]) if row else None

    @synchronized
    def withdraw_unused_approval(self, identifier):
        """Host cleanup after refused execution; never release receipt/execution claims."""
        self.db.execute(
            "UPDATE previews SET approved=0 WHERE id=? AND status='preview'", (identifier,)
        )

    @synchronized
    def set_draft_consent(self, office_ids, consent_id, *, active=True):
        """Trusted first-consent UI/host only. Never an LLM tool or admin-user fallback.

        The DB's fixed human owner consents to creating unsubmitted expenses and
        OCR uploads in these offices until explicitly revoked. Not update/delete
        or submission permission. No fixed expiry is imposed on this consent.
        """
        import re

        if (
            type(active) is not bool
            or not isinstance(consent_id, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", consent_id)
            or not isinstance(office_ids, list)
            or len(office_ids) > 50
            or (active and not office_ids)
            or any(
                not isinstance(x, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", x)
                for x in office_ids
            )
            or len(office_ids) != len(set(office_ids))
        ):
            raise ExpenseError("本人の初回許可と会社範囲を確認してください。")
        record = {
            "owner": self.owner,
            "consent_id": consent_id,
            "office_ids": sorted(office_ids),
            "active": active,
            "actions": ["create", "upload"],
        }
        self.db.execute(
            "INSERT INTO settings VALUES ('draft_creation_consent',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (json.dumps(record, sort_keys=True),),
        )

    @synchronized
    def draft_consent(self, office):
        row = self.db.execute(
            "SELECT value FROM settings WHERE key='draft_creation_consent'"
        ).fetchone()
        record = json.loads(row[0]) if row else {}
        if (
            record.get("owner") != self.owner
            or record.get("active") is not True
            or office not in record.get("office_ids", [])
            or record.get("actions") != ["create", "upload"]
        ):
            raise ExpenseError("この会社の未申請明細作成を初回の連携画面で許可してください。")
        return record

    @synchronized
    def execute(self, identifier, action, office, snapshot, write):
        hashed = digest(
            {"owner": self.owner, "action": action, "office": office, "snapshot": snapshot}
        )
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT hash,expires,status,approved,result FROM previews WHERE id=?", (identifier,)
            ).fetchone()
            if row is None or row[0] != hashed:
                raise ExpenseError("承認した本人・会社・対象・内容と一致しません。")
            if row[2] == "done":
                self.db.execute("COMMIT")
                return json.loads(row[4])
            if row[2] != "preview":
                raise OutcomeUnknownError(
                    "前回の書き込み結果を照合してください。自動再送はしません。"
                )
            if row[1] <= self.clock() or not row[3]:
                raise ExpenseError("本人の有効な承認がありません。")
            fingerprint = snapshot.get("receipt_fingerprint")
            expense_claim = fingerprint is None
            if expense_claim:
                fingerprint = snapshot.get("expense_fingerprint")
            if fingerprint is not None:
                if (
                    action not in {"create", "upload"}
                    or not isinstance(fingerprint, str)
                    or len(fingerprint) != 64
                    or any(c not in "0123456789abcdef" for c in fingerprint)
                ):
                    raise ExpenseError("領収書の照合情報を確認してください。")
                if expense_claim:
                    fingerprint = "expense:" + fingerprint
                prior = self.db.execute(
                    "SELECT p.status FROM receipt_claims c "
                    "LEFT JOIN previews p ON p.id=c.preview_id WHERE c.fingerprint=?",
                    (fingerprint,),
                ).fetchone()
                if prior:
                    if prior[0] == "done":
                        raise ExpenseError(
                            "同じ領収書または経費候補は処理済みです。既存の明細・OCR結果を確認してください。"
                            "新しいプレビューでも二重登録しません。"
                        )
                    raise OutcomeUnknownError(
                        "同じ領収書または経費候補の処理中または結果不明です。MF明細と照合してください。"
                        "新しいプレビューでも自動再送しません。"
                    )
                self.db.execute(
                    "INSERT INTO receipt_claims VALUES (?,?)", (fingerprint, identifier)
                )
            self.db.execute("UPDATE previews SET status='executing' WHERE id=?", (identifier,))
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

        try:
            result = write()
            encoded = json.dumps(result, ensure_ascii=False, allow_nan=False)
            self.db.execute(
                "UPDATE previews SET status='done',result=? WHERE id=?", (encoded, identifier)
            )
            return result
        except BaseException:
            # Even a process failure after the HTTP success must never cause an automatic retry.
            self.db.execute("UPDATE previews SET status='unknown' WHERE id=?", (identifier,))
            raise

    @synchronized
    def completed(self, identifier, action, office, intent):
        row = self.db.execute(
            "SELECT action,office,snapshot,status,result FROM previews WHERE id=?", (identifier,)
        ).fetchone()
        if row and row[3] in {"done", "executing", "unknown"}:
            if row[0] != action or row[1] != office or json.loads(row[2]).get("intent") != intent:
                raise ExpenseError("完了した操作の本人・会社・内容と一致しません。")
            if row[3] != "done":
                raise OutcomeUnknownError(
                    "前回の書き込み結果を照合してください。自動再送はしません。"
                )
            return json.loads(row[4])
        return None

    @synchronized
    def propose_fact(self, kind, content, due_date=""):
        values = _memory_values(kind, content, due_date)
        identifier = uuid.uuid4().hex
        self.db.execute(
            "INSERT INTO facts (id,kind,content,status,created,due_date) "
            "VALUES (?,?,?,'proposed',?,?)",
            (identifier, kind, content, self.clock(), values["due_date"]),
        )
        return {"id": identifier, "kind": kind, "content": content, "status": "proposed"}

    @synchronized
    def accept_fact(self, identifier):
        """Trusted human confirmation only, not an agent-callable operation."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            raw = self.db.execute("SELECT kind,content,due_date FROM facts WHERE id=? AND status='proposed'",
                                  (identifier,)).fetchone()
            if not raw:
                raise ExpenseError("記憶の確認対象が見つかりません。")
            self._claim_memory(identifier, dict(zip(("kind", "content", "due_date"), raw)))
            self.db.execute("UPDATE facts SET status='active' WHERE id=?", (identifier,))
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def _claim_memory(self, identifier, values):
        """Called only inside the same transaction as creation/GUI mutation."""
        key = _memory_claim_key(values, self._memory_scope)
        self.db.execute("INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)", (key, json.dumps(identifier)))

    @synchronized
    def remember_fact(self, kind, content, due_date=""):
        """Current memory:write host only; independent of proposal approval.

        Atomically create/replay one active fact per exact validated value tuple.
        Never update an existing fact or revive its tombstone. Capability checks
        belong to the authenticated service/dispatcher, not this storage layer.
        """
        values = _memory_values(kind, content, due_date)
        identifier = _remember_identifier(values, self._memory_scope)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            claim = self.db.execute("SELECT value FROM settings WHERE key=?",
                                    (_memory_claim_key(values, self._memory_scope),)).fetchone()
            if claim:
                identifier = json.loads(claim[0])
            else:
                # Adopt previously confirmed legacy IDs; never auto-approve a
                # proposed record. New automatic saves have their own active ID.
                prior = self.db.execute("SELECT id FROM facts WHERE kind=? AND content=? "
                                        "AND due_date IS ? AND status IN ('active','retired','done') "
                                        "ORDER BY created,id LIMIT 1",
                                        (kind, content, values["due_date"])).fetchone()
                if prior:
                    identifier = prior[0]
            raw = self.db.execute("SELECT id,kind,content,status,due_date FROM facts WHERE id=?",
                                  (identifier,)).fetchone()
            if raw:
                row = dict(zip(("id", "kind", "content", "status", "due_date"), raw))
            else:
                if claim:
                    raise ExpenseError("記憶の保存状態を確認してください。再作成はしません。")
                row = {"id": identifier, **values, "status": "active"}
                self.db.execute("INSERT INTO facts (id,kind,content,status,created,due_date) VALUES (?,?,?,?,?,?)",
                                (identifier, kind, content, "active", self.clock(), values["due_date"]))
            result = _remember_result(row, values)
            self._claim_memory(identifier, values)
            self.db.execute("COMMIT")
            return result
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    @synchronized
    def facts(self):
        rows = self.db.execute(
            "SELECT id,kind,content,status,due_date FROM facts WHERE status!='deleted' ORDER BY created,id"
        )
        return [dict(zip(("id", "kind", "content", "status", "due_date"), row)) for row in rows]

    @synchronized
    def memory_entries(self):
        """Trusted GUI host only; authenticate owner/CSRF/expiry before calling."""
        return [_memory_entry(row, self._memory_scope) for row in self.facts()]

    @synchronized
    def _change_memory(self, identifier, expected_digest, action, values=None):
        # BEGIN IMMEDIATE serializes the read + digest check + mutation across
        # separate State instances/connections, not just this instance's lock.
        self.db.execute("BEGIN IMMEDIATE")
        try:
            raw = self.db.execute(
                "SELECT id,kind,content,status,due_date FROM facts WHERE id=?", (identifier,)
            ).fetchone()
            row = dict(zip(("id", "kind", "content", "status", "due_date"), raw)) if raw else None
            allowed = {"proposed"} if action == "confirm" else {"active"} if action == "update" else {
                "proposed", "active", "retired", "done"}
            _check_memory(row, expected_digest, self._memory_scope, allowed)
            # Cover legacy random IDs and retain the old content's replay fence
            # when an active item is edited or its plaintext is erased.
            self._claim_memory(identifier, {key: row[key] for key in ("kind", "content", "due_date")})
            if action == "delete":
                # Schema-compatible tombstone: no original kind/content/date or
                # creation timestamp is retained. The NOT NULL columns are empty.
                self.db.execute("UPDATE facts SET kind='',content='',status='deleted',created=0,due_date=NULL WHERE id=?",
                                (identifier,))
                result = {"id": identifier, "status": "deleted"}
            else:
                if action == "confirm":
                    row["status"] = "active"
                else:
                    row.update(values)
                    self._claim_memory(identifier, values)
                self.db.execute("UPDATE facts SET kind=?,content=?,status=?,due_date=? WHERE id=?",
                                (row["kind"], row["content"], row["status"], row["due_date"], identifier))
                result = _memory_entry(row, self._memory_scope)
            self.db.execute("COMMIT")
            return result
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def confirm_memory(self, identifier, expected_digest):
        """Trusted GUI only. CAS-confirm a proposed item; never an LLM tool."""
        return self._change_memory(identifier, expected_digest, "confirm")

    def update_memory(self, identifier, expected_digest, kind, content, due_date=""):
        """Trusted GUI only. Edit an active item in place using its exact digest."""
        return self._change_memory(identifier, expected_digest, "update", _memory_values(kind, content, due_date))

    def delete_memory(self, identifier, expected_digest):
        """Trusted GUI only. CAS-remove content; a deleted ID cannot be revived."""
        return self._change_memory(identifier, expected_digest, "delete")

    @synchronized
    def active_facts(self):
        """Conversation input: approved active facts only, never GUI digests."""
        return [row for row in self.facts() if row["status"] == "active"]

    @synchronized
    def due_pending(self, today):
        return [
            fact
            for fact in self.active_facts()
            if fact["kind"] == "pending"
            and fact["status"] == "active"
            and fact["due_date"]
            and fact["due_date"] <= today.isoformat()
        ]

    @synchronized
    def retire_fact(self, identifier):
        """Trusted human action. Keep history instead of deleting it."""
        self.db.execute("UPDATE facts SET status='retired' WHERE id=? AND status!='deleted'", (identifier,))

    @synchronized
    def complete_pending(self, identifier):
        self.db.execute(
            "UPDATE facts SET status='done' WHERE id=? AND kind='pending' AND status='active'",
            (identifier,),
        )

    @synchronized
    def suggestion_due(self, *, heartbeat=False, urgent=False, failed=False):
        if heartbeat or urgent or failed:
            return False
        row = self.db.execute("SELECT value FROM settings WHERE key='last_suggestion'").fetchone()
        return row is None or self.clock() - float(row[0]) >= 7 * 86400

    @synchronized
    def mark_suggestion(self):
        """Caller records only an actually delivered suggestion."""
        self.db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('last_suggestion',?)", (str(self.clock()),)
        )

    @synchronized
    def close(self):
        self.db.close()
