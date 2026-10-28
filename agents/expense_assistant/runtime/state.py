"""Private state and approval ledger. Approvals are issued by a trusted UI, not tools."""

import datetime as dt
import functools
import hashlib
import json
import os
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
        self.db.execute("PRAGMA journal_mode=DELETE")
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
            "SELECT action,office,snapshot,hash,expires,status FROM previews WHERE id=?",
            (identifier,),
        ).fetchone()
        if not row:
            raise ExpenseError("本人の確認対象が見つかりません。")
        action, office, raw, hashed, expires, status = row
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
            if fingerprint is not None:
                if (
                    action not in {"create", "upload"}
                    or not isinstance(fingerprint, str)
                    or len(fingerprint) != 64
                    or any(c not in "0123456789abcdef" for c in fingerprint)
                ):
                    raise ExpenseError("領収書の照合情報を確認してください。")
                prior = self.db.execute(
                    "SELECT p.status FROM receipt_claims c "
                    "LEFT JOIN previews p ON p.id=c.preview_id WHERE c.fingerprint=?",
                    (fingerprint,),
                ).fetchone()
                if prior:
                    if prior[0] == "done":
                        raise ExpenseError(
                            "同じ領収書は処理済みです。既存の明細・OCR結果を確認してください。"
                            "新しいプレビューでも二重登録しません。"
                        )
                    raise OutcomeUnknownError(
                        "同じ領収書の処理中または結果不明です。MF明細と照合してください。"
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
        allowed = {"commuter_pass", "base_location", "formatting", "pending", "preference"}
        if kind not in allowed or not isinstance(content, str) or not 1 <= len(content) <= 1000:
            raise ExpenseError("記憶の種類または長さが不正です。")
        if kind == "pending":
            try:
                due_date = dt.date.fromisoformat(due_date).isoformat()
            except (TypeError, ValueError) as error:
                raise ExpenseError("保留には確認予定日が必要です。") from error
        elif due_date:
            raise ExpenseError("確認予定日は保留にだけ指定できます。")
        import re

        if re.search(
            r"(?i)token|password|secret|認可コード|パスワード|口座|秘密|sk-[\w-]+|"
            r"https?://|[\w.+-]+@[\w.-]+|\b\d{10,}\b",
            content,
        ):
            raise ExpenseError(
                "秘密・口座・個人情報を記憶できません。一般的な決まりに言い換えてください。"
            )
        identifier = uuid.uuid4().hex
        self.db.execute(
            "INSERT INTO facts (id,kind,content,status,created,due_date) "
            "VALUES (?,?,?,'proposed',?,?)",
            (identifier, kind, content, self.clock(), due_date or None),
        )
        return {"id": identifier, "kind": kind, "content": content, "status": "proposed"}

    @synchronized
    def accept_fact(self, identifier):
        """Trusted human confirmation only, not an agent-callable operation."""
        changed = self.db.execute(
            "UPDATE facts SET status='active' WHERE id=? AND status='proposed'", (identifier,)
        ).rowcount
        if not changed:
            raise ExpenseError("記憶の確認対象が見つかりません。")

    @synchronized
    def facts(self):
        rows = self.db.execute(
            "SELECT id,kind,content,status,due_date FROM facts ORDER BY created,id"
        )
        return [dict(zip(("id", "kind", "content", "status", "due_date"), row)) for row in rows]

    @synchronized
    def due_pending(self, today):
        return [
            fact
            for fact in self.facts()
            if fact["kind"] == "pending"
            and fact["status"] == "active"
            and fact["due_date"]
            and fact["due_date"] <= today.isoformat()
        ]

    @synchronized
    def retire_fact(self, identifier):
        """Trusted human action. Keep history instead of deleting it."""
        self.db.execute("UPDATE facts SET status='retired' WHERE id=?", (identifier,))

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
