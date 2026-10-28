"""Replaceable transactional storage for agent-owned authorization records.

Production adapters must implement the SAME atomic transaction contract, not
separate read/write calls. Provider credentials are not stored by this module.
"""

import contextlib
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Protocol


class Records(Protocol):
    def get(self, key: str) -> dict | None: ...
    def put(self, key: str, value: dict) -> None: ...


class AuthorizationStore(Protocol):
    def transaction(self):
        """Yield Records; atomically commit, or roll back the whole operation."""
        ...


class _SQLiteRecords:
    def __init__(self, db):
        self.db = db

    def get(self, key):
        row = self.db.execute("SELECT value FROM auth_records WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key, value):
        self.db.execute(
            "INSERT INTO auth_records VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value, allow_nan=False, separators=(",", ":"))),
        )


class SQLiteAuthorizationStore:
    """Single-host implementation. Cloud deployments can supply another adapter.

    Use a dedicated private directory outside the Git source. The file contains
    identity/consent metadata and hashes, never plaintext access tokens or codes.
    """

    def __init__(self, path):
        path = Path(path).expanduser().absolute()
        source = Path(__file__).resolve().parents[1]
        if path.resolve().is_relative_to(source) or path.is_symlink():
            raise ValueError("Authorization storage must be outside the agent source")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.parent.is_symlink() or path.parent.stat().st_mode & 0o077:
            raise ValueError("Authorization storage needs a private directory")
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        os.fchmod(fd, 0o600)
        os.close(fd)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=15)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS auth_records (key TEXT PRIMARY KEY,value TEXT NOT NULL)"
        )

    @contextlib.contextmanager
    def transaction(self):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield _SQLiteRecords(self._db)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def close(self):
        self._db.close()
