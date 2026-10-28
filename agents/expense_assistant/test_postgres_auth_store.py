"""Offline store contract tests; the fake models committed rows and transaction locks."""

import contextlib
import copy
import hashlib
import json
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime.postgres_auth_store import PostgresAuthorizationStore  # noqa: E402

DSN = "postgresql://synthetic.invalid/auth"


class FakeDatabase:
    """Small READ COMMITTED model, not a PostgreSQL integration-test substitute.

    SELECT FOR UPDATE locks existing rows only. Advisory and row locks live
    until transaction exit. Writes remain private until commit.
    """

    def __init__(self, *, text_json=False):
        self.rows = {}
        self.connections = []
        self.locks = {}
        self.guard = threading.Lock()
        self.text_json = text_json
        self.before_lock = None
        self.after_select = None
        self.fail_sql = None
        self.fail_enter = False
        self.fail_commit = False

    def connect(self, dsn):
        if dsn != DSN:
            raise AssertionError("Only the synthetic DSN is allowed")
        connection = FakeConnection(self)
        self.connections.append(connection)
        return connection


class FakeConnection:
    def __init__(self, database):
        self.database = database
        self.calls = []
        self.events = []
        self.pending = {}
        self.held = {}
        self.active = False

    def acquire(self, key):
        if key in self.held:
            return
        with self.database.guard:
            lock = self.database.locks.setdefault(key, threading.Lock())
        if self.database.before_lock:
            self.database.before_lock(self, key)
        if not lock.acquire(timeout=5):
            raise TimeoutError("Synthetic transaction lock timed out")
        self.held[key] = lock

    @contextlib.contextmanager
    def transaction(self):
        self.events.append("begin")
        if self.database.fail_enter:
            raise RuntimeError("begin failed")
        self.active = True
        try:
            yield
            if self.database.fail_commit:
                raise RuntimeError("commit failed")
            with self.database.guard:
                self.database.rows.update(copy.deepcopy(self.pending))
            self.events.append("commit")
        except BaseException:
            self.events.append("rollback")
            raise
        finally:
            self.pending.clear()
            self.active = False
            for lock in self.held.values():
                lock.release()
            self.held.clear()

    def execute(self, sql, params):
        if not self.active:
            raise AssertionError("SQL must run inside a transaction")
        self.calls.append((sql, params))
        if self.database.fail_sql and self.database.fail_sql in sql:
            raise RuntimeError("SQL failed")
        if sql == "SELECT pg_advisory_xact_lock(%s)":
            self.acquire(("advisory", params[0]))
            return Mock()
        table = sql.split('"')[1]
        key = (table, params[0])
        if sql.startswith("SELECT value FROM"):
            with self.database.guard:
                exists = key in self.database.rows
            if exists:
                self.acquire(("row", key))
            with self.database.guard:
                value = copy.deepcopy(self.pending.get(key, self.database.rows.get(key)))
            if self.database.after_select:
                self.database.after_select(self, key)
            if value is not None and self.database.text_json:
                value = json.dumps(value)
            return Mock(fetchone=lambda: None if value is None else (value,))
        if sql.startswith("INSERT INTO"):
            self.acquire(("row", key))
            self.pending[key] = json.loads(params[1])
            return Mock()
        raise AssertionError(f"Unexpected SQL: {sql}")

    def close(self):
        if self.active or self.held:
            raise AssertionError("Connection closed before transaction exit")
        self.events.append("close")


class PostgresAuthorizationStoreTests(unittest.TestCase):
    def setUp(self):
        self.database = FakeDatabase()
        self.store = self.make_store()

    def make_store(self, **kwargs):
        return PostgresAuthorizationStore(DSN, connect=self.database.connect, **kwargs)

    def test_schema_identifier_validation_before_connect(self):
        for schema in (
            None,
            1,
            "",
            "Upper",
            "1bad",
            "a-b",
            "a.b",
            'a"; DROP SCHEMA x;--',
            "a\n",
            "a" * 64,
        ):
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                self.make_store(schema=schema)
        self.assertEqual(self.database.connections, [])
        for schema in ("a", "auth_123", "a" * 63):
            with self.subTest(schema=schema):
                with self.make_store(schema=schema).transaction() as records:
                    records.put("key", {})
                    records.get("missing")
                calls = self.database.connections[-1].calls
                data_sql = [sql for sql, _ in calls if "auth_records" in sql]
                self.assertEqual(len(data_sql), 2)
                self.assertTrue(all(f'"{schema}"."auth_records"' in sql for sql in data_sql))

    def test_connection_string_validation_before_connect(self):
        for dsn in (None, 1, "", " \n"):
            with self.subTest(dsn=dsn), self.assertRaises(ValueError):
                PostgresAuthorizationStore(dsn, connect=self.database.connect)
        self.assertEqual(self.database.connections, [])

    def test_sql_parameters_hash_keys_and_never_interpolate_values(self):
        key = "consent:'; DROP TABLE auth_records; --"
        value = {"person": "O'Reilly", "nested": ["%s", "日本語", "\\"]}
        with self.store.transaction() as records:
            self.assertIsNone(records.get(key))
            records.put(key, value)
        calls = self.database.connections[0].calls
        select = next(call for call in calls if call[0].startswith("SELECT value"))
        insert = next(call for call in calls if call[0].startswith("INSERT"))
        digest = hashlib.sha256(key.encode()).hexdigest()
        self.assertTrue(select[0].endswith("WHERE key = %s FOR UPDATE"))
        self.assertEqual(select[1], (digest,))
        self.assertIn("VALUES (%s, %s::jsonb)", insert[0])
        self.assertIn("ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", insert[0])
        self.assertEqual(insert[1][0], digest)
        self.assertEqual(json.loads(insert[1][1]), value)
        for sql, _ in calls:
            self.assertNotIn(key, sql)
            self.assertNotIn(value["person"], sql)

    def test_json_copy_on_put_and_every_get_for_native_and_text_rows(self):
        for text_json in (False, True):
            with self.subTest(text_json=text_json):
                self.database.text_json = text_json
                value = {"nested": {"items": [1, "日本語"]}, "enabled": True, "null": None}
                expected = copy.deepcopy(value)
                with self.store.transaction() as records:
                    records.put("copy", value)
                    value["nested"]["items"].append(2)
                    first = records.get("copy")
                    first["nested"]["items"].clear()
                    self.assertEqual(records.get("copy"), expected)
                with self.store.transaction() as records:
                    first = records.get("copy")
                    first["nested"]["items"].clear()
                    self.assertEqual(records.get("copy"), expected)
                with self.store.transaction() as records:
                    self.assertEqual(records.get("copy"), expected)

    def test_invalid_keys_objects_and_nonfinite_json_never_write_sql(self):
        with self.store.transaction() as records:
            for key in (None, "", 1, b"key"):
                for operation in (records.get, lambda key: records.put(key, {})):
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        operation(key)
            for value in (None, [], "text", 1, True):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    records.put("invalid", value)
            for number in (float("nan"), float("inf"), -float("inf")):
                with self.subTest(number=number), self.assertRaises(ValueError):
                    records.put("invalid", {"nested": [number]})
            with self.assertRaises(TypeError):
                records.put("invalid", {"unsupported": object()})
            self.assertFalse(
                any("auth_records" in sql for sql, _ in self.database.connections[0].calls)
            )
        self.assertEqual(self.database.rows, {})

    def test_read_your_writes_including_cached_miss_and_overwrite(self):
        with self.store.transaction() as records:
            self.assertIsNone(records.get("key"))
            records.put("key", {"revision": 1})
            self.assertEqual(records.get("key"), {"revision": 1})
            records.put("key", {"revision": 2})
            self.assertEqual(records.get("key"), {"revision": 2})
            self.assertIsNone(records.get("absent"))
            self.assertIsNone(records.get("absent"))
        selects = [
            sql for sql, _ in self.database.connections[0].calls if sql.startswith("SELECT value")
        ]
        self.assertEqual(len(selects), 2)
        with self.store.transaction() as records:
            self.assertEqual(records.get("key"), {"revision": 2})
        self.assertEqual(
            [c.events for c in self.database.connections],
            [["begin", "commit", "close"], ["begin", "commit", "close"]],
        )

    def test_rollback_all_writes_and_close_on_base_exception(self):
        with self.store.transaction() as records:
            records.put("existing", {"revision": 1})
        for exception in (RuntimeError("abort"), KeyboardInterrupt()):
            with self.subTest(exception=type(exception)), self.assertRaises(type(exception)):
                with self.store.transaction() as records:
                    records.put("existing", {"revision": 2})
                    records.put("new", {})
                    raise exception
            self.assertEqual(self.database.connections[-1].events, ["begin", "rollback", "close"])
            with self.store.transaction() as records:
                self.assertEqual(records.get("existing"), {"revision": 1})
                self.assertIsNone(records.get("new"))

    def test_close_on_begin_sql_and_commit_failure(self):
        for failure in ("begin", "pg_advisory_xact_lock", "SELECT value", "INSERT", "commit"):
            with self.subTest(failure=failure):
                self.database.fail_enter = failure == "begin"
                self.database.fail_commit = failure == "commit"
                self.database.fail_sql = (
                    failure
                    if failure in ("pg_advisory_xact_lock", "SELECT value", "INSERT")
                    else None
                )
                with self.assertRaises(RuntimeError):
                    with self.store.transaction() as records:
                        records.get("missing")
                        records.put("new", {})
                expected = (
                    ["begin", "close"] if failure == "begin" else ["begin", "rollback", "close"]
                )
                self.assertEqual(self.database.connections[-1].events, expected)
                self.assertEqual(self.database.rows, {})

    def test_transaction_lock_is_stable_schema_scoped_and_precedes_record_access(self):
        lock_keys = []
        for schema in ("auth_a", "auth_a", "auth_b"):
            with self.make_store(schema=schema).transaction() as records:
                records.get("missing")
            calls = self.database.connections[-1].calls
            self.assertEqual(calls[0][0], "SELECT pg_advisory_xact_lock(%s)")
            self.assertEqual(len(calls[0][1]), 1)
            lock_key = calls[0][1][0]
            self.assertIsInstance(lock_key, int)
            self.assertTrue(-(2**63) <= lock_key < 2**63)
            lock_keys.append(lock_key)
        self.assertEqual(lock_keys[0], lock_keys[1])
        self.assertNotEqual(lock_keys[0], lock_keys[2])

    def test_connection_failure_propagates_and_store_close_opens_nothing(self):
        connect = Mock(side_effect=RuntimeError("connect failed"))
        store = PostgresAuthorizationStore(DSN, connect=connect)
        store.close()
        connect.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "connect failed"):
            with store.transaction():
                self.fail("Must not yield after connection failure")
        connect.assert_called_once_with(DSN)

    def test_concurrent_first_consent_creation_is_serial_and_observes_commit(self):
        self.check_concurrent_first_access(rollback=False)

    def test_concurrent_first_access_after_rollback_can_create(self):
        self.check_concurrent_first_access(rollback=True)

    def check_concurrent_first_access(self, *, rollback):
        first_read = threading.Event()
        finish_first = threading.Event()
        second_attempt = threading.Event()
        observed = []
        second_store = self.make_store()

        def mark_attempt(connection, _key):
            if connection is not self.database.connections[0]:
                second_attempt.set()

        self.database.before_lock = mark_attempt
        # Without the advisory lock, a missing-row SELECT does not block;
        # signal only after its committed snapshot has been captured.
        self.database.after_select = mark_attempt

        def first():
            try:
                with self.store.transaction() as records:
                    self.assertIsNone(records.get("consent:alice:sa"))
                    first_read.set()
                    self.assertTrue(finish_first.wait(5))
                    records.put("consent:alice:sa", {"revision": "first"})
                    if rollback:
                        raise RuntimeError("synthetic rollback")
            except RuntimeError:
                if not rollback:
                    raise

        def second():
            with second_store.transaction() as records:
                value = records.get("consent:alice:sa")
                observed.append(value)
                if value is None:
                    records.put("consent:alice:sa", {"revision": "second"})

        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(first)
            try:
                self.assertTrue(first_read.wait(5))
                second_future = executor.submit(second)
                self.assertTrue(second_attempt.wait(5))
            finally:
                finish_first.set()
            first_future.result(timeout=10)
            second_future.result(timeout=10)
        self.assertEqual(observed, [None if rollback else {"revision": "first"}])
        with self.store.transaction() as records:
            self.assertEqual(
                records.get("consent:alice:sa"), {"revision": "second" if rollback else "first"}
            )
        for connection in self.database.connections:
            self.assertEqual(connection.events[-1], "close")


if __name__ == "__main__":
    unittest.main()
