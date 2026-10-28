"""Opt-in real PostgreSQL tests: disposable loopback expense_synthetic DB ONLY."""

import base64
import hashlib
import os
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from runtime.authorization import AgentAuthorization, PublicClient
from runtime.postgres_auth_store import PostgresAuthorizationStore
from runtime.requester import Requester


@unittest.skipUnless(
    os.environ.get("EXPENSE_SYNTHETIC_POSTGRES_DSN"), "isolated local DB not supplied"
)
class LocalPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg.conninfo import conninfo_to_dict

        cls.dsn = os.environ["EXPENSE_SYNTHETIC_POSTGRES_DSN"]
        info = conninfo_to_dict(cls.dsn)
        if info.get("host") != "127.0.0.1" or info.get("dbname") != "expense_synthetic":
            raise ValueError("Only the disposable loopback expense_synthetic DB is allowed")
        cls.schema = "expense_test_" + uuid.uuid4().hex
        with psycopg.connect(cls.dsn) as connection:
            script = (
                Path(__file__).with_name("runtime").joinpath("postgres_auth_schema.sql").read_text()
            )
            connection.execute(script.replace("expense_assistant_auth", cls.schema))
        cls.addClassCleanup(cls.drop_owned_schema)
        cls.store = PostgresAuthorizationStore(cls.dsn, schema=cls.schema)

    @classmethod
    def drop_owned_schema(cls):
        import psycopg
        from psycopg import sql

        with psycopg.connect(cls.dsn) as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(cls.schema)))

    def test_commit_rollback_and_reconnect(self):
        with self.store.transaction() as records:
            records.put("persistent", {"value": "合成"})
        with self.assertRaises(RuntimeError):
            with self.store.transaction() as records:
                records.put("persistent", {"value": "rollback"})
                raise RuntimeError("synthetic abort")
        reopened = PostgresAuthorizationStore(self.dsn, schema=self.schema)
        with reopened.transaction() as records:
            self.assertEqual(records.get("persistent"), {"value": "合成"})

    def test_concurrent_initial_record_updates_do_not_lose_data(self):
        barrier = threading.Barrier(6)

        def increment(_):
            barrier.wait(timeout=5)
            with self.store.transaction() as records:
                previous = records.get("new-counter") or {"count": 0}
                records.put("new-counter", {"count": previous["count"] + 1})

        with ThreadPoolExecutor(max_workers=6) as workers:
            list(workers.map(increment, range(6)))
        with self.store.transaction() as records:
            self.assertEqual(records.get("new-counter"), {"count": 6})

    def test_runtime_role_needs_only_schema_usage_and_table_read_insert_update(self):
        import psycopg
        from psycopg import sql

        role = "expense_runtime_" + uuid.uuid4().hex
        role_name = sql.Identifier(role)
        schema_name = sql.Identifier(self.schema)
        table = sql.Identifier(self.schema, "auth_records")
        with psycopg.connect(self.dsn) as admin:
            admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(role_name))
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(schema_name, role_name))
            admin.execute(
                sql.SQL("GRANT SELECT, INSERT, UPDATE ON TABLE {} TO {}").format(table, role_name)
            )

        def connect(dsn):
            connection = psycopg.connect(dsn, autocommit=True)
            connection.execute(sql.SQL("SET ROLE {}").format(role_name))
            return connection

        try:
            restricted = PostgresAuthorizationStore(self.dsn, schema=self.schema, connect=connect)
            with restricted.transaction() as records:
                records.put("minimal-role", {"ok": True})
            with restricted.transaction() as records:
                self.assertEqual(records.get("minimal-role"), {"ok": True})
            with connect(self.dsn) as connection:
                self.assertFalse(
                    connection.execute(
                        "SELECT has_table_privilege(current_user, %s, 'DELETE')",
                        (self.schema + ".auth_records",),
                    ).fetchone()[0]
                )
        finally:
            with psycopg.connect(self.dsn) as admin:
                admin.execute(sql.SQL("REVOKE ALL ON TABLE {} FROM {}").format(table, role_name))
                admin.execute(
                    sql.SQL("REVOKE ALL ON SCHEMA {} FROM {}").format(schema_name, role_name)
                )
                admin.execute(sql.SQL("DROP ROLE {}").format(role_name))

    def test_oauth_code_single_use_refresh_and_revocation_with_real_transactions(self):
        person = Requester("synthetic-tenant", "alice", 5000)
        authority = AgentAuthorization(
            self.store,
            lambda _: person,
            issuer="https://expense.example.test",
            tenant_id=person.tenant_id,
            clients=[
                PublicClient(
                    "sa", "合成", ("https://sa.example.test/callback",), frozenset({"mf:read"})
                )
            ],
            clock=lambda: 100,
        )
        verifier = "synthetic-verifier-" + "x" * 48
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        pending = authority.begin(
            None,
            client_id="sa",
            redirect_uri="https://sa.example.test/callback",
            resource=authority.resource,
            capabilities=frozenset({"mf:read"}),
            challenge=challenge,
            state="synthetic-state",
        )
        target = authority.decide(None, pending["request_id"], pending["csrf_token"], approve=True)
        arguments = {
            "code": parse_qs(urlsplit(target).query)["code"][0],
            "client_id": "sa",
            "redirect_uri": "https://sa.example.test/callback",
            "resource": authority.resource,
            "verifier": verifier,
        }
        pair = authority.exchange(**arguments)
        self.assertEqual(authority.authenticate(pair["access_token"]).person_id, "alice")
        from runtime.authorization import AuthorizationError

        with self.assertRaises(AuthorizationError):
            authority.exchange(**arguments)
        refreshed = authority.refresh(refresh_token=pair["refresh_token"], client_id="sa")
        self.assertEqual(authority.authenticate(refreshed["access_token"]).person_id, "alice")
        authority.revoke_token(refreshed["refresh_token"], "sa")
        with self.assertRaises(AuthorizationError):
            authority.authenticate(refreshed["access_token"])


if __name__ == "__main__":
    unittest.main()
