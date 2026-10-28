"""Host wiring tests with synthetic secrets and an isolated SQLite store."""

import dataclasses
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
from authorization_host import AuthorizationHostSettings, create_host, settings_from_environment
from runtime.auth_store import SQLiteAuthorizationStore
from runtime.authorization import PublicClient


class HostTests(unittest.IsolatedAsyncioTestCase):
    def settings(self):
        return AuthorizationHostSettings(
            origin="https://expense.example.test",
            tenant_id="synthetic-tenant",
            okta_issuer="https://idp.example.test/oauth2/default",
            okta_client_id="synthetic-client",
            clients=(
                PublicClient(
                    "sa",
                    "Synthetic SA",
                    ("https://sa.example.test/callback",),
                    frozenset({"mf:read", "mf:draft"}),
                ),
            ),
            database_url="postgresql://synthetic:synthetic-password@db.example.test/qa?sslmode=verify-full",
            okta_client_secret="synthetic-okta-secret",
            state_encryption_key="synthetic-encryption-key-" + "x" * 32,
        )

    def test_secrets_are_not_in_settings_repr(self):
        settings = self.settings()
        for secret in (
            settings.database_url,
            settings.okta_client_secret,
            settings.state_encryption_key,
        ):
            self.assertNotIn(secret, repr(settings))

    def test_missing_secrets_never_fall_back_to_owner_or_shared_configuration(self):
        with patch.dict(
            os.environ,
            {"DATABASE_URL": "shared-secret", "MF_CLIENT_SECRET": "owner-secret"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "not configured") as caught:
                settings_from_environment(
                    origin="https://expense.example.test",
                    tenant_id="t",
                    okta_issuer="https://idp.example.test",
                    okta_client_id="c",
                    clients=(),
                )
        self.assertNotIn("shared-secret", str(caught.exception))

    def test_environment_uses_only_dedicated_secret_names(self):
        settings = self.settings()
        with patch.dict(
            os.environ,
            {
                "EXPENSE_AUTH_DATABASE_URL": settings.database_url,
                "EXPENSE_OKTA_CLIENT_SECRET": settings.okta_client_secret,
                "EXPENSE_OKTA_STATE_KEY": settings.state_encryption_key,
            },
            clear=True,
        ):
            result = settings_from_environment(
                origin=settings.origin,
                tenant_id=settings.tenant_id,
                okta_issuer=settings.okta_issuer,
                okta_client_id=settings.okta_client_id,
                clients=settings.clients,
            )
        self.assertEqual(result, settings)

    def test_invalid_or_weak_database_settings_fail_before_opening_store(self):
        for value in (
            "postgresql://synthetic:secret@db.example.test/qa?sslmode=require",
            "dbname=qa sslmode=verify-full",
            "not a dsn synthetic-secret",
            "host=/tmp dbname=qa user=synthetic password=secret sslmode=verify-full",
            "host=',db.example.test' dbname=qa user=synthetic password=secret sslmode=verify-full",
            "host='db.example.test,' dbname=qa user=synthetic password=secret sslmode=verify-full",
        ):
            with (
                self.subTest(value=value),
                patch("authorization_host.PostgresAuthorizationStore") as store,
            ):
                with self.assertRaises(ValueError) as caught:
                    create_host(
                        dataclasses.replace(self.settings(), database_url=value),
                        resolve_person=lambda *_: None,
                        resolve_connection=lambda *_: None,
                    )
                store.assert_not_called()
                self.assertNotIn("synthetic-secret", str(caught.exception))

    def test_missing_resolvers_and_invalid_client_fail_closed(self):
        with patch("authorization_host.PostgresAuthorizationStore") as store:
            with self.assertRaises(ValueError):
                create_host(
                    self.settings(), resolve_person=None, resolve_connection=lambda *_: None
                )
            with self.assertRaises(ValueError):
                create_host(
                    dataclasses.replace(self.settings(), clients=()),
                    resolve_person=lambda *_: None,
                    resolve_connection=lambda *_: None,
                )
            store.assert_not_called()

    def test_store_authority_session_and_resolvers_are_identical(self):
        store = object()
        store_factory = Mock(return_value=store)
        resolve_person = Mock()
        resolve_connection = Mock()
        with patch("authorization_host.create_app") as create_app:
            create_host(
                self.settings(),
                resolve_person=resolve_person,
                resolve_connection=resolve_connection,
                store_factory=store_factory,
            )
        store_factory.assert_called_once_with(self.settings().database_url)
        authority, mcp_resolver = create_app.call_args.args
        okta = create_app.call_args.kwargs["login_adapter"]
        binding = create_app.call_args.kwargs["draft_consent"]
        self.assertIs(authority.store, store)
        self.assertIs(okta.store, store)
        self.assertIs(authority.verify_login.__self__, okta)
        self.assertIs(okta.resolve_person, resolve_person)
        self.assertIs(mcp_resolver, resolve_connection)
        self.assertIs(binding.authority, authority)
        self.assertIs(binding.resolve, resolve_connection)
        resolve_person.assert_not_called()
        resolve_connection.assert_not_called()

    async def test_metadata_and_unauthorized_mcp_work_without_default_person(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700)
            store = SQLiteAuthorizationStore(Path(directory) / "auth.sqlite")
            calls = []

            def factory(dsn):
                calls.append(dsn)
                return store

            def no_identity(*_):
                raise AssertionError("Metadata must not infer a person")

            app = create_host(
                self.settings(),
                resolve_person=no_identity,
                resolve_connection=no_identity,
                store_factory=factory,
            )
            try:
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app), base_url="https://expense.example.test"
                ) as client:
                    metadata = await client.get("/.well-known/oauth-authorization-server")
                    self.assertEqual(metadata.status_code, 200)
                    self.assertEqual(metadata.json()["issuer"], self.settings().origin)
                    self.assertIn("refresh_token", metadata.json()["grant_types_supported"])
                    self.assertEqual(metadata.headers["cache-control"], "no-store")
                    response = await client.post("/mcp", json={})
                    self.assertEqual(response.status_code, 401)
                    self.assertNotIn("synthetic-password", response.text)
                self.assertEqual(calls, [self.settings().database_url])
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
