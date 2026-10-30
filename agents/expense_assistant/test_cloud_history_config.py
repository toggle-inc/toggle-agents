"""Pure opt-in config and real host composition with synthetic sources only."""

import copy
import logging
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cloud_auth_app as cloud_fixtures
from cloud_auth_app import create_app, settings_from_environment
from runtime.cloud_history_config import parse_cloud_history, build_cloud_history
from runtime.external_history_resolver import ExternalHistoryResolver
from _foundation.history_runtime import ConversationRuntime
from test_authorization import MemoryStore


class CloudHistoryConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cloud_fixtures.CloudAuthTests.setUpClass()
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        cls.read_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.read_private = cls.read_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()

    def setUp(self):
        self.fixture = cloud_fixtures.CloudAuthTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(logging.disable, logging.NOTSET)
        self.history = {
            "enabled": True,
            "source_issuer": "https://sa.example.test", "source_public_keys": {"source": self.fixture.public},
            "execution_issuer": "https://runtime.example.test", "execution_public_keys": {"runtime": self.fixture.public},
            "targets": [{"tenant_id": "engine-tenant", "agent_id": "expense-agent",
                         "version_id": "version-a", "connection_id": "connection-a"}],
            "identity_links": [
                {"issuer": "https://sa.example.test", "namespace": "source-tenant",
                 "subject": "source-alice", "person_id": "person-alice"},
                {"issuer": "https://identity.example.test", "namespace": "runtime-tenant",
                 "subject": "runtime-alice", "person_id": "person-alice"},
            ],
        }

    def settings(self, history):
        config = copy.deepcopy(self.fixture.config)
        config["history"] = history
        return settings_from_environment(self.fixture.environment(config))

    def test_default_and_disabled_require_no_new_import_keys_or_source_factory(self):
        import builtins
        original = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name == "runtime.cloud_history_config":
                raise AssertionError("legacy imported history configuration")
            return original(name, *args, **kwargs)
        source = Mock(side_effect=AssertionError("legacy source initialized"))
        with patch("builtins.__import__", side_effect=guarded), \
             patch("httpx.Client.send", side_effect=AssertionError("unexpected network")):
            for history in (None, {"enabled": False}):
                config = copy.deepcopy(self.fixture.config)
                if history is not None:
                    config["history"] = history
                self.assertIsNone(settings_from_environment(self.fixture.environment(config)).history)
                create_app(environ=self.fixture.environment(config),
                           store_factory=lambda _: MemoryStore(), history_source_factory=source)
        source.assert_not_called()

    def test_enabled_validates_independent_links_and_fixed_targets_without_store_or_http(self):
        with patch("httpx.Client.send", side_effect=AssertionError("unexpected network")):
            settings = self.settings(self.history).history
        source = settings.resolve_person("https://sa.example.test", "source-tenant", "source-alice")
        runtime = settings.resolve_person("https://identity.example.test", "runtime-tenant", "runtime-alice")
        self.assertEqual(source, runtime)
        self.assertEqual((source.tenant_id, source.person_id), ("expense-tenant", "person-alice"))
        self.assertIsNone(settings.resolve_person("https://sa.example.test", "runtime-tenant", "runtime-alice"))
        self.assertEqual(settings.targets[0].agent_id, "expense-agent")
        self.assertNotIn(self.fixture.public, repr(settings))
        self.assertNotIn("source-alice", repr(settings))

    def test_boundary_migration_is_explicit_boolean_and_wired_only_with_history(self):
        import authorization_app
        self.assertFalse(self.settings(self.history).history.boundary_migration)
        for invalid in (None, 0, 1, "true", {}, []):
            value = copy.deepcopy(self.history)
            value["boundary_migration"] = invalid
            with self.assertRaises(ValueError):
                self.settings(value)
        value = copy.deepcopy(self.history)
        value["boundary_migration"] = True
        config = copy.deepcopy(self.fixture.config)
        config["history"] = value
        store = MemoryStore()
        with patch("authorization_app.create_mcp", wraps=authorization_app.create_mcp) as mcp:
            app = create_app(environ=self.fixture.environment(config), store_factory=lambda _: store,
                history_source_factory=lambda *_: (Mock(), Mock()))
        self.assertTrue(mcp.call_args.kwargs["history_boundary_migration"])
        self.assertIsNotNone(app)
        from runtime.authorization import AgentAuthorization, PublicClient
        authority = AgentAuthorization(store, lambda _: None, issuer="https://expense.example.test",
            tenant_id="expense-tenant", clients=(PublicClient("synthetic", "Synthetic",
                ("https://sa.example.test/callback",), frozenset({"mf:read"})),))
        for invalid in (True, "true", 1, None):
            with self.assertRaisesRegex(ValueError, "History boundary migration"):
                authorization_app.create_app(authority, Mock(), history_boundary_migration=invalid)

    def test_unknown_fields_widened_people_bad_keys_and_incomplete_optin_fail_before_store(self):
        variants = [None, {}, {"enabled": "true"}, {"enabled": False, "source_public_keys": "bad"}]
        for field in ("source_public_keys", "targets", "identity_links"):
            value = copy.deepcopy(self.history)
            value.pop(field)
            variants.append(value)
        for mutation in (
            lambda v: v.update(enabled=1),
            lambda v: v.update(source_public_keys={"source": "synthetic-private-key-looking-value"}),
            lambda v: v.update(execution_issuer="http://runtime.example.test"),
            lambda v: v["targets"].append(v["targets"][0]),
            lambda v: v["identity_links"][0].update(person_id="unregistered-person"),
            lambda v: v["identity_links"].append(v["identity_links"][0]),
            lambda v: v.update(unknown="field"),
        ):
            value = copy.deepcopy(self.history)
            mutation(value)
            variants.append(value)
        for value in variants:
            config = copy.deepcopy(self.fixture.config)
            config["history"] = value
            store = Mock()
            with self.assertRaises(ValueError) as error:
                create_app(environ=self.fixture.environment(config), store_factory=store)
            self.assertNotIn("synthetic-private-key-looking-value", str(error.exception))
            store.assert_not_called()

    def test_enabled_requires_explicit_source_adapter_before_opening_store(self):
        config = copy.deepcopy(self.fixture.config)
        config["history"] = self.history
        store = Mock()
        with self.assertRaises(ValueError):
            create_app(environ=self.fixture.environment(config), store_factory=store)
        store.assert_not_called()

    def test_store_aware_factory_wires_same_authority_store_and_no_source_read(self):
        import authorization_app
        settings = self.settings(self.history).history
        store = MemoryStore()
        source, resolve_source = Mock(), Mock()
        factory = Mock(return_value=(source, resolve_source))
        runtime, resolver = build_cloud_history(settings, store, factory)
        self.assertIsInstance(runtime, ConversationRuntime)
        self.assertIsInstance(resolver, ExternalHistoryResolver)
        self.assertIs(resolver.verifier.store, store)
        factory.assert_called_once_with(settings, store)
        source.read.assert_not_called()
        resolve_source.assert_not_called()
        self.assertIsNone(build_cloud_history(None, store, Mock(side_effect=AssertionError("disabled"))))
        config = copy.deepcopy(self.fixture.config)
        config["history"] = self.history
        factory.reset_mock()
        with patch("authorization_app.create_mcp", wraps=authorization_app.create_mcp) as mcp:
            create_app(environ=self.fixture.environment(config), store_factory=lambda _: store,
                       history_source_factory=factory)
        self.assertIs(factory.call_args.args[1], store)
        self.assertIsInstance(mcp.call_args.kwargs["history_runtime"], ConversationRuntime)
        self.assertIs(mcp.call_args.kwargs["history_resolver"].verifier.store, store)
        source.read.assert_not_called()
        resolve_source.assert_not_called()

    def test_incomplete_source_result_fails_closed(self):
        settings = self.settings(self.history).history
        for pair in (None, (None, None), ({}, Mock()), (Mock(), None)):
            with self.assertRaises(ValueError):
                build_cloud_history(settings, MemoryStore(), lambda *_: pair)


    def real_history(self):
        from runtime.cloud_history_config import SOURCE_READ_KEY_ENV
        value = copy.deepcopy(self.history)
        value["targets"] = [{"tenant_id": "10", "agent_id": "12", "version_id": "18", "connection_id": "60"}]
        value["source_read"] = {"origin": "https://sa.example.test", "kid": "dedicated-read-key",
            "source_namespace": "source-tenant", "source_actor": "source-alice",
            "target": copy.deepcopy(value["targets"][0]), "agent_authors": ["source-bot"],
            "signing_key_env": SOURCE_READ_KEY_ENV}
        return value

    def real_environment(self):
        from runtime.cloud_history_config import SOURCE_READ_KEY_ENV
        config = copy.deepcopy(self.fixture.config)
        config["history"] = self.real_history()
        return {**self.fixture.environment(config), SOURCE_READ_KEY_ENV: self.read_private}

    def test_real_metadata_requires_exact_trust_target_existing_actor_and_fixed_key_reference(self):
        settings = self.settings(self.real_history()).history
        self.assertNotIn("source-alice", repr(settings.source_read))
        self.assertNotIn(self.read_private, repr(settings))
        for mutate in (
            lambda h: h["source_read"].update(origin="https://other.example.test"),
            lambda h: h.update(source_issuer="https://other.example.test"),
            lambda h: h["source_read"]["target"].update(version_id="19"),
            lambda h: h["source_read"].update(source_actor="unlinked-person"),
            lambda h: h["source_read"].update(source_namespace="other-namespace"),
            lambda h: h["source_read"].update(signing_key_env="EXPENSE_MF_CLIENT_SECRET"),
            lambda h: h["source_read"].update(agent_authors=[]),
            lambda h: h["source_read"].update(kid="bad key"),
        ):
            history = self.real_history()
            mutate(history)
            with self.assertRaises(ValueError):
                self.settings(history)

    def test_real_private_key_missing_public_or_weak_fails_before_store_and_http(self):
        from runtime.cloud_history_config import SOURCE_READ_KEY_ENV
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        for value in (None, "synthetic-not-a-key", self.fixture.public, weak):
            env = self.real_environment()
            env.pop(SOURCE_READ_KEY_ENV)
            if value is not None:
                env[SOURCE_READ_KEY_ENV] = value
            store = Mock()
            with patch("httpx.Client", side_effect=AssertionError("HTTP client before key validation")):
                with self.assertRaises(ValueError) as caught:
                    create_app(environ=env, store_factory=store)
            self.assertNotIn("synthetic-not-a-key", str(caught.exception))
            store.assert_not_called()

    def test_disabled_does_not_lookup_signing_env_import_client_or_create_http(self):
        import builtins
        from runtime.cloud_history_config import SOURCE_READ_KEY_ENV
        original = builtins.__import__
        class NoSigningLookup(dict):
            def __getitem__(self, key):
                if key == SOURCE_READ_KEY_ENV:
                    raise AssertionError("disabled signing key lookup")
                return super().__getitem__(key)
            def get(self, key, *args):
                if key == SOURCE_READ_KEY_ENV:
                    raise AssertionError("disabled signing key lookup")
                return super().get(key, *args)
        def guarded(name, *args, **kwargs):
            if name in {"runtime.sa_history_client", "runtime.cloud_history_config"}:
                raise AssertionError("disabled new client import")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=guarded), \
             patch("httpx.Client", side_effect=AssertionError("disabled new HTTP client")):
            for metadata in (None, {"enabled": False}):
                config = copy.deepcopy(self.fixture.config)
                if metadata is not None:
                    config["history"] = metadata
                env = NoSigningLookup(self.fixture.environment(config))
                with patch("cloud_auth_app.os.environ", env):
                    create_app(store_factory=lambda _: MemoryStore())

    def test_real_client_store_shared_and_shutdown_closes_once_then_refuses_use(self):
        import asyncio
        import authorization_app
        from runtime.sa_history_client import SAHistoryClient
        class Store(MemoryStore):
            def __init__(self):
                super().__init__()
                self.close_calls = 0
            def close(self):
                self.close_calls += 1
        store = Store()
        with patch("authorization_app.create_mcp", wraps=authorization_app.create_mcp) as mcp, \
             patch("httpx.Client.send", side_effect=AssertionError("construction sent HTTP")):
            app = create_app(environ=self.real_environment(), store_factory=lambda _: store)
        resolver = mcp.call_args.kwargs["history_resolver"]
        client = resolver.resolve_source.__self__
        self.assertIsInstance(client, SAHistoryClient)
        self.assertIs(resolver.verifier.store, store)
        self.assertIs(client, app._resources[-1])
        async def lifecycle():
            events = iter(({"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}))
            sent = []
            async def receive():
                return next(events)
            async def send(event):
                sent.append(event["type"])
            await app({"type": "lifespan"}, receive, send)
            self.assertEqual(sent, ["lifespan.startup.complete", "lifespan.shutdown.complete"])
        asyncio.run(lifecycle())
        self.assertTrue(client._http.is_closed)
        self.assertEqual(store.close_calls, 1)
        from _foundation.conversation import ContextError
        with self.assertRaises(ContextError):
            client.resolve_source(None)
        self.assertEqual(app._resources, [])

    def test_enabled_early_startup_failure_closes_store_before_connections_factory(self):
        store = MemoryStore()
        store.close = Mock()
        with patch("runtime.platform_login.PlatformLogin", side_effect=RuntimeError("early login setup failure")):
            with self.assertRaisesRegex(ValueError, "Dedicated expense auth startup failed"):
                create_app(environ=self.real_environment(), store_factory=lambda _: store)
        store.close.assert_called_once()

    def test_failed_startup_closes_already_created_client_store_and_continues_after_close_error(self):
        import authorization_app
        from runtime.sa_history_client import SAHistoryClient
        store = MemoryStore()
        store.close = Mock()
        clients = []
        def client_factory(**kwargs):
            client = SAHistoryClient(**kwargs)
            clients.append(client)
            return client
        with patch("runtime.sa_history_client.SAHistoryClient", side_effect=client_factory), \
             patch("authorization_app.create_mcp", side_effect=RuntimeError("synthetic-startup-failure")):
            with self.assertRaisesRegex(ValueError, "Dedicated expense auth startup failed"):
                create_app(environ=self.real_environment(), store_factory=lambda _: store)
        self.assertEqual(len(clients), 1)
        self.assertTrue(clients[0]._http.is_closed)
        store.close.assert_called_once()
        from cloud_auth_app import _close_resources
        first, bad, last = Mock(), Mock(), Mock()
        bad.close.side_effect = RuntimeError("synthetic-cleanup-failure")
        resources = [first, bad, last, first]
        with self.assertRaises(ValueError):
            _close_resources(resources)
        for resource in (first, bad, last):
            resource.close.assert_called_once()
        self.assertEqual(resources, [])
        _close_resources(resources)


if __name__ == "__main__":
    unittest.main()
