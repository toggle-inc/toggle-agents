"""Runtime-entry opt-in with synthetic keys/private policies; no real settings."""

import builtins
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet

import test_cloud_auth_app as cloud_fixture
from cloud_auth_app import create_app, settings_from_environment
from runtime.business_profile_config import BUSINESS_KEY_ENV, POLICY_ENV, prepare_business_profile
from runtime.auth_store import SQLiteAuthorizationStore
from runtime.requester import Requester


class BusinessProfileConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cloud_fixture.CloudAuthTests.setUpClass()

    def setUp(self):
        self.cloud = cloud_fixture.CloudAuthTests()
        self.cloud.setUp()
        self.addCleanup(self.cloud.doCleanups)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.policy = Path(self.temp.name) / "synthetic_policy.py"
        self.policy.write_text("def check(**fields):\n    return []\n")
        self.metadata = {"enabled": True, "namespace": "expense-business-v1", "financial_writes": False,
                         "capabilities": ["memory:read", "memory:propose"], "policies": []}
        self.key = Fernet.generate_key().decode()

    def environment(self, metadata=None):
        config = copy.deepcopy(self.cloud.config)
        config["business"] = self.metadata if metadata is None else metadata
        return {**self.cloud.environment(config), BUSINESS_KEY_ENV: self.key, POLICY_ENV: str(self.policy)}

    def store(self):
        store = SQLiteAuthorizationStore(Path(self.temp.name) / "auth.sqlite")
        self.addCleanup(store.close)
        return store

    def test_disabled_needs_no_new_key_import_policy_or_network(self):
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == "runtime.business_profile_config":
                raise AssertionError("disabled business import")
            return original(name, *args, **kwargs)
        class Environment(dict):
            def get(self, name, *args):
                if name in {BUSINESS_KEY_ENV, POLICY_ENV}:
                    raise AssertionError("disabled private material lookup")
                return super().get(name, *args)
        with patch("builtins.__import__", side_effect=guard), patch("httpx.Client.send", side_effect=AssertionError("network")):
            settings = settings_from_environment(Environment(self.environment({"enabled": False})))
            self.assertIsNone(settings.business_factory)

    def test_memory_only_runtime_entry_builds_without_financial_or_policy_requirements(self):
        env = self.environment()
        env.pop(POLICY_ENV)
        settings = settings_from_environment(env)
        profile = settings.business_factory(settings, self.store())
        self.assertFalse(profile.financial_writes)
        self.assertIsNone(profile.policy_factory)
        self.assertEqual(profile.supported_operations, {"expense_context", "propose_teaching"})
        with patch("authorization_app.create_mcp", wraps=__import__("authorization_app").create_mcp) as mcp:
            create_app(environ=env, store_factory=lambda _: self.store())
        dispatcher = mcp.call_args.args[0]
        from runtime.provider_execution import READ_OPERATIONS
        self.assertEqual(dispatcher.supported_operations, READ_OPERATIONS | profile.supported_operations)

    def test_missing_or_bad_business_key_never_falls_back_to_provider_key_and_opens_no_store(self):
        for value in (None, "bad-business-key"):
            env = self.environment()
            env.pop(BUSINESS_KEY_ENV)
            if value is not None:
                env[BUSINESS_KEY_ENV] = value
            store = Mock()
            with self.assertRaises(ValueError):
                create_app(environ=env, store_factory=store)
            store.assert_not_called()

    def test_financial_config_requires_approved_policy_hash_role_and_company_scope(self):
        metadata = {**self.metadata, "financial_writes": True, "capabilities": ["mf:read", "mf:draft", "rules:read"],
            "policies": [{"person_id": "person-alice", "office_ids": ["office-a"], "position": "member",
                          "sha256": hashlib.sha256(self.policy.read_bytes()).hexdigest()}]}
        settings = settings_from_environment(self.environment(metadata))
        profile = settings.business_factory(settings, self.store())
        alice = Requester("expense-tenant", "person-alice", 200)
        policy = profile.policy_factory(alice)
        self.assertEqual(policy.office_ids, ("office-a",))
        self.assertEqual(policy.check(value=1), [])
        for change in (lambda m: m.update(financial_writes=False),
                       lambda m: m.update(policies=[]),
                       lambda m: m["policies"][0].update(sha256="b" * 64),
                       lambda m: m["policies"][0].update(person_id="unregistered-person")):
            bad = copy.deepcopy(metadata)
            change(bad)
            with self.assertRaises(ValueError):
                settings_from_environment(self.environment(bad))
        self.policy.write_text("def check(**fields):\n    return ['changed']\n")
        from runtime.state import ExpenseError
        with self.assertRaises(ExpenseError):
            policy.check(value=1)

    def test_business_key_must_not_reuse_provider_encryption_material(self):
        env = self.environment()
        env[BUSINESS_KEY_ENV] = env["EXPENSE_PROVIDER_ENCRYPTION_KEY"]
        store = Mock()
        with self.assertRaises(ValueError):
            create_app(environ=env, store_factory=store)
        store.assert_not_called()

    def test_attachment_capability_cannot_be_created_from_static_model_or_url_configuration(self):
        with self.assertRaises(ValueError):
            prepare_business_profile({**self.metadata, "capabilities": ["attachment:read"]},
                environ={BUSINESS_KEY_ENV: self.key}, allowed_people={"person-alice"})

    def test_ocr_policy_missing_or_changed_after_candidate_and_before_wire_stops_all_mf_writes(self):
        from runtime.state import ExpenseError
        from test_durable_business import PersonalProvider
        from runtime.provider_execution import ProviderExecutionResolver
        from types import SimpleNamespace
        original = self.policy.read_bytes()
        metadata = {**self.metadata, "financial_writes": True, "capabilities": ["mf:draft"],
            "policies": [{"person_id": "person-alice", "office_ids": ["office-a"], "position": "member",
                          "sha256": hashlib.sha256(original).hexdigest()}]}
        store = self.store()
        person = Requester("expense-tenant", "person-alice", 1900001000, capabilities=frozenset({"mf:draft"}))
        for phase in ("after_candidate", "immediately_before_write"):
            for change in ("missing", "hash_changed"):
                self.policy.write_bytes(original)
                settings = settings_from_environment(self.environment(metadata))
                profile = settings.business_factory(settings, store)
                provider = PersonalProvider()
                resolver = ProviderExecutionResolver(SimpleNamespace(mf=provider), store, "provider",
                    clock=lambda: 1900000000, tenant_id="expense-tenant", profile=profile)
                service = resolver(person, "mf:draft").service
                service.state.set_draft_consent(["office-a"], "synthetic-consent")
                receipt = service.receipts.save(
                    ("%PDF-1.4\nsynthetic policy check " + phase + " " + change).encode(), "application/pdf")
                candidate = service.mf_upload_receipt("office-a", receipt["path"])
                def alter():
                    if change == "missing":
                        self.policy.unlink()
                    else:
                        self.policy.write_bytes(original + b"\n# changed approved bytes\n")
                if phase == "after_candidate":
                    alter()
                    with self.assertRaises(ExpenseError):
                        service.mf_save_draft(candidate["preview_id"])
                    with self.assertRaises(ExpenseError):
                        profile.policy_factory(person)
                else:
                    execute = service.state.execute
                    def late_change(*args, **kwargs):
                        alter()
                        return execute(*args, **kwargs)
                    with patch.object(service.state, "execute", side_effect=late_change):
                        with self.assertRaises(ExpenseError):
                            service.mf_save_draft(candidate["preview_id"])
                self.assertEqual(provider.for_person(person).writes, [], (phase, change))
