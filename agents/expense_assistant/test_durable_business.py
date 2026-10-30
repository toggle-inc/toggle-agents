"""Durable per-human business execution; synthetic providers and local store only."""

import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime.auth_store import SQLiteAuthorizationStore
from runtime.durable_receipts import DurableReceipts
from runtime.execution_profile import DurableExecutionProfile
from runtime.provider_execution import ProviderExecutionResolver, READ_OPERATIONS
from runtime.requester import AuthorizationRequiredError, Requester, RequesterDispatcher
from runtime.state import ExpenseError, OutcomeUnknownError
import test_runtime as fixtures


class PersonalProvider:
    def __init__(self):
        self.clients, self.connected = {}, True

    def status(self, person, provider):
        return "connected" if self.connected else "revoked"

    def for_person(self, person):
        if person.owner not in self.clients:
            client = fixtures.FakeMF()
            client.owner = person.owner
            self.clients[person.owner] = client
        return self.clients[person.owner]


class DurableBusinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = SQLiteAuthorizationStore(Path(self.temp.name) / "auth.sqlite")
        self.addCleanup(self.store.close)
        self.key, self.now = Fernet.generate_key(), 1900000000
        self.people = {name: Requester("synthetic-tenant", name, self.now + 1000,
            capabilities=frozenset({"mf:read", "mf:draft", "memory:read", "memory:propose", "receipt:read"}))
            for name in ("alice", "bob")}
        self.mf = PersonalProvider()
        self.profile = self.make_profile()
        self.resolver = self.make_resolver()
        self.dispatcher = RequesterDispatcher(self.people.get, self.resolver, clock=lambda: self.now)
        self.arguments = {"office": "office-a", "recognized_at": "2020-01-15", "value": 420,
                          "remark": "架空の移動", "memo": "架空駅A → 架空駅B", "ex_item_id": "item-a",
                          "ex_item_name": "旅費交通費"}

    def make_profile(self):
        return DurableExecutionProfile(self.store, self.key, "synthetic-business",
            capabilities=frozenset({"mf:read", "mf:draft", "memory:read", "memory:propose", "receipt:read"}),
            financial_writes=True, policy_factory=lambda _: fixtures.FakePolicy())

    def make_resolver(self):
        return ProviderExecutionResolver(SimpleNamespace(mf=self.mf, calendar=None), self.store,
            "synthetic-provider", clock=lambda: self.now, tenant_id="synthetic-tenant", profile=self.profile)

    def service(self, name="alice", capability="mf:draft"):
        return self.resolver(self.people[name], capability).service

    def consent(self, name="alice"):
        # SSO principal has no business scopes. The UI-only service cannot write.
        from dataclasses import replace
        service = self.resolver.consent_service(replace(self.people[name], capabilities=None))
        self.assertFalse(service.write_enabled)
        service.state.set_draft_consent(["office-a"], "synthetic-consent")

    def test_initial_company_consent_then_restart_exact_save_and_mf_link_once(self):
        preview = self.dispatcher.call("alice", "mf_create_transaction", self.arguments)
        with self.assertRaises(ExpenseError):
            self.dispatcher.call("alice", "mf_save_draft", {"preview_id": preview["preview_id"]})
        self.consent()
        restarted = RequesterDispatcher(self.people.get, self.make_resolver(), clock=lambda: self.now)
        saved = restarted.call("alice", "mf_save_draft", {"preview_id": preview["preview_id"]})
        self.assertEqual(saved["review_url"], "https://expense.moneyforward.com/transactions")
        self.assertEqual(saved["draft_status"], "saved_unsubmitted")
        self.assertFalse(saved["submitted"])
        self.assertTrue(saved["readback_verified"])
        self.assertEqual(restarted.call("alice", "mf_save_draft", {"preview_id": preview["preview_id"]}), saved)
        self.assertEqual(len(self.mf.for_person(self.people["alice"]).writes), 1)
        with self.assertRaises(ExpenseError):
            restarted.call("bob", "mf_save_draft", {"preview_id": preview["preview_id"]})

    def test_same_expense_without_receipt_cannot_be_recreated_with_another_candidate(self):
        self.consent()
        for index in range(2):
            p = self.dispatcher.call("alice", "mf_create_transaction", self.arguments)
            if index == 0:
                self.dispatcher.call("alice", "mf_save_draft", {"preview_id": p["preview_id"]})
            else:
                with self.assertRaises(ExpenseError):
                    self.dispatcher.call("alice", "mf_save_draft", {"preview_id": p["preview_id"]})
        self.assertEqual(len(self.mf.for_person(self.people["alice"]).writes), 1)

    def test_large_receipt_bytes_not_copied_to_ledger_and_ocr_duplicate_stops_after_restart(self):
        self.consent()
        service = self.service()
        content = b"%PDF-1.4\n" + b"synthetic receipt bytes " * 100000
        receipt = service.receipts.save(content, "application/pdf")
        p = self.dispatcher.call("alice", "mf_upload_receipt", {"office": "office-a", "receipt_path": receipt["path"]})
        snapshot = service.state.preview_details(p["preview_id"])["snapshot"]
        self.assertNotIn("content", snapshot["payload"])
        self.assertLess(len(json.dumps(snapshot)), 4096)
        result = self.dispatcher.call("alice", "mf_save_draft", {"preview_id": p["preview_id"]})
        self.assertEqual(result["draft_status"], "ocr_processing")
        self.assertTrue(result["ocr_pending"])
        stored = self.mf.for_person(self.people["alice"]).writes[-1][2]
        self.assertEqual(base64.b64decode(stored["content"]), content)
        restarted = self.make_resolver()(self.people["alice"], "mf:draft").service
        duplicate = restarted.receipts.save(content, "application/pdf")
        p2 = restarted.mf_upload_receipt("office-a", duplicate["path"])
        with self.assertRaises(ExpenseError):
            restarted.mf_save_draft(p2["preview_id"])
        self.assertEqual(len(self.mf.for_person(self.people["alice"]).writes), 1)

    def test_unknown_outcome_fences_same_and_new_candidate_without_receipt(self):
        self.consent()
        mf = self.mf.for_person(self.people["alice"])
        mf.fail_write = True
        p = self.dispatcher.call("alice", "mf_create_transaction", self.arguments)
        with self.assertRaises(OutcomeUnknownError):
            self.dispatcher.call("alice", "mf_save_draft", {"preview_id": p["preview_id"]})
        mf.fail_write = False
        for preview in (p, self.dispatcher.call("alice", "mf_create_transaction", self.arguments)):
            with self.assertRaises(OutcomeUnknownError):
                self.dispatcher.call("alice", "mf_save_draft", {"preview_id": preview["preview_id"]})
        self.assertEqual(len(mf.writes), 1)

    def test_narrow_read_scope_no_memory_draft_calendar_and_revocation_every_call(self):
        from dataclasses import replace
        self.people["alice"] = replace(self.people["alice"], capabilities=frozenset({"mf:read"}))
        names = self.dispatcher.available_operations("alice")
        self.assertIn("mf_offices", names)
        self.assertNotIn("expense_context", names)
        self.assertNotIn("mf_save_draft", names)
        self.assertNotIn("mf_create_transaction", names)
        self.assertNotIn("calendar_events", names)
        self.assertTrue(self.dispatcher.call("alice", "mf_offices", {}))
        self.mf.connected = False
        with self.assertRaises(AuthorizationRequiredError):
            self.dispatcher.call("alice", "mf_offices", {})
        self.assertEqual(self.dispatcher.available_operations("alice"), set())
        legacy = ProviderExecutionResolver(SimpleNamespace(mf=self.mf), self.store, "legacy")
        self.assertEqual(legacy.supported_operations, READ_OPERATIONS)

    def test_memory_only_profile_preserves_existing_stateless_mf_read_connection(self):
        from dataclasses import replace
        profile = DurableExecutionProfile(self.store, self.key, "only-memory",
                                          capabilities=frozenset({"memory:read"}))
        resolver = ProviderExecutionResolver(SimpleNamespace(mf=self.mf), self.store, "provider",
            clock=lambda: self.now, tenant_id="synthetic-tenant", profile=profile)
        person = replace(self.people["alice"], capabilities=frozenset({"mf:read"}))
        dispatcher = RequesterDispatcher(lambda _: person, resolver, clock=lambda: self.now)
        self.assertEqual(dispatcher.available_operations(None), {"mf_offices", "mf_list_transactions", "mf_list_reports"})
        self.assertTrue(dispatcher.call(None, "mf_offices", {}))
        self.assertFalse(resolver(person, "mf:read").service.write_enabled)

    def test_sqlite_state_also_fences_identical_non_receipt_expense(self):
        fixture = fixtures.RuntimeTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        fixture.state.set_draft_consent(["office-a"], "synthetic-consent")
        for index in range(2):
            p = fixture.service.mf_create_transaction(**fixture.create)
            if index == 0:
                fixture.service.mf_save_draft(p["preview_id"])
            else:
                with self.assertRaises(ExpenseError):
                    fixture.service.mf_save_draft(p["preview_id"])
        self.assertEqual(len(fixture.mf.writes), 1)

    def test_personal_memory_persists_without_mf_and_can_only_be_confirmed_by_trusted_host(self):
        self.mf.connected = False
        proposal = self.dispatcher.call("alice", "propose_teaching", {"kind": "preference", "content": "架空の短い書式"})
        self.service(capability="memory:read").state.accept_fact(proposal["id"])
        restarted = RequesterDispatcher(self.people.get, self.make_resolver(), clock=lambda: self.now)
        own = restarted.call("alice", "expense_context", {})
        other = restarted.call("bob", "expense_context", {})
        self.assertEqual(own["teachings"][0]["status"], "active")
        self.assertEqual(other["teachings"], [])
        with self.assertRaises(ExpenseError):
            restarted.call("alice", "accept_fact", {"identifier": proposal["id"]})

    def test_company_consent_can_be_revoked_while_mf_disconnected_but_cannot_be_granted(self):
        self.consent()
        self.mf.connected = False
        from dataclasses import replace
        ui = self.resolver.consent_service(replace(self.people["alice"], capabilities=None))
        with self.assertRaises(ExpenseError):
            ui.mf_offices()
        ui.state.set_draft_consent([], "synthetic-revoked", active=False)
        self.mf.connected = True
        p = self.dispatcher.call("alice", "mf_create_transaction", self.arguments)
        with self.assertRaises(ExpenseError):
            self.dispatcher.call("alice", "mf_save_draft", {"preview_id": p["preview_id"]})
        self.assertEqual(self.mf.for_person(self.people["alice"]).writes, [])

    def test_receipt_ciphertext_owner_namespace_key_and_magic_enforced(self):
        own = self.service().receipts
        receipt = own.save(b"%PDF-1.4\nsynthetic encrypted content", "application/pdf")
        self.assertEqual(own.payload(receipt["path"])["content_type"], "application/pdf")
        for other in (self.service("bob").receipts,
                      DurableReceipts(self.store, self.key, own.owner, "other-namespace"),
                      DurableReceipts(self.store, Fernet.generate_key(), own.owner, self.profile.namespace)):
            with self.assertRaises(ExpenseError):
                other.payload(receipt["path"])
        raw = str(self.store._db.execute("SELECT value FROM auth_records").fetchall())
        self.assertNotIn("synthetic encrypted content", raw)
        self.assertNotIn(base64.b64encode(b"%PDF-1.4\nsynthetic encrypted content").decode(), raw)
        with self.assertRaises(ExpenseError):
            own.save(b"not a receipt", "application/pdf")
        own.close()
        with self.assertRaises(ExpenseError):
            own.payload(receipt["path"])
        self.assertTrue(self.service().receipts.payload(receipt["path"]))

    def test_profile_requires_explicit_financial_enablement_policy_and_same_store(self):
        for options in ({}, {"financial_writes": True}):
            with self.assertRaises(ValueError):
                DurableExecutionProfile(self.store, self.key, "test", capabilities=frozenset({"mf:draft"}), **options)
        with self.assertRaises(ValueError):
            ProviderExecutionResolver(SimpleNamespace(mf=self.mf), object(), "test", profile=self.profile)
        self.consent()
        with self.assertRaises(AuthorizationRequiredError):
            self.dispatcher.call("alice", "mf_create_transaction", {**self.arguments, "confirm": True})
        self.assertEqual(self.mf.for_person(self.people["alice"]).writes, [])


class DurableConsentHTTPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from dataclasses import replace
        import httpx
        import test_authorization_app as base
        from authorization_app import create_app
        from runtime.draft_consent import DraftConsentBinding
        await base.AuthorizationAppTests.asyncSetUp(self)
        await self.client.aclose()
        self.fixture.now = 1900000000
        self.fixture.people = {name: replace(person, expires_at=self.fixture.now + 1000)
                               for name, person in self.fixture.people.items()}
        self.authority.clients["sa"] = replace(self.authority.clients["sa"],
            capabilities=self.authority.clients["sa"].capabilities | {"mf:draft"})
        self.mf = PersonalProvider()
        profile = DurableExecutionProfile(self.authority.store, Fernet.generate_key(), "synthetic-http-business",
            capabilities=frozenset({"mf:read", "mf:draft"}), financial_writes=True,
            policy_factory=lambda _: fixtures.FakePolicy())
        self.resolver = ProviderExecutionResolver(SimpleNamespace(mf=self.mf), self.authority.store,
            "provider", clock=self.authority.clock, tenant_id="synthetic-tenant", profile=profile)
        self.app = create_app(self.authority, self.resolver, draft_consent=DraftConsentBinding(
            self.authority, self.resolver, consent_service=self.resolver.consent_service))
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(self.app), base_url=self.authority.issuer)
        self.addAsyncCleanup(self.client.aclose)

    async def test_real_oauth_company_ui_to_durable_draft_and_narrow_scope(self):
        import test_draft_authorization as helpers
        import test_authorization_app as base
        self.login = base.AuthorizationAppTests.login.__get__(self)
        self.authorize = base.AuthorizationAppTests.authorize.__get__(self)
        self.decide = base.AuthorizationAppTests.decide.__get__(self)
        self.call = base.AuthorizationAppTests.call.__get__(self)
        async with self.app.app.router.lifespan_context(self.app.app):
            pair = await helpers.DraftAuthorizationTests.consent_token(self)
            token = pair["access_token"]
            self.assertEqual(self.authority.authenticate(token).capabilities, frozenset({"mf:draft"}))
            async def tool(name, args):
                return await helpers.DraftAuthorizationTests.tool(self, token, name, args)
            p = await tool("mf_create_transaction", {"office": "office-a", "recognized_at": "2020-01-15",
                "value": 420, "remark": "架空の移動", "memo": "架空駅A→架空駅B",
                "ex_item_id": "item-a", "ex_item_name": "旅費交通費"})
            result = await tool("mf_save_draft", {"preview_id": p["preview_id"]})
            self.assertEqual(result["draft_status"], "saved_unsubmitted")
            self.assertFalse(result["submitted"])
            self.assertEqual(len(self.mf.for_person(self.fixture.people["alice"]).writes), 1)
            self.assertNotIn("memory:read", self.authority.authenticate(token).capabilities)
