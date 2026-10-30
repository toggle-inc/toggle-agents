"""Readiness is agent consent + fresh personal grants, never provider UI alone."""

import dataclasses
import unittest
from pathlib import Path

import test_authorization as fixture
from runtime.authorization import AuthorizationError
from runtime.execution_readiness import ExecutionReadiness
from runtime.requester import ConnectionGrant
from runtime.service import ExpenseService
from runtime.state import State
from test_requester import SyntheticMF


class ExecutionReadinessTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.AuthorizationTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.services = {}
        for name, person in self.f.people.items():
            state = State(Path(self.f.directory.name) / (name + '.sqlite'), person.owner)
            self.addCleanup(state.close)
            self.services[name] = ExpenseService(mf=SyntheticMF(person.owner, name), state=state)
        self.calls = []
        self.disconnected = False

        def resolve(person, capability):
            self.calls.append((person.person_id, capability))
            if self.disconnected:
                return None
            return ConnectionGrant(person.tenant_id, person.person_id, person.expires_at,
                                   person.capabilities, self.services[person.person_id],
                                   agent_slug='expense_assistant')

        self.resolve = resolve
        self.ready = ExecutionReadiness(self.f.authority, resolve)
        self.params = {'schema_version': 'agent-execution-readiness-request/v1',
                       'client_id': 'sa', 'request_id': 'synthetic-request-1'}

    def consent(self):
        self.f.code(capabilities=frozenset({'mf:read', 'calendar:read'}))

    def test_connected_providers_are_not_agent_authorization(self):
        result = self.ready.view('alice', self.params)
        self.assertFalse(result['ready'])
        self.assertEqual(result['reason'], 'agent_authorization_required')
        self.assertEqual(self.calls, [])

    def test_partial_consent_cannot_satisfy_broad_registered_client(self):
        self.f.code(capabilities=frozenset({'mf:read'}))
        self.assertEqual(self.ready.view('alice', self.params)['reason'], 'agent_authorization_required')
        self.assertEqual(self.calls, [])

    def test_consent_and_fresh_grants_are_ready_without_tool_execution(self):
        self.consent()
        result = self.ready.view('alice', self.params)
        self.assertTrue(result['ready'])
        self.assertEqual(result['request_id'], self.params['request_id'])
        self.assertEqual(result['expires_at'], self.f.now + 60)
        self.assertEqual({p for p, _ in self.calls}, {'alice'})
        self.assertNotIn('access_token', result)
        self.assertFalse(self.ready.view('bob', self.params)['ready'])

    def test_revocation_and_provider_disconnect_rechecked(self):
        self.consent()
        self.disconnected = True
        self.assertEqual(self.ready.view('alice', self.params)['reason'], 'service_connection_required')
        self.disconnected = False
        self.f.authority.revoke_consent('alice', 'sa')
        self.assertEqual(self.ready.view('alice', self.params)['reason'], 'agent_authorization_required')

    def test_invalid_identity_client_and_request_are_rejected(self):
        for who, patch in [('unknown', {}), ('alice', {'client_id': 'unknown'}),
                           ('alice', {'request_id': 'two words'}), ('alice', {'person_id': 'bob'})]:
            with self.assertRaises(AuthorizationError):
                self.ready.view(who, {**self.params, **patch})

    def test_grant_for_another_person_or_expired_grant_is_not_ready(self):
        self.consent()
        def wrong(person, capability):
            return dataclasses.replace(self.resolve(person, capability), person_id='bob')
        self.assertFalse(ExecutionReadiness(self.f.authority, wrong).view('alice', self.params)['ready'])
        def expired(person, capability):
            return dataclasses.replace(self.resolve(person, capability), expires_at=self.f.now)
        self.assertFalse(ExecutionReadiness(self.f.authority, expired).view('alice', self.params)['ready'])


class OperationReadinessTests(unittest.TestCase):
    setUp = ExecutionReadinessTests.setUp

    def params_v2(self, operation):
        return {**self.params, "schema_version": "agent-operation-readiness-request/v2", "operation": operation}

    def test_general_advice_needs_no_business_scope_consent_or_provider(self):
        result = self.ready.view("alice", self.params_v2(None))
        self.assertTrue(result["ready"])
        self.assertEqual(result["reason"], "general_advice")
        self.assertEqual(result["required_capabilities"], [])
        self.assertFalse(result["execution_authorization_required"])
        self.assertEqual(self.calls, [])

    def test_operation_only_requires_its_own_scope_and_rechecks_revoke(self):
        self.assertEqual(self.ready.view("alice", self.params_v2("mf_offices"))["reason"], "agent_authorization_required")
        self.f.code(capabilities=frozenset({"mf:read"}))
        result = self.ready.view("alice", self.params_v2("mf_offices"))
        self.assertTrue(result["ready"])
        self.assertEqual(result["required_capabilities"], ["mf:read"])
        # V1 intentionally still requires all registered read capabilities.
        self.assertFalse(self.ready.view("alice", self.params)["ready"])
        self.f.authority.revoke_consent("alice", "sa")
        self.assertEqual(self.ready.view("alice", self.params_v2("mf_offices"))["reason"], "agent_authorization_required")

    def test_unprovided_operation_and_unregistered_scope_do_not_ask_for_more_consent(self):
        self.resolve.supported_operations = frozenset({"mf_offices"})
        for operation in ("calendar_events", "expense_context", "not_a_tool", "mf_save_draft"):
            result = self.ready.view("alice", self.params_v2(operation))
            self.assertFalse(result["ready"])
            self.assertEqual(result["reason"], "operation_unavailable")
        self.assertEqual(self.calls, [])

    def test_provider_outage_is_not_missing_connection_or_missing_agent_consent(self):
        self.f.code(capabilities=frozenset({"mf:read"}))
        self.disconnected = True
        self.assertEqual(self.ready.view("alice", self.params_v2("mf_offices"))["reason"], "service_connection_required")
        self.resolve.readiness_reason = lambda person, capability: "provider_unavailable"
        result = self.ready.view("alice", self.params_v2("mf_offices"))
        self.assertEqual(result["reason"], "provider_unavailable")
        self.assertIn("再同意を繰り返さず", result["description"])

    def test_v2_rejects_extra_identity_and_invalid_operation_fields(self):
        for delta in ({"operation": []}, {"person_id": "bob"}, {"request_id": "has spaces"}):
            with self.assertRaises(AuthorizationError):
                self.ready.view("alice", {**self.params_v2(None), **delta})

    def test_create_upload_readiness_uses_existing_write_or_draft_consent_without_new_grant(self):
        from runtime.requester import RequesterDispatcher
        from runtime.providers import Receipts
        import test_runtime as providers
        self.f.authority.clients["sa"] = dataclasses.replace(self.f.authority.clients["sa"],
            capabilities=self.f.authority.clients["sa"].capabilities | {"mf:write", "mf:draft"})
        service = self.services["alice"]
        service.mf = providers.FakeMF()
        service.mf.owner = service.state.owner
        service.policy = providers.FakePolicy()
        service.receipts = Receipts(Path(self.f.directory.name) / "receipts", None, service.state.owner)
        receipt = service.receipts.save(b"%PDF-1.4\nsynthetic capability test", "application/pdf")
        for capability in ("mf:write", "mf:draft"):
            self.f.code(capabilities=frozenset({capability}))
            dispatcher = RequesterDispatcher(lambda _: self.f.authority.consented_requester(
                "alice", "sa", frozenset({capability})), self.resolve, clock=lambda: self.f.now)
            operations = (
                ("mf_create_transaction", {"office": "office-a", "recognized_at": "2020-01-15",
                    "value": 420, "remark": "架空の移動", "memo": "架空駅A→架空駅B",
                    "ex_item_id": "item-a", "ex_item_name": "旅費交通費"}),
                ("mf_upload_receipt", {"office": "office-a", "receipt_path": receipt["path"]}),
            )
            for operation, arguments in operations:
                preview = dispatcher.call(None, operation, arguments)
                self.assertIn("preview_id", preview)
                status = self.ready.view("alice", self.params_v2(operation))
                self.assertTrue(status["ready"], status)
                self.assertEqual(status["required_capabilities"], [capability])
            self.assertEqual(self.f.authority.consented_requester("alice", "sa", frozenset({capability})).capabilities,
                             frozenset({capability}))
        self.assertEqual(service.mf.writes, [])

    def test_write_grant_unavailable_falls_back_to_current_draft_consent(self):
        self.f.authority.clients["sa"] = dataclasses.replace(self.f.authority.clients["sa"],
            capabilities=self.f.authority.clients["sa"].capabilities | {"mf:write", "mf:draft"})
        self.f.code(capabilities=frozenset({"mf:write", "mf:draft"}))
        resolve = self.resolve
        ready = ExecutionReadiness(self.f.authority,
            lambda person, capability: None if capability == "mf:write" else resolve(person, capability))
        result = ready.view("alice", self.params_v2("mf_create_transaction"))
        self.assertTrue(result["ready"], result)
        self.assertEqual(result["required_capabilities"], ["mf:draft"])
