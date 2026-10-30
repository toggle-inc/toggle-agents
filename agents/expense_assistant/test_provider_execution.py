"""Synthetic providers only; no live OAuth, secrets or personal records."""

import dataclasses
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runtime.authorization import AgentAuthorization, PublicClient
from runtime.provider_execution import READ_CAPABILITIES, ProviderExecutionResolver, read_service_factory
from runtime.requester import AuthorizationRequiredError, OperationUnavailableError, Requester, RequesterDispatcher
from runtime.service import ExpenseService
from runtime.state import ExpenseError
from test_authorization import CHALLENGE, VERIFIER, MemoryStore


class FakeProvider:
    def __init__(self):
        self.states, self.status_calls, self.bindings = {}, [], []
        self.wrong_owner = None

    def status(self, person, provider):
        self.status_calls.append((person.owner, provider))
        return self.states.get(person.owner, "not_connected")

    def for_person(self, person):
        self.bindings.append(person.owner)
        return SimpleNamespace(
            owner=self.wrong_owner or person.owner,
            offices=lambda: [{"id": person.person_id, "name": person.person_id}],
            events=lambda first, last: [{"summary": person.person_id}],
            create_transaction=Mock(side_effect=AssertionError("financial write reached")),
            download_receipt=Mock(side_effect=AssertionError("receipt download reached")),
        )


class ProviderExecutionTests(unittest.TestCase):
    def setUp(self):
        self.now = 100
        self.store = MemoryStore()
        self.people = {
            name: Requester("synthetic-tenant", name, 1000,
                            capabilities=frozenset({"mf:read", "calendar:read", "mf:write", "mf:draft"}))
            for name in ("alice", "bob")
        }
        self.providers = SimpleNamespace(mf=FakeProvider(), calendar=FakeProvider())
        for provider in (self.providers.mf, self.providers.calendar):
            provider.states = {p.owner: "connected" for p in self.people.values()}
        self.resolver = self.make_resolver()
        self.dispatcher = RequesterDispatcher(
            self.people.get, self.resolver, clock=lambda: self.now,
        )

    def make_resolver(self, **kwargs):
        return ProviderExecutionResolver(
            self.providers, self.store, "synthetic-execution", lambda: self.now,
            tenant_id="synthetic-tenant", **kwargs,
        )

    def test_two_people_read_their_own_mf_and_calendar(self):
        for name, person in self.people.items():
            self.assertEqual(self.dispatcher.call(name, "mf_offices", {})[0]["id"], name)
            result = self.dispatcher.call(name, "calendar_events", {
                "date_from": "2030-01-01", "date_to": "2030-01-02",
            })
            self.assertEqual(result[0]["summary"], name)
            grant = self.resolver(person, "mf:read")
            self.assertIs(type(grant.service), ExpenseService)
            self.assertEqual(grant.capabilities, frozenset({"mf:read"}))
            self.assertEqual(grant.service.state.owner, person.owner)
            self.assertIsNone(grant.service.receipts)

    def test_service_status_checked_on_every_call_without_fallback(self):
        person = self.people["alice"]
        self.assertIsNotNone(self.resolver(person, "mf:read"))
        for status in ("not_connected", "expired", "unavailable", "not_configured", "revoked"):
            self.providers.mf.states[person.owner] = status
            self.assertIsNone(self.resolver(person, "mf:read"))
        self.assertEqual(len(self.providers.mf.status_calls), 6)
        self.assertEqual(self.providers.mf.bindings, [person.owner])
        self.assertIsNotNone(self.resolver(self.people["bob"], "mf:read"))

    def test_readiness_distinguishes_provider_outage_from_personal_connection_and_unprovided(self):
        person = self.people["alice"]
        for state in ("not_connected", "expired", "revoked"):
            self.providers.mf.states[person.owner] = state
            self.assertEqual(self.resolver.readiness_reason(person, "mf:read"), "service_connection_required")
        for state in ("unavailable", "not_configured"):
            self.providers.mf.states[person.owner] = state
            self.assertEqual(self.resolver.readiness_reason(person, "mf:read"), "provider_unavailable")
        self.assertEqual(self.resolver.readiness_reason(person, "memory:read"), "operation_unavailable")

    def test_expiry_kind_tenant_and_absent_agent_permission_deny_before_provider(self):
        person = self.people["alice"]
        for change in (
            {"expires_at": 100}, {"expires_at": float("nan")},
            {"expires_at": float("inf")}, {"expires_at": True},
            {"kind": "service"}, {"kind": "admin"}, {"tenant_id": "other"},
            {"person_id": ""}, {"capabilities": None},
            {"capabilities": frozenset({"calendar:read"})},
            {"capabilities": {"mf:read"}},
        ):
            with self.subTest(change=change):
                self.assertIsNone(self.resolver(dataclasses.replace(person, **change), "mf:read"))
        self.assertEqual(self.providers.mf.status_calls, [])

    def test_unwired_capabilities_and_all_financial_writes_denied(self):
        for capability in ("mf:write", "mf:draft", "mf:connect", "receipt:read",
                           "memory:read", "fare:read", "rules:read", None, []):
            self.assertIsNone(self.resolver(self.people["alice"], capability))
        for operation, arguments in (
            ("mf_create_transaction", {"office": "alice", "recognized_at": "2030-01-01",
                                       "value": 100, "remark": "synthetic"}),
            ("mf_upload_receipt", {"office": "alice", "receipt_path": "synthetic"}),
            ("mf_delete_transaction", {"office": "alice", "transaction_id": "synthetic"}),
            ("mf_save_draft", {"preview_id": "synthetic"}),
        ):
            with self.subTest(operation=operation), self.assertRaises(OperationUnavailableError):
                self.dispatcher.call("alice", operation, arguments)
        self.assertEqual(self.providers.mf.bindings, [])

    def test_missing_provider_does_not_block_other_personal_provider(self):
        self.providers.mf = None
        self.assertIsNone(self.resolver(self.people["alice"], "mf:read"))
        self.assertIsNotNone(self.resolver(self.people["alice"], "calendar:read"))

    def test_contract_read_requires_explicit_permission_and_no_provider_calls(self):
        self.assertEqual(READ_CAPABILITIES, frozenset({"mf:read", "calendar:read", "contract:read"}))
        self.assertIsNone(self.resolver(self.people["alice"], "contract:read"))
        self.people["alice"] = dataclasses.replace(
            self.people["alice"], capabilities=frozenset({"contract:read"}),
        )
        result = self.dispatcher.call("alice", "delivery_contract", {})
        self.assertIsInstance(result, dict)
        self.assertEqual(self.providers.mf.status_calls, [])
        self.assertEqual(self.providers.calendar.status_calls, [])
        self.assertEqual(self.providers.mf.bindings, [])
        self.assertEqual(self.providers.calendar.bindings, [])

    def test_wrong_owner_including_same_person_different_tenant_is_denied(self):
        for other in (self.people["bob"], dataclasses.replace(self.people["alice"], tenant_id="other")):
            self.providers.mf.wrong_owner = other.owner
            self.assertIsNone(self.resolver(self.people["alice"], "mf:read"))

    def test_factory_is_explicit_and_rejects_wrong_owner_or_write_enabled(self):
        def factory(**kwargs):
            service = read_service_factory(**kwargs)
            service.state.owner = self.people["bob"].owner
            return service
        self.assertIsNone(self.make_resolver(service_factory=factory)(self.people["alice"], "mf:read"))
        def writable(**kwargs):
            service = read_service_factory(**kwargs)
            service.write_enabled = True
            return service
        self.assertIsNone(self.make_resolver(service_factory=writable)(self.people["alice"], "mf:read"))
        spy = Mock(wraps=read_service_factory)
        self.assertIsNotNone(self.make_resolver(service_factory=spy)(self.people["alice"], "mf:read"))
        self.assertIsNone(spy.call_args.kwargs["calendar"])

    def test_read_service_creates_no_local_state_and_blocks_receipt_and_write_methods(self):
        with patch("runtime.state.State", side_effect=AssertionError("state created")):
            service = self.resolver(self.people["alice"], "mf:read").service
        for action in (lambda: service.state.facts(), lambda: service.state.preview("x"),
                       lambda: service.mf.create_transaction("x"),
                       lambda: service.mf.download_receipt("x", "y")):
            with self.assertRaises(ExpenseError):
                action()

    def test_provider_failure_and_expiry_during_factory_fail_closed(self):
        with patch.object(self.providers.mf, "status", side_effect=RuntimeError("synthetic-secret")):
            self.assertIsNone(self.resolver(self.people["alice"], "mf:read"))
        def expire(**kwargs):
            self.now = 1000
            return read_service_factory(**kwargs)
        self.assertIsNone(self.make_resolver(service_factory=expire)(self.people["alice"], "mf:read"))

    def test_current_agent_consent_rechecked_by_authority_on_every_dispatch(self):
        authority = AgentAuthorization(
            self.store, self.people.get, issuer="https://expense.example.test",
            tenant_id="synthetic-tenant", clock=lambda: self.now,
            clients=(PublicClient("synthetic", "Synthetic", ("https://client.example.test/callback",),
                                  frozenset({"mf:read"})),),
        )
        request = authority.begin("alice", client_id="synthetic",
                                  redirect_uri="https://client.example.test/callback",
                                  resource=authority.resource, capabilities=frozenset({"mf:read"}),
                                  challenge=CHALLENGE, state="synthetic")
        target = authority.decide("alice", request["request_id"], request["csrf_token"], approve=True)
        code = parse_qs(urlsplit(target).query)["code"][0]
        token = authority.exchange(code=code, client_id="synthetic",
                                   redirect_uri="https://client.example.test/callback",
                                   resource=authority.resource, verifier=VERIFIER)["access_token"]
        dispatcher = RequesterDispatcher(authority.authenticate, self.resolver, clock=lambda: self.now)
        self.assertEqual(dispatcher.call(token, "mf_offices", {})[0]["id"], "alice")
        count = len(self.providers.mf.status_calls)
        authority.revoke_consent("alice", "synthetic")
        with self.assertRaises(ExpenseError):
            dispatcher.call(token, "mf_offices", {})
        self.assertEqual(len(self.providers.mf.status_calls), count)


if __name__ == "__main__":
    unittest.main()
