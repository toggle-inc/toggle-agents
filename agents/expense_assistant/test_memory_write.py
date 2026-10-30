"""Independent memory:write consent through real authority/dispatcher/MCP.

Synthetic people and local encrypted state only. Network transports are blocked;
HTTP MCP uses an in-process ASGI transport, never an external app or provider.
"""

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from cryptography.fernet import Fernet
import httpx

from requester_mcp import create_app
from runtime.auth_store import SQLiteAuthorizationStore
from runtime.authorization import AgentAuthorization, AuthorizationError, CAPABILITY_LABELS, PublicClient
from runtime.business_profile_config import BUSINESS_KEY_ENV, prepare_business_profile
from runtime.execution_profile import DurableExecutionProfile
from runtime.provider_execution import ProviderExecutionResolver
from runtime.requester import Requester, RequesterDispatcher
from runtime.state import ExpenseError
from test_authorization import CHALLENGE, VERIFIER


class MemoryWriteTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root, self.key, self.now = Path(temp.name), Fernet.generate_key(), 100
        self.store = SQLiteAuthorizationStore(self.root / "auth.sqlite")
        self.addCleanup(self.store.close)
        self.people = {name: Requester("test-tenant", name, 5000) for name in ("alice", "bob")}
        self.scopes = frozenset({"memory:read", "memory:propose", "memory:write"})
        self.authority = AgentAuthorization(self.store, self.people.get, issuer="https://expense.example.test",
            tenant_id="test-tenant", clock=lambda: self.now,
            clients=(PublicClient("test", "架空の入口", ("https://client.example.test/callback",), self.scopes),))
        self.providers = SimpleNamespace(mf=Mock(), calendar=Mock())
        self.profile = self.make_profile()
        self.dispatcher = self.make_dispatcher()
        self.arguments = {"kind": "preference", "content": "架空の簡潔な書式"}
        guard = patch("httpx.HTTPTransport.handle_request", side_effect=AssertionError("external network forbidden"))
        guard.start()
        self.addCleanup(guard.stop)

    def make_profile(self, scopes=None):
        return DurableExecutionProfile(self.store, self.key, "test-memory", capabilities=self.scopes if scopes is None else scopes)

    def resolver(self):
        return ProviderExecutionResolver(self.providers, self.store, "test-execution", clock=lambda: self.now,
                                         tenant_id="test-tenant", profile=self.profile)

    def make_dispatcher(self):
        return RequesterDispatcher(self.authority.authenticate, self.resolver(), clock=lambda: self.now)

    def token(self, scopes=None, who="alice"):
        pending = self.authority.begin(who, client_id="test", redirect_uri="https://client.example.test/callback",
            resource=self.authority.resource, capabilities=self.scopes if scopes is None else frozenset(scopes),
            challenge=CHALLENGE, state="test-state")
        redirect = self.authority.decide(who, pending["request_id"], pending["csrf_token"], approve=True)
        code = parse_qs(urlsplit(redirect).query)["code"][0]
        return self.authority.exchange(code=code, client_id="test", redirect_uri="https://client.example.test/callback",
                                       resource=self.authority.resource, verifier=VERIFIER)

    def test_initial_write_consent_saves_active_without_proposal_or_per_item_gui(self):
        pair = self.token()
        token = pair["access_token"]
        saved = self.dispatcher.call(token, "remember_teaching", self.arguments)
        self.assertEqual(saved["status"], "active")
        self.assertIs(saved["saved"], True)
        self.assertEqual(self.dispatcher.call(token, "expense_context", {})["teachings"][0]["id"], saved["id"])
        self.assertEqual(self.make_dispatcher().call(token, "remember_teaching", self.arguments), saved)
        self.providers.mf.status.assert_not_called()
        self.providers.calendar.status.assert_not_called()

    def test_old_propose_token_and_refresh_never_elevate_to_write(self):
        old = self.token({"memory:read", "memory:propose"})
        token = old["access_token"]
        with self.assertRaises(ExpenseError):
            self.dispatcher.call(token, "remember_teaching", self.arguments)
        proposal = self.dispatcher.call(token, "propose_teaching", self.arguments)
        self.assertEqual(proposal["status"], "proposed")
        self.assertEqual(self.dispatcher.call(token, "expense_context", {})["teachings"], [])
        with self.assertRaises(AuthorizationError):
            self.authority.refresh(refresh_token=old["refresh_token"], client_id="test", capabilities=self.scopes)
        renewed = self.authority.refresh(refresh_token=old["refresh_token"], client_id="test")
        self.assertNotIn("memory:write", self.authority.authenticate(renewed["access_token"]).capabilities)
        with self.assertRaises(ExpenseError):
            self.make_dispatcher().call(renewed["access_token"], "remember_teaching", self.arguments)

    def test_direct_service_default_and_read_grant_cannot_write_or_self_enable(self):
        pair = self.token({"memory:read"})
        service = self.resolver()(self.authority.authenticate(pair["access_token"]), "memory:read").service
        self.assertFalse(service.memory_write_enabled)
        with self.assertRaises(ExpenseError):
            service.call("remember_teaching", self.arguments)
        with self.assertRaises(ExpenseError):
            self.dispatcher.call(pair["access_token"], "remember_teaching", {**self.arguments, "memory_write_enabled": True})
        self.assertEqual(service.state.facts(), [])

    def test_profile_ceiling_and_current_revoked_or_expired_grant_deny_write(self):
        token = self.token()["access_token"]
        self.profile = self.make_profile(frozenset({"memory:read", "memory:propose"}))
        with self.assertRaises(ExpenseError):
            self.make_dispatcher().call(token, "remember_teaching", self.arguments)
        self.profile = self.make_profile()
        self.authority.revoke_consent("alice", "test")
        with self.assertRaises(ExpenseError):
            self.make_dispatcher().call(token, "remember_teaching", self.arguments)
        fresh = self.token()["access_token"]
        self.now += 901
        with self.assertRaises(ExpenseError):
            self.make_dispatcher().call(fresh, "remember_teaching", self.arguments)

    def test_delete_then_replay_after_restart_never_revives_and_other_person_is_separate(self):
        token = self.token()["access_token"]
        saved = self.dispatcher.call(token, "remember_teaching", self.arguments)
        gui = self.resolver().memory_service(self.people["alice"])
        entry = gui.state.memory_entries()[0]
        gui.state.delete_memory(saved["id"], entry["digest"])
        with self.assertRaises(ExpenseError):
            self.make_dispatcher().call(token, "remember_teaching", self.arguments)
        self.assertEqual(self.dispatcher.call(token, "expense_context", {})["teachings"], [])
        bob = self.token(who="bob")["access_token"]
        self.assertEqual(self.dispatcher.call(bob, "expense_context", {})["teachings"], [])
        separate = self.dispatcher.call(bob, "remember_teaching", self.arguments)
        self.assertNotEqual(separate["id"], saved["id"])

    def test_write_only_authorization_does_not_include_gui_approval_update_or_delete(self):
        self.profile = self.make_profile(frozenset({"memory:read", "memory:write"}))
        token = self.token({"memory:read", "memory:write"})["access_token"]
        dispatcher = self.make_dispatcher()
        self.assertIn("remember_teaching", dispatcher.available_operations(token))
        self.assertNotIn("propose_teaching", dispatcher.available_operations(token))
        gui = self.resolver().memory_service(self.people["alice"])
        self.assertFalse(gui.memory_write_enabled)
        for name in ("accept_fact", "confirm_memory", "update_memory", "delete_memory", "remember_fact"):
            with self.assertRaises(ExpenseError):
                dispatcher.call(token, name, {})

    def test_memory_read_write_profile_enables_gui_without_propose_or_financial_connection(self):
        metadata = {"enabled": True, "namespace": "test-memory", "financial_writes": False,
                    "capabilities": ["memory:read", "memory:write"], "policies": []}
        factory = prepare_business_profile(metadata, environ={BUSINESS_KEY_ENV: self.key.decode()}, allowed_people={"alice"})
        self.assertTrue(factory.supports_personal_memory)
        self.profile = factory(None, self.store)
        self.assertEqual(self.profile.supported_operations, {"expense_context", "remember_teaching"})
        self.resolver().memory_service(self.people["alice"])
        self.assertEqual(CAPABILITY_LABELS["memory:write"], "会話から必要な本人の設定・好み・保留事項を保存する（都度確認なし）")

    async def test_actual_http_mcp_catalog_and_remember_use_new_scope(self):
        token = self.token({"memory:read", "memory:write"})["access_token"]
        app = create_app(self.dispatcher, "expense.example.test")
        async with app.app.router.lifespan_context(app.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=self.authority.issuer,
                headers={"accept": "application/json, text/event-stream", "mcp-protocol-version": "2025-03-26",
                         "authorization": "Bearer " + token}) as client:
                catalog = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
                names = {tool["name"] for tool in catalog.json()["result"]["tools"]}
                self.assertIn("remember_teaching", names)
                self.assertNotIn("propose_teaching", names)
                for _ in range(2):
                    reply = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                              "params": {"name": "remember_teaching", "arguments": self.arguments}})
                    self.assertEqual(reply.status_code, 200, reply.text)
                    self.assertFalse(reply.json()["result"].get("isError"), reply.text)
        gui = self.resolver().memory_service(self.people["alice"])
        self.assertEqual(len(gui.state.active_facts()), 1)


if __name__ == "__main__":
    unittest.main()
