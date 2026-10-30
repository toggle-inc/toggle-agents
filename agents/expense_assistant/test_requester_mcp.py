"""Actual SDK HTTP/JSON-RPC path, synthetic token verifier and providers only."""

import asyncio
import dataclasses
import functools
import json
import sys
import tempfile
import unittest
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_runtime as expense_fixtures  # noqa: E402
from requester_mcp import create_app  # noqa: E402
from runtime.providers import Receipts  # noqa: E402
from runtime.requester import (  # noqa: E402
    OPERATIONS,
    ConnectionGrant,
    Requester,
    RequesterDispatcher,
)
from runtime.service import ExpenseService  # noqa: E402
from runtime.state import ExpenseError, State  # noqa: E402
from test_requester import SyntheticCalendar, SyntheticMF  # noqa: E402


def with_server(method):
    @functools.wraps(method)
    async def run(self):
        # AnyIO lifespan scopes must enter and leave on the SAME task.
        async with self.app.app.router.lifespan_context(self.app.app):
            return await method(self)

    return run


class RequesterMCPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.people, self.grants, self.tokens = {}, {}, {}
        self.now = 100
        for name in ("alice", "bob"):
            token = "synthetic-resource-token-only-" + name
            person = Requester("synthetic-tenant", name, 200)
            self.tokens[name], self.people[token] = token, person
            root = Path(self.temp.name) / person.owner
            service = ExpenseService(
                mf=SyntheticMF(person.owner, name),
                state=State(root / "state.sqlite", person.owner),
                receipts=Receipts(root / "receipts", None, person.owner),
                calendar=SyntheticCalendar(name),
                # This fixture grants every OPERATIONS capability, including
                # the new independent memory:write permission.
                memory_write_enabled=True,
            )
            self.addCleanup(service.state.close)
            self.grants[name] = ConnectionGrant(
                person.tenant_id,
                person.person_id,
                200,
                frozenset(OPERATIONS.values()) | {"receipt:read"},
                service,
                agent_slug="expense_assistant",
            )
        self.dispatcher = RequesterDispatcher(
            lambda token: self.people.get(token),
            lambda person, capability: self.grants.get(person.person_id),
            clock=lambda: self.now,
        )
        self.app = create_app(self.dispatcher, "expense.example.test")
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="https://expense.example.test"
        )
        self.addAsyncCleanup(self.client.aclose)
        self.headers = {
            "accept": "application/json, text/event-stream",
            "mcp-protocol-version": "2025-03-26",
        }

    async def rpc(self, person, method="tools/call", params=None):
        return await self.client.post(
            "/mcp",
            headers={**self.headers, "authorization": "Bearer " + self.tokens[person]},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params if params is not None else {"name": "mf_offices", "arguments": {}},
            },
        )

    @with_server
    async def test_real_http_tool_calls_use_only_each_requester(self):
        for name in self.tokens:
            reply = await self.rpc(name)
            self.assertEqual(reply.status_code, 200, reply.text)
            self.assertEqual(reply.headers["cache-control"], "no-store")
            result = reply.json()["result"]
            self.assertFalse(result.get("isError"), result)
            self.assertIn(name, json.dumps(result))
            self.assertNotIn("bob" if name == "alice" else "alice", json.dumps(result))

    def draft_service(self):
        """Synthetic providers behind the real HTTP boundary, never live MF."""
        grant = self.grants["alice"]
        service = grant.service
        service.mf = expense_fixtures.FakeMF()
        service.mf.owner = service.state.owner
        service.policy = expense_fixtures.FakePolicy()
        service.write_enabled = True
        self.grants["alice"] = dataclasses.replace(grant, capabilities=frozenset({"mf:draft"}))
        service.state.set_draft_consent(["office-a"], "synthetic-http-consent")
        return service

    async def tool_result(self, who, operation, arguments):
        reply = await self.rpc(who, params={"name": operation, "arguments": arguments})
        self.assertEqual(reply.status_code, 200, reply.text)
        result = reply.json()["result"]
        self.assertFalse(result.get("isError"), result)
        return result.get("structuredContent") or json.loads(result["content"][0]["text"])

    @with_server
    async def test_draft_only_http_save_returns_mf_link_once_and_never_crosses_person(self):
        service = self.draft_service()
        preview = await self.tool_result(
            "alice",
            "mf_create_transaction",
            {
                "office": "office-a",
                "recognized_at": "2020-01-15",
                "value": 321,
                "remark": "合成HTTPテスト",
                "memo": "駅A → 駅B（合成検証）",
                "ex_item_id": "item-a",
                "ex_item_name": "旅費交通費",
            },
        )
        arguments = {"preview_id": preview["preview_id"]}
        other = (
            await self.rpc("bob", params={"name": "mf_save_draft", "arguments": arguments})
        ).json()["result"]
        self.assertTrue(other.get("isError"))
        self.assertEqual(service.mf.writes, [])
        result = await self.tool_result("alice", "mf_save_draft", arguments)
        self.assertEqual(result["review_url"], "https://expense.moneyforward.com/transactions")
        self.assertEqual(result["draft_status"], "saved_unsubmitted")
        self.assertTrue(result["readback_verified"])
        self.assertFalse(result["submitted"])
        self.assertEqual(await self.tool_result("alice", "mf_save_draft", arguments), result)
        self.assertEqual(len(service.mf.writes), 1)
        service.state.set_draft_consent([], "synthetic-http-revoked", active=False)
        refused = (
            await self.rpc("alice", params={"name": "mf_save_draft", "arguments": arguments})
        ).json()["result"]
        self.assertTrue(refused.get("isError"))
        self.assertEqual(len(service.mf.writes), 1)

    @with_server
    async def test_draft_only_http_ocr_is_pending_not_completed_and_legacy_write_is_denied(self):
        service = self.draft_service()
        reference = service.receipts.save(b"%PDF-1.4\nsynthetic HTTP receipt", "application/pdf")[
            "path"
        ]
        arguments = {"office": "office-a", "receipt_path": reference}
        denied = (
            await self.rpc(
                "alice",
                params={
                    "name": "mf_upload_receipt",
                    "arguments": {**arguments, "confirm": True},
                },
            )
        ).json()["result"]
        self.assertTrue(denied.get("isError"))
        self.assertEqual(service.mf.writes, [])
        preview = await self.tool_result("alice", "mf_upload_receipt", arguments)
        result = await self.tool_result(
            "alice", "mf_save_draft", {"preview_id": preview["preview_id"]}
        )
        self.assertEqual(result["draft_status"], "ocr_processing")
        self.assertTrue(result["ocr_pending"])
        self.assertFalse(result["submitted"])
        self.assertEqual([row[0] for row in service.mf.writes], ["upload"])

    @with_server
    async def test_missing_invalid_duplicate_and_legacy_shared_bearers_are_unauthorized(self):
        good = "Bearer " + self.tokens["alice"]
        for headers in (
            [],
            [("authorization", "Bearer legacy-shared-key-not-a-person")],
            [("authorization", good), ("authorization", good)],
            [("authorization", "Basic synthetic")],
            [("authorization", "Bearer x y")],
        ):
            reply = await self.client.post("/mcp", headers=headers, json={})
            self.assertEqual(reply.status_code, 401)
            self.assertEqual(reply.headers["cache-control"], "no-store")
        self.assertEqual(self.grants["alice"].service.mf.calls, 0)

    @with_server
    async def test_initialize_and_catalog_expose_no_identity_selector(self):
        initialized = await self.rpc(
            "alice",
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "synthetic-engine-mcp-client", "version": "1"},
            },
        )
        self.assertIn("protocolVersion", initialized.json()["result"])
        catalog = (await self.rpc("alice", "tools/list", {})).json()["result"]["tools"]
        self.assertEqual({tool["name"] for tool in catalog}, set(OPERATIONS))
        for tool in catalog:
            properties = tool["inputSchema"].get("properties", {})
            self.assertTrue({"owner", "tenant_id", "person_id", "token"}.isdisjoint(properties))

    @with_server
    async def test_missing_personal_connection_is_safe_tool_error_without_fallback(self):
        del self.grants["bob"]
        result = (await self.rpc("bob")).json()["result"]
        self.assertTrue(result["isError"])
        self.assertIn("本人", json.dumps(result, ensure_ascii=False))
        self.assertEqual(self.grants["alice"].service.mf.calls, 0)

    @with_server
    async def test_revocation_and_expiry_apply_after_a_successful_call(self):
        self.assertEqual((await self.rpc("alice")).status_code, 200)
        self.grants["alice"] = dataclasses.replace(self.grants["alice"], revoked=True)
        self.assertTrue((await self.rpc("alice")).json()["result"]["isError"])
        del self.people[self.tokens["alice"]]
        self.assertEqual((await self.rpc("alice")).status_code, 401)
        self.now = 200
        self.assertEqual((await self.rpc("bob")).status_code, 401)

    @with_server
    async def test_receipt_resources_use_the_same_person_and_revocation_checks(self):
        receipt = self.grants["alice"].service.receipts.save(
            b"%PDF-1.4\nsynthetic-private-receipt", "application/pdf"
        )
        params = {"uri": receipt["resource_uri"]}
        alice = (await self.rpc("alice", "resources/read", params)).json()
        self.assertIn("contents", alice["result"], alice)
        bob = (await self.rpc("bob", "resources/read", params)).json()
        self.assertIn("error", bob)
        self.assertNotIn("synthetic-private-receipt", json.dumps(bob))
        self.grants["alice"] = dataclasses.replace(self.grants["alice"], revoked=True)
        self.assertIn("error", (await self.rpc("alice", "resources/read", params)).json())

    @with_server
    async def test_concurrent_http_requests_never_share_actor(self):
        names = ["alice", "bob"] * 8
        replies = await asyncio.gather(*(self.rpc(name) for name in names))
        for name, reply in zip(names, replies):
            result = reply.json()["result"]
            self.assertFalse(result.get("isError"), result)
            self.assertIn(name, json.dumps(result))
            self.assertNotIn("bob" if name == "alice" else "alice", json.dumps(result))
        self.assertIsNone(self.app.context.get())

    @with_server
    async def test_host_origin_and_missing_request_context_fail_closed(self):
        reply = await self.client.post(
            "/mcp",
            headers={
                "authorization": "Bearer " + self.tokens["alice"],
                "host": "attacker.example.test",
            },
            json={},
        )
        self.assertIn(reply.status_code, (400, 421))
        bad_origin = await self.client.post(
            "/mcp",
            headers={
                "authorization": "Bearer " + self.tokens["alice"],
                "origin": "https://attacker.example.test",
            },
            json={},
        )
        self.assertEqual(bad_origin.status_code, 403)
        with self.assertRaises(ExpenseError):
            create_app(self.dispatcher, "*.example.test")
        with self.assertRaises(ExpenseError):
            self.dispatcher.call(None, "mf_offices", {})


class ReadOnlyCatalogTests(unittest.IsolatedAsyncioTestCase):
    rpc = RequesterMCPTests.rpc

    async def asyncSetUp(self):
        from types import SimpleNamespace
        from runtime.provider_execution import ProviderExecutionResolver
        from test_authorization import MemoryStore
        from test_provider_execution import FakeProvider

        self.now = 100
        self.tokens = {name: "synthetic-read-token-" + name for name in ("alice", "bob")}
        self.people = {self.tokens[name]: Requester(
            "synthetic-tenant", name, 200, capabilities=frozenset({"mf:read"})
        ) for name in self.tokens}
        self.providers = SimpleNamespace(mf=FakeProvider(), calendar=FakeProvider())
        self.providers.mf.states = {p.owner: "connected" for p in self.people.values()}
        self.resolver = ProviderExecutionResolver(
            self.providers, MemoryStore(), "synthetic", lambda: self.now,
            tenant_id="synthetic-tenant",
        )
        self.dispatcher = RequesterDispatcher(self.people.get, self.resolver, clock=lambda: self.now)
        self.app = create_app(self.dispatcher, "expense.example.test")
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="https://expense.example.test"
        )
        self.addAsyncCleanup(self.client.aclose)
        self.headers = {"accept": "application/json, text/event-stream",
                        "mcp-protocol-version": "2025-03-26"}

    async def catalog(self, name="alice"):
        response = await self.rpc(name, "tools/list", {})
        self.assertEqual(response.status_code, 200, response.text)
        return {t["name"] for t in response.json()["result"]["tools"]}

    @with_server
    async def test_mf_only_catalog_then_offices_never_requests_other_capabilities(self):
        self.assertEqual(await self.catalog(), {
            "mf_offices", "mf_list_transactions", "mf_list_reports",
        })
        for name in ("alice", "bob"):
            result = (await self.rpc(name)).json()["result"]
            self.assertFalse(result.get("isError"), result)
            self.assertIn(name, json.dumps(result))
            self.assertNotIn("bob" if name == "alice" else "alice", json.dumps(result))
        self.assertEqual(self.providers.calendar.status_calls, [])
        templates = (await self.rpc("alice", "resources/templates/list", {})).json()
        self.assertEqual(templates["result"]["resourceTemplates"], [])

    @with_server
    async def test_hidden_memory_state_receipts_and_writes_are_unavailable_without_reconsent(self):
        for operation, args in (
            ("expense_context", {}), ("mf_known_items", {"office": "alice"}),
            ("mf_payee_memory", {}),
            ("mf_get_receipt", {"office": "alice", "transaction_id": "synthetic"}),
            ("mf_save_draft", {"preview_id": "synthetic"}),
            ("mf_create_transaction", {"office": "alice", "recognized_at": "2030-01-01",
                                       "value": 100, "remark": "synthetic"}),
        ):
            result = (await self.rpc("alice", params={"name": operation, "arguments": args})).json()["result"]
            self.assertTrue(result.get("isError"), result)
            self.assertIn("operation_unavailable", json.dumps(result))
            self.assertNotIn("requester_authorization_required", json.dumps(result))
        self.assertEqual(self.providers.mf.status_calls, [])
        self.assertFalse((await self.rpc("alice")).json()["result"].get("isError"))

    @with_server
    async def test_catalog_and_calls_recheck_scope_provider_revocation_and_tenant(self):
        self.assertIn("mf_offices", await self.catalog())
        person = self.people[self.tokens["alice"]]
        self.providers.mf.states[person.owner] = "revoked"
        self.assertEqual(await self.catalog(), set())
        self.assertTrue((await self.rpc("alice")).json()["result"].get("isError"))
        self.assertIn("mf_offices", await self.catalog("bob"))
        self.providers.mf.states[person.owner] = "connected"
        self.people[self.tokens["alice"]] = dataclasses.replace(person, capabilities=frozenset())
        self.assertEqual(await self.catalog(), set())
        self.assertTrue((await self.rpc("alice")).json()["result"].get("isError"))
        self.people[self.tokens["alice"]] = dataclasses.replace(person, tenant_id="other")
        self.assertEqual(await self.catalog(), set())
        self.assertTrue((await self.rpc("alice")).json()["result"].get("isError"))
        del self.people[self.tokens["alice"]]
        self.assertEqual((await self.rpc("alice", "tools/list", {})).status_code, 401)

    async def test_local_stdio_catalog_retains_all_tools_and_receipt_templates(self):
        from mcp_server import create_server
        server = create_server(self.resolver(self.people[self.tokens["alice"]], "mf:read").service)
        self.assertEqual({tool.name for tool in await server.list_tools()}, set(OPERATIONS))
        self.assertEqual(len(await server.list_resource_templates()), 4)


if __name__ == "__main__":
    unittest.main()
