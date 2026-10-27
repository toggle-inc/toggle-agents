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


if __name__ == "__main__":
    unittest.main()
