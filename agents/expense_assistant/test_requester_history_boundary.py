"""Two real stateless SDK servers; synthetic OAuth, proofs and sources only."""

import asyncio
from contextlib import asynccontextmanager
import json
import unittest

import httpx

from requester_mcp import create_app
from runtime.state import ExpenseError
import test_history_requester_mcp as history_fixtures
import test_requester_mcp as http_fixtures
import test_signed_history_http as signed_fixtures


class HistoryBoundaryMigrationTests(unittest.IsolatedAsyncioTestCase):
    rpc = http_fixtures.ReadOnlyCatalogTests.rpc

    async def asyncSetUp(self):
        await history_fixtures.HistoryHTTPTests.asyncSetUp(self)
        await self.client.aclose()
        original = self.app
        self.app = create_app(
            self.dispatcher, "expense.example.test", history_runtime=self.runtime,
            history_resolver=original.history_resolver, history_boundary_migration=True,
        )
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="https://expense.example.test"
        )
        self.addAsyncCleanup(self.client.aclose)

    async def strict_rpc(self, person, method="tools/call", params=None):
        # A synthetic trusted resolver is used by this fixture. Real RSA and
        # malformed-header rejection are covered by SignedBoundaryTests below.
        return await self.client.post(
            "/mcp", headers={**self.headers,
                "authorization": "Bearer " + self.tokens[person],
                "X-Agent-Source-Context": "synthetic-source",
                "X-Agent-Execution-Proof": "synthetic-execution"},
            json={"jsonrpc": "2.0", "id": 1, "method": method,
                  "params": params if params is not None else {
                      "name": "read_conversation_context", "arguments": {}}},
        )

    @http_fixtures.with_server
    async def test_separate_catalogs_and_no_legacy_history_or_resource_exposure(self):
        self.assertIsNot(self.app.legacy.app, self.app.strict.app)
        self.assertIsNot(self.app.legacy.context, self.app.strict.context)
        self.assertIsNone(self.app.legacy.history_runtime)
        self.assertIsNone(self.app.legacy.history_resolver)
        legacy = (await self.rpc("alice", "tools/list", {})).json()["result"]["tools"]
        self.assertEqual({t["name"] for t in legacy}, {
            "mf_offices", "mf_list_transactions", "mf_list_reports"})
        strict = (await self.strict_rpc("alice", "tools/list", {})).json()["result"]["tools"]
        self.assertEqual({t["name"] for t in strict},
                         {t["name"] for t in legacy} | {"read_conversation_context"})
        self.resolver_calls.clear()
        for method, params in (
            ("tools/call", {"name": "read_conversation_context", "arguments": {}}),
            ("resources/list", {}), ("resources/templates/list", {}),
            ("resources/read", {"uri": "history://synthetic"}),
        ):
            reply = await self.rpc("alice", method, params)
            self.assertNotIn("synthetic-marker", reply.text)
            data = reply.json()
            if method in {"resources/list", "resources/templates/list"}:
                self.assertEqual(next(iter(data["result"].values())), [])
            else:
                self.assertTrue("error" in data or data["result"].get("isError"), data)
        self.assertEqual(self.resolver_calls, [])
        self.assertTrue(all(not api.calls for api in self.apis.values()))

    @http_fixtures.with_server
    async def test_initialize_and_normal_oauth_tools_work_on_both_servers(self):
        params = {"protocolVersion": "2025-03-26", "capabilities": {},
                  "clientInfo": {"name": "synthetic-migration", "version": "1"}}
        for rpc in (self.rpc, self.strict_rpc):
            reply = await rpc("alice", "initialize", params)
            self.assertIn("protocolVersion", reply.json()["result"])
            self.assertNotIn("mcp-session-id", reply.headers)
            reply = await rpc("alice", params={"name": "mf_offices", "arguments": {}})
            self.assertFalse(reply.json()["result"].get("isError"), reply.text)
        self.assertIsNone(self.app.legacy.context.get())
        self.assertIsNone(self.app.strict.context.get())

    @http_fixtures.with_server
    async def test_concurrent_strict_people_and_legacy_requests_do_not_mix(self):
        requests = [(person, strict) for _ in range(3)
                    for person in self.tokens for strict in (True, False)]
        replies = await asyncio.gather(*(
            self.strict_rpc(person) if strict else self.rpc(person)
            for person, strict in requests
        ))
        for (person, strict), reply in zip(requests, replies):
            self.assertEqual(reply.status_code, 200, reply.text)
            self.assertFalse(reply.json()["result"].get("isError"), reply.text)
            if strict:
                self.assertIn("synthetic-marker-" + person, reply.text)
                self.assertNotIn("synthetic-marker-" + ("bob" if person == "alice" else "alice"),
                                 reply.text)
            else:
                self.assertNotIn("synthetic-marker", reply.text)
            self.assertEqual(reply.headers["cache-control"], "no-store")
        self.assertEqual(self.runtime.read()["status"], "unavailable")
        self.assertIsNone(self.app.legacy.context.get())
        self.assertIsNone(self.app.strict.context.get())

    @http_fixtures.with_server
    async def test_oauth_revocation_is_enforced_on_both_boundaries_before_resolver(self):
        self.people.pop(self.tokens["alice"])
        for rpc in (self.rpc, self.strict_rpc):
            self.assertEqual((await rpc("alice")).status_code, 401)
        self.assertEqual(self.resolver_calls, [])
        self.assertTrue(all(not api.calls for api in self.apis.values()))

    @http_fixtures.with_server
    async def test_strict_downstream_exception_resets_both_contexts(self):
        transport = self.app.strict.app

        async def explode(scope, receive, send):
            self.assertIsNone(self.app.legacy.context.get())
            self.assertEqual(self.app.strict.context.get(), self.tokens["alice"])
            self.assertEqual(self.runtime.read()["status"], "available")
            raise RuntimeError("synthetic downstream failure")

        self.app.strict.app = explode
        try:
            with self.assertRaisesRegex(RuntimeError, "synthetic downstream failure"):
                await self.strict_rpc("alice")
        finally:
            self.app.strict.app = transport
        self.assertIsNone(self.app.strict.context.get())
        self.assertEqual(self.runtime.read()["status"], "unavailable")
        self.assertEqual((await self.rpc("alice")).status_code, 200)

    async def test_native_asgi_lifespan_starts_and_stops_both_servers(self):
        incoming, outgoing = asyncio.Queue(), asyncio.Queue()
        task = asyncio.create_task(self.app(
            {"type": "lifespan", "asgi": {"version": "3.0", "spec_version": "2.0"},
             "state": {}}, incoming.get, outgoing.put,
        ))
        try:
            await incoming.put({"type": "lifespan.startup"})
            self.assertEqual((await asyncio.wait_for(outgoing.get(), 5))["type"],
                             "lifespan.startup.complete")
            self.assertEqual((await self.rpc("alice", "tools/list", {})).status_code, 200)
            self.assertEqual((await self.strict_rpc("bob")).status_code, 200)
        finally:
            await incoming.put({"type": "lifespan.shutdown"})
            try:
                self.assertEqual((await asyncio.wait_for(outgoing.get(), 5))["type"],
                                 "lifespan.shutdown.complete")
            finally:
                await asyncio.wait_for(task, 5)

    async def test_lifespan_startup_failure_unwinds_the_first_server(self):
        events = []

        @asynccontextmanager
        async def legacy(app):
            events.append("legacy-start")
            try:
                yield
            finally:
                events.append("legacy-stop")

        @asynccontextmanager
        async def strict(app):
            events.append("strict-start")
            raise RuntimeError("synthetic startup failure")
            yield

        self.app.legacy.app.router.lifespan_context = legacy
        self.app.strict.app.router.lifespan_context = strict
        with self.assertRaisesRegex(RuntimeError, "synthetic startup failure"):
            async with self.app.app.router.lifespan_context(self.app.app):
                self.fail("startup must fail closed")
        self.assertEqual(events, ["legacy-start", "strict-start", "legacy-stop"])

    def test_migration_is_explicit_and_disabled_history_keeps_legacy_shape(self):
        strict = create_app(self.dispatcher, "expense.example.test",
                            history_runtime=self.runtime,
                            history_resolver=self.app.strict.history_resolver)
        self.assertIs(strict.history_runtime, self.runtime)
        disabled = create_app(self.dispatcher, "expense.example.test",
                              history_boundary_migration=True)
        self.assertIsNone(disabled.history_runtime)
        self.assertFalse(hasattr(disabled, "strict"))
        with self.assertRaises(ExpenseError):
            create_app(self.dispatcher, "expense.example.test", history_boundary_migration="true")


class SignedBoundaryTests(unittest.IsolatedAsyncioTestCase):
    signed = signed_fixtures.SignedHistoryHTTPTests.signed

    @classmethod
    def setUpClass(cls):
        signed_fixtures.SignedHistoryHTTPTests.setUpClass()

    async def asyncSetUp(self):
        await signed_fixtures.SignedHistoryHTTPTests.asyncSetUp(self)
        await self.client.aclose()
        self.app = create_app(
            self.dispatcher, "agent.example.test", history_runtime=self.history,
            history_resolver=self.app.history_resolver, history_boundary_migration=True,
        )
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="https://agent.example.test"
        )
        self.addAsyncCleanup(self.client.aclose)

    @http_fixtures.with_server
    async def test_valid_proofs_read_history_and_replay_never_falls_back(self):
        body, headers = self.signed()
        response = await self.client.post("/mcp", content=body, headers=headers)
        result = response.json()["result"]
        content = result.get("structuredContent") or json.loads(result["content"][0]["text"])
        self.assertEqual(content["status"], "available")
        self.assertIn("ブルーバード", response.text)
        self.api.calls.clear()
        self.source_checks.clear()
        response = await self.client.post("/mcp", content=body, headers=headers)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.source_checks, [])

    @http_fixtures.with_server
    async def test_any_header_presence_empty_partial_duplicate_or_invalid_is_strict_only(self):
        body, valid = self.signed()
        base = [(k, v) for k, v in valid if not k.lower().startswith("x-agent-")]
        source, proof = valid[:2]
        cases = [[source], [proof], [("X-AGENT-SOURCE-CONTEXT", "")],
                 [("X-Agent-Execution-Proof", "")], [source, source, proof],
                 [source, proof, proof], [source, (proof[0], "bad-proof")],
                 [(source[0], "bad-source"), proof]]
        for supplied in cases:
            with self.subTest(headers=[k for k, _ in supplied]):
                response = await self.client.post("/mcp", content=body, headers=base + supplied)
                self.assertEqual(response.status_code, 401, response.text)
                self.assertEqual(response.text, "Unauthorized")
                self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.source_checks, [])

    @http_fixtures.with_server
    async def test_tampered_expired_and_wrong_binding_proofs_do_not_fall_back(self):
        for changes in ({"exp": self.proofs.now}, {"session_id": "another-session"},
                        {"target_version_id": "another-version"}, {"connection_id": "other"}):
            body, headers = self.signed(proof_changes=changes)
            response = await self.client.post("/mcp", content=body, headers=headers)
            self.assertEqual(response.status_code, 401, response.text)
        body, headers = self.signed()
        self.assertEqual((await self.client.post("/mcp", content=body + b" ",
                                               headers=headers)).status_code, 401)
        # A correctly signed but unbound session may reach the source authority,
        # which must reject it; no history snapshot can be read.
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.history.read()["status"], "unavailable")
