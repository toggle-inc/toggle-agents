"""Actual SDK HTTP with synthetic trusted identity/source verification only."""

import asyncio
import hashlib
from contextvars import ContextVar
from dataclasses import replace
import json
import unittest

import httpx

from _foundation.conversation import ContextError
from _foundation.history_runtime import create_conversation_runtime
from _foundation.history_sources import SuccessAssistHistory, bind_invocation
from _foundation.test_history_sources import SAAPI, event
from requester_mcp import RequestAuthorization, create_app
from runtime.history_request import HistoryRequestBinding
from runtime.state import ExpenseError
import test_requester_mcp as requester_fixtures

with_server = requester_fixtures.with_server


class HistoryHTTPTests(unittest.IsolatedAsyncioTestCase):
    rpc = requester_fixtures.ReadOnlyCatalogTests.rpc

    async def asyncSetUp(self):
        await requester_fixtures.ReadOnlyCatalogTests.asyncSetUp(self)
        await self.client.aclose()
        self.apis = {name: SAAPI() for name in self.tokens}
        for name, api in self.apis.items():
            for row in api.rows:
                row["authorId"] = name
                row["message"] += " synthetic-marker-" + name

        apis = self.apis

        class SourceTransport:
            def get(self, invocation, path, query):
                if invocation.requester not in apis:
                    raise ContextError("access_denied")
                return apis[invocation.requester].get(invocation, path, query)

        source = SuccessAssistHistory(SourceTransport(), ("agent-bot",))
        self.bindings = {}
        for name in self.tokens:
            invocation = bind_invocation(
                source, clock=lambda: self.now,
                **{**event(), "requester": name, "execution": "run-" + name},
            )
            self.bindings[name] = HistoryRequestBinding("synthetic-tenant", name, invocation)
        for api in self.apis.values():
            api.calls.clear()
        self.runtime = create_conversation_runtime(
            enabled=True, sources_factory=lambda: {"success_assist": source},
            clock=lambda: self.now,
        )
        self.resolver_calls = []

        def trusted_resolver(scope, person):
            # Synthetic stand-in for verified execution proof/account-link
            # resolution. Production does not authenticate via these test IDs.
            self.resolver_calls.append(person.person_id)
            return self.bindings[person.person_id]

        self.app = create_app(
            self.dispatcher, "expense.example.test",
            history_runtime=self.runtime, history_resolver=trusted_resolver,
        )
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="https://expense.example.test"
        )
        self.addAsyncCleanup(self.client.aclose)

    async def history(self, person):
        return await self.rpc(person, params={"name": "read_conversation_context", "arguments": {}})

    @with_server
    async def test_http_catalog_and_prior_turns_are_bound_to_the_authenticated_person(self):
        catalog = (await self.rpc("alice", "tools/list", {})).json()["result"]["tools"]
        names = {tool["name"] for tool in catalog}
        self.assertEqual(names, {"mf_offices", "mf_list_transactions", "mf_list_reports",
                                 "read_conversation_context"})
        provider_checks = list(self.providers.mf.status_calls)
        for name in self.tokens:
            response = await self.history(name)
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()["result"]
            self.assertFalse(result.get("isError"), result)
            self.assertIn("synthetic-marker-" + name, json.dumps(result))
            self.assertNotIn("synthetic-marker-" + ("bob" if name == "alice" else "alice"),
                             json.dumps(result))
            self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(self.runtime.read()["status"], "unavailable")
        self.assertEqual(self.providers.mf.status_calls, provider_checks)

    @with_server
    async def test_cross_person_missing_malformed_and_expired_bindings_fail_before_io(self):
        valid = self.bindings["alice"]
        for binding in (
            self.bindings["bob"], None, {"requester": "alice"},
            replace(valid, tenant_id="another-tenant"),
            replace(valid, invocation=replace(valid.invocation, expires_at=201)),
            replace(valid, invocation=replace(valid.invocation, expires_at=100)),
        ):
            with self.subTest(binding_type=type(binding).__name__):
                self.bindings["alice"] = binding
                reply = await self.history("alice")
                self.assertEqual(reply.status_code, 401)
                self.assertEqual(reply.text, "Unauthorized")
                self.assertEqual(reply.headers["cache-control"], "no-store")
                self.assertTrue(all(not api.calls for api in self.apis.values()))
                self.assertEqual(self.runtime.read()["status"], "unavailable")
        self.bindings["alice"] = valid
        self.assertEqual((await self.history("alice")).status_code, 200)

    @with_server
    async def test_invalid_resource_auth_never_calls_history_resolver(self):
        self.people.pop(self.tokens["alice"])
        self.assertEqual((await self.history("alice")).status_code, 401)
        self.assertEqual(self.resolver_calls, [])
        self.assertTrue(all(not api.calls for api in self.apis.values()))

    @with_server
    async def test_concurrent_http_history_does_not_cross_people_or_leave_context(self):
        people = ["alice", "bob"] * 4
        replies = await asyncio.gather(*(self.history(name) for name in people))
        for name, reply in zip(people, replies):
            self.assertEqual(reply.status_code, 200, reply.text)
            data = json.dumps(reply.json())
            self.assertIn("synthetic-marker-" + name, data)
            self.assertNotIn("synthetic-marker-" + ("bob" if name == "alice" else "alice"), data)
        self.assertEqual(self.runtime.read()["status"], "unavailable")
        self.assertIsNone(self.app.context.get())

    @with_server
    async def test_revoked_source_and_edited_anchor_cannot_return_cached_context(self):
        self.assertIn("synthetic-marker-alice", (await self.history("alice")).text)
        self.apis["alice"].denied = True
        denied = (await self.history("alice")).text
        self.assertNotIn("synthetic-marker-alice", denied)
        self.assertIn("unavailable", denied)
        self.apis["alice"].denied = False
        self.apis["alice"].rows[-1]["message"] = "edited anchor"
        self.assertNotIn("synthetic-marker-alice", (await self.history("alice")).text)

    def test_partial_or_untrusted_opt_in_is_rejected_without_changing_default(self):
        for options in (
            {"history_runtime": self.runtime},
            {"history_resolver": lambda *_: None},
            {"history_runtime": object(), "history_resolver": lambda *_: None},
        ):
            with self.assertRaises(ExpenseError):
                create_app(self.dispatcher, "expense.example.test", **options)
        legacy = create_app(self.dispatcher, "expense.example.test")
        self.assertIsNone(legacy.history_runtime)
        self.assertIsNone(legacy.history_resolver)

    async def test_downstream_exception_resets_resource_and_history_context(self):
        context = ContextVar("synthetic-resource-context", default=None)

        async def explode(scope, receive, send):
            self.assertEqual(self.runtime.read()["status"], "available")
            self.assertEqual(context.get(), self.tokens["alice"])
            raise RuntimeError("synthetic execution failure")

        middleware = RequestAuthorization(
            explode, self.dispatcher, context, history_runtime=self.runtime,
            history_resolver=lambda scope, person: self.bindings[person.person_id],
            history_target="https://expense.example.test/mcp",
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=middleware), base_url="https://expense.example.test"
        ) as client:
            with self.assertRaisesRegex(RuntimeError, "synthetic execution failure"):
                await client.post("/mcp", headers={"authorization": "Bearer " + self.tokens["alice"]})
        self.assertIsNone(context.get())
        self.assertEqual(self.runtime.read()["status"], "unavailable")

    @with_server
    async def test_transport_computes_exact_body_and_fixed_target_not_headers(self):
        seen = []

        def resolve(scope, person):
            seen.append(scope["agent_execution_request"])
            return self.bindings[person.person_id]

        self.app.history_resolver = resolve
        body = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
        reply = await self.client.post(
            "/mcp", content=body,
            headers={**self.headers, "content-type": "application/json",
                     "authorization": "Bearer " + self.tokens["alice"],
                     "x-forwarded-host": "evil.example.test"},
        )
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].target, "https://expense.example.test/mcp")
        self.assertEqual(seen[0].method, "POST")
        self.assertEqual(seen[0].body_sha256, hashlib.sha256(body).hexdigest())

    @with_server
    async def test_oversized_or_noncanonical_request_stops_before_proof_and_source(self):
        for path, body in (("/mcp", b"x" * 262145), ("/mcp?redirect=1", b"{}"),
                           ("/other", b"{}"), ("/%6dcp", b"{}")):
            reply = await self.client.post(
                path, content=body,
                headers={**self.headers, "authorization": "Bearer " + self.tokens["alice"]},
            )
            self.assertEqual(reply.status_code, 401)
        self.assertEqual(self.resolver_calls, [])
        self.assertTrue(all(not api.calls for api in self.apis.values()))

    @with_server
    async def test_chunked_body_is_replayed_to_sdk_and_bound_to_its_actual_bytes(self):
        body = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
        seen = []

        def resolve(scope, person):
            seen.append(scope["agent_execution_request"].body_sha256)
            return self.bindings[person.person_id]

        self.app.history_resolver = resolve

        async def chunks():
            yield body[:15]
            yield body[15:]

        reply = await self.client.post(
            "/mcp", content=chunks(),
            headers={**self.headers, "content-type": "application/json",
                     "authorization": "Bearer " + self.tokens["alice"]},
        )
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertEqual(seen, [hashlib.sha256(body).hexdigest()])
