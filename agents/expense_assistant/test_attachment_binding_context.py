"""Request-local attachment authority: real proofs, MockASGI/MockTransport only."""

import asyncio
from contextvars import ContextVar, copy_context
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest
from urllib.parse import quote

import httpx
import jwt

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _foundation.execution_binding import ExecutionRequest, ExternalExecutionVerifier
from _foundation.history_runtime import create_conversation_runtime
from _foundation.platform_identity import PlatformPersonLink
from requester_mcp import RequestAuthorization, create_app
from runtime.external_history_resolver import ExternalHistoryResolver
from runtime.history_request import HistoryRequestBinding, HistoryRequestContext
from runtime.requester import RequesterDispatcher
from runtime.sa_attachment_client import SAAttachmentClient, MANIFEST_PATH, ATTACHMENT_PATH
from runtime.state import ExpenseError
import test_external_history_resolver as proof_fixtures
import test_sa_attachment_client as attachment_fixtures


class AttachmentBindingContextTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        attachment_fixtures.SAAttachmentClientTests.setUpClass()
        proof_fixtures.ExternalHistoryResolverTests.setUpClass()

    async def asyncSetUp(self):
        self.fixture = attachment_fixtures.SAAttachmentClientTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.history = self.fixture.history
        self.proofs = proof_fixtures.ExternalHistoryResolverTests()
        self.proofs.setUp()
        self.proofs.target = self.fixture.reference.target
        self.people = {
            "alice": self.fixture.person,
            "bob": replace(self.fixture.person, person_id="canonical-bob"),
        }
        self.tokens = {"synthetic-" + name: person for name, person in self.people.items()}
        self.links = {}
        for name, person in self.people.items():
            self.links[("https://sa.example.test", "source-tenant", "source-" + name)] = PlatformPersonLink(
                person.tenant_id, person.person_id)
            self.links[("https://identity.example.test", "engine-tenant", "engine-" + name)] = PlatformPersonLink(
                person.tenant_id, person.person_id)
        self.verifier = ExternalExecutionVerifier(
            self.proofs.store, lambda *actor: self.links.get(actor),
            source_issuer="https://sa.example.test",
            source_keys={"source": self.proofs.public(self.proofs.source_key)},
            execution_issuer="https://runtime.example.test",
            execution_keys={"runtime": self.proofs.public(self.proofs.execution_key)},
            audience="https://agent.example.test", targets={self.proofs.target}, clock=lambda: self.history.now,
        )
        self.proofs.verifier = self.verifier
        self.sources = {"source-alice": self.history.client}
        bob_server = type(self.history.server)(self.fixture.public)
        bob_server.anchor["authorId"] = "source-bob"
        self.anchor_revisions = {
            "alice": self.fixture.reference.anchor_revision,
            "bob": attachment_fixtures.history_fixtures.revision(bob_server.anchor),
        }
        bob_http = httpx.Client(transport=httpx.MockTransport(bob_server))
        self.sources["source-bob"] = self.history.make_client(bob_server, bob_http, actor="source-bob")
        self.addCleanup(self.sources["source-bob"].close)
        self.resolved = []

        def resolve_source(ref):
            self.assertIsNone(self.resolver.current(), "verification must run without inherited authority")
            resolved = self.sources[ref.source_actor].resolve_source(ref)
            self.resolved.append(resolved)
            return resolved

        self.resolver = ExternalHistoryResolver(
            self.verifier, resolve_source, agent_slug="expense_assistant", source_platform="success_assist")
        self.runtime = create_conversation_runtime(enabled=True,
            sources_factory=lambda: {"success_assist": self.history.client}, clock=lambda: self.history.now)
        self.dispatcher = RequesterDispatcher(self.tokens.get, lambda *_: None, clock=lambda: self.history.now)
        self.clients, self.c_calls, self.c_jtis = {}, [], set()
        for name, person in self.people.items():
            client = SAAttachmentClient(
                origin="https://sa.example.test", agent_origin="https://agent.example.test",
                source_namespace="source-tenant", source_actor="source-" + name, target=self.proofs.target,
                kid="read-key", signing_private_key=self.fixture.private, owner=person.owner,
                resolve_binding=self.resolver.current,
                http=httpx.Client(transport=httpx.MockTransport(self.attachment_response)),
                clock=lambda: self.history.now,
            )
            self.clients[name] = client
            self.addCleanup(client.close)
        self.seen, self.copied, self.child_tasks = [], [], []
        self.pause, self.entered, self.release = False, asyncio.Queue(), asyncio.Event()
        self.fail_downstream, self.cancel = False, False
        self.context = ContextVar("synthetic-resource-bearer", default=None)
        self.app = RequestAuthorization(self.downstream, self.dispatcher, self.context,
            history_runtime=self.runtime, history_resolver=self.resolver,
            history_target="https://agent.example.test/mcp")
        self.http = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="https://agent.example.test")
        self.addAsyncCleanup(self.http.aclose)

    def attachment_response(self, request):
        binding = self.resolver.current()
        self.assertIsNotNone(binding)
        ref = binding.invocation.reference
        claims = jwt.decode(request.headers["x-agent-source-read-proof"], self.fixture.public,
            algorithms=["RS256"], issuer="https://agent.example.test", audience="https://sa.example.test",
            options={"verify_exp": False, "verify_iat": False})
        body = json.loads(request.content)
        self.assertEqual(claims["body_sha256"], hashlib.sha256(request.content).hexdigest())
        self.assertEqual(claims["target"], str(request.url))
        self.assertEqual(claims["source_actor"], ref.source_actor)
        self.assertEqual((body["source_handle"], body["invocation_id"], body["session_id"]),
                         (ref.source_handle, ref.invocation_id, ref.session_id))
        self.assertNotIn(claims["jti"], self.c_jtis)
        self.c_jtis.add(claims["jti"])
        self.c_calls.append((binding, request.url.path))
        content = ("%PDF-1.4\n" + binding.person_id + ":" + ref.invocation_id + ":" + ref.session_id).encode()
        item = {"id": "file-a", "filename": "synthetic.pdf", "contentType": "application/pdf", "size": len(content)}
        if request.url.path == MANIFEST_PATH:
            self.assertEqual(claims["purpose"], "source_attachment_manifest")
            self.assertEqual(set(body), {"source_handle", "invocation_id", "session_id"})
            return httpx.Response(200, json={
                "schemaVersion": "source-attachment-manifest/v1", "invocationId": ref.invocation_id,
                "sourceMessageId": binding.invocation.anchor, "attachments": [item],
                "manifestSha256": hashlib.sha256(attachment_fixtures.encoded([item])).hexdigest(),
                "expiresAt": claims["exp"] * 1000,
            }, headers={"cache-control": "no-store"})
        self.assertEqual(request.url.path, ATTACHMENT_PATH)
        self.assertEqual(claims["purpose"], "source_attachment_read")
        self.assertEqual(body["attachment_id"], "file-a")
        return httpx.Response(200, content=content, headers={
            "content-type": "application/octet-stream", "cache-control": "no-store",
            "content-length": str(len(content)), "x-attachment-id": "file-a",
            "x-attachment-filename": quote(item["filename"], safe="~()*!.'-_"),
            "x-attachment-content-type": item["contentType"], "x-attachment-sha256": hashlib.sha256(content).hexdigest(),
        })

    async def downstream(self, scope, receive, send):
        binding = self.resolver.current()
        self.assertIsNotNone(binding)
        self.assertIs(self.runtime._current.get(), binding.invocation)
        self.assertIs(self.resolved[-1].reference, binding.invocation.reference)
        self.seen.append(binding)
        self.copied.append(copy_context())
        if self.pause:
            await self.entered.put(binding)
            await self.release.wait()
        if self.fail_downstream:
            raise RuntimeError("synthetic downstream failure")
        if self.cancel:
            raise asyncio.CancelledError()
        name = "bob" if binding.person_id == self.people["bob"].person_id else "alice"
        content, mime = await asyncio.to_thread(self.clients[name].get, "attachment:file-a")
        self.assertIs(self.resolver.current(), binding)
        self.assertEqual(mime, "application/pdf")
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": content})

    def signed(self, name="alice", *, run="a", invalid=False):
        body = attachment_fixtures.encoded({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "synthetic_attachment", "arguments": {"ref": "attachment:file-a"}}})
        self.proofs.request = ExecutionRequest("POST", "https://agent.example.test/mcp", hashlib.sha256(body).hexdigest())
        second = name == "bob" or run != "a"
        scope = self.proofs.scope(source_changes={
            "source_namespace": "source-tenant", "source_actor": "source-" + name,
            "source_handle": ("q" if second else "h") * 43,
            "anchor_revision": self.anchor_revisions[name],
            "invocation_id": "invocation-" + run,
        }, proof_changes={"actor_subject": "engine-" + name, "session_id": "43" if second else "42",
                          "invocation_id": "invocation-" + run})
        headers = [(k.decode(), v.decode()) for k, v in scope["headers"]]
        if invalid:
            headers[1] = (headers[1][0], "invalid-proof")
        headers.append(("authorization", "Bearer synthetic-" + name))
        return body, headers

    async def request(self, name="alice", **options):
        body, headers = self.signed(name, **options)
        return await self.http.post("/mcp", content=body, headers=headers)

    def assert_cleared(self):
        self.assertIsNone(self.resolver.current())
        self.assertIsNone(self.context.get())
        self.assertIsNone(self.runtime._current.get())
        for copied in self.copied:
            self.assertIsNone(copied.run(self.resolver.current))
            with self.assertRaises(ExpenseError):
                copied.run(self.clients["alice"].get, "attachment:file-a")

    async def test_strict_success_feeds_both_c_requests_the_same_verified_binding_then_revokes(self):
        self.assertIsNone(self.resolver.current())
        response = await self.request()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("canonical-alice:invocation-a:42", response.text)
        self.assertEqual([path for _, path in self.c_calls], [MANIFEST_PATH, ATTACHMENT_PATH])
        self.assertTrue(all(binding is self.seen[0] for binding, _ in self.c_calls))
        self.assert_cleared()
        self.assertEqual(len(self.c_calls), 2)

    async def test_concurrent_owners_and_same_owner_other_run_never_mix(self):
        self.pause = True
        requests = [("alice", "a"), ("bob", "b"), ("alice", "c")]
        tasks = [asyncio.create_task(self.request(name, run=run)) for name, run in requests]
        try:
            observed = [await asyncio.wait_for(self.entered.get(), 5) for _ in requests]
            self.assertEqual(len({b.invocation.execution for b in observed}), 3)
            self.assertIsNone(self.resolver.current())
        finally:
            self.release.set()
        responses = await asyncio.gather(*tasks)
        for (name, run), response in zip(requests, responses):
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIn(self.people[name].person_id + ":invocation-" + run, response.text)
            self.assertNotIn(self.people["bob" if name == "alice" else "alice"].person_id, response.text)
        self.assertEqual(len(self.c_calls), 6)
        self.assert_cleared()

    async def test_bad_proof_cross_actor_and_bad_resource_auth_never_publish_binding(self):
        self.assertEqual((await self.request(invalid=True)).status_code, 401)
        body, headers = self.signed()
        headers[-1] = ("authorization", "Bearer synthetic-bob")
        self.assertEqual((await self.http.post("/mcp", content=body, headers=headers)).status_code, 401)
        body, headers = self.signed()
        headers[-1] = ("authorization", "Bearer invalid")
        self.assertEqual((await self.http.post("/mcp", content=body, headers=headers)).status_code, 401)
        self.assertEqual(self.c_calls, [])
        self.assertEqual(self.seen, [])
        self.assert_cleared()

    async def test_exception_cancellation_and_send_failure_all_revoke_copied_scope(self):
        self.fail_downstream = True
        with self.assertRaisesRegex(RuntimeError, "synthetic downstream failure"):
            await self.request()
        self.fail_downstream, self.cancel = False, True
        with self.assertRaises(asyncio.CancelledError):
            await self.request()
        self.cancel = False
        body, headers = self.signed()
        request = self.http.build_request("POST", "/mcp", content=body, headers=headers)
        events = [{"type": "http.request", "body": body}]
        async def receive():
            return events.pop(0)
        async def send(message):
            raise RuntimeError("synthetic send failure")
        with self.assertRaisesRegex(RuntimeError, "synthetic send failure"):
            await self.app({"type": "http", "method": "POST", "path": "/mcp", "raw_path": b"/mcp",
                "query_string": b"", "headers": request.headers.raw}, receive, send)
        self.assert_cleared()

    async def test_child_task_holding_context_loses_authority_after_response(self):
        wake = asyncio.Event()
        original = self.app.app
        async def wrapped(scope, receive, send):
            async def stale():
                await wake.wait()
                self.assertIsNone(self.resolver.current())
                with self.assertRaises(ExpenseError):
                    self.clients["alice"].get("attachment:file-a")
            self.child_tasks.append(asyncio.create_task(stale()))
            return await original(scope, receive, send)
        self.app.app = wrapped
        self.assertEqual((await self.request()).status_code, 200)
        wake.set()
        await asyncio.gather(*self.child_tasks)
        self.assertEqual(len(self.c_calls), 2)
        self.assert_cleared()

    async def test_resolution_alone_is_not_a_binding_and_apps_are_independent(self):
        body, headers = self.signed()
        scope = {"type": "http", "method": "POST", "agent_execution_request": self.proofs.request,
                 "headers": [(k.encode(), v.encode()) for k, v in headers]}
        binding = self.resolver(scope, self.people["alice"])
        self.assertIsNone(self.resolver.current())
        other = ExternalHistoryResolver(self.verifier, self.resolver.resolve_source,
            agent_slug="expense_assistant", source_platform="success_assist")
        with self.resolver.binding_context.bind(binding, self.people["alice"]):
            self.assertIs(self.resolver.current(), binding)
            self.assertIsNone(other.current())
        self.assert_cleared()

    async def test_legacy_boundary_masks_inherited_capability_and_never_exposes_history(self):
        migration = create_app(self.dispatcher, "agent.example.test", history_runtime=self.runtime,
            history_resolver=self.resolver, history_boundary_migration=True)
        async with migration.app.router.lifespan_context(migration.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=migration),
                                        base_url="https://agent.example.test") as http:
                response = await http.post("/mcp", headers={"authorization": "Bearer synthetic-alice",
                    "accept": "application/json, text/event-stream"}, json={"jsonrpc": "2.0", "id": 1,
                    "method": "tools/list", "params": {}})
                self.assertEqual(response.status_code, 200, response.text)
                self.assertNotIn("read_conversation_context", response.text)
                self.assertEqual(self.resolved, [])
                # Simulate a nested legacy request while an outer strict scope
                # is live. The separate legacy boundary must hide that scope.
                body, headers = self.signed()
                binding = self.resolver({"type": "http", "method": "POST",
                    "agent_execution_request": self.proofs.request,
                    "headers": [(k.encode(), v.encode()) for k, v in headers]}, self.people["alice"])
                original = migration.legacy.app
                async def legacy(scope, receive, send):
                    self.assertIsNone(self.resolver.current())
                    with self.assertRaises(ExpenseError):
                        self.clients["alice"].get("attachment:file-a")
                    return await original(scope, receive, send)
                migration.legacy.app = legacy
                with self.resolver.binding_context.bind(binding, self.people["alice"]):
                    response = await http.post("/mcp", headers={"authorization": "Bearer synthetic-alice",
                        "accept": "application/json, text/event-stream"}, json={"jsonrpc": "2.0", "id": 1,
                        "method": "tools/list", "params": {}})
                    self.assertEqual(response.status_code, 200)
                    self.assertIs(self.resolver.current(), binding)
        self.assertEqual(self.c_calls, [])
        self.assert_cleared()

    async def test_plain_resolver_keeps_legacy_injection_contract_no_duck_typed_context(self):
        binding = self.fixture.binding
        def plain(scope, person):
            return binding
        class ForbiddenContext:
            def bind(self, *args):
                raise AssertionError("plain resolver must not acquire new authority")
        plain.binding_context = ForbiddenContext()
        async def downstream(scope, receive, send):
            self.assertIsNone(self.resolver.current())
            self.assertIs(self.runtime._current.get(), binding.invocation)
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})
        app = RequestAuthorization(downstream, self.dispatcher, self.context, history_runtime=self.runtime,
            history_resolver=plain, history_target="https://agent.example.test/mcp")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://agent.example.test") as http:
            response = await http.post("/mcp", headers={"authorization": "Bearer synthetic-alice"}, content=b"{}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.c_calls, [])
        self.assert_cleared()

    async def test_context_rejects_expired_cross_person_and_model_shapes(self):
        context = HistoryRequestContext(clock=lambda: self.history.now)
        valid = self.fixture.binding
        for binding in ({"person_id": "canonical-alice"}, replace(valid, person_id="canonical-bob"),
                        replace(valid, invocation=replace(valid.invocation, expires_at=100)),
                        replace(valid, invocation=replace(valid.invocation, expires_at=181))):
            with self.assertRaises(ValueError):
                with context.bind(binding, self.people["alice"]):
                    self.fail("must not enter an invalid scope")
            self.assertIsNone(context.current())
        with context.bind(valid, self.people["alice"]):
            copied = copy_context()
            self.history.now = 181
            self.assertIsNone(context.current())
        self.assertIsNone(copied.run(context.current))

    async def test_failed_and_cancelled_setup_never_inherits_or_leaves_parent_authority(self):
        binding = self.fixture.binding
        body, headers = self.signed(invalid=True)
        scope = {"type": "http", "method": "POST", "path": "/mcp", "raw_path": b"/mcp",
                 "query_string": b"", "headers": [(k.encode(), v.encode()) for k, v in headers]}
        events = []
        async def receive():
            return {"type": "http.request", "body": body}
        async def send(message):
            self.assertIsNone(self.resolver.current())
            events.append(message)
        with self.resolver.binding_context.bind(binding, self.people["alice"]):
            await self.app(scope, receive, send)
            self.assertEqual(events[0]["status"], 401)
            self.assertIs(self.resolver.current(), binding)
            async def cancelled_receive():
                self.assertIsNone(self.resolver.current())
                raise asyncio.CancelledError()
            with self.assertRaises(asyncio.CancelledError):
                await self.app(scope, cancelled_receive, send)
            self.assertIs(self.resolver.current(), binding)
        self.assertEqual(self.c_calls, [])
        self.assert_cleared()

    async def test_expiry_inside_active_request_denies_attachment_before_c_http(self):
        self.pause = True
        task = asyncio.create_task(self.request())
        await asyncio.wait_for(self.entered.get(), 5)
        self.history.now = 160  # The fresh runtime proof expires at 159.
        self.release.set()
        with self.assertRaises(ExpenseError):
            await task
        self.assertEqual(self.c_calls, [])
        self.assert_cleared()


if __name__ == "__main__":
    unittest.main()
