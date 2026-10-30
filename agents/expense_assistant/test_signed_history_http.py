"""Signed-proof -> SDK HTTP -> agent-owned history, all services synthetic."""

from dataclasses import replace
import hashlib
import json
import unittest

import httpx

from _foundation.conversation import ContextError
from _foundation.execution_binding import ExecutionRequest
from _foundation.history_runtime import create_conversation_runtime
from _foundation.history_sources import SuccessAssistHistory, bind_invocation
from _foundation.platform_identity import PlatformPerson
from _foundation.test_history_sources import SAAPI, event
from requester_mcp import create_app
from runtime.external_history_resolver import (
    ExternalHistoryResolver, ResolvedHistorySource, history_execution_id,
)
from runtime.requester import RequesterDispatcher
import test_external_history_resolver as proof_fixtures
import test_requester_mcp as http_fixtures


class SignedHistoryHTTPTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        proof_fixtures.ExternalHistoryResolverTests.setUpClass()

    async def asyncSetUp(self):
        self.proofs = proof_fixtures.ExternalHistoryResolverTests()
        self.proofs.setUp()
        self.person = replace(self.proofs.person, capabilities=frozenset())
        self.api, self.source_checks = SAAPI(), []
        for row in self.api.rows:
            row["authorId"] = "sa-employee"
        self.api.rows[1]["message"] = "先ほどの合成検証印はブルーバードです"
        self.source = SuccessAssistHistory(self.api, ("agent-bot",))

        def bound(reference):
            return bind_invocation(
                self.source, clock=lambda: self.proofs.now,
                **{**event(), "tenant": reference.source_namespace,
                   "requester": reference.source_actor, "agent": "expense_assistant",
                   "execution": history_execution_id(reference.session_id, reference.invocation_id),
                   "expires_at": reference.expires_at},
            )

        # Synthetic preexisting source registry. Binding happens BEFORE runtime
        # activation, never on this HTTP read path. No live SA access is used.
        initial_scope = self.proofs.scope()
        first_ref = self.proofs.verifier.verify(
            initial_scope["headers"][0][1].decode(),
            initial_scope["headers"][1][1].decode(),
            request=self.proofs.request,
            person=PlatformPerson(
                self.person.tenant_id, self.person.person_id, self.person.expires_at
            ),
        )
        anchor_digest = bound(first_ref).anchor_digest
        self.api.calls.clear()

        def resolve_source(reference):
            self.source_checks.append(reference)
            if (reference.source_handle != "h" * 43 or reference.session_id != "session-a"
                    or reference.invocation_id != "invocation-a" or reference.anchor_revision != "a" * 64):
                raise ContextError("access_denied")
            invocation = bound(reference)
            if invocation.anchor_digest != anchor_digest:
                raise ContextError("stale_or_revoked")
            return ResolvedHistorySource(reference, invocation, "a" * 64)

        self.history = create_conversation_runtime(
            enabled=True, sources_factory=lambda: {"success_assist": self.source},
            clock=lambda: self.proofs.now,
        )
        self.dispatcher = RequesterDispatcher(
            lambda token: self.person if token == "synthetic-resource-token" else None,
            lambda *_: None, clock=lambda: self.proofs.now,
        )
        self.app = create_app(
            self.dispatcher, "agent.example.test", history_runtime=self.history,
            history_resolver=ExternalHistoryResolver(
                self.proofs.verifier, resolve_source,
                agent_slug="expense_assistant", source_platform="success_assist",
            ),
        )
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="https://agent.example.test"
        )
        self.addAsyncCleanup(self.client.aclose)

    def signed(self, *, proof_changes=None):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "read_conversation_context", "arguments": {}}},
                          separators=(",", ":")).encode()
        self.proofs.request = ExecutionRequest(
            "POST", "https://agent.example.test/mcp", hashlib.sha256(body).hexdigest()
        )
        scope = self.proofs.scope(proof_changes=proof_changes)
        headers = [(k.decode(), v.decode()) for k, v in scope["headers"]] + [
            ("authorization", "Bearer synthetic-resource-token"),
            ("accept", "application/json, text/event-stream"),
            ("content-type", "application/json"), ("mcp-protocol-version", "2025-03-26"),
        ]
        return body, headers

    @http_fixtures.with_server
    async def test_real_signed_http_returns_prior_user_and_assistant(self):
        body, headers = self.signed()
        reply = await self.client.post("/mcp", content=body, headers=headers)
        self.assertEqual(reply.status_code, 200, reply.text)
        result = reply.json()["result"]
        self.assertFalse(result.get("isError"), result)
        content = result.get("structuredContent") or json.loads(result["content"][0]["text"])
        self.assertEqual(content["status"], "available")
        self.assertEqual([m["role"] for m in content["messages"]], ["user", "assistant"])
        self.assertIn("ブルーバード", content["messages"][1]["text"])
        self.assertEqual(self.history.read()["status"], "unavailable")

    @http_fixtures.with_server
    async def test_signed_other_session_or_resource_person_cannot_read(self):
        body, headers = self.signed(proof_changes={"session_id": "session-b"})
        self.assertEqual((await self.client.post("/mcp", content=body, headers=headers)).status_code, 401)
        self.assertEqual(self.api.calls, [])
        self.source_checks.clear()
        self.person = replace(self.person, person_id="another-person")
        body, headers = self.signed()
        self.assertEqual((await self.client.post("/mcp", content=body, headers=headers)).status_code, 401)
        self.assertEqual(self.source_checks, [])

    @http_fixtures.with_server
    async def test_replay_and_body_tampering_stop_before_source_access(self):
        body, headers = self.signed()
        self.assertEqual((await self.client.post("/mcp", content=body, headers=headers)).status_code, 200)
        self.api.calls.clear()
        self.source_checks.clear()
        self.assertEqual((await self.client.post("/mcp", content=body, headers=headers)).status_code, 401)
        body, headers = self.signed()
        self.assertEqual((await self.client.post("/mcp", content=body + b" ", headers=headers)).status_code, 401)
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.source_checks, [])

    @http_fixtures.with_server
    async def test_edited_anchor_and_revoked_source_fail_with_fresh_valid_proofs(self):
        self.api.rows[-1]["message"] = "edited after source binding"
        body, headers = self.signed()
        reply = await self.client.post("/mcp", content=body, headers=headers)
        self.assertEqual(reply.status_code, 401)
        self.assertNotIn("ブルーバード", reply.text)
        self.api.denied = True
        body, headers = self.signed()
        reply = await self.client.post("/mcp", content=body, headers=headers)
        self.assertEqual(reply.status_code, 401)
        self.assertEqual(reply.text, "Unauthorized")
