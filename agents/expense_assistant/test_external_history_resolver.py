"""Real synthetic RSA proofs, atomic replay/CAS fakes, no service or network I/O."""

import copy
from contextlib import contextmanager
from dataclasses import replace
import hashlib
from pathlib import Path
import sys
import threading
import unittest

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _foundation.conversation import Invocation
from _foundation.execution_binding import (
    EXECUTION_TYPE, SOURCE_TYPE, ExecutionBindingError, ExecutionRequest,
    ExecutionTarget, ExternalExecutionVerifier,
)
from _foundation.platform_identity import PlatformPersonLink
from runtime.external_history_resolver import (
    ExternalHistoryResolver, ResolvedHistorySource, history_execution_id,
)
from runtime.requester import Requester


class AtomicStore:
    def __init__(self):
        self.rows, self.lock = {}, threading.RLock()

    @contextmanager
    def transaction(self):
        with self.lock:
            before = copy.deepcopy(self.rows)
            try:
                yield self
            except BaseException:
                self.rows = before
                raise

    def get(self, key):
        return copy.deepcopy(self.rows.get(key))

    def put(self, key, value):
        self.rows[key] = copy.deepcopy(value)


class AuthorizedSource:
    """Synthetic source verifies launcher-bound sessions and current permissions."""
    def __init__(self):
        self.calls, self.sessions, self.lock = [], {"h" * 43: "session-a"}, threading.RLock()
        self.allowed, self.revoked = True, False
        self.anchor_revision = "a" * 64
        self.transform = lambda result: result

    def __call__(self, reference):
        self.calls.append(reference)
        with self.lock:
            if not self.allowed or self.revoked or self.anchor_revision != reference.anchor_revision:
                raise RuntimeError("synthetic-private-source-diagnostic")
            prior = self.sessions.get(reference.source_handle)
            if prior != reference.session_id:
                raise RuntimeError("handle unbound or bound to another session")
        invocation = Invocation(
            reference.source_namespace, reference.source_actor, "expense_assistant",
            "success_assist", "source-channel", "source-thread", "source-anchor", 10,
            history_execution_id(reference.session_id, reference.invocation_id),
            reference.expires_at, anchor_digest="a" * 64,
        )
        return self.transform(ResolvedHistorySource(reference, invocation, self.anchor_revision))


class ExternalHistoryResolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.execution_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @staticmethod
    def public(key):
        return key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def setUp(self):
        self.now, self.sequence = 100, 0
        self.person = Requester("canonical-tenant", "canonical-person", 190)
        self.links = {
            ("https://source.example.test", "sa-tenant", "sa-employee"):
                PlatformPersonLink(self.person.tenant_id, self.person.person_id),
            ("https://identity.example.test", "engine-tenant", "engine-employee"):
                PlatformPersonLink(self.person.tenant_id, self.person.person_id),
        }
        self.target = ExecutionTarget("deployment-tenant", "managed-agent", "version-a", "connection-a")
        self.store, self.source = AtomicStore(), AuthorizedSource()
        self.verifier = ExternalExecutionVerifier(
            self.store, lambda *actor: self.links.get(actor),
            source_issuer="https://source.example.test", source_keys={"source": self.public(self.source_key)},
            execution_issuer="https://runtime.example.test", execution_keys={"runtime": self.public(self.execution_key)},
            audience="https://agent.example.test", targets={self.target}, clock=lambda: self.now,
        )
        self.resolver = ExternalHistoryResolver(
            self.verifier, self.source, agent_slug="expense_assistant", source_platform="success_assist",
        )
        self.request = ExecutionRequest("POST", "https://agent.example.test/mcp", hashlib.sha256(b"synthetic body").hexdigest())

    def scope(self, *, source_changes=None, proof_changes=None):
        self.sequence += 1
        target = {"target_tenant_id": self.target.tenant_id, "target_agent_id": self.target.agent_id,
                  "target_version_id": self.target.version_id, "invocation_id": "invocation-a"}
        source = {
            "iss": self.verifier.source_issuer, "aud": self.verifier.audience,
            "iat": 99, "exp": 199, "jti": "source-a", "purpose": "source_context", **target,
            "source_namespace": "sa-tenant", "source_actor": "sa-employee", "source_actor_type": "human",
            "source_handle": "h" * 43, "anchor_revision": "a" * 64, **(source_changes or {}),
        }
        source_token = jwt.encode(source, self.source_key, algorithm="RS256",
                                  headers={"kid": "source", "typ": SOURCE_TYPE})
        call = {
            "iss": self.verifier.execution_issuer, "aud": self.verifier.audience,
            "iat": 99, "exp": 159, "jti": "call-" + str(self.sequence),
            "purpose": "external_mcp_execution", **target,
            "connection_id": self.target.connection_id, "session_id": "session-a",
            "actor_issuer": "https://identity.example.test", "actor_namespace": "engine-tenant",
            "actor_subject": "engine-employee", "actor_type": "human",
            "source_grant_sha256": hashlib.sha256(source_token.encode()).hexdigest(),
            "source_handle_sha256": hashlib.sha256(source["source_handle"].encode()).hexdigest(),
            "method": self.request.method, "target": self.request.target,
            "body_sha256": self.request.body_sha256, **(proof_changes or {}),
        }
        proof = jwt.encode(call, self.execution_key, algorithm="RS256",
                           headers={"kid": "runtime", "typ": EXECUTION_TYPE})
        return {"type": "http", "method": "POST", "agent_execution_request": self.request,
                "headers": [(b"X-Agent-Source-Context", source_token.encode()),
                            (b"X-Agent-Execution-Proof", proof.encode())]}

    def refused(self, scope, person=None):
        with self.assertRaises(ExecutionBindingError) as caught:
            self.resolver(scope, self.person if person is None else person)
        self.assertEqual(str(caught.exception), "invalid_execution_binding")

    def test_distinct_source_runtime_and_canonical_namespaces_bind_without_substitution(self):
        binding = self.resolver(self.scope(), self.person)
        self.assertTrue(binding.matches(self.person))
        self.assertEqual((binding.tenant_id, binding.person_id), ("canonical-tenant", "canonical-person"))
        self.assertEqual((binding.invocation.tenant, binding.invocation.requester), ("sa-tenant", "sa-employee"))
        self.assertEqual(binding.invocation.agent, "expense_assistant")
        self.assertEqual(binding.invocation.execution, history_execution_id("session-a", "invocation-a"))
        self.assertEqual(binding.invocation.expires_at, 159)
        self.assertEqual(len(self.source.calls), 1)
        # Fresh per-call jti keeps exactly the same source/session.
        self.assertEqual(self.resolver(self.scope(), self.person), binding)

    def test_atomic_replay_rejected_before_source_and_body_substitution_rejected(self):
        scope = self.scope()
        self.resolver(scope, self.person)
        self.refused(scope)
        self.assertEqual(len(self.source.calls), 1)
        scope = self.scope()
        scope["agent_execution_request"] = replace(self.request, body_sha256="b" * 64)
        self.refused(scope)
        self.assertEqual(len(self.source.calls), 1)

    def test_headers_require_exact_single_ascii_bounded_proofs(self):
        for index in (0, 1):
            for value in (b"", b"x" * 16385, b"bad\xff", b"bad\n", "not-bytes"):
                scope = self.scope()
                key = scope["headers"][index][0]
                scope["headers"][index] = (key, value)
                self.refused(scope)
            scope = self.scope()
            key, value = scope["headers"][index]
            scope["headers"].append((key.lower(), value))
            self.refused(scope)
            scope = self.scope()
            scope["headers"].pop(index)
            self.refused(scope)
        self.assertEqual(self.source.calls, [])
        self.assertEqual(self.store.rows, {})

    def test_missing_typed_request_or_authenticated_human_never_reaches_source(self):
        for request in (None, {}, {"method": "POST", "target": self.request.target}):
            scope = self.scope()
            scope["agent_execution_request"] = request
            self.refused(scope)
        self.refused(self.scope(), replace(self.person, kind="service"))
        self.refused(self.scope(), replace(self.person, person_id="other-person"))
        self.refused(self.scope(), replace(self.person, tenant_id="other-tenant"))
        self.refused(self.scope(), replace(self.person, expires_at=100))
        self.assertEqual(self.source.calls, [])

    def test_bad_signature_scope_target_and_source_hash_do_not_call_source(self):
        for changes in ({"actor_namespace": "wrong-namespace"}, {"actor_subject": "other-person"},
                        {"target_agent_id": "other-agent"}, {"target_version_id": "other-version"},
                        {"connection_id": "other-connection"}, {"source_grant_sha256": "b" * 64},
                        {"target": "https://other.example.test/mcp"}, {"method": "DELETE"},
                        {"body_sha256": "b" * 64}, {"exp": 100}):
            self.refused(self.scope(proof_changes=changes))
        for changes in ({"source_namespace": "wrong-namespace"}, {"source_actor": "other-person"},
                        {"source_actor_type": "service"}, {"exp": 100}):
            self.refused(self.scope(source_changes=changes))
        scope = self.scope()
        key, proof = scope["headers"][1]
        chunks = proof.split(b".")
        chunks[2] = (b"A" if chunks[2][:1] != b"A" else b"B") + chunks[2][1:]
        scope["headers"][1] = (key, b".".join(chunks))
        self.refused(scope)
        self.assertEqual(self.source.calls, [])

    def test_source_prebound_session_acl_anchor_revision_and_revocation_are_rechecked(self):
        self.source.sessions.clear()
        self.refused(self.scope())
        self.assertEqual(self.source.sessions, {})
        self.source.sessions["h" * 43] = "session-a"
        self.resolver(self.scope(), self.person)
        self.refused(self.scope(proof_changes={"session_id": "session-b"}))
        self.refused(self.scope(source_changes={"source_handle": "q" * 43}))
        self.source.allowed = False
        self.refused(self.scope())
        self.source.allowed = True
        self.source.revoked = True
        self.refused(self.scope())
        self.source.revoked = False
        self.source.anchor_revision = "b" * 64
        self.refused(self.scope())
        self.assertEqual(self.source.sessions, {"h" * 43: "session-a"})

    def test_resolved_source_identity_revision_execution_and_expiry_cannot_change(self):
        transforms = [
            lambda r: replace(r, reference=replace(r.reference)),
            lambda r: replace(r, source_anchor_revision="b" * 64),
            lambda r: replace(r, invocation=replace(r.invocation, tenant="canonical-tenant")),
            lambda r: replace(r, invocation=replace(r.invocation, requester="canonical-person")),
            lambda r: replace(r, invocation=replace(r.invocation, agent="other-agent")),
            lambda r: replace(r, invocation=replace(r.invocation, platform="buzz")),
            lambda r: replace(r, invocation=replace(r.invocation, execution=history_execution_id("session-b", "invocation-a"))),
            lambda r: replace(r, invocation=replace(r.invocation, execution=history_execution_id("session-a", "invocation-b"))),
            lambda r: replace(r, invocation=replace(r.invocation, expires_at=160)),
            lambda r: replace(r, invocation=replace(r.invocation, expires_at=100)),
            lambda r: replace(r, invocation=replace(r.invocation, expires_at=float("nan"))),
            lambda r: replace(r, invocation=replace(r.invocation, anchor_digest=None)),
            lambda r: {"invocation": r.invocation},
        ]
        for transform in transforms:
            self.source.transform = transform
            self.refused(self.scope())

    def test_expiry_during_source_resolution_and_explicit_link_revocation_fail_closed(self):
        def expire(result):
            self.now = result.reference.expires_at
            return result
        self.source.transform = expire
        self.refused(self.scope())
        self.now = 100
        self.source.transform = lambda r: r
        self.links[("https://source.example.test", "sa-tenant", "sa-employee")] = PlatformPersonLink(
            self.person.tenant_id, self.person.person_id, active=False)
        before = len(self.source.calls)
        self.refused(self.scope())
        self.assertEqual(len(self.source.calls), before)

    def test_execution_pair_encoding_is_unambiguous(self):
        pairs = (("a:b", "c"), ("a", "b:c"), ("ab", "c"), ("a", "bc"),
                 ('a", "b', "c"), ("会話", "実行"))
        self.assertEqual(len({history_execution_id(*p) for p in pairs}), len(pairs))


class ExternalResolverHTTPTests(unittest.IsolatedAsyncioTestCase):
    """Real RSA resolver inside the SDK HTTP authentication boundary."""
    @classmethod
    def setUpClass(cls):
        ExternalHistoryResolverTests.setUpClass()

    async def asyncSetUp(self):
        import httpx
        from unittest.mock import Mock
        from _foundation.history_runtime import create_conversation_runtime
        from requester_mcp import create_app
        import test_requester_mcp as http_fixture
        await http_fixture.RequesterMCPTests.asyncSetUp(self)
        await self.client.aclose()
        self.proofs = ExternalHistoryResolverTests()
        self.proofs.setUp()
        self.proofs.person = self.people[self.tokens["alice"]]
        for actor in self.proofs.links:
            self.proofs.links[actor] = PlatformPersonLink(self.proofs.person.tenant_id, self.proofs.person.person_id)
        self.proofs.verifier = ExternalExecutionVerifier(
            self.proofs.store, lambda *actor: self.proofs.links.get(actor),
            source_issuer="https://source.example.test",
            source_keys={"source": self.proofs.public(self.proofs.source_key)},
            execution_issuer="https://runtime.example.test",
            execution_keys={"runtime": self.proofs.public(self.proofs.execution_key)},
            audience="https://expense.example.test", targets={self.proofs.target},
            clock=lambda: self.proofs.now)
        self.proofs.resolver = ExternalHistoryResolver(
            self.proofs.verifier, self.proofs.source, agent_slug="expense_assistant", source_platform="success_assist")
        self.history_source = Mock()
        self.history_source.read.side_effect = AssertionError("no history read expected")
        self.history = create_conversation_runtime(enabled=True,
            sources_factory=lambda: {"success_assist": self.history_source}, clock=lambda: self.proofs.now)
        self.app = create_app(self.dispatcher, "expense.example.test", history_runtime=self.history,
                              history_resolver=self.proofs.resolver)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
                                       base_url="https://expense.example.test")
        self.addAsyncCleanup(self.client.aclose)

    def signed_request(self):
        import json
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "mf_offices", "arguments": {}}}).encode()
        self.proofs.request = ExecutionRequest("POST", "https://expense.example.test/mcp",
                                               hashlib.sha256(body).hexdigest())
        headers = [(k.encode(), v.encode()) for k, v in self.headers.items()] + self.proofs.scope()["headers"]
        headers += [(b"authorization", ("Bearer " + self.tokens["alice"]).encode()),
                    (b"content-type", b"application/json")]
        return body, headers

    async def test_opted_in_http_exact_body_accepts_then_replay_and_body_change_are_401(self):
        async with self.app.app.router.lifespan_context(self.app.app):
            body, headers = self.signed_request()
            reply = await self.client.post("/mcp", headers=headers, content=body)
            self.assertEqual(reply.status_code, 200, reply.text)
            self.assertFalse(reply.json()["result"].get("isError"))
            self.assertEqual(len(self.proofs.source.calls), 1)
            replay = await self.client.post("/mcp", headers=headers, content=body)
            self.assertEqual(replay.status_code, 401)
            body, headers = self.signed_request()
            changed = await self.client.post("/mcp", headers=headers, content=body + b" ")
            self.assertEqual(changed.status_code, 401)
            self.assertEqual(len(self.proofs.source.calls), 1)
            self.history_source.read.assert_not_called()
            self.assertEqual(self.history.read()["status"], "unavailable")

    async def test_rejected_http_proofs_return_safe_401_without_source_or_mf_read(self):
        async with self.app.app.router.lifespan_context(self.app.app):
            for variant in ("missing", "duplicate", "modified", "other-person"):
                body, headers = self.signed_request()
                if variant == "missing":
                    headers = [(k, v) for k, v in headers if k.lower() != b"x-agent-execution-proof"]
                elif variant == "duplicate":
                    headers.extend([(k, v) for k, v in headers if k.lower() == b"x-agent-source-context"])
                elif variant == "modified":
                    headers = [(k, b"bad-proof" if k.lower() == b"x-agent-execution-proof" else v) for k, v in headers]
                else:
                    headers = [(k, ("Bearer " + self.tokens["bob"]).encode() if k == b"authorization" else v) for k, v in headers]
                reply = await self.client.post("/mcp", headers=headers, content=body)
                self.assertEqual(reply.status_code, 401, reply.text)
                self.assertEqual(reply.text, "Unauthorized")
            self.assertEqual(self.proofs.source.calls, [])
            self.history_source.read.assert_not_called()
            self.assertEqual(self.grants["alice"].service.mf.calls, 0)
            self.assertEqual(self.grants["bob"].service.mf.calls, 0)


if __name__ == "__main__":
    unittest.main()
