"""Real dedicated RSA signing against synthetic SA snapshot HTTP only."""

from concurrent.futures import ThreadPoolExecutor
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import threading
import unittest

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _foundation.conversation import ConversationReader, ContextError, Invocation
from _foundation.execution_binding import ExecutionTarget, VerifiedSourceCall
from _foundation.history_sources import create_reader
from runtime.sa_history_client import SAHistoryClient, SABoundInvocation, PATH
from runtime.external_history_resolver import history_execution_id


def raw(identifier, text, *, actor="source-alice", bot=None, root="root", time="03"):
    return {"id": identifier, "channelId": "channel", "rootId": root,
            "authorId": None if bot else actor, "botId": bot, "guestAuthorId": None,
            "message": text, "createdAt": "2026-10-30T00:00:" + time + ".000Z", "editAt": None, "deleted": False}


def revision(row):
    return hashlib.sha256(json.dumps([row[k] for k in (
        "id", "channelId", "rootId", "authorId", "botId", "guestAuthorId", "message", "createdAt", "editAt", "deleted")],
        ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


class SyntheticSA:
    def __init__(self, public):
        self.public, self.calls, self.jtis, self.lock = public, [], set(), threading.RLock()
        self.active, self.allowed, self.bound = True, True, True
        self.sessions = {"h" * 43: "42", "q" * 43: "43"}
        self.transform = lambda value: value
        self.status, self.content_type, self.raw_content = 200, "application/json", None
        self.root = raw("root", "最初の本人発言", root=None, time="00")
        self.anchor = raw("anchor", "前の会話を確認して", time="05")
        self.rows = [raw("prior-user", "合成印ブルーバード", time="01"),
                     raw("prior-assistant", "ブルーバードを受け取りました", bot="source-bot", time="02")]
        self.target = ExecutionTarget("10", "12", "18", "60")

    def __call__(self, request):
        with self.lock:
            self.calls.append(request)
            assert request.method == "POST"
            assert str(request.url) == "https://sa.example.test" + PATH
            assert "authorization" not in request.headers
            assert "x-agent-source-context" not in request.headers
            assert "x-agent-execution-proof" not in request.headers
            token = request.headers["x-agent-source-read-proof"]
            assert jwt.get_unverified_header(token) == {"alg": "RS256", "typ": "agent-source-read+jwt", "kid": "read-key"}
            claims = jwt.decode(token, self.public, algorithms=["RS256"], issuer="https://agent.example.test",
                                audience="https://sa.example.test", options={"verify_exp": False, "verify_iat": False})
            assert set(claims) == {"iss", "aud", "iat", "exp", "jti", "purpose", "source_namespace", "source_actor",
                "source_actor_type", "target_tenant_id", "target_agent_id", "target_version_id", "connection_id",
                "invocation_id", "session_id", "source_handle_sha256", "method", "target", "body_sha256"}
            assert claims["purpose"] == "source_snapshot_read"
            assert claims["source_actor_type"] == "human"
            assert type(claims["iat"]) is int and type(claims["exp"]) is int and 0 < claims["exp"] - claims["iat"] <= 60
            assert claims["target"] == str(request.url) and claims["method"] == request.method
            assert claims["body_sha256"] == hashlib.sha256(request.content).hexdigest()
            body = json.loads(request.content)
            assert set(body) <= {"source_handle", "invocation_id", "session_id", "scope", "limit", "before"}
            assert claims["source_handle_sha256"] == hashlib.sha256(body["source_handle"].encode()).hexdigest()
            assert claims["invocation_id"] == body["invocation_id"] and claims["session_id"] == body["session_id"]
            assert claims["jti"] not in self.jtis
            self.jtis.add(claims["jti"])
            if not self.active or not self.allowed or not self.bound or body["session_id"] != self.sessions.get(body["source_handle"]):
                return httpx.Response(401, json={"error": "source_snapshot_unavailable"})
            if self.status != 200:
                return httpx.Response(self.status, headers={"location": "https://evil.example.test"})
            if self.raw_content is not None:
                return httpx.Response(200, content=self.raw_content, headers={"content-type": self.content_type})
            rows = list(self.rows)
            if body["scope"] == "thread":
                rows = [r for r in rows if (r["rootId"] or r["id"]) == self.root["id"]]
            rows = rows[:body["limit"]]
            binding = {"sourceNamespace": claims["source_namespace"], "sourceActor": claims["source_actor"],
                       "sourceActorType": "human", "tenantId": "10", "managedAgentId": "12",
                       "managedAgentVersionId": "18", "connectionId": "60", "harnessSessionId": body["session_id"],
                       "invocationId": body["invocation_id"], "sourceHandleSha256": claims["source_handle_sha256"]}
            result = {"schemaVersion": "source-snapshot-internal/v1", "invocationId": body["invocation_id"],
                "scope": body["scope"], "source": {"channelId": "channel", "sourceMessageId": self.anchor["id"],
                                                    "rootMessageId": self.root["id"]},
                "anchor": copy.deepcopy(self.anchor), "root": copy.deepcopy(self.root),
                "messages": copy.deepcopy(rows), "nextBefore": None, "revision": "f" * 64,
                "consistency": "content_readback", "expiresAt": claims["exp"] * 1000,
                "binding": binding, "anchorRevision": revision(self.anchor), "rootRevision": revision(self.root)}
            return httpx.Response(200, json=self.transform(result), headers={"content-type": self.content_type})


class SAHistoryClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.private = cls.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()).decode()
        cls.public = cls.key.public_key()

    def setUp(self):
        self.now = 100
        self.server = SyntheticSA(self.public)
        self.http = httpx.Client(transport=httpx.MockTransport(self.server))
        self.client = self.make_client(self.server, self.http)
        self.addCleanup(self.client.close)
        self.reference = self.ref()

    def make_client(self, server, http=None, actor="source-alice"):
        return SAHistoryClient(origin="https://sa.example.test", agent_origin="https://agent.example.test",
            source_namespace="source-tenant", source_actor=actor, target=server.target, kid="read-key",
            signing_private_key=self.private, agent_authors=("source-bot",),
            http=http or httpx.Client(transport=httpx.MockTransport(server)), clock=lambda: self.now)

    def ref(self, **changes):
        result = VerifiedSourceCall("h" * 43, "https://sa.example.test", "source-tenant", "source-alice",
            revision(self.server.anchor), self.server.target, "invocation-a", "42", 180, "d" * 64)
        return replace(result, **changes)

    def test_real_signed_snapshot_reaches_foundation_with_prior_user_and_assistant(self):
        resolved = self.client.resolve_source(self.reference)
        inv = resolved.invocation
        self.assertIsInstance(inv, SABoundInvocation)
        self.assertIs(inv.reference, self.reference)
        self.assertEqual(inv.execution, history_execution_id("42", "invocation-a"))
        self.assertEqual(inv.thread, "root")
        self.assertEqual(len(self.server.calls), 1)
        reader = create_reader(self.client, lambda: inv, clock=lambda: self.now)
        result = reader.read()
        self.assertEqual(result["status"], "available")
        self.assertEqual([r["role"] for r in result["messages"]], ["user", "user", "assistant"])
        self.assertIn("ブルーバード", result["messages"][-1]["text"])
        self.assertEqual(len(self.server.calls), 4)
        self.assertEqual(len(self.server.jtis), 4)
        for request in self.server.calls[1:]:
            self.assertEqual(json.loads(request.content)["before"], {"id": "anchor", "createdAt": self.server.anchor["createdAt"]})

    def test_root_anchor_uses_conversation_and_copy_preserves_verified_reference(self):
        self.server.anchor = self.server.root
        self.server.rows = [raw("older-root", "前の本流", root=None, time="00")]
        inv = self.client.resolve_source(self.ref()).invocation
        self.assertIsNone(inv.thread)
        clone = replace(inv)
        self.assertIs(clone.reference, inv.reference)
        from _foundation.history_runtime import create_conversation_runtime
        runtime = create_conversation_runtime(enabled=True, sources_factory=lambda: {"success_assist": self.client},
                                              clock=lambda: self.now)
        with runtime.bind(clone):
            self.assertEqual(runtime.read()["status"], "available")
        self.assertEqual(runtime.read()["status"], "unavailable")
        self.assertEqual(self.client.read(clone)[0][-1].identifier, "root")
        self.assertEqual(json.loads(self.server.calls[-1].content)["scope"], "conversation")
        plain = Invocation(**{k: v for k, v in inv.__dict__.items() if k not in {"reference", "anchor_created_at", "client_binding"}})
        before = len(self.server.calls)
        with self.assertRaises(ContextError):
            self.client.read(plain)
        self.assertEqual(len(self.server.calls), before)

    def test_initial_and_every_read_require_prebound_session_acl_and_revocation(self):
        self.server.bound = False
        with self.assertRaises(ContextError):
            self.client.resolve_source(self.reference)
        self.assertFalse(self.server.bound)
        self.server.bound = True
        inv = self.client.resolve_source(self.reference).invocation
        for flag in ("allowed", "active", "bound"):
            setattr(self.server, flag, False)
            with self.assertRaises(ContextError) as caught:
                self.client.read(inv)
            self.assertEqual(str(caught.exception), "history_read_failed")
            setattr(self.server, flag, True)
        with self.assertRaises(ContextError):
            self.client.resolve_source(self.ref(session_id="43"))

    def test_anchor_edit_delete_or_source_response_binding_change_is_rejected(self):
        inv = self.client.resolve_source(self.reference).invocation
        self.server.anchor["message"] = "edited"
        with self.assertRaises(ContextError):
            self.client.read(inv)
        self.server.anchor["deleted"] = True
        self.server.anchor["message"] = None
        with self.assertRaises(ContextError):
            self.client.resolve_source(self.reference)

    def test_redirect_non_json_oversize_duplicate_json_and_bad_response_shapes_are_safe(self):
        self.server.status = 302
        with self.assertRaises(ContextError):
            self.client.resolve_source(self.reference)
        self.assertEqual(len(self.server.calls), 1)
        self.server.status = 200
        for content, mime in ((b"<html>private</html>", "text/html"), (b"x" * (2 * 1024 * 1024 + 1), "application/json"),
                              (b'{"schemaVersion":"one","schemaVersion":"two"}', "application/json")):
            self.server.raw_content, self.server.content_type = content, mime
            with self.assertRaises(ContextError) as caught:
                self.client.resolve_source(self.reference)
            self.assertEqual(str(caught.exception), "history_read_failed")
        self.server.raw_content, self.server.content_type = None, "application/json"
        for mutate in (
            lambda d: d["binding"].update(harnessSessionId="43"),
            lambda d: d["binding"].update(sourceActor="other-person"),
            lambda d: d["binding"].update(connectionId="61"),
            lambda d: d["binding"].update(sourceHandleSha256="b" * 64),
            lambda d: d.update(anchorRevision="b" * 64),
            lambda d: d.update(expiresAt=100000),
            lambda d: d.update(expiresAt=999999),
            lambda d: d.update(scope="conversation"),
            lambda d: d.update(unknown="value"),
            lambda d: d["source"].update(channelId="other-channel"),
            lambda d: d["anchor"].update(authorId="other-person"),
        ):
            def change(data):
                mutate(data)
                return data
            self.server.transform = change
            with self.assertRaises(ContextError):
                self.client.resolve_source(self.reference)

    def test_attachment_only_null_text_anchor_uses_empty_text_without_losing_revision(self):
        self.server.anchor["message"] = None
        reference = self.ref()
        resolved = self.client.resolve_source(reference)
        self.assertEqual(resolved.source_anchor_revision, revision(self.server.anchor))
        result = create_reader(self.client, lambda: resolved.invocation, clock=lambda: self.now).read()
        self.assertEqual(result["status"], "available")
        self.assertIn("ブルーバード", result["messages"][-1]["text"])

    def test_wrong_reference_expired_or_client_closed_never_sends_http(self):
        for ref in (self.ref(source_actor="other-person"), self.ref(source_namespace="other-tenant"),
                    self.ref(target=replace(self.server.target, agent_id="99")), self.ref(expires_at=100)):
            with self.assertRaises(ContextError):
                self.client.resolve_source(ref)
        self.assertEqual(self.server.calls, [])
        inv = self.client.resolve_source(self.reference).invocation
        count = len(self.server.calls)
        self.client.close()
        self.assertTrue(self.http.is_closed)
        for action in (lambda: self.client.resolve_source(self.reference), lambda: self.client.read(inv)):
            with self.assertRaises(ContextError):
                action()
        self.assertEqual(len(self.server.calls), count)

    def test_same_actor_concurrent_prebound_sessions_keep_their_own_reference(self):
        second = self.ref(source_handle="q" * 43, session_id="43", invocation_id="invocation-b")
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.client.resolve_source, self.reference)
            other = pool.submit(self.client.resolve_source, second)
            a, b = first.result().invocation, other.result().invocation
        self.assertIs(a.reference, self.reference)
        self.assertIs(b.reference, second)
        self.assertNotEqual(a.execution, b.execution)
        with ThreadPoolExecutor(max_workers=2) as pool:
            reads = list(pool.map(self.client.read, (a, b, a, b)))
        self.assertEqual(len(reads), 4)
        self.assertEqual(len(self.server.jtis), len(self.server.calls))
        self.assertEqual(a.reference.session_id, "42")
        self.assertEqual(b.reference.session_id, "43")

    def test_independent_clients_and_same_actor_sessions_do_not_mix(self):
        other = SyntheticSA(self.public)
        other.sessions["q" * 43] = "42"
        other.root["authorId"] = "source-bob"
        other.anchor["authorId"] = "source-bob"
        client = self.make_client(other, actor="source-bob")
        self.addCleanup(client.close)
        bob_ref = self.ref(source_actor="source-bob", source_handle="q" * 43, anchor_revision=revision(other.anchor), invocation_id="invocation-b")
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(self.client.resolve_source, self.reference)
            b = pool.submit(client.resolve_source, bob_ref)
            alice, bob = a.result().invocation, b.result().invocation
        self.assertEqual(alice.requester, "source-alice")
        self.assertEqual(bob.requester, "source-bob")
        count = len(self.server.calls)
        with self.assertRaises(ContextError):
            self.client.read(bob)
        self.assertEqual(len(self.server.calls), count)
        with self.assertRaises(ContextError):
            self.client.resolve_source(self.ref(session_id="43"))
        self.assertEqual(self.client.read(alice)[0][-1].author, "source-alice")


if __name__ == "__main__":
    unittest.main()
