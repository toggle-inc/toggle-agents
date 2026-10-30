"""Real C signatures and bounded streams against MockTransport; no live SA/MF."""

from contextvars import ContextVar
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.parse import quote

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _foundation.execution_binding import ExecutionTarget
from runtime.history_request import HistoryRequestBinding
from runtime.requester import Requester
from runtime.sa_attachment_client import SAAttachmentClient, MANIFEST_PATH, ATTACHMENT_PATH
from runtime.state import ExpenseError
import test_sa_history_client as history_fixtures


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


class CountingStream(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks, self.consumed, self.closed = chunks, 0, 0

    def __iter__(self):
        for chunk in self.chunks:
            self.consumed += 1
            yield chunk

    def close(self):
        self.closed += 1


class SyntheticAttachmentSA:
    def __init__(self, fixture):
        self.fixture, self.calls, self.claims, self.replay = fixture, [], [], set()
        self.allowed = True
        self.status = 200
        self.manifest_transform = lambda value: value
        self.response_transform = lambda request, response: response
        self.content = b"%PDF-1.4\nsynthetic attachment only"
        self.item = {"id": "file-a", "filename": "領収書 !'()~.pdf",
                     "contentType": "application/pdf", "size": len(self.content)}
        self.attachment_headers = {}

    def __call__(self, request):
        self.calls.append(request)
        assert request.method == "POST"
        assert str(request.url) in {"https://sa.example.test" + MANIFEST_PATH,
                                    "https://sa.example.test" + ATTACHMENT_PATH}
        assert request.headers["accept-encoding"] == "identity"
        assert request.headers["content-type"] == "application/json"
        for name in ("authorization", "cookie", "x-agent-source-context", "x-agent-execution-proof"):
            assert name not in request.headers
        token = request.headers["x-agent-source-read-proof"]
        assert jwt.get_unverified_header(token) == {
            "alg": "RS256", "kid": "read-key", "typ": "agent-source-read+jwt"}
        claims = jwt.decode(token, self.fixture.public, algorithms=["RS256"],
                            issuer="https://agent.example.test", audience="https://sa.example.test",
                            options={"verify_exp": False, "verify_iat": False})
        expected_purpose = "source_attachment_manifest" if request.url.path == MANIFEST_PATH else "source_attachment_read"
        assert set(claims) == {"iss", "aud", "iat", "exp", "jti", "purpose", "source_namespace",
            "source_actor", "source_actor_type", "target_tenant_id", "target_agent_id", "target_version_id",
            "connection_id", "invocation_id", "session_id", "source_handle_sha256", "method", "target", "body_sha256"}
        assert claims["purpose"] == expected_purpose
        assert (claims["source_namespace"], claims["source_actor"], claims["source_actor_type"]) == (
            "source-tenant", "source-alice", "human")
        assert tuple(claims[k] for k in ("target_tenant_id", "target_agent_id", "target_version_id", "connection_id")) == (
            "10", "12", "18", "60")
        assert claims["method"] == "POST" and claims["target"] == str(request.url)
        assert claims["body_sha256"] == sha(request.content)
        assert claims["source_handle_sha256"] == sha(b"h" * 43)
        assert claims["iat"] <= self.fixture.now < claims["exp"] <= min(claims["iat"] + 60, 180)
        replay = (claims["iss"], claims["aud"], claims["jti"])
        assert replay not in self.replay  # Purpose deliberately excluded.
        self.replay.add(replay)
        self.claims.append(claims)
        body = json.loads(request.content)
        assert set(body) == ({"source_handle", "invocation_id", "session_id"} if request.url.path == MANIFEST_PATH
                             else {"source_handle", "invocation_id", "session_id", "attachment_id"})
        assert body["source_handle"] == "h" * 43
        assert (body["invocation_id"], body["session_id"]) == (claims["invocation_id"], claims["session_id"])
        assert body["invocation_id"] == "invocation-a" and body["session_id"] == "42"
        if self.status != 200 or not self.allowed:
            return httpx.Response(self.status if self.allowed else 401,
                                  headers={"location": "https://evil.example.test/"})
        if request.url.path == MANIFEST_PATH:
            items = [copy.deepcopy(self.item)]
            data = {"schemaVersion": "source-attachment-manifest/v1", "invocationId": "invocation-a",
                    "sourceMessageId": "anchor", "attachments": items,
                    "manifestSha256": sha(encoded(items)), "expiresAt": claims["exp"] * 1000}
            response = httpx.Response(200, content=encoded(self.manifest_transform(data)),
                                      headers={"content-type": "application/json", "cache-control": "private, no-store"})
        else:
            assert body["attachment_id"] == self.item["id"]
            headers = {"content-type": "application/octet-stream", "cache-control": "private, no-store",
                       "content-length": str(len(self.content)), "x-attachment-id": self.item["id"],
                       "x-attachment-filename": quote(self.item["filename"], safe="~()*!.'-_"),
                       "x-attachment-content-type": self.item["contentType"], "x-attachment-sha256": sha(self.content),
                       **self.attachment_headers}
            response = httpx.Response(200, stream=CountingStream([self.content]), headers=headers)
        return self.response_transform(request, response)


class SAAttachmentClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        history_fixtures.SAHistoryClientTests.setUpClass()
        cls.private = history_fixtures.SAHistoryClientTests.private
        cls.public = history_fixtures.SAHistoryClientTests.public

    def setUp(self):
        # The original anchor comes from the real snapshot validator, not the
        # manifest response or a model-provided message identifier.
        self.history = history_fixtures.SAHistoryClientTests()
        self.history.setUp()
        self.addCleanup(self.history.doCleanups)
        self.reference = self.history.reference
        self.invocation = self.history.client.resolve_source(self.reference).invocation
        self.person = Requester("canonical-tenant", "canonical-alice", 180)
        self.binding = HistoryRequestBinding(self.person.tenant_id, self.person.person_id, self.invocation)
        self.context = ContextVar("synthetic-verified-attachment-binding", default=None)
        self.reset = self.context.set(self.binding)
        self.addCleanup(self.context.reset, self.reset)
        self.server = SyntheticAttachmentSA(self.history)
        self.http = httpx.Client(transport=httpx.MockTransport(self.server))
        self.client = self.make_client()
        self.addCleanup(self.client.close)

    def make_client(self, **changes):
        options = dict(origin="https://sa.example.test", agent_origin="https://agent.example.test",
                       source_namespace="source-tenant", source_actor="source-alice", target=self.reference.target,
                       kid="read-key", signing_private_key=self.private, owner=self.person.owner,
                       resolve_binding=self.context.get, http=self.http, clock=lambda: self.history.now)
        options.update(changes)
        return SAAttachmentClient(**options)

    def test_manifest_and_get_use_real_signed_requests_fresh_jti_and_no_shared_token(self):
        manifest = self.client.manifest()
        self.assertEqual(manifest["sourceMessageId"], self.invocation.anchor)
        self.assertEqual(self.client.get("attachment:file-a"), (self.server.content, "application/pdf"))
        self.assertEqual(len(self.server.calls), 3)
        self.assertEqual(len(self.server.replay), 3)
        self.assertEqual([v["purpose"] for v in self.server.claims], [
            "source_attachment_manifest", "source_attachment_manifest", "source_attachment_read"])
        self.assertEqual(self.client.owner, self.person.owner)

    def test_bounded_source_wait_allows_slow_response_without_extending_proof(self):
        def delayed(request, response):
            self.assertEqual(request.extensions["timeout"]["read"], 30)
            self.history.now += 12
            return response
        self.server.response_transform = delayed
        self.assertEqual(self.client.manifest()["sourceMessageId"], "anchor")
        self.assertLessEqual(self.server.claims[0]["exp"] - self.server.claims[0]["iat"], 60)
        self.assertEqual(len(self.server.calls), 1)

    def test_timeout_has_fixed_safe_diagnostic_and_is_not_retried(self):
        def timeout(request, response):
            raise httpx.ReadTimeout("untrusted secret-bearing response must not leak", request=request)
        self.server.response_transform = timeout
        with self.assertRaises(ExpenseError) as caught:
            self.client.manifest()
        self.assertIn("response_timeout", str(caught.exception))
        self.assertNotIn("untrusted", str(caught.exception))
        self.assertEqual(len(self.server.calls), 1)

    def test_only_opaque_references_are_accepted_before_http(self):
        for value in (None, {}, "https://evil.example.test/a", "http://localhost/a", "file:///tmp/a",
                      "attachment:", "attachment:../file-a", "attachment:file-a?x=1", "file-a"):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(ExpenseError):
                    self.client.get(value)
        self.assertEqual(self.server.calls, [])

    def test_missing_model_json_cross_person_and_untrusted_anchor_fail_before_http(self):
        for binding in (None, {"reference": self.reference, "sourceMessageId": "anchor"},
                        replace(self.binding, person_id="canonical-bob"),
                        replace(self.binding, tenant_id="another-tenant"),
                        replace(self.binding, invocation=replace(self.invocation, client_binding=None))):
            self.context.set(binding)
            with self.assertRaises(ExpenseError):
                self.client.get("attachment:file-a")
        self.assertEqual(self.server.calls, [])

    def test_reference_tuple_namespace_actor_and_expiry_are_required_before_http(self):
        for changes in ({"source_issuer": "https://other.example.test"}, {"source_namespace": "other"},
                        {"source_actor": "source-bob"}, {"target": ExecutionTarget("10", "12", "19", "60")},
                        {"target": ExecutionTarget("10", "12", "18", "61")}, {"session_id": "043"},
                        {"session_id": "0"}, {"source_handle": "bad"}, {"expires_at": 100},
                        {"expires_at": float("nan")}, {"anchor_revision": "bad"}):
            with self.subTest(fields=list(changes)):
                ref = replace(self.reference, **changes)
                self.context.set(replace(self.binding, invocation=replace(self.invocation, reference=ref)))
                with self.assertRaises(ExpenseError):
                    self.client.manifest()
        self.assertEqual(self.server.calls, [])

    def test_manifest_is_bound_to_exact_invocation_anchor_hash_and_metadata(self):
        cases = [("schemaVersion", "other"), ("invocationId", "other"), ("sourceMessageId", "other-anchor"),
                 ("manifestSha256", "a" * 64), ("expiresAt", 100000), ("expiresAt", 180001),
                 ("expiresAt", True), ("attachments", "not-a-list")]
        for key, value in cases:
            self.server.manifest_transform = lambda data, k=key, v=value: {**data, k: v}
            with self.subTest(key=key), self.assertRaises(ExpenseError):
                self.client.manifest()
        for changed in ({"size": True}, {"size": -1}, {"size": 1.5}, {"filename": "bad\nname"},
                        {"id": "../file"}, {"contentType": ""}, {"extra": "no"}):
            def transform(data, change=changed):
                data["attachments"][0].update(change)
                data["manifestSha256"] = sha(encoded(data["attachments"]))
                return data
            self.server.manifest_transform = transform
            with self.subTest(changed=changed), self.assertRaises(ExpenseError):
                self.client.manifest()
        self.server.manifest_transform = lambda data: {**data, "extra": "no"}
        with self.assertRaises(ExpenseError):
            self.client.manifest()

    def test_duplicate_manifest_ids_and_unknown_attachment_never_fetch_binary(self):
        def duplicate(data):
            data["attachments"] *= 2
            data["manifestSha256"] = sha(encoded(data["attachments"]))
            return data
        self.server.manifest_transform = duplicate
        with self.assertRaises(ExpenseError):
            self.client.get("attachment:file-a")
        self.server.manifest_transform = lambda data: data
        with self.assertRaises(ExpenseError):
            self.client.get("attachment:other")
        self.assertTrue(all(r.url.path == MANIFEST_PATH for r in self.server.calls))

    def test_unsupported_type_and_over_agent_limit_reject_before_binary(self):
        for changes in ({"contentType": "text/plain"}, {"size": 0}, {"size": 10 * 1024 * 1024 + 1}):
            original = dict(self.server.item)
            self.server.item.update(changes)
            with self.assertRaises(ExpenseError):
                self.client.get("attachment:file-a")
            self.server.item = original
        self.assertTrue(all(r.url.path == MANIFEST_PATH for r in self.server.calls))

    def test_all_non200_and_redirects_fail_closed_at_both_endpoints(self):
        for status in (301, 302, 303, 307, 308, 401, 404, 413, 502):
            with self.subTest(status=status):
                self.server.status = status
                with self.assertRaises(ExpenseError):
                    self.client.manifest()
                self.server.status = 200
                self.server.response_transform = lambda req, resp, status=status: (
                    httpx.Response(status, headers={"location": "https://evil.example.test"})
                    if req.url.path == ATTACHMENT_PATH else resp)
                with self.assertRaises(ExpenseError):
                    self.client.get("attachment:file-a")
                self.server.response_transform = lambda req, resp: resp
        self.assertTrue(all(r.url.host == "sa.example.test" for r in self.server.calls))

    def test_binary_metadata_size_and_hash_are_exact(self):
        for headers in ({"content-length": "1"}, {"x-attachment-id": "other"},
                        {"x-attachment-filename": "other.pdf"}, {"x-attachment-filename": "%zz"},
                        {"x-attachment-content-type": "image/png"}, {"x-attachment-sha256": "a" * 64},
                        {"x-attachment-sha256": "bad"}, {"content-type": "application/pdf"},
                        {"cache-control": "public"}):
            self.server.attachment_headers = headers
            with self.subTest(headers=headers), self.assertRaises(ExpenseError):
                self.client.get("attachment:file-a")
        self.server.attachment_headers = {}
        self.server.content += b"extra bytes beyond manifest size"
        with self.assertRaises(ExpenseError):
            self.client.get("attachment:file-a")

    def test_compression_and_duplicate_security_headers_reject_before_stream_consumption(self):
        for path in (MANIFEST_PATH, ATTACHMENT_PATH):
            for values in (["gzip"], ["br"], ["deflate"], ["gzip, identity"], ["identity", "identity"],
                           [""], ["identity", "gzip"]):
                stream = CountingStream([b"do not decode this"])
                def transform(req, response):
                    if req.url.path != path:
                        return response
                    return httpx.Response(200, stream=stream, headers=[
                        ("content-type", "application/json" if path == MANIFEST_PATH else "application/octet-stream"),
                        ("cache-control", "no-store"),
                        *(("content-encoding", v) for v in values)])
                self.server.response_transform = transform
                with self.subTest(path=path, values=values), self.assertRaises(ExpenseError):
                    self.client.get("attachment:file-a")
                self.assertEqual((stream.consumed, stream.closed), (0, 1))
        stream = CountingStream([b"unused"])
        self.server.response_transform = lambda req, response: (
            httpx.Response(200, stream=stream, headers=[("content-type", "application/json"),
                ("content-type", "application/json"), ("cache-control", "no-store")])
            if req.url.path == MANIFEST_PATH else response)
        with self.assertRaises(ExpenseError):
            self.client.manifest()
        self.assertEqual((stream.consumed, stream.closed), (0, 1))

    def test_manifest_stream_limit_and_duplicate_json_keys_fail_closed(self):
        for raw in (b"x" * (1024 * 1024 + 1), b'{"schemaVersion":"a","schemaVersion":"b"}'):
            stream = CountingStream([raw])
            self.server.response_transform = lambda req, response: httpx.Response(
                200, stream=stream, headers={"content-type": "application/json", "cache-control": "no-store"})
            with self.assertRaises(ExpenseError):
                self.client.manifest()
            self.assertEqual(stream.closed, 1)

    def test_binary_stream_cannot_exceed_manifest_size_or_forge_hash(self):
        for chunks, expected_consumed in (([self.server.content, b"excess", b"not consumed"], 2),
                                          ([b"x" * len(self.server.content)], 1),
                                          ([self.server.content[:-1]], 1)):
            stream = CountingStream(chunks)
            def transform(req, response):
                if req.url.path == ATTACHMENT_PATH:
                    return httpx.Response(200, stream=stream, headers=response.headers)
                return response
            self.server.response_transform = transform
            with self.assertRaises(ExpenseError):
                self.client.get("attachment:file-a")
            self.assertEqual((stream.consumed, stream.closed), (expected_consumed, 1))

    def test_identity_encoding_and_duplicate_binary_headers(self):
        self.server.attachment_headers = {"content-encoding": "identity"}
        self.assertEqual(self.client.get("attachment:file-a"), (self.server.content, "application/pdf"))
        for header in ("x-attachment-id", "x-attachment-filename", "x-attachment-content-type",
                       "x-attachment-sha256", "content-length", "cache-control"):
            stream = CountingStream([self.server.content])
            def transform(req, response):
                if req.url.path == ATTACHMENT_PATH:
                    pairs = list(response.headers.multi_items())
                    pairs.append((header, response.headers[header]))
                    return httpx.Response(200, stream=stream, headers=pairs)
                return response
            self.server.response_transform = transform
            with self.subTest(header=header), self.assertRaises(ExpenseError):
                self.client.get("attachment:file-a")
            self.assertEqual((stream.consumed, stream.closed), (0, 1))

    def test_source_acl_revocation_fails_without_binary_fallback(self):
        self.server.allowed = False
        with self.assertRaises(ExpenseError):
            self.client.get("attachment:file-a")
        self.assertEqual(len(self.server.calls), 1)
        self.server.allowed = True
        self.server.response_transform = lambda req, response: (
            httpx.Response(401) if req.url.path == ATTACHMENT_PATH else response)
        with self.assertRaises(ExpenseError):
            self.client.get("attachment:file-a")
        self.assertEqual(len(self.server.calls), 3)

    def test_expiry_and_context_change_during_either_response_prevent_return(self):
        for path in (MANIFEST_PATH, ATTACHMENT_PATH):
            for change in ("expiry", "owner", "anchor", "reference", "closed"):
                self.history.now = 100
                self.context.set(self.binding)
                def transform(req, response):
                    if req.url.path == path:
                        if change == "expiry":
                            self.history.now = 181
                        elif change == "owner":
                            self.context.set(replace(self.binding, person_id="canonical-bob"))
                        elif change == "anchor":
                            self.context.set(replace(self.binding, invocation=replace(self.invocation, anchor="other")))
                        elif change == "reference":
                            self.context.set(replace(self.binding, invocation=replace(
                                self.invocation, reference=replace(self.reference))))
                        else:
                            self.client.close()
                    return response
                self.server.response_transform = transform
                with self.subTest(path=path, change=change), self.assertRaises(ExpenseError):
                    self.client.get("attachment:file-a")
                if change == "closed":
                    # Close is separately verified below; use a new owned mock
                    # client for the next scheduled boundary.
                    self.http = httpx.Client(transport=httpx.MockTransport(self.server))
                    self.client = self.make_client()
                    self.addCleanup(self.client.close)

    def test_js_stringify_unicode_and_field_order_hash_matches(self):
        # JS JSON.stringify emits UTF-8 Unicode (including U+2028 and emoji)
        # and the schema's id/filename/contentType/size property order.
        self.server.item["filename"] = '領収書😀\u2028"\\.pdf'
        def reorder(data):
            data["attachments"] = [dict(reversed(list(data["attachments"][0].items())))]
            return data
        self.server.manifest_transform = reorder
        self.assertEqual(self.client.get("attachment:file-a"), (self.server.content, "application/pdf"))

    def test_closed_is_idempotent_and_never_sends_or_keeps_key(self):
        self.client.close()
        self.client.close()
        self.assertIsNone(self.client._key)
        for call in (self.client.manifest, lambda: self.client.get("attachment:file-a")):
            with self.assertRaises(ExpenseError):
                call()
        self.assertEqual(self.server.calls, [])

    def test_injected_shared_credentials_cookies_and_auth_are_never_sent(self):
        for header in ("Authorization", "Cookie", "Proxy-Authorization"):
            self.http.headers[header] = "synthetic-do-not-send"
            with self.subTest(header=header), self.assertRaises(ExpenseError):
                self.client.manifest()
            del self.http.headers[header]
        self.http.auth = ("synthetic-user", "synthetic-password")
        with self.assertRaises(ExpenseError):
            self.client.manifest()
        self.http.auth = None
        self.http.cookies.set("synthetic", "do-not-send")
        with self.assertRaises(ExpenseError):
            self.client.manifest()
        self.assertEqual(self.server.calls, [])

    def test_expiry_during_signing_sends_nothing(self):
        original = jwt.encode
        def delayed(*args, **kwargs):
            result = original(*args, **kwargs)
            self.history.now = 181
            return result
        with patch("runtime.sa_attachment_client.jwt.encode", side_effect=delayed):
            with self.assertRaises(ExpenseError):
                self.client.manifest()
        self.assertEqual(self.server.calls, [])

    def test_explicit_config_rejects_weak_key_bad_target_and_noncanonical_owner(self):
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        for options in ({"origin": "http://sa.example.test"}, {"origin": "https://sa.example.test/path"},
                        {"signing_private_key": weak}, {"signing_private_key": "not-a-private-key"},
                        {"owner": "source-alice"}, {"resolve_binding": None}, {"kid": "bad kid"},
                        {"target": ExecutionTarget("10", "12", "v18", "60")}):
            with self.subTest(fields=list(options)), self.assertRaises(ValueError):
                self.make_client(**options)
        self.assertEqual(self.server.calls, [])


if __name__ == "__main__":
    unittest.main()
