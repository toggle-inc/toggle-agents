import json
import tempfile
import time
import unittest
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from runtime.auth_store import SQLiteAuthorizationStore
from runtime.okta_oidc import OktaOIDCLogin
from starlette.requests import Request


class _Response:
    def __init__(self, payload, status_code=200):
        self._payload, self.status_code = payload, status_code

    def json(self):
        return self._payload


class _HTTPClient:
    def __init__(self, owner, **_):
        self.owner = owner

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def get(self, url, **_):
        if url.endswith("/.well-known/openid-configuration"):
            return _Response(self.owner.metadata)
        if url == self.owner.metadata["jwks_uri"]:
            return _Response({"keys": [self.owner.jwk]})
        return _Response({}, 404)

    async def post(self, _url, **kwargs):
        self.owner.token_request = kwargs
        return _Response({"id_token": self.owner.issue_id_token()})


class OktaOIDCLoginTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteAuthorizationStore(Path(self.temp.name) / "auth.sqlite3")
        self.issuer = "https://toggle.okta.com/oauth2/default"
        self.app_origin = "https://expense.example.test"
        self.client_id = "expense-client"
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key()))
        self.jwk["kid"] = "test-key"
        self.jwk["alg"] = "RS256"
        self.jwk["use"] = "sig"
        self.metadata = {
            "issuer": self.issuer,
            "authorization_endpoint": self.issuer + "/v1/authorize",
            "token_endpoint": self.issuer + "/v1/token",
            "jwks_uri": self.issuer + "/v1/keys",
        }
        self.token_claim_overrides = {}
        self.token_request = None
        self.resolved = []

        def resolve_person(tenant, issuer, subject):
            self.resolved.append((tenant, issuer, subject))
            return "person-canonical-1" if subject == "okta-sub-1" else None

        self.adapter = OktaOIDCLogin(
            self.store,
            resolve_person,
            issuer=self.issuer,
            client_id=self.client_id,
            client_secret="test-only-client-secret",
            callback_uri=self.app_origin + "/login/callback",
            tenant_id="tenant-10",
            state_encryption_key="test-only-state-key-material-long-enough",
            clock=time.time,
            http_client_factory=lambda **kwargs: _HTTPClient(self, **kwargs),
        )

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def issue_id_token(self):
        claims = {
            "iss": self.issuer,
            "aud": self.client_id,
            "sub": "okta-sub-1",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
            "nonce": self.expected_nonce,
            **self.token_claim_overrides,
        }
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": "test-key"})

    def authorize_request(self):
        query = (
            "client_id=sa&redirect_uri=https%3A%2F%2Fsa.example.test%2Fcallback&state=client-state"
        )
        scope = {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "server": ("expense.example.test", 443),
            "client": ("127.0.0.1", 1),
            "root_path": "",
            "path": "/oauth/authorize",
            "raw_path": b"/oauth/authorize",
            "query_string": query.encode(),
            "headers": [(b"host", b"expense.example.test")],
        }
        return Request(scope)

    async def begin(self):
        response = await self.adapter.start_login(self.authorize_request())
        location = response.headers["location"]
        query = parse_qs(urlsplit(location).query)
        self.expected_nonce = query["nonce"][0]
        return query

    async def callback_request(self, state):
        query = f"state={state}&code=single-use-code"
        scope = {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "server": ("expense.example.test", 443),
            "client": ("127.0.0.1", 1),
            "root_path": "",
            "path": "/login/callback",
            "raw_path": b"/login/callback",
            "query_string": query.encode(),
            "headers": [(b"host", b"expense.example.test")],
        }
        return await self.adapter.callback(Request(scope))

    async def test_pkce_callback_creates_expiring_server_side_canonical_session(self):
        query = await self.begin()
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        response = await self.callback_request(query["state"][0])
        self.assertEqual(response.status_code, 303)
        self.assertTrue(
            response.headers["location"].startswith(self.app_origin + "/oauth/authorize?")
        )
        self.assertIn("Secure", response.headers["set-cookie"])
        self.assertIn("HttpOnly", response.headers["set-cookie"])
        self.assertIn("SameSite=lax", response.headers["set-cookie"])
        cookie = SimpleCookie()
        cookie.load(response.headers["set-cookie"])
        session_id = cookie["expense_session"].value
        request = Request(
            {"type": "http", "headers": [(b"cookie", f"expense_session={session_id}".encode())]}
        )
        person = self.adapter.verify_login(request)
        self.assertEqual(person.tenant_id, "tenant-10")
        self.assertEqual(person.person_id, "person-canonical-1")
        self.assertEqual(self.resolved, [("tenant-10", self.issuer, "okta-sub-1")])
        self.assertEqual(
            self.token_request["data"]["redirect_uri"], self.app_origin + "/login/callback"
        )
        self.assertGreaterEqual(len(self.token_request["data"]["code_verifier"]), 43)

    async def test_logout_revokes_server_session_and_clears_cookie(self):
        query = await self.begin()
        response = await self.callback_request(query["state"][0])
        cookie = SimpleCookie()
        cookie.load(response.headers["set-cookie"])
        session_id = cookie["expense_session"].value
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "scheme": "https",
                "server": ("expense.example.test", 443),
                "client": ("127.0.0.1", 1),
                "root_path": "",
                "path": "/logout",
                "raw_path": b"/logout",
                "query_string": b"",
                "headers": [
                    (b"host", b"expense.example.test"),
                    (b"origin", b"https://expense.example.test"),
                    (b"cookie", f"expense_session={session_id}".encode()),
                ],
            }
        )
        logout_response = await self.adapter.logout(request)
        self.assertEqual(logout_response.status_code, 204)
        self.assertIn("Max-Age=0", logout_response.headers["set-cookie"])
        self.assertIsNone(self.adapter.verify_login(request))

    async def test_state_is_single_use_and_wrong_nonce_is_rejected(self):
        query = await self.begin()
        state = query["state"][0]
        first = await self.callback_request(state)
        second = await self.callback_request(state)
        self.assertEqual(first.status_code, 303)
        self.assertEqual(second.status_code, 400)
        self.assertEqual(len(self.resolved), 1)

        query = await self.begin()
        self.token_claim_overrides = {"nonce": "wrong-nonce"}
        response = await self.callback_request(query["state"][0])
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(self.resolved), 1)

    async def test_unlinked_subject_is_rejected_without_email_fallback(self):
        query = await self.begin()
        self.token_claim_overrides = {"sub": "unlinked-subject", "email": "person@example.test"}
        response = await self.callback_request(query["state"][0])
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.resolved[-1][2], "unlinked-subject")
        self.assertIsNone(self.adapter.verify_login(Request({"type": "http", "headers": []})))

    async def test_invalid_audience_issuer_and_expiry_are_rejected(self):
        for override in (
            {"aud": "another-client"},
            {"iss": "https://attacker.example.test"},
            {"exp": int(time.time()) - 120},
            {"aud": [self.client_id, "another-client"], "azp": "another-client"},
        ):
            with self.subTest(override=override):
                query = await self.begin()
                self.token_claim_overrides = override
                response = await self.callback_request(query["state"][0])
                self.assertEqual(response.status_code, 400)
        self.assertEqual(self.resolved, [])

    async def test_metadata_issuer_mismatch_and_cross_origin_endpoint_fail_closed(self):
        self.metadata["issuer"] = "https://attacker.example.test"
        with self.assertRaises(Exception):
            await self.adapter._get_metadata()
        self.metadata["issuer"] = self.issuer
        self.metadata["jwks_uri"] = "https://attacker.example.test/keys"
        self.adapter._metadata = None
        with self.assertRaises(Exception):
            await self.adapter._get_metadata()


if __name__ == "__main__":
    unittest.main()
