"""Signed platform requests -> consent -> OAuth/MCP; no real SA, Okta or MF."""

import functools
import hashlib
import json
import secrets
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
import test_authorization as auth_fixture
from _foundation import test_platform_identity as identity_fixture
from _foundation.platform_identity import (
    ASSERTION_TYPE,
    PlatformIdentityVerifier,
    PlatformPersonLink,
)
from authorization_app import create_app
from authorization_host import PlatformAuthorizationHostSettings, create_platform_host
from runtime.authorization import AgentAuthorization
from runtime.platform_login import PlatformLogin
from runtime.providers import Receipts
from runtime.requester import ConnectionGrant
from runtime.service import ExpenseService
from runtime.state import State
from test_authorization import CHALLENGE, VERIFIER
from test_authorization_app import FormParser
from test_requester import SyntheticMF


def with_platform_server(function):
    @functools.wraps(function)
    async def run(self):
        app = self.app.app.app
        async with app.router.lifespan_context(app):
            return await function(self)

    return run


class PlatformLoginTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        identity_fixture.PlatformIdentityTests.setUpClass()
        cls.key = identity_fixture.PlatformIdentityTests.key
        cls.public = identity_fixture.PlatformIdentityTests.public

    async def asyncSetUp(self):
        self.fixture = auth_fixture.AuthorizationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.origin, self.platform = "https://expense.example.test", "https://sa.example.test"
        self.now = time.time()
        self.services = {}
        for name, person in self.fixture.people.items():
            root = Path(self.fixture.directory.name) / person.owner
            service = ExpenseService(
                mf=SyntheticMF(person.owner, name),
                state=State(root / "state.sqlite", person.owner),
                receipts=Receipts(root / "receipts", None, person.owner),
            )
            self.addCleanup(service.state.close)
            self.services[name] = service
        self.verifier = PlatformIdentityVerifier(
            self.fixture.store,
            lambda issuer, tenant, sub: PlatformPersonLink("synthetic-tenant", sub)
            if issuer == self.platform and tenant == "sa-tenant" and sub in self.services
            else None,
            issuer=self.platform,
            audience=self.origin,
            tenant_id="synthetic-tenant",
            public_keys={"synthetic-key": self.public},
        )
        self.login = PlatformLogin(self.verifier)
        self.authority = AgentAuthorization(
            self.fixture.store,
            self.login.verify_login,
            issuer=self.origin,
            tenant_id="synthetic-tenant",
            clients=self.fixture.clients,
        )
        self.resolve = lambda person, capability: ConnectionGrant(
            person.tenant_id,
            person.person_id,
            self.now + 3000,
            frozenset({"mf:read"}),
            self.services[person.person_id],
            agent_slug="expense_assistant",
        )
        self.app = self.login.wrap(
            create_app(self.authority, self.resolve, platform_login=self.login)
        )
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(self.app), base_url=self.origin
        )
        self.addAsyncCleanup(self.client.aclose)

    def signed(self, method, path, body=b"", *, person="alice", claims=None):
        values = {
            "iss": self.platform,
            "aud": self.origin,
            "sub": person,
            "tenant_id": "sa-tenant",
            "actor_type": "human",
            "purpose": "platform_login",
            "iat": self.now,
            "exp": self.now + 60,
            "auth_expires_at": self.now + 3000,
            "jti": secrets.token_urlsafe(24),
            "method": method,
            "target": self.origin + path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "origin": self.platform if method == "POST" else "",
        }
        token = jwt.encode(
            {**values, **(claims or {})},
            self.key,
            algorithm="RS256",
            headers={"kid": "synthetic-key", "typ": ASSERTION_TYPE},
        )
        return {
            "x-agent-platform-assertion": token,
            **({"origin": self.platform} if method == "POST" else {}),
        }

    def authorize_path(self):
        return "/oauth/authorize?" + urlencode(
            {
                "response_type": "code",
                "client_id": "sa",
                "redirect_uri": self.platform + "/callback",
                "resource": self.origin + "/mcp",
                "scope": "mf:read",
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
                "state": "synthetic-platform-state",
            }
        )

    async def consent(self, person="alice"):
        path = self.authorize_path()
        page = await self.client.get(path, headers=self.signed("GET", path, person=person))
        self.assertEqual(page.status_code, 200, page.text)
        self.assertNotIn("okta", page.text.lower())
        self.assertNotIn("set-cookie", page.headers)
        body = urlencode({**FormParser(page.text).fields, "decision": "approve"}).encode()
        return await self.client.post(
            "/oauth/consent",
            content=body,
            headers={
                **self.signed("POST", "/oauth/consent", body, person=person),
                "content-type": "application/x-www-form-urlencoded",
            },
        )

    @with_platform_server
    async def test_logged_in_platform_people_consent_and_receive_only_their_mcp_data(self):
        for person in ("alice", "bob"):
            reply = await self.consent(person)
            self.assertEqual(reply.status_code, 303, reply.text)
            code = parse_qs(urlsplit(reply.headers["location"]).query)["code"][0]
            token = await self.client.post(
                "/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": "sa",
                    "redirect_uri": self.platform + "/callback",
                    "resource": self.origin + "/mcp",
                    "code_verifier": VERIFIER,
                },
            )
            self.assertEqual(token.status_code, 200, token.text)
            result = await self.client.post(
                "/mcp",
                headers={
                    "authorization": "Bearer " + token.json()["access_token"],
                    "accept": "application/json, text/event-stream",
                    "mcp-protocol-version": "2025-03-26",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "mf_offices", "arguments": {}},
                },
            )
            self.assertEqual(result.status_code, 200, result.text)
            payload = result.json()["result"]
            offices = payload.get("structuredContent") or json.loads(payload["content"][0]["text"])
            self.assertIn(person, json.dumps(offices))
            self.assertNotIn("bob" if person == "alice" else "alice", json.dumps(offices))

    async def test_unsigned_or_reused_assertion_never_becomes_a_login(self):
        path = self.authorize_path()
        unsigned = await self.client.get(path, headers={"x-user-id": "alice"})
        self.assertEqual(unsigned.status_code, 401)
        headers = self.signed("GET", path)
        first = await self.client.get(path, headers=headers)
        second = await self.client.get(path, headers=headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 401)
        self.assertNotIn("set-cookie", second.headers)

    @with_platform_server
    async def test_platform_identity_proof_does_not_grant_mcp_access(self):
        proof = self.signed("GET", self.authorize_path())["x-agent-platform-assertion"]
        response = await self.client.post(
            "/mcp",
            headers={
                "authorization": "Bearer " + proof,
                "accept": "application/json, text/event-stream",
                "mcp-protocol-version": "2025-03-26",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "mf_offices", "arguments": {}},
            },
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.services["alice"].mf.calls, 0)

    async def test_signed_get_does_not_authorize_a_different_person_post_or_modified_body(self):
        path = self.authorize_path()
        page = await self.client.get(path, headers=self.signed("GET", path))
        body = urlencode({**FormParser(page.text).fields, "decision": "approve"}).encode()
        bob = await self.client.post(
            "/oauth/consent",
            content=body,
            headers={
                **self.signed("POST", "/oauth/consent", body, person="bob"),
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        self.assertEqual(bob.status_code, 400)
        altered = await self.client.post(
            "/oauth/consent",
            content=body + b"&scope=mf:write",
            headers={
                **self.signed("POST", "/oauth/consent", body),
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        self.assertEqual(altered.status_code, 401)

    async def test_expired_unlinked_wrong_origin_and_duplicate_headers_fail_closed(self):
        path = self.authorize_path()
        variants = [{"sub": "unlinked"}, {"exp": self.now - 1}, {"purpose": "agent:run"}]
        for claims in variants:
            with self.subTest(claims=claims):
                response = await self.client.get(
                    path, headers=self.signed("GET", path, claims=claims)
                )
                self.assertEqual(response.status_code, 401)
        headers = self.signed("GET", path)
        response = await self.client.get(
            path, headers=list(headers.items()) + list(headers.items())
        )
        self.assertEqual(response.status_code, 401)

    async def test_platform_factory_needs_no_okta_secrets_or_callback(self):
        settings = PlatformAuthorizationHostSettings(
            self.origin,
            "synthetic-tenant",
            self.platform,
            {"synthetic-key": self.public},
            tuple(self.fixture.clients),
            "postgresql://synthetic:synthetic@db.example.test/qa?sslmode=verify-full",
        )
        with patch.dict("os.environ", {}, clear=True):
            app = create_platform_host(
                settings,
                resolve_person=self.verifier.resolve_person,
                resolve_connection=self.resolve,
                store_factory=lambda _: self.fixture.store,
            )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url=self.origin
        ) as client:
            path = self.authorize_path()
            reply = await client.get(path, headers=self.signed("GET", path))
            self.assertEqual(reply.status_code, 200, reply.text)
            self.assertNotIn("set-cookie", reply.headers)
            callback = await client.get("/login/callback")
            self.assertNotEqual(callback.status_code, 200)

    async def test_json_consent_view_is_plain_data_and_keeps_agent_policy(self):
        path = self.authorize_path()
        reply = await self.client.get(
            path, headers={**self.signed("GET", path), "accept": "application/json"}
        )
        self.assertEqual(reply.status_code, 200, reply.text)
        data = reply.json()
        self.assertEqual(data["schema_version"], "agent-consent/v1")
        self.assertEqual(data["capabilities"][0]["id"], "mf:read")
        self.assertEqual(data["draft_companies"], [])
        self.assertGreater(data["expires_at"], self.now + 200)
        self.assertEqual(reply.headers["cache-control"], "no-store")


if __name__ == "__main__":
    unittest.main()
