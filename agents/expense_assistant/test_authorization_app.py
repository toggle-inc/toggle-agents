"""Consent page -> PKCE exchange -> real issued Bearer -> MCP, synthetic SSO/MF."""

import dataclasses
import json
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_authorization as auth_fixture  # noqa: E402
from authorization_app import create_app  # noqa: E402
from runtime.authorization import CAPABILITIES  # noqa: E402
from runtime.providers import Receipts  # noqa: E402
from runtime.requester import ConnectionGrant  # noqa: E402
from runtime.service import ExpenseService  # noqa: E402
from runtime.state import State  # noqa: E402
from test_authorization import CHALLENGE, VERIFIER  # noqa: E402
from test_requester import SyntheticMF  # noqa: E402
from test_requester_mcp import with_server  # noqa: E402


class FormParser(HTMLParser):
    def __init__(self, value):
        super().__init__()
        self.fields = {}
        self.feed(value)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input":
            self.fields[attrs["name"]] = attrs["value"]


class AuthorizationAppTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = auth_fixture.AuthorizationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.authority = self.fixture.authority
        # Synthetic SSO adapter only. Production must VERIFY an SSO session.
        self.authority.verify_login = lambda request: self.fixture.people.get(
            request.cookies.get("synthetic_login")
        )
        self.services = {}
        for name, person in self.fixture.people.items():
            root = Path(self.fixture.directory.name) / person.owner
            service = ExpenseService(
                mf=SyntheticMF(person.owner, name),
                state=State(root / "state.sqlite", person.owner),
                receipts=Receipts(root / "receipts", None, person.owner),
            )
            self.services[name] = service
            self.addCleanup(service.state.close)

        def resolve(person, capability):
            return ConnectionGrant(
                person.tenant_id,
                person.person_id,
                5000,
                CAPABILITIES,
                self.services[person.person_id],
                agent_slug="expense_assistant",
            )

        self.app = create_app(self.authority, resolve)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url=self.authority.issuer
        )
        self.addAsyncCleanup(self.client.aclose)

    def login(self, name):
        return {"cookie": "synthetic_login=" + name}

    async def authorize(self, name="alice", **overrides):
        params = {
            "response_type": "code",
            "client_id": "sa",
            "redirect_uri": "https://sa.example.test/callback",
            "resource": self.authority.resource,
            "scope": "mf:read",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "state": "synthetic-state",
        }
        return await self.client.get(
            "/oauth/authorize", params={**params, **overrides}, headers=self.login(name)
        )

    async def decide(self, response, name="alice", **overrides):
        return await self.client.post(
            "/oauth/consent",
            data={**FormParser(response.text).fields, "decision": "approve", **overrides},
            headers={**self.login(name), "origin": self.authority.issuer},
        )

    async def token_pair(self, name="alice"):
        page = await self.authorize(name)
        self.assertEqual(page.status_code, 200, page.text)
        consent = await self.decide(page, name)
        self.assertEqual(consent.status_code, 303, consent.text)
        code = parse_qs(urlsplit(consent.headers["location"]).query)["code"][0]
        reply = await self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": "sa",
                "redirect_uri": "https://sa.example.test/callback",
                "resource": self.authority.resource,
                "code_verifier": VERIFIER,
            },
        )
        self.assertEqual(reply.status_code, 200, reply.text)
        return reply.json()

    async def token(self, name="alice"):
        return (await self.token_pair(name))["access_token"]

    async def call(self, token, name="mf_offices", arguments=None):
        return await self.client.post(
            "/mcp",
            headers={
                "authorization": "Bearer " + token,
                "accept": "application/json, text/event-stream",
                "mcp-protocol-version": "2025-03-26",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            },
        )

    @with_server
    async def test_full_flow_two_people_get_only_their_own_mcp_result(self):
        for who in ("alice", "bob"):
            token = await self.token(who)
            reply = await self.call(token)
            self.assertEqual(reply.status_code, 200, reply.text)
            result = reply.json()["result"]
            self.assertFalse(result.get("isError"), result)
            self.assertIn(who, json.dumps(result))
            self.assertNotIn("alice" if who == "bob" else "bob", json.dumps(result))

    @with_server
    async def test_read_only_token_cannot_use_backend_write_permission(self):
        token = await self.token()
        reply = await self.call(
            token, "mf_delete_transaction", {"office": "alice", "transaction_id": "test"}
        )
        self.assertTrue(reply.json()["result"]["isError"])
        self.assertEqual(self.services["alice"].mf.calls, 0)

    @with_server
    async def test_http_revocation_invalidates_the_real_issued_mcp_token(self):
        token = await self.token()
        self.assertEqual((await self.call(token)).status_code, 200)
        result = await self.client.post("/oauth/revoke", data={"token": token, "client_id": "sa"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual((await self.call(token)).status_code, 401)

    @with_server
    async def test_consent_ui_can_disconnect_all_tokens_for_this_client_and_person(self):
        token = await self.token()
        page = await self.authorize()
        result = await self.decide(page, decision="revoke")
        self.assertEqual(result.status_code, 303)
        self.assertNotIn("code=", result.headers["location"])
        self.assertEqual((await self.call(token)).status_code, 401)

    @with_server
    async def test_missing_login_and_different_user_cannot_approve(self):
        missing = await self.authorize("not-logged-in")
        self.assertEqual(missing.status_code, 401)
        page = await self.authorize()
        self.assertEqual((await self.decide(page, "bob")).status_code, 400)
        self.assertEqual((await self.decide(page, "alice")).status_code, 303)

    @with_server
    async def test_origin_nonce_and_replay_protection(self):
        page = await self.authorize()
        self.assertEqual((await self.decide(page, csrf_token="wrong")).status_code, 400)
        form = {**FormParser(page.text).fields, "decision": "approve"}
        bad = await self.client.post(
            "/oauth/consent",
            data=form,
            headers={**self.login("alice"), "origin": "https://attacker.example.test"},
        )
        self.assertEqual(bad.status_code, 400)
        self.assertEqual((await self.decide(page)).status_code, 303)
        self.assertEqual((await self.decide(page)).status_code, 400)

    @with_server
    async def test_rejects_implicit_plain_pkce_unregistered_redirect_and_scope(self):
        for params in (
            {"response_type": "token"},
            {"code_challenge_method": "plain"},
            {"redirect_uri": "https://attacker.example.test"},
            {"scope": "admin"},
        ):
            reply = await self.authorize(**params)
            self.assertEqual(reply.status_code, 400)
            self.assertNotIn("location", reply.headers)
        for grant in ("password", "client_credentials"):
            result = await self.client.post("/oauth/token", data={"grant_type": grant})
            self.assertEqual(result.json()["error"], "unsupported_grant_type")

    @with_server
    async def test_exact_https_host_size_and_duplicate_parameters(self):
        for base in ("http://expense.example.test", "https://attacker.example.test"):
            reply = await self.client.get(base + "/.well-known/oauth-authorization-server")
            self.assertEqual(reply.status_code, 400)
        reply = await self.client.post(
            "/oauth/token",
            content="x=" + "x" * 17000,
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(reply.status_code, 400)
        duplicate = await self.client.post(
            "/oauth/token",
            content="client_id=sa&client_id=buzz",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(duplicate.status_code, 400)

    @with_server
    async def test_metadata_matches_authority_and_mcp_challenge(self):
        metadata = await self.client.get("/.well-known/oauth-authorization-server")
        self.assertEqual(metadata.json()["issuer"], self.authority.issuer)
        self.assertEqual(
            metadata.json()["grant_types_supported"], ["authorization_code", "refresh_token"]
        )
        self.assertNotIn("registration_endpoint", metadata.json())
        unauthorized = await self.call("not-an-issued-personal-token")
        self.assertEqual(unauthorized.status_code, 401)
        self.assertIn("oauth-protected-resource", unauthorized.headers["www-authenticate"])
        self.assertEqual(
            unauthorized.headers["www-authenticate"],
            " ".join(
                (
                    "Bearer",
                    f'resource_metadata="{self.authority.issuer}/.well-known/oauth-protected-resource"',
                )
            ),
        )
        resource = await self.client.get("/.well-known/oauth-protected-resource")
        self.assertEqual(resource.json()["resource"], self.authority.resource)

    @with_server
    async def test_consent_html_is_escaped_and_private(self):
        original = self.authority.clients["sa"]
        self.authority.clients["sa"] = dataclasses.replace(
            original, display_name='<script>alert("test")</script>'
        )
        page = await self.authorize()
        self.assertNotIn("<script>", page.text)
        self.assertIn("&lt;script&gt;", page.text)
        self.assertEqual(page.headers["cache-control"], "no-store")
        self.assertIn("frame-ancestors 'none'", page.headers["content-security-policy"])
        self.assertEqual(page.headers["referrer-policy"], "no-referrer")
        self.assertIn("解除するまで継続", page.text)

    @with_server
    async def test_expired_mcp_token_can_refresh_without_login_then_reenter_mcp(self):
        original = await self.token_pair()
        self.fixture.now += 901
        self.assertEqual((await self.call(original["access_token"])).status_code, 401)
        # No cookie, login, consent UI, or resource override on refresh.
        reply = await self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "sa",
                "refresh_token": original["refresh_token"],
            },
        )
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertEqual(reply.headers["cache-control"], "no-store")
        updated = reply.json()
        result = (await self.call(updated["access_token"])).json()["result"]
        self.assertFalse(result.get("isError"), result)
        self.assertIn("alice", json.dumps(result))
        self.assertNotEqual(updated["refresh_token"], original["refresh_token"])

    @with_server
    async def test_http_refresh_reuse_revokes_new_access_and_refresh_tokens(self):
        original = await self.token_pair()
        form = {
            "grant_type": "refresh_token",
            "client_id": "sa",
            "refresh_token": original["refresh_token"],
        }
        first = await self.client.post("/oauth/token", data=form)
        self.assertEqual(first.status_code, 200)
        current = first.json()
        replay = await self.client.post("/oauth/token", data=form)
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(replay.json()["error"], "invalid_grant")
        self.assertEqual((await self.call(current["access_token"])).status_code, 401)
        again = await self.client.post(
            "/oauth/token", data={**form, "refresh_token": current["refresh_token"]}
        )
        self.assertEqual(again.status_code, 400)


if __name__ == "__main__":
    unittest.main()
