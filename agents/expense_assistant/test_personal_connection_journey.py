"""Signed GUI -> synthetic provider OAuth -> encrypted vault -> same person's MCP.

This is an in-process HTTP test, not a live SA/MF deployment receipt.
"""

import json
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from cryptography.fernet import Fernet

import test_platform_login as platform_fixture
from authorization_app import create_app
from runtime.connection_providers import build_service_connections
from runtime.personal_mf import PersonalMF
from runtime.provider_vault import EncryptedProviderVault
from runtime.requester import ConnectionGrant, Requester
from runtime.service import ExpenseService
from runtime.state import State
from test_authorization import VERIFIER


class PersonalConnectionJourneyTests(unittest.IsolatedAsyncioTestCase):
    signed = platform_fixture.PlatformLoginTests.signed
    authorize_path = platform_fixture.PlatformLoginTests.authorize_path
    consent = platform_fixture.PlatformLoginTests.consent

    @classmethod
    def setUpClass(cls):
        platform_fixture.PlatformLoginTests.setUpClass.__func__(cls)

    async def asyncSetUp(self):
        await platform_fixture.PlatformLoginTests.asyncSetUp(self)
        self.provider_now = self.now
        self.provider_calls = []
        def provider(request):
            self.provider_calls.append((request.method, request.url.path))
            if request.url.path == "/oauth/token":
                params = parse_qs(request.content.decode())
                if params["grant_type"] == ["authorization_code"]:
                    name = params["code"][0]
                else:
                    name = params["refresh_token"][0].removeprefix("synthetic-refresh-")
                return httpx.Response(200, json={
                    "access_token": "synthetic-access-" + name,
                    "refresh_token": "synthetic-refresh-" + name, "expires_in": 600,
                })
            if request.url.path == "/api/external/v1/offices":
                name = request.headers["authorization"].removeprefix("Bearer synthetic-access-")
                return httpx.Response(200, json={"offices": [{"id": name, "name": name}]})
            raise AssertionError("Unexpected provider operation")
        self.http = httpx.Client(transport=httpx.MockTransport(provider), base_url="https://expense.moneyforward.com")
        self.addCleanup(self.http.close)
        self.vault = EncryptedProviderVault(self.fixture.store, Fernet.generate_key(), namespace=self.origin)
        self.mf = PersonalMF(
            client_id="synthetic-app", client_secret="synthetic-app-secret",
            redirect_uri=self.platform + "/connections/callback?provider=mf", vault_store=self.vault,
            http=self.http, clock=lambda: self.provider_now,
        )
        self.manager = build_service_connections(
            self.fixture.store, mf=self.mf, clock=lambda: self.provider_now,
        )
        self.services = {}
        for name in ("alice", "bob"):
            person = Requester("synthetic-tenant", name, self.now + 3000)
            state = State(Path(self.fixture.directory.name) / name / "live-adapter-state.sqlite", person.owner)
            self.addCleanup(state.close)
            self.services[name] = ExpenseService(mf=self.mf.for_person(person), state=state, write_enabled=False)
        def resolve(person, capability):
            if capability != "mf:read" or self.mf.status(person, "mf") != "connected":
                return None
            return ConnectionGrant(person.tenant_id, person.person_id, self.now + 3000,
                frozenset({"mf:read"}), self.services[person.person_id], agent_slug="expense_assistant")
        self.app = self.login.wrap(create_app(
            self.authority, resolve, platform_login=self.login, service_connections=self.manager,
        ))
        await self.client.aclose()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(self.app), base_url=self.origin)
        self.addAsyncCleanup(self.client.aclose)

    async def connect_mf(self, person):
        view = await self.client.get("/connections", headers={
            **self.signed("GET", "/connections", person=person), "accept": "application/json",
        })
        self.assertEqual(view.status_code, 200, view.text)
        self.assertEqual(view.json()["connections"][0]["status"], "not_connected")
        self.assertEqual(view.json()["connections"][1]["status"], "unavailable")
        body = urlencode({"provider": "mf", "csrf_token": view.json()["csrf_token"]}).encode()
        start = await self.client.post("/connections/start", content=body, headers={
            **self.signed("POST", "/connections/start", body, person=person),
            "content-type": "application/x-www-form-urlencoded",
        })
        self.assertEqual(start.status_code, 303, start.text)
        authorization = parse_qs(urlsplit(start.headers["location"]).query)
        state = authorization["state"][0]
        registered = urlsplit(authorization["redirect_uri"][0])
        # Model the provider's real callback, retaining its registered query.
        # The trusted BFF proxies the same path/query to the fixed agent origin.
        query = parse_qs(registered.query)
        self.assertEqual(query, {"provider": ["mf"]})
        callback = registered.path + "?" + urlencode({
            **{key: values[0] for key, values in query.items()}, "code": person, "state": state,
        })
        wrong = "bob" if person == "alice" else "alice"
        denied = await self.client.get(callback, headers=self.signed("GET", callback, person=wrong))
        self.assertEqual(denied.status_code, 400)
        result = await self.client.get(callback, headers={
            **self.signed("GET", callback, person=person), "accept": "application/json",
        })
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()["status"], "connected")
        self.assertNotIn("access_token", result.text)
        replay = await self.client.get(callback, headers=self.signed("GET", callback, person=person))
        self.assertEqual(replay.status_code, 400)

    async def test_unconnected_intake_view_proposes_gui_without_starting_provider_or_business_calls(self):
        # A platform may read this typed state before executing a work request.
        # It must not infer a provider outage to mean missing human consent.
        for person in ("alice", "bob"):
            view = await self.client.get("/connections", headers={
                **self.signed("GET", "/connections", person=person), "accept": "application/json",
            })
            self.assertEqual(view.status_code, 200)
            self.assertEqual({row["id"]: row["status"] for row in view.json()["connections"]},
                             {"mf": "not_connected", "calendar": "unavailable"})
            html = await self.client.get("/connections", headers=self.signed("GET", "/connections", person=person))
            self.assertIn("マネーフォワード経費に接続する", html.text)
            self.assertNotIn("Googleカレンダーに接続する</button>", html.text)
            self.assertIn("再認証やキー入力は不要", html.text)
            with self.vault.transaction(Requester("synthetic-tenant", person, self.now + 3000).owner, "mf") as data:
                self.assertNotIn("oauth", data)
                self.assertNotIn("pending", data)
        path = "/connections?person_id=bob"
        self.assertEqual((await self.client.get(path, headers=self.signed("GET", path))).status_code, 400)
        self.assertEqual((await self.client.get("/connections")).status_code, 401)
        self.assertEqual(self.provider_calls, [])

    @platform_fixture.with_platform_server
    async def test_two_people_gui_connect_refresh_and_mcp_keep_credentials_separate(self):
        for name in ("alice", "bob"):
            await self.connect_mf(name)
        tokens = {}
        for name in ("alice", "bob"):
            consent = await self.consent(name)
            code = parse_qs(urlsplit(consent.headers["location"]).query)["code"][0]
            reply = await self.client.post("/oauth/token", data={
                "grant_type": "authorization_code", "code": code, "client_id": "sa",
                "redirect_uri": self.platform + "/callback", "resource": self.origin + "/mcp",
                "code_verifier": VERIFIER,
            })
            self.assertEqual(reply.status_code, 200, reply.text)
            tokens[name] = reply.json()["access_token"]
        # The provider access token expires. No GUI login/consent is repeated.
        self.provider_now += 601
        for name in ("alice", "bob"):
            result = await self.client.post("/mcp", headers={
                "authorization": "Bearer " + tokens[name], "accept": "application/json, text/event-stream",
                "mcp-protocol-version": "2025-03-26",
            }, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "mf_offices", "arguments": {}}})
            self.assertEqual(result.status_code, 200, result.text)
            payload = result.json()["result"]
            self.assertFalse(payload.get("isError", False), payload)
            data = payload.get("structuredContent") or json.loads(payload["content"][0]["text"])
            self.assertIn(name, json.dumps(data))
            self.assertNotIn("bob" if name == "alice" else "alice", json.dumps(data))
        stored = str(self.fixture.store._db.execute("SELECT value FROM auth_records").fetchall())
        self.assertNotIn("synthetic-access-", stored)
        self.assertNotIn("synthetic-refresh-", stored)
        self.assertNotIn("synthetic-app-secret", stored)
        self.assertEqual(sum(path == "/oauth/token" for _, path in self.provider_calls), 4)
        self.assertTrue(all(method == "GET" or path == "/oauth/token" for method, path in self.provider_calls))
