"""Synthetic signed platform HTTP -> agent-owned per-person service connection GUI."""

from urllib.parse import urlencode
from unittest.mock import patch

import httpx

from authorization_app import create_app
from runtime.service_connections import ConnectionProvider, ServiceConnections
import test_platform_login as platform_fixture
from runtime.requester import Requester


class ServiceConnectionTests(platform_fixture.PlatformLoginTests):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.states = {("alice", "mf"): "not_connected", ("bob", "mf"): "connected"}
        self.begun = []

        def begin(person, provider):
            self.begun.append((person.person_id, provider))
            return "https://expense.example.provider/oauth/authorize?state=synthetic"

        self.manager = ServiceConnections(
            self.fixture.store,
            providers=(ConnectionProvider("mf", "マネーフォワード", frozenset({"https://expense.example.provider"})),),
            status=lambda person, provider: self.states[(person.person_id, provider)],
            begin=begin,
            clock=lambda: self.now,
        )
        self.app = self.login.wrap(create_app(
            self.authority, self.resolve, platform_login=self.login,
            service_connections=self.manager,
        ))
        await self.client.aclose()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(self.app), base_url=self.origin)
        self.addAsyncCleanup(self.client.aclose)

    async def connection_view(self, person="alice", *, html=False):
        return await self.client.get("/connections", headers={
            **self.signed("GET", "/connections", person=person),
            "accept": "text/html" if html else "application/json",
        })

    async def start_connection(self, csrf, person="alice", **extra):
        body = urlencode({"provider": "mf", "csrf_token": csrf, **extra}).encode()
        return await self.client.post("/connections/start", content=body, headers={
            **self.signed("POST", "/connections/start", body, person=person),
            "content-type": "application/x-www-form-urlencoded",
        })

    async def test_signed_gui_has_connect_button_and_no_key_fields(self):
        page = await self.connection_view(html=True)
        self.assertEqual(page.status_code, 200)
        self.assertIn("マネーフォワードに接続する", page.text)
        self.assertNotIn('name="person', page.text)
        self.assertNotIn('name="token', page.text)
        self.assertIn("no-store", page.headers["cache-control"])
        self.assertIn("frame-ancestors 'none'", page.headers["content-security-policy"])
        self.assertIn(
            "form-action 'self' https://expense.example.provider;",
            page.headers["content-security-policy"],
        )
        consent_path = self.authorize_path()
        consent = await self.client.get(consent_path, headers=self.signed("GET", consent_path))
        self.assertNotIn("expense.example.provider", consent.headers["content-security-policy"])
        bob = await self.connection_view("bob", html=True)
        self.assertIn("接続済み", bob.text)
        self.assertNotIn("に接続する</button>", bob.text)

    async def test_per_person_authorization_start_is_one_time_and_not_a_financial_write(self):
        view = (await self.connection_view()).json()
        csrf = view["csrf_token"]
        response = await self.start_connection(csrf)
        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(self.begun, [("alice", "mf")])
        self.assertTrue(response.headers["location"].startswith("https://expense.example.provider/"))
        replay = await self.start_connection(csrf)
        self.assertEqual(replay.status_code, 503)
        self.assertEqual(len(self.begun), 1)

    async def test_other_person_expiry_and_model_chosen_identity_are_refused(self):
        csrf = (await self.connection_view()).json()["csrf_token"]
        self.assertEqual((await self.start_connection(csrf, "bob")).status_code, 503)
        self.assertEqual((await self.start_connection(csrf, person_id="bob")).status_code, 400)
        self.manager.clock = lambda: self.now + 301
        self.assertEqual((await self.start_connection(csrf)).status_code, 503)
        self.assertEqual(self.begun, [])

    async def test_provider_outage_has_no_reauthorization_button_or_raw_exception(self):
        self.states[("alice", "mf")] = "unavailable"
        page = await self.connection_view(html=True)
        self.assertIn("一時的に利用できません", page.text)
        self.assertNotIn("に接続する</button>", page.text)
        csrf = (await self.connection_view()).json()["csrf_token"]
        self.assertEqual((await self.start_connection(csrf)).status_code, 503)
        self.assertEqual(self.begun, [])
        def broken(*args):
            raise RuntimeError("synthetic-secret-must-not-leak")
        self.manager.status = broken
        page = await self.connection_view(html=True)
        self.assertNotIn("synthetic-secret", page.text)

    async def test_unsigned_target_tampering_and_arbitrary_redirect_are_refused(self):
        self.assertEqual((await self.client.get("/connections")).status_code, 401)
        signed = self.signed("GET", "/oauth/authorize")
        self.assertEqual((await self.client.get("/connections", headers=signed)).status_code, 401)
        csrf = (await self.connection_view()).json()["csrf_token"]
        self.manager.begin = lambda *args: "https://attacker.example/steal"
        response = await self.start_connection(csrf)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("location", response.headers)

    async def test_wrong_origin_provider_and_changed_body_cannot_start_connections(self):
        csrf = (await self.connection_view()).json()["csrf_token"]
        body = urlencode({"provider": "mf", "csrf_token": csrf}).encode()
        headers = self.signed("POST", "/connections/start", body)
        response = await self.client.post("/connections/start", content=body, headers={
            **headers, "origin": "https://attacker.example",
            "content-type": "application/x-www-form-urlencoded",
        })
        self.assertEqual(response.status_code, 401)
        changed = body.replace(b"provider=mf", b"provider=calendar")
        response = await self.client.post("/connections/start", content=changed, headers={
            **self.signed("POST", "/connections/start", body),
            "content-type": "application/x-www-form-urlencoded",
        })
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.begun, [])

    async def test_missing_deployment_adapter_never_claims_connected(self):
        app = self.login.wrap(create_app(self.authority, self.resolve, platform_login=self.login))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=self.origin) as client:
            response = await client.get("/connections", headers=self.signed("GET", "/connections"))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"], "service_connections_unavailable")

    async def test_calendar_authorization_uses_only_current_person_and_configured_origin(self):
        self.states[("alice", "calendar")] = "expired"
        self.manager.providers["calendar"] = ConnectionProvider(
            "calendar", "Googleカレンダー", frozenset({"https://calendar.example.provider"})
        )
        self.manager.begin = lambda person, provider: "https://calendar.example.provider/authorize"
        page = await self.connection_view(html=True)
        self.assertIn("Googleカレンダーに接続する", page.text)
        csrf = (await self.connection_view()).json()["csrf_token"]
        body = urlencode({"provider": "calendar", "csrf_token": csrf}).encode()
        response = await self.client.post("/connections/start", content=body, headers={
            **self.signed("POST", "/connections/start", body),
            "content-type": "application/x-www-form-urlencoded",
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "https://calendar.example.provider/authorize")

    async def test_wrong_tenant_login_cannot_read_or_start_service_connection(self):
        other = Requester("another-tenant", "alice", self.now + 600)
        with patch.object(self.authority, "verify_login", return_value=other):
            response = await self.connection_view()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.begun, [])

