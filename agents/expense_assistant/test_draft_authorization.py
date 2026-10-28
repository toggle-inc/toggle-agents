"""Initial person/company consent -> real OAuth/MCP -> FakeMF, no live services."""

import dataclasses
import json
import unittest
from urllib.parse import parse_qs, urlsplit

import httpx
import test_authorization_app as app_fixtures
import test_runtime as providers
from authorization_app import create_app
from runtime.draft_consent import DraftConsentBinding
from runtime.requester import ConnectionGrant
from runtime.state import ExpenseError
from test_authorization import VERIFIER
from test_requester_mcp import with_server


class DraftAuthorizationTests(unittest.IsolatedAsyncioTestCase):
    login = app_fixtures.AuthorizationAppTests.login
    authorize = app_fixtures.AuthorizationAppTests.authorize
    decide = app_fixtures.AuthorizationAppTests.decide
    call = app_fixtures.AuthorizationAppTests.call

    async def asyncSetUp(self):
        await app_fixtures.AuthorizationAppTests.asyncSetUp(self)
        client = self.authority.clients["sa"]
        self.authority.clients["sa"] = dataclasses.replace(
            client, capabilities=client.capabilities | {"mf:draft"}
        )
        for service in self.services.values():
            service.mf = providers.FakeMF()
            service.mf.owner = service.state.owner
            service.policy = providers.FakePolicy()
            service.write_enabled = True

        def resolve(person, capability):
            return ConnectionGrant(
                person.tenant_id,
                person.person_id,
                5000,
                frozenset({"mf:draft", "mf:read"}),
                self.services[person.person_id],
                agent_slug="expense_assistant",
            )

        self.resolve = resolve
        self.binding = DraftConsentBinding(self.authority, resolve)
        self.app = create_app(self.authority, resolve, draft_consent=self.binding)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url=self.authority.issuer
        )
        self.addAsyncCleanup(self.client.aclose)

    async def consent_token(self):
        page = await self.authorize(scope="mf:draft")
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn('name="draft_office"', page.text)
        self.assertIn("都度確認なし", page.text)
        reply = await self.decide(page, draft_office="office-a")
        self.assertEqual(reply.status_code, 303, reply.text)
        code = parse_qs(urlsplit(reply.headers["location"]).query)["code"][0]
        token = await self.client.post(
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
        self.assertEqual(token.status_code, 200, token.text)
        return token.json()

    async def tool(self, token, name, arguments):
        reply = await self.call(token, name, arguments)
        result = reply.json()["result"]
        self.assertFalse(result.get("isError"), result)
        return result.get("structuredContent") or json.loads(result["content"][0]["text"])

    @with_server
    async def test_initial_consent_then_mcp_save_and_oauth_refresh_need_no_per_item_ui(self):
        pair = await self.consent_token()
        service = self.services["alice"]
        self.assertEqual(service.state.draft_consent("office-a")["office_ids"], ["office-a"])
        with self.assertRaises(ExpenseError):
            self.services["bob"].state.draft_consent("office-a")
        with self.assertRaises(ExpenseError):
            service.state.draft_consent("office-b")
        preview = await self.tool(
            pair["access_token"],
            "mf_create_transaction",
            {
                "office": "office-a",
                "recognized_at": "2020-01-15",
                "value": 321,
                "remark": "合成同意テスト",
                "memo": "駅A→駅B（合成）",
                "ex_item_id": "item-a",
                "ex_item_name": "旅費交通費",
            },
        )
        result = await self.tool(
            pair["access_token"], "mf_save_draft", {"preview_id": preview["preview_id"]}
        )
        self.assertTrue(result["readback_verified"])
        self.assertEqual(result["review_url"], "https://expense.moneyforward.com/transactions")
        self.assertFalse(result["submitted"])
        refresh = await self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": pair["refresh_token"],
                "client_id": "sa",
                "resource": self.authority.resource,
            },
        )
        self.assertEqual(refresh.status_code, 200, refresh.text)
        repeated = await self.tool(
            refresh.json()["access_token"], "mf_save_draft", {"preview_id": preview["preview_id"]}
        )
        self.assertEqual(result, repeated)
        self.assertEqual(len(service.mf.writes), 1)

    @with_server
    async def test_forged_company_csrf_other_person_and_denial_never_grant(self):
        for overrides in (
            {"draft_office": "other-company"},
            {"csrf_token": "wrong"},
            {"name": "bob"},
        ):
            page = await self.authorize(scope="mf:draft")
            kwargs = {"draft_office": "office-a", **overrides}
            reply = await self.decide(page, **kwargs)
            self.assertEqual(reply.status_code, 400, reply.text)
        page = await self.authorize(scope="mf:draft")
        self.assertIn('value="deny" formnovalidate', page.text)
        denied = await self.decide(page, decision="deny")
        self.assertEqual(denied.status_code, 303)
        for service in self.services.values():
            with self.assertRaises(ExpenseError):
                service.state.draft_consent("office-a")
            self.assertEqual(service.mf.writes, [])

    @with_server
    async def test_revoke_invalidates_both_oauth_and_company_draft_consent(self):
        pair = await self.consent_token()
        page = await self.authorize(scope="mf:draft")
        self.assertIn('value="revoke" formnovalidate', page.text)
        revoked = await self.decide(page, decision="revoke")
        self.assertEqual(revoked.status_code, 303, revoked.text)
        with self.assertRaises(ExpenseError):
            self.services["alice"].state.draft_consent("office-a")
        self.assertEqual((await self.call(pair["access_token"])).status_code, 401)

    async def test_draft_scope_requires_configured_binding_not_just_oauth_scope(self):
        app = create_app(self.authority, self.resolve)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=self.authority.issuer
        ) as client:
            original = self.client
            self.client = client
            try:
                page = await self.authorize(scope="mf:draft")
            finally:
                self.client = original
        self.assertEqual(page.status_code, 400)
        self.assertEqual(page.json()["error"], "draft_consent_unavailable")
        with self.assertRaises(ExpenseError):
            self.services["alice"].state.draft_consent("office-a")


if __name__ == "__main__":
    unittest.main()
