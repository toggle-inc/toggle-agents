"""Signed real HTTP v2 readiness; no business API execution or live services."""

import dataclasses
import json
import unittest

import test_platform_login as fixtures


class OperationReadinessHTTPTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = fixtures.PlatformLoginTests.asyncSetUp
    signed = fixtures.PlatformLoginTests.signed
    authorize_path = fixtures.PlatformLoginTests.authorize_path
    consent = fixtures.PlatformLoginTests.consent

    @classmethod
    def setUpClass(cls):
        fixtures.PlatformLoginTests.setUpClass.__func__(cls)

    async def status(self, operation, *, signed=True):
        body = json.dumps({"schema_version": "agent-operation-readiness-request/v2", "client_id": "sa",
                           "request_id": "synthetic-v2-request", "operation": operation}).encode()
        return await self.client.post("/execution/status", content=body, headers={"content-type": "application/json",
            **(self.signed("POST", "/execution/status", body) if signed else {})})

    async def test_signed_general_advice_and_one_scope_status_preserve_auth_and_v1(self):
        self.authority.clients["sa"] = dataclasses.replace(self.authority.clients["sa"], capabilities=frozenset({"mf:read"}))
        self.assertEqual((await self.status(None, signed=False)).status_code, 401)
        advice = await self.status(None)
        self.assertEqual(advice.status_code, 200)
        self.assertEqual(advice.json()["reason"], "general_advice")
        missing = await self.status("mf_offices")
        self.assertEqual(missing.json()["reason"], "agent_authorization_required")
        unavailable = await self.status("mf_save_draft")
        self.assertEqual(unavailable.json()["reason"], "operation_unavailable")
        self.assertEqual((await self.consent()).status_code, 303)
        ready = await self.status("mf_offices")
        self.assertTrue(ready.json()["ready"])
        self.assertEqual(ready.json()["required_capabilities"], ["mf:read"])
        for service in self.services.values():
            self.assertEqual(service.mf.calls, 0)
