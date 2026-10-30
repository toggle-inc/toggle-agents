"""Synthetic config, ASGI and cross-person isolation checks; no cloud calls."""

import copy
import hashlib
import json
import logging
import secrets
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cloud_auth_app import create_app, main, settings_from_environment
from _foundation.platform_identity import ASSERTION_TYPE
from runtime.auth_store import SQLiteAuthorizationStore
from runtime.provider_vault import EncryptedProviderVault
from runtime.requester import Requester
from runtime.personal_mf import PersonalMF
from test_authorization import CHALLENGE, VERIFIER


class CloudAuthTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public = cls.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def setUp(self):
        self.addCleanup(logging.disable, logging.NOTSET)
        self.config = {
            "origin": "https://expense.example.test", "tenant_id": "expense-tenant",
            "platform_issuer": "https://sa.example.test", "platform_public_keys": {"test-key": self.public},
            "clients": [{"client_id": "sa", "display_name": "SA", "redirect_uris": ["https://sa.example.test/oauth/callback"],
                         "capabilities": ["mf:read"]}],
            "identity_links": [{"platform_tenant_id": "sa-tenant", "subject": name, "person_id": "person-" + name}
                               for name in ("alice", "bob")],
            "provider_namespace": "synthetic-dedicated-v1", "ingress_mode": "cloud_run_tls",
            "mf": {"client_id": "synthetic-mf", "callback_uri": "https://sa.example.test/api/chat/agent-service-callback?provider=mf"},
        }
        self.env = {
            "EXPENSE_AUTH_DATABASE_URL": "postgresql://auth:synthetic-db-secret@db.example.test/auth?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca-certificates.crt",
            "EXPENSE_PROVIDER_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "EXPENSE_MF_CLIENT_SECRET": "synthetic-mf-secret",
        }

    def environment(self, config=None):
        return {**self.env, "EXPENSE_AUTH_CONFIG": json.dumps(self.config if config is None else config)}

    def app(self, config=None):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        Path(directory.name).chmod(0o700)
        self.store = SQLiteAuthorizationStore(Path(directory.name) / "auth.sqlite")
        self.addCleanup(self.store.close)
        return create_app(environ=self.environment(config), store_factory=lambda _: self.store)

    def signed(self, method, path, *, subject="alice", body=b"", tenant="sa-tenant"):
        now = time.time()
        claims = {
            "iss": self.config["platform_issuer"], "aud": self.config["origin"],
            "sub": subject, "tenant_id": tenant, "actor_type": "human", "purpose": "platform_login",
            "iat": now, "exp": now + 50, "auth_expires_at": now + 3600,
            "jti": secrets.token_urlsafe(24), "method": method, "target": self.config["origin"] + path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "origin": self.config["platform_issuer"] if method == "POST" else "",
        }
        proof = jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "test-key", "typ": ASSERTION_TYPE})
        return {"x-agent-platform-assertion": proof, "accept": "application/json",
                **({"origin": self.config["platform_issuer"]} if method == "POST" else {})}

    def test_config_and_exact_links_no_default_person(self):
        settings = settings_from_environment(self.environment())
        for name in ("alice", "bob"):
            self.assertEqual(settings.resolve_person(self.config["platform_issuer"], "sa-tenant", name).person_id, "person-" + name)
        for issuer, tenant, subject in ((self.config["platform_issuer"], "other", "alice"),
                                        ("https://other.test", "sa-tenant", "alice"),
                                        (self.config["platform_issuer"], "sa-tenant", "unknown")):
            self.assertIsNone(settings.resolve_person(issuer, tenant, subject))

    async def test_setup_reports_runtime_shortfall_without_minting_permissions(self):
        app = self.app()
        path = "/setup?client_id=sa"
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=self.config["origin"]) as client:
            response = await client.get(path, headers=self.signed("GET", path))
        self.assertEqual(response.status_code, 200, response.text)
        view = response.json()
        self.assertEqual(view["schema_version"], "agent-setup/v1")
        self.assertEqual(view["status"], "blocked")
        self.assertIn("memory:write", view["missing_capabilities"])
        self.assertIn("memory:write", view["missing_runtime_capabilities"])
        self.assertIn("mf:draft", view["missing_runtime_capabilities"])
        self.assertNotIn("mf:read", view["missing_runtime_capabilities"])
        self.assertTrue(view["requires_company_selection"])

    def test_secrets_absent_from_repr_and_errors(self):
        env = self.environment()
        settings = settings_from_environment(env)
        for secret in self.env.values():
            self.assertNotIn(secret, repr(settings))
            self.assertNotIn(secret, repr(settings.host))
        env["EXPENSE_AUTH_CONFIG"] = "invalid-json-secret"
        with self.assertRaises(ValueError) as caught:
            settings_from_environment(env)
        self.assertNotIn("invalid-json-secret", str(caught.exception))

    def test_invalid_configuration_fails_before_store(self):
        variants = []
        for field, value in (("ingress_mode", "forwarded"), ("origin", "http://expense.test"),
                             ("identity_links", []), ("clients", []), ("platform_public_keys", {"key": "bad-key"}),
                             ("default_person", "alice"), ("tenant_id", " ")):
            config = copy.deepcopy(self.config)
            config[field] = value
            variants.append(self.environment(config))
        for change in (lambda c: c["identity_links"].append(c["identity_links"][0]),
                       lambda c: c["identity_links"][1].update(person_id="person-alice"),
                       lambda c: c["mf"].update(callback_uri="https://evil.test/callback?provider=google")):
            config = copy.deepcopy(self.config)
            change(config)
            variants.append(self.environment(config))
        for field, value in (("EXPENSE_AUTH_DATABASE_URL", "postgresql://u:secret@db.test/auth?sslmode=require"),
                             ("EXPENSE_AUTH_DATABASE_URL", self.env["EXPENSE_AUTH_DATABASE_URL"].replace("/etc/ssl/certs/ca-certificates.crt", "/Mac/certifi.pem")),
                             ("EXPENSE_PROVIDER_ENCRYPTION_KEY", "invalid-key"), ("EXPENSE_MF_CLIENT_SECRET", ""),
                             ("EXPENSE_GOOGLE_CLIENT_SECRET", "orphan-secret")):
            variants.append({**self.environment(), field: value})
        variants.append({**self.env, "EXPENSE_AUTH_CONFIG": '{"origin":"one","origin":"two"}'})
        for env in variants:
            with self.subTest(index=variants.index(env)):
                factory = Mock()
                with self.assertRaisesRegex(ValueError, "Invalid dedicated expense auth configuration"):
                    create_app(environ=env, store_factory=factory)
                factory.assert_not_called()
        with self.assertRaises(ValueError):
            create_app(environ={"DATABASE_URL": "shared", "MF_CLIENT_SECRET": "shared"})

    async def test_cloud_factory_consent_to_personal_read_uses_real_resolver(self):
        calls = []
        def mf_response(request):
            calls.append((request.method, request.url.path))
            self.assertEqual(request.method, 'GET')
            self.assertEqual(request.url.path, '/api/external/v1/offices')
            self.assertEqual(request.headers['authorization'], 'Bearer synthetic-alice-access')
            return httpx.Response(200, json={'offices': [{'id': 'synthetic-company', 'name': 'Synthetic'}]})
        with httpx.Client(transport=httpx.MockTransport(mf_response), base_url='https://expense.moneyforward.com') as mf_http:
            with patch('cloud_auth_app.PersonalMF', side_effect=lambda **kw: PersonalMF(**kw, http=mf_http)):
                app = self.app()
            settings = settings_from_environment(self.environment())
            vault = EncryptedProviderVault(self.store, settings.encryption_key, namespace=settings.provider_namespace)
            person = Requester('expense-tenant', 'person-alice', time.time() + 3600)
            with vault.transaction(person.owner, 'mf') as row:
                row.update(owner=person.owner, oauth={'access_token': 'synthetic-alice-access',
                           'obtained_at': time.time(), 'expires_in': 3600})
            web = app.app.app.app
            async with web.router.lifespan_context(web):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=self.config['origin']) as client:
                    callback = self.config['clients'][0]['redirect_uris'][0]
                    path = '/oauth/authorize?' + urlencode({'response_type': 'code', 'client_id': 'sa',
                        'redirect_uri': callback, 'resource': self.config['origin'] + '/mcp', 'scope': 'mf:read',
                        'code_challenge': CHALLENGE, 'code_challenge_method': 'S256', 'state': 'synthetic-state'})
                    page = await client.get(path, headers=self.signed('GET', path))
                    self.assertEqual(page.status_code, 200)
                    body = urlencode({'request_id': page.json()['request_id'],
                                      'csrf_token': page.json()['csrf_token'], 'decision': 'approve'}).encode()
                    consent = await client.post('/oauth/consent', content=body, headers={
                        **self.signed('POST', '/oauth/consent', body=body),
                        'content-type': 'application/x-www-form-urlencoded'})
                    self.assertEqual(consent.status_code, 303)
                    code = parse_qs(urlsplit(consent.headers['location']).query)['code'][0]
                    token = await client.post('/oauth/token', data={'grant_type': 'authorization_code',
                        'client_id': 'sa', 'redirect_uri': callback, 'resource': self.config['origin'] + '/mcp',
                        'code': code, 'code_verifier': VERIFIER})
                    self.assertEqual(token.status_code, 200)
                    bearer = token.json()['access_token']
                    catalog = await client.post('/mcp', headers={
                        'authorization': 'Bearer ' + bearer,
                        'accept': 'application/json, text/event-stream',
                        'mcp-protocol-version': '2025-03-26'},
                        json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}})
                    self.assertEqual(catalog.status_code, 200)
                    self.assertEqual({t['name'] for t in catalog.json()['result']['tools']},
                                     {'mf_offices', 'mf_list_transactions', 'mf_list_reports'})
                    self.assertEqual(calls, [])
                    for operation, args, denied in [('mf_offices', {}, False),
                            ('expense_context', {}, True),
                            ('mf_create_transaction', {'office': 'synthetic-company', 'recognized_at': '2030-01-01',
                             'value': 1, 'remark': 'synthetic'}, True)]:
                        result = await client.post('/mcp', headers={'authorization': 'Bearer ' + bearer,
                            'accept': 'application/json, text/event-stream', 'mcp-protocol-version': '2025-03-26'},
                            json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                  'params': {'name': operation, 'arguments': args}})
                        self.assertEqual(result.status_code, 200)
                        self.assertEqual(bool(result.json()['result'].get('isError')), denied, result.json())
                        if denied:
                            self.assertIn('operation_unavailable', result.text)
                    self.assertEqual(calls, [('GET', '/api/external/v1/offices')])

    async def test_mf_only_two_people_isolated_and_unknown_denied(self):
        app = self.app()
        settings = settings_from_environment(self.environment())
        vault = EncryptedProviderVault(self.store, settings.encryption_key, namespace=settings.provider_namespace)
        alice = Requester("expense-tenant", "person-alice", time.time() + 3600)
        with vault.transaction(alice.owner, "mf") as record:
            record.update(owner=alice.owner, oauth={"refresh_token": "alice-private-refresh"})
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=self.config["origin"]) as client:
            views = {}
            for name in ("alice", "bob"):
                response = await client.get("/connections", headers=self.signed("GET", "/connections", subject=name))
                self.assertEqual(response.status_code, 200, response.text)
                views[name] = response.json()
                statuses = {row["id"]: row["status"] for row in views[name]["connections"]}
                self.assertEqual(statuses, {"mf": "connected" if name == "alice" else "not_connected", "calendar": "not_configured"})
                self.assertNotIn("alice-private-refresh", response.text)
            # Another person's CSRF nonce cannot begin a provider grant.
            body = urlencode({"provider": "mf", "csrf_token": views["alice"]["csrf_token"]}).encode()
            response = await client.post("/connections/start", content=body, headers={
                **self.signed("POST", "/connections/start", subject="bob", body=body),
                "content-type": "application/x-www-form-urlencoded"})
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["error"], "service_connection_start_unavailable")
            body = urlencode({"provider": "mf", "csrf_token": views["bob"]["csrf_token"]}).encode()
            response = await client.post("/connections/start", content=body, headers={
                **self.signed("POST", "/connections/start", subject="bob", body=body),
                "content-type": "application/x-www-form-urlencoded"})
            self.assertEqual(response.status_code, 303)
            destination = urlsplit(response.headers["location"])
            self.assertEqual(destination.netloc, "expense.moneyforward.com")
            self.assertEqual(parse_qs(destination.query)["redirect_uri"], [self.config["mf"]["callback_uri"]])
            for subject, tenant in (("unknown", "sa-tenant"), ("alice", "wrong-tenant")):
                response = await client.get("/connections", headers=self.signed("GET", "/connections", subject=subject, tenant=tenant))
                self.assertEqual(response.status_code, 401)

    async def test_health_tls_host_and_cloud_callback_methods(self):
        app = self.app()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://expense.example.test") as client:
            health = await client.get("/health")
            self.assertEqual(health.json(), {"status": "ok"})
            metadata = await client.get("/.well-known/oauth-authorization-server", headers={"x-forwarded-proto": "http"})
            self.assertEqual(metadata.status_code, 200)
            bad_host = await client.get("/connections", headers={"host": "other.test", **self.signed("GET", "/connections")})
            self.assertEqual(bad_host.status_code, 401)
            response = await client.get("/connections/callback?provider=mf&code=private-code")
            self.assertEqual(response.status_code, 405)
            self.assertEqual(response.headers["allow"], "POST")
            self.assertNotIn("private-code", response.text)
            # Signed POST reaches the existing callback handler (invalid state).
            body = b"provider=mf&code=private-code&state=unknown"
            response = await client.post("/connections/callback", content=body, headers={
                **self.signed("POST", "/connections/callback", body=body),
                "content-type": "application/x-www-form-urlencoded"})
            self.assertEqual(response.status_code, 400, response.text)
            self.assertEqual(response.json()["error"], "service_connection_callback_failed")
            self.assertEqual((await client.post("/mcp", json={})).status_code, 401)
        config = {**self.config, "ingress_mode": "asgi_tls"}
        direct = self.app(config)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(direct), base_url="http://expense.example.test") as client:
            response = await client.get("/.well-known/oauth-authorization-server", headers={"x-forwarded-proto": "https", "forwarded": "proto=https"})
            self.assertEqual(response.status_code, 400)

    async def test_other_provider_combinations_and_lifespan_cleanup(self):
        for mf, google in ((False, False), (False, True), (True, True)):
            with self.subTest(mf=mf, google=google):
                config = copy.deepcopy(self.config)
                if not mf:
                    config.pop("mf")
                    self.env.pop("EXPENSE_MF_CLIENT_SECRET", None)
                else:
                    self.env["EXPENSE_MF_CLIENT_SECRET"] = "synthetic-mf-secret"
                if google:
                    config["google"] = {"client_id": "synthetic-google", "callback_uri": "https://sa.example.test/api/chat/agent-service-callback?provider=calendar"}
                    self.env["EXPENSE_GOOGLE_CLIENT_SECRET"] = "synthetic-google-secret"
                app = self.app(config)
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=self.config["origin"]) as client:
                    response = await client.get("/connections", headers=self.signed("GET", "/connections"))
                    self.assertEqual(response.status_code, 200)
                    statuses = {row["id"]: row["status"] for row in response.json()["connections"]}
                    self.assertEqual(statuses, {"mf": "not_connected" if mf else "not_configured", "calendar": "not_connected" if google else "not_configured"})
                    page = await client.get("/connections", headers={
                        **self.signed("GET", "/connections"), "accept": "text/html"})
                    for label, configured in (("マネーフォワード経費", mf), ("Googleカレンダー", google)):
                        self.assertEqual(label + "に接続する</button>" in page.text, configured)
                    if not mf or not google:
                        self.assertIn("設定未完了", page.text)
                    self.assertNotIn("再認証", page.text)
                    self.assertNotIn("復旧", page.text)
                queue = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
                messages = []

                async def receive():
                    return next(queue)

                async def send(message):
                    messages.append(message)

                with patch.object(app._resources[0], "close") as close:
                    await app({"type": "lifespan"}, receive, send)
                    close.assert_called_once()
                self.assertEqual([m["type"] for m in messages], ["lifespan.startup.complete", "lifespan.shutdown.complete"])

    def test_entrypoint_disables_proxy_access_and_library_logging(self):
        with patch("uvicorn.run") as run, patch.dict("os.environ", {"PORT": "9090"}):
            main()
        self.assertFalse(run.call_args.kwargs["proxy_headers"])
        self.assertFalse(run.call_args.kwargs["access_log"])
        self.assertEqual(run.call_args.kwargs["port"], 9090)
        self.assertEqual(run.call_args.kwargs["log_level"], "critical")
        self.assertTrue(logging.root.manager.disable >= logging.CRITICAL)


if __name__ == "__main__":
    unittest.main()
