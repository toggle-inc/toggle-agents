"""Synthetic MF HTTP only; private temp storage, no real credentials/network."""

import contextlib
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from cryptography.fernet import Fernet
from starlette.datastructures import QueryParams

from runtime.auth_store import SQLiteAuthorizationStore
from runtime.personal_mf import PersonalMF
from runtime.provider_vault import EncryptedProviderVault
from runtime.requester import Requester
from runtime.service_connections import ConnectionProvider, ServiceConnections
from runtime.state import ExpenseError, OutcomeUnknownError


class PersonalMFTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = 1000
        self.person = Requester("synthetic-tenant", "alice", 10000)
        self.bob = Requester("synthetic-tenant", "bob", 10000)
        self.store = SQLiteAuthorizationStore(self.root / "auth.sqlite")
        self.addCleanup(self.store.close)
        self.vault = EncryptedProviderVault(self.store, Fernet.generate_key(), namespace="mf-test")
        self.calls = []
        self.handler = self.success
        self.http = httpx.Client(base_url="https://expense.moneyforward.com",
                                 transport=httpx.MockTransport(self.dispatch))
        self.addCleanup(self.http.close)
        self.adapter = self.make_adapter()

    def success(self, request):
        if request.url.path == "/oauth/token":
            return httpx.Response(200, json={"access_token": "synthetic-access",
                                            "refresh_token": "synthetic-refresh", "expires_in": 3600})
        return httpx.Response(200, json={"offices": [{"id": "synthetic-office"}]})

    def dispatch(self, request):
        self.calls.append(request)
        return self.handler(request)

    def make_adapter(self, **kwargs):
        return PersonalMF(client_id="synthetic-app", client_secret="synthetic-secret",
                          redirect_uri="https://callback.example.test/connections/callback",
                          vault_store=kwargs.pop("vault_store", self.vault),
                          http=self.http, clock=lambda: self.now, **kwargs)

    def start(self, person=None, adapter=None):
        url = (adapter or self.adapter).begin(person or self.person, "mf")
        return parse_qs(urlsplit(url).query)["state"][0]

    def connect(self):
        return self.adapter.complete(self.person, "mf", {"state": self.start(), "code": "synthetic-code"})

    def put(self, data, person=None):
        person = person or self.person
        with self.vault.transaction(person.owner, "mf") as record:
            record.clear()
            record.update({"owner": person.owner, **data})

    def read(self):
        with self.vault.transaction(self.person.owner, "mf") as record:
            return dict(record)

    def test_gui_contract_success_and_no_secret_result_or_plaintext_auth_record(self):
        manager = ServiceConnections(self.store, providers=(ConnectionProvider(
            "mf", "MF", frozenset({"https://expense.moneyforward.com"})),),
            status=self.adapter.status, begin=self.adapter.begin, clock=lambda: self.now)
        view = manager.view(self.person)
        self.assertEqual(view["connections"][0]["status"], "not_connected")
        target = manager.start(self.person, "mf", view["csrf_token"])
        query = parse_qs(urlsplit(target).query)
        self.assertEqual(query["redirect_uri"], [self.adapter.redirect_uri])
        result = self.adapter.complete(self.person, "mf", {"state": query["state"][0], "code": "synthetic-code"})
        self.assertEqual(result, {"provider": "mf", "status": "connected"})
        self.assertEqual(self.adapter.status(self.person, "mf"), "connected")
        self.assertEqual(self.adapter.status(self.bob, "mf"), "not_connected")
        self.assertEqual(self.calls[0].url.path, "/oauth/token")
        self.assertEqual(parse_qs(self.calls[0].content.decode())["redirect_uri"], [self.adapter.redirect_uri])
        raw = (self.root / "auth.sqlite").read_bytes()
        for secret in (b"synthetic-access", b"synthetic-refresh", b"synthetic-secret", b"synthetic-code"):
            self.assertNotIn(secret, raw)
        self.assertEqual(len(self.calls), 1)

    def test_fixed_provider_query_callback_preserves_exact_exchange_redirect_uri(self):
        redirect_uri = "https://callback.example.test/connections/callback?provider=mf"
        adapter = PersonalMF(
            client_id="synthetic-app", client_secret="synthetic-secret",
            redirect_uri=redirect_uri, vault_store=self.vault,
            http=self.http, clock=lambda: self.now,
        )
        manager = ServiceConnections(
            self.store, providers=(ConnectionProvider(
                "mf", "MF", frozenset({"https://expense.moneyforward.com"})),),
            status=adapter.status, begin=adapter.begin, complete=adapter.complete,
            clock=lambda: self.now,
        )
        target = manager.start(self.person, "mf", manager.view(self.person)["csrf_token"])
        authorization = parse_qs(urlsplit(target).query)
        self.assertEqual(authorization["redirect_uri"], [redirect_uri])
        # MF appends code/state to the registered callback's existing query.
        code = "synthetic+code/with=reserved&characters"
        callback_url = authorization["redirect_uri"][0] + "&" + urlencode({
            "code": code, "state": authorization["state"][0],
        })
        parameters = QueryParams(urlsplit(callback_url).query)
        provider = parameters["provider"]
        result = manager.complete(self.person, provider, {
            key: value for key, value in parameters.items() if key != "provider"
        })
        self.assertEqual(result["status"], "connected")
        self.assertEqual(result["provider"], "mf")
        self.assertEqual(adapter.status(self.person, "mf"), "connected")
        self.assertEqual(len(self.calls), 1)
        exchanged = parse_qs(self.calls[0].content.decode())
        self.assertEqual(exchanged["redirect_uri"], [redirect_uri])
        self.assertEqual(exchanged["code"], [code])

    def test_status_uses_vault_only_and_validates_schema(self):
        cases = [({}, "not_connected"), ({"oauth": {"refresh_token": "r"}}, "connected"),
                 ({"oauth": {"access_token": "a", "obtained_at": 900, "expires_in": 101}}, "connected"),
                 ({"oauth": {"access_token": "a", "obtained_at": 900, "expires_in": 100}}, "expired"),
                 ({"oauth": []}, "unavailable"), ({"oauth": {"access_token": []}}, "unavailable"),
                 ({"oauth": {"access_token": "a", "obtained_at": "900", "expires_in": 3}}, "unavailable"),
                 ({"oauth": {"reconnect_required": True}}, "expired")]
        for data, expected in cases:
            with self.subTest(data=data):
                self.put(data)
                self.assertEqual(self.adapter.status(self.person, "mf"), expected)
        self.assertEqual(self.calls, [])

    def test_wrong_owner_tenant_and_replayed_callback_refused(self):
        state = self.start()
        params = {"state": state, "code": "synthetic-code"}
        for person in (self.bob, Requester("other-tenant", "alice", 10000)):
            with self.assertRaises(ExpenseError):
                self.adapter.complete(person, "mf", params)
        self.adapter.complete(self.person, "mf", params)
        with self.assertRaises(ExpenseError):
            self.make_adapter().complete(self.person, "mf", params)
        self.assertEqual(len(self.calls), 1)

    def test_expired_session_state_wrong_state_and_duplicate_parameters(self):
        state = self.start()
        with self.assertRaises(ExpenseError):
            self.adapter.complete(self.person, "mf", {"state": "wrong", "code": "code"})
        with self.assertRaises(ValueError):
            self.adapter.complete(self.person, "mf", QueryParams(f"state={state}&code=a&code=b"))
        self.now += 600
        with self.assertRaises(ExpenseError):
            self.adapter.complete(self.person, "mf", {"state": state, "code": "code"})
        for person in (Requester("t", "p", self.now), Requester("t", "p", 10000, "service"),
                       Requester("", "p", 10000), {"tenant_id": "t"}):
            with self.assertRaises(ValueError):
                self.adapter.status(person, "mf")
        self.assertEqual(self.calls, [])

    def test_consent_denial_consumes_state_without_network(self):
        state = self.start()
        with self.assertRaises(ExpenseError) as error:
            self.adapter.complete(self.person, "mf", {"state": state, "error": "secret-error-body"})
        self.assertNotIn("secret-error", str(error.exception))
        with self.assertRaises(ExpenseError):
            self.adapter.complete(self.person, "mf", {"state": state, "code": "code"})
        self.assertEqual(self.calls, [])
        self.assertEqual(self.read()["auth_outcome"], "denied")

    def test_exchange_timeout_is_consumed_and_error_is_safe(self):
        def timeout(request):
            raise httpx.ReadTimeout("secret-code-token-body")
        self.handler = timeout
        params = {"state": self.start(), "code": "synthetic-code"}
        for _ in range(2):
            with self.assertRaises(ExpenseError) as error:
                self.make_adapter().complete(self.person, "mf", params)
            self.assertNotIn("secret-code", str(error.exception))
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn("pending", self.read())

    def test_concurrent_instances_exchange_exactly_once(self):
        params = {"state": self.start(), "code": "synthetic-code"}
        barrier = threading.Barrier(2)
        def callback(_):
            adapter = self.make_adapter()
            barrier.wait(timeout=5)
            try:
                adapter.complete(self.person, "mf", params)
                return True
            except ExpenseError:
                return False
        with ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(callback, range(2))), [False, True])
        self.assertEqual(len(self.calls), 1)

    def test_new_begin_invalidates_consumed_old_attempt_before_exchange(self):
        state = self.start()
        original = self.vault
        adapter = self.adapter
        class Interleave:
            fired = False
            @contextlib.contextmanager
            def transaction(inner, owner, provider):
                with original.transaction(owner, provider) as data:
                    consumed = "pending" in data
                    yield data
                    consumed = consumed and "pending" not in data
                if consumed and not inner.fired:
                    inner.fired = True
                    adapter.begin(self.person, "mf")
        adapter.vault_store = Interleave()
        with self.assertRaises(ExpenseError):
            adapter.complete(self.person, "mf", {"state": state, "code": "old-code"})
        self.assertEqual(self.calls, [])
        self.assertIn("pending", self.read())

    def test_new_completed_authorization_cannot_be_overwritten_by_old_callback(self):
        state = self.start()
        original = self.vault
        adapter = self.adapter
        class Interleave:
            fired = False
            @contextlib.contextmanager
            def transaction(inner, owner, provider):
                with original.transaction(owner, provider) as data:
                    consumed = "pending" in data
                    yield data
                    consumed = consumed and "pending" not in data
                if consumed and not inner.fired:
                    inner.fired = True
                    fresh = self.start()
                    adapter.complete(self.person, "mf", {"state": fresh, "code": "new-code"})
        adapter.vault_store = Interleave()
        with self.assertRaises(ExpenseError):
            adapter.complete(self.person, "mf", {"state": state, "code": "old-code"})
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(parse_qs(self.calls[0].content.decode())["code"], ["new-code"])
        self.assertEqual(self.adapter.status(self.person, "mf"), "connected")

    def test_refresh_success_rotation_and_preserved_refresh_token(self):
        self.connect()
        self.handler = lambda request: httpx.Response(200, json={"access_token": "new-access", "expires_in": 3600})
        self.adapter.refresh(self.person)
        self.assertEqual(self.read()["oauth"]["refresh_token"], "synthetic-refresh")
        self.assertEqual(self.read()["oauth"]["access_token"], "new-access")

    def test_refresh_timeout_persists_reconnect_and_never_reuses_old_token(self):
        self.connect()
        self.handler = lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("secret-body"))
        for _ in range(2):
            with self.assertRaises(ExpenseError):
                self.adapter.refresh(self.person)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.adapter.status(self.person, "mf"), "expired")
        self.assertTrue(self.read()["oauth"]["reconnect_required"])
        self.assertTrue(self.read()["oauth"]["refresh_unknown"])
        self.assertNotIn("refresh_token", self.read()["oauth"])
        with self.assertRaises(ExpenseError):
            self.adapter.for_person(self.person).offices()
        self.assertEqual(len(self.calls), 2)

    def test_facade_refreshes_expired_token_and_rechecks_person(self):
        self.connect()
        self.now += 3500
        facade = self.adapter.for_person(self.person)
        self.assertEqual(facade.owner, self.person.owner)
        self.assertEqual(facade.offices(), [{"id": "synthetic-office"}])
        self.assertEqual([r.url.path for r in self.calls], ["/oauth/token", "/oauth/token", "/api/external/v1/offices"])
        with self.assertRaises(AttributeError):
            facade.complete_auth("raw-code")
        with self.assertRaises(AttributeError):
            facade.authorize_url()
        self.now = self.person.expires_at
        with self.assertRaises(ValueError):
            facade.offices()

    def test_facade_get_401_refreshes_once(self):
        self.connect()
        reads = []
        def unauthorized(request):
            if request.url.path == "/oauth/token":
                return self.success(request)
            reads.append(request)
            return httpx.Response(401, json={})
        self.handler = unauthorized
        with self.assertRaises(ExpenseError):
            self.adapter.for_person(self.person).offices()
        self.assertEqual(len(reads), 2)
        self.assertEqual(sum(r.url.path == "/oauth/token" for r in self.calls), 2)

    def test_facade_financial_write_unknown_keeps_type_and_never_retries(self):
        self.connect()
        self.handler = lambda request: httpx.Response(503, text="synthetic-private-response")
        with self.assertRaises(OutcomeUnknownError) as error:
            self.adapter.for_person(self.person).create_transaction("office", {"value": 321})
        self.assertNotIn("synthetic-private-response", str(error.exception))
        self.assertEqual(len(self.calls), 2)

    def test_file_fallback_is_explicit_private_and_rejects_corruption(self):
        root = self.root / "vault"
        adapter = self.make_adapter(vault_store=None, vault_root=root)
        state = self.start(adapter=adapter)
        adapter.complete(self.person, "mf", {"state": state, "code": "code"})
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        path = next(root.glob("*.json"))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(adapter.status(self.person, "mf"), "connected")
        # Test-only corruption in the isolated temp vault.
        path.write_text("[]")
        self.assertEqual(adapter.status(self.person, "mf"), "unavailable")
        path.unlink()
        path.symlink_to(self.root / "absent")
        self.assertEqual(adapter.status(self.person, "mf"), "unavailable")

    def test_no_implicit_file_fallback_and_exact_https_callback_required(self):
        with self.assertRaises(ValueError):
            self.make_adapter(vault_store=None)
        with self.assertRaises(ValueError):
            self.make_adapter(vault_root=self.root / "vault")
        for url in ("http://callback.example/cb", "urn:ietf:wg:oauth:2.0:oob",
                    "https://u:p@callback.example/cb", "https://callback.example/cb?next=x",
                    "https://callback.example/connections/callback?provider=calendar",
                    "https://callback.example/connections/callback?provider=mf&next=x",
                    "https://callback.example/connections/callback?provider=mf&provider=mf",
                    "https://callback.example/connections/callback?provider=%6df",
                    "https://callback.example/connections/callback?provider=mf&",
                    "https://callback.example/connections/callback?code=x&provider=mf",
                    "https://callback.example/cb#fragment"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                PersonalMF(client_id="app", client_secret="secret", redirect_uri=url, vault_store=self.vault)

    def test_mismatched_vault_owner_is_unavailable_and_cannot_be_overwritten(self):
        self.put({"owner": self.bob.owner, "oauth": {"refresh_token": "other-token"}})
        self.assertEqual(self.adapter.status(self.person, "mf"), "unavailable")
        with self.assertRaises(ExpenseError):
            self.start()
        self.assertEqual(self.calls, [])

    def test_commit_failure_after_exchange_does_not_allow_callback_replay(self):
        state = self.start()
        original = self.vault
        class FailCredentialCommit:
            @contextlib.contextmanager
            def transaction(inner, owner, provider):
                with original.transaction(owner, provider) as data:
                    yield data
                    if "oauth" in data:
                        raise OSError("synthetic-private-store-error")
        self.adapter.vault_store = FailCredentialCommit()
        params = {"state": state, "code": "synthetic-code"}
        for _ in range(2):
            with self.assertRaises(ExpenseError):
                self.adapter.complete(self.person, "mf", params)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.read()["auth_outcome"], "unknown")
        self.assertEqual(self.adapter.status(self.person, "mf"), "expired")

    def test_refresh_commit_failure_retains_unknown_and_no_old_token(self):
        self.connect()
        original = self.vault
        class FailCredentialCommit:
            @contextlib.contextmanager
            def transaction(inner, owner, provider):
                with original.transaction(owner, provider) as data:
                    yield data
                    if data.get("oauth", {}).get("access_token"):
                        raise OSError("synthetic-private-store-error")
        self.adapter.vault_store = FailCredentialCommit()
        for _ in range(2):
            with self.assertRaises(ExpenseError):
                self.adapter.refresh(self.person)
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(self.read()["oauth"]["refresh_unknown"])
        self.assertNotIn("refresh_token", self.read()["oauth"])

    def test_concurrent_file_vault_instances_exchange_once(self):
        root = self.root / "file-vault"
        adapter = self.make_adapter(vault_store=None, vault_root=root)
        params = {"state": self.start(adapter=adapter), "code": "synthetic-code"}
        barrier = threading.Barrier(2)
        def callback(_):
            instance = self.make_adapter(vault_store=None, vault_root=root)
            barrier.wait(timeout=5)
            try:
                instance.complete(self.person, "mf", params)
                return True
            except ExpenseError:
                return False
        with ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(callback, range(2))), [False, True])
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
