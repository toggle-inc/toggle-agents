"""Synthetic OAuth/Calendar only: MockTransport and temporary private vaults."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import copy
import hashlib
import multiprocessing
import os
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

import httpx
from starlette.datastructures import QueryParams

from runtime.personal_calendar import PersonalCalendar, SCOPE, TOKEN_URL, EVENTS_URL
from runtime.requester import Requester
from runtime.state import ExpenseError


def _file_refresh_worker(root, now, started, committed, results):
    def handler(request):
        results.put("refresh")
        return httpx.Response(200, json={"access_token": "process-access",
            "refresh_token": "process-refresh", "expires_in": 3600, "token_type": "Bearer"})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        adapter = PersonalCalendar(client_id="synthetic-client", client_secret="synthetic-secret",
            callback_uri="https://app.example/connections/callback", private_vault_root=root,
            clock=lambda: now, http_client=client)
        person = Requester("tenant-a", "alice", now + 10000)
        started.wait(timeout=10)
        initial = adapter.status(person)
        if initial == "connected":
            committed.set()
        if not committed.wait(timeout=10):
            raise AssertionError("Refresh did not commit")
        results.put({"initial": initial, "final": adapter.status(person)})


class MemoryVault:
    """Transactional stand-in; a separate adapter instance sees the same lock."""

    def __init__(self):
        self.rows = {}
        self.lock = threading.RLock()
        self.calls = []

    @contextmanager
    def transaction(self, owner, provider):
        with self.lock:
            self.calls.append((owner, provider))
            key = (owner, provider)
            data = copy.deepcopy(self.rows.get(key, {}))
            yield data
            self.rows[key] = copy.deepcopy(data)


class PersonalCalendarTests(unittest.TestCase):
    def setUp(self):
        self.now = 1900000000.0
        self.alice = Requester("tenant-a", "alice", self.now + 10000)
        self.bob = Requester("tenant-a", "bob", self.now + 10000)
        self.other_tenant = Requester("tenant-b", "alice", self.now + 10000)
        self.vault = MemoryVault()
        self.requests = []
        self.handler = lambda request: httpx.Response(200, json=self.tokens())
        self.client = httpx.Client(transport=httpx.MockTransport(self.dispatch))
        self.addCleanup(self.client.close)
        self.adapter = self.make_adapter()

    def tokens(self, **overrides):
        return {"access_token": "synthetic-access", "refresh_token": "synthetic-refresh",
                "expires_in": 3600, "token_type": "Bearer", "scope": SCOPE, **overrides}

    def dispatch(self, request):
        self.requests.append(request)
        self.assertIn(str(request.url).split("?")[0], (TOKEN_URL, EVENTS_URL))
        return self.handler(request)

    def make_adapter(self, **overrides):
        return PersonalCalendar(**{
            "client_id": "synthetic-client", "client_secret": "synthetic-secret",
            "callback_uri": "https://app.example/connections/callback",
            "vault_store": self.vault, "clock": lambda: self.now,
            "http_client": self.client, **overrides})

    def begin(self, person=None):
        url = self.adapter.begin(person or self.alice, "calendar")
        return parse_qs(urlsplit(url).query)

    def connect(self, person=None):
        person = person or self.alice
        query = self.begin(person)
        state = query["state"][0]
        self.assertEqual(self.adapter.complete(person, "calendar", {
            "state": state, "code": "synthetic-code"}), "connected")
        return state

    def row(self, person=None):
        return self.vault.rows[((person or self.alice).owner, "calendar")]

    def test_pkce_offline_fixed_callback_and_no_secret_outputs(self):
        self.assertEqual(self.adapter.status(self.alice, "calendar"), "not_connected")
        query = self.begin()
        self.assertEqual(query["scope"], [SCOPE])
        self.assertEqual(query["access_type"], ["offline"])
        self.assertEqual(query["prompt"], ["consent"])
        self.assertEqual(query["redirect_uri"], [self.adapter.callback_uri])
        self.assertNotIn("synthetic-secret", str(query))
        verifier = self.row()["pending"]["verifier"]
        import base64
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(query["code_challenge"], [challenge])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        result = self.adapter.complete(self.alice, "calendar", {
            "state": query["state"][0], "code": "synthetic-code"})
        self.assertEqual(result, "connected")
        posted = parse_qs(self.requests[-1].content.decode())
        self.assertEqual(posted["code_verifier"], [verifier])
        self.assertEqual(posted["client_secret"], ["synthetic-secret"])
        self.assertNotIn("code", self.row())
        self.assertNotIn("pending", self.row())
        self.assertTrue(all(provider == "calendar" for _, provider in self.vault.calls))

    def test_other_person_and_tenant_cannot_use_callback_or_connection(self):
        state = self.begin()["state"][0]
        for person in (self.bob, self.other_tenant):
            with self.assertRaises(ValueError):
                self.adapter.complete(person, "calendar", {"code": "code", "state": state})
            self.assertEqual(self.adapter.status(person), "not_connected")
        self.assertEqual(self.requests, [])
        self.assertEqual(self.adapter.complete(self.alice, "calendar", {
            "code": "code", "state": state}), "connected")

    def test_callback_replay_expiry_and_replaced_pending(self):
        state = self.connect()
        with self.assertRaises(ValueError):
            self.adapter.complete(self.alice, "calendar", {"state": state, "code": "code"})
        state = self.begin()["state"][0]
        self.now += 301
        with self.assertRaises(ValueError):
            self.adapter.complete(self.alice, "calendar", {"state": state, "code": "code"})
        state = self.begin()["state"][0]
        self.begin()
        with self.assertRaises(ValueError):
            self.adapter.complete(self.alice, "calendar", {"state": state, "code": "code"})
        self.assertEqual(len(self.requests), 1)

    def test_denial_and_duplicate_callback_parameters_are_consumed(self):
        for params in (lambda s: {"state": s, "error": "access_denied"},
                       lambda s: QueryParams("state=" + s + "&code=a&code=b")):
            state = self.begin()["state"][0]
            self.assertEqual(self.adapter.complete(self.alice, "calendar", params(state)), "expired")
            with self.assertRaises(ValueError):
                self.adapter.complete(self.alice, "calendar", {"state": state, "code": "code"})
        self.assertEqual(self.requests, [])

    def test_unknown_code_exchange_never_retries(self):
        def fail(request):
            raise httpx.ReadTimeout("synthetic-sensitive-error")
        self.handler = fail
        state = self.begin()["state"][0]
        with self.assertRaisesRegex(ExpenseError, "一時的"):
            self.adapter.complete(self.alice, "calendar", {"state": state, "code": "code"})
        with self.assertRaises(ValueError):
            self.adapter.complete(self.alice, "calendar", {"state": state, "code": "code"})
        self.assertNotIn("pending", self.row())
        self.assertEqual(len(self.requests), 1)

    def test_missing_refresh_requires_reconsent_without_reusing_old_account(self):
        self.connect()
        tokens = self.tokens()
        del tokens["refresh_token"]
        self.handler = lambda request: httpx.Response(200, json=tokens)
        state = self.begin()["state"][0]
        self.assertEqual(self.adapter.complete(self.alice, "calendar", {
            "state": state, "code": "code"}), "expired")
        self.assertEqual(self.adapter.status(self.alice), "expired")
        self.assertNotIn("oauth", self.row())

    def test_refresh_preserves_token_when_omitted_and_rotates_when_returned(self):
        self.connect()
        self.now += 3541
        tokens = self.tokens(access_token="second-access")
        del tokens["refresh_token"]
        self.handler = lambda request: httpx.Response(200, json=tokens)
        self.assertEqual(self.adapter.status(self.alice), "connected")
        self.assertEqual(self.row()["oauth"]["refresh_token"], "synthetic-refresh")
        posted = parse_qs(self.requests[-1].content.decode())
        self.assertEqual(posted["grant_type"], ["refresh_token"])
        self.now += 3541
        self.handler = lambda request: httpx.Response(200, json=self.tokens(refresh_token="rotated"))
        self.assertEqual(self.adapter.status(self.alice), "connected")
        self.assertEqual(self.row()["oauth"]["refresh_token"], "rotated")

    def test_refresh_serialized_across_adapter_instances(self):
        self.connect()
        self.now += 3541
        other = self.make_adapter()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda adapter: adapter.status(self.alice), (self.adapter, other)))
        self.assertEqual(results, ["connected", "connected"])
        self.assertEqual(len(self.requests), 2)  # code + one refresh

    def test_invalid_grant_is_reauthentication_and_reconnect_restores_connection(self):
        self.connect()
        self.now += 3541
        self.handler = lambda request: httpx.Response(400, json={"error": "invalid_grant"})
        self.assertEqual(self.adapter.status(self.alice), "expired")
        self.assertEqual(self.adapter.status(self.alice), "expired")
        self.assertEqual(len(self.requests), 2)
        self.handler = lambda request: httpx.Response(200, json=self.tokens())
        self.connect()
        self.assertEqual(self.adapter.status(self.alice), "connected")

    def test_unknown_refresh_persists_fence_and_never_blindly_retries(self):
        for response in (None, httpx.Response(503, json={"error": "temporary"}),
                         httpx.Response(200, json=self.tokens(token_type=123))):
            self.now = 1900000000.0
            self.vault.rows.clear()
            self.handler = lambda request: httpx.Response(200, json=self.tokens())
            self.connect()
            self.now += 3541
            def fail(request):
                if response is None:
                    raise httpx.ReadTimeout("synthetic-sensitive-error")
                return response
            self.handler = fail
            self.assertEqual(self.adapter.status(self.alice), "expired")
            count = len(self.requests)
            other = self.make_adapter()
            self.assertEqual(other.status(self.alice), "expired")
            self.assertEqual(len(self.requests), count)
            self.assertTrue(self.row()["refresh_unknown"])
            state = self.begin()["state"][0]
            self.assertTrue(self.row()["refresh_unknown"])
            self.assertEqual(other.status(self.alice), "expired")
            self.assertEqual(len(self.requests), count)
            self.assertEqual(self.adapter.complete(self.alice, "calendar", {
                "state": state, "error": "access_denied"}), "expired")
            self.assertTrue(self.row()["refresh_unknown"])
            self.handler = lambda request: httpx.Response(200, json=self.tokens())
            self.connect()
            self.assertNotIn("refresh_unknown", self.row())
            self.assertEqual(other.status(self.alice), "connected")
            self.assertEqual(len(self.requests), count + 1)
            self.assertEqual(parse_qs(self.requests[-1].content.decode())["grant_type"],
                             ["authorization_code"])

    def test_encrypted_vault_contract_consumption_and_refresh_fence_survive_reopen(self):
        from cryptography.fernet import Fernet
        from runtime.provider_vault import EncryptedProviderVault

        class Records:
            def __init__(self):
                self.rows = {}

            def get(self, key):
                return self.rows.get(key)

            def put(self, key, value):
                self.rows[key] = value

        class Store:
            def __init__(self):
                self.records = Records()

            @contextmanager
            def transaction(self):
                previous = copy.deepcopy(self.records.rows)
                try:
                    yield self.records
                except Exception:
                    self.records.rows = previous
                    raise

        store, key = Store(), Fernet.generate_key()
        self.vault = EncryptedProviderVault(store, key, namespace="synthetic")
        self.adapter = self.make_adapter()
        self.connect()
        self.assertNotIn("synthetic-refresh", str(store.records.rows))
        self.assertNotIn("synthetic-access", str(store.records.rows))
        self.now += 3541
        def fail(request):
            raise httpx.ReadTimeout("synthetic")
        self.handler = fail
        self.assertEqual(self.adapter.status(self.alice), "expired")
        count = len(self.requests)
        reopened = self.make_adapter(vault_store=EncryptedProviderVault(store, key, namespace="synthetic"))
        self.assertEqual(reopened.status(self.alice), "expired")
        self.assertEqual(len(self.requests), count)
        state = parse_qs(urlsplit(reopened.begin(self.alice)).query)["state"][0]
        with self.assertRaisesRegex(ExpenseError, "一時的"):
            reopened.complete(self.alice, "calendar", {"state": state, "code": "synthetic"})
        self.assertEqual(reopened.status(self.alice), "expired")
        with self.assertRaises(ValueError):
            reopened.complete(self.alice, "calendar", {"state": state, "code": "synthetic"})

    def test_callback_with_fixed_provider_query_is_preserved_exactly(self):
        self.adapter = self.make_adapter(
            callback_uri="https://app.example/connections/callback?provider=calendar")
        state = self.connect()
        self.assertTrue(state)
        posted = parse_qs(self.requests[-1].content.decode())
        self.assertEqual(posted["redirect_uri"], [self.adapter.callback_uri])

    def test_events_matches_calendar_shape_pagination_and_inclusive_japan_dates(self):
        self.connect()
        def events(request):
            self.assertEqual(request.headers["authorization"], "Bearer synthetic-access")
            params = request.url.params
            self.assertEqual(params["timeMin"], "2030-01-01T00:00:00+09:00")
            self.assertEqual(params["timeMax"], "2030-01-03T00:00:00+09:00")
            if params.get("pageToken") == "next":
                return httpx.Response(200, json={"items": [{"id": "all-day",
                    "start": {"date": "2030-01-02"}, "end": {"date": "2030-01-03"}}]})
            return httpx.Response(200, json={"items": [
                {"id": "cancel", "status": "cancelled"},
                {"id": "free", "transparency": "transparent"},
                {"id": "meeting", "start": {"dateTime": "2030-01-01T00:00:00Z"},
                 "end": {"dateTime": "2030-01-01T01:00:00Z"}, "summary": "Synthetic",
                 "description": "x" * 400, "location": "Example"}], "nextPageToken": "next"})
        self.handler = events
        bound = self.adapter.for_person(self.alice)
        result = bound.events("2030-01-01", "2030-01-02")
        self.assertEqual(bound.owner, self.alice.owner)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["start"], "2030-01-01T09:00+09:00")
        self.assertFalse(result[0]["all_day"])
        self.assertEqual(len(result[0]["description"]), 300)
        self.assertTrue(result[1]["all_day"])

    def test_events_failure_keeps_rotated_refresh_committed_and_no_partial_results(self):
        self.connect()
        self.now += 3541
        def handler(request):
            if str(request.url) == TOKEN_URL:
                return httpx.Response(200, json=self.tokens(refresh_token="rotated"))
            raise httpx.ReadTimeout("sensitive-error")
        self.handler = handler
        with self.assertRaisesRegex(ExpenseError, "一時的"):
            self.adapter.events(self.alice, "2030-01-01", "2030-01-02")
        self.assertEqual(self.row()["oauth"]["refresh_token"], "rotated")
        self.assertEqual(self.adapter.status(self.alice), "connected")

    def test_read_provider_503_remains_unavailable_without_reauthorization(self):
        self.connect()
        original = copy.deepcopy(self.row()["oauth"])
        self.handler = lambda request: httpx.Response(503, json={"error": "temporary"})
        with self.assertRaisesRegex(ExpenseError, "一時的"):
            self.adapter.events(self.alice, "2030-01-01", "2030-01-02")
        self.assertEqual(self.row()["oauth"], original)
        self.assertNotIn("refresh_unknown", self.row())
        self.assertFalse(self.row().get("reauthorize"))
        self.assertEqual(self.adapter.status(self.alice), "connected")
        self.assertEqual(len(self.requests), 2)  # code exchange and read only

    def test_revoked_events_connection_and_validation_no_fallback(self):
        self.connect()
        self.handler = lambda request: httpx.Response(401, json={"error": "revoked"})
        with self.assertRaisesRegex(ExpenseError, "再接続"):
            self.adapter.events(self.alice, "2030-01-01", "2030-01-02")
        self.assertEqual(self.adapter.status(self.alice), "expired")
        count = len(self.requests)
        with self.assertRaises(ExpenseError):
            self.adapter.events(self.bob, "2030-01-01", "2030-01-02")
        with self.assertRaises(ExpenseError):
            self.adapter.events(self.alice, "2031-01-01", "2030-01-02")
        with self.assertRaises(ValueError):
            self.adapter.begin(Requester("a", "b", self.now - 1))
        with self.assertRaises(ValueError):
            self.adapter.status(self.alice, "mf")
        self.assertEqual(len(self.requests), count)

    def test_configuration_and_vault_binding_fail_closed(self):
        for overrides in ({"callback_uri": "http://app.example/callback"},
                          {"callback_uri": "https://app.example/callback?next=evil"},
                          {"vault_store": None},
                          {"private_vault_root": "/unused"}):
            with self.assertRaises(ValueError):
                self.make_adapter(**overrides)
        self.connect()
        self.assertEqual(self.make_adapter(client_id="different").status(self.alice), "unavailable")
        self.row()["owner"] = self.bob.owner
        self.assertEqual(self.adapter.status(self.alice), "unavailable")

    def test_file_vault_permissions_atomic_reopen_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "private"
            self.adapter = self.make_adapter(vault_store=None, private_vault_root=root)
            self.connect()
            tokens = list(root.glob("*/vault.json"))
            self.assertEqual(len(tokens), 1)
            token = tokens[0]
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(token.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(token.stat().st_mode & 0o777, 0o600)
            other = self.make_adapter(vault_store=None, private_vault_root=root)
            self.assertEqual(other.status(self.alice), "connected")
            saved = token.read_text()
            target = Path(temporary) / "target"
            target.write_text(saved)
            os.chmod(target, 0o600)
            token.unlink()
            token.symlink_to(target)
            self.assertEqual(other.status(self.alice), "unavailable")
            self.assertEqual(target.read_text(), saved)
            linked = Path(temporary) / "linked"
            linked.symlink_to(root, target_is_directory=True)
            self.assertEqual(self.make_adapter(vault_store=None, private_vault_root=linked)
                             .status(self.alice), "unavailable")
            token.unlink()
            token.write_text(saved)
            os.chmod(token, 0o644)
            self.assertEqual(other.status(self.alice), "unavailable")

    def test_provider_exchange_commit_failure_never_replays_code_or_refresh(self):
        original = self.vault
        fault = {"armed": False, "fail_commit": False}
        class FaultVault:
            @contextmanager
            def transaction(inner, owner, provider):
                with original.transaction(owner, provider) as data:
                    yield data
                    if fault["fail_commit"]:
                        fault["fail_commit"] = False
                        fault["armed"] = False
                        raise RuntimeError("synthetic commit loss")
        self.adapter = self.make_adapter(vault_store=FaultVault())
        def token(request):
            if fault["armed"]:
                fault["fail_commit"] = True
            return httpx.Response(200, json=self.tokens())
        self.handler = token
        state = self.begin()["state"][0]
        fault["armed"] = True
        with self.assertRaises(RuntimeError):
            self.adapter.complete(self.alice, "calendar", {"state": state, "code": "synthetic-code"})
        count = len(self.requests)
        with self.assertRaises(ValueError):
            self.adapter.complete(self.alice, "calendar", {"state": state, "code": "synthetic-code"})
        self.assertEqual(len(self.requests), count)
        self.assertEqual(self.adapter.status(self.alice), "expired")
        self.connect()
        self.now += 3541
        fault["armed"] = True
        self.assertEqual(self.adapter.status(self.alice), "unavailable")
        count = len(self.requests)
        self.assertEqual(self.adapter.status(self.alice), "unavailable")
        self.now += 61
        self.assertEqual(self.adapter.status(self.alice), "expired")
        self.assertEqual(len(self.requests), count)

    def test_file_refresh_serializes_between_processes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = str(Path(temporary).resolve() / "private")
            self.adapter = self.make_adapter(vault_store=None, private_vault_root=root)
            self.connect()
            self.now += 3541
            context = multiprocessing.get_context("spawn")
            started, committed, results = context.Event(), context.Event(), context.Queue()
            processes = [context.Process(target=_file_refresh_worker,
                args=(root, self.now, started, committed, results)) for _ in range(2)]
            try:
                for process in processes:
                    process.start()
                started.set()
                for process in processes:
                    process.join(timeout=15)
                    self.assertEqual(process.exitcode, 0)
                observed = [results.get(timeout=3) for _ in range(3)]
                # The committed refresh fence intentionally reports unavailable
                # to a concurrent caller while the other process exchanges.
                # Both must observe the same rotated token after its commit,
                # without replaying the old refresh token or provider exchange.
                self.assertEqual(observed.count("refresh"), 1)
                statuses = [row for row in observed if isinstance(row, dict)]
                self.assertEqual(len(statuses), 2)
                self.assertTrue(all(row["initial"] in {"connected", "unavailable"} for row in statuses))
                self.assertEqual([row["final"] for row in statuses], ["connected", "connected"])
                self.assertEqual(self.adapter.status(self.alice), "connected")
                self.assertEqual(self.requests[-1].url, TOKEN_URL)  # Initial code exchange only.
            finally:
                for process in processes:
                    if process.is_alive():
                        process.terminate()
                        process.join(timeout=5)
                results.close()


if __name__ == "__main__":
    unittest.main()
