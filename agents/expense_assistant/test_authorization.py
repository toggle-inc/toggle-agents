"""Real agent token issuance/consent logic with synthetic SSO and no provider APIs."""

import base64
import concurrent.futures
import contextlib
import copy
import dataclasses
import hashlib
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from runtime.auth_store import SQLiteAuthorizationStore  # noqa: E402
from runtime.authorization import AgentAuthorization, AuthorizationError, PublicClient  # noqa: E402
from runtime.requester import Requester, RequesterDispatcher  # noqa: E402
from runtime.state import ExpenseError  # noqa: E402

VERIFIER = "synthetic-pkce-verifier-" + "a" * 43
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()
)


class MemoryStore:
    """Test adapter: same atomic transaction contract, no filesystem or Engine."""

    def __init__(self):
        self.rows, self.lock = {}, threading.RLock()

    @contextlib.contextmanager
    def transaction(self):
        with self.lock:
            prior = copy.deepcopy(self.rows)
            try:
                yield self
            except BaseException:
                self.rows = prior
                raise

    def get(self, key):
        return copy.deepcopy(self.rows.get(key))

    def put(self, key, value):
        self.rows[key] = copy.deepcopy(value)


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "auth.sqlite"
        self.store = SQLiteAuthorizationStore(self.path)
        self.addCleanup(self.store.close)
        self.now = 100
        self.people = {name: Requester("synthetic-tenant", name, 5000) for name in ("alice", "bob")}
        self.clients = [
            PublicClient(
                "sa",
                "SA 検証用",
                ("https://sa.example.test/callback",),
                frozenset({"mf:read", "mf:write", "calendar:read"}),
            ),
            PublicClient(
                "buzz",
                "Buzz 検証用",
                ("https://buzz.example.test/callback",),
                frozenset({"mf:read"}),
            ),
        ]
        self.authority = self.make_authority(self.store)

    def make_authority(self, store, issuer="https://expense.example.test"):
        return AgentAuthorization(
            store,
            lambda session: self.people.get(session),
            issuer=issuer,
            tenant_id="synthetic-tenant",
            clients=self.clients,
            clock=lambda: self.now,
        )

    def pending(self, who="alice", **overrides):
        params = {
            "client_id": "sa",
            "redirect_uri": "https://sa.example.test/callback",
            "resource": self.authority.resource,
            "capabilities": frozenset({"mf:read"}),
            "challenge": CHALLENGE,
            "state": "synthetic-caller-state",
        }
        return self.authority.begin(who, **{**params, **overrides})

    def code(self, who="alice", **overrides):
        pending = self.pending(who, **overrides)
        redirect = self.authority.decide(
            who, pending["request_id"], pending["csrf_token"], approve=True
        )
        self.assertEqual(parse_qs(urlsplit(redirect).query)["state"], ["synthetic-caller-state"])
        return parse_qs(urlsplit(redirect).query)["code"][0]

    def exchange(self, code, **overrides):
        args = {
            "code": code,
            "client_id": "sa",
            "redirect_uri": "https://sa.example.test/callback",
            "resource": self.authority.resource,
            "verifier": VERIFIER,
        }
        return self.authority.exchange(**{**args, **overrides})

    def test_two_people_issue_different_tokens_with_exact_identity_and_scope(self):
        tokens = []
        for who in self.people:
            result = self.exchange(self.code(who))
            token = result["access_token"]
            person = self.authority.authenticate(token)
            self.assertEqual(person.person_id, who)
            self.assertEqual(person.tenant_id, "synthetic-tenant")
            self.assertEqual(person.capabilities, frozenset({"mf:read"}))
            self.assertEqual(result["expires_in"], 900)
            self.assertNotIn("refresh_token", result)
            tokens.append(token)
        self.assertNotEqual(*tokens)

    def test_unknown_service_admin_expired_or_cross_tenant_login_cannot_consent(self):
        self.people.update(
            {
                "admin": Requester("synthetic-tenant", "alice", 5000, kind="admin"),
                "expired": Requester("synthetic-tenant", "alice", 100),
                "other": Requester("other-tenant", "alice", 5000),
            }
        )
        for who in ("unknown", "admin", "expired", "other"):
            with self.subTest(who=who), self.assertRaises(AuthorizationError):
                self.pending(who)

    def test_client_redirect_resource_scopes_and_pkce_are_fixed(self):
        for changes in (
            {"client_id": "unregistered"},
            {"redirect_uri": "https://attacker.example.test"},
            {"resource": "https://other.example.test/mcp"},
            {"capabilities": frozenset({"admin"})},
            {"challenge": "plain-verifier"},
        ):
            with self.subTest(changes=changes), self.assertRaises(AuthorizationError):
                self.pending(**changes)

    def test_consent_requires_same_person_nonce_and_is_single_use(self):
        pending = self.pending()
        for who, nonce in (("bob", pending["csrf_token"]), ("alice", "wrong-nonce")):
            with self.assertRaises(AuthorizationError):
                self.authority.decide(who, pending["request_id"], nonce, approve=True)
        target = self.authority.decide(
            "alice", pending["request_id"], pending["csrf_token"], approve=False
        )
        self.assertIn("access_denied", target)
        with self.assertRaises(AuthorizationError):
            self.authority.decide(
                "alice", pending["request_id"], pending["csrf_token"], approve=True
            )

    def test_no_token_without_consent_and_expired_request_refused(self):
        pending = self.pending()
        with self.assertRaises(AuthorizationError):
            self.exchange(pending["request_id"])
        self.now += 301
        with self.assertRaises(AuthorizationError):
            self.authority.decide(
                "alice", pending["request_id"], pending["csrf_token"], approve=True
            )

    def test_exchange_is_bound_to_pkce_client_redirect_and_resource(self):
        code = self.code()
        for changes in (
            {"verifier": "b" * 64},
            {"client_id": "buzz"},
            {"redirect_uri": "https://sa.example.test/other"},
            {"resource": "https://other.example.test/mcp"},
        ):
            with self.subTest(changes=changes), self.assertRaises(AuthorizationError):
                self.exchange(code, **changes)
        self.exchange(code)
        with self.assertRaises(AuthorizationError):
            self.exchange(code)

    def test_expired_code_and_token_are_refused(self):
        code = self.code()
        self.now += 61
        with self.assertRaises(AuthorizationError):
            self.exchange(code)
        token = self.exchange(self.code())["access_token"]
        self.now += 900
        with self.assertRaises(AuthorizationError):
            self.authority.authenticate(token)

    def test_consent_revoke_invalidates_outstanding_code_and_existing_tokens(self):
        token = self.exchange(self.code())["access_token"]
        # Other person's connection remains usable.
        bob = self.exchange(self.code("bob"))["access_token"]
        self.authority.revoke_consent("alice", "sa")
        with self.assertRaises(AuthorizationError):
            self.authority.authenticate(token)
        self.assertEqual(self.authority.authenticate(bob).person_id, "bob")
        code = self.code()
        self.authority.revoke_consent("alice", "sa")
        with self.assertRaises(AuthorizationError):
            self.exchange(code)

    def test_new_consent_does_not_resurrect_old_tokens(self):
        old = self.exchange(self.code())["access_token"]
        new = self.exchange(self.code())["access_token"]
        with self.assertRaises(AuthorizationError):
            self.authority.authenticate(old)
        self.assertEqual(self.authority.authenticate(new).person_id, "alice")

    def test_token_revoke_requires_matching_client(self):
        token = self.exchange(self.code())["access_token"]
        self.authority.revoke_token(token, "buzz")
        self.authority.authenticate(token)
        self.authority.revoke_token(token, "sa")
        with self.assertRaises(AuthorizationError):
            self.authority.authenticate(token)

    def test_issuer_namespace_and_client_policy_changes_are_enforced(self):
        token = self.exchange(self.code())["access_token"]
        with self.assertRaises(AuthorizationError):
            self.make_authority(self.store, "https://other.example.test").authenticate(token)
        self.authority.clients.pop("sa")
        with self.assertRaises(AuthorizationError):
            self.authority.authenticate(token)

    def test_issued_scope_cannot_be_enlarged_by_provider_resolver(self):
        token = self.exchange(self.code())["access_token"]
        calls = []
        dispatcher = RequesterDispatcher(
            self.authority.authenticate, lambda *args: calls.append(args), clock=lambda: self.now
        )
        with self.assertRaises(AuthorizationError):
            self.authority.authenticate("legacy-shared-token")
        with self.assertRaisesRegex(ExpenseError, "本人の接続"):
            dispatcher.call(
                token, "mf_delete_transaction", {"office": "synthetic", "transaction_id": "test"}
            )
        self.assertEqual(calls, [])

    def test_concurrent_code_exchange_succeeds_once(self):
        code = self.code()

        def attempt(_):
            try:
                return self.exchange(code)["token_type"]
            except AuthorizationError:
                return "refused"

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(8)))
        self.assertEqual(results.count("Bearer"), 1)
        self.assertEqual(results.count("refused"), 7)

    def test_removed_redirect_cannot_receive_consent_code_or_exchange_old_code(self):
        pending = self.pending()
        code = self.code()
        self.authority.clients["sa"] = dataclasses.replace(
            self.authority.clients["sa"], redirect_uris=("https://sa.example.test/new-callback",)
        )
        with self.assertRaises(AuthorizationError):
            self.authority.decide(
                "alice", pending["request_id"], pending["csrf_token"], approve=True
            )
        with self.assertRaises(AuthorizationError):
            self.exchange(code)

    def test_different_storage_adapter_uses_same_authority_without_engine(self):
        memory = self.make_authority(MemoryStore())
        pending = memory.begin(
            "alice",
            client_id="sa",
            redirect_uri="https://sa.example.test/callback",
            resource=memory.resource,
            capabilities=frozenset({"mf:read"}),
            challenge=CHALLENGE,
            state="test",
        )
        location = memory.decide(
            "alice", pending["request_id"], pending["csrf_token"], approve=True
        )
        code = parse_qs(urlsplit(location).query)["code"][0]
        result = memory.exchange(
            code=code,
            client_id="sa",
            redirect_uri="https://sa.example.test/callback",
            resource=memory.resource,
            verifier=VERIFIER,
        )
        self.assertEqual(memory.authenticate(result["access_token"]).person_id, "alice")

    def test_separate_sqlite_connections_cannot_exchange_the_same_code_twice(self):
        second = SQLiteAuthorizationStore(self.path)
        self.addCleanup(second.close)
        other_authority = self.make_authority(second)
        code = self.code()

        def attempt(authority):
            try:
                return authority.exchange(
                    code=code,
                    client_id="sa",
                    redirect_uri="https://sa.example.test/callback",
                    resource=authority.resource,
                    verifier=VERIFIER,
                )["token_type"]
            except AuthorizationError:
                return "refused"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, (self.authority, other_authority)))
        self.assertCountEqual(results, ["Bearer", "refused"])

    def test_sqlite_is_private_and_contains_no_raw_codes_or_tokens(self):
        code = self.code()
        token = self.exchange(code)["access_token"]
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        content = self.path.read_bytes()
        self.assertNotIn(code.encode(), content)
        self.assertNotIn(token.encode(), content)
        alias = Path(self.directory.name) / "alias.sqlite"
        alias.symlink_to(self.path)
        with self.assertRaises(ValueError):
            SQLiteAuthorizationStore(alias)


if __name__ == "__main__":
    unittest.main()
