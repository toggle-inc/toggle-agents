"""Rotating refresh grants: real authority/storage, synthetic SSO only."""

import concurrent.futures
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_authorization as fixtures  # noqa: E402
from runtime.auth_store import SQLiteAuthorizationStore  # noqa: E402
from runtime.authorization import AuthorizationError  # noqa: E402


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AuthorizationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.authority = self.fixture.authority

    def issue(self, who="alice", **overrides):
        return self.fixture.exchange(self.fixture.code(who, **overrides))

    def refresh(self, pair, **overrides):
        return self.authority.refresh(
            **{
                "refresh_token": pair["refresh_token"],
                "client_id": "sa",
                **overrides,
            }
        )

    def test_expired_access_refreshes_without_login_or_consent(self):
        pair = self.issue()
        # Well beyond the original SSO session and access token. Consent persists.
        self.fixture.now += 365 * 86400
        with self.assertRaises(AuthorizationError):
            self.authority.authenticate(pair["access_token"])
        updated = self.refresh(pair)
        person = self.authority.authenticate(updated["access_token"])
        self.assertEqual(person.person_id, "alice")
        self.assertNotEqual(updated["refresh_token"], pair["refresh_token"])
        self.assertNotEqual(updated["access_token"], pair["access_token"])
        self.assertEqual(updated["expires_in"], 900)

    def test_multiple_rotations_keep_identity_and_cannot_use_refresh_as_access(self):
        pair = self.issue()
        for _ in range(4):
            with self.assertRaises(AuthorizationError):
                self.authority.authenticate(pair["refresh_token"])
            with self.assertRaises(AuthorizationError):
                self.refresh(pair, refresh_token=pair["access_token"])
            self.fixture.now += 901
            pair = self.refresh(pair)
            self.assertEqual(self.authority.authenticate(pair["access_token"]).person_id, "alice")

    def test_refresh_scope_cannot_expand_even_after_narrowing(self):
        pair = self.issue(capabilities=frozenset({"mf:read", "mf:write"}))
        narrowed = self.refresh(pair, capabilities=frozenset({"mf:read"}))
        with self.assertRaises(AuthorizationError) as caught:
            self.refresh(narrowed, capabilities=frozenset({"mf:write"}))
        self.assertEqual(caught.exception.code, "invalid_scope")
        result = self.refresh(narrowed)
        self.assertEqual(result["scope"], "mf:read")

    def test_reused_refresh_revokes_the_entire_family_and_commit_persists(self):
        original = self.issue()
        first = self.refresh(original)
        last = self.refresh(first)
        with self.assertRaises(AuthorizationError):
            self.refresh(original)
        # The invalid_grant exception must NOT roll back family revocation.
        other_store = SQLiteAuthorizationStore(self.fixture.path)
        self.addCleanup(other_store.close)
        reloaded = self.fixture.make_authority(other_store)
        for pair in (original, first, last):
            with self.assertRaises(AuthorizationError):
                reloaded.authenticate(pair["access_token"])
        with self.assertRaises(AuthorizationError):
            self.refresh(last)

    def test_wrong_client_or_resource_cannot_refresh_or_revoke_another_family(self):
        original = self.issue()
        active = self.refresh(original)
        for override in ({"client_id": "buzz"}, {"resource": "https://attacker.example.test/mcp"}):
            with self.subTest(override=override), self.assertRaises(AuthorizationError):
                self.refresh(original, **override)
        self.authority.authenticate(active["access_token"])
        self.refresh(active)

    def test_revoking_access_or_refresh_also_revokes_the_other(self):
        for field in ("access_token", "refresh_token"):
            pair = self.issue()
            self.authority.revoke_token(pair[field], "sa")
            with self.assertRaises(AuthorizationError):
                self.authority.authenticate(pair["access_token"])
            with self.assertRaises(AuthorizationError):
                self.refresh(pair)

    def test_revoking_a_previously_used_refresh_revokes_current_descendants(self):
        original = self.issue()
        current = self.refresh(original)
        self.authority.revoke_token(original["refresh_token"], "sa")
        with self.assertRaises(AuthorizationError):
            self.refresh(current)

    def test_person_consent_revocation_does_not_affect_another_person(self):
        alice, bob = self.issue(), self.issue("bob")
        self.authority.revoke_consent("alice", "sa")
        with self.assertRaises(AuthorizationError):
            self.refresh(alice)
        self.assertEqual(
            self.authority.authenticate(self.refresh(bob)["access_token"]).person_id, "bob"
        )

    def test_new_consent_does_not_restore_old_refresh_or_allow_removed_client(self):
        old = self.issue()
        current = self.issue()
        with self.assertRaises(AuthorizationError):
            self.refresh(old)
        self.authority.clients.pop("sa")
        with self.assertRaises(AuthorizationError):
            self.refresh(current)

    def test_refresh_plaintext_is_not_saved(self):
        original = self.issue()
        current = self.refresh(original)
        content = self.fixture.path.read_bytes()
        for pair in (original, current):
            for field in ("access_token", "refresh_token"):
                self.assertNotIn(pair[field].encode(), content)

    def test_concurrent_refresh_is_single_use_and_replay_revokes_winner(self):
        pair = self.issue()
        other_store = SQLiteAuthorizationStore(self.fixture.path)
        self.addCleanup(other_store.close)
        other = self.fixture.make_authority(other_store)

        def attempt(authority):
            try:
                return authority.refresh(refresh_token=pair["refresh_token"], client_id="sa")
            except AuthorizationError:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, (self.authority, other)))
        winners = [result for result in results if result is not None]
        self.assertEqual(len(winners), 1)
        with self.assertRaises(AuthorizationError):
            self.authority.authenticate(winners[0]["access_token"])
        with self.assertRaises(AuthorizationError):
            self.refresh(winners[0])

    def test_replaceable_storage_supports_the_same_refresh_lifecycle(self):
        self.authority = self.fixture.make_authority(fixtures.MemoryStore())
        self.fixture.authority = self.authority
        original = self.issue()
        current = self.refresh(original)
        self.authority.authenticate(current["access_token"])
        with self.assertRaises(AuthorizationError):
            self.refresh(original)
        with self.assertRaises(AuthorizationError):
            self.authority.authenticate(current["access_token"])


if __name__ == "__main__":
    unittest.main()
