"""No live secrets or databases: ciphertext, rollback and requester separation."""

import json
import tempfile
import unittest
from pathlib import Path

from cryptography.fernet import Fernet
from runtime.auth_store import SQLiteAuthorizationStore
from runtime.provider_vault import EncryptedProviderVault
from runtime.requester import Requester


class ProviderVaultTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        root.chmod(0o700)
        self.store = SQLiteAuthorizationStore(root / "auth.sqlite")
        self.addCleanup(self.store.close)
        self.key = Fernet.generate_key()
        self.vault = EncryptedProviderVault(self.store, self.key, namespace="synthetic-host")
        self.alice = Requester("synthetic", "alice", 99999).owner
        self.bob = Requester("synthetic", "bob", 99999).owner

    def test_plaintext_never_reaches_store_and_only_same_person_provider_can_read(self):
        with self.vault.transaction(self.alice, "mf") as record:
            record["access_token"] = "synthetic-provider-secret"
        rows = self.store._db.execute("SELECT value FROM auth_records").fetchall()
        self.assertNotIn("synthetic-provider-secret", str(rows))
        self.assertEqual(set(json.loads(rows[0][0])), {"ciphertext"})
        with self.vault.transaction(self.alice, "mf") as record:
            self.assertEqual(record["access_token"], "synthetic-provider-secret")
        for owner, provider in ((self.bob, "mf"), (self.alice, "calendar")):
            with self.vault.transaction(owner, provider) as record:
                self.assertEqual(record, {})

    def test_error_rolls_back_without_replacing_credential(self):
        with self.vault.transaction(self.alice, "mf") as record:
            record["refresh_token"] = "synthetic-original"
        with self.assertRaises(RuntimeError):
            with self.vault.transaction(self.alice, "mf") as record:
                record["refresh_token"] = "synthetic-uncommitted"
                raise RuntimeError("synthetic failure")
        with self.vault.transaction(self.alice, "mf") as record:
            self.assertEqual(record["refresh_token"], "synthetic-original")

    def test_ciphertext_swap_or_wrong_key_fails_without_secret_disclosure(self):
        for owner in (self.alice, self.bob):
            with self.vault.transaction(owner, "mf") as record:
                record["token"] = owner
        rows = self.store._db.execute("SELECT key,value FROM auth_records ORDER BY key").fetchall()
        self.store._db.execute("UPDATE auth_records SET value=? WHERE key=?", (rows[0][1], rows[1][0]))
        bad_owner = self.alice
        for owner in (self.alice, self.bob):
            try:
                with self.vault.transaction(owner, "mf"):
                    pass
            except ValueError:
                bad_owner = owner
                break
        with self.assertRaisesRegex(ValueError, "unavailable"):
            with self.vault.transaction(bad_owner, "mf"):
                pass
        other = EncryptedProviderVault(self.store, Fernet.generate_key(), namespace="synthetic-host")
        with self.assertRaisesRegex(ValueError, "unavailable"):
            with other.transaction(self.alice, "mf"):
                pass
