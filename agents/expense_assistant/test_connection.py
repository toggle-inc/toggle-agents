"""Synthetic tests for linking private credentials without copying or leaking them."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from runtime.connection import (  # noqa: E402
    LinkedMFClient,
    connect,
    initialize_profile,
    read_settings,
)
from runtime.providers import MFClient  # noqa: E402
from runtime.state import ExpenseError  # noqa: E402


class ConnectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.legacy = self.root / "legacy"
        (self.legacy / "tokens").mkdir(parents=True)
        (self.legacy / "keihi_mcp").mkdir()
        (self.legacy / "keihi_mcp" / "rules.py").write_text("def check(**kwargs):\n    return []\n")
        self.env = self.legacy / ".env"
        self.env.write_text(
            "MF_CLIENT_ID=synthetic-client\nMF_CLIENT_SECRET='synthetic-secret'\n"
            "KEIHI_OWNER_PUBKEY=synthetic-owner\n"
        )
        self.token = self.legacy / "tokens" / "mf.json"
        self.token.write_text(
            json.dumps(
                {
                    "access_token": "synthetic-access",
                    "refresh_token": "synthetic-refresh",
                    "expires_in": 3600,
                    "obtained_at": 1000,
                }
            )
        )
        os.chmod(self.token, 0o600)
        self.private = self.root / "private"

    def tearDown(self):
        self.temporary.cleanup()

    def test_settings_are_not_executed_or_interpolated(self):
        marker = self.root / "must-not-exist"
        self.env.write_text(f"VALUE=$(touch {marker})\nOTHER='${{UNSET}}'\n")
        data = read_settings(self.env)
        self.assertIn("$(touch", data["VALUE"])
        self.assertEqual(data["OTHER"], "${UNSET}")
        self.assertFalse(marker.exists())

    def test_profile_contains_only_references_and_does_not_overwrite_legacy(self):
        before = self.token.read_bytes()
        profile = initialize_profile(self.env, self.private)
        self.assertEqual(self.token.read_bytes(), before)
        self.assertNotIn("synthetic-access", profile.read_text())
        self.assertNotIn("synthetic-secret", profile.read_text())
        metadata = (self.private / "oauth-link.json").read_text()
        self.assertNotIn("access_token", metadata)
        self.assertEqual(os.stat(profile).st_mode & 0o777, 0o600)
        self.assertEqual(initialize_profile(self.env, self.private), profile)

    def test_service_reads_shared_token_and_refresh_save_keeps_link_binding(self):
        profile = initialize_profile(self.env, self.private)
        service = connect(profile)
        try:
            self.assertIsInstance(service.mf, LinkedMFClient)
            self.assertFalse(service.write_enabled)
            self.assertEqual(service.mf._load()["oauth"]["access_token"], "synthetic-access")
            service.mf._save(
                {"oauth": {"access_token": "synthetic-new", "refresh_token": "synthetic-refresh"}}
            )
            self.assertEqual(json.loads(self.token.read_text())["access_token"], "synthetic-new")
            self.assertEqual(service.mf._load()["oauth"]["access_token"], "synthetic-new")
            self.assertNotIn("synthetic-new", (self.private / "oauth-link.json").read_text())
            self.assertEqual(os.stat(self.token).st_mode & 0o777, 0o600)
        finally:
            service.state.close()
            service.mf.http.close()

    def test_expiry_refresh_updates_the_shared_original_vault_without_breaking_the_link(self):
        import httpx

        profile = initialize_profile(self.env, self.private)
        service = connect(profile)
        service.mf.http.close()
        service.mf.http = httpx.Client(
            base_url="https://expense.moneyforward.com",
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    json={
                        "access_token": "synthetic-refreshed",
                        "refresh_token": "synthetic-rotated",
                        "expires_in": 3600,
                    },
                )
            ),
        )
        service.mf.clock = lambda: 5000
        try:
            self.assertEqual(service.mf._token(), "synthetic-refreshed")
            self.assertEqual(
                json.loads(self.token.read_text())["refresh_token"], "synthetic-rotated"
            )
            self.assertEqual(service.mf._load()["oauth"]["access_token"], "synthetic-refreshed")
            self.assertNotIn("synthetic-refreshed", (self.private / "oauth-link.json").read_text())
        finally:
            service.state.close()
            service.mf.http.close()

    def test_changed_owner_or_token_binding_is_refused(self):
        profile = initialize_profile(self.env, self.private)
        data = read_settings(self.env)
        self.env.write_text(self.env.read_text().replace("synthetic-owner", "other-owner"))
        with self.assertRaises(ExpenseError):
            connect(profile)
        self.env.write_text(self.env.read_text().replace("other-owner", data["KEIHI_OWNER_PUBKEY"]))
        service = connect(profile)
        try:
            service.mf._binding = "wrong-binding"
            with self.assertRaises(ExpenseError):
                service.mf._load()
        finally:
            service.state.close()
            service.mf.http.close()

    def test_loose_permissions_are_refused(self):
        os.chmod(self.token, 0o644)
        with self.assertRaises(ExpenseError):
            initialize_profile(self.env, self.private)

    def test_private_reference_cache_can_be_bound_without_copying_it_to_public_source(self):
        profile = initialize_profile(self.env, self.private)
        references = self.private / "private-refs"
        references.mkdir()
        (references / "index.md").write_text("synthetic private reference")
        record = json.loads(profile.read_text())
        record["private_references"] = str(references)
        profile.write_text(json.dumps(record))
        service = connect(profile)
        try:
            self.assertEqual(service.read_reference()["text"], "synthetic private reference")
            self.assertFalse(service.write_enabled)
        finally:
            service.state.close()
            service.mf.http.close()
        (references / "index.md").unlink()
        with self.assertRaises(ExpenseError):
            connect(profile)

    def test_unbound_metadata_cannot_read_legacy_tokens(self):
        client = LinkedMFClient(
            "synthetic-client",
            "synthetic-secret",
            self.root / "metadata.json",
            "synthetic-owner",
            legacy_token_file=self.token,
            legacy_owner="synthetic-owner",
        )
        try:
            MFClient._save(client, {"owner": "synthetic-owner"})
            with self.assertRaises(ExpenseError):
                client._load()
        finally:
            client.http.close()


if __name__ == "__main__":
    unittest.main()
