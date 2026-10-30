"""Composition is engine-independent and never uses shared user tokens."""

import unittest

import httpx
from cryptography.fernet import Fernet

from runtime.provider_host import ProviderHost, ProviderHostSettings
from runtime.requester import Requester
from test_authorization import MemoryStore


class ProviderHostTests(unittest.TestCase):
    def test_composes_same_encrypted_vault_and_does_not_contact_providers_on_initial_view(self):
        calls = []
        def unexpected(request):
            calls.append(request)
            raise AssertionError("Unexpected external operation")
        with httpx.Client(transport=httpx.MockTransport(unexpected)) as http:
            settings = ProviderHostSettings(
                namespace="synthetic-expense-host/tenant-a", mf_client_id="synthetic-mf-app",
                mf_callback_uri="https://sa.example.test/mf/callback", google_client_id="synthetic-google-app",
                google_callback_uri="https://sa.example.test/calendar/callback",
                encryption_key=Fernet.generate_key(), mf_client_secret="synthetic-mf-secret",
                google_client_secret="synthetic-google-secret",
            )
            host = ProviderHost(MemoryStore(), settings, mf_http=http, calendar_http=http, clock=lambda: 100)
            self.assertIs(host.mf.vault_store, host.calendar.vault_store)
            view = host.connections.view(Requester("tenant-a", "alice", 1000))
            self.assertEqual([c["status"] for c in view["connections"]], ["not_connected", "not_connected"])
            self.assertIsInstance(view["expires_at"], int)
            self.assertEqual(view["agent_slug"], "expense_assistant")
            self.assertEqual(calls, [])
            for secret in (settings.encryption_key.decode(), "synthetic-mf-secret", "synthetic-google-secret"):
                self.assertNotIn(secret, repr(settings))
            host.close()

    def test_no_missing_profile_or_shared_environment_fallback(self):
        with self.assertRaises(ValueError):
            ProviderHost(MemoryStore(), None)
