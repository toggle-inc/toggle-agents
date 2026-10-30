"""Synthetic setup declaration tests: no grants, providers or external HTTP."""

import copy
from dataclasses import replace
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from runtime import agent_setup
from runtime.agent_setup import AgentSetup, REQUIRED_CAPABILITIES, REQUIRED_PROVIDERS
from runtime.authorization import AgentAuthorization, AuthorizationError, CAPABILITY_LABELS, PublicClient
from runtime.requester import Requester
from runtime.service_connections import ConnectionProvider, ServiceConnections
from test_authorization import MemoryStore


class AgentSetupTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.25
        self.person = Requester("synthetic-tenant", "alice", 5000)
        self.client = PublicClient("sa", "Synthetic client", ("https://platform.example.test/callback",),
                                   REQUIRED_CAPABILITIES)
        self.store = MemoryStore()
        self.authority = SimpleNamespace(tenant_id="synthetic-tenant", clients={"sa": self.client},
                                         store=self.store, begin=Mock(), decide=Mock())
        self.states = {("alice", "mf"): "connected", ("alice", "calendar"): "not_connected",
                       ("bob", "mf"): "expired", ("bob", "calendar"): "unavailable"}
        self.begin = Mock(side_effect=AssertionError("setup must not start authorization"))
        self.connections = ServiceConnections(
            self.store, providers=(
                ConnectionProvider("mf", "Synthetic MF", frozenset({"https://mf.example.test"})),
                ConnectionProvider("calendar", "Synthetic calendar", frozenset({"https://calendar.example.test"})),
            ), status=lambda person, provider: self.states[(person.person_id, provider)],
            begin=self.begin, clock=lambda: self.now,
        )
        self.setup = AgentSetup(self.authority, self.connections, clock=lambda: self.now,
                                available_capabilities=REQUIRED_CAPABILITIES)

    def view(self, **kwargs):
        return self.setup.view(kwargs.get("person", self.person), kwargs.get("client_id", "sa"))

    def test_exact_public_wire_and_all_required_capabilities(self):
        view = self.view()
        self.assertEqual(set(view), {
            "schema_version", "agent_slug", "client_id", "declaration_digest", "capabilities",
            "required_providers", "requires_company_selection", "status", "expires_at",
            "missing_capabilities", "missing_runtime_capabilities",
        })
        self.assertEqual(view["schema_version"], "agent-setup/v1")
        self.assertEqual(view["agent_slug"], "expense_assistant")
        self.assertEqual(view["client_id"], "sa")
        self.assertEqual([row["id"] for row in view["capabilities"]], sorted(REQUIRED_CAPABILITIES))
        self.assertEqual(len(view["capabilities"]), 10)
        self.assertIn("memory:write", [row["id"] for row in view["capabilities"]])
        self.assertNotIn("memory:propose", [row["id"] for row in view["capabilities"]])
        self.assertEqual([row["id"] for row in view["required_providers"]], ["mf", "calendar"])
        for row in view["required_providers"]:
            self.assertEqual(set(row), {"id", "label", "status", "authorization_origins"})
        self.assertTrue(view["requires_company_selection"])
        self.assertEqual(view["status"], "ready")
        self.assertEqual(view["missing_capabilities"], [])
        self.assertEqual(view["missing_runtime_capabilities"], [])
        self.assertEqual(view, json.loads(json.dumps(view, allow_nan=False)))
        self.assertRegex(view["declaration_digest"], r"^[a-f0-9]{64}$")

    def test_required_labels_are_real_nonempty_authority_labels(self):
        self.assertTrue(REQUIRED_CAPABILITIES <= CAPABILITY_LABELS.keys())
        for row in self.view()["capabilities"]:
            self.assertEqual(row["label"], CAPABILITY_LABELS[row["id"]])
            self.assertTrue(row["label"].strip())

    def test_client_ceiling_does_not_shrink_or_silently_widen(self):
        self.authority.clients["sa"] = replace(self.client, capabilities=frozenset({"mf:read"}))
        before = copy.deepcopy(self.authority.clients)
        view = self.view()
        self.assertEqual(view["status"], "blocked")
        self.assertEqual(view["missing_capabilities"], sorted(REQUIRED_CAPABILITIES - {"mf:read"}))
        self.assertEqual(len(view["capabilities"]), 10)
        self.assertEqual(self.authority.clients, before)
        self.assertEqual(view["missing_runtime_capabilities"], [])
        self.begin.assert_not_called()
        self.authority.begin.assert_not_called()
        self.authority.decide.assert_not_called()

    def test_unknown_runtime_is_blocked_and_distinct_from_client_ceiling(self):
        setup = AgentSetup(self.authority, self.connections, clock=lambda: self.now)
        view = setup.view(self.person, "sa")
        self.assertEqual(view["status"], "blocked")
        self.assertEqual(view["missing_runtime_capabilities"], sorted(REQUIRED_CAPABILITIES))
        self.assertEqual(view["missing_capabilities"], [])

    def test_explicit_runtime_subset_and_empty_are_blocked_without_widening(self):
        for available in (frozenset(), frozenset({"mf:read", "memory:read"})):
            with self.subTest(available=available):
                setup = AgentSetup(self.authority, self.connections, clock=lambda: self.now,
                                   available_capabilities=available)
                view = setup.view(self.person, "sa")
                self.assertEqual(view["status"], "blocked")
                self.assertEqual(view["missing_runtime_capabilities"], sorted(REQUIRED_CAPABILITIES - available))
                self.assertEqual(set(row["id"] for row in view["capabilities"]), REQUIRED_CAPABILITIES)
                self.assertEqual(setup.available_capabilities, available)

    def test_runtime_caps_must_be_explicit_frozenset(self):
        for available in (set(REQUIRED_CAPABILITIES), list(REQUIRED_CAPABILITIES), "mf:read",
                          frozenset({False}), frozenset({""})):
            with self.subTest(available=available), self.assertRaises(ValueError):
                AgentSetup(self.authority, self.connections, clock=lambda: self.now,
                           available_capabilities=available)

    def test_unknown_client_is_rejected_before_provider_io(self):
        with patch.object(self.connections, "view") as read:
            for client_id in ("missing", "", None, [], True):
                with self.subTest(client_id=client_id), self.assertRaises(AuthorizationError):
                    self.view(client_id=client_id)
            read.assert_not_called()

    def test_person_identity_tenant_and_finite_session_required(self):
        bad_people = [None, SimpleNamespace(**self.person.__dict__), replace(self.person, kind="agent"),
                      replace(self.person, tenant_id="other"), replace(self.person, person_id=""),
                      replace(self.person, person_id=True)]
        bad_people += [replace(self.person, expires_at=value) for value in
                       (float("nan"), float("inf"), True, "5000", self.now, self.now - 1)]
        with patch.object(self.connections, "view") as read:
            for person in bad_people:
                with self.subTest(person=person), self.assertRaises(AuthorizationError):
                    self.view(person=person)
            read.assert_not_called()

    def test_expiry_is_integral_bounded_and_near_expiry_is_refused(self):
        self.assertEqual(self.view()["expires_at"], 1300)
        view = self.view(person=replace(self.person, expires_at=1100.75))
        self.assertIs(type(view["expires_at"]), int)
        self.assertEqual(view["expires_at"], 1100)
        with self.assertRaises(AuthorizationError):
            self.view(person=replace(self.person, expires_at=1000.75))

    def test_expiry_during_provider_io_is_rechecked(self):
        read = self.connections.view
        def delayed(person):
            result = read(person)
            self.now = 5001
            return result
        with patch.object(self.connections, "view", side_effect=delayed), self.assertRaises(AuthorizationError):
            self.view()

    def test_client_removal_and_ceiling_change_during_io_are_rechecked(self):
        read = self.connections.view
        def change(person):
            result = read(person)
            self.authority.clients["sa"] = replace(self.client, capabilities=frozenset({"mf:read"}))
            return result
        with patch.object(self.connections, "view", side_effect=change):
            self.assertEqual(self.view()["status"], "blocked")
        def remove(person):
            result = read(person)
            del self.authority.clients["sa"]
            return result
        with patch.object(self.connections, "view", side_effect=remove), self.assertRaises(AuthorizationError):
            self.view()

    def test_provider_states_block_outage_but_connected_needs_no_new_start(self):
        for status in ("connected", "not_connected", "expired", "not_configured", "unavailable"):
            self.states[("alice", "mf")] = status
            view = self.view()
            self.assertEqual(view["required_providers"][0]["status"], status)
            self.assertEqual(view["status"], "blocked" if status in {"not_configured", "unavailable"} else "ready")
        self.begin.assert_not_called()

    def test_provider_exception_is_sanitized_to_blocked(self):
        with patch.object(self.connections, "status", side_effect=RuntimeError("private provider secret")):
            view = self.view()
        self.assertEqual(view["status"], "blocked")
        self.assertEqual({row["status"] for row in view["required_providers"]}, {"unavailable"})
        self.assertNotIn("private provider secret", json.dumps(view))

    def test_required_providers_only_missing_provider_is_blocked(self):
        raw = self.connections.view(self.person)
        raw["connections"].append({"id": "extra", "secret": "never return"})
        with patch.object(self.connections, "view", return_value=raw):
            view = self.view()
        self.assertEqual([row["id"] for row in view["required_providers"]], list(REQUIRED_PROVIDERS))
        self.assertNotIn("never return", json.dumps(view))
        raw["connections"] = raw["connections"][:1]
        with patch.object(self.connections, "view", return_value=raw):
            view = self.view()
        self.assertEqual(view["status"], "blocked")
        self.assertEqual([row["id"] for row in view["required_providers"]], ["mf"])

    def test_personal_status_is_fresh_per_person_and_not_part_of_digest(self):
        alice = self.view()
        bob = self.view(person=replace(self.person, person_id="bob"))
        self.assertEqual([row["status"] for row in bob["required_providers"]], ["expired", "unavailable"])
        self.assertEqual(bob["status"], "blocked")
        self.assertEqual(alice["declaration_digest"], bob["declaration_digest"])
        self.now += 25
        self.assertEqual(alice["declaration_digest"], self.view()["declaration_digest"])
        self.assertEqual([row["status"] for row in self.view()["required_providers"]], ["connected", "not_connected"])

    def test_digest_binds_labels_consent_required_order_and_destinations(self):
        original = self.view()["declaration_digest"]
        with patch.dict(CAPABILITY_LABELS, {"mf:read": "Changed declaration label"}):
            self.assertNotEqual(original, self.view()["declaration_digest"])
        with patch.object(agent_setup, "CONSENT_TEXT", "Changed consent text"):
            self.assertNotEqual(original, self.view()["declaration_digest"])
        with patch.object(agent_setup, "REQUIRED_PROVIDERS", ("calendar", "mf")):
            self.assertNotEqual(original, self.view()["declaration_digest"])
        raw = self.connections.view(self.person)
        for key, value in (("label", "Changed provider label"),
                           ("authorization_origins", ["https://changed.example.test"])):
            changed = copy.deepcopy(raw)
            changed["connections"][0][key] = value
            with patch.object(self.connections, "view", return_value=changed):
                self.assertNotEqual(original, self.view()["declaration_digest"])

    def test_digest_is_canonical_and_not_client_specific(self):
        original = self.view()["declaration_digest"]
        self.authority.clients["other"] = replace(self.client, client_id="other", capabilities=frozenset({"mf:read"}))
        self.assertEqual(original, self.view(client_id="other")["declaration_digest"])
        raw = self.connections.view(self.person)
        raw["connections"].reverse()
        with patch.object(self.connections, "view", return_value=raw):
            self.assertEqual(original, self.view()["declaration_digest"])

    def test_unknown_or_empty_required_label_fails_closed(self):
        for label in (None, "", " "):
            with patch.dict(CAPABILITY_LABELS, {"memory:write": label}), self.assertRaises(AuthorizationError):
                self.view()
        labels = {key: value for key, value in CAPABILITY_LABELS.items() if key != "memory:write"}
        with patch.object(agent_setup, "CAPABILITY_LABELS", labels), self.assertRaises(AuthorizationError):
            self.view()

    def test_bad_provider_metadata_and_store_failure_fail_closed(self):
        raw = self.connections.view(self.person)
        for key, value in (("label", ""), ("status", "unknown"),
                           ("authorization_origins", ["http://wrong.example.test"])):
            changed = copy.deepcopy(raw)
            changed["connections"][0][key] = value
            with patch.object(self.connections, "view", return_value=changed), self.assertRaises(AuthorizationError):
                self.view()
        with patch.object(self.connections, "view", side_effect=RuntimeError("private details")):
            with self.assertRaises(AuthorizationError) as error:
                self.view()
            self.assertNotIn("private details", str(error.exception))

    def test_returned_metadata_is_detached_and_never_exposes_private_fields(self):
        raw = self.connections.view(self.person)
        raw["connections"][0]["token"] = "private provider token"
        raw["owner"] = self.person.owner
        with patch.object(self.connections, "view", return_value=raw):
            view = self.view()
        public = json.dumps(view)
        for private in ("csrf_token", "private provider token", self.person.owner):
            self.assertNotIn(private, public)
        view["required_providers"][0]["authorization_origins"].append("https://untrusted.example.test")
        self.assertEqual(raw["connections"][0]["authorization_origins"], ["https://mf.example.test"])

    def test_real_authority_accepts_the_same_explicit_ceiling_without_grants(self):
        authority = AgentAuthorization(self.store, lambda _: self.person,
                                       issuer="https://agent.example.test", tenant_id=self.person.tenant_id,
                                       clients=[self.client], clock=lambda: self.now)
        view = AgentSetup(authority, self.connections, clock=lambda: self.now,
                          available_capabilities=REQUIRED_CAPABILITIES).view(self.person, "sa")
        self.assertEqual(view["status"], "ready")
        self.assertTrue(all(key.startswith("service-connect:") for key in self.store.rows))


if __name__ == "__main__":
    unittest.main()
