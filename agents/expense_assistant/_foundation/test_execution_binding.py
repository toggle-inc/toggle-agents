"""Real ephemeral RSA signatures; synthetic actors and stores, no live keys."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import unittest

from .execution_binding import (
    EXECUTION_TYPE, SOURCE_TYPE, ExecutionBindingError, ExecutionRequest,
    ExecutionTarget, ExternalExecutionVerifier,
)
from .platform_identity import PlatformPerson, PlatformPersonLink
from .test_platform_identity import MemoryStore


class ExecutionBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        cls.source_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.runtime_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public = staticmethod(lambda key: key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode())

    def setUp(self):
        self.now, self.lookups = 1000, []
        self.store = MemoryStore()
        self.links = {
            ("https://source.example.test", "source-namespace", "source-employee"):
                PlatformPersonLink("canonical-tenant", "canonical-person"),
            ("https://login.example.test", "login-namespace", "login-subject"):
                PlatformPersonLink("canonical-tenant", "canonical-person"),
        }

        def resolve(*actor):
            self.lookups.append(actor)
            return self.links.get(actor)

        self.target = ExecutionTarget("runtime-tenant", "runtime-agent", "version-a", "conn-a")
        self.verifier = ExternalExecutionVerifier(
            self.store, resolve,
            source_issuer="https://source.example.test", source_keys={"source": self.public(self.source_key)},
            execution_issuer="https://runtime.example.test", execution_keys={"runtime": self.public(self.runtime_key)},
            audience="https://agent.example.test", targets=[self.target], clock=lambda: self.now,
        )
        self.request = ExecutionRequest("POST", "https://agent.example.test/mcp",
                                        hashlib.sha256(b'{"synthetic":"body"}').hexdigest())
        self.person = PlatformPerson("canonical-tenant", "canonical-person", 2000)

    def source(self, **changes):
        import jwt

        payload = {
            "iss": self.verifier.source_issuer, "aud": self.verifier.audience,
            "iat": 999, "exp": 1200, "jti": "source-once", "purpose": "source_context",
            "target_tenant_id": self.target.tenant_id, "target_agent_id": self.target.agent_id,
            "target_version_id": self.target.version_id, "invocation_id": "invocation-a",
            "source_namespace": "source-namespace", "source_actor": "source-employee",
            "source_actor_type": "human", "source_handle": "A" * 43, "anchor_revision": "a" * 64,
        }
        return jwt.encode({**payload, **changes}, self.source_key, algorithm="RS256",
                          headers={"kid": "source", "typ": SOURCE_TYPE})

    def call(self, source, **changes):
        import jwt

        payload = {
            "iss": self.verifier.execution_issuer, "aud": self.verifier.audience,
            "iat": 999, "exp": 1050, "jti": "call-once", "purpose": "external_mcp_execution",
            "target_tenant_id": self.target.tenant_id, "target_agent_id": self.target.agent_id,
            "target_version_id": self.target.version_id, "invocation_id": "invocation-a",
            "connection_id": self.target.connection_id, "session_id": "session-a",
            "actor_issuer": "https://login.example.test", "actor_namespace": "login-namespace",
            "actor_subject": "login-subject", "actor_type": "human",
            "source_grant_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "source_handle_sha256": hashlib.sha256(("A" * 43).encode()).hexdigest(),
            "method": self.request.method, "target": self.request.target,
            "body_sha256": self.request.body_sha256,
        }
        return jwt.encode({**payload, **changes}, self.runtime_key, algorithm="RS256",
                          headers={"kid": "runtime", "typ": EXECUTION_TYPE})

    def verify(self, source=None, call=None, **kwargs):
        source = source or self.source()
        return self.verifier.verify(source, call or self.call(source),
                                    request=kwargs.get("request", self.request),
                                    person=kwargs.get("person", self.person))

    def test_two_namespaces_resolve_to_resource_person_without_canonical_id_in_proofs(self):
        source = self.source()
        call = self.call(source)
        self.assertNotIn("canonical-person", source + call)
        verified = self.verify(source, call)
        self.assertEqual(verified.target, self.target)
        self.assertEqual(verified.session_id, "session-a")
        self.assertEqual(verified.expires_at, 1050)
        self.assertEqual(len(self.lookups), 2)
        self.assertNotIn("A" * 43, repr(verified))
        self.assertNotIn("canonical-person", repr(self.store.values))

    def test_request_body_target_method_and_grant_substitution_refused_before_links(self):
        source = self.source()
        for changes in (
            {"method": "GET"}, {"target": self.request.target + "?extra=1"},
            {"body_sha256": "b" * 64}, {"source_grant_sha256": "c" * 64},
            {"source_handle_sha256": "d" * 64},
        ):
            with self.subTest(changes=changes), self.assertRaises(ExecutionBindingError):
                self.verify(source, self.call(source, **changes))
        self.assertEqual(self.lookups, [])
        self.assertEqual(self.store.values, {})

    def test_deployment_version_connection_and_invocation_are_exact(self):
        source = self.source()
        for changes in (
            {"target_tenant_id": "another"}, {"target_agent_id": "another"},
            {"target_version_id": "another"}, {"connection_id": "another"},
            {"invocation_id": "another"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ExecutionBindingError):
                self.verify(source, self.call(source, **changes))
        self.assertEqual(self.lookups, [])

    def test_resource_person_and_both_current_account_links_must_match(self):
        for person in (
            replace(self.person, person_id="another"),
            replace(self.person, tenant_id="another"),
            replace(self.person, expires_at=1000),
        ):
            with self.assertRaises(ExecutionBindingError):
                self.verify(person=person)
        for actor in list(self.links):
            prior = self.links[actor]
            for replacement in (None, replace(prior, active=False), replace(prior, person_id="other")):
                self.links[actor] = replacement
                with self.assertRaises(ExecutionBindingError):
                    self.verify()
            self.links[actor] = prior
        self.assertEqual(self.store.values, {})

    def test_service_actors_and_self_reported_canonical_identity_are_refused(self):
        source = self.source()
        for changes in ({"actor_type": "service"}, {"person_id": "canonical-person"},
                        {"actor_subject": "canonical-person"}):
            with self.assertRaises(ExecutionBindingError):
                self.verify(source, self.call(source, **changes))
        with self.assertRaises(ExecutionBindingError):
            self.verify(self.source(source_actor_type="service"))
        self.assertEqual(self.store.values, {})

    def test_strict_types_issuers_audience_times_claims_and_purpose(self):
        source = self.source()
        for changes in (
            {"iss": "https://other.example.test"}, {"aud": "https://other.example.test"},
            {"aud": [self.verifier.audience]}, {"purpose": "history_call"},
            {"iat": 1001}, {"iat": True}, {"exp": 1000}, {"exp": 1061},
            {"exp": float("inf")}, {"jti": "\nforged"}, {"session_id": ""},
            {"target_agent_id": 123}, {"additional": "forbidden"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ExecutionBindingError):
                self.verify(source, self.call(source, **changes))
        for changes in ({"exp": 1300}, {"source_handle": "short"}, {"anchor_revision": "invalid"}):
            with self.assertRaises(ExecutionBindingError):
                self.verify(self.source(**changes))
        self.assertEqual(self.lookups, [])

    def test_wrong_signature_algorithm_and_remote_key_discovery_are_refused(self):
        import jwt

        source = self.source()
        payload = jwt.decode(self.call(source), options={"verify_signature": False})
        for token in (
            jwt.encode(payload, self.source_key, algorithm="RS256",
                       headers={"kid": "runtime", "typ": EXECUTION_TYPE}),
            jwt.encode(payload, "synthetic-only" * 8, algorithm="HS256",
                       headers={"kid": "runtime", "typ": EXECUTION_TYPE}),
            jwt.encode(payload, self.runtime_key, algorithm="RS256",
                       headers={"kid": "runtime", "typ": EXECUTION_TYPE, "jku": "https://evil.test"}),
        ):
            with self.assertRaisesRegex(ExecutionBindingError, "^invalid_execution_binding$"):
                self.verify(source, token)
        self.assertEqual(self.lookups, [])

    def test_replay_has_one_winner_even_in_concurrent_calls(self):
        source = self.source()
        call = self.call(source)

        def attempt(_):
            try:
                self.verify(source, call)
                return True
            except ExecutionBindingError:
                return False

        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(attempt, range(4))), 1)
        refreshed = self.verify(source, self.call(source, jti="new-call"))
        self.assertEqual(refreshed.session_id, "session-a")

    def test_expiry_during_link_lookup_and_store_failure_leak_no_proofs(self):
        def expire(*actor):
            self.now = 1050
            return self.links[actor]

        self.verifier.resolve_person = expire
        with self.assertRaisesRegex(ExecutionBindingError, "^invalid_execution_binding$"):
            self.verify()
        self.assertEqual(self.store.values, {})
        self.now = 1000
        self.verifier.resolve_person = lambda *actor: self.links[actor]
        self.store.transaction = lambda: (_ for _ in ()).throw(RuntimeError("private proof response"))
        with self.assertRaisesRegex(ExecutionBindingError, "^invalid_execution_binding$"):
            self.verify()

    def test_source_reference_does_not_claim_source_acl_or_session_registry_is_verified(self):
        # A legitimate runtime can sign another session. Only the source handle
        # registry can check its one-session CAS binding; this verifier is NOT it.
        source = self.source()
        result = self.verify(source, self.call(source, session_id="session-b"))
        self.assertEqual(result.session_id, "session-b")
        self.assertFalse(hasattr(result, "messages"))

