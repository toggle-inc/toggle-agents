"""Synthetic proof validation only; no keys, scopes or services are deployed."""

import dataclasses
import hashlib
import sys
import unittest
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime.history_invocation import (
    ExpectedHistoryCall, HistoryInvocationValidator, HistoryProofError,
)


class HistoryInvocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.call_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @staticmethod
    def public(key):
        return key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def setUp(self):
        self.now = 100
        self.expected = ExpectedHistoryCall(
            "agent-tenant", "canonical-alice", "source-tenant", "source-alice",
            "expense_assistant", "invocation-a", "session-a", 200,
        )
        self.validator = HistoryInvocationValidator(
            source_issuer="https://source.example.test", source_keys={"source": self.public(self.source_key)},
            call_issuer="https://transport.example.test", call_keys={"call": self.public(self.call_key)},
            audience="https://agent.example.test/mcp", clock=lambda: self.now,
        )
        self.source = {
            "iss": self.validator.source_issuer, "aud": self.validator.audience,
            "iat": 99, "exp": 199, "jti": "synthetic-source-proof", "purpose": "history_source",
            "source_tenant_id": self.expected.source_tenant_id,
            "source_actor_id": self.expected.source_actor_id, "agent_id": self.expected.agent_id,
            "invocation_id": self.expected.invocation_id, "anchor_id": "anchor-a",
            "source_handle": "synthetic_source_opaque_handle_12345",
        }
        self.call = {
            "iss": self.validator.call_issuer, "aud": self.validator.audience,
            "iat": 99, "exp": 159, "jti": "synthetic-call-proof", "purpose": "history_call",
            "tenant_id": self.expected.tenant_id, "person_id": self.expected.person_id,
            "agent_id": self.expected.agent_id, "invocation_id": self.expected.invocation_id,
            "session_id": self.expected.session_id,
        }

    def tokens(self, *, source_changes=None, call_changes=None):
        source = jwt.encode({**self.source, **(source_changes or {})}, self.source_key,
                            algorithm="RS256", headers={"kid": "source", "typ": self.validator.SOURCE_TYP})
        call = jwt.encode({**self.call, "source_grant_sha256": hashlib.sha256(source.encode()).hexdigest(),
                           **(call_changes or {})}, self.call_key, algorithm="RS256",
                          headers={"kid": "call", "typ": self.validator.CALL_TYP})
        return source, call

    def test_valid_reference_is_exact_and_contains_no_proofs_or_credentials(self):
        source, call = self.tokens()
        result = self.validator.validate(source, call, expected=self.expected)
        self.assertEqual(result.source_handle, self.source["source_handle"])
        self.assertEqual(result.session_id, "session-a")
        self.assertEqual(result.anchor_id, "anchor-a")
        self.assertEqual(result.expires_at, 159)
        self.assertNotIn(source, repr(result))
        self.assertNotIn(call, repr(result))
        self.assertNotIn(result.source_handle, repr(result))
        # Read retries keep the same binding; no source writes or latest-person state.
        self.assertEqual(self.validator.validate(source, call, expected=self.expected), result)

    def test_cross_person_tenant_agent_invocation_and_session_are_rejected(self):
        source, call = self.tokens()
        for field in ("tenant_id", "person_id", "source_tenant_id", "source_actor_id",
                      "agent_id", "invocation_id", "session_id"):
            with self.subTest(field=field), self.assertRaises(HistoryProofError):
                self.validator.validate(source, call, expected=dataclasses.replace(
                    self.expected, **{field: "other-synthetic-value"}))

    def test_concurrent_invocations_never_use_a_person_latest_binding(self):
        first = self.tokens()
        second_expected = dataclasses.replace(self.expected, invocation_id="invocation-b", session_id="session-b")
        second = self.tokens(source_changes={"invocation_id": "invocation-b", "anchor_id": "anchor-b",
                                            "source_handle": "other_synthetic_opaque_handle_12345"},
                             call_changes={"invocation_id": "invocation-b", "session_id": "session-b"})
        for tokens, expected in ((first, self.expected), (second, second_expected), (first, self.expected)):
            self.assertEqual(self.validator.validate(*tokens, expected=expected).session_id, expected.session_id)
        for tokens, expected in ((first, second_expected), (second, self.expected)):
            with self.assertRaises(HistoryProofError):
                self.validator.validate(*tokens, expected=expected)
        # A valid call proof cannot be combined with another valid source proof.
        with self.assertRaises(HistoryProofError):
            self.validator.validate(second[0], first[1], expected=self.expected)

    def test_signed_source_change_including_anchor_cannot_reuse_call_proof(self):
        first = self.tokens()
        for field, value in (("anchor_id", "edited-anchor"), ("source_handle", "other_synthetic_handle_1234567890")):
            source, _ = self.tokens(source_changes={field: value})
            with self.subTest(field=field), self.assertRaises(HistoryProofError):
                self.validator.validate(source, first[1], expected=self.expected)

    def test_no_model_context_or_service_identity_substitutes_for_authenticated_expected(self):
        source, call = self.tokens()
        for expected in (None, dataclasses.asdict(self.expected),
                         dataclasses.replace(self.expected, actor_kind="service"),
                         dataclasses.replace(self.expected, auth_expires_at=100),
                         dataclasses.replace(self.expected, auth_expires_at=float("nan"))):
            with self.assertRaises(HistoryProofError):
                self.validator.validate(source, call, expected=expected)

    def test_expiry_ttl_future_issuance_boolean_and_nonfinite_timestamps_rejected(self):
        for changes in ({"exp": 100}, {"iat": 101}, {"iat": 100, "exp": 100},
                        {"iat": True}, {"exp": True}, {"iat": float("nan")},
                        {"exp": float("inf")}, {"iat": 1, "exp": 1000}):
            for kind in ("source_changes", "call_changes"):
                with self.subTest(kind=kind, changes=changes), self.assertRaises(HistoryProofError):
                    self.validator.validate(*self.tokens(**{kind: changes}), expected=self.expected)
        tokens = self.tokens()
        self.now = 159
        with self.assertRaises(HistoryProofError):
            self.validator.validate(*tokens, expected=self.expected)

    def test_issuer_audience_purpose_unknown_claim_and_handle_shape_rejected(self):
        for field, value in (("iss", "https://other.example.test"), ("aud", "https://other.example.test/mcp"),
                             ("aud", [self.validator.audience]), ("purpose", "platform_login"),
                             ("unexpected", "field"), ("jti", "")):
            for kind in ("source_changes", "call_changes"):
                with self.subTest(field=field, kind=kind), self.assertRaises(HistoryProofError):
                    self.validator.validate(*self.tokens(**{kind: {field: value}}), expected=self.expected)
        for handle in ("short", "https://source.example.test/a", "a" * 129, " ", 123):
            with self.assertRaises(HistoryProofError):
                self.validator.validate(*self.tokens(source_changes={"source_handle": handle}), expected=self.expected)

    def test_signature_algorithm_typ_kid_missing_and_malformed_proofs_fail_safely(self):
        good_source, good_call = self.tokens()
        bad = ["not-a-token", "a" * 16385]
        for headers in ({"kid": "missing", "typ": self.validator.SOURCE_TYP},
                        {"kid": "source", "typ": "JWT"},
                        {"kid": "source", "typ": self.validator.SOURCE_TYP, "jku": "https://evil.example.test"}):
            bad.append(jwt.encode(self.source, self.source_key, algorithm="RS256", headers=headers))
        bad.append(jwt.encode(self.source, self.call_key, algorithm="RS256",
                              headers={"kid": "source", "typ": self.validator.SOURCE_TYP}))
        bad.append(jwt.encode(self.source, "synthetic-hmac-secret-with-32-characters", algorithm="HS256",
                              headers={"kid": "source", "typ": self.validator.SOURCE_TYP}))
        for source in bad:
            with self.assertRaises(HistoryProofError) as caught:
                self.validator.validate(source, good_call, expected=self.expected)
            self.assertEqual(str(caught.exception), "invalid_history_invocation")
        with self.assertRaises(HistoryProofError):
            self.validator.validate(good_source, good_source, expected=self.expected)

    def test_explicit_trust_configuration_cannot_use_private_or_weak_keys_or_http(self):
        kwargs = dict(source_issuer=self.validator.source_issuer, call_issuer=self.validator.call_issuer,
                      audience=self.validator.audience, source_keys={"source": self.public(self.source_key)},
                      call_keys={"call": self.public(self.call_key)})
        for changes in ({"source_issuer": "http://source.example.test"}, {"call_keys": {}},
                        {"source_keys": {"source": "not-a-public-key"}},
                        {"call_keys": {"weak": self.public(rsa.generate_private_key(public_exponent=65537, key_size=1024))}}):
            with self.assertRaises(ValueError):
                HistoryInvocationValidator(**{**kwargs, **changes})


if __name__ == "__main__":
    unittest.main()
