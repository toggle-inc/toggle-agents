"""Real RSA signatures with synthetic principals/store, no platform access."""

import contextlib
import dataclasses
import hashlib
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from .platform_identity import (
    ASSERTION_TYPE,
    PlatformIdentityError,
    PlatformIdentityVerifier,
    PlatformPersonLink,
    RequestBinding,
)


class MemoryStore:
    def __init__(self):
        self.values, self.lock = {}, threading.RLock()

    @contextlib.contextmanager
    def transaction(self):
        with self.lock:
            yield self

    def get(self, key):
        return self.values.get(key)

    def put(self, key, value):
        self.values[key] = dict(value)


class PlatformIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public = (
            cls.key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

    def setUp(self):
        self.store, self.lookups = MemoryStore(), []

        def resolve(issuer, tenant, subject):
            self.lookups.append((issuer, tenant, subject))
            if (issuer, tenant, subject) == ("https://sa.example.test", "sa-tenant", "employee-a"):
                return PlatformPersonLink("canonical-tenant", "person-a")
            return None

        self.verifier = PlatformIdentityVerifier(
            self.store,
            resolve,
            issuer="https://sa.example.test",
            audience="https://agent.example.test",
            tenant_id="canonical-tenant",
            public_keys={"test-key": self.public},
            clock=lambda: 1000,
        )
        self.binding = RequestBinding(
            "POST",
            "https://agent.example.test/oauth/consent",
            hashlib.sha256(b"decision=approve").hexdigest(),
            "https://sa.example.test",
        )

    def token(self, **changes):
        import jwt

        claims = {
            "iss": self.verifier.issuer,
            "aud": self.verifier.audience,
            "sub": "employee-a",
            "tenant_id": "sa-tenant",
            "actor_type": "human",
            "purpose": "platform_login",
            "iat": 999,
            "exp": 1050,
            "auth_expires_at": 2000,
            "jti": "synthetic-once",
            **dataclasses.asdict(self.binding),
        }
        return jwt.encode(
            {**claims, **changes},
            self.key,
            algorithm="RS256",
            headers={"kid": "test-key", "typ": ASSERTION_TYPE},
        )

    def test_verifies_signature_and_returns_explicit_canonical_person_not_email(self):
        person = self.verifier.authenticate(self.token(), self.binding)
        self.assertEqual((person.tenant_id, person.person_id), ("canonical-tenant", "person-a"))
        self.assertEqual(self.lookups, [("https://sa.example.test", "sa-tenant", "employee-a")])
        self.assertEqual(person.expires_at, 2000)
        self.assertNotIn("employee-a", str(self.store.values))

    def test_replay_and_concurrent_double_use_have_one_winner(self):
        token = self.token()

        def verify(_):
            try:
                self.verifier.authenticate(token, self.binding)
                return True
            except PlatformIdentityError:
                return False

        with ThreadPoolExecutor(max_workers=4) as workers:
            self.assertEqual(sum(workers.map(verify, range(4))), 1)

    def test_tampering_and_wrong_key_are_rejected_without_store_or_link_access(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa

        original = self.token()
        payload = jwt.decode(original, options={"verify_signature": False})
        forged = jwt.encode(
            payload,
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            algorithm="RS256",
            headers={"kid": "test-key", "typ": ASSERTION_TYPE},
        )
        for token in (
            forged,
            "not-a-token",
            jwt.encode(
                payload,
                "synthetic" * 8,
                algorithm="HS256",
                headers={"kid": "test-key", "typ": ASSERTION_TYPE},
            ),
        ):
            with self.subTest(token=token[:12]), self.assertRaises(PlatformIdentityError):
                self.verifier.authenticate(token, self.binding)
        self.assertEqual(self.lookups, [])
        self.assertEqual(self.store.values, {})

    def test_wrong_binding_issuer_audience_time_and_service_identity_are_rejected(self):
        variants = [
            {"iss": "https://preview.example.test"},
            {"aud": "https://other.example.test"},
            {"aud": [self.verifier.audience]},
            {"sub": "other-user"},
            {"tenant_id": "other"},
            {"actor_type": "service"},
            {"purpose": "agent:run"},
            {"iat": 1010},
            {"exp": 1000},
            {"exp": 1100},
            {"auth_expires_at": 1000},
            {"auth_expires_at": float("inf")},
            {"iat": True},
            {"method": "GET"},
            {"target": self.binding.target + "?other=1"},
            {"body_sha256": "0" * 64},
            {"origin": "https://evil.example.test"},
            {"email": "same@example.test"},
        ]
        for changes in variants:
            with self.subTest(changes=changes), self.assertRaises(PlatformIdentityError):
                self.verifier.authenticate(self.token(**changes), self.binding)
        self.assertEqual(self.store.values, {})

    def test_invalid_request_origin_and_missing_or_revoked_link_fail_closed(self):
        for binding in (
            dataclasses.replace(self.binding, origin=""),
            dataclasses.replace(self.binding, target="http://agent.example.test/oauth/consent"),
        ):
            with self.assertRaises(PlatformIdentityError):
                self.verifier.authenticate(self.token(), binding)
        self.verifier.resolve_person = lambda *_: PlatformPersonLink(
            "canonical-tenant", "person-a", False
        )
        with self.assertRaises(PlatformIdentityError):
            self.verifier.authenticate(self.token(), self.binding)
        self.assertEqual(self.store.values, {})


if __name__ == "__main__":
    unittest.main()
