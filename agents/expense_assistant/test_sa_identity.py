"""Synthetic tests for binding authenticated SA scope to requester ownership."""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from runtime.requester import Requester  # noqa: E402
from runtime.sa_identity import VerifiedSAInvocation, verify_sa_scope  # noqa: E402


class SAScopeIdentityTests(unittest.TestCase):
    def setUp(self):
        self.origin = "https://sa.example.test"
        self.scope = {
            "invocationId": "agentize-mention:" + "a" * 64,
            "requesterEmployeeId": "employee-7",
            "runId": "run-9",
            "harnessSessionId": 42,
            "managedAgentVersionId": 17,
            "tenantId": 10,
            "managedAgentId": 12,
            "sourceMessageId": "message-3",
            "rootMessageId": "message-1",
            "sourceChannelId": "channel-5",
        }
        self.now = 1_000
        self.person_id = "canonical-person-7"
        self.owner = Requester("10", self.person_id, 5_000).owner

    def verifier(self, *, scope=None, origin=None, expires_at=5_000):
        observed = []

        def verify(actual_scope, actual_origin):
            observed.append((actual_scope, actual_origin))
            return VerifiedSAInvocation(
                self.scope if scope is None else scope,
                self.origin if origin is None else origin,
                expires_at,
            )

        return verify, observed

    def test_verified_scope_and_explicit_identity_link_match_requester_owner(self):
        verify, observed = self.verifier()
        result = verify_sa_scope(
            self.scope,
            self.owner,
            verify_invocation=verify,
            resolve_person=lambda tenant, employee: (
                self.person_id if (tenant, employee) == (10, "employee-7") else None
            ),
            origin=self.origin,
            clock=lambda: self.now,
        )
        self.assertIs(result, True)
        self.assertEqual(observed, [(self.scope, self.origin)])

    def test_different_person_or_missing_explicit_link_fails_closed(self):
        verify, _ = self.verifier()
        different_person = verify_sa_scope(
            self.scope,
            self.owner,
            verify_invocation=verify,
            resolve_person=lambda *_: "canonical-person-8",
            origin=self.origin,
            clock=lambda: self.now,
        )
        missing_link = verify_sa_scope(
            self.scope,
            self.owner,
            verify_invocation=verify,
            resolve_person=lambda *_: None,
            origin=self.origin,
            clock=lambda: self.now,
        )
        self.assertIs(different_person, False)
        self.assertIs(missing_link, False)

    def test_unverified_self_report_does_not_match_verified_scope(self):
        forged = {**self.scope, "requesterEmployeeId": "employee-8"}
        verify, _ = self.verifier()
        result = verify_sa_scope(
            forged,
            self.owner,
            verify_invocation=verify,
            resolve_person=lambda *_: self.person_id,
            origin=self.origin,
            clock=lambda: self.now,
        )
        self.assertIs(result, False)

    def test_expired_wrong_origin_and_boolean_verifiers_are_refused(self):
        for verifier, origin in (
            (self.verifier(expires_at=self.now)[0], self.origin),
            (self.verifier(origin="https://attacker.example.test")[0], self.origin),
            (lambda *_: True, self.origin),
        ):
            with self.subTest(origin=origin):
                self.assertIs(
                    verify_sa_scope(
                        self.scope,
                        self.owner,
                        verify_invocation=verifier,
                        resolve_person=lambda *_: self.person_id,
                        origin=origin,
                        clock=lambda: self.now,
                    ),
                    False,
                )

    def test_scope_shape_and_origin_are_fixed_and_invalid_scope_never_calls_host(self):
        verify, observed = self.verifier()
        invalid = {**self.scope, "requesterEmployeeId": "employee-7", "extra": "claim"}
        for scope, origin in (
            (invalid, self.origin),
            (self.scope, "http://sa.example.test"),
            (self.scope, "https://user@sa.example.test"),
        ):
            with self.subTest(origin=origin):
                self.assertIs(
                    verify_sa_scope(
                        scope,
                        self.owner,
                        verify_invocation=verify,
                        resolve_person=lambda *_: self.person_id,
                        origin=origin,
                        clock=lambda: self.now,
                    ),
                    False,
                )
        self.assertEqual(observed, [])

    def test_verifier_is_called_fresh_for_every_check_and_exceptions_fail_closed(self):
        verify, observed = self.verifier()
        args = {
            "verify_invocation": verify,
            "resolve_person": lambda *_: self.person_id,
            "origin": self.origin,
            "clock": lambda: self.now,
        }
        self.assertIs(verify_sa_scope(self.scope, self.owner, **args), True)
        self.assertIs(verify_sa_scope(self.scope, self.owner, **args), True)
        self.assertEqual(len(observed), 2)
        self.assertIs(
            verify_sa_scope(
                self.scope,
                self.owner,
                verify_invocation=lambda *_: (_ for _ in ()).throw(RuntimeError()),
                resolve_person=lambda *_: self.person_id,
                origin=self.origin,
                clock=lambda: self.now,
            ),
            False,
        )


if __name__ == "__main__":
    unittest.main()
