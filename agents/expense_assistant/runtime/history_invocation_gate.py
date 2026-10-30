"""Opt-in composition seam; no route is wired and legacy behavior stays default.

Trusted host code creates one gate for an explicitly opted-in agent connection.
No environment, request header, model argument or proof can enable this gate.
The disabled path does not import proof/crypto dependencies, resolve identity,
load keys/proofs, perform HTTP, register tools or change existing authentication.
"""


class HistoryInvocationGate:
    def __init__(self, *, enabled=False, validator_factory=None,
                 resolve_expected=None, load_proofs=None):
        if type(enabled) is not bool:
            raise ValueError("Explicit boolean history opt-in required")
        if enabled and not all(callable(v) for v in (
                validator_factory, resolve_expected, load_proofs)):
            raise ValueError("Opted-in history requires explicit trusted adapters")
        self._enabled = enabled
        self._validator_factory = validator_factory
        self._resolve_expected, self._load_proofs = resolve_expected, load_proofs

    def reference(self, request_context):
        """Resolve only a validated opaque reference; never fetch history here.

        resolve_expected must authenticate the CURRENT request and explicit
        account link. load_proofs must read the trusted per-call transport,
        never instruction JSON or a person's shared latest-invocation record.
        All callbacks are trusted host injection and are not model tools.
        Source ACL/consent checks remain necessary after this validation seam.
        """
        if not self._enabled:
            return None
        from .history_invocation import (
            ExpectedHistoryCall, HistoryInvocationValidator, HistoryProofError,
        )

        try:
            expected = self._resolve_expected(request_context)
            # Authenticate before loading proofs or creating trust/key clients.
            if not isinstance(expected, ExpectedHistoryCall):
                raise HistoryProofError()
            validator = self._validator_factory()
            if not isinstance(validator, HistoryInvocationValidator):
                raise HistoryProofError()
            source_grant, call_proof = self._load_proofs(request_context)
            return validator.validate(source_grant, call_proof, expected=expected)
        except Exception:
            raise HistoryProofError() from None
