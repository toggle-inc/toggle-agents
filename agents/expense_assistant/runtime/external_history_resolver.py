"""Explicitly injected external-history adapter; no default host wiring.

Only the agent-owned verifier authenticates incoming proof headers. The source
adapter MUST verify the handle is already bound to exactly one session and recheck current
source ACL, anchor revision, expiry and revocation through its authenticated API.
A signature alone is not source permission. No network or credentials are supplied
here. The older history_invocation validator/gate draft is NOT this wire protocol.
"""

import json
import math
from dataclasses import dataclass

from _foundation.conversation import ConversationReader, Invocation
from _foundation.execution_binding import (
    ExecutionBindingError, ExecutionRequest, ExternalExecutionVerifier, VerifiedSourceCall,
)
from _foundation.platform_identity import PlatformPerson, _identifier
from .history_request import HistoryRequestBinding
from .requester import Requester


@dataclass(frozen=True)
class ResolvedHistorySource:
    """Trusted source API result, not deserialized model or HTTP input.

    reference must be the SAME VerifiedSourceCall supplied to resolve_source.
    The adapter must verify the pre-bound single session, never bind on history
    read, reauthorize the source, and bind sequence/digest against its anchor. Source
    revision can be provider-specific; it must match the signed anchor revision.
    """

    reference: VerifiedSourceCall
    invocation: Invocation
    source_anchor_revision: str


def history_execution_id(session_id, invocation_id):
    """Injective pair encoding; unlike delimiter joins, IDs cannot collide.

    Keeps the verified session and intake invocation distinct, even when multiple
    invocations share a session. This value is never selected by the model.
    """
    if not _identifier(session_id) or not _identifier(invocation_id):
        raise ExecutionBindingError()
    return "external-history-v1:" + json.dumps(
        [session_id, invocation_id], ensure_ascii=True, separators=(",", ":")
    )


def _proof_header(scope, name):
    headers = scope.get("headers", ())
    values = [v for k, v in headers if isinstance(k, bytes) and k.lower() == name]
    if (len(values) != 1 or not isinstance(values[0], bytes)
            or not 1 <= len(values[0]) <= 16384
            or any(c <= 32 or c >= 127 for c in values[0])):
        raise ExecutionBindingError()
    return values[0].decode("ascii")


class ExternalHistoryResolver:
    """Trusted resolver(scope, authenticated Requester) for opt-in HTTP hosts.

    source_platform and Git agent_slug are fixed deployment composition inputs.
    This class does not enable a route, fetch history, modify scopes, or choose a
    source from request fields. resolve_source receives only a verified reference.
    """

    def __init__(self, verifier, resolve_source, *, agent_slug, source_platform):
        if (not isinstance(verifier, ExternalExecutionVerifier) or not callable(resolve_source)
                or not _identifier(agent_slug) or not _identifier(source_platform)):
            raise ValueError("Explicit external history verifier and source adapter required")
        self.verifier, self.resolve_source = verifier, resolve_source
        self.agent_slug, self.source_platform = agent_slug, source_platform

    def __call__(self, scope, person):
        try:
            if (not isinstance(scope, dict) or scope.get("type") != "http"
                    or not isinstance(scope.get("agent_execution_request"), ExecutionRequest)
                    or not isinstance(person, Requester) or person.kind != "human"):
                raise ExecutionBindingError()
            request = scope["agent_execution_request"]
            if request.method != scope.get("method"):
                raise ExecutionBindingError()
            source = _proof_header(scope, b"x-agent-source-context")
            proof = _proof_header(scope, b"x-agent-execution-proof")
            reference = self.verifier.verify(
                source, proof, request=request,
                person=PlatformPerson(person.tenant_id, person.person_id, person.expires_at),
            )
            if not isinstance(reference, VerifiedSourceCall):
                raise ExecutionBindingError()
            resolved = self.resolve_source(reference)
            if (not isinstance(resolved, ResolvedHistorySource)
                    or resolved.reference is not reference
                    or resolved.source_anchor_revision != reference.anchor_revision
                    or not isinstance(resolved.invocation, Invocation)):
                raise ExecutionBindingError()
            invocation = resolved.invocation
            # Keep platform source identity separate from OAuth canonical identity.
            # The verifier has already checked both independent explicit mappings.
            ConversationReader(lambda: None, None, clock=self.verifier.clock)._validate(invocation)
            if (invocation.tenant != reference.source_namespace
                    or invocation.requester != reference.source_actor
                    or invocation.agent != self.agent_slug
                    or invocation.platform != self.source_platform
                    or invocation.execution != history_execution_id(
                        reference.session_id, reference.invocation_id)
                    or invocation.anchor_digest is None
                    or type(invocation.expires_at) not in (int, float)
                    or not math.isfinite(invocation.expires_at)
                    or invocation.expires_at > reference.expires_at
                    or self.verifier.clock() >= min(invocation.expires_at, reference.expires_at)):
                raise ExecutionBindingError()
            return HistoryRequestBinding(person.tenant_id, person.person_id, invocation)
        except Exception:
            raise ExecutionBindingError() from None
