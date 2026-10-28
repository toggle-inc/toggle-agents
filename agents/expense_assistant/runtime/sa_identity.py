"""Bind a verified SA invocation to an explicitly linked agent person.

This helper does not authenticate an SA request. The deployment host must
verify the invocation against its trusted SA issuer before constructing
VerifiedSAInvocation, then resolve an explicit SA-employee-to-canonical-person
link. Missing or stale evidence always fails closed.
"""

import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from urllib.parse import urlsplit

from .requester import Requester

SCOPE_KEYS = frozenset(
    {
        "invocationId",
        "requesterEmployeeId",
        "runId",
        "harnessSessionId",
        "managedAgentVersionId",
        "tenantId",
        "managedAgentId",
        "sourceMessageId",
        "rootMessageId",
        "sourceChannelId",
    }
)


@dataclass(frozen=True)
class VerifiedSAInvocation:
    """Normalized invocation snapshot returned only by the trusted host verifier.

    `scope` must be read from a signed SA assertion or a fresh authenticated
    read from the configured SA origin. Never construct this from prompt/body
    fields. The verifier must include the current run, source, version,
    tenant, requester and authorization status in its decision.
    """

    scope: Mapping
    origin: str
    expires_at: float

    def __post_init__(self):
        object.__setattr__(self, "scope", MappingProxyType(dict(self.scope)))


def _canonical_origin(value):
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    return bool(
        parsed.scheme == "https"
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and parsed.port in (None, 443)
        and parsed.path in ("", "/")
        and not parsed.query
        and not parsed.fragment
        and value.rstrip("/") == f"https://{parsed.netloc}"
    )


def _valid_scope(scope):
    if not isinstance(scope, dict) or set(scope) != SCOPE_KEYS:
        return False
    if (
        not isinstance(scope["invocationId"], str)
        or not re.fullmatch(r"agentize-mention:[a-f0-9]{64}", scope["invocationId"])
    ):
        return False
    for key in ("tenantId", "managedAgentId", "managedAgentVersionId", "harnessSessionId"):
        if type(scope[key]) is not int or scope[key] <= 0:
            return False
    for key in SCOPE_KEYS - {
        "invocationId",
        "tenantId",
        "managedAgentId",
        "managedAgentVersionId",
        "harnessSessionId",
    }:
        value = scope[key]
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
            return False
    return True


def verify_sa_scope(
    scope,
    owner,
    *,
    verify_invocation,
    resolve_person,
    origin,
    clock=time.time,
):
    """Return whether a live SA scope belongs to this service's canonical owner.

    `verify_invocation(scope, origin)` must freshly validate the scope with
    trusted SA evidence and return a VerifiedSAInvocation. `resolve_person`
    must use an explicit tenant + SA employee mapping to the same canonical
    person ID used by the company's verified SSO adapter. Neither callback may
    derive identity from prompt text, request-body claims, email matching, or a
    tenant-wide credential alone.

    Intended for `SAApprovalAdapter(..., verify_scope=...)`. It never receives
    or forwards the SA service credential; the separate credential callback
    remains host-only and is not the personal MCP bearer.
    """
    try:
        if not _canonical_origin(origin) or not _valid_scope(scope):
            return False
        if not isinstance(owner, str) or not owner:
            return False
        snapshot = verify_invocation(dict(scope), origin.rstrip("/"))
        if not isinstance(snapshot, VerifiedSAInvocation):
            return False
        if (
            snapshot.origin.rstrip("/") != origin.rstrip("/")
            or dict(snapshot.scope) != scope
            or type(snapshot.expires_at) not in (int, float)
            or not math.isfinite(snapshot.expires_at)
            or snapshot.expires_at <= clock()
        ):
            return False
        person_id = resolve_person(scope["tenantId"], scope["requesterEmployeeId"])
        if not isinstance(person_id, str) or not person_id.strip() or len(person_id) > 512:
            return False
        expected_owner = Requester(
            tenant_id=str(scope["tenantId"]),
            person_id=person_id,
            expires_at=snapshot.expires_at,
        ).owner
        return expected_owner == owner
    except Exception:
        return False
