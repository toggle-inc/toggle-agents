"""Agent-owned verification of source and runtime proofs, not history policy.

This optional protocol has no Engine imports or key discovery. It does not
issue tokens or turn a valid signature into source access. A source adapter
must STILL verify the opaque handle's one-session binding and current ACL.
"""

import hashlib
import math
import re
import time
from dataclasses import dataclass, field

from .platform_identity import PlatformPerson, PlatformPersonLink, _identifier, _origin

SOURCE_TYPE = "agent-source-context+jwt"
EXECUTION_TYPE = "agent-execution+jwt"
COMMON_FIELDS = {"iss", "aud", "iat", "exp", "jti", "purpose"}
TARGET_FIELDS = {"target_tenant_id", "target_agent_id", "target_version_id", "invocation_id"}
SOURCE_FIELDS = TARGET_FIELDS | {
    "source_namespace", "source_actor", "source_actor_type", "source_handle", "anchor_revision",
}
EXECUTION_FIELDS = TARGET_FIELDS | {
    "connection_id", "session_id", "actor_issuer", "actor_namespace", "actor_subject", "actor_type",
    "source_grant_sha256", "source_handle_sha256", "method", "target", "body_sha256",
}


class ExecutionBindingError(Exception):
    def __init__(self):
        super().__init__("invalid_execution_binding")


def _time(value):
    return type(value) in (int, float) and math.isfinite(value)


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


@dataclass(frozen=True)
class ExecutionTarget:
    tenant_id: str
    agent_id: str
    version_id: str
    connection_id: str


@dataclass(frozen=True)
class ExecutionRequest:
    """Exact incoming bytes/target, computed by trusted HTTP middleware."""

    method: str
    target: str
    body_sha256: str


@dataclass(frozen=True)
class VerifiedSourceCall:
    """Proof reference only, NOT permission or an authenticated source snapshot."""

    source_handle: str = field(repr=False)
    source_issuer: str
    source_namespace: str
    source_actor: str
    anchor_revision: str
    target: ExecutionTarget
    invocation_id: str
    session_id: str
    expires_at: float
    source_grant_sha256: str


class ExternalExecutionVerifier:
    """Explicit opt-in; resource OAuth remains mandatory on EVERY request.

    resolve_person(issuer, namespace, subject) must resolve current explicit
    links, not display names/emails. Both issuers' actors must resolve to the
    resource-authenticated canonical person. The runtime never needs that ID.
    store.transaction/get/put must be atomic across all runtime instances.
    The caller supplies fixed deployment targets and an exact MCP endpoint.
    """

    def __init__(self, store, resolve_person, *, source_issuer, source_keys,
                 execution_issuer, execution_keys, audience, targets,
                 endpoint="/mcp", clock=time.time):
        self.source_issuer = _origin(source_issuer)
        self.execution_issuer = _origin(execution_issuer)
        self.audience = _origin(audience)
        if (not isinstance(endpoint, str) or not re.fullmatch(r"/[A-Za-z0-9/_-]+", endpoint)
                or "//" in endpoint or not callable(resolve_person) or not callable(clock)):
            raise ValueError("Explicit execution trust required")
        self.endpoint = self.audience + endpoint
        self.targets = frozenset(targets)
        if not self.targets or any(
            not isinstance(t, ExecutionTarget)
            or not all(_identifier(v) for v in (t.tenant_id, t.agent_id, t.version_id, t.connection_id))
            for t in self.targets
        ):
            raise ValueError("Explicit deployment targets required")
        self._source_keys = self._keys(source_keys)
        self._execution_keys = self._keys(execution_keys)
        self.store, self.resolve_person, self.clock = store, resolve_person, clock

    @staticmethod
    def _keys(values):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

        try:
            if not isinstance(values, dict) or not 1 <= len(values) <= 16:
                raise ValueError
            keys = {}
            for kid, pem in values.items():
                if not _identifier(kid) or len(kid) > 128 or not isinstance(pem, str):
                    raise ValueError
                key = serialization.load_pem_public_key(pem.encode())
                if not isinstance(key, RSAPublicKey) or key.key_size < 2048:
                    raise ValueError
                keys[kid] = key
            return keys
        except Exception:
            raise ValueError("Pinned RSA public keys required") from None

    def _decode(self, token, *, keys, issuer, typ, purpose, ttl, fields, now):
        import jwt

        if not isinstance(token, str) or not 1 <= len(token) <= 16384:
            raise ExecutionBindingError()
        header = jwt.get_unverified_header(token)
        if (set(header) != {"alg", "kid", "typ"} or header["alg"] != "RS256"
                or header["typ"] != typ or header["kid"] not in keys):
            raise ExecutionBindingError()
        claims = jwt.decode(
            token, keys[header["kid"]], algorithms=["RS256"],
            issuer=issuer, audience=self.audience,
            options={"require": list(COMMON_FIELDS | fields), "verify_exp": False,
                     "verify_iat": False, "verify_nbf": False, "strict_aud": True},
        )
        if (set(claims) != COMMON_FIELDS | fields or claims["purpose"] != purpose
                or not _identifier(claims["jti"])
                or not all(_identifier(claims[f]) for f in fields)
                or not _time(claims["iat"]) or not _time(claims["exp"])
                or not claims["iat"] <= now < claims["exp"]
                or not 0 < claims["exp"] - claims["iat"] <= ttl):
            raise ExecutionBindingError()
        return claims

    def verify(self, source_grant, execution_proof, *, request, person):
        """Authenticate proofs before consulting links; consume call jti once.

        A caller retry must use a fresh execution proof, retaining exactly the
        same source/session. This does not authorize a business write retry.
        """
        try:
            now = self.clock()
            if (not _time(now) or not isinstance(person, PlatformPerson)
                    or not _identifier(person.tenant_id) or not _identifier(person.person_id)
                    or not _time(person.expires_at) or person.expires_at <= now
                    or not isinstance(request, ExecutionRequest)
                    or request.method not in {"GET", "POST", "DELETE"}
                    or request.target != self.endpoint or not _digest(request.body_sha256)):
                raise ExecutionBindingError()
            source = self._decode(
                source_grant, keys=self._source_keys, issuer=self.source_issuer,
                typ=SOURCE_TYPE, purpose="source_context", ttl=300, fields=SOURCE_FIELDS, now=now,
            )
            call = self._decode(
                execution_proof, keys=self._execution_keys, issuer=self.execution_issuer,
                typ=EXECUTION_TYPE, purpose="external_mcp_execution", ttl=60,
                fields=EXECUTION_FIELDS, now=now,
            )
            target = ExecutionTarget(call["target_tenant_id"], call["target_agent_id"],
                                     call["target_version_id"], call["connection_id"])
            grant_hash = hashlib.sha256(source_grant.encode()).hexdigest()
            if (target not in self.targets or any(source[f] != call[f] for f in TARGET_FIELDS)
                    or source["source_actor_type"] != "human" or call["actor_type"] != "human"
                    or not re.fullmatch(r"[A-Za-z0-9_-]{43}", source["source_handle"])
                    or not _digest(source["anchor_revision"])
                    or call["source_grant_sha256"] != grant_hash
                    or call["source_handle_sha256"] != hashlib.sha256(source["source_handle"].encode()).hexdigest()
                    or any(call[f] != getattr(request, f) for f in ("method", "target", "body_sha256"))):
                raise ExecutionBindingError()
            # Two independent namespace mappings. Neither proof contains the
            # canonical person, nor is an email/string equality a valid link.
            actors = (
                (self.source_issuer, source["source_namespace"], source["source_actor"]),
                (_origin(call["actor_issuer"]), call["actor_namespace"], call["actor_subject"]),
            )
            for actor in actors:
                link = self.resolve_person(*actor)
                if (not isinstance(link, PlatformPersonLink) or link.active is not True
                        or (link.tenant_id, link.person_id) != (person.tenant_id, person.person_id)):
                    raise ExecutionBindingError()
            expiry = min(source["exp"], call["exp"], person.expires_at)
            if self.clock() >= expiry:
                raise ExecutionBindingError()
            replay = hashlib.sha256((self.execution_issuer + "\n" + self.audience
                                     + "\n" + call["jti"]).encode()).hexdigest()
            with self.store.transaction() as records:
                if records.get("external-execution-v1:" + replay) is not None:
                    raise ExecutionBindingError()
                records.put("external-execution-v1:" + replay, {"expires_at": call["exp"]})
            if self.clock() >= expiry:
                raise ExecutionBindingError()
            return VerifiedSourceCall(
                source["source_handle"], self.source_issuer, source["source_namespace"],
                source["source_actor"], source["anchor_revision"], target,
                source["invocation_id"], call["session_id"], expiry, grant_hash,
            )
        except Exception:
            raise ExecutionBindingError() from None
