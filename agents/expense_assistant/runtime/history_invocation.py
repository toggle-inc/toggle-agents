"""Draft, unwired validation of source authority + per-call execution proof.

No HTTP, storage, keys, issuing, credential selection or history access is supplied.
ExpectedHistoryCall MUST come from authenticated transport and explicit account
links, never model arguments, instruction JSON or a person's latest invocation.
A valid reference is NOT a history permission: the source adapter must check
current source ACL, anchor edits/deletion and revocation on EVERY history read.
The separate resource OAuth authentication/consent gate must also run every call.
"""

import hashlib
import math
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class HistoryProofError(Exception):
    """No source data, tokens, claims or signature diagnostics in public errors."""

    def __init__(self):
        super().__init__("invalid_history_invocation")


@dataclass(frozen=True)
class ExpectedHistoryCall:
    tenant_id: str
    person_id: str
    source_tenant_id: str
    source_actor_id: str
    agent_id: str
    invocation_id: str
    session_id: str
    auth_expires_at: float
    actor_kind: str = "human"


@dataclass(frozen=True)
class HistorySourceReference:
    source_handle: str = field(repr=False)
    anchor_id: str
    source_tenant_id: str
    source_actor_id: str
    agent_id: str
    invocation_id: str
    session_id: str
    expires_at: float


def _id(value):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 512


def _time(value):
    return type(value) in (int, float) and math.isfinite(value)


def _https(value):
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    return (parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username
            and not parsed.password and not parsed.query and not parsed.fragment)


class HistoryInvocationValidator:
    """Two independent trusted issuers, fixed resource audience, no discovery.

    Source issuer attests actor/source access at intake, before session creation.
    Call issuer attests the CURRENT execution/session and the source proof hash.
    Both are verified independently; a source proof alone cannot choose a session.
    Key rotation/trust and short-proof renewal require explicit host composition.
    This preparation is deliberately not wired to any existing OAuth/MCP route.
    """

    SOURCE_TYP = "agent-history-source+jwt"
    CALL_TYP = "agent-history-call+jwt"
    SOURCE_MAX_TTL = 300
    CALL_MAX_TTL = 60

    def __init__(self, *, source_issuer, source_keys, call_issuer, call_keys,
                 audience, clock=time.time):
        if not all(_https(v) for v in (source_issuer, call_issuer, audience)) or not callable(clock):
            raise ValueError("Explicit HTTPS history trust required")
        self.source_issuer, self.call_issuer, self.audience = source_issuer, call_issuer, audience
        self._source_keys, self._call_keys = self._keys(source_keys), self._keys(call_keys)
        self.clock = clock

    @staticmethod
    def _keys(keys):
        try:
            if not isinstance(keys, dict) or not keys or len(keys) > 16:
                raise ValueError
            result = {}
            for kid, pem in keys.items():
                if not _id(kid) or not isinstance(pem, str):
                    raise ValueError
                key = serialization.load_pem_public_key(pem.encode())
                if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
                    raise ValueError
                result[kid] = key
            return result
        except Exception:
            raise ValueError("Explicit RSA history verification keys required") from None

    def _decode(self, token, *, issuer, keys, typ, purpose, ttl, fields, now):
        if not isinstance(token, str) or not 1 <= len(token) <= 16384:
            raise HistoryProofError()
        header = jwt.get_unverified_header(token)
        if (header.get("alg") != "RS256" or header.get("typ") != typ
                or header.get("kid") not in keys
                or set(header) != {"alg", "typ", "kid"}):
            raise HistoryProofError()
        claims = jwt.decode(token, keys[header["kid"]], algorithms=["RS256"],
                            issuer=issuer, audience=self.audience,
                            options={"require": ["iss", "aud", "iat", "exp", "jti", "purpose"],
                                     "verify_iat": False, "verify_exp": False,
                                     "strict_aud": True})
        if (set(claims) != {"iss", "aud", "iat", "exp", "jti", "purpose"} | set(fields)
                or claims["purpose"] != purpose or not _id(claims["jti"])
                or not all(_id(claims[name]) for name in fields)
                or not _time(claims["iat"]) or not _time(claims["exp"])
                or not claims["iat"] <= now < claims["exp"]
                or not 0 < claims["exp"] - claims["iat"] <= ttl):
            raise HistoryProofError()
        return claims

    def validate(self, source_grant, call_proof, *, expected):
        """Return only an opaque reference, bound to the authenticated call.

        Repeated reads of the same execution are allowed within both proof TTLs.
        This is read-only binding, not a one-use write approval/replay ledger.
        """
        try:
            now = self.clock()
            if (not _time(now) or not isinstance(expected, ExpectedHistoryCall)
                    or expected.actor_kind != "human" or not _time(expected.auth_expires_at)
                    or expected.auth_expires_at <= now
                    or not all(_id(getattr(expected, name)) for name in (
                        "tenant_id", "person_id", "source_tenant_id", "source_actor_id",
                        "agent_id", "invocation_id", "session_id"))):
                raise HistoryProofError()
            source = self._decode(
                source_grant, issuer=self.source_issuer, keys=self._source_keys,
                typ=self.SOURCE_TYP, purpose="history_source", ttl=self.SOURCE_MAX_TTL,
                fields=("source_tenant_id", "source_actor_id", "agent_id", "invocation_id",
                        "anchor_id", "source_handle"), now=now,
            )
            call = self._decode(
                call_proof, issuer=self.call_issuer, keys=self._call_keys,
                typ=self.CALL_TYP, purpose="history_call", ttl=self.CALL_MAX_TTL,
                fields=("tenant_id", "person_id", "agent_id", "invocation_id", "session_id",
                        "source_grant_sha256"), now=now,
            )
            if (not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", source["source_handle"])
                    or call["source_grant_sha256"] != hashlib.sha256(source_grant.encode()).hexdigest()
                    or any(source[name] != getattr(expected, name) for name in (
                        "source_tenant_id", "source_actor_id", "agent_id", "invocation_id"))
                    or any(call[name] != getattr(expected, name) for name in (
                        "tenant_id", "person_id", "agent_id", "invocation_id", "session_id"))):
                raise HistoryProofError()
            return HistorySourceReference(
                source["source_handle"], source["anchor_id"], source["source_tenant_id"],
                source["source_actor_id"], source["agent_id"], source["invocation_id"],
                call["session_id"], min(source["exp"], call["exp"], expected.auth_expires_at),
            )
        except Exception:
            raise HistoryProofError() from None
