"""Verify platform-authenticated humans without re-running an agent's SSO login.

Private signing keys remain at the platform. Only pinned RSA public keys are
accepted here; no discovery URL, model fields, email matching or shared owner.
PyJWT/cryptography is imported only when this optional capability is configured.
"""

import hashlib
import math
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

ASSERTION_TYPE = "agent-platform-principal+jwt"


class PlatformIdentityError(Exception):
    def __init__(self):
        super().__init__("Verified platform identity required")


def _identifier(value):
    return (
        isinstance(value, str)
        and 0 < len(value) <= 512
        and value == value.strip()
        and not any(ord(c) < 32 or ord(c) == 127 for c in value)
    )


def _origin(value):
    if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        raise ValueError("Exact HTTPS origin required")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.path
        or parsed.query
        or parsed.fragment
        or value != "https://" + parsed.netloc
    ):
        raise ValueError("Exact HTTPS origin required")
    return value


@dataclass(frozen=True)
class PlatformPersonLink:
    tenant_id: str
    person_id: str
    active: bool = True


@dataclass(frozen=True)
class PlatformPerson:
    tenant_id: str
    person_id: str
    expires_at: float


@dataclass(frozen=True)
class RequestBinding:
    method: str
    target: str
    body_sha256: str
    origin: str


class PlatformIdentityVerifier:
    """Authenticate one signed HTTP request; never grant provider permissions.

    resolve_person(issuer, platform_tenant, subject) must read an explicit active
    canonical identity link. The platform tenant is not an Engine tenant.
    store.transaction/get/put must be atomic across workers to consume jti once.
    Revalidate the platform session before signing EACH request (no PAT/guest/
    impersonation/service identities); all request fields come from trusted BFF
    configuration, not a prompt, user-supplied subject or arbitrary proxy target.
    """

    def __init__(
        self, store, resolve_person, *, issuer, audience, tenant_id, public_keys, clock=time.time
    ):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

        self.issuer, self.audience = _origin(issuer), _origin(audience)
        if not _identifier(tenant_id) or not callable(resolve_person) or not public_keys:
            raise ValueError("Explicit tenant, identity resolver and public keys required")
        self._keys = {}
        for kid, pem in public_keys.items():
            if not _identifier(kid) or len(kid) > 128 or not isinstance(pem, str):
                raise ValueError("Pinned RSA public keys required")
            key = serialization.load_pem_public_key(pem.encode())
            if not isinstance(key, RSAPublicKey) or key.key_size < 2048:
                raise ValueError("Pinned RSA public keys of at least 2048 bits required")
            self._keys[kid] = key
        self.store, self.resolve_person = store, resolve_person
        self.tenant_id, self.clock = tenant_id, clock

    def authenticate(self, assertion, binding):
        import jwt

        try:
            if not isinstance(assertion, str) or not 1 <= len(assertion) <= 16384:
                raise PlatformIdentityError
            if not isinstance(binding, RequestBinding):
                raise PlatformIdentityError
            parsed = urlsplit(binding.target)
            if (
                binding.method not in {"GET", "POST"}
                or parsed.scheme != "https"
                or parsed.netloc != urlsplit(self.audience).netloc
                or parsed.username
                or parsed.password
                or parsed.fragment
                or not parsed.path.startswith("/")
                or len(binding.target) > 16384
                or any(ord(c) <= 32 or ord(c) >= 127 for c in binding.target)
                or not re.fullmatch(r"[a-f0-9]{64}", binding.body_sha256)
                or binding.origin not in ("", self.issuer)
                or (binding.method == "POST" and binding.origin != self.issuer)
            ):
                raise PlatformIdentityError
            header = jwt.get_unverified_header(assertion)
            if (
                set(header) != {"alg", "kid", "typ"}
                or header["alg"] != "RS256"
                or header["typ"] != ASSERTION_TYPE
                or header["kid"] not in self._keys
            ):
                raise PlatformIdentityError
            required = {
                "iss",
                "aud",
                "sub",
                "tenant_id",
                "actor_type",
                "purpose",
                "iat",
                "exp",
                "auth_expires_at",
                "jti",
                "method",
                "target",
                "body_sha256",
                "origin",
            }
            claims = jwt.decode(
                assertion,
                self._keys[header["kid"]],
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "require": list(required),
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                    "strict_aud": True,
                },
            )
            now = self.clock()
            times = [claims[name] for name in ("iat", "exp", "auth_expires_at")]
            if (
                set(claims) != required
                or any(type(t) not in (int, float) or not math.isfinite(t) for t in times)
                or not (now - 60 <= claims["iat"] <= now + 5)
                or not (now < claims["exp"] <= claims["iat"] + 60)
                or not (claims["exp"] <= claims["auth_expires_at"] <= now + 86400)
                or claims["actor_type"] != "human"
                or claims["purpose"] != "platform_login"
                or any(not _identifier(claims[name]) for name in ("sub", "tenant_id", "jti"))
                or any(
                    claims[name] != getattr(binding, name)
                    for name in ("method", "target", "body_sha256", "origin")
                )
            ):
                raise PlatformIdentityError
            link = self.resolve_person(self.issuer, claims["tenant_id"], claims["sub"])
            if (
                not isinstance(link, PlatformPersonLink)
                or link.active is not True
                or link.tenant_id != self.tenant_id
                or not _identifier(link.person_id)
            ):
                raise PlatformIdentityError
            # The replay namespace binds issuer + audience + platform tenant.
            raw = "\n".join((self.issuer, self.audience, claims["tenant_id"], claims["jti"]))
            key = "platform-principal-v1:" + hashlib.sha256(raw.encode()).hexdigest()
            with self.store.transaction() as records:
                if records.get(key) is not None:
                    raise PlatformIdentityError
                records.put(key, {"expires_at": claims["exp"]})
            return PlatformPerson(self.tenant_id, link.person_id, claims["auth_expires_at"])
        except Exception:
            raise PlatformIdentityError from None
