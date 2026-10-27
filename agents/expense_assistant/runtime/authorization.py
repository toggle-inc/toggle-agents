"""Agent-owned consent + opaque OAuth authorization-code/PKCE authority.

No Engine imports or signing secrets. Login is verified by a configured SSO
adapter; this program owns consent, resource tokens, scope checks and revocation.
Only explicit public clients are accepted; no DCR, refresh or implicit grants.
"""

import base64
import hashlib
import hmac
import math
import re
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

from .requester import OPERATIONS, Requester
from .state import ExpenseError

CAPABILITIES = frozenset(OPERATIONS.values()) | {"receipt:read"}
CAPABILITY_LABELS = {
    "mf:read": "本人のMF明細・会社・申請情報を読む",
    "mf:write": "MF明細の作成・修正・削除・領収書登録（個別承認は別途必要）",
    "mf:connect": "本人のMF連携を開始・完了する",
    "calendar:read": "本人のカレンダーを読む",
    "fare:read": "交通運賃を調べる",
    "rules:read": "許可済みの社内規則・資料を読む",
    "attachment:read": "本人が許可した添付を取得する",
    "receipt:read": "本人の保存済み領収書を読む",
    "memory:read": "本人の設定・記憶・保留事項を読む",
    "memory:propose": "本人の記憶候補を作る",
    "contract:read": "エージェントの配送ルールを読む",
}


class AuthorizationError(ExpenseError):
    def __init__(self, code="invalid_grant"):
        self.code = code
        super().__init__("本人の認証・同意・接続期限を確認してください。")


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _https(value, *, origin=False):
    if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        raise ValueError("HTTPS URL required")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
        or "?" in value
        or "#" in value
        or (origin and parsed.path not in ("", "/"))
    ):
        raise ValueError("Exact HTTPS URL without query/fragment required")
    if origin and parsed.port not in (None, 443):
        raise ValueError("Issuer must use the standard HTTPS port")
    return value.rstrip("/") if origin else value


@dataclass(frozen=True)
class PublicClient:
    client_id: str
    display_name: str
    redirect_uris: tuple[str, ...]
    capabilities: frozenset[str]


class AgentAuthorization:
    """Trusted web routes call begin/decide; NEVER expose these as model tools.

    verify_login(request) must verify an SSO-backed browser session and return a
    canonical human Requester. It must not trust form fields, email matching,
    unsigned platform headers or a tenant-wide execution token.
    """

    def __init__(self, store, verify_login, *, issuer, tenant_id, clients, clock=time.time):
        self.issuer = _https(issuer, origin=True)
        self.resource = self.issuer + "/mcp"
        self.store, self.verify_login, self.clock = store, verify_login, clock
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("Deployment tenant is required")
        self.tenant_id = tenant_id
        self.clients = {}
        for client in clients:
            if (
                not isinstance(client, PublicClient)
                or not client.client_id
                or client.client_id in self.clients
                or not client.display_name
                or not client.redirect_uris
                or not isinstance(client.capabilities, frozenset)
                or not client.capabilities
                or not client.capabilities <= CAPABILITIES
            ):
                raise ValueError("Explicit client and allowed capabilities required")
            for uri in client.redirect_uris:
                _https(uri)
            self.clients[client.client_id] = client
        if not self.clients:
            raise ValueError("At least one explicit client required")
        self.namespace = "expense-auth-v1:" + _hash(self.issuer + "\n" + tenant_id) + ":"

    def _key(self, kind, value):
        return self.namespace + kind + ":" + _hash(value)

    def _client(self, client_id):
        client = self.clients.get(client_id)
        if client is None:
            raise AuthorizationError("invalid_client")
        return client

    def _login(self, context):
        try:
            person = self.verify_login(context)
            valid = (
                isinstance(person, Requester)
                and person.kind == "human"
                and person.tenant_id == self.tenant_id
                and isinstance(person.person_id, str)
                and bool(person.person_id.strip())
                and len(person.person_id) <= 512
                and type(person.expires_at) in (int, float)
                and math.isfinite(person.expires_at)
                and person.expires_at > self.clock()
            )
        except Exception:
            valid = False
        if not valid:
            raise AuthorizationError("login_required")
        return person

    def begin(self, context, *, client_id, redirect_uri, resource, capabilities, challenge, state):
        person = self._login(context)
        client = self._client(client_id)
        if redirect_uri not in client.redirect_uris or resource != self.resource:
            raise AuthorizationError("invalid_target")
        if (
            not isinstance(capabilities, frozenset)
            or not capabilities
            or not capabilities <= client.capabilities
        ):
            raise AuthorizationError("invalid_scope")
        if (
            not isinstance(challenge, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge)
            or not isinstance(state, str)
            or not 1 <= len(state) <= 2048
        ):
            raise AuthorizationError("invalid_request")
        request_id, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        record = {
            "tenant_id": person.tenant_id,
            "person_id": person.person_id,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "resource": resource,
            "capabilities": sorted(capabilities),
            "challenge": challenge,
            "state": state,
            "csrf_hash": _hash(nonce),
            "expires_at": min(self.clock() + 300, person.expires_at),
            "used": False,
        }
        with self.store.transaction() as records:
            records.put(self._key("request", request_id), record)
        return {
            "request_id": request_id,
            "csrf_token": nonce,
            "client_name": client.display_name,
            "capabilities": sorted(capabilities),
        }

    def decide(self, context, request_id, csrf_token, *, approve, revoke=False):
        person = self._login(context)
        if (
            type(approve) is not bool
            or type(revoke) is not bool
            or (approve and revoke)
            or not isinstance(csrf_token, str)
        ):
            raise AuthorizationError("invalid_request")
        with self.store.transaction() as records:
            key = self._key("request", request_id)
            record = records.get(key)
            if (
                not record
                or record["used"]
                or record["expires_at"] <= self.clock()
                or record["tenant_id"] != person.tenant_id
                or record["person_id"] != person.person_id
                or not hmac.compare_digest(record["csrf_hash"], _hash(csrf_token))
            ):
                raise AuthorizationError()
            client = self._client(record["client_id"])
            if record["redirect_uri"] not in client.redirect_uris:
                raise AuthorizationError("invalid_target")
            record["used"] = True
            records.put(key, record)
            params = {"state": record["state"]}
            if approve:
                if not set(record["capabilities"]) <= client.capabilities:
                    raise AuthorizationError("invalid_scope")
                consent_key = self._consent_key(person, client.client_id)
                revision = secrets.token_hex(16)
                records.put(
                    consent_key,
                    {
                        "revision": revision,
                        "revoked": False,
                        "capabilities": record["capabilities"],
                    },
                )
                code = secrets.token_urlsafe(32)
                records.put(
                    self._key("code", code),
                    {
                        **record,
                        "used": False,
                        "consent_key": consent_key,
                        "revision": revision,
                        "expires_at": min(self.clock() + 60, person.expires_at),
                    },
                )
                params["code"] = code
            else:
                params["error"] = "access_denied"
                if revoke:
                    records.put(
                        self._consent_key(person, record["client_id"]),
                        {
                            "revision": secrets.token_hex(16),
                            "revoked": True,
                            "capabilities": [],
                        },
                    )
            return record["redirect_uri"] + "?" + urlencode(params)

    def _consent_key(self, person, client_id):
        return self._key("consent", person.owner + "\n" + client_id)

    def _current(self, records, record):
        if not record or record["expires_at"] <= self.clock():
            raise AuthorizationError()
        consent = records.get(record["consent_key"])
        client = self._client(record["client_id"])
        if (
            not consent
            or consent["revoked"]
            or consent["revision"] != record["revision"]
            or not set(record["capabilities"]) <= client.capabilities
            or not set(record["capabilities"]) <= set(consent["capabilities"])
            or record["resource"] != self.resource
            or record["redirect_uri"] not in client.redirect_uris
            or record["tenant_id"] != self.tenant_id
        ):
            raise AuthorizationError()

    def exchange(self, *, code, client_id, redirect_uri, resource, verifier):
        self._client(client_id)
        if not isinstance(verifier, str) or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier):
            raise AuthorizationError()
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        with self.store.transaction() as records:
            key = self._key("code", code)
            record = records.get(key)
            self._current(records, record)
            if (
                record["used"]
                or record["client_id"] != client_id
                or record["redirect_uri"] != redirect_uri
                or resource != self.resource
                or not hmac.compare_digest(record["challenge"], challenge)
            ):
                raise AuthorizationError()
            record["used"] = True
            records.put(key, record)
            token = secrets.token_urlsafe(48)
            lifetime = 900
            records.put(
                self._key("token", token),
                {
                    **record,
                    "expires_at": self.clock() + lifetime,
                },
            )
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": lifetime,
            "scope": " ".join(record["capabilities"]),
        }

    def authenticate(self, token):
        if not isinstance(token, str) or not 1 <= len(token) <= 8192:
            raise AuthorizationError()
        with self.store.transaction() as records:
            record = records.get(self._key("token", token))
            self._current(records, record)
            if record.get("revoked", False):
                raise AuthorizationError()
            return Requester(
                record["tenant_id"],
                record["person_id"],
                record["expires_at"],
                capabilities=frozenset(record["capabilities"]),
            )

    def revoke_token(self, token, client_id):
        self._client(client_id)
        with self.store.transaction() as records:
            key = self._key("token", token)
            record = records.get(key)
            if record and record["client_id"] == client_id:
                record["revoked"] = True
                records.put(key, record)

    def revoke_consent(self, context, client_id):
        person = self._login(context)
        self._client(client_id)
        with self.store.transaction() as records:
            records.put(
                self._consent_key(person, client_id),
                {"revision": secrets.token_hex(16), "revoked": True, "capabilities": []},
            )
