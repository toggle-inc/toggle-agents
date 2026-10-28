"""Okta OIDC login adapter for the agent-owned OAuth consent host.

The host must supply a private transactional store and an explicit identity
link resolver. No email, profile claim, platform assertion, or self-registration
is used to choose a canonical person.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from cryptography.fernet import Fernet, InvalidToken
from starlette.responses import RedirectResponse, Response

from .requester import Requester


class OktaLoginError(Exception):
    """Generic login failure; do not expose provider details to the browser."""


def _https_url(value):
    if not isinstance(value, str) or any(ord(char) <= 32 or ord(char) >= 127 for char in value):
        raise ValueError("HTTPS URL required")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
    ):
        raise ValueError("Exact HTTPS URL required")
    return value.rstrip("/")


def _origin(url):
    parsed = urlsplit(url)
    return f"https://{parsed.netloc}"


class OktaOIDCLogin:
    """Authorization Code + PKCE login with encrypted one-time state and sessions.

    `resolve_person(tenant_id, issuer, subject)` must return a canonical person
    ID from an explicit, administrator-managed identity link, or None.
    `store` must provide atomic `transaction()` with Records.get/put.
    """

    def __init__(
        self,
        store,
        resolve_person,
        *,
        issuer,
        client_id,
        client_secret,
        callback_uri,
        tenant_id,
        state_encryption_key,
        session_ttl=8 * 60 * 60,
        clock=time.time,
        http_client_factory=httpx.AsyncClient,
    ):
        self.issuer = _https_url(issuer)
        self.callback_uri = _https_url(callback_uri)
        if not all(
            isinstance(value, str) and value.strip()
            for value in (client_id, client_secret, tenant_id)
        ):
            raise ValueError("Okta client and tenant configuration required")
        if not callable(resolve_person):
            raise ValueError("Explicit identity-link resolver required")
        if type(session_ttl) is not int or not 60 <= session_ttl <= 86400:
            raise ValueError("Session TTL must be between one minute and one day")
        if not isinstance(state_encryption_key, str) or len(state_encryption_key) < 32:
            raise ValueError("Dedicated state encryption key must contain at least 32 characters")
        self.store = store
        self.resolve_person = resolve_person
        self.client_id = client_id
        self._client_secret = client_secret
        self.tenant_id = tenant_id
        self.session_ttl = session_ttl
        self.clock = clock
        self.http_client_factory = http_client_factory
        self._fernet = Fernet(
            base64.urlsafe_b64encode(hashlib.sha256(state_encryption_key.encode()).digest())
        )
        namespace = f"expense-okta-v1:{self.issuer}:{tenant_id}:"
        self._prefix = hashlib.sha256(namespace.encode()).hexdigest()
        self._metadata = None
        self._metadata_expiry = 0

    def _key(self, kind, value):
        digest = hashlib.sha256(value.encode()).hexdigest()
        return f"expense-okta-v1:{self._prefix}:{kind}:{digest}"

    async def _get_metadata(self):
        if self._metadata is not None and self._metadata_expiry > self.clock():
            return self._metadata
        url = self.issuer + "/.well-known/openid-configuration"
        try:
            async with self.http_client_factory(timeout=10, follow_redirects=False) as client:
                response = await client.get(url, headers={"accept": "application/json"})
            if response.status_code != 200:
                raise OktaLoginError
            metadata = response.json()
            if metadata.get("issuer") != self.issuer:
                raise OktaLoginError
            for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                endpoint = _https_url(metadata.get(name))
                if _origin(endpoint) != _origin(self.issuer):
                    raise OktaLoginError
                metadata[name] = endpoint
            self._metadata = metadata
            self._metadata_expiry = self.clock() + 300
            return metadata
        except Exception as error:
            raise OktaLoginError from error

    async def start_login(self, request):
        """Redirect to Okta; recover only this validated authorization URL."""
        authorize_url = str(request.url)
        parsed = urlsplit(authorize_url)
        if (
            parsed.scheme != "https"
            or _origin(authorize_url) != _origin(self.callback_uri)
            or parsed.path != "/oauth/authorize"
            or parsed.fragment
            or not parsed.query
        ):
            raise OktaLoginError
        metadata = await self._get_metadata()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        now = self.clock()
        payload = {
            "authorize_url": authorize_url,
            "nonce": nonce,
            "verifier": verifier,
            "expires_at": now + 300,
        }
        encrypted = self._fernet.encrypt(
            json.dumps(payload, separators=(",", ":")).encode()
        ).decode()
        with self.store.transaction() as records:
            records.put(self._key("state", state), {"payload": encrypted, "used": False})
        query = urlencode(
            {
                "client_id": self.client_id,
                "response_type": "code",
                "response_mode": "query",
                "scope": "openid profile",
                "redirect_uri": self.callback_uri,
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        return RedirectResponse(metadata["authorization_endpoint"] + "?" + query, status_code=303)

    async def callback(self, request):
        try:
            params = request.query_params
            callback_request = urlsplit(str(request.url))
            if (
                callback_request.scheme != "https"
                or _origin(str(request.url)) != _origin(self.callback_uri)
                or callback_request.path != urlsplit(self.callback_uri).path
            ):
                raise OktaLoginError
            state_values = params.getlist("state")
            code_values = params.getlist("code")
            if len(state_values) != 1 or len(code_values) != 1 or params.get("error"):
                raise OktaLoginError
            state, code = state_values[0], code_values[0]
            if not state or not code or len(code) > 4096:
                raise OktaLoginError
            now = self.clock()
            with self.store.transaction() as records:
                key = self._key("state", state)
                record = records.get(key)
                if not record or record.get("used") is not False:
                    raise OktaLoginError
                record["used"] = True
                records.put(key, record)
            payload = json.loads(self._fernet.decrypt(record["payload"].encode()))
            if payload.get("expires_at", 0) <= now:
                raise OktaLoginError
            metadata = await self._get_metadata()
            async with self.http_client_factory(timeout=10, follow_redirects=False) as client:
                response = await client.post(
                    metadata["token_endpoint"],
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": self.callback_uri,
                        "code_verifier": payload["verifier"],
                    },
                    auth=(self.client_id, self._client_secret),
                    headers={"accept": "application/json"},
                )
            if response.status_code != 200:
                raise OktaLoginError
            tokens = response.json()
            id_token = tokens.get("id_token")
            if not isinstance(id_token, str) or len(id_token) > 16384:
                raise OktaLoginError
            claims = await self._verify_id_token(id_token, metadata, payload["nonce"])
            subject = claims.get("sub")
            if not isinstance(subject, str) or not subject or len(subject) > 512:
                raise OktaLoginError
            person_id = self.resolve_person(self.tenant_id, self.issuer, subject)
            if not isinstance(person_id, str) or not person_id.strip() or len(person_id) > 512:
                raise OktaLoginError
            session_id = secrets.token_urlsafe(32)
            expires_at = now + self.session_ttl
            with self.store.transaction() as records:
                records.put(
                    self._key("session", session_id),
                    {
                        "tenant_id": self.tenant_id,
                        "person_id": person_id,
                        "expires_at": expires_at,
                        "revoked": False,
                    },
                )
            response = RedirectResponse(payload["authorize_url"], status_code=303)
            response.set_cookie(
                "expense_session",
                session_id,
                max_age=self.session_ttl,
                httponly=True,
                secure=True,
                samesite="lax",
                path="/",
            )
            return response
        except (
            OktaLoginError,
            InvalidToken,
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
        ):
            return Response(
                "ログインを確認できませんでした。最初からやり直してください。", status_code=400
            )
        except Exception:
            return Response(
                "ログインを確認できませんでした。最初からやり直してください。", status_code=400
            )

    async def _verify_id_token(self, token, metadata, expected_nonce):
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                raise OktaLoginError
            async with self.http_client_factory(timeout=10, follow_redirects=False) as client:
                response = await client.get(
                    metadata["jwks_uri"], headers={"accept": "application/json"}
                )
            if response.status_code != 200:
                raise OktaLoginError
            jwks = response.json().get("keys", [])
            matches = [
                jwt.PyJWK.from_dict(item) for item in jwks if item.get("kid") == header["kid"]
            ]
            if len(matches) != 1 or matches[0].algorithm_name != "RS256":
                raise OktaLoginError
            claims = jwt.decode(
                token,
                matches[0].key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
                leeway=60,
            )
            audience = claims.get("aud")
            if (
                isinstance(audience, list)
                and len(audience) > 1
                and claims.get("azp") != self.client_id
            ):
                raise OktaLoginError
            if claims.get("azp") is not None and claims.get("azp") != self.client_id:
                raise OktaLoginError
            if not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(
                claims["nonce"], expected_nonce
            ):
                raise OktaLoginError
            return claims
        except Exception as error:
            raise OktaLoginError from error

    def verify_login(self, request):
        """Return only a current, server-side session and linked human identity."""
        session_id = request.cookies.get("expense_session")
        if not isinstance(session_id, str) or not session_id:
            return None
        now = self.clock()
        with self.store.transaction() as records:
            key = self._key("session", session_id)
            session = records.get(key)
            if (
                not session
                or session.get("revoked") is not False
                or session.get("tenant_id") != self.tenant_id
                or not isinstance(session.get("person_id"), str)
                or type(session.get("expires_at")) not in (int, float)
                or session["expires_at"] <= now
            ):
                return None
            return Requester(
                tenant_id=self.tenant_id,
                person_id=session["person_id"],
                expires_at=session["expires_at"],
            )

    async def logout(self, request):
        if request.headers.getlist("origin") != [_origin(self.callback_uri)]:
            return Response("invalid request", status_code=400)
        session_id = request.cookies.get("expense_session")
        if isinstance(session_id, str) and session_id:
            with self.store.transaction() as records:
                key = self._key("session", session_id)
                session = records.get(key)
                if session:
                    session["revoked"] = True
                    records.put(key, session)
        response = Response(status_code=204)
        response.delete_cookie(
            "expense_session", path="/", secure=True, httponly=True, samesite="lax"
        )
        return response
