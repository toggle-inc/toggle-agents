"""Agent-side HTTP binding for verified platform/BFF requests, not a new SSO.

The platform renders/proxies initial consent for its logged-in human. It must
recheck its session and CSRF before signing exact GET/POST bytes. A browser or
model must never receive the assertion/private key or pick an arbitrary target.
"""

import hashlib
from urllib.parse import urlsplit

from _foundation.platform_identity import PlatformIdentityError, RequestBinding
from starlette.responses import JSONResponse

from .requester import Requester


class PlatformLogin:
    def __init__(self, verifier):
        self.verifier = verifier
        self._scope_key = object()

    def verify_login(self, request):
        person = request.scope.get(self._scope_key)
        if person is None:
            return None
        return Requester(person.tenant_id, person.person_id, person.expires_at)

    def wrap(self, app):
        return _VerifiedPlatformRequests(app, self)

    def allows_consent_origin(self, request):
        return request.scope.get(self._scope_key) is not None and request.headers.getlist(
            "origin"
        ) == [self.verifier.issuer]


class _VerifiedPlatformRequests:
    def __init__(self, app, login):
        self.app, self.login = app, login

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") not in {
            "/oauth/authorize",
            "/oauth/consent",
            "/connections",
            "/connections/start",
            "/connections/callback",
            "/execution/status",
            "/memory",
            "/memory/decision",
        }:
            return await self.app(scope, receive, send)
        try:
            origin = self.login.verifier.audience
            headers = scope.get("headers", [])

            def values(name):
                return [v.decode("ascii") for k, v in headers if k.lower() == name]

            proofs = values(b"x-agent-platform-assertion")
            source_origin = values(b"origin")
            if (
                scope.get("scheme") != "https"
                or values(b"host") != [urlsplit(origin).netloc]
                or len(proofs) != 1
                or len(source_origin) > 1
                or scope["method"] not in (
                    {"GET", "POST"} if scope["path"] == "/connections/callback"
                    else {"GET"} if scope["path"] in {"/oauth/authorize", "/connections", "/memory"}
                    else {"POST"}
                )
                or (scope["method"] == "POST" and scope.get("query_string", b""))
            ):
                raise PlatformIdentityError
            chunks, size = [], 0
            while True:
                message = await receive()
                if message["type"] != "http.request":
                    raise PlatformIdentityError
                size += len(message.get("body", b""))
                if size > 16384:
                    raise PlatformIdentityError
                chunks.append(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            body = b"".join(chunks)
            if scope["method"] == "GET" and body:
                raise PlatformIdentityError
            raw_path = scope.get("raw_path", scope["path"].encode("ascii")).decode("ascii")
            query = scope.get("query_string", b"").decode("ascii")
            target = origin + raw_path + ("?" + query if query else "")
            person = self.login.verifier.authenticate(
                proofs[0],
                RequestBinding(
                    scope["method"],
                    target,
                    hashlib.sha256(body).hexdigest(),
                    source_origin[0] if source_origin else "",
                ),
            )
            new_scope = {**scope, self.login._scope_key: person}
            # Preserve the signed browser Origin; the OAuth app checks it via
            # the verified adapter rather than pretending it is the agent host.
            new_scope["headers"] = [
                (k, v) for k, v in headers if k.lower() != b"x-agent-platform-assertion"
            ]
        except Exception:
            return await JSONResponse(
                {"error": "platform_login_required"},
                status_code=401,
                headers={"cache-control": "no-store", "referrer-policy": "no-referrer"},
            )(scope, receive, send)
        delivered = False

        async def replay_body():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        return await self.app(new_scope, replay_body, send)
