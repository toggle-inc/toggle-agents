"""Agent-owned consent UI/OAuth endpoints + requester-scoped MCP, no Engine dependency."""

import contextlib
import html
from urllib.parse import parse_qs, urlsplit

from requester_mcp import create_app as create_mcp
from runtime.authorization import (
    CAPABILITIES,
    CAPABILITY_LABELS,
    AgentAuthorization,
    AuthorizationError,
)
from runtime.requester import RequesterDispatcher
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route


async def _form(request):
    if (
        request.headers.get("content-type", "").split(";", 1)[0]
        != "application/x-www-form-urlencoded"
    ):
        raise AuthorizationError("invalid_request")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > 16384:
            raise AuthorizationError("invalid_request")
        chunks.append(chunk)
    return _parameters(b"".join(chunks).decode("utf-8"))


def _parameters(value):
    parsed = parse_qs(value, keep_blank_values=True, strict_parsing=True, max_num_fields=20)
    if any(len(values) != 1 for values in parsed.values()):
        raise AuthorizationError("invalid_request")
    return {key: values[0] for key, values in parsed.items()}


class _PrivateHTTPS:
    def __init__(self, app, origin):
        self.app, self.origin = app, origin

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            await send({"type": "websocket.close", "code": 1008})
            return
        hosts = [
            v.decode("ascii", errors="replace")
            for k, v in scope.get("headers", ())
            if k.lower() == b"host"
        ]
        if scope.get("scheme") != "https" or hosts != [urlsplit(self.origin).netloc]:
            return await Response("HTTPS host required", status_code=400)(scope, receive, send)

        async def private_send(message):
            if message["type"] == "http.response.start":
                headers = [
                    (k, v)
                    for k, v in message.get("headers", ())
                    if k.lower() not in (b"cache-control", b"content-security-policy")
                ]
                headers += [
                    (b"cache-control", b"no-store"),
                    (
                        b"content-security-policy",
                        b"default-src 'none'; frame-ancestors 'none'; "
                        b"form-action 'self'; base-uri 'none'",
                    ),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-content-type-options", b"nosniff"),
                ]
                if message["status"] == 401 and scope.get("path") == "/mcp":
                    headers = [(k, v) for k, v in headers if k.lower() != b"www-authenticate"]
                    challenge = (
                        f'Bearer resource_metadata="{self.origin}'
                        '/.well-known/oauth-protected-resource"'
                    )
                    headers.append((b"www-authenticate", challenge.encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        return await self.app(scope, receive, private_send)


def create_app(authority, resolve):
    """Host supplies SSO verification + private storage/providers, not auth logic.

    The configured verify_login(Request) adapter must verify its own secure SSO
    session, including subject, tenant and expiry. Unconfigured login fails closed.
    No cookie/query/body claiming a person is accepted by this program itself.
    """
    if not isinstance(authority, AgentAuthorization):
        raise ValueError("Agent-owned authority is required")
    origin = authority.issuer
    dispatcher = RequesterDispatcher(authority.authenticate, resolve, clock=authority.clock)
    mcp = create_mcp(dispatcher, urlsplit(origin).hostname)

    async def endpoint(request):
        try:
            path = request.url.path
            if path == "/.well-known/oauth-authorization-server":
                return JSONResponse(
                    {
                        "issuer": origin,
                        "authorization_endpoint": origin + "/oauth/authorize",
                        "token_endpoint": origin + "/oauth/token",
                        "revocation_endpoint": origin + "/oauth/revoke",
                        "response_types_supported": ["code"],
                        "grant_types_supported": ["authorization_code"],
                        "code_challenge_methods_supported": ["S256"],
                        "token_endpoint_auth_methods_supported": ["none"],
                        "scopes_supported": sorted(CAPABILITIES),
                    }
                )
            if path == "/.well-known/oauth-protected-resource":
                return JSONResponse(
                    {
                        "resource": authority.resource,
                        "authorization_servers": [origin],
                        "scopes_supported": sorted(CAPABILITIES),
                    }
                )
            if path == "/oauth/authorize":
                params = _parameters(request.url.query)
                if (
                    params.get("response_type") != "code"
                    or params.get("code_challenge_method") != "S256"
                ):
                    raise AuthorizationError("invalid_request")
                pending = authority.begin(
                    request,
                    client_id=params["client_id"],
                    redirect_uri=params["redirect_uri"],
                    resource=params["resource"],
                    capabilities=frozenset(params["scope"].split()),
                    challenge=params["code_challenge"],
                    state=params["state"],
                )
                fields = "".join(
                    f'<input type="hidden" name="{key}" '
                    f'value="{html.escape(pending[key], quote=True)}">'
                    for key in ("request_id", "csrf_token")
                )
                scopes = "".join(
                    f"<li>{html.escape(CAPABILITY_LABELS[capability])} "
                    f"({html.escape(capability)})</li>"
                    for capability in pending["capabilities"]
                )
                return HTMLResponse(
                    '<!doctype html><html lang="ja"><meta charset="utf-8">'
                    "<title>経費アシスタントの利用許可</title>"
                    "<h1>経費アシスタントの利用許可</h1><p>"
                    + html.escape(pending["client_name"])
                    + "から、本人の接続を使って次の操作を呼べるようにします。</p><ul>"
                    + scopes
                    + "</ul><p>MF・カレンダーへの連携同意、"
                    "および経費の個別登録承認は別に必要です。</p>"
                    '<form method="post" action="/oauth/consent">'
                    + fields
                    + '<button name="decision" value="approve">許可する</button>'
                    '<button name="decision" value="deny">許可しない</button>'
                    '<button name="decision" value="revoke">'
                    "既存の利用許可も解除する</button></form></html>"
                )
            params = await _form(request)
            if path == "/oauth/consent":
                if request.headers.getlist("origin") != [origin]:
                    raise AuthorizationError("invalid_request")
                if params.get("decision") not in ("approve", "deny", "revoke"):
                    raise AuthorizationError("invalid_request")
                target = authority.decide(
                    request,
                    params["request_id"],
                    params["csrf_token"],
                    approve=params["decision"] == "approve",
                    revoke=params["decision"] == "revoke",
                )
                return RedirectResponse(target, status_code=303)
            if path == "/oauth/token":
                if params.get("grant_type") != "authorization_code":
                    raise AuthorizationError("unsupported_grant_type")
                return JSONResponse(
                    authority.exchange(
                        code=params["code"],
                        client_id=params["client_id"],
                        redirect_uri=params["redirect_uri"],
                        resource=params["resource"],
                        verifier=params["code_verifier"],
                    )
                )
            if path == "/oauth/revoke":
                authority.revoke_token(params["token"], params["client_id"])
                return Response(status_code=200)
            raise AuthorizationError("invalid_request")
        except AuthorizationError as error:
            return JSONResponse(
                {"error": error.code}, status_code=401 if error.code == "login_required" else 400
            )
        except (KeyError, ValueError, UnicodeError):
            return JSONResponse({"error": "invalid_request"}, status_code=400)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with mcp.app.router.lifespan_context(mcp.app):
            yield

    routes = [
        Route(path, endpoint, methods=methods)
        for path, methods in (
            ("/.well-known/oauth-authorization-server", ["GET"]),
            ("/.well-known/oauth-protected-resource", ["GET"]),
            ("/oauth/authorize", ["GET"]),
            ("/oauth/consent", ["POST"]),
            ("/oauth/token", ["POST"]),
            ("/oauth/revoke", ["POST"]),
        )
    ]
    routes.append(Mount("/", app=mcp))
    return _PrivateHTTPS(Starlette(routes=routes, lifespan=lifespan), origin)
