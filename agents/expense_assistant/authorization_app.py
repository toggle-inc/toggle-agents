"""Agent-owned consent UI/OAuth endpoints + requester-scoped MCP, no Engine dependency."""

import contextlib
import html
import inspect
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
                    challenge_parameters = (
                        f'resource_metadata="{self.origin}/.well-known/oauth-protected-resource"'
                    )
                    headers.append(
                        (b"www-authenticate", ("Bearer " + challenge_parameters).encode("ascii"))
                    )
                message = {**message, "headers": headers}
            await send(message)

        return await self.app(scope, receive, private_send)


def create_app(authority, resolve, *, start_login=None, login_adapter=None, draft_consent=None):
    """Host supplies SSO verification + private storage/providers, not auth logic.

    The configured verify_login(Request) adapter must verify its own secure SSO
    session, including subject, tenant and expiry. Unconfigured login fails closed.
    Optional start_login(Request) initiates the host's SSO flow for an
    unauthenticated browser authorization request and must return to the exact
    original /oauth/authorize URL after validating a signed, single-use state.
    No cookie/query/body claiming a person is accepted by this program itself.
    """
    if not isinstance(authority, AgentAuthorization):
        raise ValueError("Agent-owned authority is required")
    if draft_consent is not None:
        from runtime.draft_consent import DraftConsentBinding

        if (
            not isinstance(draft_consent, DraftConsentBinding)
            or draft_consent.authority is not authority
        ):
            raise ValueError("Draft consent must use this same agent-owned authority")
    origin = authority.issuer
    if login_adapter is not None:
        if start_login is not None:
            raise ValueError("Configure either login_adapter or start_login, not both")
        if (
            login_adapter.tenant_id != authority.tenant_id
            or login_adapter.callback_uri != origin + "/login/callback"
            or authority.verify_login != login_adapter.verify_login
        ):
            raise ValueError("Okta adapter tenant, session verifier, and fixed callback must match")
        start_login = login_adapter.start_login
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
                        "grant_types_supported": ["authorization_code", "refresh_token"],
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
                draft_fields = ""
                if "mf:draft" in pending["capabilities"]:
                    if draft_consent is None:
                        raise AuthorizationError("draft_consent_unavailable")
                    offices = draft_consent.choices(request, pending["request_id"])
                    options = "".join(
                        '<option value="'
                        + html.escape(office["id"], quote=True)
                        + '">'
                        + html.escape(office["name"])
                        + "</option>"
                        for office in offices
                    )
                    draft_fields = (
                        '<label>未申請明細の作成を許可する会社<select name="draft_office" required>'
                        '<option value="">会社を選択してください</option>'
                        + options
                        + "</select></label>"
                        "<p>選択した会社で、未申請明細の作成と領収書OCR送信を都度確認なしで行います。"
                        "確認・修正・申請はMF画面で行ってください。既存明細の変更・削除・提出は許可しません。</p>"
                    )
                return HTMLResponse(
                    '<!doctype html><html lang="ja"><meta charset="utf-8">'
                    "<title>経費アシスタントの利用許可</title>"
                    "<h1>経費アシスタントの利用許可</h1><p>"
                    + html.escape(pending["client_name"])
                    + "から、本人の接続を使って次の操作を呼べるようにします。</p><ul>"
                    + scopes
                    + "</ul><p>MF・カレンダーへの連携同意は別に必要です。"
                    "既存明細の変更・削除には別の本人承認が必要です。</p>"
                    "<p>この利用許可は解除するまで継続し、接続用トークンを自動更新できます。"
                    "不正な使い回しの検出時には停止します。</p>"
                    '<form method="post" action="/oauth/consent">'
                    + fields
                    + draft_fields
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
                draft_decision = None
                if draft_consent is not None and params["decision"] in {"approve", "revoke"}:
                    with authority.store.transaction() as records:
                        pending = records.get(authority._key("request", params["request_id"]))
                    if pending and "mf:draft" in pending["capabilities"]:
                        draft_decision = draft_consent.prepare(
                            request,
                            params["request_id"],
                            params["csrf_token"],
                            params.get("draft_office"),
                            revoke=params["decision"] == "revoke",
                        )
                target = authority.decide(
                    request,
                    params["request_id"],
                    params["csrf_token"],
                    approve=params["decision"] == "approve",
                    revoke=params["decision"] == "revoke",
                )
                if draft_decision is not None:
                    draft_consent.apply(request, draft_decision)
                return RedirectResponse(target, status_code=303)
            if path == "/oauth/token":
                if params.get("grant_type") == "refresh_token":
                    return JSONResponse(
                        authority.refresh(
                            refresh_token=params["refresh_token"],
                            client_id=params["client_id"],
                            resource=params.get("resource"),
                            capabilities=frozenset(params["scope"].split())
                            if "scope" in params
                            else None,
                        )
                    )
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
            if (
                error.code == "login_required"
                and path == "/oauth/authorize"
                and start_login is not None
            ):
                try:
                    response = start_login(request)
                    if inspect.isawaitable(response):
                        response = await response
                    if isinstance(response, Response):
                        return response
                except Exception:
                    # Do not expose identity-provider or session details.
                    pass
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
    if login_adapter is not None:
        routes.extend(
            (
                Route("/login/callback", login_adapter.callback, methods=["GET"]),
                Route("/logout", login_adapter.logout, methods=["POST"]),
            )
        )
    routes.append(Mount("/", app=mcp))
    return _PrivateHTTPS(Starlette(routes=routes, lifespan=lifespan), origin)
