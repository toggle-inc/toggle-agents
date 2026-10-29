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
    def __init__(self, app, origin, *, connection_form_origins=()):
        self.app, self.origin = app, origin
        self.connection_form_origins = tuple(connection_form_origins)

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
                form_action = "form-action 'self'"
                if scope.get("path") == "/connections" and self.connection_form_origins:
                    # Chromium applies form-action to a POST's redirect chain.
                    # Only this GUI may redirect to explicitly configured providers.
                    form_action += " " + " ".join(self.connection_form_origins)
                headers = [
                    (k, v)
                    for k, v in message.get("headers", ())
                    if k.lower() not in (b"cache-control", b"content-security-policy")
                ]
                headers += [
                    (b"cache-control", b"no-store"),
                    (
                        b"content-security-policy",
                        ("default-src 'none'; frame-ancestors 'none'; "
                         + form_action + "; base-uri 'none'").encode("ascii"),
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


def create_app(
    authority,
    resolve,
    *,
    start_login=None,
    login_adapter=None,
    draft_consent=None,
    platform_login=None,
    service_connections=None,
):
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
    if service_connections is not None:
        from runtime.service_connections import ServiceConnections

        if not isinstance(service_connections, ServiceConnections) or service_connections.store is not authority.store:
            raise ValueError("Service connections must use this same private store")
    if platform_login is not None:
        from runtime.platform_login import PlatformLogin

        if (
            not isinstance(platform_login, PlatformLogin)
            or login_adapter is not None
            or start_login is not None
            or authority.verify_login != platform_login.verify_login
            or platform_login.verifier.store is not authority.store
            or platform_login.verifier.tenant_id != authority.tenant_id
            or platform_login.verifier.audience != origin
        ):
            raise ValueError("Platform verifier, authority and store must match")
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
            if path in {"/connections", "/connections/start", "/connections/callback"}:
                person = authority._login(request)
                if service_connections is None:
                    return JSONResponse({"error": "service_connections_unavailable"}, status_code=503)
                if path == "/connections/callback":
                    params = _parameters(request.url.query)
                    provider = params.pop("provider", None)
                    try:
                        result = service_connections.complete(person, provider, params)
                    except Exception:
                        return JSONResponse({"error": "service_connection_callback_failed"}, status_code=400)
                    if request.headers.getlist("accept") == ["application/json"]:
                        return JSONResponse(result)
                    return HTMLResponse(
                        '<!doctype html><html lang="ja"><meta charset="utf-8">'
                        '<title>サービス連携の確認</title><h1>認証の応答を受け付けました</h1>'
                        '<p>接続状態を確認してください。</p><a href="/connections">サービス連携へ戻る</a></html>'
                    )
                if path == "/connections":
                    if request.url.query:
                        raise AuthorizationError("invalid_request")
                    return service_connections.render(
                        person, as_json=request.headers.getlist("accept") == ["application/json"]
                    )
                if (platform_login is None and request.headers.getlist("origin") != [origin]) or (
                    platform_login is not None and not platform_login.allows_consent_origin(request)
                ):
                    raise AuthorizationError("invalid_request")
                params = await _form(request)
                if set(params) != {"provider", "csrf_token"}:
                    raise AuthorizationError("invalid_request")
                try:
                    target = service_connections.start(person, params["provider"], params["csrf_token"])
                except Exception:
                    return JSONResponse({"error": "service_connection_start_unavailable"}, status_code=503)
                return RedirectResponse(target, status_code=303)
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
                draft_fields, offices = "", []
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
                if platform_login is not None and request.headers.getlist("accept") == [
                    "application/json"
                ]:
                    return JSONResponse(
                        {
                            "schema_version": "agent-consent/v1",
                            "request_id": pending["request_id"],
                            "csrf_token": pending["csrf_token"],
                            "client_name": pending["client_name"],
                            "capabilities": [
                                {"id": cap, "label": CAPABILITY_LABELS[cap]}
                                for cap in pending["capabilities"]
                            ],
                            "draft_companies": offices,
                            "expires_at": pending["expires_at"],
                        }
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
                    '<button name="decision" value="deny" formnovalidate>許可しない</button>'
                    '<button name="decision" value="revoke" formnovalidate>'
                    "既存の利用許可も解除する</button></form></html>"
                )
            params = await _form(request)
            if path == "/oauth/consent":
                if (platform_login is None and request.headers.getlist("origin") != [origin]) or (
                    platform_login is not None and not platform_login.allows_consent_origin(request)
                ):
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
            ("/connections", ["GET"]),
            ("/connections/start", ["POST"]),
            ("/connections/callback", ["GET"]),
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
    return _PrivateHTTPS(
        Starlette(routes=routes, lifespan=lifespan), origin,
        connection_form_origins=sorted({
            provider_origin
            for provider in service_connections.providers.values()
            for provider_origin in provider.authorization_origins
        }) if service_connections is not None else (),
    )
