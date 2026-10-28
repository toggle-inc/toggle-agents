"""Multi-person HTTP MCP boundary for a privately configured trusted OAuth host.

This resource adapter does NOT issue tokens, authenticate SSO, or implement an
OAuth authorization server. Supply a RequesterDispatcher whose authenticate
callback verifies the resource-specific per-person Bearer token on EVERY call.
Never pass the legacy owner key or a tenant-wide Engine execution JWT here.
"""

import functools
import inspect
from contextvars import ContextVar

from mcp.server.transport_security import TransportSecuritySettings
from mcp_server import create_server
from runtime.requester import RequesterDispatcher
from runtime.service import ExpenseService
from runtime.state import ExpenseError


class RequestAuthorization:
    """Pure ASGI middleware, with an isolated context for each HTTP request."""

    def __init__(self, app, dispatcher, context):
        self.app, self.dispatcher, self.context = app, dispatcher, context

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            await send({"type": "websocket.close", "code": 1008})
            return
        values = [v for k, v in scope.get("headers", ()) if k.lower() == b"authorization"]
        try:
            if len(values) != 1 or not values[0].startswith(b"Bearer "):
                raise ExpenseError("Missing personal authorization")
            credential = values[0][7:]
            if not 1 <= len(credential) <= 8192 or any(c <= 32 or c >= 127 for c in credential):
                raise ExpenseError("Invalid personal authorization")
            token = credential.decode("ascii")
            self.dispatcher.validate_request(token)
        except ExpenseError:
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"text/plain"),
                        (b"cache-control", b"no-store"),
                        (b"www-authenticate", b'Bearer realm="expense-assistant"'),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b"Unauthorized"})
            return
        handle = self.context.set(token)

        async def private_send(message):
            if message["type"] == "http.response.start":
                message = {
                    **message,
                    "headers": [
                        (key, value)
                        for key, value in message.get("headers", [])
                        if key.lower() != b"cache-control"
                    ]
                    + [(b"cache-control", b"no-store")],
                }
            await send(message)

        try:
            return await self.app(scope, receive, private_send)
        finally:
            self.context.reset(handle)


class _RequestService:
    """Keep canonical tool schemas; choose no service until a verified call."""

    def __init__(self, dispatcher, context):
        self.dispatcher, self.context = dispatcher, context

    def call(self, operation, arguments):
        return self.dispatcher.call(self._context(), operation, arguments)

    def read_receipt(self, reference):
        return self.dispatcher.read_receipt(self._context(), reference)

    def _context(self):
        token = self.context.get()
        if token is None:
            raise ExpenseError("認証済みのHTTPリクエストが必要です。")
        return token

    def __getattr__(self, operation):
        method = getattr(ExpenseService, operation)

        @functools.wraps(method)
        def invoke(**arguments):
            return self.call(operation, arguments)

        signature = inspect.signature(method)
        invoke.__signature__ = signature.replace(parameters=list(signature.parameters.values())[1:])
        return invoke


def create_app(dispatcher, public_host):
    """Configure the existing Engine external-OAuth MCP endpoint as this /mcp.

    The external OAuth issuer/consent UI is a separate prerequisite, not created
    by this function. All tools AND receipt resources use the same boundary.
    No disk credentials, live connections, or token issuers are supplied here.
    """
    if not isinstance(dispatcher, RequesterDispatcher):
        raise ExpenseError("本人別の認証・接続ディスパッチが必要です。")
    if (
        not isinstance(public_host, str)
        or not public_host
        or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in public_host)
        or public_host.startswith((".", "-"))
        or public_host.endswith((".", "-"))
    ):
        raise ExpenseError("HTTPS接続窓口の正確なホスト名を指定してください。")
    context = ContextVar("expense_authenticated_bearer", default=None)
    service = _RequestService(dispatcher, context)
    server = create_server(service, receipt_reader=service.read_receipt)
    transport = server.streamable_http_app(
        stateless_http=True,
        json_response=True,
        max_request_body_size=262144,
        transport_security=TransportSecuritySettings(
            allowed_hosts=[public_host], allowed_origins=["https://" + public_host]
        ),
    )
    return RequestAuthorization(transport, dispatcher, context)
