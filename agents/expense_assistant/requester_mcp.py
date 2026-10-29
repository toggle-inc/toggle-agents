"""Multi-person HTTP MCP boundary for a privately configured trusted OAuth host.

This resource adapter does NOT issue tokens, authenticate SSO, or implement an
OAuth authorization server. Supply a RequesterDispatcher whose authenticate
callback verifies the resource-specific per-person Bearer token on EVERY call.
Never pass the legacy owner key or a tenant-wide Engine execution JWT here.
"""

import asyncio
import functools
import hashlib
import inspect
from contextlib import ExitStack
from contextvars import ContextVar

from mcp.server.transport_security import TransportSecuritySettings
from mcp_server import create_server
from runtime.requester import RequesterDispatcher
from runtime.service import ExpenseService
from runtime.state import ExpenseError


class RequestAuthorization:
    """Pure ASGI middleware, with an isolated context for each HTTP request."""

    def __init__(self, app, dispatcher, context, *, history_runtime=None, history_resolver=None,
                 history_target=None):
        self.app, self.dispatcher, self.context = app, dispatcher, context
        self.history_runtime, self.history_resolver = history_runtime, history_resolver
        self.history_target = history_target
        if history_runtime is not None and history_target is None:
            raise ExpenseError("A fixed history resource target is required")

    async def _history_request(self, scope, receive):
        """Bind exact bytes before the trusted verifier; never log the body."""
        from _foundation.execution_binding import ExecutionRequest

        if (scope.get("method") not in {"GET", "POST", "DELETE"}
                or scope.get("path") != "/mcp" or scope.get("query_string", b"")
                or scope.get("raw_path", b"/mcp") != b"/mcp"):
            raise ExpenseError("Invalid history request")
        parts, size = [], 0
        async with asyncio.timeout(10):
            while True:
                event = await receive()
                if event.get("type") != "http.request" or not isinstance(event.get("body", b""), bytes):
                    raise ExpenseError("Invalid history request")
                body = event.get("body", b"")
                size += len(body)
                if size > 262144:
                    raise ExpenseError("Invalid history request")
                parts.append(body)
                if not event.get("more_body", False):
                    break
        data = b"".join(parts)
        received = False

        async def replay_receive():
            nonlocal received
            if not received:
                received = True
                return {"type": "http.request", "body": data, "more_body": False}
            return await receive()

        return {
            **scope,
            "agent_execution_request": ExecutionRequest(
                scope["method"], self.history_target, hashlib.sha256(data).hexdigest()
            ),
        }, replay_receive

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            await send({"type": "websocket.close", "code": 1008})
            return
        values = [v for k, v in scope.get("headers", ()) if k.lower() == b"authorization"]
        history_scope = ExitStack()
        try:
            if len(values) != 1 or not values[0].startswith(b"Bearer "):
                raise ExpenseError("Missing personal authorization")
            credential = values[0][7:]
            if not 1 <= len(credential) <= 8192 or any(c <= 32 or c >= 127 for c in credential):
                raise ExpenseError("Invalid personal authorization")
            token = credential.decode("ascii")
            person = self.dispatcher.validate_request(token)
            if self.history_runtime is not None:
                from runtime.history_request import HistoryRequestBinding
                try:
                    verified_scope, receive = await self._history_request(scope, receive)
                    binding = self.history_resolver(verified_scope, person)
                    if not isinstance(binding, HistoryRequestBinding) or not binding.matches(person):
                        raise ExpenseError("Invalid history binding")
                    history_scope.enter_context(self.history_runtime.bind(binding.invocation))
                except Exception:
                    raise ExpenseError("Invalid history binding") from None
        except ExpenseError:
            history_scope.close()
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
            history_scope.close()


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


def create_app(dispatcher, public_host, *, history_runtime=None, history_resolver=None):
    """Configure the existing Engine external-OAuth MCP endpoint as this /mcp.

    The external OAuth issuer/consent UI is a separate prerequisite, not created
    by this function. All tools AND receipt resources use the same boundary.
    No disk credentials, live connections, or token issuers are supplied here.
    History is opt-in, with an agent-owned runtime and trusted per-request
    resolver supplied together. No request header can turn this option on.
    """
    if not isinstance(dispatcher, RequesterDispatcher):
        raise ExpenseError("本人別の認証・接続ディスパッチが必要です。")
    if (history_runtime is None) != (history_resolver is None):
        raise ExpenseError("履歴には検証済みの実行情報と読取接続の両方が必要です。")
    if history_runtime is not None:
        from _foundation.history_runtime import ConversationRuntime
        if not isinstance(history_runtime, ConversationRuntime) or not callable(history_resolver):
            raise ExpenseError("履歴には信頼済みの接続アダプターが必要です。")
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
    server = create_server(
        service, receipt_reader=service.read_receipt,
        tool_catalog=lambda: dispatcher.available_operations(service._context()),
        receipt_resources=dispatcher.receipt_resources,
        conversation_reader=history_runtime,
    )
    transport = server.streamable_http_app(
        stateless_http=True,
        json_response=True,
        max_request_body_size=262144,
        transport_security=TransportSecuritySettings(
            allowed_hosts=[public_host], allowed_origins=["https://" + public_host]
        ),
    )
    return RequestAuthorization(
        transport, dispatcher, context,
        history_runtime=history_runtime, history_resolver=history_resolver,
        history_target="https://" + public_host + "/mcp" if history_runtime is not None else None,
    )
