#!/usr/bin/env python3
"""Owner-scoped Engine MCP adapter. Private credentials and state remain on its host."""

import argparse
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from mcp.server.transport_security import TransportSecuritySettings
from mcp_server import create_server
from runtime.connection import connect
from runtime.state import ExpenseError

MAX_KEY_HOURS = 48


def read_key(path, owner, *, clock=time.time):
    path = Path(path)
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise ExpenseError("専用接続キーのアクセス権を確認してください。")
    data = json.loads(path.read_text())
    if (
        data.get("owner") != owner
        or data.get("tenant_id") != 10
        or not isinstance(data.get("token"), str)
        or len(data["token"]) < 40
        or type(data.get("expires_at")) not in (int, float)
        or not clock() < data["expires_at"] <= clock() + MAX_KEY_HOURS * 3600
    ):
        raise ExpenseError("専用接続キーの本人・テナント・期限を確認してください。")
    return data


def issue_key(path, owner, *, hours=24, clock=time.time):
    if type(hours) is not int or not 1 <= hours <= MAX_KEY_HOURS:
        raise ExpenseError("接続キーの期限は1〜48時間にしてください。")
    path = Path(path).expanduser().absolute()
    if path.is_relative_to(Path(__file__).resolve().parent):
        raise ExpenseError("接続キーは公開フォルダの外に保存してください。")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = {
        "owner": owner,
        "tenant_id": 10,
        "token": secrets.token_urlsafe(48),
        "expires_at": clock() + hours * 3600,
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(data, stream)
    return {key: value for key, value in data.items() if key != "token"}


class OwnerAuthorization:
    """Reject every unauthenticated HTTP request before MCP handles any data.

    This is one person's connection capability, not a multi-user identity service.
    Only a trusted Engine administrator may bind it to that person's test agent.
    Per-financial-operation approval remains separate and is never an MCP tool.
    """

    def __init__(self, app, key_file, owner):
        self.app, self.key_file, self.owner = app, key_file, owner

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            await send({"type": "websocket.close", "code": 1008})
            return
        values = [v for k, v in scope.get("headers", []) if k.lower() == b"authorization"]
        valid = False
        try:
            key = read_key(self.key_file, self.owner)
            valid = len(values) == 1 and hmac.compare_digest(
                values[0], ("Bearer " + key["token"]).encode("ascii")
            )
        except (ExpenseError, OSError, ValueError, KeyError, TypeError):
            pass
        if not valid:
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"content-type", b"text/plain"), (b"cache-control", b"no-store")],
                }
            )
            await send({"type": "http.response.body", "body": b"Unauthorized"})
            return
        return await self.app(scope, receive, send)


def create_app(service, key_file, public_host):
    # Exact hosts only; never disable SDK DNS-rebinding protection for a tunnel.
    if not public_host or any(c in public_host for c in "/:@*?#"):
        raise ExpenseError("HTTPS接続窓口の正確なホスト名を指定してください。")
    read_key(key_file, service.state.owner)
    server = create_server(service)
    transport = server.streamable_http_app(
        stateless_http=True,
        json_response=True,
        max_request_body_size=262144,
        transport_security=TransportSecuritySettings(
            allowed_hosts=[public_host, "127.0.0.1:*", "localhost:*"],
            allowed_origins=["https://" + public_host],
        ),
    )
    return OwnerAuthorization(transport, key_file, service.state.owner)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("issue-key", "serve"))
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--public-host")
    parser.add_argument("--port", type=int, default=8767)
    parser.add_argument("--hours", type=int, default=24, help="Key lifetime, 1–48 hours")
    parser.add_argument("--read-only", action="store_true", help="Disable MF financial writes")
    args = parser.parse_args()
    service = None
    try:
        service = connect(args.profile)
        if args.command == "issue-key":
            issue_key(args.key_file, service.state.owner, hours=args.hours)
            print(
                f"Private tenant-10 key created; expires within {args.hours} hours. Value not printed."
            )
            return
        if args.read_only:
            service.write_enabled = False
        app = create_app(service, args.key_file, args.public_host)
        import uvicorn

        # A separately managed HTTPS ingress is required. Never bind all interfaces.
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=args.port,
            access_log=False,
            proxy_headers=False,
            log_level="warning",
        )
    except (ExpenseError, OSError, ValueError, KeyError):
        parser.exit(
            2, "本人専用の接続・キー・HTTPSホスト設定を確認してください。秘密は表示しません。\n"
        )
    finally:
        if service is not None:
            service.state.close()
            service.mf.http.close()


if __name__ == "__main__":
    main()
