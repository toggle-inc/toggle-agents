"""Trusted SA approval adapter, not an agent-callable approval or identity tool.

The host supplies authenticated invocation scope AND a fresh verifier mapping it
to this service's human owner. Service credentials stay in the host. This module
neither authenticates users from prompt fields nor performs financial writes.
"""

import base64
import datetime as dt
import hashlib
import json
import re
import time
from urllib.parse import quote, urlsplit

from .presentation import build_presentation
from .state import ExpenseError, digest

SCOPE_KEYS = {
    "invocationId",
    "requesterEmployeeId",
    "runId",
    "harnessSessionId",
    "managedAgentVersionId",
    "tenantId",
    "managedAgentId",
    "sourceMessageId",
    "rootMessageId",
    "sourceChannelId",
}
OPERATIONS = {
    "create": "mf_create_transaction",
    "update": "mf_update_transaction",
    "upload": "mf_upload_receipt",
    "delete": "mf_delete_transaction",
}


def _json(value):
    # SA displays these exact bytes without reparsing. Indentation is owned by
    # the agent so neither numbers nor hidden business fields are reformatted
    # by a chat platform. This is not a new approval of an existing proposal.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)


def _visible(value):
    """Keep all business fields, replacing receipt bytes with their exact identity."""
    if isinstance(value, dict):
        if {"content", "content_type", "filename"}.issubset(value):
            try:
                content = base64.b64decode(value["content"], validate=True)
            except (ValueError, TypeError) as error:
                raise ExpenseError("領収書の確認内容が不正です。") from error
            return {
                **{k: _visible(v) for k, v in value.items() if k != "content"},
                "content_sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
            }
        return {key: _visible(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_visible(item) for item in value]
    return value


class SAApprovalAdapter:
    """Host-only API. Never register these methods with MCP/LLM dispatch.

    verify_scope(scope, owner) must freshly verify the canonical human mapping,
    active run/source/version and current permission; a constant true callback
    or a scope copied from a model's text is NOT a usable real connection.
    credential('read'|'write') resolves host service credentials, not MF tokens.
    """

    def __init__(
        self, service, origin, scope, *, verify_scope, credential, http=None, clock=time.time
    ):
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.port not in (None, 443)
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ExpenseError("固定のHTTPS接続先が必要です。")
        if not isinstance(scope, dict) or set(scope) != SCOPE_KEYS:
            raise ExpenseError("信頼済みの実行範囲が必要です。")
        for key, value in scope.items():
            if key == "invocationId":
                valid = isinstance(value, str) and re.fullmatch(
                    r"agentize-mention:[a-f0-9]{64}", value
                )
            elif key in {"tenantId", "managedAgentId", "managedAgentVersionId", "harnessSessionId"}:
                valid = type(value) is int and value > 0
            else:
                valid = isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value)
            if not valid:
                raise ExpenseError("実行範囲の形式を確認してください。")
        self.service, self.scope = service, dict(scope)
        self.origin, self.clock = origin.rstrip("/"), clock
        self._verify, self._credential = verify_scope, credential
        if http is None:
            import httpx

            http = httpx.Client(timeout=30, follow_redirects=False, trust_env=False)
        self.http = http

    def _check(self):
        try:
            valid = self._verify(dict(self.scope), self.service.state.owner)
        except Exception:
            valid = False
        if valid is not True:
            raise ExpenseError("本人・実行・起点・権限の有効性を確認できません。")

    def _request(self, method, body=None):
        self._check()
        try:
            token = self._credential("write" if method == "POST" else "read")
            if (
                not isinstance(token, str)
                or not token
                or len(token) > 8192
                or any(ord(c) <= 32 or ord(c) >= 127 for c in token)
            ):
                raise ValueError("invalid service credential")
            headers = {
                "Authorization": "Bearer " + token,
                "X-Agentize-Tenant-Id": str(self.scope["tenantId"]),
                "X-Agentize-Managed-Agent-Id": str(self.scope["managedAgentId"]),
                "X-Agentize-Harness-Session-Id": str(self.scope["harnessSessionId"]),
            }
            path = (
                "/api/integrations/agentize/chat/managed-invocations/"
                + quote(self.scope["invocationId"], safe="")
                + "/approvals"
            )
            # Never follow redirects with a service credential or consume unbounded JSON.
            with self.http.stream(
                method, self.origin + path, headers=headers, json=body, follow_redirects=False
            ) as response:
                if response.status_code != 200:
                    raise ValueError("request unavailable")
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > 16 * 1024 * 1024:
                        raise ValueError("response too large")
                data = json.loads(content)
            self._check()
            if not isinstance(data, dict) or data.get("scope") != self.scope:
                raise ValueError("scope changed")
            return data
        except Exception:
            raise ExpenseError(
                "SAの本人確認記録を安全に取得できません。再送で承認を代用しません。"
            ) from None

    def _proposal(self, preview_id):
        self._check()
        details = self.service.state.preview_details(preview_id)
        if (
            details["status"] != "preview"
            or details["action"] not in OPERATIONS
            or not self.clock() < details["expires_at"] <= self.clock() + 3600
        ):
            raise ExpenseError("本人確認の対象・期限・状態を確認してください。")
        attachments = []
        reference = details["snapshot"].get("intent", {}).get("receipt_path")
        if reference:
            source = self.service.state.source_receipt(self.origin, digest(self.scope), reference)
            payload_receipt = details["snapshot"]["payload"]
            if details["action"] != "upload":
                payload_receipt = payload_receipt.get("receipt_input", {})
            visible = _visible(payload_receipt)
            if (
                source is None
                or source.get("sha256") != visible.get("content_sha256")
                or source.get("size") != visible.get("bytes")
                or source.get("contentType") != visible.get("content_type")
            ):
                raise ExpenseError("領収書と今回の起点添付の対応を確認できません。")
            attachments.append(source)
        visible_snapshot = _visible(details["snapshot"])
        payload = _json(
            {
                "protocol": "expense-human-preview/v1",
                "scope": self.scope,
                "action": details["action"],
                "office_id": details["office"],
                "snapshot": visible_snapshot,
                "preview_digest": details["preview_digest"],
                "source_attachments": attachments,
                "presentation": build_presentation(details, visible_snapshot, attachments),
            }
        )
        if len(payload.encode("utf-8")) > 128000:
            raise ExpenseError("本人確認内容が大きすぎます。内容を省略せず分割してください。")
        return {
            "previewId": preview_id,
            "previewDigest": details["preview_digest"],
            "expiresAt": dt.datetime.fromtimestamp(details["expires_at"], dt.timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "payload": payload,
        }, details

    def _approval(self, row, expected):
        if not isinstance(row, dict):
            raise ExpenseError("本人確認記録が不正です。")
        if any(row.get(key) != value for key, value in expected.items()):
            raise ExpenseError("確認した内容・ダイジェスト・期限と一致しません。")
        if (
            row.get("invocationId") != self.scope["invocationId"]
            or not isinstance(row.get("id"), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", row["id"])
            or row.get("contentDigest") != hashlib.sha256(expected["payload"].encode()).hexdigest()
        ):
            raise ExpenseError("本人確認の実行範囲・表示内容を確認できません。")
        return row

    def propose(self, preview_id):
        expected, _ = self._proposal(preview_id)
        data = self._request("POST", expected)
        row = self._approval(data.get("approval"), expected)
        path = "/chat/agent-approvals/" + row["id"]
        if data.get("approvalPath") != path:
            raise ExpenseError("本人確認画面の接続先を確認できません。")
        return {
            "approval_id": row["id"],
            "approval_url": self.origin + path,
            "preview_id": preview_id,
            "approved": False,
        }

    def execute_approved(self, preview_id, approval_id):
        """Fresh SA readback → verified human decision → local approval → exact intent.

        The host must serialize this with other actions on the same service.
        No arbitrary new args, actor ID, operation or destination are accepted.
        """
        with self.service._lock:
            expected, details = self._proposal(preview_id)
            data = self._request("GET")
            if data.get("protocol") != "success-assist-managed-approval/v1":
                raise ExpenseError("未対応の本人確認プロトコルです。")
            rows = data.get("approvals")
            if not isinstance(rows, list) or len(rows) > 100:
                raise ExpenseError("本人確認記録の一覧を確認できません。")
            matches = [
                row for row in rows if isinstance(row, dict) and row.get("id") == approval_id
            ]
            if len(matches) != 1:
                raise ExpenseError("今回の本人確認記録を一意に確認できません。")
            row = self._approval(matches[0], expected)
            try:
                instant = dt.datetime.fromisoformat(row["decidedAt"].replace("Z", "+00:00"))
                if instant.utcoffset() is None:
                    raise ValueError("missing timezone")
                decided = instant.timestamp()
                expiry = dt.datetime.fromisoformat(
                    expected["expiresAt"].replace("Z", "+00:00")
                ).timestamp()
            except (KeyError, TypeError, ValueError, AttributeError):
                raise ExpenseError("本人の承認時刻を確認できません。") from None
            if (
                row.get("decision") != "APPROVED"
                or row.get("decidedById") != self.scope["requesterEmployeeId"]
                or not 0 < decided <= self.clock() < expiry
            ):
                raise ExpenseError("本人の有効な明示承認がありません。")
            self._check()
            operation = OPERATIONS.get(details["action"])
            if not operation:
                raise ExpenseError("未対応の経費操作です。")
            self.service.state.approve_external(
                self.origin,
                row["id"],
                preview_id,
                expected["previewDigest"],
                {
                    "scope": self.scope,
                    "content_digest": row["contentDigest"],
                    "decided_by": row["decidedById"],
                    "decided_at": row["decidedAt"],
                },
            )
            try:
                return self.service.call(
                    operation,
                    {**details["snapshot"]["intent"], "confirm": True, "preview_id": preview_id},
                )
            finally:
                self.service.state.withdraw_unused_approval(preview_id)
