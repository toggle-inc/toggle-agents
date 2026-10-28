"""Host-only SA attachment importer. No arbitrary URLs, cookies or MF writes."""

import hashlib
import re
from urllib.parse import quote, unquote

from .providers import MAX_FILE
from .sa_approval import SAApprovalAdapter
from .state import ExpenseError, digest

SA_MAX_FILE = 25 * 1024 * 1024
TYPES = {"application/pdf", "image/png", "image/jpeg", "image/heic"}


class SAAttachmentAdapter(SAApprovalAdapter):
    """Use only a host-verified frozen manifest from the same saved invocation.

    Inherits host scope and private service-credential verification. Manifest is
    never accepted from model args, URLs, display text or a different message.
    The source transport supports 25MiB; the expense runtime's existing 10MiB
    limit remains authoritative. This importer does not enlarge that capability.
    """

    def __init__(self, *args, manifest, **kwargs):
        super().__init__(*args, **kwargs)
        if not isinstance(manifest, (list, tuple)) or len(manifest) > 100:
            raise ExpenseError("起点の確定した添付一覧が必要です。")
        self._manifest = {}
        for item in manifest:
            if (
                not isinstance(item, dict)
                or set(item) != {"id", "filename", "contentType", "size"}
                or not isinstance(item["id"], str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", item["id"])
                or item["id"] in self._manifest
                or not isinstance(item["filename"], str)
                or not 1 <= len(item["filename"]) <= 512
                or any(ord(c) < 32 for c in item["filename"])
                or not isinstance(item["contentType"], str)
                or type(item["size"]) is not int
                or not 0 < item["size"] <= SA_MAX_FILE
            ):
                raise ExpenseError("添付一覧の形式・サイズ・重複を確認してください。")
            self._manifest[item["id"]] = dict(item)

    def fetch(self, attachment_id):
        self._check()
        if not isinstance(attachment_id, str) or attachment_id not in self._manifest:
            raise ExpenseError("今回の起点投稿の添付だけを取得できます。")
        item = self._manifest[attachment_id]
        if item["contentType"] not in TYPES or item["size"] > MAX_FILE:
            raise ExpenseError("経費領収書は対応形式かつ10MiB以下で送ってください。")
        receipts = self.service._require(self.service.receipts, "領収書")
        if receipts.owner != self.service.state.owner:
            raise ExpenseError("領収書の保存先の本人が一致しません。")
        try:
            token = self._credential("read")
            if (
                not isinstance(token, str)
                or not token
                or len(token) > 8192
                or any(ord(c) <= 32 or ord(c) >= 127 for c in token)
            ):
                raise ValueError("invalid credential")
            headers = {
                "Authorization": "Bearer " + token,
                "X-Agentize-Tenant-Id": str(self.scope["tenantId"]),
                "X-Agentize-Managed-Agent-Id": str(self.scope["managedAgentId"]),
                "X-Agentize-Harness-Session-Id": str(self.scope["harnessSessionId"]),
            }
            path = (
                "/api/integrations/agentize/chat/managed-invocations/"
                + quote(self.scope["invocationId"], safe="")
                + "/attachments/"
                + quote(attachment_id, safe="")
            )
            with self.http.stream(
                "GET", self.origin + path, headers=headers, follow_redirects=False
            ) as response:
                h = response.headers
                expected_hash = h.get("x-attachment-sha256", "")
                if (
                    response.status_code != 200
                    or h.get("content-type", "").split(";", 1)[0] != "application/octet-stream"
                    or h.get("x-attachment-id") != attachment_id
                    or unquote(h.get("x-attachment-filename", ""), errors="strict")
                    != item["filename"]
                    or h.get("x-attachment-content-type") != item["contentType"]
                    or h.get("content-length") != str(item["size"])
                    or not re.fullmatch(r"[a-f0-9]{64}", expected_hash)
                ):
                    raise ValueError("attachment metadata mismatch")
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > min(MAX_FILE, item["size"]):
                        raise ValueError("attachment too large")
                if (
                    len(content) != item["size"]
                    or hashlib.sha256(content).hexdigest() != expected_hash
                ):
                    raise ValueError("attachment content mismatch")
            self._check()
            with self.service._lock:
                self._check()
                result = receipts.save(bytes(content), item["contentType"])
                self.service.state.bind_source_receipt(
                    self.origin,
                    digest(self.scope),
                    result["path"],
                    {**item, "sha256": expected_hash},
                )
            return {**result, "source_attachment_id": attachment_id, "sha256": expected_hash}
        except Exception:
            raise ExpenseError(
                "起点の領収書を安全に取得できません。保存先や秘密は表示しません。"
            ) from None
