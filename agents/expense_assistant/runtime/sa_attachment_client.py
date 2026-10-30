"""Explicit C-proof SA attachment reader. No shared token, URL fetch or wiring.

resolve_binding() is trusted composition: it must read the request-local
HistoryRequestBinding set AFTER ExternalHistoryResolver succeeds, never tool
JSON. Its SABoundInvocation supplies the snapshot-verified original anchor ID.
The explicit owner is the canonical Requester.owner, not the source actor ID.
The caller transfers lifecycle ownership of an injected HTTP client.
"""

import hashlib
import json
import math
import re
import time
import uuid
from urllib.parse import quote

import httpx
import jwt

from _foundation.execution_binding import ExecutionTarget, VerifiedSourceCall
from _foundation.platform_identity import _origin
from .external_history_resolver import history_execution_id
from .history_request import HistoryRequestBinding
from .providers import MAX_FILE
from .requester import Requester
from .sa_history_client import SABoundInvocation, validate_source_read_key
from .state import ExpenseError

MANIFEST_PATH = "/api/integrations/agentize/chat/source-attachment-manifest"
ATTACHMENT_PATH = "/api/integrations/agentize/chat/source-attachment"
TYPES = frozenset({"application/pdf", "image/png", "image/jpeg", "image/heic"})
MANIFEST_LIMIT = 1024 * 1024
SOURCE_READ_TIMEOUT = 30


class _ManifestFailure(ValueError):
    """Fixed diagnostic phase only; never carry remote text or credentials."""
    def __init__(self, phase):
        self.phase = phase


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _id(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,256}", value) is not None


def _label(value, limit=256):
    return (isinstance(value, str) and 0 < len(value) <= limit and value == value.strip()
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _numeric(value):
    return (isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,15}", value) is not None
            and int(value) <= 2**53 - 1)


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _header(headers, name):
    values = headers.get_list(name)
    if len(values) != 1:
        raise ValueError
    return values[0]


class SAAttachmentClient:
    def __init__(self, *, origin, agent_origin, source_namespace, source_actor, target,
                 kid, signing_private_key, owner, resolve_binding,
                 agent_slug="expense_assistant", http=None, clock=time.time):
        try:
            self.origin, self.agent_origin = _origin(origin), _origin(agent_origin)
            if (not _label(source_namespace, 128) or not _label(source_actor)
                    or not _id(kid) or len(kid) > 128 or not _id(agent_slug)
                    or not isinstance(target, ExecutionTarget) or not all(_numeric(v) for v in (
                        target.tenant_id, target.agent_id, target.version_id, target.connection_id))
                    or not isinstance(owner, str) or re.fullmatch(r"requester-v1:[a-f0-9]{64}", owner) is None
                    or not callable(resolve_binding) or not callable(clock)):
                raise ValueError
            key = validate_source_read_key(signing_private_key)
        except Exception:
            raise ValueError("Explicit dedicated SA attachment configuration required") from None
        self.namespace, self.actor, self.target, self.kid = source_namespace, source_actor, target, kid
        self.owner, self._resolve, self.agent_slug = owner, resolve_binding, agent_slug
        self.clock, self._key, self._closed = clock, key, False
        self._http = http if http is not None else httpx.Client(
            timeout=SOURCE_READ_TIMEOUT, follow_redirects=False, trust_env=False)

    def close(self):
        if not self._closed:
            self._closed = True
            self._key = None
            self._http.close()

    def _current(self, expected=None):
        if self._closed:
            raise ValueError
        binding = self._resolve()
        if not isinstance(binding, HistoryRequestBinding) or not isinstance(binding.invocation, SABoundInvocation):
            raise ValueError
        inv, now = binding.invocation, self.clock()
        ref = inv.reference
        if (not isinstance(ref, VerifiedSourceCall) or not _finite(now)
                or not _label(binding.tenant_id) or not _label(binding.person_id)
                or Requester(binding.tenant_id, binding.person_id, inv.expires_at).owner != self.owner
                or (ref.source_issuer, ref.source_namespace, ref.source_actor, ref.target)
                    != (self.origin, self.namespace, self.actor, self.target)
                or not isinstance(ref.source_handle, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", ref.source_handle) is None
                or not _label(ref.invocation_id) or not _numeric(ref.session_id)
                or not isinstance(ref.anchor_revision, str) or re.fullmatch(r"[a-f0-9]{64}", ref.anchor_revision) is None
                or not isinstance(ref.source_grant_sha256, str) or re.fullmatch(r"[a-f0-9]{64}", ref.source_grant_sha256) is None
                or not _finite(inv.expires_at) or not _finite(ref.expires_at)
                or not now < inv.expires_at <= ref.expires_at
                or (inv.tenant, inv.requester, inv.agent, inv.platform, inv.execution)
                    != (self.namespace, self.actor, self.agent_slug, "success_assist",
                        history_execution_id(ref.session_id, ref.invocation_id))
                or not _id(inv.anchor) or not _id(inv.conversation)
                or inv.client_binding is None
                or expected is not None and (binding != expected
                    or ref is not expected.invocation.reference
                    or inv.client_binding is not expected.invocation.client_binding)):
            raise ValueError
        return binding

    def _request(self, binding, path, purpose, attachment_id=None):
        self._current(binding)
        # Even an injected client must not attach shared credentials or cookies
        # from another integration. C proof is the only outbound credential.
        if (self._http.auth is not None or self._http.cookies
                or any(name.lower() in {"authorization", "cookie", "proxy-authorization"}
                       for name in self._http.headers)):
            raise ValueError
        ref, now = binding.invocation.reference, self.clock()
        issued = math.floor(now)
        expires = min(issued + 60, math.floor(ref.expires_at), math.floor(binding.invocation.expires_at))
        if expires <= now:
            raise ValueError
        body = {"source_handle": ref.source_handle, "invocation_id": ref.invocation_id,
                "session_id": ref.session_id}
        if attachment_id is not None:
            body["attachment_id"] = attachment_id
        payload, target = _json(body), self.origin + path
        claims = {"iss": self.agent_origin, "aud": self.origin, "iat": issued, "exp": expires,
                  "jti": uuid.uuid4().hex, "purpose": purpose,
                  "source_namespace": self.namespace, "source_actor": self.actor, "source_actor_type": "human",
                  "target_tenant_id": self.target.tenant_id, "target_agent_id": self.target.agent_id,
                  "target_version_id": self.target.version_id, "connection_id": self.target.connection_id,
                  "invocation_id": ref.invocation_id, "session_id": ref.session_id,
                  "source_handle_sha256": _sha(ref.source_handle.encode("ascii")),
                  "method": "POST", "target": target, "body_sha256": _sha(payload)}
        proof = jwt.encode(claims, self._key, algorithm="RS256", headers={
            "kid": self.kid, "typ": "agent-source-read+jwt"})
        self._current(binding)
        if self.clock() >= expires:
            raise ValueError
        return self._http.stream("POST", target, content=payload, headers={
            "X-Agent-Source-Read-Proof": proof, "Content-Type": "application/json",
            "Accept": "application/json" if attachment_id is None else "application/octet-stream",
            "Accept-Encoding": "identity",
        }, follow_redirects=False, timeout=SOURCE_READ_TIMEOUT), expires

    @staticmethod
    def _response(response, content_type):
        if response.status_code != 200 or _header(response.headers, "content-type") != content_type:
            raise ValueError
        encodings = response.headers.get_list("content-encoding")
        if encodings and (len(encodings) != 1 or encodings[0].strip().lower() != "identity"):
            raise ValueError
        cache = _header(response.headers, "cache-control").lower().split(",")
        if "no-store" not in {v.strip() for v in cache}:
            raise ValueError

    def _manifest(self, binding):
        try:
            return self._manifest_response(binding)
        except httpx.TimeoutException:
            raise _ManifestFailure("response_timeout") from None
        except _ManifestFailure:
            raise
        except Exception:
            raise _ManifestFailure("response_validation") from None

    def _manifest_response(self, binding):
        stream, expires = self._request(binding, MANIFEST_PATH, "source_attachment_manifest")
        with stream as response:
            try:
                self._response(response, "application/json")
            except Exception:
                raise _ManifestFailure("response_headers") from None
            content = bytearray()
            for chunk in response.iter_bytes():
                if len(chunk) > MANIFEST_LIMIT - len(content):
                    raise ValueError
                content.extend(chunk)
        data = json.loads(content, object_pairs_hook=_unique)
        if (not isinstance(data, dict) or set(data) != {
                "schemaVersion", "invocationId", "sourceMessageId", "attachments", "manifestSha256", "expiresAt"}
                or data["schemaVersion"] != "source-attachment-manifest/v1"
                or data["invocationId"] != binding.invocation.reference.invocation_id
                or data["sourceMessageId"] != binding.invocation.anchor
                or type(data["expiresAt"]) is not int
                or not self.clock() * 1000 < data["expiresAt"] <= expires * 1000
                or not isinstance(data["attachments"], list) or len(data["attachments"]) > 100):
            raise _ManifestFailure("manifest_binding")
        canonical, ids = [], set()
        for item in data["attachments"]:
            if (not isinstance(item, dict) or set(item) != {"id", "filename", "contentType", "size"}
                    or not _id(item["id"]) or item["id"] in ids
                    or not isinstance(item["filename"], str) or not 0 < len(item["filename"].encode("utf-16-le")) // 2 <= 1024
                    or any(ord(c) < 32 or ord(c) == 127 for c in item["filename"])
                    or not _label(item["contentType"], 128)
                    or type(item["size"]) is not int or not 0 <= item["size"] <= 2**53 - 1):
                raise _ManifestFailure("manifest_items")
            ids.add(item["id"])
            # SA's strict schema constructs these fields in this order before
            # JS JSON.stringify; JSON response property order is not authority.
            canonical.append({k: item[k] for k in ("id", "filename", "contentType", "size")})
        if data["manifestSha256"] != _sha(_json(canonical)):
            raise _ManifestFailure("manifest_digest")
        self._current(binding)
        if self.clock() * 1000 >= data["expiresAt"]:
            raise ValueError
        return data

    def manifest(self):
        """Current source's exact manifest, never a caller-supplied source ID."""
        try:
            return self._manifest(self._current())
        except _ManifestFailure as error:
            raise ExpenseError("起点の添付一覧を安全に取得できません。（" + error.phase + "）") from None
        except Exception:
            raise ExpenseError("起点の添付一覧を安全に取得できません。") from None

    def get(self, reference):
        """Personal fetcher API: opaque attachment:<id> only; returns bytes/MIME."""
        return self._get(reference)

    def read_for_draft(self, attachment_id=""):
        """One verified manifest + binary. Never reuse a manifest across calls."""
        if not isinstance(attachment_id, str):
            raise ExpenseError("この依頼の添付IDを指定してください。")
        return self._get("attachment:" + attachment_id, draft=True)

    def _get(self, reference, *, draft=False):
        try:
            if not isinstance(reference, str) or not reference.startswith("attachment:"):
                raise ValueError
            attachment_id = reference[len("attachment:"):]
            if not _id(attachment_id) and not (draft and attachment_id == ""):
                raise ValueError
            binding = self._current()
            manifest = self._manifest(binding)
            if draft and attachment_id == "":
                if len(manifest["attachments"]) != 1:
                    raise ValueError
                attachment_id = manifest["attachments"][0]["id"]
            matches = [v for v in manifest["attachments"] if v["id"] == attachment_id]
            if len(matches) != 1:
                raise ValueError
            item = matches[0]
            if item["contentType"] not in TYPES or not 0 < item["size"] <= MAX_FILE:
                raise ValueError
            stream, expires = self._request(binding, ATTACHMENT_PATH, "source_attachment_read", attachment_id)
            with stream as response:
                self._response(response, "application/octet-stream")
                h = response.headers
                expected_hash = _header(h, "x-attachment-sha256")
                if (_header(h, "x-attachment-id") != attachment_id
                        or _header(h, "x-attachment-filename") != quote(item["filename"], safe="~()*!.'-_")
                        or _header(h, "x-attachment-content-type") != item["contentType"]
                        or _header(h, "content-length") != str(item["size"])
                        or re.fullmatch(r"[a-f0-9]{64}", expected_hash) is None):
                    raise ValueError
                content = bytearray()
                for chunk in response.iter_bytes():
                    if len(chunk) > min(MAX_FILE, item["size"]) - len(content):
                        raise ValueError
                    content.extend(chunk)
                if len(content) != item["size"] or _sha(content) != expected_hash:
                    raise ValueError
            self._current(binding)
            if self.clock() >= expires or self.clock() * 1000 >= manifest["expiresAt"]:
                raise ValueError
            result = (bytes(content), item["contentType"])
            return (*result, manifest) if draft else result
        except _ManifestFailure as error:
            raise ExpenseError("起点の添付を安全に取得できません。（" + error.phase + "）") from None
        except httpx.TimeoutException:
            raise ExpenseError("起点の添付を安全に取得できません。（binary_response_timeout）") from None
        except Exception:
            raise ExpenseError("起点の添付を安全に取得できません。") from None
