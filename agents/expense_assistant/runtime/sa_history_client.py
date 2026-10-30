"""Opt-in signed SA snapshot client; no env reads, runtime-proof reuse or bind API.

The dedicated source-read signing key is supplied explicitly by trusted deployment.
Only verified references enter resolve_source. An initial snapshot verifies an
already-bound session; it never binds or activates one. No transcript/global
latest-invocation cache is kept. Supplied HTTP clients transfer lifecycle ownership.
"""

import copy
import datetime as dt
import hashlib
import json
import math
import re
import time
import uuid
from dataclasses import dataclass, field

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from _foundation.conversation import ContextError, Invocation
from _foundation.execution_binding import ExecutionTarget, VerifiedSourceCall
from _foundation.history_sources import SuccessAssistHistory, bind_invocation
from _foundation.platform_identity import _origin
from .external_history_resolver import ResolvedHistorySource, history_execution_id

PATH = "/api/integrations/agentize/chat/source-snapshot"
RAW_FIELDS = {"id", "channelId", "rootId", "authorId", "botId", "guestAuthorId", "message",
              "createdAt", "editAt", "deleted"}
RESPONSE_FIELDS = {"schemaVersion", "invocationId", "scope", "source", "anchor", "root", "messages",
                   "nextBefore", "revision", "consistency", "expiresAt", "binding", "anchorRevision", "rootRevision"}
BINDING_FIELDS = {"sourceNamespace", "sourceActor", "sourceActorType", "tenantId", "managedAgentId",
                  "managedAgentVersionId", "connectionId", "harnessSessionId", "invocationId", "sourceHandleSha256"}


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _unique(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError
        result[k] = v
    return result


def _id(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) is not None


def _label(value, limit=256):
    return (isinstance(value, str) and 0 < len(value) <= limit and value == value.strip()
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _numeric(value):
    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,15}", value) is not None and int(value) <= 2**53 - 1


def _stamp(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError
    return dt.datetime.fromisoformat(value[:-1] + "+00:00")


def _raw(row):
    if (not isinstance(row, dict) or set(row) != RAW_FIELDS or not _id(row["id"])
            or not _id(row["channelId"]) or type(row["deleted"]) is not bool
            or row["rootId"] is not None and not _id(row["rootId"])
            or any(row[k] is not None and not _label(row[k]) for k in ("authorId", "botId", "guestAuthorId"))
            or not (isinstance(row["message"], str) or row["message"] is None)
            or row["deleted"] is True and row["message"] is not None):
        raise ValueError
    _stamp(row["createdAt"])
    if row["editAt"] is not None:
        _stamp(row["editAt"])
    return row


def _revision(row):
    return _sha(_json([row[k] for k in ("id", "channelId", "rootId", "authorId", "botId", "guestAuthorId",
                                         "message", "createdAt", "editAt", "deleted")]))


def validate_source_read_key(value):
    """Validate an explicitly supplied dedicated private key without HTTP creation."""
    try:
        key = serialization.load_pem_private_key(value.encode("ascii"), password=None)
        if not isinstance(key, RSAPrivateKey) or key.key_size < 2048:
            raise ValueError
        return key
    except Exception:
        raise ValueError("Dedicated RSA source-read signing key required") from None


@dataclass(frozen=True)
class SABoundInvocation(Invocation):
    reference: VerifiedSourceCall = field(kw_only=True, repr=False)
    anchor_created_at: str = field(kw_only=True, repr=False)
    client_binding: object = field(kw_only=True, repr=False, compare=False)


class _SnapshotTransport:
    def __init__(self, snapshot, invocation, *, anchor_only=False):
        self.snapshot, self.invocation, self.anchor_only = snapshot, invocation, anchor_only

    @staticmethod
    def _message(row):
        value = copy.deepcopy(row)
        if value["message"] is None and value["deleted"] is False:
            value["message"] = ""
        return value

    def get(self, invocation, path, query):
        if invocation != self.invocation:
            raise ContextError("scope_mismatch")
        snapshot = self.snapshot
        if path == "/api/chat/messages/" + invocation.anchor and query == {}:
            return self._message(snapshot["anchor"])
        expected_query = {"rootId": invocation.thread} if invocation.thread is not None else {"limit": 200}
        if path != "/api/chat/channels/" + invocation.conversation + "/messages" or query != expected_query:
            raise ContextError("access_denied")
        rows = [] if self.anchor_only else list(snapshot["messages"])
        excluded = {invocation.anchor}
        if invocation.thread is not None:
            excluded.add(invocation.thread)
        rows = [row for row in rows if row["id"] not in excluded]
        if invocation.anchor != invocation.thread:
            rows.append(snapshot["anchor"])
        result = {"messages": [self._message(row) for row in rows]}
        if invocation.thread is not None:
            result.update(root=self._message(snapshot["root"]), hasMoreOlder=snapshot["nextBefore"] is not None)
        else:
            result["nextBefore"] = copy.deepcopy(snapshot["nextBefore"])
        return result


class SAHistoryClient:
    def __init__(self, *, origin, agent_origin, source_namespace, source_actor, target,
                 kid, signing_private_key, agent_authors, agent_slug="expense_assistant",
                 http=None, clock=time.time):
        try:
            self.origin, self.agent_origin = _origin(origin), _origin(agent_origin)
            if (not _label(source_namespace, 128) or not _label(source_actor) or not _id(kid) or not _id(agent_slug)
                    or not isinstance(target, ExecutionTarget) or not all(_numeric(v) for v in (
                        target.tenant_id, target.agent_id, target.version_id, target.connection_id))
                    or not isinstance(agent_authors, tuple) or not agent_authors or not all(_label(v) for v in agent_authors)
                    or not callable(clock)):
                raise ValueError
            key = validate_source_read_key(signing_private_key)
        except Exception:
            raise ValueError("Explicit dedicated SA source-read configuration required") from None
        self.namespace, self.actor, self.target, self.kid = source_namespace, source_actor, target, kid
        self.agent_authors, self.agent_slug, self.clock = agent_authors, agent_slug, clock
        self._key, self._binding, self._closed = key, object(), False
        self._http = http if http is not None else httpx.Client(timeout=10, follow_redirects=False, trust_env=False)

    def close(self):
        if not self._closed:
            self._closed = True
            self._key = None
            self._http.close()

    def _reference(self, ref):
        now = self.clock()
        if (self._closed or not isinstance(ref, VerifiedSourceCall)
                or (ref.source_issuer, ref.source_namespace, ref.source_actor, ref.target)
                    != (self.origin, self.namespace, self.actor, self.target)
                or not isinstance(ref.source_handle, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", ref.source_handle) is None
                or not isinstance(ref.invocation_id, str) or not 1 <= len(ref.invocation_id) <= 256
                or not _numeric(ref.session_id) or type(now) not in (int, float) or not math.isfinite(now) or now < 0
                or type(ref.expires_at) not in (int, float) or not math.isfinite(ref.expires_at) or now >= ref.expires_at):
            raise ValueError
        return now

    def _snapshot(self, ref, scope, *, limit, before=None):
        now = self._reference(ref)
        issued, expires = math.floor(now), min(math.floor(now) + 60, math.floor(ref.expires_at))
        if expires <= now:
            raise ValueError
        body = {"source_handle": ref.source_handle, "invocation_id": ref.invocation_id,
                "session_id": ref.session_id, "scope": scope, "limit": limit}
        if before is not None:
            body["before"] = before
        payload = _json(body)
        target = self.origin + PATH
        claims = {"iss": self.agent_origin, "aud": self.origin, "iat": issued, "exp": expires,
                  "jti": uuid.uuid4().hex, "purpose": "source_snapshot_read",
                  "source_namespace": self.namespace, "source_actor": self.actor, "source_actor_type": "human",
                  "target_tenant_id": self.target.tenant_id, "target_agent_id": self.target.agent_id,
                  "target_version_id": self.target.version_id, "connection_id": self.target.connection_id,
                  "invocation_id": ref.invocation_id, "session_id": ref.session_id,
                  "source_handle_sha256": _sha(ref.source_handle.encode("ascii")),
                  "method": "POST", "target": target, "body_sha256": _sha(payload)}
        proof = jwt.encode(claims, self._key, algorithm="RS256", headers={"kid": self.kid, "typ": "agent-source-read+jwt"})
        with self._http.stream("POST", target, content=payload, headers={
            "X-Agent-Source-Read-Proof": proof, "Content-Type": "application/json", "Accept": "application/json",
            "Accept-Encoding": "identity",
        }, follow_redirects=False, timeout=10) as response:
            if response.status_code != 200 or response.headers.get("content-type", "").split(";", 1)[0] != "application/json":
                raise ValueError
            # httpx decodes content before yielding iter_bytes chunks. Reject
            # compression before touching the stream so the byte limit cannot
            # be bypassed by a decompression allocation.
            encodings = response.headers.get_list("content-encoding")
            if encodings and (len(encodings) != 1 or encodings[0].strip().lower() != "identity"):
                raise ValueError
            chunks, total = [], 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > 2 * 1024 * 1024:
                    raise ValueError
                chunks.append(chunk)
        data = json.loads(b"".join(chunks), object_pairs_hook=_unique)
        self._validate_snapshot(data, ref, scope, limit, expires)
        self._reference(ref)
        return data

    def _validate_snapshot(self, data, ref, scope, limit, proof_expires):
        if (not isinstance(data, dict) or set(data) != RESPONSE_FIELDS
                or data["schemaVersion"] != "source-snapshot-internal/v1" or data["scope"] != scope
                or data["invocationId"] != ref.invocation_id or data["consistency"] != "content_readback"
                or not isinstance(data["binding"], dict) or set(data["binding"]) != BINDING_FIELDS):
            raise ValueError
        expected = dict(zip(("sourceNamespace", "sourceActor", "sourceActorType", "tenantId", "managedAgentId",
                             "managedAgentVersionId", "connectionId", "harnessSessionId", "invocationId", "sourceHandleSha256"),
                            (self.namespace, self.actor, "human", self.target.tenant_id, self.target.agent_id,
                             self.target.version_id, self.target.connection_id, ref.session_id, ref.invocation_id,
                             _sha(ref.source_handle.encode("ascii")))))
        if data["binding"] != expected:
            raise ValueError
        source, anchor, root = data["source"], _raw(data["anchor"]), _raw(data["root"])
        if (not isinstance(source, dict) or set(source) != {"channelId", "sourceMessageId", "rootMessageId"}
                or not all(_id(v) for v in source.values())
                or (anchor["id"], root["id"], anchor["channelId"], root["channelId"])
                    != (source["sourceMessageId"], source["rootMessageId"], source["channelId"], source["channelId"])
                or (anchor["rootId"] or anchor["id"]) != root["id"] or root["rootId"] is not None
                or anchor["authorId"] != self.actor or anchor["botId"] is not None or anchor["guestAuthorId"] is not None
                or anchor["deleted"] or root["deleted"]
                or data["anchorRevision"] != ref.anchor_revision or _revision(anchor) != ref.anchor_revision
                or _revision(root) != data["rootRevision"]
                or not isinstance(data["revision"], str) or re.fullmatch(r"[a-f0-9]{64}", data["revision"]) is None
                or type(data["expiresAt"]) is not int
                or not self.clock() * 1000 < data["expiresAt"] <= min(ref.expires_at, proof_expires) * 1000
                or not isinstance(data["messages"], list) or len(data["messages"]) > limit):
            raise ValueError
        ids = set()
        for row in data["messages"]:
            _raw(row)
            if (row["id"] in ids or row["channelId"] != source["channelId"]
                    or scope == "thread" and (row["rootId"] or row["id"]) != root["id"]):
                raise ValueError
            ids.add(row["id"])
        cursor = data["nextBefore"]
        if cursor is not None:
            if not isinstance(cursor, dict) or set(cursor) != {"id", "createdAt"} or not _id(cursor["id"]):
                raise ValueError
            _stamp(cursor["createdAt"])

    def resolve_source(self, reference):
        try:
            snapshot = self._snapshot(reference, "thread", limit=1)
            src = snapshot["source"]
            thread = src["rootMessageId"] if src["rootMessageId"] != src["sourceMessageId"] else None
            event = dict(tenant=self.namespace, requester=self.actor, agent=self.agent_slug, platform="success_assist",
                         conversation=src["channelId"], thread=thread, anchor=src["sourceMessageId"],
                         execution=history_execution_id(reference.session_id, reference.invocation_id),
                         expires_at=min(reference.expires_at, snapshot["expiresAt"] / 1000))
            initial = Invocation(anchor_sequence=0, **event)
            source = SuccessAssistHistory(_SnapshotTransport(snapshot, initial, anchor_only=True), self.agent_authors)
            bound = bind_invocation(source, clock=self.clock, **event)
            invocation = SABoundInvocation(**bound.__dict__, reference=reference,
                anchor_created_at=snapshot["anchor"]["createdAt"], client_binding=self._binding)
            return ResolvedHistorySource(reference, invocation, snapshot["anchorRevision"])
        except Exception:
            raise ContextError("history_read_failed") from None

    def read(self, invocation):
        try:
            if (not isinstance(invocation, SABoundInvocation) or invocation.client_binding is not self._binding):
                raise ValueError
            ref = invocation.reference
            self._reference(ref)
            if ((invocation.tenant, invocation.requester, invocation.agent, invocation.platform, invocation.execution)
                    != (self.namespace, self.actor, self.agent_slug, "success_assist",
                        history_execution_id(ref.session_id, ref.invocation_id))
                    or invocation.expires_at > ref.expires_at or self.clock() >= invocation.expires_at):
                raise ValueError
            scope = "thread" if invocation.thread is not None else "conversation"
            snapshot = self._snapshot(ref, scope, limit=199,
                before={"id": invocation.anchor, "createdAt": invocation.anchor_created_at})
            src = snapshot["source"]
            if ((src["channelId"], src["sourceMessageId"], src["rootMessageId"], snapshot["anchor"]["createdAt"])
                    != (invocation.conversation, invocation.anchor, invocation.thread or invocation.anchor,
                        invocation.anchor_created_at)):
                raise ValueError
            return SuccessAssistHistory(_SnapshotTransport(snapshot, invocation), self.agent_authors).read(invocation)
        except Exception:
            raise ContextError("history_read_failed") from None
