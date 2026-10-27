"""Agent-owned SA/Buzz readers. No Engine imports, listeners, or model IDs.

Credential providers and Invocation resolvers are trusted application code.
They must bind an authenticated event, not deserialize chat/model instructions.
Credentials stay outside Git and are selected again on every platform request.
"""

import datetime as dt
import hashlib
import json
import math
import re
import subprocess
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace

from .conversation import ContextError, ConversationReader, Invocation, Message, Snapshot

FETCH_LIMIT = 200
RESPONSE_LIMIT = 2 * 1024 * 1024


@dataclass(frozen=True)
class PersonalCredential:
    tenant: str
    requester: str
    audience: str
    secret: str = field(repr=False)
    expires_at: float


def _credential(provider, invocation, audience, clock):
    try:
        value = provider(invocation)
    except Exception:
        raise ContextError("access_denied") from None
    if (
        not isinstance(value, PersonalCredential)
        or (value.tenant, value.requester, value.audience)
        != (invocation.tenant, invocation.requester, audience)
        or type(value.expires_at) not in (int, float)
        or not math.isfinite(value.expires_at)
        or value.expires_at <= clock()
        or not isinstance(value.secret, str)
        or not value.secret
        or any(ord(c) <= 32 or ord(c) >= 127 for c in value.secret)
    ):
        raise ContextError("access_denied")
    return value


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
        raise ContextError("invalid_snapshot")
    return value


def _sequence(timestamp, identifier):
    """Stable platform order (time, id); do not renumber after deletions."""
    identifier = _identifier(identifier)
    if isinstance(timestamp, str):
        try:
            parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
            timestamp = parsed.timestamp()
        except ValueError:
            raise ContextError("invalid_snapshot") from None
    if type(timestamp) not in (int, float) or not math.isfinite(timestamp) or timestamp < 0:
        raise ContextError("invalid_snapshot")
    # Fixed-width ASCII encoding preserves lexicographic ID order, including prefixes.
    return int(timestamp * 1_000_000) * (1 << 1024) + int.from_bytes(
        identifier.encode().ljust(128, b"\0"), "big"
    )


@dataclass(frozen=True)
class Record:
    identifier: str
    sequence: int
    author: str
    role: str
    text: str


def _anchor(invocation, records):
    found = [row for row in records if row.identifier == invocation.anchor]
    if len(found) != 1 or found[0].author != invocation.requester or found[0].role != "user":
        raise ContextError("access_denied")
    return found[0]


def _revision(records, truncated):
    # Re-read current effective text, not a persistent cache or inferred memory.
    payload = [[r.identifier, r.sequence, r.author, r.role, r.text] for r in records]
    return hashlib.sha256(json.dumps([payload, truncated], ensure_ascii=False).encode()).hexdigest()


def _anchor_digest(record):
    return _revision([record], False)


class PlatformHistoryBackend:
    """Adapt live source readers to the shared history contract.

    These APIs have no transactional revision fence. The fence here is a fresh
    content readback plus current access check, NOT an atomic provider snapshot.
    """

    def __init__(self, source):
        self.source = source

    def authorize(self, invocation, revision):
        records, truncated = self.source.read(invocation)
        anchor = _anchor(invocation, records)
        if anchor.sequence != invocation.anchor_sequence:
            return False
        if invocation.anchor_digest != _anchor_digest(anchor):
            return False
        return revision is None or _revision(records, truncated) == revision

    def fetch(self, invocation, *, max_messages, max_characters):
        records, truncated = self.source.read(invocation)
        source_revision = _revision(records, truncated)
        if _anchor(invocation, records).sequence != invocation.anchor_sequence:
            raise ContextError("scope_mismatch")
        if invocation.anchor_digest != _anchor_digest(_anchor(invocation, records)):
            raise ContextError("stale_or_revoked")
        prior = [r for r in records if r.sequence < invocation.anchor_sequence]
        truncated = truncated or len(prior) > max_messages
        selected, remaining = [], max_characters
        for row in reversed(prior[-max_messages:]):
            if remaining == 0:
                truncated = True
                break
            text = row.text[:remaining]
            truncated = truncated or len(text) != len(row.text)
            remaining -= len(text)
            selected.append(
                Message(invocation.source, row.identifier, row.sequence, row.role, text)
            )
        return Snapshot(
            invocation,
            source_revision,
            tuple(reversed(selected)),
            truncated,
            consistency="content_readback",
        )


def bind_invocation(source, *, clock=time.time, **verified_event):
    """Trusted entrance only; validate the actor's anchor against the real API.

    verified_event is authenticated entrance data, NEVER model/tool arguments.
    The returned Invocation can be resolved per execution via ContextVar etc.
    """
    invocation = Invocation(anchor_sequence=0, **verified_event)
    ConversationReader(lambda: invocation, None, clock=clock)._validate(invocation)
    records, _ = source.read(invocation)
    anchor = _anchor(invocation, records)
    return replace(
        invocation, anchor_sequence=anchor.sequence, anchor_digest=_anchor_digest(anchor)
    )


def create_reader(source, resolve, *, clock=time.time):
    return ConversationReader(resolve, PlatformHistoryBackend(source), clock=clock)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ContextError("history_read_failed")


class SuccessAssistHTTP:
    """Only authenticated GETs to a fixed HTTPS origin, without redirects."""

    def __init__(self, origin, credentials, *, clock=time.time):
        parsed = urllib.parse.urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("A fixed HTTPS origin is required")
        self.origin = origin.rstrip("/")
        self.credentials, self.clock = credentials, clock

    def get(self, invocation, path, query):
        credential = _credential(self.credentials, invocation, self.origin, self.clock)
        anchor_path = f"/api/chat/messages/{_identifier(invocation.anchor)}"
        channel_path = f"/api/chat/channels/{_identifier(invocation.conversation)}/messages"
        expected_query = (
            {"rootId": _identifier(invocation.thread)}
            if invocation.thread is not None
            else {"limit": FETCH_LIMIT}
        )
        if invocation.platform != "success_assist" or (path, query) not in (
            (anchor_path, {}),
            (channel_path, expected_query),
        ):
            raise ContextError("access_denied")
        request = urllib.request.Request(
            self.origin + path + "?" + urllib.parse.urlencode(query),
            headers={"Authorization": "Bearer " + credential.secret, "Accept": "application/json"},
        )
        try:
            opener = urllib.request.build_opener(_NoRedirect())
            with opener.open(request, timeout=10) as response:
                if (
                    response.status != 200
                    or response.headers.get_content_type() != "application/json"
                ):
                    raise ContextError("history_read_failed")
                data = response.read(RESPONSE_LIMIT + 1)
            if len(data) > RESPONSE_LIMIT:
                raise ContextError("window_exceeded")
            result = json.loads(data)
            if not isinstance(result, dict):
                raise ContextError("invalid_snapshot")
            return result
        except ContextError:
            raise
        except Exception:
            raise ContextError("history_read_failed") from None


class SuccessAssistHistory:
    def __init__(self, transport, agent_authors=()):
        self.transport, self.agent_authors = transport, frozenset(agent_authors)

    def read(self, invocation):
        if invocation.platform != "success_assist":
            raise ContextError("scope_mismatch")
        channel, anchor = _identifier(invocation.conversation), _identifier(invocation.anchor)
        root = _identifier(invocation.thread) if invocation.thread is not None else None
        located = self.transport.get(invocation, f"/api/chat/messages/{anchor}", {})
        if (
            located.get("id") != anchor
            or located.get("channelId") != channel
            or located.get("deleted") is not False
            or (root is not None and (located.get("rootId") or anchor) != root)
            or (root is None and located.get("rootId") is not None)
        ):
            raise ContextError("access_denied")
        query = {"rootId": root} if root else {"limit": FETCH_LIMIT}
        page = self.transport.get(invocation, f"/api/chat/channels/{channel}/messages", query)
        rows = page.get("messages")
        if not isinstance(rows, list) or len(rows) > FETCH_LIMIT:
            raise ContextError("invalid_snapshot")
        if root:
            origin = page.get("root")
            if not isinstance(origin, dict) or origin.get("id") != root or origin.get("deleted"):
                raise ContextError("access_denied")
            rows = [origin, *rows]
        result, seen = [], set()
        for row in rows:
            if not isinstance(row, dict):
                raise ContextError("invalid_snapshot")
            if row.get("deleted") is True:
                continue
            identifier = _identifier(row.get("id"))
            if identifier in seen or row.get("channelId") != channel:
                raise ContextError("scope_mismatch")
            seen.add(identifier)
            if root is not None and (row.get("rootId") or identifier) != root:
                raise ContextError("scope_mismatch")
            if root is None and row.get("rootId") is not None:
                continue
            author = row.get("botId") or row.get("authorId") or row.get("guestAuthorId")
            if not isinstance(author, str) or not isinstance(row.get("message"), str):
                raise ContextError("invalid_snapshot")
            result.append(
                Record(
                    identifier,
                    _sequence(row.get("createdAt"), identifier),
                    author,
                    "assistant" if author in self.agent_authors else "user",
                    row["message"],
                )
            )
        _anchor(invocation, result)
        truncated = page.get("hasMoreOlder", False) if root else page.get("nextBefore") is not None
        if type(truncated) is not bool:
            raise ContextError("invalid_snapshot")
        return sorted(result, key=lambda row: row.sequence), truncated


class BuzzCLITransport:
    """Read-only commands through the installed, authenticated Buzz CLI.

    No shell, inherited credentials, membership mutation, or relay from model.
    Only a personal identity is supported; delegated identities need a separate
    verified delegation contract, not a shared agent-key fallback.
    """

    def __init__(self, binary, relay, credentials, *, clock=time.time, allow_local=False):
        parsed = urllib.parse.urlsplit(relay)
        local = allow_local and relay == "http://127.0.0.1:3000"
        if (
            not binary.startswith("/")
            or (parsed.scheme != "https" and not local)
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("An absolute CLI and fixed HTTPS relay are required")
        self.binary, self.relay = binary, relay.rstrip("/")
        self.credentials, self.clock = credentials, clock

    def get(self, invocation, operation):
        credential = _credential(self.credentials, invocation, self.relay, self.clock)
        if operation == "identity":
            arguments = ["users", "get"]
        elif operation == "messages":
            arguments = [
                "messages",
                "get",
                "--channel",
                invocation.conversation,
                "--limit",
                str(FETCH_LIMIT),
                "--kinds",
                "9,40002,40003,5,9005",
            ]
        else:
            raise ContextError("access_denied")
        try:
            result = subprocess.run(
                [self.binary, "--format", "json", *arguments],
                shell=False,
                env={
                    "PATH": "/usr/bin:/bin",
                    "BUZZ_RELAY_URL": self.relay,
                    "BUZZ_PRIVATE_KEY": credential.secret,
                },
                capture_output=True,
                timeout=10,
                check=True,
            )
            if len(result.stdout) > RESPONSE_LIMIT:
                raise ContextError("window_exceeded")
            value = json.loads(result.stdout)
            if not isinstance(value, list):
                raise ContextError("invalid_snapshot")
            return value
        except ContextError:
            raise
        except Exception:
            raise ContextError("history_read_failed") from None


class BuzzHistory:
    def __init__(self, transport, agent_authors=()):
        self.transport, self.agent_authors = transport, frozenset(agent_authors)

    def read(self, invocation):
        from uuid import UUID

        if invocation.platform != "buzz":
            raise ContextError("scope_mismatch")
        for value in (invocation.requester, invocation.anchor, invocation.thread):
            if value is not None and not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ContextError("scope_mismatch")
        try:
            if str(UUID(invocation.conversation)) != invocation.conversation:
                raise ValueError
        except ValueError:
            raise ContextError("scope_mismatch") from None
        identity = self.transport.get(invocation, "identity")
        if (
            not isinstance(identity, list)
            or len(identity) != 1
            or not isinstance(identity[0], dict)
            or identity[0].get("pubkey") != invocation.requester
        ):
            raise ContextError("access_denied")
        rows = self.transport.get(invocation, "messages")
        if not isinstance(rows, list) or len(rows) >= FETCH_LIMIT:
            # A clipped raw event window cannot prove all edits were included.
            raise ContextError("window_exceeded")
        messages, changes, seen = {}, [], set()
        for row in rows:
            if not isinstance(row, dict):
                raise ContextError("invalid_snapshot")
            identifier = _identifier(row.get("id"))
            tags = row.get("tags")
            if (
                not re.fullmatch(r"[0-9a-f]{64}", identifier)
                or identifier in seen
                or not isinstance(tags, list)
                or not isinstance(row.get("content"), str)
                or not isinstance(row.get("pubkey"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", row["pubkey"])
            ):
                raise ContextError("invalid_snapshot")
            seen.add(identifier)
            if any(
                not isinstance(tag, list)
                or len(tag) < 1
                or any(not isinstance(part, str) for part in tag)
                for tag in tags
            ):
                raise ContextError("invalid_snapshot")
            channels = [tag[1] for tag in tags if tag[0] == "h" and len(tag) >= 2]
            if channels != [invocation.conversation]:
                raise ContextError("scope_mismatch")
            sequence = _sequence(row.get("created_at"), identifier)
            kind = row.get("kind")
            if type(kind) is not int:
                raise ContextError("invalid_snapshot")
            if kind in (9, 40002):
                roots = [
                    tag[1] for tag in tags if len(tag) >= 4 and tag[0] == "e" and tag[3] == "root"
                ]
                references = [tag for tag in tags if tag[0] == "e"]
                if len(roots) > 1 or (references and not roots):
                    raise ContextError("invalid_snapshot")
                messages[identifier] = {
                    **row,
                    "sequence": sequence,
                    "root": roots[0] if roots else None,
                }
            elif kind in (40003, 5, 9005):
                targets = [tag[1] for tag in tags if tag[0] == "e" and len(tag) >= 2]
                if not targets or (kind == 40003 and len(targets) != 1):
                    raise ContextError("invalid_snapshot")
                changes.append((sequence, row, targets))
            else:
                raise ContextError("invalid_snapshot")
        deleted = set()
        for _, row, targets in sorted(changes, key=lambda change: change[0]):
            for target in targets:
                original = messages.get(target)
                if row["kind"] == 40003 and original is not None:
                    if row["pubkey"] != original["pubkey"]:
                        raise ContextError("access_denied")
                    original["content"] = row["content"]
                elif row["kind"] in (5, 9005):
                    deleted.add(target)
        if invocation.thread is not None and (
            invocation.thread not in messages
            or invocation.thread in deleted
            or messages[invocation.thread]["root"] is not None
        ):
            raise ContextError("access_denied")
        result = []
        for identifier, row in messages.items():
            if identifier in deleted:
                continue
            if invocation.thread is None:
                if row["root"] is not None:
                    continue
            elif (row["root"] or identifier) != invocation.thread:
                continue
            result.append(
                Record(
                    identifier,
                    row["sequence"],
                    row["pubkey"],
                    "assistant" if row["pubkey"] in self.agent_authors else "user",
                    row["content"],
                )
            )
        _anchor(invocation, result)
        return sorted(result, key=lambda row: row.sequence), False
