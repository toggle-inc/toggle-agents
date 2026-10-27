"""API/CLI contract fixtures, not live SA/Buzz acceptance evidence."""

import copy
import io
import json
import subprocess
import unittest
from dataclasses import replace
from email.message import Message as Headers
from unittest.mock import patch

from .conversation import ContextError
from .history_sources import (
    FETCH_LIMIT,
    RESPONSE_LIMIT,
    BuzzCLITransport,
    BuzzHistory,
    PersonalCredential,
    SuccessAssistHistory,
    SuccessAssistHTTP,
    bind_invocation,
    create_reader,
)


class SAAPI:
    def __init__(self):
        self.rows = [
            self.row("root", 1, "架空の曲を紹介して"),
            self.row("answer", 2, "架空の曲『青い朝』です", bot="agent-bot"),
            self.row("current", 3, "それの説明をして"),
        ]
        self.calls, self.denied, self.more = [], False, False
        self.after_get = lambda: None

    def row(self, identifier, second, text, bot=None):
        return {
            "id": identifier,
            "channelId": "conversation",
            "authorId": "person",
            "botId": bot,
            "rootId": None if identifier == "root" else "root",
            "createdAt": f"2030-01-01T00:00:{second:02d}Z",
            "message": text,
        }

    def get(self, invocation, path, query):
        self.calls.append((path, query))
        if self.denied:
            raise ContextError("access_denied")
        if path.endswith("/messages/current"):
            return {
                "id": "current",
                "channelId": "conversation",
                "rootId": "root",
                "deleted": False,
            }
        self.after_get()
        return {
            "root": copy.deepcopy(self.rows[0]),
            "messages": copy.deepcopy(self.rows[1:]),
            "hasMoreOlder": self.more,
        }


def event(platform="success_assist"):
    return {
        "tenant": "tenant",
        "requester": "person",
        "agent": "agent",
        "platform": platform,
        "conversation": "conversation",
        "thread": "root",
        "anchor": "current",
        "execution": "execution",
        "expires_at": 200,
    }


class SuccessAssistTests(unittest.TestCase):
    def setUp(self):
        self.api = SAAPI()
        self.source = SuccessAssistHistory(self.api, ("agent-bot",))
        self.bound = bind_invocation(self.source, clock=lambda: 100, **event())
        self.reader = create_reader(self.source, lambda: self.bound, clock=lambda: 100)

    def test_real_route_shapes_read_previous_question_and_bot_answer(self):
        result = self.reader.read()
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["consistency"], "content_readback")
        self.assertEqual([r["role"] for r in result["messages"]], ["user", "assistant"])
        self.assertIn("青い朝", result["messages"][1]["text"])
        self.assertTrue(
            all("rootId" in q for path, q in self.api.calls if path.endswith("/messages"))
        )

    def test_source_not_delivery_channel_and_other_thread_are_refused(self):
        for overrides in (
            {"conversation": "private-reply-destination"},
            {"thread": "other-thread"},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ContextError):
                bind_invocation(self.source, clock=lambda: 100, **{**event(), **overrides})

    def test_foreign_row_and_bot_requester_are_not_authorized(self):
        self.api.rows[1]["channelId"] = "another-conversation"
        with self.assertRaises(ContextError):
            self.reader.read()
        self.api.rows[1]["channelId"] = "conversation"
        self.api.rows[-1]["botId"] = "agent-bot"
        with self.assertRaises(ContextError):
            self.reader.read()

    def test_edits_and_deletions_are_re_read_not_cached(self):
        self.reader.read()
        self.api.rows[1]["message"] = "編集後の架空の回答"
        self.assertEqual(self.reader.read()["messages"][-1]["text"], "編集後の架空の回答")
        self.api.rows[1] = {"id": "answer", "deleted": True}
        self.assertEqual(len(self.reader.read()["messages"]), 1)

    def test_revision_change_during_read_refuses_the_result(self):
        counter = [0]

        def mutate():
            counter[0] += 1
            if counter[0] == 3:
                self.api.rows[1]["message"] = "Changed during fetch"

        self.api.after_get = mutate
        with self.assertRaisesRegex(ContextError, "stale_or_revoked"):
            self.reader.read()

    def test_revocation_and_root_deletion_do_not_return_history(self):
        self.api.denied = True
        with self.assertRaises(ContextError):
            self.reader.read()
        self.api.denied = False
        self.api.rows[0]["deleted"] = True
        with self.assertRaises(ContextError):
            self.reader.read()

    def test_truncation_and_character_limits_do_not_break_revision_check(self):
        self.api.more = True
        self.api.rows[1]["message"] = "x" * 15000
        result = self.reader.read()
        self.assertTrue(result["truncated"])
        self.assertLessEqual(sum(len(m["text"]) for m in result["messages"]), 12000)

    def test_expired_binding_is_rejected_before_network_access(self):
        self.api.calls.clear()
        with self.assertRaises(ContextError):
            bind_invocation(self.source, clock=lambda: 200, **event())
        self.assertEqual(self.api.calls, [])

    def test_anchor_edit_after_binding_is_not_the_original_request(self):
        self.api.rows[-1]["message"] = "変更された別の依頼"
        with self.assertRaisesRegex(ContextError, "access_denied"):
            self.reader.read()

    def test_private_conversation_feed_does_not_include_other_threads(self):
        for row in self.api.rows:
            row["rootId"] = None
        self.api.rows.append({**self.api.row("other", 4, "別スレッド"), "rootId": "other-root"})

        def feed(invocation, path, query):
            if path.endswith("/messages/current"):
                return {
                    "id": "current",
                    "channelId": "conversation",
                    "rootId": None,
                    "deleted": False,
                }
            self.assertEqual(query, {"limit": FETCH_LIMIT})
            return {"messages": copy.deepcopy(self.api.rows), "nextBefore": None}

        self.api.get = feed
        self.bound = bind_invocation(self.source, clock=lambda: 100, **{**event(), "thread": None})
        result = self.reader.read()
        self.assertEqual(len(result["messages"]), 2)
        self.assertNotIn("別スレッド", str(result))


class HTTPTransportTests(unittest.TestCase):
    def setUp(self):
        self.api = SAAPI()
        self.bound = bind_invocation(SuccessAssistHistory(self.api), clock=lambda: 100, **event())
        self.credential = PersonalCredential(
            "tenant", "person", "https://sa.example.test", "synthetic", 200
        )
        self.transport = SuccessAssistHTTP(
            "https://sa.example.test", lambda _: self.credential, clock=lambda: 100
        )

    def test_cross_subject_tenant_origin_expiry_and_header_injection_fail_before_io(self):
        for changes in (
            {"tenant": "other"},
            {"requester": "other"},
            {"audience": "https://other.example.test"},
            {"expires_at": 100},
            {"secret": "synthetic\r\ninjected"},
        ):
            with self.subTest(changes=changes), patch("urllib.request.build_opener") as opener:
                self.credential = replace(
                    PersonalCredential(
                        "tenant", "person", "https://sa.example.test", "synthetic", 200
                    ),
                    **changes,
                )
                with self.assertRaises(ContextError):
                    self.transport.get(self.bound, "/api/chat/messages/current", {})
                opener.assert_not_called()
        self.assertNotIn("synthetic", repr(self.credential))

    def test_real_http_request_is_get_bounded_and_credential_bound(self):
        headers = Headers()
        headers["Content-Type"] = "application/json"
        response = io.BytesIO(b'{"messages": []}')
        response.status, response.headers = 200, headers
        with patch("urllib.request.build_opener") as factory:
            factory.return_value.open.return_value = response
            self.assertEqual(
                self.transport.get(self.bound, "/api/chat/messages/current", {}), {"messages": []}
            )
            request = factory.return_value.open.call_args.args[0]
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.get_header("Authorization"), "Bearer synthetic")
            self.assertEqual(factory.return_value.open.call_args.kwargs["timeout"], 10)

    def test_redirect_html_and_upstream_errors_are_not_history(self):
        from .history_sources import _NoRedirect

        with self.assertRaises(ContextError):
            _NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example.test")
        with patch("urllib.request.build_opener") as factory:
            factory.return_value.open.side_effect = RuntimeError("private upstream response")
            with self.assertRaisesRegex(ContextError, "^history_read_failed$"):
                self.transport.get(self.bound, "/api/chat/messages/current", {})

    def test_html_and_oversized_responses_fail_closed(self):
        for content_type, content in (
            ("text/html", b"login"),
            ("application/json", b"x" * (RESPONSE_LIMIT + 1)),
        ):
            headers = Headers()
            headers["Content-Type"] = content_type
            response = io.BytesIO(content)
            response.status, response.headers = 200, headers
            with patch("urllib.request.build_opener") as factory:
                factory.return_value.open.return_value = response
                with self.assertRaises(ContextError):
                    self.transport.get(self.bound, "/api/chat/messages/current", {})

    def test_transport_rejects_other_conversation_and_path_traversal(self):
        for path, query in (
            ("/api/chat/messages/other", {}),
            ("/api/chat/messages/../../private", {}),
            ("/api/chat/channels/conversation/messages", {"rootId": "other"}),
        ):
            with patch("urllib.request.build_opener") as factory:
                with self.assertRaises(ContextError):
                    self.transport.get(self.bound, path, query)
                factory.assert_not_called()


CHANNEL = "00000000-0000-4000-8000-000000000001"
PERSON, BOT = "a" * 64, "b" * 64


def buzz_row(number, author, content, *, root=None, kind=9, target=None):
    tags = [["h", CHANNEL]]
    if root:
        tags.append(["e", root, "", "root"])
    if target:
        tags.append(["e", target])
    return {
        "id": f"{number:064x}",
        "pubkey": author,
        "created_at": number,
        "kind": kind,
        "content": content,
        "tags": tags,
    }


class BuzzAPI:
    def __init__(self):
        root = f"{1:064x}"
        self.rows = [
            buzz_row(1, PERSON, "架空の質問"),
            buzz_row(2, BOT, "架空の回答", root=root),
            buzz_row(3, PERSON, "その続きは？", root=root),
        ]
        self.identity, self.calls = PERSON, []

    def get(self, invocation, operation):
        self.calls.append(operation)
        return [{"pubkey": self.identity}] if operation == "identity" else copy.deepcopy(self.rows)


class BuzzTests(unittest.TestCase):
    def setUp(self):
        self.api = BuzzAPI()
        self.source = BuzzHistory(self.api, (BOT,))
        values = {
            **event("buzz"),
            "requester": PERSON,
            "conversation": CHANNEL,
            "thread": f"{1:064x}",
            "anchor": f"{3:064x}",
        }
        self.bound = bind_invocation(self.source, clock=lambda: 100, **values)
        self.reader = create_reader(self.source, lambda: self.bound, clock=lambda: 100)

    def test_buzz_signed_identity_thread_and_prior_assistant_reply(self):
        result = self.reader.read()
        self.assertEqual([m["role"] for m in result["messages"]], ["user", "assistant"])
        self.assertEqual(result["messages"][-1]["text"], "架空の回答")

    def test_edit_replaces_original_and_native_delete_removes_it(self):
        self.api.rows.append(buzz_row(4, BOT, "編集後", kind=40003, target=f"{2:064x}"))
        self.assertEqual(self.reader.read()["messages"][-1]["text"], "編集後")
        self.api.rows.append(buzz_row(5, PERSON, "", kind=9005, target=f"{2:064x}"))
        self.assertEqual(len(self.reader.read()["messages"]), 1)

    def test_other_identity_channel_root_and_unauthorized_edit_are_refused(self):
        self.api.identity = BOT
        with self.assertRaises(ContextError):
            self.reader.read()
        self.api.identity = PERSON
        self.api.rows[1]["tags"][0][1] = "other"
        with self.assertRaises(ContextError):
            self.reader.read()
        self.api.rows[1]["tags"][0][1] = CHANNEL
        self.api.rows.append(buzz_row(4, PERSON, "forged", kind=40003, target=f"{2:064x}"))
        with self.assertRaises(ContextError):
            self.reader.read()

    def test_clipped_raw_event_window_is_not_reported_as_complete(self):
        self.api.rows = self.api.rows * FETCH_LIMIT
        with self.assertRaisesRegex(ContextError, "window_exceeded"):
            self.reader.read()

    def test_top_level_dm_history_excludes_other_thread_replies(self):
        for row in self.api.rows:
            row["tags"] = [["h", CHANNEL]]
        self.api.rows.append(buzz_row(4, BOT, "別スレッド", root=f"{99:064x}"))
        values = {
            **event("buzz"),
            "requester": PERSON,
            "conversation": CHANNEL,
            "thread": None,
            "anchor": f"{3:064x}",
        }
        self.bound = bind_invocation(self.source, clock=lambda: 100, **values)
        result = self.reader.read()
        self.assertEqual(len(result["messages"]), 2)
        self.assertNotIn("別スレッド", str(result))

    def test_cli_uses_only_fixed_reads_no_shell_or_inherited_secrets(self):
        credential = PersonalCredential("tenant", PERSON, "http://127.0.0.1:3000", "synthetic", 200)
        transport = BuzzCLITransport(
            "/opt/example/buzz",
            credential.audience,
            lambda _: credential,
            clock=lambda: 100,
            allow_local=True,
        )
        completed = subprocess.CompletedProcess([], 0, json.dumps(self.api.rows).encode(), b"")
        with patch("subprocess.run", return_value=completed) as run:
            transport.get(self.bound, "messages")
            arguments, options = run.call_args.args[0], run.call_args.kwargs
            self.assertIn("get", arguments)
            self.assertNotIn("send", arguments)
            self.assertFalse(options["shell"])
            self.assertEqual(set(options["env"]), {"PATH", "BUZZ_RELAY_URL", "BUZZ_PRIVATE_KEY"})
            with self.assertRaises(ContextError):
                transport.get(self.bound, "send")
        with self.assertRaises(ValueError):
            BuzzCLITransport("/opt/example/buzz", credential.audience, lambda _: credential)
