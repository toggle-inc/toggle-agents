"""Synthetic host-independent request lifecycle; no Engine or live API access."""

import asyncio
from dataclasses import replace
import unittest
from unittest.mock import Mock

from .conversation import ContextError, register_history_tool
from .history_runtime import create_conversation_runtime
from .history_sources import bind_invocation
from .test_history_sources import (
    BOT, CHANNEL, PERSON, BuzzAPI, BuzzHistory, SAAPI, SuccessAssistHistory, event,
)


class HistoryRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.api = SAAPI()
        self.source = SuccessAssistHistory(self.api, ("agent-bot",))
        self.bound = bind_invocation(self.source, clock=lambda: 100, **event())
        self.factory = Mock(return_value={"success_assist": self.source})
        self.runtime = create_conversation_runtime(
            enabled=True, sources_factory=self.factory, clock=lambda: 100
        )

    def test_default_does_not_initialize_sources_or_register_tools(self):
        factory = Mock(side_effect=AssertionError("must not access credentials"))
        reader = create_conversation_runtime(sources_factory=factory)
        self.assertIsNone(reader)
        factory.assert_not_called()
        server = Mock()
        register_history_tool(server, reader)
        server.tool.assert_not_called()
        for value in (None, 1, "true"):
            with self.assertRaises(ValueError):
                create_conversation_runtime(enabled=value, sources_factory=factory)
        factory.assert_not_called()

    def test_agent_reads_history_without_engine_and_cleans_up_on_exception(self):
        self.assertEqual(self.runtime.read()["status"], "unavailable")
        with self.assertRaisesRegex(RuntimeError, "execution failed"):
            with self.runtime.bind(self.bound):
                result = self.runtime.read()
                self.assertEqual(result["status"], "available")
                self.assertEqual([m["role"] for m in result["messages"]], ["user", "assistant"])
                raise RuntimeError("execution failed")
        self.assertEqual(self.runtime.read()["status"], "unavailable")

    def test_invalid_binding_and_unregistered_platform_never_read_source(self):
        self.api.calls.clear()
        for candidate in ({"requester": "person"}, replace(self.bound, platform="unknown")):
            with self.assertRaises(ContextError):
                with self.runtime.bind(candidate):
                    self.fail("must not enter")
        self.assertEqual(self.api.calls, [])

    def test_concurrent_requests_cannot_inherit_another_person(self):
        async def run():
            ready, finish = asyncio.Event(), asyncio.Event()

            async def first():
                with self.runtime.bind(self.bound):
                    ready.set()
                    await finish.wait()
                    return self.runtime.read()

            async def second():
                await ready.wait()
                self.assertEqual(self.runtime.read()["status"], "unavailable")
                with self.runtime.bind(replace(self.bound, requester="other")):
                    with self.assertRaises(ContextError):
                        self.runtime.read()
                finish.set()

            result, _ = await asyncio.gather(first(), second())
            return result

        self.assertEqual(asyncio.run(run())["status"], "available")
        self.assertEqual(self.runtime.read()["status"], "unavailable")

    def test_nested_execution_restores_previous_binding(self):
        with self.runtime.bind(self.bound):
            with self.runtime.bind(replace(self.bound, requester="other")):
                with self.assertRaises(ContextError):
                    self.runtime.read()
            self.assertEqual(self.runtime.read()["status"], "available")

    def test_same_agent_runtime_routes_sa_and_buzz_without_engine(self):
        buzz = BuzzHistory(BuzzAPI(), (BOT,))
        runtime = create_conversation_runtime(
            enabled=True,
            sources_factory=lambda: {"success_assist": self.source, "buzz": buzz},
            clock=lambda: 100,
        )
        buzz_bound = bind_invocation(
            buzz, clock=lambda: 100,
            **{**event("buzz"), "requester": PERSON, "conversation": CHANNEL,
               "thread": f"{1:064x}", "anchor": f"{3:064x}"},
        )
        with runtime.bind(self.bound):
            self.assertIn("青い朝", str(runtime.read()))
        with runtime.bind(buzz_bound):
            result = runtime.read()
            self.assertIn("架空の回答", str(result))
            self.assertNotIn("青い朝", str(result))
        self.assertEqual(runtime.read()["status"], "unavailable")

    def test_scope_and_expiry_are_rechecked_per_read(self):
        with self.runtime.bind(self.bound):
            self.assertEqual(self.runtime.read()["status"], "available")
            self.api.rows[0]["deleted"] = True
            with self.assertRaises(ContextError):
                self.runtime.read()
        with self.assertRaises(ContextError):
            with self.runtime.bind(replace(self.bound, expires_at=100)):
                self.fail("expired")
