"""The actual expense entrance opts into the same foundation, without MF writes."""

import asyncio
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from _foundation import test_conversation as fixtures
from _foundation.conversation import ConversationReader
from mcp_server import create_server
from runtime.service import ExpenseService
from runtime.state import State
from test_runtime import FakeMF


class HistoryEntranceTests(unittest.TestCase):
    def test_history_is_separate_from_expense_context_and_default_tools(self):
        fixture = fixtures.ConversationTests()
        fixture.setUp()
        backend = fixtures.Backend(fixture.invocation)
        reader = ConversationReader(lambda: fixture.invocation, backend, clock=lambda: fixture.now)
        with tempfile.TemporaryDirectory() as directory:
            state = State(Path(directory) / "state.sqlite", FakeMF.owner)
            mf = FakeMF()
            try:
                service = ExpenseService(mf=mf, state=state)
                defaults = {t.name for t in asyncio.run(create_server(service).list_tools())}
                self.assertNotIn("read_conversation_context", defaults)
                server = create_server(service, conversation_reader=reader)
                names = {t.name for t in asyncio.run(server.list_tools())}
                self.assertEqual(names - defaults, {"read_conversation_context"})
                result = asyncio.run(server.call_tool("read_conversation_context", {}))
                self.assertFalse(result.is_error)
                self.assertIn("青い朝", str(result))
                self.assertEqual(mf.writes, [])
            finally:
                state.close()

    def test_expense_scope_filter_preserves_independently_authorized_history(self):
        fixture = fixtures.ConversationTests()
        fixture.setUp()
        backend = fixture.backend
        with tempfile.TemporaryDirectory() as directory:
            state = State(Path(directory) / "state.sqlite", FakeMF.owner)
            self.addCleanup(state.close)
            service = ExpenseService(mf=FakeMF(), state=state)
            server = create_server(service, conversation_reader=fixture.reader,
                                   tool_catalog=lambda: {"mf_offices"})
            self.assertEqual({t.name for t in asyncio.run(server.list_tools())},
                             {"mf_offices", "read_conversation_context"})

            def read():
                result = asyncio.run(server.call_tool("read_conversation_context", {}))
                self.assertFalse(result.is_error)
                return json.loads(result.content[0].text)

            result = read()
            self.assertEqual(result["status"], "available")
            self.assertEqual([m["role"] for m in result["messages"]], ["user", "assistant"])
            self.assertIn("青い朝", result["messages"][1]["text"])
            # Listing retains a registered capability; its reader still checks
            # current identity/source, revocation and expiry on every call.
            backend.allowed = False
            self.assertEqual(read()["status"], "unavailable")
            backend.allowed = True
            fixture.current = replace(fixture.invocation, requester="other-person")
            self.assertEqual(read()["status"], "unavailable")
            fixture.current = replace(fixture.invocation, thread="other-thread")
            self.assertEqual(read()["status"], "unavailable")
            fixture.current = fixture.invocation
            fixture.now = fixture.invocation.expires_at
            self.assertEqual(read()["status"], "unavailable")
            self.assertEqual(service.mf.writes, [])

    def test_expense_scope_filter_does_not_create_unconnected_history(self):
        with tempfile.TemporaryDirectory() as directory:
            state = State(Path(directory) / "state.sqlite", FakeMF.owner)
            self.addCleanup(state.close)
            service = ExpenseService(mf=FakeMF(), state=state)
            names = {t.name for t in asyncio.run(create_server(
                service, tool_catalog=lambda: {"mf_offices"}
            ).list_tools())}
            self.assertEqual(names, {"mf_offices"})
