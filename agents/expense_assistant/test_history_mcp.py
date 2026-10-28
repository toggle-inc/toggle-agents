"""The actual expense entrance opts into the same foundation, without MF writes."""

import asyncio
import tempfile
import unittest
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
