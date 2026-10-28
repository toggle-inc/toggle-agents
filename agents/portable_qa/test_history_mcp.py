"""The actual optional MCP entrance, not a platform connection test."""

import asyncio
import unittest

from _foundation import test_conversation as fixtures
from _foundation.conversation import ConversationReader
from mcp_server import create_server


class HistoryEntranceTests(unittest.TestCase):
    def test_entrance_registers_history_only_when_explicitly_bound(self):
        self.assertEqual(asyncio.run(create_server().list_tools()), [])
        fixture = fixtures.ConversationTests()
        fixture.setUp()
        reader = ConversationReader(
            lambda: fixture.invocation,
            fixtures.Backend(fixture.invocation),
            clock=lambda: fixture.now,
        )
        server = create_server(conversation_reader=reader)
        result = asyncio.run(server.call_tool("read_conversation_context", {}))
        self.assertFalse(result.is_error)
        self.assertIn("青い朝", str(result))
