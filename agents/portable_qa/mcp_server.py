"""Optional history-only MCP entrance. A trusted host must supply the reader.

This module does not start a listener, infer identity from chat text, or create
an SA/Buzz connection. No reader means no registered history capability.
"""

from _foundation.conversation import register_history_tool


def create_server(*, conversation_reader=None):
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("portable-qa")
    register_history_tool(server, conversation_reader)
    return server
