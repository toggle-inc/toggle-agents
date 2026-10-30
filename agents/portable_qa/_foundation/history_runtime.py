"""Agent-owned, request-local history routing; independent of execution hosts.

The caller MUST verify identity and source/execution binding before entering
``bind``. Accepting an Invocation here is not authentication of HTTP headers or
model input. Provider credentials and current visibility are checked by readers.
"""

from contextlib import contextmanager
from contextvars import ContextVar
import time

from .conversation import ContextError, ConversationReader, unavailable
from .history_sources import create_reader


class ConversationRuntime:
    """One agent's fixed sources, with no global current user or transcript cache."""

    def __init__(self, sources, *, clock=time.time):
        self._sources = dict(sources)
        self._current = ContextVar("agent_history_invocation", default=None)
        self._clock = clock

    @contextmanager
    def bind(self, verified_invocation):
        """Trusted application code only; reset even when execution raises."""
        ConversationReader(lambda: None, None, clock=self._clock)._validate(
            verified_invocation
        )
        if verified_invocation.platform not in self._sources:
            raise ContextError("scope_mismatch")
        token = self._current.set(verified_invocation)
        try:
            yield
        finally:
            self._current.reset(token)

    def read(self):
        """MCP-compatible argument-free entry, resolved afresh for every call."""
        invocation = self._current.get()
        if invocation is None:
            return unavailable("not_connected")
        source = self._sources[invocation.platform]
        return create_reader(source, self._current.get, clock=self._clock).read()


def create_conversation_runtime(*, enabled=False, sources_factory, clock=time.time):
    """Explicit opt-in. The default never initializes sources or credentials."""
    if enabled is False:
        return None
    if enabled is not True:
        raise ValueError("History opt-in must be an explicit boolean")
    return ConversationRuntime(sources_factory(), clock=clock)
