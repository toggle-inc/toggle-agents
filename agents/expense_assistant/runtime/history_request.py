"""Trusted host composition result, not an authenticator or a model schema."""

from dataclasses import dataclass
from contextlib import contextmanager
from contextvars import ContextVar
import math
import time

from _foundation.conversation import Invocation


@dataclass(frozen=True)
class HistoryRequestBinding:
    """Explicit canonical account link plus independently verified source event.

    A resolver must verify transport proofs, current execution binding and the
    explicit account link BEFORE constructing this value. In particular the
    canonical person must not be copied from an Engine assertion: the Engine
    need not know that identifier. Never deserialize this object from tool args.
    """

    tenant_id: str
    person_id: str
    invocation: Invocation

    def matches(self, person):
        return (
            (self.tenant_id, self.person_id) == (person.tenant_id, person.person_id)
            and isinstance(self.invocation, Invocation)
            and type(self.invocation.expires_at) in (int, float)
            and math.isfinite(self.invocation.expires_at)
            and self.invocation.expires_at <= person.expires_at
        )


@dataclass
class _RequestScope:
    # Shared by copied contexts so response completion revokes child tasks too.
    binding: HistoryRequestBinding | None


class HistoryRequestContext:
    """One resolver/app's trusted binding accessor, never a model-facing setter.

    Only the authenticated HTTP boundary enters bind(), after proof resolution
    and matches(person). No global/current-last cache or raw grants are stored.
    A copied context loses access when the originating request exits.
    """

    def __init__(self, *, clock=time.time):
        if not callable(clock):
            raise ValueError("Explicit request-context clock required")
        self._clock = clock
        self._scope = ContextVar("verified_history_request_binding", default=None)

    def current(self):
        scope = self._scope.get()
        binding = scope.binding if scope is not None else None
        if binding is None:
            return None
        now = self._clock()
        if (scope.binding is not binding or type(now) not in (int, float) or not math.isfinite(now)
                or now < 0 or now >= binding.invocation.expires_at):
            return None
        return binding

    @contextmanager
    def bind(self, binding, person):
        if not isinstance(binding, HistoryRequestBinding) or not binding.matches(person):
            raise ValueError("Verified personal history binding required")
        scope = _RequestScope(binding)
        token = self._scope.set(scope)
        try:
            if self.current() is None:
                raise ValueError("Live personal history binding required")
            yield
        finally:
            scope.binding = None
            self._scope.reset(token)

    @contextmanager
    def unbound(self):
        """Explicit capability-free scope for the separate legacy boundary."""
        token = self._scope.set(None)
        try:
            yield
        finally:
            self._scope.reset(token)
