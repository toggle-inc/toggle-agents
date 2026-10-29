"""Trusted host composition result, not an authenticator or a model schema."""

from dataclasses import dataclass
import math

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
