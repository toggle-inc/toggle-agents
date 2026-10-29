"""Resolve fresh, personal read grants after agent-authority authentication.

The host MUST authenticate with its agent authority on every dispatch. In
particular, Requester.capabilities must be the current authority-issued subset,
including current client/agent consent checks, not a platform login's scopes.
Provider status supplies current service consent. No independent consent schema
is invented here; store/namespace are explicit deployment composition inputs.
"""

import time

from .requester import ConnectionGrant, Requester, _unexpired, _valid_id
from .service import ExpenseService
from .state import ExpenseError

READ_CAPABILITIES = frozenset({"mf:read", "calendar:read", "contract:read"})


class _ReadState:
    """No local files, approval ledger, settings, facts or receipt persistence."""

    def __init__(self, owner, clock):
        self.owner, self.clock = owner, clock

    def __getattr__(self, name):
        raise ExpenseError("この接続では状態の保存・設定・記憶は利用できません。")


class _ReadMF:
    METHODS = frozenset({"offices", "list_transactions", "list_reports", "get_transaction"})

    def __init__(self, owner, client=None):
        self.owner, self._client = owner, client

    def __getattr__(self, name):
        if self._client is None or name not in self.METHODS:
            raise ExpenseError("この接続ではMFの読み取り以外は利用できません。")
        return getattr(self._client, name)


def read_service_factory(*, person, mf, calendar, clock):
    """Build an exact ExpenseService without Cloud Run temporary write state.

    Receipt download/save is intentionally unavailable until durable personal
    receipt storage is wired. No State/Receipts database or directory is created.
    """
    return ExpenseService(
        mf=_ReadMF(person.owner, mf), state=_ReadState(person.owner, clock),
        calendar=calendar, write_enabled=False,
    )


class ProviderExecutionResolver:
    """Trusted callback, never a model tool or a platform-login authenticator.

    providers supplies .mf/.calendar adapters with status and for_person.
    service_factory is trusted explicit injection, called with keyword arguments
    person, mf, calendar, clock. Only the requested provider is bound. An optional
    deployment tenant_id additionally fences callers before provider access.
    """

    CAPABILITIES = {"mf:read": "mf", "calendar:read": "calendar", "contract:read": None}

    def __init__(self, providers, store, namespace, clock=time.time, *,
                 service_factory=read_service_factory, tenant_id=None):
        if not _valid_id(namespace) or not callable(clock) or not callable(service_factory):
            raise ValueError("Explicit execution namespace, clock and service factory required")
        if store is None or not callable(getattr(store, "transaction", None)):
            raise ValueError("Explicit transactional authorization store required")
        if tenant_id is not None and not _valid_id(tenant_id):
            raise ValueError("Explicit deployment tenant required")
        self.providers, self.store, self.namespace = providers, store, namespace
        self.clock, self.service_factory, self.tenant_id = clock, service_factory, tenant_id

    def __call__(self, person, capability):
        if (
            not isinstance(capability, str) or capability not in self.CAPABILITIES
            or not isinstance(person, Requester) or person.kind != "human"
            or not _valid_id(person.tenant_id) or not _valid_id(person.person_id)
            or (self.tenant_id is not None and person.tenant_id != self.tenant_id)
            or not _unexpired(person.expires_at, self.clock())
            or not isinstance(person.capabilities, frozenset)
            or capability not in person.capabilities
        ):
            return None
        provider = self.CAPABILITIES[capability]
        try:
            bound = None
            if provider is not None:
                adapter = getattr(self.providers, provider, None)
                if adapter is None or adapter.status(person, provider) != "connected":
                    return None
                bound = adapter.for_person(person)
                if bound.owner != person.owner:
                    return None
            service = self.service_factory(
                person=person, mf=bound if provider == "mf" else None,
                calendar=bound if provider == "calendar" else None, clock=self.clock,
            )
            if (
                not isinstance(service, ExpenseService) or service.write_enabled is not False
                or service.state.owner != person.owner or service.mf.owner != person.owner
                or (service.calendar is not None and service.calendar.owner != person.owner)
                or (service.receipts is not None and service.receipts.owner != person.owner)
                or not _unexpired(person.expires_at, self.clock())
            ):
                return None
            return ConnectionGrant(
                person.tenant_id, person.person_id, person.expires_at,
                frozenset({capability}), service, agent_slug="expense_assistant",
            )
        except Exception:
            # Provider/store failures may contain credential-bearing diagnostics.
            return None
