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

# Only operations tested with this stateless read service are exposed. MF memory,
# historical item suggestions, receipt storage/OCR and write flows stay disabled.
READ_OPERATIONS = frozenset({
    "mf_offices", "mf_list_transactions", "mf_list_reports",
    "calendar_events", "delivery_contract",
})

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

    supported_operations = READ_OPERATIONS
    CAPABILITIES = {"mf:read": "mf", "calendar:read": "calendar", "contract:read": None}

    def __init__(self, providers, store, namespace, clock=time.time, *,
                 service_factory=read_service_factory, tenant_id=None, profile=None):
        if not _valid_id(namespace) or not callable(clock) or not callable(service_factory):
            raise ValueError("Explicit execution namespace, clock and service factory required")
        if store is None or not callable(getattr(store, "transaction", None)):
            raise ValueError("Explicit transactional authorization store required")
        if tenant_id is not None and not _valid_id(tenant_id):
            raise ValueError("Explicit deployment tenant required")
        self.providers, self.store, self.namespace = providers, store, namespace
        self.clock, self.service_factory, self.tenant_id = clock, service_factory, tenant_id
        self.profile = profile
        if profile is not None:
            from .execution_profile import DurableExecutionProfile
            if (not isinstance(profile, DurableExecutionProfile) or profile.store is not store
                    or service_factory is not read_service_factory):
                raise ValueError("Explicit same-store durable profile required")
            self.supported_operations = READ_OPERATIONS | profile.supported_operations
            self.receipt_resources = "receipt:read" in profile.capabilities
            self.CAPABILITIES = {**self.CAPABILITIES, **{
                cap: "mf" if cap.startswith("mf:") else "calendar" if cap == "calendar:read" else None
                for cap in profile.capabilities}}

    def consent_service(self, person):
        """Trusted initial company-consent UI only, never a business grant/tool.

        A pending authority request is checked by DraftConsentBinding before this
        method. No scope is minted here; the returned service cannot write to MF.
        """
        if (self.profile is None or "mf:draft" not in self.profile.capabilities
                or not isinstance(person, Requester) or person.kind != "human"
                or not _valid_id(person.tenant_id) or not _valid_id(person.person_id)
                or (self.tenant_id is not None and person.tenant_id != self.tenant_id)
                or not _unexpired(person.expires_at, self.clock())):
            raise ExpenseError("本人の会社別初回許可の接続を確認してください。")
        adapter = getattr(self.providers, "mf", None)
        mf = None
        # State-only revocation must remain possible when MF is disconnected.
        # Company choices still call mf_offices and fail without an own provider.
        try:
            if adapter is not None and adapter.status(person, "mf") == "connected":
                candidate = adapter.for_person(person)
                if candidate.owner == person.owner:
                    mf = candidate
        except Exception:
            mf = None
        service = self.profile.service(person=person, mf=mf, calendar=None, clock=self.clock,
                                       capability="mf:read", consent_only=True)
        if not _unexpired(person.expires_at, self.clock()):
            raise ExpenseError("本人の初回許可操作の有効期限を確認してください。")
        return service

    def memory_service(self, person):
        """Verified-human GUI only. Exact decisions are authorized in the GUI.

        This does not issue MCP grants or bind MF/calendar credentials.
        """
        if (self.profile is None
                or 'memory:read' not in self.profile.capabilities
                or not self.profile.capabilities & {'memory:propose', 'memory:write'}
                or not isinstance(person, Requester) or person.kind != 'human'
                or not _valid_id(person.tenant_id) or not _valid_id(person.person_id)
                or (self.tenant_id is not None and person.tenant_id != self.tenant_id)
                or not _unexpired(person.expires_at, self.clock())):
            raise ExpenseError('本人専用の記憶管理はまだ利用できません。')
        service = self.profile.service(person=person, mf=None, calendar=None,
                                       clock=self.clock, capability='memory:read')
        if service.state.owner != person.owner or not _unexpired(person.expires_at, self.clock()):
            raise ExpenseError('本人専用の記憶管理を確認できません。')
        return service

    def readiness_reason(self, person, capability):
        """Safe diagnostics after a failed grant, never a permission decision."""
        if capability not in self.CAPABILITIES:
            return "operation_unavailable"
        provider = self.CAPABILITIES[capability]
        if provider is None:
            return "unavailable"
        adapter = getattr(self.providers, provider, None)
        if adapter is None:
            return "operation_unavailable"
        try:
            status = adapter.status(person, provider)
        except Exception:
            return "provider_unavailable"
        if status in {"not_connected", "expired", "revoked"}:
            return "service_connection_required"
        if status in {"unavailable", "not_configured"}:
            return "provider_unavailable"
        return "unavailable"

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
            durable = self.profile is not None and capability in self.profile.capabilities
            factory = self.profile.service if durable else self.service_factory
            service = factory(
                person=person, mf=bound if provider == "mf" else None,
                calendar=bound if provider == "calendar" else None, clock=self.clock,
                **({"capability": capability} if durable else {}),
            )
            expected_write = self.profile is not None and capability in {"mf:draft", "mf:write"}
            expected_memory_write = durable and capability == "memory:write"
            if (
                not isinstance(service, ExpenseService) or service.write_enabled is not expected_write
                or service.memory_write_enabled is not expected_memory_write
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
