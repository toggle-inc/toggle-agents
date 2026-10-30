"""Requester-scoped dispatch for a trusted host, NOT an HTTP authenticator.

The host authenticates each call and resolves current, agent-authorized grants.
Neither callback nor request_context may be exposed as an LLM tool parameter.
There is deliberately no default owner, environment fallback or service cache.
"""

import hashlib
import inspect
import json
import math
import time
from dataclasses import dataclass, field

from .service import ORIGINAL_TOOLS, ExpenseService
from .state import ExpenseError

OPERATIONS = {
    **dict.fromkeys(
        (
            "mf_offices",
            "mf_list_transactions",
            "mf_list_reports",
            "mf_known_items",
            "mf_payee_memory",
            "mf_get_receipt",
            "mf_receipt_status",
        ),
        "mf:read",
    ),
    **dict.fromkeys(
        (
            "mf_create_transaction",
            "mf_update_transaction",
            "mf_upload_receipt",
            "mf_delete_transaction",
        ),
        "mf:write",
    ),
    "mf_auth_url": "mf:connect",
    "mf_save_draft": "mf:draft",
    "mf_auth_complete": "mf:connect",
    "calendar_events": "calendar:read",
    "fare_lookup": "fare:read",
    "check_rules": "rules:read",
    "fetch_attachment": "attachment:read",
    "expense_context": "memory:read",
    "propose_teaching": "memory:propose",
    "read_reference": "rules:read",
    "delivery_contract": "contract:read",
}


def access_contract():
    """Static Git policy, not evidence of a host's implemented authentication."""
    return {
        "schema_version": "expense-requester-access/v1",
        "authority": "agent_owned_no_engine_dependency",
        "storage": "deployment_supplied_transactional_adapter",
        "principal": "verified_canonical_human_in_tenant",
        "identity_mapping": "trusted_explicit_account_link_only",
        "connection_selection": "requester_only_no_shared_or_admin_fallback",
        "grant_check": "every_tool_call",
        "consent": "service_and_agent_authorization_required",
        "unlinked": "stop_and_request_private_authorization_ui",
        "connection_ui": {
            "schema_version": "agent-service-connections/v1",
            "view_path": "/connections",
            "start_path": "/connections/start",
            "identity": "verified_platform_or_sso_human_only",
            "provider_selection": "deployment_configured_mf_or_calendar",
            "not_connected_or_expired": "show_private_connect_button",
            "unavailable": "show_service_outage_without_reauthorization",
            "credential_entry_in_chat": "never",
            "status_authority": "trusted_per_person_provider_resolver_not_model_text",
        },
        "execution_readiness": {
            "schema_version": "agent-execution-readiness/v1",
            "path": "/execution/status",
            "identity": "signed_platform_human",
            "authority": "current_personal_agent_consent_and_provider_grant",
            "provider_connected_alone": "not_authorization_to_execute",
            "read_only_initial_capabilities": ["mf:read", "calendar:read", "contract:read"],
            "financial_writes": "unavailable_in_read_only_host",
        },
        "financial_writes": "bound_candidate_and_person_office_consent_or_per_item_approval",
        "capabilities": dict(OPERATIONS),
        "receipt_resource_capability": "receipt:read",
    }


def _valid_id(value):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 512


def _unexpired(value, now):
    return type(value) in (int, float) and math.isfinite(value) and value > now


@dataclass(frozen=True)
class Requester:
    """Produced ONLY by host authentication + verified identity mapping.

    person_id is a canonical human identity, not an email or a display name.
    A tenant-wide API key or administrator identity alone is insufficient.
    """

    tenant_id: str
    person_id: str
    expires_at: float
    kind: str = "human"
    capabilities: frozenset[str] | None = None

    @property
    def owner(self):
        # Unambiguous tenant/person namespace for state, tokens and receipts.
        raw = json.dumps([self.tenant_id, self.person_id], ensure_ascii=True)
        return "requester-v1:" + hashlib.sha256(raw.encode()).hexdigest()


@dataclass(frozen=True)
class ConnectionGrant:
    """Fresh authorization snapshot from the host's private connection store.

    The resolver must check service-consent, agent-consent and revocation each
    time, and return only a service built with this human's own credentials.
    Capabilities below are internal capabilities, NOT provider OAuth scopes.
    """

    tenant_id: str
    person_id: str
    expires_at: float
    capabilities: frozenset[str]
    service: ExpenseService = field(repr=False, compare=False)
    agent_slug: str = field(kw_only=True)
    revoked: bool = False


class AuthorizationRequiredError(ExpenseError):
    code = "requester_authorization_required"

    def __init__(self, capability):
        self.capability = capability
        super().__init__(
            "本人の接続または利用許可が必要です。認証画面で連携してください。"
            "他の人の接続では実行しません。"
        )


class OperationUnavailableError(ExpenseError):
    code = "operation_unavailable"

    def __init__(self):
        super().__init__(
            "operation_unavailable: この接続ではこの操作は提供されていません。"
            "再同意や他サービスの再接続は不要です。利用可能なツールで続けてください。"
        )


class RequesterDispatcher:
    """Invoke from trusted adapter code with opaque per-request auth context.

    authenticate(context) -> Requester: verify signature, issuer, audience,
    expiry and tenant; map the platform account to a verified common person.
    resolve(requester, capability) -> ConnectionGrant | None: read current
    grants without shared/admin credential fallback. No callbacks are model tools.

    The existing ExpenseService still enforces per-write preview/approval.
    HTTP/MCP wiring must also route receipt resources through this boundary;
    wrapping only tool calls of the legacy single-owner MCP server is NOT safe.
    """

    def __init__(self, authenticate, resolve, *, clock=time.time):
        self._authenticate, self._resolve, self._clock = authenticate, resolve, clock
        # Trusted deployment implementation ceiling; never supplied by the model.
        self.supported_operations = frozenset(getattr(resolve, "supported_operations", OPERATIONS))
        if not self.supported_operations <= OPERATIONS.keys():
            raise ValueError("Unknown supported expense operation")
        self.receipt_resources = getattr(resolve, "receipt_resources", "mf_get_receipt" in self.supported_operations)
        if type(self.receipt_resources) is not bool:
            raise ValueError("Explicit receipt resource availability required")

    def available_operations(self, request_context):
        """Fresh catalog, intersect implementation, authority and provider grants.

        This is discovery only. Calls always repeat authentication and resolution.
        No service/credential survives beyond this method or gets cached in MCP.
        """
        self.validate_request(request_context)
        allowed = set()
        for capability in {OPERATIONS[name] for name in self.supported_operations}:
            try:
                self._service(request_context, capability)
            except ExpenseError:
                continue
            allowed.add(capability)
        return {name for name in self.supported_operations if OPERATIONS[name] in allowed} | (
            {"mf_create_transaction", "mf_upload_receipt"} & self.supported_operations
            if "mf:draft" in allowed else set()
        )

    def call(self, request_context, operation, arguments):
        capability = OPERATIONS.get(operation) if isinstance(operation, str) else None
        if capability is None or not isinstance(arguments, dict):
            raise ExpenseError("未対応の経費操作です。")
        self.validate_request(request_context)
        if operation not in self.supported_operations:
            raise OperationUnavailableError()
        # Identity, connection IDs, credentials and approvals are never tool args.
        try:
            inspect.signature(getattr(ExpenseService, operation)).bind(None, **arguments)
        except TypeError:
            raise ExpenseError("操作の引数から本人・接続・承認は変更できません。") from None
        try:
            service = self._service(request_context, capability)
        except AuthorizationRequiredError:
            # Narrow draft-only grants can prepare candidates, not use the old
            # confirm=True write path, nor prepare existing-record edits/deletes.
            if operation not in {"mf_create_transaction", "mf_upload_receipt"} or (
                arguments.get("confirm", False) is not False
            ):
                raise
            service = self._service(request_context, "mf:draft")
        return service.call(operation, arguments)

    def read_receipt(self, request_context, reference):
        """Trusted resource adapter path; never use a global service.receipts."""
        self.validate_request(request_context)
        if not self.receipt_resources:
            raise OperationUnavailableError()
        service = self._service(request_context, "receipt:read")
        with service._lock:
            return service._require(service.receipts, "領収書").payload(reference)

    def validate_request(self, request_context):
        """Trusted HTTP host's authentication gate; never register as a tool."""
        try:
            person = self._authenticate(request_context)
        except Exception:
            raise ExpenseError("認証済みの依頼者を確認できません。") from None
        now = self._clock()
        if (
            not isinstance(person, Requester)
            or person.kind != "human"
            or not _valid_id(person.tenant_id)
            or not _valid_id(person.person_id)
            or not _unexpired(person.expires_at, now)
        ):
            raise ExpenseError("認証済みの依頼者を確認できません。")
        return person

    def _service(self, request_context, capability):
        person = self.validate_request(request_context)
        if person.capabilities is not None and (
            not isinstance(person.capabilities, frozenset) or capability not in person.capabilities
        ):
            raise AuthorizationRequiredError(capability)
        try:
            grant = self._resolve(person, capability)
        except Exception:
            raise ExpenseError("本人専用の接続を確認できません。") from None
        if grant is None:
            raise AuthorizationRequiredError(capability)
        if (
            not isinstance(grant, ConnectionGrant)
            or grant.tenant_id != person.tenant_id
            or grant.person_id != person.person_id
            or grant.agent_slug != "expense_assistant"
            or grant.revoked is not False
            or not _unexpired(grant.expires_at, self._clock())
            or not _unexpired(person.expires_at, self._clock())
            or not isinstance(grant.capabilities, frozenset)
            or capability not in grant.capabilities
        ):
            raise AuthorizationRequiredError(capability)
        service = grant.service
        if (
            not isinstance(service, ExpenseService)
            or service.state.owner != person.owner
            or service.mf.owner != person.owner
            or (service.receipts is not None and service.receipts.owner != person.owner)
        ):
            raise ExpenseError("本人専用の接続と保存先を確認できません。")
        return service


assert set(OPERATIONS) == set(ORIGINAL_TOOLS) | {
    "expense_context",
    "propose_teaching",
    "read_reference",
    "delivery_contract",
    "mf_receipt_status",
    "mf_save_draft",
}
