"""Fixed setup declaration for a verified human; never grants or starts OAuth.

``ready`` means this declaration can be presented with the configured client
ceiling and providers, not that the person has consented or may execute tools.
The existing connection view supplies public provider metadata; its nonce is
deliberately discarded. No owner, credential or grant is part of this contract.
"""

import hashlib
import json
import math

from .authorization import AuthorizationError, CAPABILITY_LABELS
from .requester import Requester, _valid_id
from .service_connections import ServiceConnections


REQUIRED_CAPABILITIES = frozenset({
    "mf:read", "mf:draft", "calendar:read", "fare:read", "rules:read",
    "attachment:read", "receipt:read", "memory:read", "memory:write", "contract:read",
})
REQUIRED_PROVIDERS = ("mf", "calendar")
PROVIDER_LABELS = {"mf": "マネーフォワード経費", "calendar": "Googleカレンダー"}
CONSENT_TEXT = (
    "一覧の操作を本人の接続で行うことを許可します。未申請明細の作成と領収書のOCR送信は、"
    "選択した会社で都度確認なしに行います。確認・修正・申請はMF画面で行ってください。"
    "既存明細の変更・削除・提出は含みません。外部サービス自身のログイン・同意は別に必要です。"
    "この一覧を開くだけでは許可の付与や元の依頼の実行は行いません。"
)


class AgentSetup:
    def __init__(self, authority, service_connections, *, clock, available_capabilities=None):
        if (not isinstance(getattr(authority, "clients", None), dict)
                or not _valid_id(getattr(authority, "tenant_id", None))
                or not callable(getattr(service_connections, "view", None))
                or not callable(clock)):
            raise ValueError("Explicit authority, personal connection view and clock required")
        if available_capabilities is not None and (
                not isinstance(available_capabilities, frozenset)
                or any(not isinstance(capability, str) or not capability.strip()
                       for capability in available_capabilities)):
            raise ValueError("Runtime capabilities must be an explicit trusted frozenset or unknown")
        self.authority, self.service_connections, self.clock = authority, service_connections, clock
        self.available_capabilities = available_capabilities

    def _person(self, person):
        now = self.clock()
        if (type(now) not in (int, float) or not math.isfinite(now)
                or not isinstance(person, Requester) or person.kind != "human"
                or not _valid_id(person.tenant_id) or not _valid_id(person.person_id)
                or person.tenant_id != self.authority.tenant_id
                or type(person.expires_at) not in (int, float)
                or not math.isfinite(person.expires_at) or person.expires_at <= now):
            raise AuthorizationError("login_required")
        return now

    def _client(self, client_id):
        if not _valid_id(client_id):
            raise AuthorizationError("invalid_client")
        client = self.authority.clients.get(client_id)
        if (client is None or getattr(client, "client_id", None) != client_id
                or not isinstance(getattr(client, "capabilities", None), frozenset)):
            raise AuthorizationError("invalid_client")
        return client

    def view(self, person, client_id):
        self._person(person)
        self._client(client_id)
        capabilities = []
        for identifier in sorted(REQUIRED_CAPABILITIES):
            label = CAPABILITY_LABELS.get(identifier)
            if not isinstance(label, str) or not label.strip():
                raise AuthorizationError("setup_unavailable")
            capabilities.append({"id": identifier, "label": label})
        try:
            view = self.service_connections.view(person)
            if (not isinstance(view, dict)
                    or view.get("schema_version") != "agent-service-connections/v1"
                    or view.get("agent_slug") != "expense_assistant"
                    or not isinstance(view.get("connections"), list)):
                raise ValueError
            providers = {}
            for row in view["connections"]:
                if not isinstance(row, dict):
                    raise ValueError
                identifier = row.get("id")
                if identifier not in REQUIRED_PROVIDERS:
                    continue
                label, origins = row.get("label"), row.get("authorization_origins")
                if (identifier in providers
                        or not isinstance(label, str) or not label.strip() or len(label) > 500
                        or row.get("status") not in ServiceConnections.STATES
                        or not isinstance(origins, list) or not origins
                        or any(not isinstance(origin, str)
                               or ServiceConnections._origin(origin) != origin for origin in origins)
                        or len(set(origins)) != len(origins)):
                    raise ValueError
                providers[identifier] = {
                    "id": identifier, "label": label, "status": row["status"],
                    "authorization_origins": sorted(origins),
                }
        except Exception:
            raise AuthorizationError("setup_unavailable") from None
        # Recheck after the provider callbacks/store I/O, including the client
        # ceiling: deployment changes must not leave an obsolete ready result.
        now = self._person(person)
        client = self._client(client_id)
        missing_capabilities = sorted(REQUIRED_CAPABILITIES - client.capabilities)
        missing_runtime_capabilities = sorted(REQUIRED_CAPABILITIES - (self.available_capabilities or frozenset()))
        missing_providers = [identifier for identifier in REQUIRED_PROVIDERS if identifier not in providers]
        required_providers = [providers[identifier] for identifier in REQUIRED_PROVIDERS if identifier in providers]
        declaration = {
            "schema_version": "agent-setup/v1", "agent_slug": "expense_assistant",
            "capabilities": capabilities,
            "required_providers": [
                {"id": identifier,
                 "label": providers[identifier]["label"] if identifier in providers else PROVIDER_LABELS[identifier],
                 "authorization_origins": providers[identifier]["authorization_origins"] if identifier in providers else []}
                for identifier in REQUIRED_PROVIDERS],
            "consent_text": CONSENT_TEXT,
            "requires_company_selection": True,
        }
        declaration_digest = hashlib.sha256(json.dumps(
            declaration, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")).hexdigest()
        expires_at = math.floor(min(person.expires_at, now + 300))
        if not 0 < expires_at <= 2**53 - 1 or self._person(person) >= expires_at:
            raise AuthorizationError("login_required")
        return {
            "schema_version": "agent-setup/v1", "agent_slug": "expense_assistant",
            "client_id": client_id, "declaration_digest": declaration_digest,
            "capabilities": capabilities, "required_providers": required_providers,
            "requires_company_selection": True,
            "status": "blocked" if missing_capabilities or missing_runtime_capabilities or missing_providers or any(
                row["status"] in {"not_configured", "unavailable"} for row in required_providers
            ) else "ready",
            "missing_capabilities": missing_capabilities,
            "missing_runtime_capabilities": missing_runtime_capabilities,
            "expires_at": expires_at,
        }
