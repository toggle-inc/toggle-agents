"""Agent-owned execution readiness, independent of Engine and chat products."""

from .authorization import AuthorizationError
from .requester import AuthorizationRequiredError, RequesterDispatcher
from .provider_execution import READ_CAPABILITIES


class ExecutionReadiness:
    """Conservative v1: every registered read capability is required.

    Use a narrowly scoped client for a narrow workflow. Partial consent never
    upgrades a broad client to ready, even if one isolated operation could run.
    The request cannot lower the trusted deployment's required capabilities.
    """
    def __init__(self, authority, resolve):
        self.authority, self.resolve = authority, resolve

    def view(self, context, params):
        if (not isinstance(params, dict)
                or set(params) != {"schema_version", "request_id", "client_id"}
                or params["schema_version"] != "agent-execution-readiness-request/v1"
                or not isinstance(params["request_id"], str)
                or not 1 <= len(params["request_id"]) <= 256
                or any(ord(c) < 33 or ord(c) > 126 for c in params["request_id"])
                or not isinstance(params["client_id"], str)):
            raise AuthorizationError("invalid_request")
        person = self.authority._login(context)
        client = self.authority._client(params["client_id"])
        capabilities = client.capabilities & READ_CAPABILITIES
        if not capabilities:
            raise AuthorizationError("invalid_scope")
        ready, reason = False, "unavailable"
        try:
            consented = self.authority.consented_requester(context, client.client_id, capabilities)
        except AuthorizationError as error:
            if error.code != "consent_required":
                raise
            reason = "agent_authorization_required"
        else:
            dispatcher = RequesterDispatcher(lambda _: consented, self.resolve,
                                             clock=self.authority.clock)
            try:
                for capability in sorted(capabilities):
                    dispatcher._service(None, capability)
            except AuthorizationRequiredError:
                reason = "service_connection_required"
            except Exception:
                reason = "unavailable"
            else:
                ready, reason = True, "ready"
        return {
            "schema_version": "agent-execution-readiness/v1",
            "agent_slug": "expense_assistant",
            "request_id": params["request_id"],
            "client_id": client.client_id,
            "ready": ready,
            "capabilities": sorted(capabilities),
            "expires_at": int(min(person.expires_at, self.authority.clock() + 60)),
            "reason": reason,
        }
