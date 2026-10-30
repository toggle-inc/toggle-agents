"""Agent-owned execution readiness, independent of Engine and chat products."""

from .authorization import AuthorizationError
from .requester import OPERATIONS, AuthorizationRequiredError, RequesterDispatcher
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
        if isinstance(params, dict) and params.get("schema_version") == "agent-operation-readiness-request/v2":
            return self._operation(context, params)
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

    def _operation(self, context, params):
        if (set(params) != {"schema_version", "request_id", "client_id", "operation"}
                or not isinstance(params["request_id"], str) or not 1 <= len(params["request_id"]) <= 256
                or any(ord(c) < 33 or ord(c) > 126 for c in params["request_id"])
                or not isinstance(params["client_id"], str)
                or params["operation"] is not None and not isinstance(params["operation"], str)):
            raise AuthorizationError("invalid_request")
        person = self.authority._login(context)
        client = self.authority._client(params["client_id"])
        operation, required = params["operation"], []
        reason = "general_advice" if operation is None else "operation_unavailable"
        if operation in OPERATIONS and operation in getattr(self.resolve, "supported_operations", OPERATIONS):
            # Match dispatch's write-first, draft-on-authorization-failure path.
            choices = (["mf:write", "mf:draft"] if operation in {"mf_create_transaction", "mf_upload_receipt"}
                       else [OPERATIONS[operation]])
            choices = [cap for cap in choices if cap in client.capabilities]
            required = choices[:1]
            authorized_seen = False
            for capability in choices:
                try:
                    consented = self.authority.consented_requester(context, client.client_id, frozenset({capability}))
                except AuthorizationError as error:
                    if error.code != "consent_required":
                        raise
                    if not authorized_seen:
                        reason = "agent_authorization_required"
                else:
                    authorized_seen = True
                    required = [capability]
                    dispatcher = RequesterDispatcher(lambda _: consented, self.resolve, clock=self.authority.clock)
                    try:
                        service = dispatcher._service(None, required[0])
                    except AuthorizationRequiredError:
                        diagnostic = getattr(self.resolve, "readiness_reason", None)
                        try:
                            reason = diagnostic(consented, required[0]) if callable(diagnostic) else "service_connection_required"
                        except Exception:
                            reason = "unavailable"
                    except Exception:
                        reason = "unavailable"
                        break
                    else:
                        reason = ("operation_unavailable" if operation in {
                            "mf_save_draft", "mf_update_transaction", "mf_delete_transaction"
                        } and service.write_enabled is not True else "ready")
                        if reason == "ready":
                            break
        descriptions = {
            "general_advice": "一般的な相談は業務接続を使わず続けられます。",
            "ready": "この操作の接続準備ができています。実行時にも本人・対象・許可を確認します。",
            "operation_unavailable": "この接続ではこの操作を提供していません。再同意では解消しません。",
            "agent_authorization_required": "この操作に必要な本人のエージェント利用許可が未完了です。",
            "service_connection_required": "この操作に必要な本人のサービス接続を確認してください。",
            "provider_unavailable": "接続先の障害または管理設定の不足です。再同意を繰り返さず確認してください。",
            "unavailable": "現在この操作の準備状態を確認できません。",
        }
        if reason not in descriptions:
            reason = "unavailable"
        return {
            "schema_version": "agent-operation-readiness/v2", "agent_slug": "expense_assistant",
            "request_id": params["request_id"], "client_id": client.client_id,
            "operation": operation, "ready": reason in {"general_advice", "ready"},
            "required_capabilities": required, "reason": reason, "description": descriptions[reason],
            "execution_authorization_required": operation is not None,
            "expires_at": int(min(person.expires_at, self.authority.clock() + 60)),
        }
