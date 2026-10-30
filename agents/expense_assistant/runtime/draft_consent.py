"""First-consent UI binding. Never register these host operations as model tools."""

import hmac
from dataclasses import dataclass

from .authorization import AuthorizationError, _hash
from .requester import RequesterDispatcher
from .state import ExpenseError


@dataclass(frozen=True)
class _Decision:
    person: object
    request_id: str
    office_ids: tuple[str, ...]
    active: bool


class DraftConsentBinding:
    """Bind verified initial OAuth consent to the same person's private MF state.

    Supply the SAME current person-scoped resolver as the MCP app. Missing
    linkage fails closed. The UI selects one company, never all available ones.
    """

    def __init__(self, authority, resolve, *, consent_service=None):
        self.authority, self.resolve = authority, resolve
        self.consent_service = consent_service or getattr(resolve, "consent_service", None)
        if self.consent_service is not None and not callable(self.consent_service):
            raise ValueError("Explicit trusted consent service callback required")

    def _pending(self, context, request_id, csrf_token=None):
        person = self.authority._login(context)
        with self.authority.store.transaction() as records:
            record = records.get(self.authority._key("request", request_id))
        if (
            not record
            or record["used"]
            or record["expires_at"] <= self.authority.clock()
            or record["tenant_id"] != person.tenant_id
            or record["person_id"] != person.person_id
            or "mf:draft" not in record["capabilities"]
            or (
                csrf_token is not None
                and not hmac.compare_digest(record["csrf_hash"], _hash(csrf_token))
            )
        ):
            raise AuthorizationError("invalid_draft_consent")
        return person

    def _service(self, person):
        try:
            if self.consent_service is not None:
                service = self.consent_service(person)
                if (service.state.owner != person.owner or service.mf.owner != person.owner
                        or service.write_enabled is not False):
                    raise ExpenseError("初回許可には本人専用の読み取り接続が必要です。")
                return service
            return RequesterDispatcher(
                lambda _: person, self.resolve, clock=self.authority.clock
            )._service(None, "mf:draft")
        except ExpenseError:
            raise AuthorizationError("draft_connection_required") from None

    def choices(self, context, request_id):
        person = self._pending(context, request_id)
        try:
            service = self._service(person)
            offices = service.call("mf_offices", {})
            allowed = getattr(service, "consent_office_ids", None)
            if allowed is not None:
                offices = [office for office in offices if office["id"] in allowed]
        except ExpenseError:
            raise AuthorizationError("draft_connection_required") from None
        if not offices or len(offices) > 50:
            raise AuthorizationError("invalid_draft_companies")
        if self._pending(context, request_id).owner != person.owner:
            raise AuthorizationError("invalid_draft_consent")
        return offices

    def prepare(self, context, request_id, csrf_token, office_id=None, *, revoke=False):
        person = self._pending(context, request_id, csrf_token)
        if revoke:
            return _Decision(person, request_id, (), False)
        offices = self.choices(context, request_id)
        if not isinstance(office_id, str) or office_id not in {x["id"] for x in offices}:
            raise AuthorizationError("invalid_draft_company")
        return _Decision(person, request_id, (office_id,), True)

    def apply(self, context, decision):
        # OAuth decide has consumed the request and validated CSRF. Recheck
        # SSO and current resolver. OAuth permission alone never enables writes.
        person = self.authority._login(context)
        if not isinstance(decision, _Decision) or person.owner != decision.person.owner:
            raise AuthorizationError("invalid_draft_consent")
        self._service(person).state.set_draft_consent(
            list(decision.office_ids), decision.request_id, active=decision.active
        )
