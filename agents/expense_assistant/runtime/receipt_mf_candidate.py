"""Pure conversion of a verified personal receipt preview to MF preview arguments.

The trusted host MUST obtain details from the current person's state.preview_details
and select the binding from its own verified company/item registry. Neither input
is a model-tool argument. This module cannot authenticate a person, verify a rule
file, establish receipt authenticity, authorize a write or deduplicate execution.
Those checks remain the future service integration's responsibility.

No clock reads, OCR, state access, provider calls or other I/O occur here. Even a
successful conversion is incomplete: purpose and other non-image facts require
an explicit human answer. Synthetic rules are never eligible for this MF API;
tests must not use its output as permission to send fictional receipts to MF.
"""

from dataclasses import dataclass
import datetime as dt
from decimal import Decimal
import math
import re


# ExTransactionCreateInput: https://expense.moneyforward.com/api/index.json
_MF_ITEM_ID_MAX_LENGTH = 40
_MF_REMARK_MAX_LENGTH = 100
_MF_VALUE_MAX = Decimal("999999999999.999")


class CandidateError(ValueError):
    """Invalid/unsafe candidate; the message is a stable reason, not OCR text."""


@dataclass(frozen=True)
class TrustedMFBinding:
    """Host-selected mapping for this person; not proof of consent/membership."""

    company_key: str
    office_id: str
    ex_item_id: str
    ex_item_name: str

    def __post_init__(self):
        for name, limit in (("company_key", 128), ("office_id", 200),
                            ("ex_item_id", _MF_ITEM_ID_MAX_LENGTH)):
            value = getattr(self, name)
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1," + str(limit) + "}", value):
                raise CandidateError("invalid_host_binding")
        if (not isinstance(self.ex_item_name, str) or not self.ex_item_name.strip()
                or self.ex_item_name != self.ex_item_name.strip() or len(self.ex_item_name) > 200):
            raise CandidateError("invalid_host_binding")


def _extracted(fields, name):
    field = fields.get(name)
    if not isinstance(field, dict) or field.get("status") != "extracted":
        raise CandidateError(name + "_requires_confirmation")
    value = field.get("value")
    # A selected value must agree with the parser's unique candidate. Do not
    # discard competing values just because an outer status says 'extracted'.
    if (not isinstance(value, str) or not value.strip() or len(value) > 500
            or field.get("candidates") != [value]):
        raise CandidateError(name + "_requires_confirmation")
    return value


def receipt_mf_candidate(details, *, binding, now, today):
    """Return {args, needs_confirmation, ...}; never return an executable approval.

    now is a host-supplied epoch timestamp; today is the host's business-local
    datetime.date (normally Asia/Tokyo). Details must be the *private* verified
    receipt_draft preview, not prepare_receipt_draft's public result. A prior
    receipt preview_id is provenance only, never a create preview/approval ID.
    Raises CandidateError for invalid, expired, conflicting or blocked inputs.
    No overrides or confirmations are accepted from OCR or extra snapshot keys.
    """
    if not isinstance(binding, TrustedMFBinding):
        raise CandidateError("trusted_host_binding_required")
    if (type(now) not in (int, float) or not math.isfinite(now)
            or type(today) is not dt.date):
        raise CandidateError("explicit_host_time_required")
    if not isinstance(details, dict):
        raise CandidateError("verified_receipt_details_required")
    if (details.get("action") != "receipt_draft" or details.get("status") != "preview"
            or details.get("result") is not None):
        raise CandidateError("invalid_receipt_preview_state")
    expires = details.get("expires_at")
    if type(expires) not in (int, float) or not math.isfinite(expires) or expires <= now:
        raise CandidateError("receipt_preview_expired")
    identifier, hashed = details.get("preview_id"), details.get("preview_digest")
    if (not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{32}", identifier)
            or not isinstance(hashed, str) or not re.fullmatch(r"[a-f0-9]{64}", hashed)):
        raise CandidateError("verified_receipt_details_required")
    draft = details.get("snapshot")
    if (not isinstance(draft, dict) or draft.get("schema_version") != "receipt-draft/v1"
            or draft.get("status") != "draft" or draft.get("submitted") is not False
            or draft.get("mf_registered") is not False):
        raise CandidateError("invalid_receipt_draft")
    if details.get("office") != binding.company_key or draft.get("company_key") != binding.company_key:
        raise CandidateError("company_binding_mismatch")
    if draft.get("synthetic_rules") is not False:
        raise CandidateError("non_synthetic_rules_required_for_mf")
    rule = draft.get("rule_check")
    if (not isinstance(rule, dict) or rule.get("blocked") is not False
            or rule.get("status") not in ("within_limit", "warning")):
        raise CandidateError("company_rule_blocked_or_unresolved")
    if rule.get("account") != binding.ex_item_name:
        raise CandidateError("item_binding_mismatch")
    reference = draft.get("receipt_reference")
    if not isinstance(reference, str) or not re.fullmatch(r"receipt:[a-f0-9]{32}\.(pdf|png|jpg|heic)", reference):
        raise CandidateError("stored_personal_receipt_required")
    fields = draft.get("fields")
    if not isinstance(fields, dict):
        raise CandidateError("receipt_fields_required")
    date = _extracted(fields, "date")
    try:
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", date):
            raise ValueError
        recognized = dt.date.fromisoformat(date)
    except ValueError:
        raise CandidateError("invalid_receipt_date") from None
    if recognized > today:
        raise CandidateError("future_receipt_date")
    total = _extracted(fields, "total")
    # Keep the existing service's two-decimal precision even though MF permits
    # three. Compare the API maximum exactly; never round or clamp a candidate.
    if (not re.fullmatch(r"[0-9]{1,16}(?:\.[0-9]{1,2})?", total)
            or not 0 < Decimal(total) <= _MF_VALUE_MAX):
        raise CandidateError("invalid_receipt_amount")
    payee = _extracted(fields, "payee")
    if len(payee) > _MF_REMARK_MAX_LENGTH:
        raise CandidateError("payee_exceeds_mf_remark_limit")
    pending = ["purpose"]
    if any(word in binding.ex_item_name for word in ("会議費", "交際", "歓送迎", "懇親", "飲食")):
        pending.extend(("own_count", "other_count", "own_names", "other_names"))
    if "交通" in binding.ex_item_name:
        pending.append("memo")
    number = fields.get("registration_number")
    registration = ""
    if not isinstance(number, dict):
        raise CandidateError("invalid_registration_field")
    if number.get("status") == "extracted":
        registration = _extracted(fields, "registration_number")
        if not re.fullmatch(r"T[0-9]{13}", registration):
            raise CandidateError("invalid_registration_number_shape")
    elif number.get("status") == "needs_confirmation":
        pending.append("invoice_registration_number")
    elif not (number.get("status") == "missing" and number.get("value") is None
              and number.get("candidates") == []):
        raise CandidateError("invalid_registration_field")
    return {
        # The existing create preview rejects an empty remark. Transcribe only
        # the payee; its source explicitly keeps purpose unresolved in form().
        "args": {"office": binding.office_id, "recognized_at": date, "value": total,
                 "remark": payee, "ex_item_id": binding.ex_item_id, "ex_item_name": binding.ex_item_name,
                 "receipt_path": reference, "invoice_registration_number": registration, "confirm": False,
                 "sources": {"remark": "領収書の支払先のみ転記・用途は要確認"}},
        "source_preview_id": identifier, "source_preview_digest": hashed,
        "payee": payee, "needs_confirmation": pending, "ready": False,
        "registration_number_verified": False,
        "rule_status": rule["status"], "submitted": False, "mf_registered": False,
    }
