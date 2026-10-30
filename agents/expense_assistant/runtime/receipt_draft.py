"""Pure receipt draft extraction; no OCR execution, provider, consent or writes.

The host verifies the rules file/hash and person-to-company mapping, then injects
the parsed rules dict and selects company_key. Never accept either from a model
or receipt text. OCR evidence is untrusted data, including any instructions in it.
Amounts are decimal strings; taxes are transcribed only, never calculated or
mapped onto MF fields. Synthetic rules are examples, not approved company policy.
"""

import copy
import datetime as dt
from decimal import Decimal, InvalidOperation
import re
import unicodedata


SCHEMA_VERSION = "receipt-company-rules/v1"
_NUMBER = r"(?:[0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)(?:\.[0-9]{1,2})?"
_MONEY = r"(?:[¥￥$]\s*|JPY\s*|USD\s*)?(" + _NUMBER + r")(?:\s*(?:円|JPY|USD))?"
_MONTHS = {name.lower(): number for number, name in enumerate((
    "January", "February", "March", "April", "May", "June", "July", "August",
    "September", "October", "November", "December"), 1)}
_MONTHS.update({name[:3]: number for name, number in list(_MONTHS.items())})
_MONTH = "(?:" + "|".join(_MONTHS) + ")"
_TOTAL = re.compile(
    r"^(?:税込(?:み)?(?:合計(?:金額)?|金額|総額)?|合計(?:金額)?|総合計|総額|"
    r"お買上(?:げ)?金額|grand\s+total|total(?:\s+amount)?|amount\s+paid)"
    r"\s*(?:[（(]\s*(?:税込(?:み)?|tax\s+included|incl\.?\s+tax)\s*[）)]|税込(?:み)?)?"
    r"\s*[:：=]?\s*" + _MONEY + r"\s*$", re.I)
_TAX = re.compile(
    r"^(?:内消費税(?:額)?|消費税(?:額)?|内税|税額|tax(?:\s+amount)?|vat)"
    r"\s*(?:[（(]?\s*[0-9]+(?:\.[0-9]+)?\s*%\s*[）)]?)?"
    r"\s*[:：=]?\s*" + _MONEY + r"\s*$", re.I)
_PAYEE = re.compile(r"^(?:支払先|店舗名|店名|発行者|販売者|payee|merchant|vendor|store)\s*[:：]\s*(\S.*)$", re.I)
_TOTAL_LABEL = re.compile(r"^(?:税込|合計|総合計|総額|お買上(?:げ)?金額|grand\s+total\b|total\b|amount\s+paid\b)", re.I)
_TAX_LABEL = re.compile(r"^(?:内消費税|消費税|内税|税額|tax(?:\s+amount)?\b|vat\b)", re.I)
_UNKNOWN = re.compile(r"(?:不明|判読不能|読取不能|未確認|unknown|unreadable|illegible|n/?a|[?？]+|[-ー]+)", re.I)


def _decimal(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("Explicit nonnegative decimal amount required")
    try:
        if len(str(value)) > 64 or not re.fullmatch(_NUMBER, str(value)):
            raise ValueError
        result = Decimal(str(value).replace(",", ""))
        if not result.is_finite() or result < 0 or result.as_tuple().exponent < -2:
            raise ValueError
    except (InvalidOperation, ValueError):
        raise ValueError("Explicit nonnegative decimal amount required") from None
    text = format(result, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _field(candidates, *, invalid=False):
    values = list(dict.fromkeys(row["value"] for row in candidates if row["value"] is not None))
    status = "needs_confirmation" if invalid or len(values) > 1 else "extracted" if values else "missing"
    return {"value": values[0] if status == "extracted" else None,
            "status": status, "candidates": values,
            "evidence": [{k: v for k, v in row.items() if k != "value"} for row in candidates]}


class ReceiptDraftBuilder:
    """Build from host-selected company + trusted registry dict, never user rules.

    Registry: {schema_version, synthetic, companies: {key: {label, account,
    max_total, exceed_action}}}. exceed_action is warning or block. The caller
    must authorize company_key for this person before invoking build().
    """

    def __init__(self, rules):
        if (not isinstance(rules, dict) or set(rules) != {"schema_version", "synthetic", "companies"}
                or rules["schema_version"] != SCHEMA_VERSION or type(rules["synthetic"]) is not bool
                or not isinstance(rules["companies"], dict) or not rules["companies"]):
            raise ValueError("Explicit trusted receipt rules registry required")
        self._rules = copy.deepcopy(rules)
        for key, rule in self._rules["companies"].items():
            if (not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", key)
                    or not isinstance(rule, dict) or set(rule) != {"label", "account", "max_total", "exceed_action"}
                    or any(not isinstance(rule[name], str) or not rule[name].strip() or len(rule[name]) > 200
                           for name in ("label", "account"))
                    or rule["exceed_action"] not in ("warning", "block")):
                raise ValueError("Explicit trusted company rule required")
            rule["max_total"] = _decimal(rule["max_total"])

    def build(self, ocr_result, receipt_reference, company_key):
        if not isinstance(company_key, str) or company_key not in self._rules["companies"]:
            raise ValueError("Trusted registered company key required")
        if (not isinstance(ocr_result, dict) or ocr_result.get("engine") != "tesseract"
                or not isinstance(ocr_result.get("text"), str) or len(ocr_result["text"]) > 100000
                or not isinstance(ocr_result.get("language"), str)
                or not re.fullmatch(r"[A-Za-z0-9_+.-]{1,80}", ocr_result["language"])):
            raise ValueError("Bounded tesseract OCR result required")
        if (not isinstance(receipt_reference, str) or not re.fullmatch(
                r"(?:receipt|attachment):[A-Za-z0-9_.:-]{1,240}", receipt_reference)):
            raise ValueError("Opaque personal receipt reference required")
        candidates = {key: [] for key in ("date", "payee", "total", "tax_amount", "tax_rate", "registration_number")}
        invalid = set()

        def add(field, value, number, raw, matched):
            candidates[field].append({"value": value, "line": number, "text": raw,
                                      "matched": matched, "source": "untrusted_ocr"})

        def uncertain(field, number, raw, matched):
            invalid.add(field)
            add(field, None, number, raw, matched)

        for number, raw in enumerate(ocr_result["text"].splitlines(), 1):
            line = unicodedata.normalize("NFKC", raw).strip()
            # Explicit year-first dates and named English months only. Ambiguous
            # locale-dependent 01/02/2026 is intentionally left for confirmation.
            dates = [(m, m.groups()) for m in re.finditer(
                r"(?<![0-9])([0-9]{4})\s*(?:[-/.]|年)\s*([0-9]{1,2})\s*(?:[-/.]|月)\s*([0-9]{1,2})(?:日)?(?![0-9])", line)]
            for m in re.finditer(r"\b(" + _MONTH + r")\.?\s+([0-9]{1,2}),?\s+([0-9]{4})\b", line, re.I):
                dates.append((m, (m[3], str(_MONTHS[m[1].lower()]), m[2])))
            for m in re.finditer(r"\b([0-9]{1,2})\s+(" + _MONTH + r")\.?\s+([0-9]{4})\b", line, re.I):
                dates.append((m, (m[3], str(_MONTHS[m[2].lower()]), m[1])))
            for match, parts in dates:
                try:
                    value = dt.date(*map(int, parts)).isoformat()
                except ValueError:
                    uncertain("date", number, raw, match[0])
                else:
                    add("date", value, number, raw, match[0])
            if re.search(r"\b[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}\b", line):
                uncertain("date", number, raw, line)
            match = _PAYEE.fullmatch(line)
            if match:
                if _UNKNOWN.fullmatch(match[1].strip()):
                    uncertain("payee", number, raw, match[0])
                else:
                    add("payee", match[1].strip(), number, raw, match[0])
            for field, pattern in (("total", _TOTAL), ("tax_amount", _TAX)):
                match = pattern.fullmatch(line)
                if match:
                    add(field, _decimal(match[1]), number, raw, match[0])
                elif (field == "total" and _TOTAL_LABEL.match(line) or field == "tax_amount"
                      and _TAX_LABEL.match(line) and not re.match(r"^tax\s+rate\b", line, re.I)):
                    uncertain(field, number, raw, line)
            if re.search(r"税率|消費税|内税|対象|\btax\b|\bvat\b", line, re.I):
                for match in re.finditer(r"(?<![0-9.])([0-9]{1,3}(?:\.[0-9]{1,2})?)\s*%", line):
                    if Decimal(match[1]) > 100:
                        uncertain("tax_rate", number, raw, match[0])
                    else:
                        add("tax_rate", _decimal(match[1]), number, raw, match[0])
            for match in re.finditer(r"(?<![A-Za-z0-9])T[0-9]{13}(?![A-Za-z0-9])", line):
                add("registration_number", match[0], number, raw, match[0])
            if re.search(r"登録番号|registration\s+(?:no\.?|number)", line, re.I) and not re.search(
                    r"(?<![A-Za-z0-9])T[0-9]{13}(?![A-Za-z0-9])", line):
                uncertain("registration_number", number, raw, line)

        fields = {key: _field(rows, invalid=key in invalid) for key, rows in candidates.items()}
        rule = copy.deepcopy(self._rules["companies"][company_key])
        check = "needs_confirmation"
        warnings = []
        if fields["total"]["status"] == "extracted":
            exceeds = Decimal(fields["total"]["value"]) > Decimal(rule["max_total"])
            check = ("blocked" if rule["exceed_action"] == "block" else "warning") if exceeds else "within_limit"
            if exceeds:
                warnings.append({"code": "company_total_limit_exceeded", "action": rule["exceed_action"],
                                 "message": "会社規則の税込上限を超えています。"})
        return {"schema_version": "receipt-draft/v1", "status": "draft", "submitted": False,
                "mf_registered": False, "synthetic_rules": self._rules["synthetic"],
                "receipt_reference": receipt_reference, "company_key": company_key,
                "ocr": {"engine": "tesseract", "language": ocr_result["language"]},
                "fields": fields, "missing": [key for key, field in fields.items() if field["status"] == "missing"],
                "needs_confirmation": [key for key, field in fields.items() if field["status"] == "needs_confirmation"],
                "registration_number_verified": False,
                "rule_check": {**rule, "status": check, "blocked": check == "blocked", "warnings": warnings},
                "evidence_is_untrusted": True}
