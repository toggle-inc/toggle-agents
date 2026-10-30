"""Operator/Git-managed company rules. Never populated from chat/tool arguments."""

import hashlib
import json
from pathlib import Path
import re

from .state import ExpenseError


def prepare_receipt_drafts(value, *, allowed_people):
    if not isinstance(value, dict) or set(value) != {"rules_file", "sha256", "person_companies"}:
        raise ValueError("Explicit agent-owned receipt rules required")
    path = Path(value["rules_file"])
    expected = value["sha256"]
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected)):
        raise ValueError("Pinned agent-owned receipt rules required")

    def read_rules():
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024:
            raise ExpenseError("会社ルールの配置・版を確認してください。")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ExpenseError("会社ルールの版が変わりました。配置を確認してください。")
        return json.loads(raw)

    from .receipt_draft import ReceiptDraftBuilder
    rules = read_rules()
    ReceiptDraftBuilder(rules)
    mappings = {}
    rows = value["person_companies"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 256:
        raise ValueError("Explicit personal company bindings required")
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {"person_id", "company_key"}
                or row["person_id"] not in allowed_people or row["person_id"] in mappings
                or not isinstance(row["company_key"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", row["company_key"])
                or row["company_key"] not in rules["companies"]):
            raise ValueError("Explicit personal company bindings required")
        mappings[row["person_id"]] = row["company_key"]

    class PinnedBuilder:
        def build(self, ocr_result, receipt_reference, company_key):
            builder = ReceiptDraftBuilder(read_rules())
            return builder.build(ocr_result, receipt_reference, company_key)

    def factory(person):
        if person.person_id not in mappings:
            raise ExpenseError("本人に適用する会社ルールを管理者が登録する必要があります。")
        read_rules()
        return PinnedBuilder(), mappings[person.person_id]

    return factory
