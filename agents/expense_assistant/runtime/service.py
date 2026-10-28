"""All original expense operations behind one platform-independent service."""

import collections
import datetime as dt
import decimal
import inspect
import re
import threading
from zoneinfo import ZoneInfo

from .state import ExpenseError, OutcomeUnknownError, digest

ORIGINAL_TOOLS = (
    "mf_auth_url",
    "mf_auth_complete",
    "mf_offices",
    "mf_list_transactions",
    "mf_list_reports",
    "mf_known_items",
    "mf_payee_memory",
    "calendar_events",
    "fare_lookup",
    "check_rules",
    "fetch_attachment",
    "mf_get_receipt",
    "mf_create_transaction",
    "mf_update_transaction",
    "mf_upload_receipt",
    "mf_delete_transaction",
)


def compact(transaction):
    return {
        "id": transaction.get("id"),
        "date": transaction.get("recognized_at"),
        "value": transaction.get("value"),
        "remark": transaction.get("remark"),
        "memo": transaction.get("memo"),
        "ex_item": (transaction.get("ex_item") or {}).get("name"),
        "ex_item_id": transaction.get("ex_item_id"),
        "project": (transaction.get("project") or {}).get("name"),
        "report_number": transaction.get("report_number"),
        "in_report": bool(transaction.get("ex_report")),
        "has_file": bool(transaction.get("mf_file")),
        "warning": transaction.get("warning_message") or transaction.get("error_message"),
        "invoice_registration_number": transaction.get("invoice_registration_number"),
    }


def amount(value, *, allow_zero=False):
    if isinstance(value, bool):
        raise ExpenseError("金額を確認してください。")
    number = decimal.Decimal(str(value))
    if (
        not number.is_finite()
        or number < 0
        or (number == 0 and not allow_zero)
        or number != number.quantize(decimal.Decimal("0.01"))
    ):
        raise ExpenseError("金額は正の数、小数点以下2桁以内で指定してください。")
    return int(number) if number == int(number) else float(number)


def invoice_number(value):
    """Validate transcription shape only, not issuer registration or tax eligibility."""
    if not isinstance(value, str) or (value and not re.fullmatch(r"T[0-9]{13}", value)):
        raise ExpenseError("登録番号はTと半角数字13桁で指定し、不明なら空欄にしてください。")
    return value


def form(office, fields, *, warnings, sources, item_options, receipt=""):
    """A neutral draft UI contract; renderers never authorize a write by themselves."""
    meal = any(
        word in fields.get("ex_item_name", "")
        for word in ("会議費", "交際", "歓送迎", "懇親", "飲食")
    )
    transit = "交通" in fields.get("ex_item_name", "")
    definitions = [
        ("office", "会社", "select", True),
        ("recognized_at", "日付", "date", True),
        ("value", "金額", "number", True),
        ("remark", "内容", "text", True),
        ("ex_item_name", "経費科目", "select", True),
        ("report_number", "事前申請番号", "text", False),
        ("memo", "メモ", "text_long", transit),
        ("invoice_registration_number", "適格請求書発行事業者登録番号", "text", False),
    ]
    if meal:
        definitions += [
            ("own_count", "出席者（自社）", "number", True),
            ("other_count", "出席者（他社）", "number", False),
            ("own_names", "代表者（自社）", "text", True),
            ("other_names", "代表者（他社）", "text", bool(fields.get("other_count"))),
        ]
    definitions.append(("receipt", "領収書", "file", not transit))
    values = {**fields, "office": office["name"], "receipt": receipt or None}
    rows = []
    for key, label, kind, required in definitions:
        value = values.get(key)
        if value in ("", 0):
            value = None
        source = sources.get(key, "")
        row = {
            "key": key,
            "label": label,
            "type": kind,
            "required": required,
            "value": value,
            "status": "empty"
            if value is None and required
            else "guess"
            if re.search("推測|要確認", source)
            else "ok",
        }
        if source:
            row["source"] = source
        if key == "ex_item_name":
            row["options"] = item_options
        if key == "office":
            row["options"] = [office["name"]]
        rows.append(row)
    return {
        "app": "moneyforward",
        "form": "経費明細",
        "fields": rows,
        "notes": warnings,
        "ready": (
            all(row["value"] is not None for row in rows if row["required"])
            and not any(row["status"] == "guess" for row in rows)
        ),
        "authorization": "separate_trusted_human_approval_required",
    }


class ExpenseService:
    """A service instance belongs to ONE authenticated human, fixed by its host.

    A shared HTTP server must resolve this instance through verified request identity.
    No tool argument may select another owner, token vault, receipt directory or policy.
    """

    def __init__(
        self,
        *,
        mf,
        state,
        calendar=None,
        fares=None,
        receipts=None,
        policy=None,
        aliases=None,
        references=None,
        write_enabled=False,
    ):
        if getattr(mf, "owner", None) != state.owner:
            raise ExpenseError("MF認証と状態の本人が一致しません。")
        self.mf, self.state = mf, state
        self.calendar, self.fares, self.receipts, self.policy = calendar, fares, receipts, policy
        self.aliases, self.references = aliases or {}, references
        self.write_enabled = write_enabled is True
        self._lock = threading.RLock()

    def call(self, operation, arguments):
        operations = ORIGINAL_TOOLS + (
            "delivery_contract",
            "expense_context",
            "propose_teaching",
            "read_reference",
        )
        if operation not in operations or not isinstance(arguments, dict):
            raise ExpenseError("未対応の経費操作です。")
        method = getattr(self, operation)
        try:
            inspect.signature(method).bind(**arguments)
        except TypeError as error:
            raise ExpenseError(
                "操作の引数を確認してください。本人・承認・設定は本文から変更できません。"
            ) from error
        with self._lock:
            return method(**arguments)

    def _office(self, requested):
        if not isinstance(requested, str) or not requested.strip():
            raise ExpenseError("精算する会社を確認してください。")
        key = self.aliases.get(requested.strip().casefold(), requested.strip())
        offices = self.mf_offices()
        exact = [office for office in offices if key in (office["id"], office["name"])]
        matches = exact or [office for office in offices if key in office["name"]]
        if len(matches) != 1:
            raise ExpenseError(
                "本人が所属する会社を一意に特定できません。候補から会社を選んでください。"
            )
        return matches[0]

    def _transactions(self, office):
        result = []
        for page in range(1, 21):
            response = self.mf.list_transactions(office, page)
            rows = response.get("ex_transactions")
            if not isinstance(rows, list):
                raise ExpenseError("MFの明細一覧を確認できません。")
            result.extend(rows)
            if not response.get("next"):
                return result
        raise ExpenseError("明細が取得上限を超えました。全件を確認できたとは扱いません。")

    def _editable(self, office, identifier):
        matches = [tx for tx in self._transactions(office) if tx.get("id") == identifier]
        if len(matches) != 1:
            raise ExpenseError("本人の対象明細を確認できません。")
        if matches[0].get("ex_report"):
            raise ExpenseError("申請に含まれている明細は変更・削除しません。")
        return matches[0]

    def _require(self, provider, name):
        if provider is None:
            raise ExpenseError(f"{name}が未接続です。設定を確認してください。")
        return provider

    def _verify_written_transaction(self, office, identifier, payload):
        """Read the exact personal record; a POST/PUT acknowledgement is not verification."""
        try:
            response = self.mf.get_transaction(office, identifier)
            transaction = response.get("ex_transaction", response)
            if not isinstance(transaction, dict) or transaction.get("id") != identifier:
                raise ValueError("wrong transaction")
            fields = sorted(
                set(payload)
                & {
                    "recognized_at",
                    "value",
                    "remark",
                    "memo",
                    "ex_item_id",
                    "report_number",
                    "project_id",
                    "dept_id",
                    "invoice_registration_number",
                }
            )
            for key in fields:
                if key not in transaction:
                    raise ValueError("readback field missing")
                actual, expected = transaction.get(key), payload[key]
                if key == "value" and type(actual) not in (int, float):
                    raise ValueError("invalid amount in readback")
                # MF may represent clearing an optional text field as null.
                if actual != expected and not (expected == "" and actual is None):
                    raise ValueError("readback mismatch")
            if payload.get("receipt_input") and not transaction.get("mf_file"):
                raise ValueError("receipt attachment not yet visible")
            return transaction, fields
        except Exception as error:
            raise OutcomeUnknownError(
                "MFへの書き込み後の照合が完了していません。実際の明細を確認してください。"
                "書き込みを自動再送しません。"
            ) from error

    def mf_auth_url(self):
        return self.mf.authorize_url()

    def mf_auth_complete(self, code_or_url):
        return self.mf.complete_auth(code_or_url)

    def mf_offices(self):
        return [{"id": row["id"], "name": row.get("name", "")} for row in self.mf.offices()]

    def mf_list_transactions(self, office, date_from, date_to):
        first, last = dt.date.fromisoformat(date_from), dt.date.fromisoformat(date_to)
        if first > last:
            raise ExpenseError("期間を確認してください。")
        company = self._office(office)
        return [
            compact(row)
            for row in self._transactions(company["id"])
            if date_from <= (row.get("recognized_at") or "") <= date_to
        ]

    def mf_list_reports(self, office, pages=2):
        if type(pages) is not int or not 1 <= pages <= 5:
            raise ExpenseError("取得ページ数は1〜5で指定してください。")
        company, result = self._office(office), []
        for page in range(1, pages + 1):
            response = self.mf.list_reports(company["id"], page)
            result.extend(
                {
                    key: row.get(key)
                    for key in (
                        "number",
                        "title",
                        "status",
                        "ex_report_type_id",
                        "submitted_at",
                        "approved_at",
                    )
                }
                for row in response.get("ex_reports", [])
            )
            if not response.get("next"):
                break
        return result

    def mf_known_items(self, office):
        company = self._office(office)
        items, projects = collections.Counter(), collections.Counter()
        identities, examples = {}, []
        for row in self._transactions(company["id"]):
            name = (row.get("ex_item") or {}).get("name")
            if name:
                items[name] += 1
                identities[name] = row.get("ex_item_id")
            if (row.get("project") or {}).get("name"):
                projects[(row["project"]["name"], row.get("project_id"))] += 1
            if name and "交通" in name and len(examples) < 8:
                examples.append({key: row.get(key) for key in ("remark", "value", "memo")})
        return {
            "ex_items": [
                {"name": name, "ex_item_id": identities[name], "count": count}
                for name, count in items.most_common()
            ],
            "projects": [
                {"name": name, "project_id": identifier, "count": count}
                for (name, identifier), count in projects.most_common(15)
            ],
            "transit_remark_examples": examples,
        }

    def mf_payee_memory(self, office=""):
        offices = [self._office(office)] if office else self.mf_offices()
        today = dt.datetime.fromtimestamp(self.state.clock(), ZoneInfo("Asia/Tokyo")).date()
        current = today.strftime("%Y-%m")
        ordinal = today.year * 12 + today.month - 1
        recent = {
            f"{(ordinal - offset) // 12:04d}-{(ordinal - offset) % 12 + 1:02d}"
            for offset in range(1, 13)
        }
        grouped = {}
        for company in offices:
            for row in self._transactions(company["id"]):
                payee = re.sub(
                    r"\s+|株式会社|（株）|\(株\)", "", row.get("remark") or ""
                ).casefold()
                payee = re.split(r"[（(]", payee)[0][:100]
                if not payee:
                    continue
                bucket = grouped.setdefault((company["id"], payee), [])
                bucket.append(row)
        result, missing = [], []
        for (office_id, _), rows in grouped.items():
            company = next(row for row in offices if row["id"] == office_id)
            names = collections.Counter((row.get("ex_item") or {}).get("name") for row in rows)
            invoices = sorted(
                {
                    row["invoice_registration_number"]
                    for row in rows
                    if row.get("invoice_registration_number")
                }
            )
            months = {(row.get("recognized_at") or "")[:7] for row in rows}
            dates = [row.get("recognized_at") or "" for row in rows]
            record = {
                "支払先": rows[0].get("remark"),
                "会社": [company["name"]],
                "登録番号": invoices,
                "よく使う科目": names.most_common(1)[0][0],
                "金額の例": sorted({row["value"] for row in rows if row.get("value")})[:3],
                "最後の利用": max(dates),
                "回数": len(rows),
            }
            if invoices or len(rows) >= 3:
                result.append(record)
            if len(months & recent) >= 3 and current not in months:
                missing.append(
                    {
                        "支払先": record["支払先"],
                        "会社": record["会社"],
                        "最後に出した月": max(months),
                        "過去12か月で出した月数": len(months & recent),
                        "登録番号": invoices,
                    }
                )
        return {
            "支払先の記憶": sorted(result, key=lambda row: -row["回数"])[:60],
            "出し忘れの候補": missing,
        }

    def calendar_events(self, date_from, date_to):
        return self._require(self.calendar, "本人のカレンダー").events(date_from, date_to)

    def fare_lookup(self, from_station, to_station, date="", ic=True):
        return self._require(self.fares, "運賃検索").lookup(from_station, to_station, date, ic)

    def check_rules(
        self,
        recognized_at,
        value,
        ex_item_name="",
        remark="",
        memo="",
        report_number="",
        has_receipt=False,
        own_count=0,
        other_count=0,
    ):
        dt.date.fromisoformat(recognized_at)
        if any(type(count) is not int or count < 0 for count in (own_count, other_count)):
            raise ExpenseError("出席者数を確認してください。")
        return self._require(self.policy, "社内規則").check(
            recognized_at=recognized_at,
            value=amount(value, allow_zero=True),
            ex_item_name=ex_item_name,
            remark=remark,
            memo=memo,
            report_number=report_number,
            has_receipt=has_receipt,
            own_count=own_count,
            other_count=other_count,
            today=dt.datetime.fromtimestamp(self.state.clock(), ZoneInfo("Asia/Tokyo")).date(),
        )

    def fetch_attachment(self, url):
        return self._require(self.receipts, "添付ファイル").fetch_attachment(url)

    def mf_get_receipt(self, office, transaction_id):
        company = self._office(office)
        content, mime = self.mf.download_receipt(company["id"], transaction_id)
        return self._require(self.receipts, "領収書").save(content, mime)

    def _write(self, action, company, intent, prepare, execute, *, confirm, preview_id):
        if type(confirm) is not bool:
            raise ExpenseError("confirmは真偽値で指定してください。")
        if confirm:
            if not self.write_enabled:
                raise ExpenseError("この実接続は読み取り専用です。書き込みは別途承認が必要です。")
            if not preview_id:
                raise ExpenseError("本人に示したプレビューと承認が必要です。")
            completed = self.state.completed(preview_id, action, company["id"], intent)
            if completed is not None:
                return completed
        snapshot, display = prepare()
        snapshot["intent"] = intent
        if not confirm:
            return {**display, **self.state.preview(action, company["id"], snapshot)}
        if "form" in snapshot and not snapshot["form"]["ready"]:
            raise ExpenseError(
                "不足・推測の項目があります。本人に確認してプレビューを修正してください。"
            )
        return self.state.execute(
            preview_id, action, company["id"], snapshot, lambda: execute(snapshot)
        )

    def mf_create_transaction(
        self,
        office,
        recognized_at,
        value,
        remark,
        ex_item_id="",
        ex_item_name="",
        memo="",
        report_number="",
        project_id="",
        dept_id="",
        receipt_path="",
        own_count=0,
        other_count=0,
        own_names="",
        other_names="",
        confirm=False,
        sources=None,
        ex_item_options=None,
        preview_id="",
        invoice_registration_number="",
    ):
        company = self._office(office)
        intent = {
            key: value
            for key, value in locals().copy().items()
            if key not in {"self", "company", "confirm", "preview_id"}
        }

        def prepare():
            invoice_number(invoice_registration_number)
            parsed_date = dt.date.fromisoformat(recognized_at)
            if (
                parsed_date
                > dt.datetime.fromtimestamp(self.state.clock(), ZoneInfo("Asia/Tokyo")).date()
            ):
                raise ExpenseError("未来の利用日は登録せず、保留して本人に確認します。")
            if not isinstance(remark, str) or not remark.strip():
                raise ExpenseError("明細の内容が必要です。")
            warnings = self.check_rules(
                recognized_at,
                value,
                ex_item_name,
                remark,
                memo,
                report_number,
                bool(receipt_path),
                own_count,
                other_count,
            )
            payload = {
                "recognized_at": recognized_at,
                "value": amount(value, allow_zero=True),
                "remark": remark,
            }
            payload.update(
                {
                    key: val
                    for key, val in (
                        ("ex_item_id", ex_item_id),
                        ("memo", memo),
                        ("report_number", report_number),
                        ("project_id", project_id),
                        ("dept_id", dept_id),
                        ("invoice_registration_number", invoice_registration_number),
                    )
                    if val
                }
            )
            if own_count or other_count:
                payload["ex_transaction_attendant_count_attributes"] = {
                    "own_count": own_count,
                    "other_count": other_count,
                }
                payload["ex_transaction_attendant_representative_attributes"] = {
                    "own_name": own_names,
                    "other_name": other_names,
                }
            if receipt_path:
                payload["receipt_input"] = self._require(self.receipts, "領収書").payload(
                    receipt_path
                )
            fields = {
                "recognized_at": recognized_at,
                "value": amount(value, allow_zero=True),
                "remark": remark,
                "ex_item_name": ex_item_name,
                "memo": memo,
                "report_number": report_number,
                "own_count": own_count,
                "other_count": other_count,
                "own_names": own_names,
                "other_names": other_names,
                "invoice_registration_number": invoice_registration_number,
            }
            shown = {key: val for key, val in payload.items() if key != "receipt_input"}
            if receipt_path:
                shown["receipt"] = payload["receipt_input"]["filename"]
            draft = form(
                company,
                fields,
                warnings=warnings,
                sources=sources or {},
                item_options=ex_item_options or [],
                receipt=receipt_path,
            )
            snapshot = {
                "payload": payload,
                "policy_version": self.policy.version,
                "warnings": warnings,
                "form": draft,
            }
            if receipt_path:
                snapshot["receipt_fingerprint"] = digest(
                    {key: payload["receipt_input"][key] for key in ("content", "content_type")}
                )
            return snapshot, {
                "preview": shown,
                "office": company["name"],
                "warnings": warnings,
                "created": False,
                "form": draft,
            }

        def execute(snapshot):
            if not snapshot["form"]["ready"]:
                raise ExpenseError("必須項目が不足しています。プレビューを修正してください。")
            response = self.mf.create_transaction(company["id"], snapshot["payload"])
            transaction = response.get("ex_transaction", response)
            if not transaction.get("id"):
                raise OutcomeUnknownError("作成結果を確認できません。MF明細を照合してください。")
            transaction, verified = self._verify_written_transaction(
                company["id"], transaction["id"], snapshot["payload"]
            )
            return {
                "created": True,
                "transaction": compact(transaction),
                "warnings": snapshot["warnings"],
                "readback_verified": True,
                "verified_fields": verified,
            }

        return self._write(
            "create", company, intent, prepare, execute, confirm=confirm, preview_id=preview_id
        )

    def mf_update_transaction(
        self,
        office,
        transaction_id,
        remark=None,
        value=None,
        ex_item_id=None,
        memo=None,
        report_number=None,
        project_id=None,
        receipt_path="",
        confirm=False,
        preview_id="",
        invoice_registration_number=None,
    ):
        company = self._office(office)
        intent = {
            key: val
            for key, val in locals().copy().items()
            if key not in {"self", "company", "confirm", "preview_id"}
        }

        def prepare():
            if invoice_registration_number is not None:
                invoice_number(invoice_registration_number)
            before = self._editable(company["id"], transaction_id)
            payload = {
                key: val
                for key, val in (
                    ("remark", remark),
                    ("ex_item_id", ex_item_id),
                    ("memo", memo),
                    ("report_number", report_number),
                    ("project_id", project_id),
                    ("invoice_registration_number", invoice_registration_number),
                )
                if val is not None
            }
            if value is not None:
                payload["value"] = amount(value)
            if receipt_path:
                payload["receipt_input"] = self._require(self.receipts, "領収書").payload(
                    receipt_path
                )
            if not payload:
                raise ExpenseError("変更する項目がありません。")
            warnings = self.check_rules(
                before["recognized_at"],
                payload.get("value", before["value"]),
                (before.get("ex_item") or {}).get("name", ""),
                payload.get("remark", before.get("remark", "")),
                payload.get("memo", before.get("memo", "")),
                payload.get("report_number", before.get("report_number", "")),
                bool(receipt_path or before.get("mf_file")),
            )
            snapshot = {
                "before": compact(before),
                "payload": payload,
                "warnings": warnings,
                "policy_version": self.policy.version,
            }
            shown = {key: val for key, val in payload.items() if key != "receipt_input"}
            if receipt_path:
                shown["receipt"] = payload["receipt_input"]["filename"]
            return snapshot, {
                "preview": shown,
                "transaction_id": transaction_id,
                "warnings": warnings,
                "updated": False,
                "office": company["name"],
            }

        def execute(snapshot):
            response = self.mf.update_transaction(
                company["id"], transaction_id, snapshot["payload"]
            )
            transaction = response.get("ex_transaction", response)
            if transaction.get("id") != transaction_id:
                raise OutcomeUnknownError("更新結果を照合してください。")
            transaction, verified = self._verify_written_transaction(
                company["id"], transaction_id, snapshot["payload"]
            )
            return {
                "updated": True,
                "transaction": compact(transaction),
                "readback_verified": True,
                "verified_fields": verified,
            }

        return self._write(
            "update", company, intent, prepare, execute, confirm=confirm, preview_id=preview_id
        )

    def mf_upload_receipt(self, office, receipt_path, confirm=False, preview_id=""):
        company = self._office(office)
        intent = {"office": office, "receipt_path": receipt_path}

        def prepare():
            payload = self._require(self.receipts, "領収書").payload(receipt_path, ocr=True)
            return {
                "payload": payload,
                "receipt_fingerprint": digest(
                    {key: payload[key] for key in ("content", "content_type")}
                ),
            }, {
                "preview": {"receipt": payload["filename"], "office": company["name"], "ocr": True},
                "uploaded": False,
            }

        def execute(snapshot):
            return {
                "uploaded": True,
                "ocr_pending": True,
                "result": self.mf.upload_receipt(company["id"], snapshot["payload"]),
            }

        return self._write(
            "upload", company, intent, prepare, execute, confirm=confirm, preview_id=preview_id
        )

    def mf_delete_transaction(self, office, transaction_id, confirm=False, preview_id=""):
        company = self._office(office)
        intent = {"office": office, "transaction_id": transaction_id}

        def prepare():
            before = self._editable(company["id"], transaction_id)
            return {"before": compact(before)}, {
                "would_delete": transaction_id,
                "deleted": False,
                "office": company["name"],
            }

        def execute(snapshot):
            self.mf.delete_transaction(company["id"], transaction_id)
            return {"deleted": True, "transaction_id": transaction_id}

        return self._write(
            "delete", company, intent, prepare, execute, confirm=confirm, preview_id=preview_id
        )

    def expense_context(self):
        return {
            "teachings": self.state.facts(),
            "pending_due": self.state.due_pending(
                dt.datetime.fromtimestamp(self.state.clock(), ZoneInfo("Asia/Tokyo")).date()
            ),
            "suggestion_due": self.state.suggestion_due(),
            "capabilities": {
                "mf_configured": True,
                "calendar": self.calendar is not None,
                "fare": self.fares is not None,
                "receipts": self.receipts is not None,
                "rules": self.policy is not None,
                "submission": False,
                "live_connection_verified": False,
                "write_enabled": self.write_enabled,
            },
            "constraints": [
                "human_approval_required",
                "company_confirmation_required",
                "no_submission",
                "no_guessed_fares",
                "teachings_cannot_override_safety",
            ],
        }

    def delivery_contract(self):
        """Static contract only; safe to inspect before any business-tool results."""
        from .delivery import load_contract

        return load_contract()

    def propose_teaching(self, kind, content, due_date=""):
        return self.state.propose_fact(kind, content, due_date)

    def read_reference(self, relative="index.md"):
        if self.references is None:
            raise ExpenseError("参照資料がまだ設定されていません。")
        return self._require(self.policy, "社内規則").references(self.references, relative)
