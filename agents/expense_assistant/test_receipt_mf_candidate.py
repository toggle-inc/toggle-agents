"""Pure synthetic candidate tests: no MF, OCR execution, network or state I/O."""

import copy
from dataclasses import replace
import datetime as dt
import inspect
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from runtime.receipt_draft import ReceiptDraftBuilder
from runtime.receipt_mf_candidate import CandidateError, TrustedMFBinding, receipt_mf_candidate
from runtime.service import ExpenseService


class ReceiptMFCandidateTests(unittest.TestCase):
    def setUp(self):
        # False exercises an approved-rule-shaped input, NOT real approved rules.
        # All values, identities and receipts in these tests are fictional.
        self.rules = {"schema_version": "receipt-company-rules/v1", "synthetic": False,
                      "companies": {"test-company": {"label": "架空会社", "account": "消耗品費",
                                                     "max_total": 1000, "exceed_action": "warning"}}}
        self.text = "2026年10月30日\n支払先: 架空店舗\n税込合計: 500円\n消費税(10%): 45円\n登録番号: T1234567890123"
        self.binding = TrustedMFBinding("test-company", "office-test", "item-test", "消耗品費")
        self.details = self.make_details()
        # Any accidental I/O by the converter fails every test immediately.
        for target in ("socket.socket", "socket.create_connection", "builtins.open"):
            guard = patch(target, side_effect=AssertionError("pure conversion attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)

    def make_details(self, text=None):
        draft = ReceiptDraftBuilder(self.rules).build(
            {"engine": "tesseract", "language": "jpn+eng", "text": self.text if text is None else text},
            "receipt:" + "a" * 32 + ".png", "test-company")
        return {"preview_id": "b" * 32, "preview_digest": "c" * 64, "expires_at": 1600,
                "action": "receipt_draft", "office": "test-company", "status": "preview",
                "snapshot": draft, "result": None}

    def convert(self, **kwargs):
        return receipt_mf_candidate(self.details, binding=self.binding,
                                    now=1000, today=dt.date(2026, 10, 30), **kwargs)

    def reject(self, details=None, **kwargs):
        with self.assertRaises(CandidateError):
            receipt_mf_candidate(self.details if details is None else details,
                                 **({"binding": self.binding, "now": 1000,
                                     "today": dt.date(2026, 10, 30)} | kwargs))

    def test_real_builder_shape_maps_only_existing_create_arguments(self):
        result = self.convert()
        args = result["args"]
        inspect.signature(ExpenseService.mf_create_transaction).bind(None, **args)
        self.assertEqual(args, {"office": "office-test", "recognized_at": "2026-10-30", "value": "500",
                                "remark": "架空店舗", "ex_item_id": "item-test", "ex_item_name": "消耗品費",
                                "receipt_path": "receipt:" + "a" * 32 + ".png",
                                "invoice_registration_number": "T1234567890123", "confirm": False,
                                "sources": {"remark": "領収書の支払先のみ転記・用途は要確認"}})
        self.assertEqual(result["payee"], "架空店舗")
        self.assertEqual(result["needs_confirmation"], ["purpose"])
        for flag in ("ready", "submitted", "mf_registered", "registration_number_verified"):
            self.assertIs(result[flag], False)
        self.assertNotIn("preview_id", args)
        self.assertEqual(result["source_preview_id"], self.details["preview_id"])

    def test_args_prepare_existing_create_preview_in_memory_but_cannot_be_ready(self):
        # Exercise the existing preview consumer with memory-only stubs. There
        # is no provider connection, DB, consent or external financial I/O.
        mf = SimpleNamespace(owner="test-person", offices=lambda: [{"id": "office-test", "name": "架空会社"}],
                             create_transaction=Mock(side_effect=AssertionError("unexpected financial write")))
        state = SimpleNamespace(owner="test-person", clock=lambda: 1900000000,
                                preview=Mock(return_value={"preview_id": "d" * 32}))
        receipts = SimpleNamespace(payload=lambda reference: {"content": "dGVzdA==", "content_type": "image/png",
                                                               "filename": "synthetic.png"})
        policy = SimpleNamespace(version="test", check=lambda **kwargs: [])
        service = ExpenseService(mf=mf, state=state, receipts=receipts, policy=policy)
        preview = service.mf_create_transaction(**self.convert()["args"])
        self.assertFalse(preview["form"]["ready"])
        remark = next(row for row in preview["form"]["fields"] if row["key"] == "remark")
        self.assertEqual((remark["value"], remark["status"]), ("架空店舗", "guess"))
        mf.create_transaction.assert_not_called()
        self.assertEqual(state.preview.call_args.args[0:2], ("create", "office-test"))

    def test_pure_deterministic_and_detached(self):
        before = copy.deepcopy(self.details)
        first, second = self.convert(), self.convert()
        self.assertEqual(first, second)
        first["args"]["office"] = "changed"
        first["needs_confirmation"].append("changed")
        self.assertEqual(self.convert(), second)
        self.assertEqual(self.details, before)

    def test_expiry_including_exact_boundary_and_invalid_numbers(self):
        for expires in (1000, 999, None, "1600", True, float("nan"), float("inf")):
            with self.subTest(expires=expires):
                self.details["expires_at"] = expires
                self.reject()

    def test_time_must_be_explicit_host_values(self):
        for now in (None, "1000", True, float("nan"), float("inf")):
            self.reject(now=now)
        for today in (None, "2026-10-30", dt.datetime(2026, 10, 30)):
            self.reject(today=today)

    def test_wrong_action_status_or_existing_result(self):
        for key, values in {"action": ["create", "upload", None],
                            "status": ["done", "executing", "unknown", None],
                            "result": [{}, {"created": True}]}.items():
            for value in values:
                details = copy.deepcopy(self.details)
                details[key] = value
                self.reject(details)

    def test_public_output_and_malformed_details_are_not_private_state_details(self):
        self.reject(self.details["snapshot"])
        for key in ("preview_id", "preview_digest", "snapshot", "expires_at"):
            details = copy.deepcopy(self.details)
            del details[key]
            self.reject(details)
        for value in (None, [], "unverified"):
            self.reject(value if value is not None else [])

    def test_draft_flags_and_version_must_be_exact(self):
        for key, value in (("schema_version", "other"), ("status", "saved"),
                           ("submitted", True), ("mf_registered", True),
                           ("submitted", 0), ("mf_registered", None)):
            details = copy.deepcopy(self.details)
            details["snapshot"][key] = value
            self.reject(details)

    def test_company_binding_is_required_on_both_snapshot_and_envelope(self):
        for location in (self.details, self.details["snapshot"]):
            key = "office" if location is self.details else "company_key"
            original = location[key]
            for value in ("other-company", "office-test", None):
                location[key] = value
                self.reject()
            location[key] = original
        self.reject(binding=replace(self.binding, company_key="other-company"))
        self.reject(binding={"company_key": "test-company", "office_id": "office-test"})

    def test_host_item_mapping_must_match_company_rule(self):
        self.reject(binding=replace(self.binding, ex_item_name="旅費交通費"))
        self.details["snapshot"]["rule_check"]["account"] = "other"
        self.reject()

    def test_host_ids_are_explicit_and_bounded(self):
        for name in ("company_key", "office_id", "ex_item_id", "ex_item_name"):
            for value in (None, "", " ", "x" * 201):
                with self.subTest(name=name, value=value), self.assertRaises(CandidateError):
                    replace(self.binding, **{name: value})
        for name in ("company_key", "office_id", "ex_item_id"):
            with self.assertRaises(CandidateError):
                replace(self.binding, **{name: "../model-selected"})

    def test_synthetic_or_missing_rules_never_convert_for_mf(self):
        for value in (True, None, 0, "false"):
            self.details["snapshot"]["synthetic_rules"] = value
            self.reject()
        del self.details["snapshot"]["synthetic_rules"]
        self.reject()

    def test_mf_item_id_length_boundary_without_truncation(self):
        for length in (39, 40):
            with self.subTest(length=length):
                self.binding = replace(self.binding, ex_item_id="i" * length)
                self.assertEqual(self.convert()["args"]["ex_item_id"], "i" * length)
        for length in (41, 200):
            with self.subTest(length=length), self.assertRaises(CandidateError):
                replace(self.binding, ex_item_id="i" * length)

    def test_mf_remark_length_boundary_counts_characters_and_never_truncates(self):
        for length in (99, 100, 101, 500):
            with self.subTest(length=length):
                payee = "店" * length
                self.details = self.make_details(self.text.replace("架空店舗", payee))
                before = copy.deepcopy(self.details)
                if length <= 100:
                    result = self.convert()
                    self.assertEqual(result["args"]["remark"], payee)
                    self.assertEqual(result["payee"], payee)
                    self.assertEqual(result["needs_confirmation"], ["purpose"])
                else:
                    with self.assertRaisesRegex(CandidateError, "payee_exceeds_mf_remark_limit"):
                        self.convert()
                self.assertEqual(self.details, before)

    def test_mf_value_maximum_and_service_precision_without_rounding_or_clamping(self):
        # MF permits 999999999999.999; the service's two-decimal constraint
        # makes .99 the greatest supported fractional amount at that magnitude.
        accepted = ("999999999999", "999999999999.98", "999999999999.99")
        rejected = ("1000000000000", "1000000000000.00", "9999999999999999",
                    "999999999999.999", "999999999999.991", "1000000000000.001")
        for total in accepted + rejected:
            with self.subTest(total=total):
                self.details = self.make_details(self.text.replace("500円", total + "円"))
                # The parser deliberately doesn't extract three-decimal money;
                # set a selected field too, to exercise this converter's guard.
                self.details["snapshot"]["fields"]["total"].update(
                    status="extracted", value=total, candidates=[total])
                self.details["snapshot"]["rule_check"].update(status="warning", blocked=False)
                before = copy.deepcopy(self.details)
                if total in accepted:
                    self.assertEqual(self.convert()["args"]["value"], total)
                else:
                    with self.assertRaisesRegex(CandidateError, "invalid_receipt_amount"):
                        self.convert()
                self.assertEqual(self.details, before)

    def test_blocked_or_unresolved_rule_is_rejected(self):
        for key, value in (("blocked", True), ("blocked", None), ("blocked", 0),
                           ("status", "blocked"), ("status", "needs_confirmation")):
            details = copy.deepcopy(self.details)
            details["snapshot"]["rule_check"][key] = value
            self.reject(details)

    def test_warning_keeps_candidate_but_not_permission(self):
        self.details = self.make_details(self.text.replace("500円", "1001円"))
        result = self.convert()
        self.assertEqual(result["rule_status"], "warning")
        self.assertFalse(result["ready"])
        self.rules["companies"]["test-company"]["exceed_action"] = "block"
        self.reject(self.make_details(self.text.replace("500円", "1001円")))

    def test_missing_and_conflicting_required_image_fields(self):
        for name in ("date", "total", "payee"):
            for field in ({"status": "missing", "value": None, "candidates": []},
                          {"status": "needs_confirmation", "value": None, "candidates": ["a", "b"]},
                          {"status": "extracted", "value": "a", "candidates": ["a", "b"]}):
                details = copy.deepcopy(self.details)
                details["snapshot"]["fields"][name] = field
                self.reject(details)

    def test_real_parser_conflicts_are_never_selected(self):
        for extra in ("\n2026年10月29日", "\n合計: 600円", "\n支払先: 別の架空店"):
            self.reject(self.make_details(self.text + extra))

    def test_future_and_invalid_date(self):
        for value in ("2026-10-31", "2026-02-30", "20261030", "2026-1-1"):
            details = copy.deepcopy(self.details)
            details["snapshot"]["fields"]["date"].update(value=value, candidates=[value])
            self.reject(details)

    def test_positive_decimal_amount_without_float_rounding(self):
        for value in ("0", "-1", "NaN", "Infinity", "1e3", "1.001", "1,000", True, 500, "9" * 65):
            details = copy.deepcopy(self.details)
            details["snapshot"]["fields"]["total"].update(value=value, candidates=[value])
            self.reject(details)
        self.details = self.make_details(self.text.replace("500円", "500.25円"))
        self.assertEqual(self.convert()["args"]["value"], "500.25")

    def test_purpose_attendees_and_route_are_not_invented_from_ocr(self):
        for item, expected in (("会議費", ["purpose", "own_count", "other_count", "own_names", "other_names"]),
                               ("旅費交通費", ["purpose", "memo"])):
            self.rules["companies"]["test-company"]["account"] = item
            self.binding = replace(self.binding, ex_item_name=item)
            self.details = self.make_details(self.text + "\npurpose: 接待\nown_count: 3\nmemo: A→B")
            self.details["snapshot"].update(purpose="接待", own_count=3, own_names="架空氏名", memo="A→B")
            result = self.convert()
            self.assertEqual(result["needs_confirmation"], expected)
            self.assertEqual(result["args"]["remark"], "架空店舗")
            self.assertIn("要確認", result["args"]["sources"]["remark"])
            for key in ("own_count", "other_count", "own_names", "other_names", "memo"):
                self.assertNotIn(key, result["args"])

    def test_tax_fields_are_not_sent_or_used_to_calculate_total(self):
        # The MF API has excise_value; this tool's create interface does not.
        self.details["snapshot"]["fields"]["tax_amount"] = {"value": "999999"}
        self.details["snapshot"]["fields"]["tax_rate"] = {"value": "99"}
        args = self.convert()["args"]
        self.assertEqual(args["value"], "500")
        self.assertNotIn("tax_amount", args)
        self.assertNotIn("tax_rate", args)
        self.assertNotIn("excise_value", args)

    def test_registration_missing_is_optional_conflict_waits_and_shape_is_checked(self):
        self.details = self.make_details(self.text.split("\n登録番号:")[0])
        self.assertEqual(self.convert()["args"]["invoice_registration_number"], "")
        self.details = self.make_details(self.text + "\n登録番号: T9999999999999")
        result = self.convert()
        self.assertIn("invoice_registration_number", result["needs_confirmation"])
        self.assertEqual(result["args"]["invoice_registration_number"], "")
        for value in ("T123", "T１２３４５６７８９０１２３", "t1234567890123"):
            field = self.details["snapshot"]["fields"]["registration_number"]
            field.update(status="extracted", value=value, candidates=[value])
            self.reject()

    def test_no_model_selected_targets_approvals_or_confirmations_are_copied(self):
        self.details["snapshot"].update(office="evil", ex_item_id="evil", confirm=True,
                                        preview_id="evil", purpose="用途", submitted_by_model=False)
        result = self.convert()
        self.assertEqual(result["args"]["office"], "office-test")
        self.assertEqual(result["args"]["ex_item_id"], "item-test")
        self.assertIs(result["args"]["confirm"], False)
        self.assertEqual(result["args"]["remark"], "架空店舗")
        self.assertNotIn("preview_id", result["args"])

    def test_only_stored_opaque_receipt_reference_is_accepted(self):
        for reference in ("/tmp/receipt.png", "https://example.test/r.png", "attachment:file-a", "receipt:../r", None):
            self.details["snapshot"]["receipt_reference"] = reference
            self.reject()


if __name__ == "__main__":
    unittest.main()
