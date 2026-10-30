"""Offline business scenario: fake OCR + fake MF, never live/image/SA UI evidence."""

import copy
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_durable_business as durable
from runtime.execution_profile import DurableExecutionProfile
from runtime.requester import RequesterDispatcher
from runtime.state import ExpenseError, OutcomeUnknownError


class FictionalPolicy:
    """Test-only invented warning rule; not an actual company's policy."""
    version = "synthetic-scenario-policy-v1"

    def __init__(self, config):
        self.office_ids = config["office_ids"]
        self.limit = config["warning_limit_yen"]

    def check(self, **fields):
        return ["架空規則: 上限目安1000円を超過。本人確認が必要"] if fields["value"] > self.limit else []


class SyntheticExpenseScenarioTests(unittest.TestCase):
    def setUp(self):
        network = patch("socket.socket.connect", side_effect=AssertionError("live network forbidden"))
        network.start()
        self.addCleanup(network.stop)
        self.data = json.loads((Path(__file__).parent / "fixtures/synthetic_receipt_scenario.json").read_text())
        self.assertTrue(self.data["synthetic_only"])
        self.host = durable.DurableBusinessTests(methodName="runTest")
        self.host.setUp()
        self.addCleanup(self.host.doCleanups)
        self.host.now = 1906000000  # after the fictional receipt date; fixed test clock
        # Requester expiry must follow this scenario's fixed clock as well.
        from dataclasses import replace
        self.host.people = {name: replace(person, expires_at=self.host.now + 1000)
                            for name, person in self.host.people.items()}
        self.host.profile = DurableExecutionProfile(
            self.host.store, self.host.key, "synthetic-scenario",
            capabilities=self.host.profile.capabilities, financial_writes=True,
            policy_factory=lambda _: FictionalPolicy(self.data["fictional_policy"]))
        self.host.resolver = self.host.make_resolver()
        self.host.dispatcher = RequesterDispatcher(self.host.people.get, self.host.resolver,
                                                   clock=lambda: self.host.now)
        self.service = self.host.service()
        self.mf = self.host.mf.for_person(self.host.people["alice"])
        # A PDF signature plus invented text is NOT a rendered receipt or OCR input.
        self.content = b"%PDF-1.4\n" + self.data["receipt_text"].encode()
        self.receipt = self.service.receipts.save(self.content, "application/pdf")

    def fake_ocr_candidate(self):
        # Deliberately local fixture lookup. No OCR model, MF upload, or HTTP call.
        self.assertEqual(self.service.receipts.payload(self.receipt["path"])["content_type"], "application/pdf")
        return {**copy.deepcopy(self.data["fake_ocr"]), "receipt_path": self.receipt["path"]}

    def confirmed(self):
        return {**self.fake_ocr_candidate(), **self.data["synthetic_human_answer"]}

    def consent(self):
        self.host.consent()

    def test_receipt_fake_ocr_missing_question_consent_create_review_and_duplicate(self):
        args = self.fake_ocr_candidate()
        incomplete = self.service.mf_create_transaction(**args)
        fields = {field["key"]: field for field in incomplete["form"]["fields"]}
        self.assertEqual(fields["value"]["status"], "empty")
        self.assertEqual(fields["value"]["label"], "金額")  # renderer can ask this missing field
        self.assertIsNone(fields["invoice_registration_number"]["value"])
        self.assertFalse(incomplete["form"]["ready"])
        self.consent()
        with self.assertRaises(ExpenseError):
            self.service.mf_save_draft(incomplete["preview_id"])
        self.assertEqual(self.mf.writes, [])
        # Only the explicit synthetic human response supplies amount/number.
        candidate = self.service.mf_create_transaction(**self.confirmed())
        self.assertTrue(candidate["form"]["ready"])
        self.assertEqual(candidate["warnings"], [])
        self.service.state.set_draft_consent([], "synthetic-revoked", active=False)
        with self.assertRaises(ExpenseError):
            self.service.mf_save_draft(candidate["preview_id"])
        self.assertEqual(self.mf.writes, [])
        self.consent()
        saved = self.service.mf_save_draft(candidate["preview_id"])
        self.assertTrue(saved["readback_verified"])
        self.assertFalse(saved["submitted"])
        self.assertEqual(saved["draft_status"], "saved_unsubmitted")
        self.assertEqual(saved["review_office_id"], "office-a")
        self.assertEqual(saved["review_url"], "https://expense.moneyforward.com/transactions")
        self.assertEqual(saved["review_link_kind"], "transaction_list")
        self.assertEqual(self.mf.writes[0][0:2], ("create", "office-a"))
        self.assertEqual(self.mf.writes[0][2]["value"], 880)
        self.assertEqual(self.mf.writes[0][2]["invoice_registration_number"], "T0000000000000")
        self.assertEqual(self.service.mf_save_draft(candidate["preview_id"]), saved)
        duplicate = self.service.mf_create_transaction(**self.confirmed())
        with self.assertRaises(ExpenseError):
            self.service.mf_save_draft(duplicate["preview_id"])
        self.assertEqual(len(self.mf.writes), 1)
        for operation in ("mf_submit_report", "mf_submit_transaction"):
            with self.assertRaises(ExpenseError):
                self.service.call(operation, {})
        self.assertFalse(any("submit" in name for name in self.host.dispatcher.available_operations("alice")))

    def test_other_person_receipt_and_candidate_and_other_company_are_refused(self):
        self.consent()
        candidate = self.service.mf_create_transaction(**self.confirmed())
        bob = self.host.service("bob")
        for attempt in (lambda: bob.receipts.payload(self.receipt["path"]),
                        lambda: bob.mf_save_draft(candidate["preview_id"]),
                        lambda: self.service.mf_create_transaction(**{**self.confirmed(), "office": "office-b"})):
            with self.assertRaises(ExpenseError):
                attempt()
        self.assertEqual(self.mf.writes, [])
        self.assertEqual(self.host.mf.for_person(self.host.people["bob"]).writes, [])

    def test_fictional_upper_limit_is_visible_warning_not_a_hard_save_gate(self):
        candidate = self.service.mf_create_transaction(**{**self.confirmed(), "value": 1001})
        self.assertIn("1000", candidate["warnings"][0])
        self.assertEqual(candidate["form"]["notes"], candidate["warnings"])
        self.assertTrue(candidate["form"]["ready"])
        self.consent()
        saved = self.service.mf_save_draft(candidate["preview_id"])
        self.assertFalse(saved["submitted"])
        self.assertEqual(len(self.mf.writes), 1)

    def test_tax_fields_unsupported_and_invoice_guess_or_bad_shape_not_silently_used(self):
        self.assertNotIn("tax_rate", inspect.signature(self.service.mf_create_transaction).parameters)
        self.assertNotIn("tax_amount", inspect.signature(self.service.mf_create_transaction).parameters)
        for field, value in self.data["unsupported_tax"].items():
            with self.assertRaises(TypeError):
                self.service.mf_create_transaction(**self.confirmed(), **{field: value})
        guessed = self.service.mf_create_transaction(**self.confirmed(),
            sources={"invoice_registration_number": "推測・要確認"})
        self.assertFalse(guessed["form"]["ready"])
        self.consent()
        with self.assertRaises(ExpenseError):
            self.service.mf_save_draft(guessed["preview_id"])
        with self.assertRaises(ExpenseError):
            self.service.mf_create_transaction(**{**self.confirmed(), "invoice_registration_number": "T123"})
        self.assertEqual(self.mf.writes, [])

    def test_fake_mf_unknown_outcome_blocks_same_receipt_retry(self):
        self.consent()
        self.mf.fail_write = True
        candidate = self.service.mf_create_transaction(**self.confirmed())
        with self.assertRaises(OutcomeUnknownError):
            self.service.mf_save_draft(candidate["preview_id"])
        self.mf.fail_write = False
        duplicate = self.service.mf_create_transaction(**self.confirmed())
        with self.assertRaises(OutcomeUnknownError):
            self.service.mf_save_draft(duplicate["preview_id"])
        self.assertEqual(len(self.mf.writes), 1)


if __name__ == "__main__":
    unittest.main()
