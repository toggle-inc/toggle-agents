"""MF review replaces per-item UI only under explicit person/office initial consent."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_runtime as fixtures  # noqa: E402
from runtime.requester import OPERATIONS  # noqa: E402
from runtime.state import ExpenseError, OutcomeUnknownError, State  # noqa: E402


class DraftTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RuntimeTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.service, self.state = self.fixture.service, self.fixture.state

    def consent(self):
        self.state.set_draft_consent(["office-a"], "synthetic-consent")

    def test_save_without_per_item_approval_returns_verified_mf_list_link(self):
        self.consent()
        preview = self.service.mf_create_transaction(**self.fixture.create)
        result = self.service.call("mf_save_draft", {"preview_id": preview["preview_id"]})
        self.assertEqual(result["review_url"], "https://expense.moneyforward.com/transactions")
        self.assertEqual(result["review_company"], "架空商事A")
        self.assertTrue(result["created"])
        self.assertTrue(result["readback_verified"])
        self.assertFalse(result["submitted"])
        self.assertEqual(result["draft_status"], "saved_unsubmitted")
        self.assertIn("[MFで下書きを確認](" + result["review_url"] + ")", result["reply_text"])
        self.assertIn("会社選択", result["reply_text"])
        self.assertIn("申請はまだ提出していません", result["reply_text"])
        repeated = self.service.mf_save_draft(preview["preview_id"])
        self.assertEqual(result, repeated)
        self.assertEqual(len(self.fixture.mf.writes), 1)

    def test_missing_consent_other_office_revocation_and_readonly_never_write(self):
        preview = self.service.mf_create_transaction(**self.fixture.create)
        for setup in (
            lambda: None,
            lambda: self.state.set_draft_consent(["office-b"], "synthetic-other"),
            lambda: self.state.set_draft_consent(["office-a"], "synthetic-revoked", active=False),
        ):
            setup()
            with self.assertRaises(ExpenseError):
                self.service.mf_save_draft(preview["preview_id"])
        self.consent()
        self.service.write_enabled = False
        with self.assertRaises(ExpenseError):
            self.service.mf_save_draft(preview["preview_id"])
        self.assertEqual(self.fixture.mf.writes, [])

    def test_initial_draft_consent_does_not_allow_existing_edit_or_delete(self):
        self.consent()
        for method, args in (
            (self.service.mf_update_transaction, {"memo": "架空の変更"}),
            (self.service.mf_delete_transaction, {}),
        ):
            preview = method("office-a", "tx-a", **args)
            with self.assertRaises(ExpenseError):
                self.service.mf_save_draft(preview["preview_id"])
        self.assertEqual(self.fixture.mf.writes, [])

    def test_ocr_is_requested_once_and_returns_pending_not_complete(self):
        self.consent()
        reference = self.fixture.files.save(b"%PDF-1.4\nsynthetic receipt", "application/pdf")[
            "path"
        ]
        preview = self.service.mf_upload_receipt("office-a", reference)
        first = self.service.mf_save_draft(preview["preview_id"])
        self.assertEqual(first["draft_status"], "ocr_processing")
        self.assertTrue(first["ocr_pending"])
        self.assertIn("[MFで読取状況を確認](" + first["review_url"] + ")", first["reply_text"])
        self.assertIn("完了は未確認", first["reply_text"])
        self.assertNotIn("明細を保存しました", first["reply_text"])
        self.assertEqual(self.service.mf_save_draft(preview["preview_id"]), first)
        self.assertEqual([row[0] for row in self.fixture.mf.writes], ["upload"])

    def test_initial_consent_cannot_be_issued_by_model(self):
        for method in ("set_draft_consent", "draft_consent"):
            with self.assertRaises(ExpenseError):
                self.service.call(method, {})
        self.assertEqual(OPERATIONS["mf_save_draft"], "mf:draft")
        self.assertNotEqual(OPERATIONS["mf_save_draft"], OPERATIONS["mf_update_transaction"])

    def test_persisted_consent_and_completed_result_survive_restart(self):
        self.consent()
        preview = self.service.mf_create_transaction(**self.fixture.create)
        first = self.service.mf_save_draft(preview["preview_id"])
        self.state.close()
        self.state = State(
            self.fixture.root / "state.sqlite",
            self.fixture.mf.owner,
            clock=lambda: self.fixture.now[0],
        )
        self.service.state = self.fixture.state = self.state
        self.assertEqual(self.service.mf_save_draft(preview["preview_id"]), first)
        self.assertEqual(len(self.fixture.mf.writes), 1)
        self.state.set_draft_consent([], "synthetic-revoked", active=False)
        with self.assertRaises(ExpenseError):
            self.service.mf_save_draft(preview["preview_id"])

    def test_expired_candidate_and_unknown_outcome_are_not_resent(self):
        self.consent()
        expired = self.service.mf_create_transaction(**self.fixture.create)
        self.fixture.now[0] += 601
        with self.assertRaises(ExpenseError):
            self.service.mf_save_draft(expired["preview_id"])
        self.assertEqual(self.fixture.mf.writes, [])
        fresh = self.service.mf_create_transaction(**self.fixture.create)
        self.fixture.mf.fail_write = True
        for _ in range(2):
            with self.assertRaises(OutcomeUnknownError):
                self.service.mf_save_draft(fresh["preview_id"])
        self.assertEqual(len(self.fixture.mf.writes), 1)

    def test_revoked_consent_during_office_read_stops_before_financial_write(self):
        self.consent()
        preview = self.service.mf_create_transaction(**self.fixture.create)
        original = self.fixture.mf.offices

        def revoke():
            self.state.set_draft_consent([], "synthetic-consent", active=False)
            return original()

        with patch.object(self.fixture.mf, "offices", side_effect=revoke):
            with self.assertRaises(ExpenseError):
                self.service.mf_save_draft(preview["preview_id"])
        self.assertEqual(self.fixture.mf.writes, [])


if __name__ == "__main__":
    unittest.main()
