"""Full source-owned flow with synthetic SA HTTP and MF, never live financial I/O."""

import copy
import datetime as dt
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_runtime as fixtures  # noqa: E402
from runtime.sa_approval import SAApprovalAdapter  # noqa: E402
from runtime.sa_attachment import SAAttachmentAdapter  # noqa: E402
from runtime.state import ExpenseError  # noqa: E402


class ReceiptWorkflowTests(unittest.TestCase):
    def setUp(self):
        # MockTransport and FakeMF must be the only transports in this flow.
        network = patch("socket.socket.connect", side_effect=AssertionError("live network forbidden"))
        network.start()
        self.addCleanup(network.stop)
        self.fixture = fixtures.RuntimeTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.service = self.fixture.service
        self.scope = {
            "invocationId": "agentize-mention:" + "b" * 64,
            "requesterEmployeeId": "synthetic-person",
            "runId": "synthetic-run",
            "harnessSessionId": 1,
            "managedAgentVersionId": 2,
            "tenantId": 3,
            "managedAgentId": 4,
            "sourceMessageId": "synthetic-message",
            "rootMessageId": "synthetic-root",
            "sourceChannelId": "synthetic-channel",
        }
        self.approvals, self.posts, self.requests = {}, [], []
        # Synthetic signature bytes, never a real receipt or an OCR model input.
        self.content = b"\x89PNG\r\n\x1a\nsynthetic receipt image"
        self.file = {
            "id": "synthetic-file",
            "filename": "架空領収書.png",
            "contentType": "image/png",
            "size": len(self.content),
        }
        self.http = httpx.Client(transport=httpx.MockTransport(self.handle))
        self.addCleanup(self.http.close)
        trusted_scope, trusted_owner = copy.deepcopy(self.scope), self.fixture.state.owner
        self.active = True
        options = dict(
            verify_scope=lambda scope, owner: self.active and scope == trusted_scope
            and owner == trusted_owner,
            credential=lambda mode: "synthetic-service-" + mode,
            http=self.http,
            clock=lambda: self.fixture.now[0],
        )
        self.adapter = SAApprovalAdapter(
            self.service, "https://sa.example.test", self.scope, **options
        )
        self.attachments = SAAttachmentAdapter(
            self.service, "https://sa.example.test", self.scope, manifest=[self.file], **options
        )

        def upload(office, payload):
            self.fixture.mf.writes.append(("upload", office, copy.deepcopy(payload)))
            row = self.fixture.mf.rows[office][0]
            row.update(
                {
                    "automatic_status": "waiting_for_ocr_input",
                    "mf_file": {"id": "mf-synthetic-file"},
                }
            )
            return {
                "mf_files": [{"id": "mf-synthetic-file"}],
                "ex_transactions": [{"id": row["id"]}],
            }

        self.fixture.mf.upload_receipt = upload

    def handle(self, request):
        self.requests.append(request)
        if "/attachments/" in request.url.path:
            return httpx.Response(
                200,
                content=self.content,
                headers={
                    "content-type": "application/octet-stream",
                    "content-length": str(len(self.content)),
                    "x-attachment-id": self.file["id"],
                    "x-attachment-filename": quote(self.file["filename"], safe=""),
                    "x-attachment-content-type": self.file["contentType"],
                    "x-attachment-sha256": hashlib.sha256(self.content).hexdigest(),
                },
            )
        if request.method == "POST":
            body = json.loads(request.content)
            identifier = "event-" + body["previewId"]
            row = {
                **body,
                "id": identifier,
                "invocationId": self.scope["invocationId"],
                "contentDigest": hashlib.sha256(body["payload"].encode()).hexdigest(),
                "decision": None,
                "decidedAt": None,
                "decidedById": None,
            }
            self.approvals[identifier] = row
            self.posts.append(body)
            return httpx.Response(
                200,
                json={
                    "scope": self.scope,
                    "approval": row,
                    "approvalPath": "/chat/agent-approvals/" + identifier,
                },
            )
        return httpx.Response(
            200,
            json={
                "protocol": "success-assist-managed-approval/v1",
                "scope": self.scope,
                "approvals": list(self.approvals.values()),
            },
        )

    def decide(self, proposed, decision="APPROVED"):
        self.approvals[proposed["approval_id"]].update(
            {
                "decision": decision,
                "decidedById": self.scope["requesterEmployeeId"],
                "decidedAt": dt.datetime.fromtimestamp(self.fixture.now[0], dt.timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
            }
        )

    def start_ocr(self):
        reference = self.attachments.fetch(self.file["id"])["path"]
        preview = self.service.mf_upload_receipt("office-a", reference)
        before = self.service.mf_receipt_status(preview["preview_id"])
        self.assertEqual(before["status"], "not_submitted")
        self.assertFalse(before["ocr_complete"])
        proposed = self.adapter.propose(preview["preview_id"])
        visible = json.loads(self.posts[-1]["payload"])
        self.assertEqual(visible["office_id"], "office-a")
        self.assertEqual(visible["snapshot"]["office"]["name"], "架空商事A")
        self.assertEqual(visible["source_attachments"][0]["id"], self.file["id"])
        self.assertEqual(
            visible["source_attachments"][0]["sha256"], hashlib.sha256(self.content).hexdigest()
        )
        self.assertEqual(self.fixture.mf.writes, [])
        with self.assertRaises(ExpenseError):
            self.adapter.execute_approved(preview["preview_id"], proposed["approval_id"])
        self.decide(proposed)
        self.approvals[proposed["approval_id"]]["decidedById"] = "another-person"
        with self.assertRaises(ExpenseError):
            self.adapter.execute_approved(preview["preview_id"], proposed["approval_id"])
        self.assertEqual(self.fixture.mf.writes, [])
        self.decide(proposed)
        result = self.adapter.execute_approved(preview["preview_id"], proposed["approval_id"])
        self.assertTrue(result["uploaded"])
        self.assertTrue(result["ocr_pending"])
        self.assertEqual(self.fixture.mf.writes[0][1], "office-a")
        self.assertEqual(self.fixture.mf.writes[0][2]["content_type"], "image/png")
        self.assertEqual(self.fixture.mf.writes[0][2]["process_type"], "2")
        return reference, preview

    def assert_mf_review(self, result):
        self.assertEqual(result["review_url"], "https://expense.moneyforward.com/transactions")
        self.assertEqual(result["review_link_kind"], "transaction_list")
        self.assertEqual(result["review_company"], "架空商事A")
        self.assertEqual(result["review_office_id"], "office-a")
        self.assertFalse(result["submitted"])
        self.assertIn("会社", result["next_step"])

    def assert_no_duplicate(self, reference):
        writes = copy.deepcopy(self.fixture.mf.writes)
        # Refetching identical bytes changes the local reference, not the receipt identity.
        refetched = self.attachments.fetch(self.file["id"])["path"]
        self.assertNotEqual(reference, refetched)
        for office in ("office-a", "office-b"):
            for action in ("upload", "create"):
                with self.subTest(office=office, duplicate_action=action):
                    duplicate = (
                        self.service.mf_upload_receipt(office, refetched)
                        if action == "upload"
                        else self.service.mf_create_transaction(
                            **{**self.fixture.create, "office": office}, receipt_path=refetched
                        )
                    )
                    proposed = self.adapter.propose(duplicate["preview_id"])
                    self.decide(proposed)
                    with self.assertRaisesRegex(ExpenseError, "同じ領収書"):
                        self.adapter.execute_approved(duplicate["preview_id"], proposed["approval_id"])
        self.assertEqual(self.fixture.mf.writes, writes)

    def test_attachment_ocr_readback_second_consent_and_update_use_same_ledger(self):
        reference, uploaded = self.start_ocr()
        status = self.service.mf_receipt_status(uploaded["preview_id"])
        self.assertEqual(status["status"], "processing")
        self.assertFalse(status["ocr_complete"])
        self.assert_mf_review(status)
        with self.assertRaises(ExpenseError):
            self.service.mf_update_transaction("office-a", "tx-a", memo="補正")
        row = self.fixture.mf.rows["office-a"][0]
        row.update(
            {"automatic_status": "input_done", "invoice_registration_number": "T0000000000000"}
        )
        status = self.service.mf_receipt_status(uploaded["preview_id"])
        self.assertTrue(status["ocr_complete"])
        self.assertTrue(status["human_confirmation_required"])
        self.assertEqual(status["transactions"][0]["invoice_registration_number"], "T0000000000000")
        self.assertEqual(status["transactions"][0]["receipt_file_id"], "mf-synthetic-file")
        self.assert_mf_review(status)
        change = {
            "office": "office-a",
            "transaction_id": status["transactions"][0]["id"],
            "invoice_registration_number": "T0000000000001",
            "memo": "本人確認後の架空補正",
        }
        preview = self.service.mf_update_transaction(**change)
        proposed = self.adapter.propose(preview["preview_id"])
        visible = json.loads(self.posts[-1]["payload"])
        self.assertEqual(
            visible["snapshot"]["payload"]["invoice_registration_number"],
            change["invoice_registration_number"],
        )
        with self.assertRaises(ExpenseError):
            self.adapter.execute_approved(preview["preview_id"], proposed["approval_id"])
        self.decide(proposed)
        result = self.adapter.execute_approved(preview["preview_id"], proposed["approval_id"])
        self.assertTrue(result["readback_verified"])
        self.assertEqual(
            result["transaction"]["invoice_registration_number"],
            change["invoice_registration_number"],
        )
        self.assertEqual([row[0] for row in self.fixture.mf.writes], ["upload", "update"])
        self.assertEqual(self.fixture.mf.writes[-1][2]["invoice_registration_number"], "T0000000000001")
        self.assert_no_duplicate(reference)

    def test_unverified_attachment_identity_or_company_stops_before_ocr(self):
        for scope_key in ("requesterEmployeeId", "runId", "sourceMessageId"):
            with self.subTest(scope_key=scope_key):
                with patch.dict(self.attachments.scope, {scope_key: "another-source"}):
                    with self.assertRaises(ExpenseError):
                        self.attachments.fetch(self.file["id"])
        self.active = False
        with self.assertRaises(ExpenseError):
            self.attachments.fetch(self.file["id"])
        self.active = True
        with patch.object(self.fixture.files, "owner", "another-owner"):
            with self.assertRaises(ExpenseError):
                self.attachments.fetch(self.file["id"])
        with self.assertRaises(ExpenseError):
            self.attachments.fetch("another-attachment")
        self.assertEqual(self.requests, [])
        self.assertEqual(list(self.fixture.files.root.iterdir()), [])
        reference = self.attachments.fetch(self.file["id"])["path"]
        for office in ("", "架空商事", "not-owned"):
            with self.subTest(office=office), self.assertRaises(ExpenseError):
                self.service.mf_upload_receipt(office, reference)
        self.assertEqual(self.fixture.mf.writes, [])
        # Recovering valid host identity/company can continue through the same flow.
        self.start_ocr()

    def test_missing_ocr_invoice_is_not_filled_from_history_or_correction(self):
        reference, uploaded = self.start_ocr()
        # A similar historical merchant is not evidence for this receipt's number.
        historical = copy.deepcopy(self.fixture.mf.rows["office-a"][0])
        historical.update(id="historical-tx", invoice_registration_number="T0000000000009")
        self.fixture.mf.rows["office-a"].append(historical)
        row = self.fixture.mf.rows["office-a"][0]
        row["automatic_status"] = "input_done"
        for unknown in (None, ""):
            with self.subTest(unknown=unknown):
                row["invoice_registration_number"] = unknown
                status = self.service.mf_receipt_status(uploaded["preview_id"])
                self.assertTrue(status["ocr_complete"])
                self.assertTrue(status["human_confirmation_required"])
                self.assertEqual(status["transactions"][0]["invoice_registration_number"], unknown)
                self.assert_mf_review(status)
                preview = self.service.mf_update_transaction("office-a", "tx-a", memo="本人確認済み補足")
                self.assertNotIn("invoice_registration_number", preview["preview"])
                proposed = self.adapter.propose(preview["preview_id"])
                self.decide(proposed)
                result = self.adapter.execute_approved(preview["preview_id"], proposed["approval_id"])
                self.assertTrue(result["readback_verified"])
                self.assertEqual(result["transaction"]["invoice_registration_number"], unknown)
                self.assertNotIn("invoice_registration_number", self.fixture.mf.writes[-1][2])
        self.assert_no_duplicate(reference)

    def test_initial_company_consent_image_ocr_and_mf_review_without_item_approval(self):
        reference = self.attachments.fetch(self.file["id"])["path"]
        preview = self.service.mf_upload_receipt("office-a", reference)
        for offices, active in ((None, True), (["office-b"], True), (["office-a"], False)):
            with self.subTest(offices=offices, active=active):
                if offices is not None:
                    self.fixture.state.set_draft_consent(offices, "synthetic-consent", active=active)
                with self.assertRaises(ExpenseError):
                    self.service.mf_save_draft(preview["preview_id"])
        self.assertEqual(self.fixture.mf.writes, [])
        self.fixture.state.set_draft_consent(["office-a"], "synthetic-consent")
        result = self.service.mf_save_draft(preview["preview_id"])
        self.assertTrue(result["ocr_pending"])
        self.assertEqual(result["draft_status"], "ocr_processing")
        self.assert_mf_review(result)
        self.assertEqual(self.service.mf_save_draft(preview["preview_id"]), result)
        self.assertEqual(self.service.mf_receipt_status(preview["preview_id"])["status"], "processing")
        self.fixture.mf.rows["office-a"][0].update(
            automatic_status="input_done", invoice_registration_number="T0000000000000"
        )
        status = self.service.mf_receipt_status(preview["preview_id"])
        self.assertTrue(status["ocr_complete"])
        self.assertTrue(status["human_confirmation_required"])
        self.assertEqual(status["transactions"][0]["invoice_registration_number"], "T0000000000000")
        self.assert_mf_review(status)
        self.assertEqual(self.posts, [])
        self.assertEqual([row[0] for row in self.fixture.mf.writes], ["upload"])
        self.assert_no_duplicate(reference)

    def test_declined_correction_does_not_reuse_ocr_upload_approval(self):
        _, uploaded = self.start_ocr()
        self.fixture.mf.rows["office-a"][0]["automatic_status"] = "input_done"
        self.assertTrue(self.service.mf_receipt_status(uploaded["preview_id"])["ocr_complete"])
        preview = self.service.mf_update_transaction("office-a", "tx-a", memo="却下する架空補正")
        proposed = self.adapter.propose(preview["preview_id"])
        self.decide(proposed, "DENIED")
        with self.assertRaises(ExpenseError):
            self.adapter.execute_approved(preview["preview_id"], proposed["approval_id"])
        self.assertEqual([row[0] for row in self.fixture.mf.writes], ["upload"])


if __name__ == "__main__":
    unittest.main()
