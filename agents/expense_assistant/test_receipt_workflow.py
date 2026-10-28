"""Full source-owned flow with synthetic SA HTTP and MF, never live financial I/O."""

import copy
import datetime as dt
import hashlib
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import quote

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_runtime as fixtures  # noqa: E402
from runtime.sa_approval import SAApprovalAdapter  # noqa: E402
from runtime.sa_attachment import SAAttachmentAdapter  # noqa: E402
from runtime.state import ExpenseError  # noqa: E402


class ReceiptWorkflowTests(unittest.TestCase):
    def setUp(self):
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
        self.approvals, self.posts = {}, []
        self.content = b"%PDF-1.4\nsynthetic receipt"
        self.file = {
            "id": "synthetic-file",
            "filename": "架空領収書.pdf",
            "contentType": "application/pdf",
            "size": len(self.content),
        }
        self.http = httpx.Client(transport=httpx.MockTransport(self.handle))
        self.addCleanup(self.http.close)
        options = dict(
            verify_scope=lambda scope, owner: scope == self.scope
            and owner == self.fixture.state.owner,
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
        proposed = self.adapter.propose(preview["preview_id"])
        self.assertEqual(self.fixture.mf.writes, [])
        with self.assertRaises(ExpenseError):
            self.adapter.execute_approved(preview["preview_id"], proposed["approval_id"])
        self.decide(proposed)
        result = self.adapter.execute_approved(preview["preview_id"], proposed["approval_id"])
        self.assertTrue(result["uploaded"])
        self.assertTrue(result["ocr_pending"])
        return reference, preview

    def test_attachment_ocr_readback_second_consent_and_update_use_same_ledger(self):
        reference, uploaded = self.start_ocr()
        status = self.service.mf_receipt_status(uploaded["preview_id"])
        self.assertEqual(status["status"], "processing")
        with self.assertRaises(ExpenseError):
            self.service.mf_update_transaction("office-a", "tx-a", memo="補正")
        row = self.fixture.mf.rows["office-a"][0]
        row.update(
            {"automatic_status": "input_done", "invoice_registration_number": "T0000000000000"}
        )
        status = self.service.mf_receipt_status(uploaded["preview_id"])
        self.assertTrue(status["ocr_complete"])
        self.assertTrue(status["human_confirmation_required"])
        change = {
            "office": "office-a",
            "transaction_id": status["transactions"][0]["id"],
            "invoice_registration_number": "T0000000000001",
            "memo": "本人確認後の架空補正",
        }
        preview = self.service.mf_update_transaction(**change)
        proposed = self.adapter.propose(preview["preview_id"])
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
        # Even a separately approved new create must not duplicate this OCR receipt.
        duplicate = self.service.mf_create_transaction(
            **self.fixture.create, receipt_path=reference
        )
        proposed = self.adapter.propose(duplicate["preview_id"])
        self.decide(proposed)
        with self.assertRaises(ExpenseError):
            self.adapter.execute_approved(duplicate["preview_id"], proposed["approval_id"])
        self.assertEqual([row[0] for row in self.fixture.mf.writes], ["upload", "update"])

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
