"""Receipt pipeline with real PNG/source verification and explicitly fake OCR.

No live network or MF calls. The stub builder isolates this service contract
from the independently developed OCR/parser and company-rule implementation.
"""

import copy
from dataclasses import replace
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image

from runtime.providers import Receipts
from runtime.requester import ConnectionGrant, OPERATIONS, RequesterDispatcher
from runtime.service import ExpenseService
from runtime.state import ExpenseError, State
from test_runtime import FakeMF
import test_sa_attachment_client as attachment_fixtures


class FakeOCR:
    """Synthetic extraction only: never evidence of actual image recognition."""

    def __init__(self):
        self.calls = []
        self.after_read = lambda: None
        self.result = {"text": "SYNTHETIC RECEIPT 321", "fake_ocr": True}

    def read(self, content, mime):
        self.calls.append((content, mime))
        self.after_read()
        return copy.deepcopy(self.result)


class StubDraftBuilder:
    def __init__(self):
        self.calls = []

    def build(self, result, reference, company):
        self.calls.append((copy.deepcopy(result), reference, company))
        return {"receipt_reference": reference, "company_key": company,
                "synthetic_extraction": copy.deepcopy(result), "needs_confirmation": True}


class ReceiptPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        attachment_fixtures.SAAttachmentClientTests.setUpClass()

    def setUp(self):
        self.source = attachment_fixtures.SAAttachmentClientTests()
        self.source.setUp()
        self.addCleanup(self.source.doCleanups)
        self.person = self.source.person
        output = io.BytesIO()
        Image.new("RGB", (32, 24), "white").save(output, format="PNG")
        self.png = output.getvalue()
        self.source.server.content = self.png
        self.source.server.item.update(filename="synthetic-receipt.png", contentType="image/png", size=len(self.png))
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.state = State(root / "state.sqlite", self.person.owner, clock=lambda: self.source.history.now)
        self.addCleanup(self.state.close)
        self.mf = FakeMF()
        self.mf.owner = self.person.owner
        self.files = Receipts(root / "files", self.source.client, self.person.owner)
        self.ocr, self.builder = FakeOCR(), StubDraftBuilder()
        self.service = ExpenseService(mf=self.mf, state=self.state, receipts=self.files,
            receipt_ocr=self.ocr, receipt_drafts=self.builder, receipt_company="trusted-company",
            write_enabled=True)
        self.grant = ConnectionGrant(self.person.tenant_id, self.person.person_id, 180,
            frozenset({"attachment:read"}), self.service, agent_slug="expense_assistant")
        self.dispatcher = RequesterDispatcher(lambda token: self.person if token == "alice" else None,
            lambda person, capability: self.grant, clock=lambda: self.source.history.now)

    def call(self, **arguments):
        return self.dispatcher.call("alice", "prepare_receipt_draft", arguments)

    def tearDown(self):
        self.assertEqual(self.mf.writes, [], "Preparing a local receipt draft must never write to MF")

    def assert_rejected_without_preview(self, arguments=None):
        with patch.object(self.state, "preview", wraps=self.state.preview) as preview:
            with self.assertRaises(ExpenseError):
                self.call(**(arguments or {}))
            preview.assert_not_called()

    def test_single_image_pipeline_preserves_bytes_and_commits_only_local_preview(self):
        result = self.call()
        self.assertEqual(self.ocr.calls, [(self.png, "image/png")])
        extracted, reference, company = self.builder.calls[0]
        self.assertEqual(extracted, self.ocr.result)
        self.assertEqual(company, "trusted-company")
        self.assertTrue(reference.startswith("receipt:"))
        details = self.state.preview_details(result["preview_id"])
        self.assertEqual((details["action"], details["office"]), ("receipt_draft", "trusted-company"))
        self.assertEqual(details["snapshot"]["receipt_reference"], reference)
        self.assertEqual(details["status"], "preview")
        self.assertIsNone(details["result"])
        for field in ("mf_registered", "submitted", "approved"):
            self.assertIs(result[field], False)
        self.assertEqual([request.url.path for request in self.source.server.calls], [
            attachment_fixtures.MANIFEST_PATH, attachment_fixtures.MANIFEST_PATH,
            attachment_fixtures.ATTACHMENT_PATH, attachment_fixtures.MANIFEST_PATH])

    def test_multiple_images_require_explicit_source_id(self):
        def multiple(manifest):
            items = manifest["attachments"]
            items.append({**items[0], "id": "file-b", "filename": "other.png"})
            manifest["manifestSha256"] = attachment_fixtures.sha(attachment_fixtures.encoded(items))
            return manifest
        self.source.server.manifest_transform = multiple
        self.assert_rejected_without_preview()
        self.assertEqual(self.ocr.calls, [])
        self.assertEqual(self.call(attachment_id="file-a")["company_key"], "trusted-company")

    def test_unknown_ids_urls_and_receipt_references_cannot_select_source(self):
        for identifier in ("file-b", "https://evil.example.test/a", "attachment:file-a", "../file-a", {"id": "file-a"}):
            with self.subTest(identifier=identifier):
                self.assert_rejected_without_preview({"attachment_id": identifier})
        self.assertEqual(self.ocr.calls, [])
        self.assertFalse(any(request.url.path == attachment_fixtures.ATTACHMENT_PATH
                             for request in self.source.server.calls))

    def test_acl_revoked_during_ocr_prevents_preview(self):
        self.ocr.after_read = lambda: setattr(self.source.server, "allowed", False)
        self.assert_rejected_without_preview()
        self.assertEqual(len(self.ocr.calls), 1)

    def test_source_expires_during_ocr_prevents_preview(self):
        self.ocr.after_read = lambda: setattr(self.source.history, "now", 181)
        self.assert_rejected_without_preview()
        self.assertEqual(len(self.ocr.calls), 1)

    def test_manifest_changes_after_ocr_prevent_preview(self):
        def change_source():
            self.source.server.item["filename"] = "replaced.png"
        self.ocr.after_read = change_source
        self.assert_rejected_without_preview()
        self.assertEqual(len(self.builder.calls), 1)

    def test_modified_download_is_rejected_before_ocr(self):
        self.source.server.attachment_headers["x-attachment-sha256"] = "0" * 64
        self.assert_rejected_without_preview()
        self.assertEqual(self.ocr.calls, [])
        self.assertEqual(self.builder.calls, [])

    def test_tool_arguments_cannot_override_company_rules_or_owner(self):
        for name, value in (("receipt_company", "other"), ("company", "other"), ("office", "other"),
                            ("rules", {}), ("receipt_drafts", {}), ("owner", "bob"),
                            ("person_id", "bob"), ("confirm", True)):
            with self.subTest(argument=name):
                self.assert_rejected_without_preview({name: value})
        self.assertEqual(self.source.server.calls, [])

    def test_dispatcher_requires_attachment_permission_and_matching_owner(self):
        self.assertEqual(OPERATIONS["prepare_receipt_draft"], "attachment:read")
        original = self.grant
        for grant in (replace(original, capabilities=frozenset({"mf:draft"})),
                      replace(original, person_id="bob"), replace(original, tenant_id="other"),
                      replace(original, revoked=True), replace(original, expires_at=100)):
            with self.subTest(grant=grant):
                self.grant = grant
                self.assert_rejected_without_preview()
        self.grant = original
        self.files.owner = "another-owner"
        self.assert_rejected_without_preview()
        self.assertEqual(self.source.server.calls, [])

    def test_cross_person_source_binding_never_reads_attachment(self):
        self.source.context.set(replace(self.source.binding, person_id="canonical-bob"))
        self.assert_rejected_without_preview()
        self.assertEqual(self.source.server.calls, [])

    def test_repeated_calls_create_distinct_unapproved_previews_without_mf_write(self):
        first, second = self.call(), self.call()
        self.assertNotEqual(first["preview_id"], second["preview_id"])
        self.assertEqual(len(self.ocr.calls), 2)
        for result in (first, second):
            self.assertIs(result["mf_registered"], False)
            self.assertIs(result["submitted"], False)
            self.assertIs(result["approved"], False)
            self.assertEqual(self.state.preview_details(result["preview_id"])["status"], "preview")

    def test_missing_trusted_dependencies_fail_before_source_access(self):
        for name in ("receipt_ocr", "receipt_drafts", "receipt_company"):
            with self.subTest(dependency=name), patch.object(self.service, name, None):
                self.assert_rejected_without_preview()
        self.assertEqual(self.source.server.calls, [])

    def test_ocr_or_builder_failure_never_creates_preview(self):
        for component, method in ((self.ocr, "read"), (self.builder, "build")):
            with self.subTest(component=type(component).__name__), patch.object(
                    component, method, side_effect=ExpenseError("synthetic extraction failure")):
                self.assert_rejected_without_preview()


if __name__ == "__main__":
    unittest.main()
