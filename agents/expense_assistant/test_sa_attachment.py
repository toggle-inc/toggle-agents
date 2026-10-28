"""Source-bound attachment import tests. No service credentials, storage or MF I/O."""

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import quote

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_sa_approval as fixtures  # noqa: E402
from runtime.sa_attachment import SAAttachmentAdapter  # noqa: E402
from runtime.state import ExpenseError, State, digest  # noqa: E402


class SAAttachmentTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SAApprovalTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.service = self.fixture.service
        self.content = b"%PDF-1.4\nsynthetic receipt"
        self.item = {
            "id": "synthetic-file",
            "filename": "架空領収書.pdf",
            "contentType": "application/pdf",
            "size": len(self.content),
        }
        self.manifest = [copy.deepcopy(self.item)]
        self.headers = {
            "content-type": "application/octet-stream",
            "content-length": str(len(self.content)),
            "x-attachment-id": self.item["id"],
            "x-attachment-filename": quote(self.item["filename"], safe=""),
            "x-attachment-content-type": self.item["contentType"],
            "x-attachment-sha256": hashlib.sha256(self.content).hexdigest(),
        }
        self.status, self.calls = 200, []
        self.on_receive = lambda: None
        self.http = httpx.Client(transport=httpx.MockTransport(self.handle))
        self.addCleanup(self.http.close)
        self.adapter = self.make_adapter(self.manifest)

    def make_adapter(self, manifest):
        return SAAttachmentAdapter(
            self.service,
            self.fixture.adapter.origin,
            self.fixture.scope,
            manifest=manifest,
            verify_scope=self.fixture.adapter._verify,
            credential=self.fixture.adapter._credential,
            http=self.http,
            clock=lambda: self.fixture.fixture.now[0],
        )

    def handle(self, request):
        self.calls.append(request)
        self.on_receive()
        return httpx.Response(self.status, content=self.content, headers=self.headers)

    def test_frozen_manifest_import_and_persistent_source_binding(self):
        self.manifest[0]["filename"] = "changed.pdf"
        result = self.adapter.fetch(self.item["id"])
        self.assertTrue(result["path"].startswith("receipt:"))
        self.assertEqual(result["source_attachment_id"], self.item["id"])
        self.assertEqual(self.calls[0].headers["authorization"], "Bearer synthetic-read")
        self.assertIn(b"agentize-mention%3A", self.calls[0].url.raw_path)
        state = State(self.fixture.fixture.root / "state.sqlite", self.service.state.owner)
        try:
            metadata = state.source_receipt(
                self.adapter.origin, digest(self.fixture.scope), result["path"]
            )
            self.assertEqual(metadata["filename"], self.item["filename"])
            self.assertEqual(metadata["sha256"], hashlib.sha256(self.content).hexdigest())
            self.assertIsNone(
                state.source_receipt(
                    "https://other.example.test", digest(self.fixture.scope), result["path"]
                )
            )
        finally:
            state.close()
        self.assertEqual(self.fixture.fixture.mf.writes, [])

    def test_import_connects_source_attachment_to_human_approval_payload(self):
        result = self.adapter.fetch(self.item["id"])
        preview = self.service.mf_create_transaction(
            **self.fixture.fixture.create, receipt_path=result["path"]
        )
        self.fixture.adapter.propose(preview["preview_id"])
        payload = json.loads(self.fixture.rows[0]["payload"])
        self.assertEqual(payload["source_attachments"][0]["id"], self.item["id"])
        self.assertEqual(payload["source_attachments"][0]["sha256"], result["sha256"])
        self.assertEqual(self.fixture.fixture.mf.writes, [])

    def test_unbound_or_different_run_receipt_cannot_be_proposed(self):
        result = self.adapter.fetch(self.item["id"])
        preview = self.service.mf_create_transaction(
            **self.fixture.fixture.create, receipt_path=result["path"]
        )
        self.fixture.adapter.scope["runId"] = "another-run"
        self.fixture.scope["runId"] = "another-run"
        with self.assertRaises(ExpenseError):
            self.fixture.adapter.propose(preview["preview_id"])

    def test_unknown_or_injected_id_has_no_network_or_file_effect(self):
        for identifier in ("another-file", "../synthetic-file", "synthetic-file?other=1"):
            with self.subTest(identifier=identifier), self.assertRaises(ExpenseError):
                self.adapter.fetch(identifier)
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.fixture.fixture.files.root.iterdir()), [])

    def test_metadata_hash_size_and_type_mismatch_are_refused_without_saving(self):
        original = dict(self.headers)
        for changes in (
            {"x-attachment-id": "other"},
            {"x-attachment-filename": "other.pdf"},
            {"x-attachment-content-type": "text/html"},
            {"content-length": "1"},
            {"x-attachment-sha256": "0" * 64},
            {"content-type": "text/html"},
        ):
            self.headers = {**original, **changes}
            with self.subTest(changes=changes), self.assertRaises(ExpenseError):
                self.adapter.fetch(self.item["id"])
        self.assertEqual(list(self.fixture.fixture.files.root.iterdir()), [])

    def test_revocation_during_download_or_wrong_owner_does_not_save(self):
        self.on_receive = lambda: setattr(self.fixture, "active", False)
        with self.assertRaises(ExpenseError):
            self.adapter.fetch(self.item["id"])
        self.assertEqual(list(self.fixture.fixture.files.root.iterdir()), [])
        self.fixture.active = True
        self.fixture.fixture.files.owner = "another-owner"
        with self.assertRaises(ExpenseError):
            self.adapter.fetch(self.item["id"])
        self.assertEqual(list(self.fixture.fixture.files.root.iterdir()), [])

    def test_redirect_never_follows_or_discloses_body(self):
        self.status = 302
        self.headers["location"] = "https://other.example.test"
        with self.assertRaises(ExpenseError) as caught:
            self.adapter.fetch(self.item["id"])
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn("synthetic-read", str(caught.exception))

    def test_existing_ten_mib_limit_is_not_expanded_by_sa_transport(self):
        adapter = self.make_adapter([{**self.item, "size": 11 * 1024 * 1024}])
        with self.assertRaises(ExpenseError):
            adapter.fetch(self.item["id"])
        self.assertEqual(self.calls, [])

    def test_duplicate_manifest_and_wrong_magic_are_refused(self):
        with self.assertRaises(ExpenseError):
            self.make_adapter([self.item, self.item])
        self.content = b"<html>not a PDF</html>"
        self.headers["content-length"] = str(len(self.content))
        self.headers["x-attachment-sha256"] = hashlib.sha256(self.content).hexdigest()
        adapter = self.make_adapter([{**self.item, "size": len(self.content)}])
        with self.assertRaises(ExpenseError):
            adapter.fetch(self.item["id"])
        self.assertEqual(list(self.fixture.fixture.files.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
