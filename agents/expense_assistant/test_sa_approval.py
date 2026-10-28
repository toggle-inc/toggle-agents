"""Synthetic SA HTTP + real local approval ledger; no external credentials or writes."""

import copy
import datetime as dt
import hashlib
import json
import sys
import unittest
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_runtime as fixtures  # noqa: E402
from runtime.sa_approval import SAApprovalAdapter  # noqa: E402
from runtime.state import ExpenseError, digest  # noqa: E402


class SAApprovalTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RuntimeTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.service = self.fixture.service
        self.scope = {
            "invocationId": "agentize-mention:" + "a" * 64,
            "requesterEmployeeId": "synthetic-person",
            "runId": "synthetic-run",
            "harnessSessionId": 12,
            "managedAgentVersionId": 34,
            "tenantId": 56,
            "managedAgentId": 78,
            "sourceMessageId": "synthetic-message",
            "rootMessageId": "synthetic-root",
            "sourceChannelId": "synthetic-channel",
        }
        self.active = True
        self.calls, self.rows = [], []
        self.mutate = lambda data: data
        self.http = httpx.Client(transport=httpx.MockTransport(self.handle))
        self.addCleanup(self.http.close)
        self.adapter = SAApprovalAdapter(
            self.service,
            "https://sa.example.test",
            self.scope,
            verify_scope=lambda scope, owner: self.active
            and scope == self.scope
            and owner == self.fixture.state.owner,
            credential=lambda mode: "synthetic-" + mode,
            http=self.http,
            clock=lambda: self.fixture.now[0],
        )

    def handle(self, request):
        self.calls.append(request)
        if request.method == "POST":
            row = {
                **json.loads(request.content),
                "id": "synthetic-approval",
                "invocationId": self.scope["invocationId"],
                "decision": None,
                "decidedAt": None,
                "decidedById": None,
            }
            row["contentDigest"] = hashlib.sha256(row["payload"].encode()).hexdigest()
            self.rows = [row]
            data = {
                "scope": copy.deepcopy(self.scope),
                "approval": copy.deepcopy(row),
                "approvalPath": "/chat/agent-approvals/synthetic-approval",
            }
        else:
            data = {
                "protocol": "success-assist-managed-approval/v1",
                "scope": copy.deepcopy(self.scope),
                "approvals": copy.deepcopy(self.rows),
            }
        return httpx.Response(200, json=self.mutate(data))

    def propose(self, *, receipt=False):
        args = dict(self.fixture.create)
        if receipt:
            args["receipt_path"] = self.fixture.files.save(
                b"%PDF-1.4\nsynthetic receipt", "application/pdf"
            )["path"]
            self.service.state.bind_source_receipt(
                self.adapter.origin,
                digest(self.scope),
                args["receipt_path"],
                {
                    "id": "synthetic-file",
                    "filename": "synthetic.pdf",
                    "contentType": "application/pdf",
                    "size": len(b"%PDF-1.4\nsynthetic receipt"),
                    "sha256": hashlib.sha256(b"%PDF-1.4\nsynthetic receipt").hexdigest(),
                },
            )
        self.preview = self.service.mf_create_transaction(**args)
        return self.adapter.propose(self.preview["preview_id"])

    def decide(self):
        self.rows[0].update(
            {
                "decision": "APPROVED",
                "decidedById": self.scope["requesterEmployeeId"],
                "decidedAt": dt.datetime.fromtimestamp(self.fixture.now[0], dt.timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
            }
        )

    def execute(self):
        return self.adapter.execute_approved(self.preview["preview_id"], "synthetic-approval")

    def test_proposal_only_shows_exact_content_and_never_self_approves(self):
        result = self.propose(receipt=True)
        self.assertFalse(result["approved"])
        self.assertEqual(
            result["approval_url"],
            "https://sa.example.test/chat/agent-approvals/synthetic-approval",
        )
        payload = json.loads(self.rows[0]["payload"])
        receipt = payload["snapshot"]["payload"]["receipt_input"]
        self.assertNotIn("content", receipt)
        self.assertEqual(
            receipt["content_sha256"], hashlib.sha256(b"%PDF-1.4\nsynthetic receipt").hexdigest()
        )
        self.assertEqual(payload["office_id"], "office-a")
        self.assertEqual(payload["snapshot"]["payload"]["value"], self.fixture.create["value"])
        self.assertEqual(self.fixture.mf.writes, [])
        with self.assertRaises(ExpenseError):
            self.execute()
        self.assertEqual(self.fixture.mf.writes, [])

    def test_real_host_path_uses_only_stored_intent_after_verified_human_decision(self):
        self.propose()
        self.decide()
        result = self.execute()
        self.assertTrue(result["created"])
        self.assertTrue(result["readback_verified"])
        self.assertEqual(len(self.fixture.mf.writes), 1)
        self.assertEqual(self.calls[0].headers["authorization"], "Bearer synthetic-write")
        self.assertEqual(self.calls[1].headers["authorization"], "Bearer synthetic-read")
        self.assertEqual(self.calls[1].headers["x-agentize-harness-session-id"], "12")
        self.assertEqual(
            self.calls[1].url.path,
            "/api/integrations/agentize/chat/managed-invocations/"
            + self.scope["invocationId"]
            + "/approvals",
        )
        self.assertIn(b"agentize-mention%3A", self.calls[1].url.raw_path)
        with self.assertRaises(ExpenseError):
            self.execute()
        self.assertEqual(len(self.fixture.mf.writes), 1)

    def test_different_actor_denial_missing_decision_and_expiry_do_not_approve(self):
        self.propose()
        self.decide()
        original = copy.deepcopy(self.rows[0])
        for changes in (
            {"decidedById": "another-person"},
            {"decision": "DENIED"},
            {"decision": None},
            {"decidedAt": None},
            {"decidedAt": "2099-01-01T00:00:00Z"},
        ):
            with self.subTest(changes=changes):
                self.rows[0] = {**original, **changes}
                with self.assertRaises(ExpenseError):
                    self.execute()
        self.rows[0] = original
        self.fixture.now[0] += 3601
        with self.assertRaises(ExpenseError):
            self.execute()
        self.assertEqual(self.fixture.mf.writes, [])

    def test_scope_actor_run_version_source_tampering_is_rejected(self):
        self.propose()
        self.decide()
        for key in self.scope:

            def mutate(data, key=key):
                data["scope"][key] = "other"
                return data

            self.mutate = mutate
            with self.subTest(field=key), self.assertRaises(ExpenseError):
                self.execute()
        self.assertEqual(self.fixture.mf.writes, [])

    def test_snapshot_digest_payload_or_event_tampering_is_rejected(self):
        self.propose()
        self.decide()
        original = copy.deepcopy(self.rows[0])
        for changes in (
            {"payload": "{}"},
            {"previewDigest": "0" * 64},
            {"previewId": "other-preview"},
            {"contentDigest": "0" * 64},
            {"invocationId": "other-invocation"},
            {"expiresAt": "2099-01-01T00:00:00Z"},
        ):
            with self.subTest(changes=changes):
                self.rows[0] = {**original, **changes}
                with self.assertRaises(ExpenseError):
                    self.execute()
        self.assertEqual(self.fixture.mf.writes, [])

    def test_revocation_during_network_read_is_rechecked_before_local_approval(self):
        self.propose()
        self.decide()

        def revoke(data):
            self.active = False
            return data

        self.mutate = revoke
        with self.assertRaises(ExpenseError):
            self.execute()
        self.assertEqual(self.fixture.mf.writes, [])

    def test_redirect_and_error_bodies_do_not_leak_credentials_or_approve(self):
        self.propose()
        self.decide()
        for status in (301, 401, 404, 500):

            def bad(request, status=status):
                return httpx.Response(
                    status,
                    headers={"location": "https://other.example.test"},
                    text="synthetic-secret-do-not-leak",
                )

            with httpx.Client(transport=httpx.MockTransport(bad)) as http:
                self.adapter.http = http
                with self.subTest(status=status), self.assertRaises(ExpenseError) as caught:
                    self.execute()
                self.assertNotIn("synthetic-secret", str(caught.exception))
        self.assertEqual(self.fixture.mf.writes, [])

    def test_host_only_methods_cannot_be_called_by_model_dispatch(self):
        for method in (
            "preview_details",
            "execute_approved",
            "propose",
            "approve",
            "approve_external",
            "withdraw_unused_approval",
            "bind_source_receipt",
            "source_receipt",
            "fetch",
        ):
            with self.subTest(method=method), self.assertRaises(ExpenseError):
                self.service.call(method, {})

    def test_refused_execution_does_not_leave_a_standalone_local_approval(self):
        self.propose()
        self.decide()
        self.service.write_enabled = False
        with self.assertRaises(ExpenseError):
            self.execute()
        self.service.write_enabled = True
        with self.assertRaises(ExpenseError):
            self.service.mf_create_transaction(
                **self.fixture.create, confirm=True, preview_id=self.preview["preview_id"]
            )
        self.assertEqual(self.fixture.mf.writes, [])

    def test_same_external_event_cannot_be_reassigned_to_another_preview(self):
        self.propose()
        self.decide()
        self.service.write_enabled = False
        with self.assertRaises(ExpenseError):
            self.execute()
        self.service.write_enabled = True
        self.propose()
        self.decide()
        with self.assertRaises(ExpenseError):
            self.execute()
        self.assertEqual(self.fixture.mf.writes, [])

    def test_missing_root_or_malformed_invocation_never_constructs_a_bridge(self):
        for changes in (
            {"rootMessageId": None},
            {"invocationId": "../other"},
            {"invocationId": "agentize-mention:" + "a" * 63},
        ):
            with self.subTest(changes=changes), self.assertRaises(ExpenseError):
                SAApprovalAdapter(
                    self.service,
                    "https://sa.example.test",
                    {**self.scope, **changes},
                    verify_scope=lambda *args: True,
                    credential=lambda _: "synthetic",
                    http=self.http,
                )


if __name__ == "__main__":
    unittest.main()
