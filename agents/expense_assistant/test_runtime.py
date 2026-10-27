"""Full operation-parity and safety tests with synthetic providers, never live MF."""

import copy
import datetime as dt
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from runtime.providers import (  # noqa: E402
    Calendar,
    Fares,
    MFClient,
    PrivatePolicy,
    Receipts,
    SafeFetch,
)
from runtime.service import ORIGINAL_TOOLS, ExpenseService  # noqa: E402
from runtime.state import ExpenseError, OutcomeUnknownError, State  # noqa: E402


class FakeMF:
    owner = "synthetic-owner"

    def __init__(self):
        self.writes = []
        self.fail_write = False
        self.rows = {
            "office-a": [
                {
                    "id": "tx-a",
                    "recognized_at": "2030-01-15",
                    "value": 321,
                    "remark": "架空の訪問先",
                    "memo": "駅A -> 駅B",
                    "ex_item": {"name": "旅費交通費"},
                    "ex_item_id": "item-a",
                    "project": {"name": "架空案件"},
                    "project_id": "project-a",
                }
            ],
            "office-b": [],
        }

    def authorize_url(self):
        return "https://identity.example.test/consent"

    def complete_auth(self, code_or_url):
        return {"saved": True}

    def offices(self):
        return [{"id": "office-a", "name": "架空商事A"}, {"id": "office-b", "name": "架空商事B"}]

    def list_transactions(self, office, page):
        return {"ex_transactions": copy.deepcopy(self.rows[office]), "next": None}

    def list_reports(self, office, page):
        return {
            "ex_reports": [{"number": "synthetic-report", "title": "架空の事前申請"}],
            "next": None,
        }

    def create_transaction(self, office, payload):
        self.writes.append(("create", office, copy.deepcopy(payload)))
        if self.fail_write:
            raise OutcomeUnknownError("synthetic unknown outcome")
        row = {**payload, "id": "synthetic-created"}
        self.rows[office].append(row)
        return {"ex_transaction": copy.deepcopy(row)}

    def update_transaction(self, office, identifier, payload):
        self.writes.append(("update", office, copy.deepcopy(payload)))
        row = next(row for row in self.rows[office] if row["id"] == identifier)
        row.update(payload)
        return {"ex_transaction": copy.deepcopy(row)}

    def delete_transaction(self, office, identifier):
        self.writes.append(("delete", office, identifier))
        self.rows[office] = [row for row in self.rows[office] if row["id"] != identifier]
        return {}

    def upload_receipt(self, office, payload):
        self.writes.append(("upload", office, copy.deepcopy(payload)))
        return {"accepted": True}

    def download_receipt(self, office, identifier):
        return b"%PDF-1.4\nsynthetic receipt", "application/pdf"


class FakePolicy:
    version = "synthetic-policy-v1"

    def check(self, **fields):
        return ["架空の注意点"] if fields["value"] > 900 else []


class FakeFetch:
    def __init__(self, content=b"%PDF-1.4\nsynthetic receipt", mime="application/pdf"):
        self.content, self.mime = content, mime

    def get(self, url, **kwargs):
        return self.content, self.mime


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.now = [dt.datetime(2030, 2, 20, tzinfo=dt.timezone.utc).timestamp()]
        self.state = State(self.root / "state.sqlite", FakeMF.owner, clock=lambda: self.now[0])
        self.mf, self.policy = FakeMF(), FakePolicy()
        self.files = Receipts(self.root / "files", FakeFetch(), FakeMF.owner)
        self.service = ExpenseService(
            mf=self.mf,
            state=self.state,
            policy=self.policy,
            receipts=self.files,
            write_enabled=True,
            fares=Fares(
                FakeFetch('<div id="route01">IC優先 321円 25分 乗換1回</div>'.encode(), "text/html")
            ),
        )
        self.create = {
            "office": "office-a",
            "recognized_at": "2030-01-15",
            "value": 321,
            "remark": "架空の訪問先",
            "ex_item_id": "item-a",
            "ex_item_name": "旅費交通費",
            "memo": "駅A -> 駅B（synthetic:fare）",
        }

    def tearDown(self):
        self.state.close()
        self.temporary.cleanup()

    def approve(self, preview):
        self.state.approve(preview["preview_id"], preview["preview_digest"])

    def test_all_sixteen_original_operations_exist(self):
        expected = {
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
        }
        self.assertEqual(set(ORIGINAL_TOOLS), expected)
        self.assertTrue(all(callable(getattr(self.service, name)) for name in expected))

    def test_auth_and_offices(self):
        self.assertIn("consent", self.service.mf_auth_url())
        self.assertEqual(self.service.mf_auth_complete("synthetic-code"), {"saved": True})
        self.assertEqual(len(self.service.mf_offices()), 2)

    def test_reads_known_items_and_reports(self):
        self.assertEqual(
            len(self.service.mf_list_transactions("架空商事A", "2030-01-01", "2030-01-31")), 1
        )
        self.assertEqual(
            self.service.mf_known_items("office-a")["ex_items"][0]["ex_item_id"], "item-a"
        )
        self.assertEqual(self.service.mf_list_reports("office-a")[0]["number"], "synthetic-report")
        self.assertEqual(self.mf.writes, [])

    def test_ambiguous_or_unowned_company_is_refused(self):
        for company in ("架空商事", "not-owned"):
            with self.subTest(company=company), self.assertRaises(ExpenseError):
                self.service.mf_known_items(company)

    def test_pagination_limit_is_not_silently_treated_as_full_history(self):
        with patch.object(
            self.mf, "list_transactions", return_value={"ex_transactions": [], "next": True}
        ):
            with self.assertRaises(ExpenseError):
                self.service.mf_known_items("office-a")

    def test_payee_memory_and_missing_months_stay_company_scoped(self):
        for date in ("2029-11-20", "2029-12-20", "2030-01-20"):
            self.mf.rows["office-a"].append(
                {
                    "id": date,
                    "recognized_at": date,
                    "value": 432,
                    "remark": "架空定期サービス",
                    "invoice_registration_number": "SYNTHETIC-INVOICE-A",
                    "ex_item": {"name": "通信費"},
                }
            )
        self.mf.rows["office-b"].append(
            {
                "id": "other",
                "recognized_at": "2030-02-10",
                "value": 999,
                "remark": "架空定期サービス",
                "invoice_registration_number": "SYNTHETIC-INVOICE-B",
            }
        )
        memory = self.service.mf_payee_memory()
        self.assertEqual(len(memory["出し忘れの候補"]), 1)
        self.assertEqual(memory["出し忘れの候補"][0]["会社"], ["架空商事A"])
        self.assertEqual(memory["出し忘れの候補"][0]["登録番号"], ["SYNTHETIC-INVOICE-A"])

    def test_preview_never_writes_and_confirm_true_does_not_self_authorize(self):
        preview = self.service.mf_create_transaction(**self.create)
        self.assertFalse(preview["created"])
        self.assertEqual(preview["form"]["fields"][0]["value"], "架空商事A")
        with self.assertRaises(ExpenseError):
            self.service.mf_create_transaction(
                **self.create, confirm=True, preview_id=preview["preview_id"]
            )
        self.assertEqual(self.mf.writes, [])

    def test_read_only_live_profile_blocks_even_a_trusted_approved_write(self):
        self.service.write_enabled = False
        preview = self.service.mf_create_transaction(**self.create)
        self.approve(preview)
        with self.assertRaises(ExpenseError):
            self.service.mf_create_transaction(
                **self.create, confirm=True, preview_id=preview["preview_id"]
            )
        self.assertEqual(self.mf.writes, [])

    def test_approved_create_is_durable_and_idempotent(self):
        preview = self.service.mf_create_transaction(**self.create)
        self.approve(preview)
        first = self.service.mf_create_transaction(
            **self.create, confirm=True, preview_id=preview["preview_id"]
        )
        second = self.service.mf_create_transaction(
            **self.create, confirm=True, preview_id=preview["preview_id"]
        )
        self.assertTrue(first["created"])
        self.assertEqual(first, second)
        self.assertEqual(len(self.mf.writes), 1)

    def test_approval_cannot_change_company_amount_policy_or_expiry(self):
        for field in ("company", "amount", "policy", "expiry"):
            with self.subTest(field=field):
                preview = self.service.mf_create_transaction(**self.create)
                self.approve(preview)
                request = self.create.copy()
                if field == "company":
                    request["office"] = "office-b"
                elif field == "amount":
                    request["value"] = 654
                elif field == "policy":
                    self.policy.version = "synthetic-policy-v2"
                else:
                    self.now[0] += 601
                with self.assertRaises(ExpenseError):
                    self.service.mf_create_transaction(
                        **request, confirm=True, preview_id=preview["preview_id"]
                    )
                self.policy.version = "synthetic-policy-v1"
        self.assertEqual(self.mf.writes, [])

    def test_unknown_write_is_not_retried_even_after_reopening_state(self):
        preview = self.service.mf_create_transaction(**self.create)
        self.approve(preview)
        self.mf.fail_write = True
        with self.assertRaises(OutcomeUnknownError):
            self.service.mf_create_transaction(
                **self.create, confirm=True, preview_id=preview["preview_id"]
            )
        self.state.close()
        self.state = State(self.root / "state.sqlite", FakeMF.owner, clock=lambda: self.now[0])
        self.service.state = self.state
        with self.assertRaises(OutcomeUnknownError):
            self.service.mf_create_transaction(
                **self.create, confirm=True, preview_id=preview["preview_id"]
            )
        self.assertEqual(len(self.mf.writes), 1)

    def test_two_process_connections_cannot_execute_the_same_approval_twice(self):
        import concurrent.futures
        import threading

        second = State(self.root / "state.sqlite", FakeMF.owner, clock=lambda: self.now[0])
        snapshot = {"intent": {"synthetic": True}}
        preview = self.state.preview("create", "office-a", snapshot)
        self.approve(preview)
        entered, release = threading.Event(), threading.Event()
        writes = []

        def write():
            writes.append("one")
            entered.set()
            if not release.wait(5):
                raise AssertionError("test release timed out")
            return {"created": True}

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                future = pool.submit(
                    self.state.execute, preview["preview_id"], "create", "office-a", snapshot, write
                )
                try:
                    self.assertTrue(entered.wait(5))
                    with self.assertRaises(OutcomeUnknownError):
                        second.execute(preview["preview_id"], "create", "office-a", snapshot, write)
                finally:
                    release.set()
                self.assertEqual(future.result(timeout=5), {"created": True})
                self.assertEqual(
                    second.execute(preview["preview_id"], "create", "office-a", snapshot, write),
                    {"created": True},
                )
            self.assertEqual(writes, ["one"])
        finally:
            second.close()

    def test_update_and_delete_are_previewed_approved_and_idempotent(self):
        change = {"office": "office-a", "transaction_id": "tx-a", "memo": "本人が直した経路"}
        preview = self.service.mf_update_transaction(**change)
        self.assertFalse(preview["updated"])
        self.approve(preview)
        self.assertTrue(
            self.service.mf_update_transaction(
                **change, confirm=True, preview_id=preview["preview_id"]
            )["updated"]
        )
        self.service.mf_update_transaction(**change, confirm=True, preview_id=preview["preview_id"])
        preview = self.service.mf_delete_transaction("office-a", "tx-a")
        self.assertFalse(preview["deleted"])
        self.approve(preview)
        self.assertTrue(
            self.service.mf_delete_transaction("office-a", "tx-a", True, preview["preview_id"])[
                "deleted"
            ]
        )
        self.service.mf_delete_transaction("office-a", "tx-a", True, preview["preview_id"])
        self.assertEqual([row[0] for row in self.mf.writes], ["update", "delete"])

    def test_submitted_or_other_persons_transactions_cannot_be_modified(self):
        self.mf.rows["office-a"][0]["ex_report"] = {"number": "synthetic-submitted"}
        for operation in ("mf_update_transaction", "mf_delete_transaction"):
            with self.subTest(operation=operation), self.assertRaises(ExpenseError):
                self.service.call(operation, {"office": "office-a", "transaction_id": "tx-a"})
        with self.assertRaises(ExpenseError):
            self.service.mf_delete_transaction("office-b", "tx-a")

    def test_attachment_download_receipt_and_ocr(self):
        downloaded = self.service.fetch_attachment("https://files.example.test/receipt.pdf")
        self.assertTrue(downloaded["path"].startswith("receipt:"))
        previous = self.service.mf_get_receipt("office-a", "tx-a")
        preview = self.service.mf_upload_receipt("office-a", previous["path"])
        self.assertFalse(preview["uploaded"])
        self.approve(preview)
        result = self.service.mf_upload_receipt(
            "office-a", previous["path"], True, preview["preview_id"]
        )
        self.assertTrue(result["uploaded"])
        self.assertTrue(result["ocr_pending"])
        self.assertEqual(self.mf.writes[0][2]["process_type"], "2")

    def test_receipt_file_changes_invalidate_approval(self):
        reference = self.service.fetch_attachment("https://files.example.test/receipt.pdf")["path"]
        preview = self.service.mf_upload_receipt("office-a", reference)
        self.approve(preview)
        (self.files.root / reference.split(":", 1)[1]).write_bytes(b"%PDF-1.4\nchanged")
        with self.assertRaises(ExpenseError):
            self.service.mf_upload_receipt("office-a", reference, True, preview["preview_id"])
        self.assertEqual(self.mf.writes, [])

    def test_local_paths_and_other_owners_receipts_are_refused(self):
        other = Receipts(self.root / "files", FakeFetch(), "different-synthetic-owner")
        reference = other.save(b"%PDF-1.4\nsynthetic receipt", "application/pdf")["path"]
        for value in ("/etc/passwd", "receipt:../../config", reference):
            with self.subTest(reference=value), self.assertRaises(ExpenseError):
                self.files.payload(value)

    def test_mismatched_owner_and_state_cannot_be_reused(self):
        with self.assertRaises(ExpenseError):
            State(self.root / "state.sqlite", "different-synthetic-owner")
        self.mf.owner = "different-synthetic-owner"
        with self.assertRaises(ExpenseError):
            ExpenseService(mf=self.mf, state=self.state)

    def test_missing_policy_does_not_mean_rules_passed(self):
        self.service.policy = None
        with self.assertRaises(ExpenseError):
            self.service.mf_create_transaction(**self.create)
        self.assertEqual(self.mf.writes, [])

    def test_incomplete_amount_is_a_missing_form_field_not_a_guessed_charge(self):
        self.create["value"] = 0
        preview = self.service.mf_create_transaction(**self.create)
        field = next(row for row in preview["form"]["fields"] if row["key"] == "value")
        self.assertIsNone(field["value"])
        self.assertFalse(preview["form"]["ready"])
        self.approve(preview)
        with self.assertRaises(ExpenseError):
            self.service.mf_create_transaction(
                **self.create, confirm=True, preview_id=preview["preview_id"]
            )
        self.assertEqual(self.mf.writes, [])

    def test_missing_capabilities_and_references_are_explicit(self):
        for operation, arguments in (
            ("calendar_events", {"date_from": "2030-01-01", "date_to": "2030-01-31"}),
            ("read_reference", {}),
        ):
            with self.subTest(operation=operation), self.assertRaises(ExpenseError):
                self.service.call(operation, arguments)

    def test_future_transaction_is_pending_not_written(self):
        self.create["recognized_at"] = "2031-01-01"
        with self.assertRaises(ExpenseError):
            self.service.mf_create_transaction(**self.create)

    def test_guessed_fields_do_not_authorize_a_registration(self):
        preview = self.service.mf_create_transaction(
            **self.create, sources={"value": "推測・要確認"}
        )
        by_key = {row["key"]: row for row in preview["form"]["fields"]}
        self.assertEqual(by_key["value"]["status"], "guess")
        self.assertFalse(preview["form"]["ready"])
        self.approve(preview)
        with self.assertRaises(ExpenseError):
            self.service.mf_create_transaction(
                **self.create,
                sources={"value": "推測・要確認"},
                confirm=True,
                preview_id=preview["preview_id"],
            )
        self.assertEqual(self.mf.writes, [])

    def test_teachings_require_confirmation_and_never_override_write_guard(self):
        proposed = self.service.propose_teaching("commuter_pass", "架空駅Aと架空駅Bの間は定期区間")
        self.assertEqual(self.state.facts()[0]["status"], "proposed")
        self.state.accept_fact(proposed["id"])
        self.assertEqual(self.service.expense_context()["teachings"][0]["status"], "active")
        self.state.retire_fact(proposed["id"])
        self.assertEqual(self.state.facts()[0]["status"], "retired")
        for operation in ("approve", "accept_fact", "execute"):
            with self.assertRaises(ExpenseError):
                self.service.call(operation, {})
        with self.assertRaises(ExpenseError):
            self.service.call("mf_offices", {"owner": "another-person"})

    def test_secrets_are_not_saved_as_teachings(self):
        for content in (
            "パスワードを覚える",
            "token synthetic",
            "口座の番号",
            "https://private.example.test",
        ):
            with self.subTest(content=content), self.assertRaises(ExpenseError):
                self.state.propose_fact("preference", content)

    def test_weekly_suggestion_limit_and_context_exclusions(self):
        self.assertTrue(self.state.suggestion_due())
        for flag in ("heartbeat", "urgent", "failed"):
            self.assertFalse(self.state.suggestion_due(**{flag: True}))
        self.state.mark_suggestion()
        self.assertFalse(self.state.suggestion_due())
        self.now[0] += 7 * 86400
        self.assertTrue(self.state.suggestion_due())

    def test_future_pending_returns_after_due_date_and_can_be_completed(self):
        fact = self.service.propose_teaching(
            "pending", "架空の訪問後に移動実績を確認", "2030-03-01"
        )
        self.state.accept_fact(fact["id"])
        self.assertEqual(self.service.expense_context()["pending_due"], [])
        self.now[0] += 30 * 86400
        self.assertEqual(len(self.service.expense_context()["pending_due"]), 1)
        self.state.complete_pending(fact["id"])
        self.assertEqual(self.service.expense_context()["pending_due"], [])

    def test_fare_lookup_includes_source_and_does_not_parse_advertisement(self):
        result = self.service.fare_lookup("架空駅A", "架空駅B", "2030-01-15")
        self.assertEqual(result["routes"][0]["fare_yen"], 321)
        self.assertIn("transit.yahoo.co.jp", result["source_url"])
        self.assertEqual(Fares.parse_routes("広告 999円"), [])

    def test_fare_comments_and_whitespace_do_not_select_commuter_pass_price(self):
        page = (
            '<div id="route01"><li>乗換：<span>0<!-- -->回</span></li>'
            '<li class="fare">IC優先：<span>321<!-- -->円</span></li>'
            "<div>定期券 1か月 9,999 円</div></div>"
        )
        result = Fares.parse_routes(page)
        self.assertEqual(result[0]["fare_yen"], 321)
        self.assertEqual(result[0]["transfers"], 0)

    def test_private_policy_is_hash_pinned_without_copying_it_to_public_source(self):
        path = self.root / "synthetic_policy.py"
        path.write_text("def check(**fields):\n    return ['synthetic-rule']\n")
        policy = PrivatePolicy(path, hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(policy.check(value=123), ["synthetic-rule"])
        path.write_text("def check(**fields):\n    return []\n")
        with self.assertRaises(ExpenseError):
            policy.check(value=123)

    def test_reference_traversal_is_refused(self):
        self.service.references = self.root / "refs"
        self.service.references.mkdir()
        (self.service.references / "index.md").write_text("架空の非公開資料")
        self.policy.references = PrivatePolicy.references.__get__(self.policy)
        self.assertIn("架空", self.service.read_reference()["text"])
        with self.assertRaises(ExpenseError):
            self.service.read_reference("../outside.md")


class ProviderTests(unittest.TestCase):
    def test_ssrf_private_hosts_ports_and_redirect_targets_are_not_allowed(self):
        fetch = SafeFetch(("files.example.test",))
        for url in (
            "http://files.example.test/a",
            "https://127.0.0.1/a",
            "https://files.example.test:8443/a",
            "https://user:pass@files.example.test/a",
            "https://metadata.google.internal/a",
        ):
            with self.subTest(url=url), self.assertRaises(ExpenseError):
                fetch.get(url)
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]):
            with self.assertRaises(ExpenseError):
                fetch.get("https://files.example.test/a")

    def test_calendar_recurrence_timezone_all_day_and_cancelled(self):
        calendar = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:synthetic-visit\r\n"
            "DTSTART:20300115T000000Z\r\nDTEND:20300115T010000Z\r\nRRULE:FREQ=DAILY;COUNT=2\r\n"
            "SUMMARY:架空の訪問\r\nLOCATION:架空の会場\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\n"
            "UID:synthetic-cancel\r\nDTSTART:20300115T040000Z\r\nDTEND:20300115T050000Z\r\n"
            "STATUS:CANCELLED\r\nSUMMARY:中止\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        provider = Calendar(
            "https://calendar.example.test/synthetic.ics",
            FakeFetch(calendar.encode(), "text/calendar"),
        )
        events = provider.events("2030-01-15", "2030-01-16")
        self.assertEqual(len(events), 2)
        self.assertTrue(all(event["start"].endswith("+09:00") for event in events))
        self.assertEqual(events[0]["start"], "2030-01-15T09:00+09:00")

    def test_oauth_state_owner_file_permissions_refresh_and_no_secret_response(self):
        import httpx

        calls = []

        def handle(request):
            calls.append(request)
            if request.url.path == "/oauth/token":
                return httpx.Response(
                    200,
                    json={
                        "access_token": "synthetic-access",
                        "refresh_token": "synthetic-refresh",
                        "expires_in": 3600,
                    },
                )
            return httpx.Response(
                200, json={"offices": [{"id": "synthetic-office", "name": "架空商事"}]}
            )

        with tempfile.TemporaryDirectory() as directory:
            http = httpx.Client(
                base_url="https://expense.moneyforward.com", transport=httpx.MockTransport(handle)
            )
            vault = Path(directory) / "oauth.json"
            now = [1000]
            client = MFClient(
                "synthetic-client",
                "synthetic-secret",
                vault,
                "synthetic-owner",
                http=http,
                clock=lambda: now[0],
                redirect_uri="https://callback.example.test/oauth",
            )
            from urllib.parse import parse_qs, urlsplit

            consent = client.authorize_url()
            state = parse_qs(urlsplit(consent).query)["state"][0]
            with self.assertRaises(ExpenseError):
                client.complete_auth(
                    "https://callback.example.test/oauth?code=synthetic-code&state=wrong"
                )
            self.assertEqual(calls, [])
            result = client.complete_auth(
                f"https://callback.example.test/oauth?code=synthetic-code&state={state}"
            )
            self.assertTrue(result["saved"])
            self.assertNotIn("access_token", result)
            self.assertEqual(os.stat(vault).st_mode & 0o777, 0o600)
            self.assertEqual(client.offices()[0]["id"], "synthetic-office")
            now[0] += 4000
            client.offices()
            self.assertEqual(sum(request.url.path == "/oauth/token" for request in calls), 2)
            other = MFClient(
                "synthetic-client", "synthetic-secret", vault, "different-owner", http=http
            )
            with self.assertRaises(ExpenseError):
                other.offices()

    def test_mf_api_paths_and_write_errors_do_not_retry(self):
        import httpx

        calls = []

        def handle(request):
            calls.append(request)
            return httpx.Response(503, text="must-not-leak-response-body")

        with tempfile.TemporaryDirectory() as directory:
            http = httpx.Client(
                base_url="https://expense.moneyforward.com", transport=httpx.MockTransport(handle)
            )
            client = MFClient(
                "synthetic-client",
                "synthetic-secret",
                Path(directory) / "oauth.json",
                "synthetic-owner",
                http=http,
                clock=lambda: 1000,
            )
            client._save(
                {
                    "oauth": {
                        "access_token": "synthetic-access",
                        "expires_in": 3600,
                        "obtained_at": 1000,
                    }
                }
            )
            with self.assertRaises(OutcomeUnknownError) as caught:
                client.create_transaction("office-a", {"value": 321})
            self.assertNotIn("must-not-leak", str(caught.exception))
            self.assertEqual(len(calls), 1)
            self.assertEqual(
                calls[0].url.path, "/api/external/v1/offices/office-a/me/ex_transactions"
            )

    def test_mcp_exposes_operations_but_not_trusted_approval_methods(self):
        import asyncio

        import mcp_server

        with tempfile.TemporaryDirectory() as directory:
            state = State(Path(directory) / "state.sqlite", FakeMF.owner)
            try:
                service = ExpenseService(mf=FakeMF(), state=state)
                server = mcp_server.create_server(service)
                tools = asyncio.run(server.list_tools())
                names = {tool.name for tool in tools}
                self.assertTrue(set(ORIGINAL_TOOLS).issubset(names))
                self.assertFalse({"approve", "accept_fact", "execute"} & names)
                create = next(tool for tool in tools if tool.name == "mf_create_transaction")
                self.assertIn("preview_id", create.input_schema["properties"])
                self.assertNotIn("owner", create.input_schema["properties"])
                result = asyncio.run(server.call_tool("mf_offices", {}))
                self.assertFalse(result.is_error)
                self.assertIn("架空商事A", str(result))
                with patch.object(state, "facts", side_effect=AssertionError("private data read")):
                    contract = asyncio.run(server.call_tool("delivery_contract", {}))
                self.assertFalse(contract.is_error)
                self.assertIn("authenticated_requester_only", str(contract))
                self.assertIn("platform_bindings", str(contract))
            finally:
                state.close()

    def test_mcp_stdio_protocol_round_trip_uses_the_same_service(self):
        import asyncio

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        with tempfile.TemporaryDirectory() as directory:
            factory = Path(directory) / "synthetic_profile.py"
            factory.write_text(
                "import sys\nfrom pathlib import Path\n"
                f"sys.path.insert(0, {str(HERE)!r})\n"
                "from test_runtime import FakeMF\n"
                "from runtime.service import ExpenseService\n"
                "from runtime.state import State\n"
                "def create_service():\n"
                f"    state = State({str(Path(directory) / 'state.sqlite')!r}, FakeMF.owner)\n"
                "    return ExpenseService(mf=FakeMF(), state=state)\n"
            )

            async def round_trip():
                parameters = StdioServerParameters(
                    command=sys.executable,
                    args=[str(HERE / "mcp_server.py"), "--factory", str(factory)],
                )
                async with stdio_client(parameters) as (reader, writer):
                    async with ClientSession(reader, writer) as session:
                        await session.initialize()
                        tools = await session.list_tools()
                        self.assertTrue(
                            set(ORIGINAL_TOOLS).issubset({tool.name for tool in tools.tools})
                        )
                        result = await session.call_tool("mf_offices", {})
                        self.assertFalse(result.is_error)
                        self.assertIn("架空商事A", str(result))

            asyncio.run(round_trip())

    def test_mcp_receipt_resource_has_original_bytes_and_mime_type(self):
        import asyncio

        import mcp_server

        with tempfile.TemporaryDirectory() as directory:
            state = State(Path(directory) / "state.sqlite", FakeMF.owner)
            try:
                receipts = Receipts(Path(directory) / "files", FakeFetch(), FakeMF.owner)
                service = ExpenseService(mf=FakeMF(), state=state, receipts=receipts)
                saved = receipts.save(b"%PDF-1.4\nsynthetic receipt", "application/pdf")
                server = mcp_server.create_server(service)
                result = asyncio.run(server.read_resource(saved["resource_uri"]))
                self.assertEqual(result[0].content, b"%PDF-1.4\nsynthetic receipt")
                self.assertEqual(result[0].mime_type, "application/pdf")
            finally:
                state.close()


if __name__ == "__main__":
    unittest.main()
