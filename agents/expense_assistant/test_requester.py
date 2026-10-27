"""Synthetic host only. No real JWT verification, OAuth, MF or Engine calls."""

import concurrent.futures
import dataclasses
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from runtime.providers import Receipts  # noqa: E402
from runtime.requester import (  # noqa: E402
    OPERATIONS,
    AuthorizationRequiredError,
    ConnectionGrant,
    Requester,
    RequesterDispatcher,
    access_contract,
)
from runtime.service import ExpenseService  # noqa: E402
from runtime.state import ExpenseError, State  # noqa: E402


class SyntheticMF:
    def __init__(self, owner, label):
        self.owner, self.label, self.calls = owner, label, 0

    def offices(self):
        self.calls += 1
        return [{"id": self.label, "name": self.label}]

    def list_transactions(self, office, page):
        return {"ex_transactions": [{"id": "synthetic", "value": 100}]}


class SyntheticCalendar:
    def __init__(self, label):
        self.label = label

    def events(self, date_from, date_to):
        return [{"summary": self.label}]


class RequesterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.now = 100
        self.people = {name: Requester("test-tenant", name, 200) for name in ("alice", "bob")}
        self.contexts = {object(): person for person in self.people.values()}
        self.handles = {p.person_id: context for context, p in self.contexts.items()}
        self.grants = {}
        for name, person in self.people.items():
            root = Path(self.directory.name) / person.owner
            service = ExpenseService(
                mf=SyntheticMF(person.owner, name),
                state=State(root / "state.sqlite", person.owner, clock=lambda: self.now),
                receipts=Receipts(root / "receipts", None, person.owner),
                calendar=SyntheticCalendar(name),
            )
            self.addCleanup(service.state.db.close)
            self.grants[name] = ConnectionGrant(
                person.tenant_id,
                name,
                200,
                frozenset(OPERATIONS.values()) | {"receipt:read"},
                service,
                agent_slug="expense_assistant",
            )
        self.dispatcher = RequesterDispatcher(
            lambda context: self.contexts.get(context),
            lambda person, capability: self.grants.get(person.person_id),
            clock=lambda: self.now,
        )

    def call(self, who, operation="mf_offices", **arguments):
        return self.dispatcher.call(self.handles[who], operation, arguments)

    def test_two_people_same_dispatcher_use_only_their_connection(self):
        for name in self.people:
            self.assertEqual(self.call(name)[0]["id"], name)
            self.assertEqual(self.grants[name].service.mf.calls, 1)

    def test_unlinked_user_never_falls_back_to_another_user(self):
        del self.grants["bob"]
        with self.assertRaises(AuthorizationRequiredError):
            self.call("bob")
        self.assertEqual(self.grants["alice"].service.mf.calls, 0)

    def test_calendar_uses_own_connection_and_requires_its_own_permission(self):
        for name in self.people:
            rows = self.call(name, "calendar_events", date_from="2030-01-01", date_to="2030-01-02")
            self.assertEqual(rows[0]["summary"], name)
        self.grants["bob"] = dataclasses.replace(
            self.grants["bob"], capabilities=frozenset({"mf:read"})
        )
        with self.assertRaises(AuthorizationRequiredError):
            self.call("bob", "calendar_events", date_from="2030-01-01", date_to="2030-01-02")

    def test_host_errors_do_not_disclose_credentials(self):
        def unavailable(*args):
            raise RuntimeError("synthetic-secret-do-not-disclose")

        for dispatcher in (
            RequesterDispatcher(unavailable, unavailable),
            RequesterDispatcher(lambda _: self.people["alice"], unavailable),
        ):
            with self.assertRaises(ExpenseError) as caught:
                dispatcher.call(self.handles["alice"], "mf_offices", {})
            self.assertNotIn("synthetic-secret", str(caught.exception))

    def test_context_and_tool_arguments_cannot_select_identity(self):
        with self.assertRaises(ExpenseError):
            self.dispatcher.call("alice", "mf_offices", {})
        for field in ("owner", "person_id", "tenant_id", "connection_id", "token"):
            with self.subTest(field=field), self.assertRaises(ExpenseError):
                self.call("alice", **{field: "bob"})

    def test_wrong_owner_or_tenant_grant_is_refused(self):
        grant = self.grants["alice"]
        for bad in (
            self.grants["bob"],
            dataclasses.replace(grant, tenant_id="other-tenant"),
            dataclasses.replace(grant, agent_slug="another-agent"),
            dataclasses.replace(grant, service=self.grants["bob"].service),
        ):
            self.grants["alice"] = bad
            with self.assertRaises(ExpenseError):
                self.call("alice")
        self.assertEqual(self.grants["bob"].service.mf.calls, 0)

    def test_revocation_expiry_and_capability_checked_on_every_call(self):
        grant = self.grants["alice"]
        self.call("alice")
        for bad in (
            dataclasses.replace(grant, revoked=True),
            dataclasses.replace(grant, expires_at=100),
            dataclasses.replace(grant, expires_at=float("nan")),
            dataclasses.replace(grant, capabilities=frozenset({"calendar:read"})),
        ):
            self.grants["alice"] = bad
            with self.assertRaises(AuthorizationRequiredError):
                self.call("alice")
        self.assertEqual(grant.service.mf.calls, 1)

    def test_nonhuman_or_expired_identity_is_refused(self):
        original = self.people["alice"]
        for change in (
            {"kind": "admin"},
            {"kind": "service"},
            {"expires_at": 100},
            {"expires_at": float("inf")},
            {"tenant_id": ""},
        ):
            self.contexts[self.handles["alice"]] = dataclasses.replace(original, **change)
            with self.assertRaises(ExpenseError):
                self.call("alice")

    def test_person_memory_and_receipts_are_separate(self):
        self.call("alice", "propose_teaching", kind="preference", content="synthetic-a")
        a, b = (self.grants[name].service for name in ("alice", "bob"))
        self.assertNotEqual(a.receipts.root, b.receipts.root)
        receipt = a.receipts.save(b"%PDF-1.4\nsynthetic", "application/pdf")
        self.assertEqual(
            self.dispatcher.read_receipt(self.handles["alice"], receipt["path"])["content_type"],
            "application/pdf",
        )
        with self.assertRaises(ExpenseError):
            self.dispatcher.read_receipt(self.handles["bob"], receipt["path"])
        self.assertEqual(b.state.db.execute("SELECT count(*) FROM facts").fetchone()[0], 0)

    def test_receipt_resource_requires_current_personal_consent(self):
        grant = self.grants["alice"]
        reference = grant.service.receipts.save(b"%PDF-1.4\nsynthetic", "application/pdf")["path"]
        for bad in (
            dataclasses.replace(grant, revoked=True),
            dataclasses.replace(grant, capabilities=frozenset({"mf:read"})),
        ):
            self.grants["alice"] = bad
            with self.assertRaises(AuthorizationRequiredError):
                self.dispatcher.read_receipt(self.handles["alice"], reference)

    def test_approval_of_one_person_cannot_execute_for_another(self):
        a, b = (self.grants[name].service.state for name in ("alice", "bob"))
        preview = a.preview("create", "synthetic-office", {"amount": 100})
        a.approve(preview["preview_id"], preview["preview_digest"])
        with self.assertRaises(ExpenseError):
            b.execute(
                preview["preview_id"],
                "create",
                "synthetic-office",
                {"amount": 100},
                lambda: self.fail("cross-user write"),
            )

    def test_connection_consent_is_not_financial_write_approval(self):
        self.grants["alice"].service.write_enabled = True
        with self.assertRaisesRegex(ExpenseError, "プレビュー|承認"):
            self.call(
                "alice",
                "mf_delete_transaction",
                office="alice",
                transaction_id="synthetic",
                confirm=True,
                preview_id="",
            )

    def test_concurrent_calls_have_no_global_current_user(self):
        names = ["alice", "bob"] * 25
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(self.call, names))
        self.assertEqual([row[0]["id"] for row in results], names)

    def test_same_person_id_in_different_tenants_has_different_owner(self):
        person = self.people["alice"]
        self.assertNotEqual(person.owner, dataclasses.replace(person, tenant_id="other").owner)

    def test_contract_has_no_deployment_or_personal_identifiers(self):
        self.assertEqual(access_contract()["capabilities"], OPERATIONS)
        self.assertNotIn("alice", str(access_contract()))


if __name__ == "__main__":
    unittest.main()
