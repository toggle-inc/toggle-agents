"""Synthetic ledgers/callbacks only. Never calls MF, Cloud Run or Engine."""

import concurrent.futures
import contextlib
import copy
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.fernet import Fernet
from runtime.auth_store import SQLiteAuthorizationStore
from runtime.durable_state import DurableState
from runtime.requester import Requester
from runtime.service import ExpenseService
from runtime.state import ExpenseError, OutcomeUnknownError, State
import test_runtime as runtime_fixture
import test_drafts as draft_fixture


class FaultStore:
    """Serializable fake with failures before and after commit acknowledgements."""

    def __init__(self):
        self.rows, self.lock = {}, threading.RLock()
        self.fail_writes = False
        self.fail_on_status = None
        self.after_commit = False
        self.cipher = None

    @contextlib.contextmanager
    def transaction(self):
        with self.lock:
            before = copy.deepcopy(self.rows)
            failed = False
            try:
                yield self
                if self.cipher and self.fail_on_status and self.rows != before:
                    for row in self.rows.values():
                        data = json.loads(self.cipher.decrypt(row["ciphertext"].encode()))["data"]
                        failed |= any(p["status"] == self.fail_on_status for p in data["previews"].values())
                if failed and not self.after_commit:
                    raise RuntimeError("synthetic-commit-failure")
            except BaseException:
                self.rows = before
                raise
            if failed:
                raise RuntimeError("synthetic-commit-acknowledgement-lost")

    def get(self, key):
        return copy.deepcopy(self.rows.get(key))

    def put(self, key, value):
        if self.fail_writes:
            raise RuntimeError("synthetic-storage-unavailable")
        self.rows[key] = copy.deepcopy(value)


class DurableStateTests(unittest.TestCase):
    def setUp(self):
        self.key, self.store, self.now = Fernet.generate_key(), FaultStore(), 100
        self.people = {name: Requester("synthetic-tenant", name, 1000) for name in ("alice", "bob")}
        self.store.cipher = Fernet(self.key)
        self.state = self.make()
        self.snapshot = {"intent": {"value": 123}, "receipt_fingerprint": "a" * 64}

    def make(self, who="alice", namespace="synthetic-state", key=None):
        return DurableState(self.store, key or self.key, self.people[who].owner,
                            namespace, clock=lambda: self.now)

    def preview(self, state=None, action="create", office="office-a", snapshot=None, approve=True):
        state = state or self.state
        value = self.snapshot if snapshot is None else snapshot
        p = state.preview(action, office, value)
        if approve:
            state.approve(p["preview_id"], p["preview_digest"])
        return p

    def execute(self, p, write=None, state=None, action="create", office="office-a", snapshot=None):
        return (state or self.state).execute(p["preview_id"], action, office,
                                            self.snapshot if snapshot is None else snapshot,
                                            write or (lambda: {"created": True}))

    def test_public_state_method_surface_is_supported_without_db(self):
        methods = {name for name in dir(State) if not name.startswith('_') and callable(getattr(State, name))}
        self.assertTrue(all(callable(getattr(self.state, name)) for name in methods))
        self.assertFalse(hasattr(self.state, 'db'))

    def test_person_namespace_key_isolation_and_no_plaintext(self):
        p = self.preview()
        for other in (self.make("bob"), self.make(namespace="another")):
            with self.assertRaises(ExpenseError):
                other.preview_details(p["preview_id"])
        self.assertNotIn('receipt_fingerprint', json.dumps(self.store.rows))
        self.assertNotIn('office-a', json.dumps(self.store.rows))
        self.assertEqual(self.execute(self.preview(self.make("bob")), state=self.make("bob")), {"created": True})

    def test_other_owner_namespace_and_wrong_key_ciphertext_swap_rejected(self):
        self.preview()
        alice_row = copy.deepcopy(self.store.rows[self.state._key])
        for other in (self.make("bob"), self.make(namespace="another")):
            self.store.rows[other._key] = alice_row
            with self.assertRaises(ExpenseError):
                other.facts()
        with self.assertRaises(ExpenseError):
            self.make(key=Fernet.generate_key()).facts()
        self.store.rows[self.state._key] = {"ciphertext": "invalid"}
        with self.assertRaises(ExpenseError):
            self.state.facts()

    def test_done_replay_is_read_only_even_after_expiry_and_checks_exact_content(self):
        p, write = self.preview(), Mock(return_value={"id": "synthetic"})
        self.assertEqual(self.execute(p, write), {"id": "synthetic"})
        self.now += 1000
        self.assertEqual(self.execute(p, write, state=self.make()), {"id": "synthetic"})
        self.assertEqual(write.call_count, 1)
        for kwargs in ({"office": "office-b"}, {"action": "upload"}, {"snapshot": {"intent": {"value": 124}}}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ExpenseError):
                self.execute(p, write, **kwargs)
        self.assertEqual(self.state.completed(p["preview_id"], "create", "office-a", self.snapshot["intent"]), {"id": "synthetic"})
        with self.assertRaises(ExpenseError):
            self.state.completed(p["preview_id"], "create", "office-a", {"value": 9})

    def test_unapproved_expired_withdrawn_and_mismatched_approvals_never_write(self):
        write = Mock()
        p = self.preview(approve=False)
        with self.assertRaises(ExpenseError):
            self.execute(p, write)
        with self.assertRaises(ExpenseError):
            self.state.approve(p["preview_id"], "wrong-digest")
        self.state.approve(p["preview_id"], p["preview_digest"])
        self.state.withdraw_unused_approval(p["preview_id"])
        with self.assertRaises(ExpenseError):
            self.execute(p, write)
        self.state.approve(p["preview_id"], p["preview_digest"])
        self.now += 600
        with self.assertRaises(ExpenseError):
            self.execute(p, write)
        with self.assertRaises(ExpenseError):
            self.state.approve(p["preview_id"], p["preview_digest"])
        write.assert_not_called()

    def test_ambiguous_callback_persists_unknown_and_claim_across_instances(self):
        p, write = self.preview(), Mock(side_effect=OutcomeUnknownError("synthetic ambiguous response"))
        with self.assertRaises(OutcomeUnknownError):
            self.execute(p, write)
        self.assertEqual(self.make().preview_details(p["preview_id"])["status"], "unknown")
        for candidate, kwargs in ((p, {}), (self.preview(action="upload", office="office-b"), {"action": "upload", "office": "office-b"})):
            with self.assertRaises(OutcomeUnknownError):
                self.execute(candidate, write, state=self.make(), **kwargs)
        write.assert_called_once()

    def test_final_result_persistence_failure_never_retries_external_success(self):
        p = self.preview()
        self.store.fail_on_status = "done"
        write = Mock(return_value={"created": True})
        with self.assertRaises(OutcomeUnknownError):
            self.execute(p, write)
        self.store.fail_on_status = None
        self.assertEqual(self.make().preview_details(p["preview_id"])["status"], "unknown")
        with self.assertRaises(OutcomeUnknownError):
            self.execute(p, write, state=self.make())
        write.assert_called_once()

    def test_lost_done_commit_acknowledgement_preserves_success(self):
        p = self.preview()
        self.store.fail_on_status, self.store.after_commit = "done", True
        write = Mock(return_value={"created": True})
        with self.assertRaises(OutcomeUnknownError):
            self.execute(p, write)
        self.store.fail_on_status = None
        self.assertEqual(self.execute(p, write, state=self.make()), {"created": True})
        write.assert_called_once()

    def test_failure_to_mark_unknown_leaves_executing_fence_and_claim(self):
        p = self.preview()
        def write():
            self.store.fail_writes = True
            raise RuntimeError("synthetic external failure")
        with self.assertRaises(OutcomeUnknownError):
            self.execute(p, write)
        self.store.fail_writes = False
        self.assertEqual(self.make().preview_details(p["preview_id"])["status"], "executing")
        for candidate in (p, self.preview()):
            with self.assertRaises(OutcomeUnknownError):
                self.execute(candidate, state=self.make())

    def test_storage_outage_after_callback_success_leaves_executing(self):
        p = self.preview()
        calls = []
        def write():
            calls.append(True)
            self.store.fail_writes = True
            return {"created": True}
        with self.assertRaises(OutcomeUnknownError):
            self.execute(p, write)
        self.store.fail_writes = False
        self.assertEqual(self.make().preview_details(p["preview_id"])["status"], "executing")
        with self.assertRaises(OutcomeUnknownError):
            self.execute(self.preview(), write, state=self.make())
        self.assertEqual(calls, [True])

    def test_large_external_result_keeps_unknown_not_preview(self):
        p, write = self.preview(), Mock(return_value={"large": "x" * 4000})
        with patch.object(self.state, "MAX_PLAINTEXT_BYTES", 2048):
            with self.assertRaises(OutcomeUnknownError):
                self.execute(p, write)
        self.assertEqual(self.make().preview_details(p["preview_id"])["status"], "unknown")
        write.assert_called_once()

    def test_executing_commit_failure_prevents_callback_even_if_ack_lost(self):
        for committed in (False, True):
            self.setUp()
            p, write = self.preview(), Mock()
            self.store.fail_on_status, self.store.after_commit = "executing", committed
            with self.assertRaises(ExpenseError):
                self.execute(p, write)
            write.assert_not_called()
            self.store.fail_on_status = None
            self.assertEqual(self.make().preview_details(p["preview_id"])["status"],
                             "executing" if committed else "preview")

    def test_unserializable_result_fences_success_without_retry(self):
        p, write = self.preview(), Mock(return_value=object())
        with self.assertRaises(OutcomeUnknownError):
            self.execute(p, write)
        with self.assertRaises(OutcomeUnknownError):
            self.execute(p, write, state=self.make())
        write.assert_called_once()

    def test_external_evidence_and_source_receipts_immutable_and_scoped(self):
        p = self.preview(approve=False)
        self.state.approve_external("synthetic", "event-a", p["preview_id"], p["preview_digest"], {"actor": "alice"})
        self.state.approve_external("synthetic", "event-a", p["preview_id"], p["preview_digest"], {"actor": "alice"})
        other = self.preview(approve=False)
        for target, evidence in ((other, {"actor": "alice"}), (p, {"actor": "bob"})):
            with self.assertRaises(ExpenseError):
                self.state.approve_external("synthetic", "event-a", target["preview_id"], target["preview_digest"], evidence)
        write = Mock()
        with self.assertRaises(ExpenseError):
            self.execute(other, write)
        write.assert_not_called()
        self.state.bind_source_receipt("synthetic", "scope", "reference", {"sha": "a"})
        self.assertEqual(self.make().source_receipt("synthetic", "scope", "reference"), {"sha": "a"})
        self.assertIsNone(self.make("bob").source_receipt("synthetic", "scope", "reference"))
        self.assertIsNone(self.state.source_receipt("synthetic", "other-scope", "reference"))
        with self.assertRaises(ExpenseError):
            self.state.bind_source_receipt("synthetic", "scope", "reference", {"sha": "b"})

    def test_immutable_evidence_distinguishes_json_boolean_number_and_float(self):
        p = self.preview(approve=False)
        self.state.approve_external("synthetic", "typed", p["preview_id"], p["preview_digest"], {"id": 1})
        self.state.bind_source_receipt("synthetic", "scope", "typed", {"id": 1})
        for value in (True, 1.0):
            with self.subTest(value=value), self.assertRaises(ExpenseError):
                self.state.approve_external("synthetic", "typed", p["preview_id"], p["preview_digest"], {"id": value})
            with self.assertRaises(ExpenseError):
                self.state.bind_source_receipt("synthetic", "scope", "typed", {"id": value})

    def test_failed_external_approval_does_not_consume_event(self):
        old = self.preview(approve=False)
        self.now += 601
        with self.assertRaises(ExpenseError):
            self.state.approve_external("synthetic", "event", old["preview_id"], old["preview_digest"], {})
        fresh = self.preview(approve=False)
        self.state.approve_external("synthetic", "event", fresh["preview_id"], fresh["preview_digest"], {})
        self.assertEqual(self.execute(fresh), {"created": True})

    def test_snapshot_returns_are_detached_and_hash_integrity_checked(self):
        p = self.preview()
        self.state.preview_details(p["preview_id"])["snapshot"]["intent"]["value"] = 999
        self.assertEqual(self.state.preview_details(p["preview_id"])["snapshot"], self.snapshot)
        row = self.store.rows[self.state._key]
        payload = json.loads(Fernet(self.key).decrypt(row["ciphertext"].encode()))
        payload["data"]["previews"][p["preview_id"]]["snapshot"]["intent"]["value"] = 999
        row["ciphertext"] = Fernet(self.key).encrypt(json.dumps(payload).encode()).decode()
        write = Mock()
        with self.assertRaises(ExpenseError):
            self.execute(p, write)
        write.assert_not_called()

    def test_nonfinite_lifetime_invalid_receipt_and_initial_consent_rejected(self):
        for lifetime in (float('nan'), float('inf'), True, 0, 3601):
            with self.subTest(lifetime=lifetime), self.assertRaises(ExpenseError):
                self.state.preview('create', 'office-a', {}, lifetime=lifetime)
        for fingerprint in ('bad', 'A' * 64, True):
            value = {"receipt_fingerprint": fingerprint}
            p = self.preview(snapshot=value)
            with self.assertRaises(ExpenseError):
                self.execute(p, snapshot=value)
        for offices, consent_id, active in (([], 'synthetic', True), (['a', 'a'], 'synthetic', True),
                                             (['a'], '../bad', True), (['a'], 'synthetic', 1)):
            with self.assertRaises(ExpenseError):
                self.state.set_draft_consent(offices, consent_id, active=active)

    def test_draft_consent_requires_trusted_call_and_rechecks_current_state(self):
        with self.assertRaises(ExpenseError):
            self.state.draft_consent("office-a")

        self.state.set_draft_consent(["office-a"], "synthetic-consent")
        second = self.make()
        self.assertEqual(second.draft_consent("office-a")["consent_id"], "synthetic-consent")
        for state, office in ((self.make("bob"), "office-a"), (second, "office-b")):
            with self.assertRaises(ExpenseError):
                state.draft_consent(office)
        second.set_draft_consent([], "synthetic-revoked", active=False)
        with self.assertRaises(ExpenseError):
            self.state.draft_consent("office-a")

    def test_llm_tool_dispatch_cannot_issue_consent_or_approvals(self):
        service = ExpenseService(mf=Mock(owner=self.state.owner), state=self.state, write_enabled=True)
        for operation in ('set_draft_consent', 'approve', 'approve_external', 'execute', 'accept_fact',
                          'memory_entries', 'confirm_memory', 'update_memory', 'delete_memory'):
            with self.subTest(operation=operation), self.assertRaises(ExpenseError):
                service.call(operation, {})
        with self.assertRaises(ExpenseError):
            self.state.draft_consent('office-a')

    def test_facts_pending_settings_persist_and_returns_are_detached(self):
        fact = self.state.propose_fact("pending", "架空の移動を確認", "2030-01-01")
        self.make().accept_fact(fact["id"])
        rows = self.state.due_pending(dt.date(2030, 1, 1))
        self.assertEqual(len(rows), 1)
        rows[0]["status"] = "retired"
        self.assertEqual(self.make().facts()[0]["status"], "active")
        self.make().complete_pending(fact["id"])
        self.assertEqual(self.state.due_pending(dt.date(2030, 1, 1)), [])
        self.state.retire_fact(fact["id"])
        self.assertEqual(self.make().facts()[0]["status"], "retired")
        self.assertTrue(self.state.suggestion_due())
        self.make().mark_suggestion()
        self.assertFalse(self.state.suggestion_due())
        self.now += 7 * 86400
        self.assertTrue(self.make().suggestion_due())
        self.assertFalse(self.make().suggestion_due(urgent=True))

    def test_memory_gui_mutation_rollback_on_store_failure_and_retry(self):
        proposal = self.state.propose_fact("preference", "架空の確認方法")
        entry = self.state.memory_entries()[0]
        before = copy.deepcopy(self.store.rows)
        self.store.fail_writes = True
        with self.assertRaises(ExpenseError):
            self.state.confirm_memory(proposal["id"], entry["digest"])
        self.assertEqual(self.store.rows, before)
        self.store.fail_writes = False
        active = self.make().confirm_memory(proposal["id"], entry["digest"])
        for mutate in (lambda: self.state.update_memory(active["id"], active["digest"], "preference", "架空の変更"),
                       lambda: self.state.delete_memory(active["id"], active["digest"])):
            before = copy.deepcopy(self.store.rows)
            self.store.fail_writes = True
            with self.assertRaises(ExpenseError):
                mutate()
            self.assertEqual(self.store.rows, before)
            self.store.fail_writes = False
            self.assertEqual(self.make().memory_entries(), [active])

    def test_memory_digest_is_owner_namespace_bound_even_for_same_id_and_content(self):
        item = self.state.propose_fact("preference", "架空の同じ内容")
        entry = self.state.memory_entries()[0]
        with self.state._record() as data:
            row = copy.deepcopy(data["facts"][item["id"]])
        for other in (self.make("bob"), self.make(namespace="other")):
            with other._record() as data:
                data["facts"][item["id"]] = copy.deepcopy(row)
            self.assertNotEqual(other.memory_entries()[0]["digest"], entry["digest"])
            with self.assertRaises(ExpenseError):
                other.confirm_memory(item["id"], entry["digest"])

    def test_size_limit_fails_closed_without_dropping_history(self):
        p = self.preview()
        with patch.object(self.state, "MAX_PLAINTEXT_BYTES", 2048):
            with self.assertRaises(ExpenseError):
                self.state.preview("create", "office-a", {"large": "x" * 4000})
        self.assertEqual(self.state.preview_details(p["preview_id"])["status"], "preview")
        self.assertEqual(self.execute(p), {"created": True})

    def test_close_does_not_close_shared_store(self):
        self.state.close()
        with self.assertRaises(ExpenseError):
            self.state.facts()
        self.assertEqual(self.make().facts(), [])


class DurableConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path, self.key = Path(self.temp.name) / "auth.sqlite", Fernet.generate_key()
        self.owner = Requester("synthetic-tenant", "alice", time.time() + 1000).owner
        self.stores = [SQLiteAuthorizationStore(self.path) for _ in range(2)]
        for store in self.stores:
            self.addCleanup(store.close)
        self.states = [DurableState(s, self.key, self.owner, "synthetic") for s in self.stores]
        self.snapshot = {"intent": {"value": 123}, "receipt_fingerprint": "c" * 64}

    def prepare(self, index=0, action="create", office="office-a"):
        state = self.states[index]
        p = state.preview(action, office, self.snapshot)
        state.approve(p["preview_id"], p["preview_digest"])
        return p

    def test_competing_instances_same_approval_or_receipt_and_no_lock_during_write(self):
        first = self.prepare()
        second = self.prepare(1, "upload", "office-b")
        entered, release = threading.Event(), threading.Event()
        writes = []
        def write():
            writes.append(True)
            entered.set()
            if not release.wait(5):
                raise AssertionError("synthetic release timed out")
            return {"created": True}
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            future = pool.submit(self.states[0].execute, first["preview_id"], "create", "office-a", self.snapshot, write)
            try:
                self.assertTrue(entered.wait(3))
                # A separate thread/connection must acquire the store lock while
                # the callback is still blocked, even for another human.
                bob = DurableState(self.stores[1], self.key, "synthetic-bob", "synthetic")
                bob_fact = pool.submit(bob.propose_fact, "preference", "架空の書式").result(timeout=2)
                own_fact = self.states[1].propose_fact("preference", "架空の確認方法")
                self.states[1].mark_suggestion()
                self.assertEqual(self.states[1].preview_details(first["preview_id"])["status"], "executing")
                for p, action, office in ((first, "create", "office-a"), (second, "upload", "office-b")):
                    with self.assertRaises(OutcomeUnknownError):
                        self.states[1].execute(p["preview_id"], action, office, self.snapshot, write)
            finally:
                release.set()
            self.assertEqual(future.result(timeout=3), {"created": True})
        self.assertEqual(len(writes), 1)
        self.assertEqual(bob.facts()[0]['id'], bob_fact['id'])
        self.assertEqual(self.states[0].facts()[0]['id'], own_fact['id'])
        self.assertFalse(self.states[0].suggestion_due())
        with self.assertRaises(ExpenseError):
            self.states[1].execute(second["preview_id"], "upload", "office-b", self.snapshot, write)

    def test_real_process_loss_leaves_executing_and_receipt_claim_durable(self):
        p = self.prepare()
        # Child performs only a synthetic callback, exiting without finally or
        # exception handlers. It never contacts a service or reads credentials.
        code = """
import json, os, sys
from runtime.auth_store import SQLiteAuthorizationStore
from runtime.durable_state import DurableState
params = json.loads(sys.stdin.read())
store = SQLiteAuthorizationStore(params['path'])
state = DurableState(store, params['key'].encode(), params['owner'], 'synthetic')
state.execute(params['preview_id'], 'create', 'office-a', params['snapshot'], lambda: os._exit(73))
"""
        child = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parent,
                               input=json.dumps({"path": str(self.path), "key": self.key.decode(),
                                                 "owner": self.owner, "preview_id": p["preview_id"],
                                                 "snapshot": self.snapshot}),
                               text=True, capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 73, child.stderr)
        self.assertEqual(self.states[1].preview_details(p["preview_id"])["status"], "executing")
        callback = Mock()
        for candidate in (p, self.prepare(1)):
            with self.assertRaises(OutcomeUnknownError):
                self.states[1].execute(candidate["preview_id"], "create", "office-a", self.snapshot, callback)
        callback.assert_not_called()


class DurableRuntimeCompatibilityTests(runtime_fixture.RuntimeTests):
    """Run the existing service's behavior tests against the new storage API."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        store = SQLiteAuthorizationStore(Path(temporary.name) / "auth.sqlite")
        self.addCleanup(store.close)
        key = Fernet.generate_key()
        def factory(path, owner, *, clock=time.time):
            return DurableState(store, key, owner, str(path), clock)
        patcher = patch.object(runtime_fixture, "State", factory)
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()

    def test_mismatched_owner_and_state_cannot_be_reused(self):
        # SQLite's one-file/one-owner constructor check is inapplicable: a KV
        # store deliberately contains multiple separately bound personal keys.
        self.mf.owner = "different-synthetic-owner"
        with self.assertRaises(ExpenseError):
            ExpenseService(mf=self.mf, state=self.state)


class DurableDraftCompatibilityTests(draft_fixture.DraftTests):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        store = SQLiteAuthorizationStore(Path(temporary.name) / "auth.sqlite")
        self.addCleanup(store.close)
        key = Fernet.generate_key()
        def factory(path, owner, *, clock=time.time):
            return DurableState(store, key, owner, str(path), clock)
        for module in (runtime_fixture, draft_fixture):
            patcher = patch.object(module, "State", factory)
            patcher.start()
            self.addCleanup(patcher.stop)
        super().setUp()


if __name__ == "__main__":
    unittest.main()
