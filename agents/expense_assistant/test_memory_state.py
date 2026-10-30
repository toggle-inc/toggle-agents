"""SQLite/encrypted-store memory parity using synthetic people and local files."""

import concurrent.futures
import copy
import datetime as dt
from pathlib import Path
import tempfile
import threading
import unittest
import sqlite3

from cryptography.fernet import Fernet

from runtime.auth_store import SQLiteAuthorizationStore
from runtime.durable_state import DurableState
from runtime.requester import OPERATIONS
from runtime.service import ExpenseService
from runtime.state import ExpenseError, State


class MemoryContract:
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.key = Fernet.generate_key()
        self.state = self.make()

    def proposed(self, kind="preference", content="架空の確認方法", due_date=""):
        item = self.state.propose_fact(kind, content, due_date)
        return next(row for row in self.state.memory_entries() if row["id"] == item["id"])

    def active(self, **kwargs):
        row = self.proposed(**kwargs)
        return self.state.confirm_memory(row["id"], row["digest"])

    def test_automatic_memory_is_independent_active_and_replayed_after_restart(self):
        proposal = self.proposed()
        first = self.state.remember_fact("preference", proposal["content"])
        self.assertNotEqual(first["id"], proposal["id"])
        self.assertEqual(first["status"], "active")
        self.assertEqual(next(r for r in self.state.memory_entries() if r["id"] == proposal["id"])["status"], "proposed")
        self.state.close()
        state = self.make()
        self.assertEqual(state.remember_fact("preference", proposal["content"]), first)
        self.assertEqual(state.active_facts(), [first])

    def test_automatic_memory_competing_connections_deduplicate_atomically(self):
        second = self.make()
        barrier = threading.Barrier(2)
        def save(state):
            barrier.wait(timeout=3)
            return state.remember_fact("preference", "架空の自動記憶")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(save, state) for state in (self.state, second)]
            results = [job.result(timeout=5) for job in jobs]
        self.assertEqual(results[0], results[1])
        self.assertEqual(self.state.active_facts(), [results[0]])

    def test_automatic_memory_deleted_tombstone_blocks_replay_after_restart(self):
        saved = self.state.remember_fact("preference", "架空の自動記憶")
        entry = self.state.memory_entries()[0]
        self.state.delete_memory(saved["id"], entry["digest"])
        self.assert_erased(saved["id"], saved["content"])
        self.state.close()
        state = self.make()
        with self.assertRaises(ExpenseError):
            state.remember_fact("preference", "架空の自動記憶")
        self.assertEqual(state.active_facts(), [])

    def test_legacy_gui_confirm_then_automatic_save_adopts_random_id_without_duplicate(self):
        for legacy_accept in (False, True):
            content = "架空の旧確定情報" + str(legacy_accept)
            proposed = self.proposed(content=content)
            if legacy_accept:
                self.state.accept_fact(proposed["id"])
            else:
                self.state.confirm_memory(proposed["id"], proposed["digest"])
            remembered = self.make().remember_fact("preference", content)
            self.assertEqual(remembered["id"], proposed["id"])
        self.assertEqual(len(self.state.facts()), 2)

    def test_legacy_propose_confirm_delete_then_remember_cannot_revive(self):
        proposed = self.proposed(content="架空の旧GUI記憶")
        active = self.state.confirm_memory(proposed["id"], proposed["digest"])
        self.state.delete_memory(active["id"], active["digest"])
        self.assert_erased(active["id"], active["content"])
        state = self.make()
        with self.assertRaises(ExpenseError):
            state.remember_fact("preference", active["content"])
        self.assertEqual(state.facts(), [])

    def test_pre_alias_legacy_rows_are_adopted_and_fenced_by_gui_mutations(self):
        old = self.active(content="架空の移行前情報")
        # Simulate a record confirmed before content aliases existed.
        self.clear_content_claims()
        self.assertEqual(self.make().remember_fact("preference", old["content"])["id"], old["id"])
        self.assertEqual(len(self.state.active_facts()), 1)
        self.clear_content_claims()
        edited = self.state.update_memory(old["id"], old["digest"], "preference", "架空の移行後情報")
        with self.assertRaises(ExpenseError):
            self.make().remember_fact("preference", old["content"])
        self.state.delete_memory(edited["id"], edited["digest"])
        for content in (old["content"], edited["content"]):
            with self.assertRaises(ExpenseError):
                self.make().remember_fact("preference", content)
        separate = self.active(content="架空の移行前削除対象")
        self.clear_content_claims()
        self.state.delete_memory(separate["id"], separate["digest"])
        with self.assertRaises(ExpenseError):
            self.make().remember_fact("preference", separate["content"])
        self.assertEqual(self.state.active_facts(), [])

    def test_gui_update_old_alias_then_delete_new_alias_blocks_both_contents(self):
        for auto in (False, True):
            old, new = "架空の変更前" + str(auto), "架空の変更後" + str(auto)
            if auto:
                self.state.remember_fact("preference", old)
                entry = next(r for r in self.state.memory_entries() if r["content"] == old)
            else:
                entry = self.active(content=old)
            edited = self.state.update_memory(entry["id"], entry["digest"], "preference", new)
            with self.assertRaises(ExpenseError):
                self.make().remember_fact("preference", old)
            self.assertEqual(self.make().remember_fact("preference", new)["id"], entry["id"])
            self.state.delete_memory(edited["id"], edited["digest"])
            for content in (old, new):
                with self.assertRaises(ExpenseError):
                    self.make().remember_fact("preference", content)
        self.assertEqual(self.state.active_facts(), [])

    def test_automatic_memory_is_person_namespace_bound_and_tuple_specific(self):
        saved = self.state.remember_fact("preference", "架空の本人情報")
        for other in (self.make(owner="bob"), self.make(namespace="other")):
            self.assertEqual(other.facts(), [])
            separate = other.remember_fact("preference", "架空の本人情報")
            self.assertNotEqual(saved["id"], separate["id"])
        first = self.state.remember_fact("pending", "架空の予定", "2030-01-01")
        same = self.state.remember_fact("pending", "架空の予定", "20300101")
        later = self.state.remember_fact("pending", "架空の予定", "2030-01-02")
        self.assertEqual(first, same)
        self.assertNotEqual(first["id"], later["id"])

    def test_propose_confirm_and_legacy_accept_compatibility(self):
        row = self.proposed()
        self.assertEqual(set(row), {"id", "kind", "content", "status", "due_date", "digest"})
        self.assertIsNone(row["due_date"])
        self.assertEqual(len(row["digest"]), 64)
        self.assertEqual(self.state.active_facts(), [])
        active = self.state.confirm_memory(row["id"], row["digest"])
        self.assertNotEqual(active["digest"], row["digest"])
        self.assertEqual(active["status"], "active")
        legacy = self.state.propose_fact("formatting", "架空の書式")
        self.assertEqual(set(legacy), {"id", "kind", "content", "status"})
        self.assertIsNone(self.state.accept_fact(legacy["id"]))
        self.assertEqual(len(self.state.active_facts()), 2)
        with self.assertRaises(ExpenseError):
            self.state.accept_fact(legacy["id"])

    def test_update_active_same_id_and_exact_current_digest_after_restart(self):
        row = self.active()
        self.state.close()
        restarted = self.make()
        self.assertEqual(restarted.memory_entries(), [row])
        # No store-level TTL: the GUI owns expiry. Exact current content wins.
        updated = restarted.update_memory(row["id"], row["digest"], "pending", "架空の予定を確認", "2030-01-02")
        self.assertEqual((updated["id"], updated["status"], updated["due_date"]),
                         (row["id"], "active", "2030-01-02"))
        self.assertNotEqual(updated["digest"], row["digest"])
        self.assertEqual(self.make().memory_entries(), [updated])
        self.assertEqual(len(restarted.due_pending(dt.date(2030, 1, 2))), 1)
        for method in (restarted.confirm_memory, restarted.delete_memory):
            with self.assertRaises(ExpenseError):
                method(row["id"], row["digest"])
        with self.assertRaises(ExpenseError):
            restarted.update_memory(row["id"], row["digest"], "preference", "古い画面の変更")
        cleared = restarted.update_memory(updated["id"], updated["digest"], "formatting", "架空の新書式")
        self.assertIsNone(cleared["due_date"])

    def test_update_only_active_and_old_status_digest_cannot_confirm(self):
        proposed = self.proposed()
        with self.assertRaises(ExpenseError):
            self.state.update_memory(proposed["id"], proposed["digest"], "preference", "未承認の変更")
        self.state.accept_fact(proposed["id"])
        with self.assertRaises(ExpenseError):
            self.state.confirm_memory(proposed["id"], proposed["digest"])
        active = self.state.memory_entries()[0]
        self.state.retire_fact(active["id"])
        for digest in (active["digest"], self.state.memory_entries()[0]["digest"]):
            with self.assertRaises(ExpenseError):
                self.state.update_memory(active["id"], digest, "preference", "変更不可")
        pending = self.active(kind="pending", due_date="2030-01-01")
        self.state.complete_pending(pending["id"])
        done = next(row for row in self.state.memory_entries() if row["id"] == pending["id"])
        with self.assertRaises(ExpenseError):
            self.state.update_memory(done["id"], done["digest"], "preference", "変更不可")

    def test_stale_delete_and_double_delete_are_refused(self):
        row = self.active()
        updated = self.state.update_memory(row["id"], row["digest"], "preference", "新しい架空の確認方法")
        with self.assertRaises(ExpenseError):
            self.make().delete_memory(row["id"], row["digest"])
        self.assertEqual(self.state.memory_entries(), [updated])
        self.state.delete_memory(updated["id"], updated["digest"])
        with self.assertRaises(ExpenseError):
            self.state.delete_memory(updated["id"], updated["digest"])

    def test_delete_erases_content_and_cannot_be_revived_after_restart(self):
        content = "架空の削除対象文面 unique erase marker"
        row = self.active(content=content)
        self.assertEqual(self.state.delete_memory(row["id"], row["digest"]),
                         {"id": row["id"], "status": "deleted"})
        self.assert_erased(row["id"], content)
        self.state.close()
        state = self.make()
        self.assertEqual(state.facts(), [])
        self.assertEqual(state.memory_entries(), [])
        self.assertEqual(state.active_facts(), [])
        self.assertEqual(state.due_pending(dt.date(2030, 1, 1)), [])
        # Legacy host actions must not turn a tombstone back into a normal row.
        state.retire_fact(row["id"])
        state.complete_pending(row["id"])
        for call in (lambda: state.accept_fact(row["id"]),
                     lambda: state.confirm_memory(row["id"], row["digest"]),
                     lambda: state.update_memory(row["id"], row["digest"], "preference", "復元不可")):
            with self.assertRaises(ExpenseError):
                call()
        self.assertEqual(state.facts(), [])

    def test_delete_handles_proposed_retired_and_done_but_never_uses_stale_status(self):
        proposed = self.proposed()
        self.state.delete_memory(proposed["id"], proposed["digest"])
        retired = self.active()
        self.state.retire_fact(retired["id"])
        with self.assertRaises(ExpenseError):
            self.state.delete_memory(retired["id"], retired["digest"])
        retired = self.state.memory_entries()[0]
        self.state.delete_memory(retired["id"], retired["digest"])
        done = self.active(kind="pending", due_date="2030-01-01")
        self.state.complete_pending(done["id"])
        done = self.state.memory_entries()[0]
        self.state.delete_memory(done["id"], done["digest"])
        self.assertEqual(self.state.memory_entries(), [])

    def test_active_reader_excludes_every_other_lifecycle_and_is_detached(self):
        self.proposed()
        active = self.active(content="架空の有効情報")
        retired = self.active(content="架空の過去情報")
        self.state.retire_fact(retired["id"])
        done = self.active(kind="pending", due_date="2030-01-01")
        self.state.complete_pending(done["id"])
        deleted = self.active(content="架空の消去情報")
        self.state.delete_memory(deleted["id"], deleted["digest"])
        rows = self.state.active_facts()
        self.assertEqual([row["id"] for row in rows], [active["id"]])
        self.assertNotIn("digest", rows[0])
        rows[0]["content"] = "外部からの変更"
        entries = self.state.memory_entries()
        entries[0]["content"] = "外部からの変更"
        self.assertEqual(self.state.active_facts()[0]["content"], "架空の有効情報")

    def test_owner_and_namespace_cannot_read_or_mutate_other_memory(self):
        row = self.active()
        for other in (self.make(owner="bob"), self.make(namespace="other")):
            self.assertEqual(other.memory_entries(), [])
            self.assertEqual(other.active_facts(), [])
            for method in (other.confirm_memory, other.delete_memory):
                with self.assertRaises(ExpenseError):
                    method(row["id"], row["digest"])
            with self.assertRaises(ExpenseError):
                other.update_memory(row["id"], row["digest"], "preference", "架空の変更")
        self.assertEqual(self.state.memory_entries(), [row])

    def test_digest_is_bound_to_id_and_every_old_value(self):
        first, second = self.active(), self.active()
        self.assertNotEqual(first["digest"], second["digest"])
        with self.assertRaises(ExpenseError):
            self.state.delete_memory(second["id"], first["digest"])
        previous = first
        for kind, content, due in (("formatting", first["content"], ""),
                                   ("formatting", "変更後の架空情報", ""),
                                   ("pending", "変更後の架空情報", "2030-01-01"),
                                   ("pending", "変更後の架空情報", "2030-01-02")):
            current = self.state.update_memory(previous["id"], previous["digest"], kind, content, due)
            self.assertNotEqual(current["digest"], previous["digest"])
            with self.assertRaises(ExpenseError):
                self.state.delete_memory(previous["id"], previous["digest"])
            previous = current

    def test_secret_and_kind_due_length_validation_applies_to_proposal_and_update(self):
        active = self.active()
        cases = [("preference", value, "") for value in
                 ("password", "token", "secret", "認可コード", "口座", "秘密", "sk-test",
                  "https://example.test", "test@example.test", "12345678901", "", "x" * 1001, None)]
        cases += [("unknown", "架空の情報", ""), ([], "架空の情報", ""),
                  ("pending", "架空の情報", ""), ("pending", "架空の情報", "2030-02-30"),
                  ("preference", "架空の情報", "2030-01-01"),
                  ("preference", "架空の情報", []), ("preference", "架空の情報", False)]
        for kind, content, due in cases:
            with self.subTest(kind=kind, content=content):
                before = self.state.memory_entries()
                with self.assertRaises(ExpenseError):
                    self.state.propose_fact(kind, content, due)
                with self.assertRaises(ExpenseError):
                    self.state.remember_fact(kind, content, due)
                with self.assertRaises(ExpenseError):
                    self.state.update_memory(active["id"], active["digest"], kind, content, due)
                self.assertEqual(self.state.memory_entries(), before)

    def test_invalid_or_missing_digest_never_changes_memory(self):
        row = self.proposed()
        for bad in (None, "", "bad", "0" * 64, True, {}):
            with self.subTest(digest=bad), self.assertRaises(ExpenseError):
                self.state.confirm_memory(row["id"], bad)
        self.assertEqual(self.state.memory_entries(), [row])
        row = self.state.confirm_memory(row["id"], row["digest"])
        for bad in (None, "", "bad", "0" * 64, True, {}):
            with self.assertRaises(ExpenseError):
                self.state.update_memory(row["id"], bad, "preference", "変更不可")
            with self.assertRaises(ExpenseError):
                self.state.delete_memory(row["id"], bad)
        self.assertEqual(self.state.memory_entries(), [row])

    def test_competing_connections_only_one_update_or_delete_wins(self):
        row = self.active()
        second = self.make()
        barrier = threading.Barrier(2)

        def change(state, delete):
            barrier.wait(timeout=3)
            try:
                if delete:
                    return state.delete_memory(row["id"], row["digest"])
                return state.update_memory(row["id"], row["digest"], "preference", "競合後の架空情報")
            except ExpenseError:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(change, self.state, False), pool.submit(change, second, True)]
            results = [future.result(timeout=5) for future in futures]
        self.assertEqual(sum(result is not None for result in results), 1)

    def test_gui_methods_are_not_model_operations(self):
        service = ExpenseService(mf=type("FakeMF", (), {"owner": self.state.owner})(), state=self.state)
        for name in ("memory_entries", "confirm_memory", "update_memory", "delete_memory", "accept_fact", "remember_fact"):
            self.assertNotIn(name, OPERATIONS)
            with self.assertRaises(ExpenseError):
                service.call(name, {})


class SQLiteMemoryTests(MemoryContract, unittest.TestCase):
    def clear_content_claims(self):
        self.state.db.execute("DELETE FROM settings WHERE key LIKE 'memory_content_claim:%'")

    def make(self, owner="alice", namespace="memory"):
        state = State(self.root / (owner + "-" + namespace + ".sqlite"), owner, clock=lambda: 100)
        self.addCleanup(state.close)
        return state

    def assert_erased(self, identifier, content):
        raw = self.state.db.execute("SELECT id,kind,content,status,created,due_date FROM facts WHERE id=?",
                                    (identifier,)).fetchone()
        self.assertEqual(raw, (identifier, "", "", "deleted", 0, None))
        self.assertNotIn(content.encode(), (self.root / "alice-memory.sqlite").read_bytes())

    def test_database_itself_cannot_be_opened_as_another_owner(self):
        with self.assertRaises(ExpenseError):
            State(self.root / "alice-memory.sqlite", "bob")

    def test_sql_failure_rolls_back_cas_transaction_and_leaves_digest_usable(self):
        row = self.active()
        self.state.db.execute("CREATE TRIGGER reject_memory_update BEFORE UPDATE ON facts "
                              "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
        for mutate in (lambda: self.state.update_memory(row["id"], row["digest"], "preference", "架空の変更"),
                       lambda: self.state.delete_memory(row["id"], row["digest"])):
            with self.assertRaises(sqlite3.IntegrityError):
                mutate()
            self.assertFalse(self.state.db.in_transaction)
            self.assertEqual(self.state.memory_entries(), [row])
        self.state.db.execute("DROP TRIGGER reject_memory_update")
        updated = self.state.update_memory(row["id"], row["digest"], "preference", "架空の変更")
        self.assertNotEqual(updated["digest"], row["digest"])


class DurableMemoryTests(MemoryContract, unittest.TestCase):
    def clear_content_claims(self):
        with self.state._record() as data:
            for key in list(data["settings"]):
                if key.startswith("memory_content_claim:"):
                    del data["settings"][key]

    def make(self, owner="alice", namespace="memory"):
        store = SQLiteAuthorizationStore(self.root / "auth.sqlite")
        self.addCleanup(store.close)
        state = DurableState(store, self.key, owner, namespace, clock=lambda: 100)
        self.addCleanup(state.close)
        return state

    def assert_erased(self, identifier, content):
        with self.state._record() as data:
            raw = copy.deepcopy(data["facts"][identifier])
        self.assertEqual(raw, {"id": identifier, "status": "deleted"})
        self.assertNotIn(content.encode(), (self.root / "auth.sqlite").read_bytes())


if __name__ == "__main__":
    unittest.main()
