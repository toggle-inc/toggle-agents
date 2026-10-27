"""Synthetic, offline migration tests. Not evidence of calendar or MF connectivity."""

import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("expense_preview_core", HERE / "expense_preview.py")
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)


class ExpensePreviewTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((HERE / "fixtures" / "synthetic_transport.json").read_text())

    def preview(self):
        return core.build_preview(self.data)

    def candidate(self):
        return self.preview()["candidates"][0]

    def test_calendar_to_one_way_draft_with_fare_and_sources(self):
        result = self.preview()
        self.assertEqual(len(result["candidates"]), 1)
        line = result["candidates"][0]
        self.assertEqual(line["from_station"], "テスト駅A")
        self.assertEqual(line["to_station"], "テスト駅B")
        self.assertEqual(line["amount_yen"], 321)
        self.assertEqual(line["direction"], "one_way")
        self.assertEqual(line["fare_source_ref"], "synthetic:fare-a-to-b")
        self.assertEqual(len(line["calendar_sources"]), 2)
        self.assertIn("actual_travel_unconfirmed", line["unresolved"])
        self.assertFalse(line["ready_to_register"])
        self.assertEqual(result["writes_performed"], 0)

    def test_input_changes_result_instead_of_canned_response(self):
        original = self.candidate()
        self.data["fares"][0]["amount_yen"] = 654
        changed = self.candidate()
        self.assertEqual(changed["amount_yen"], 654)
        self.assertNotEqual(original["preview_digest"], changed["preview_digest"])

    def test_missing_fare_is_not_zero_or_guessed(self):
        self.data["fares"] = []
        self.assertIsNone(self.candidate()["amount_yen"])
        self.assertIn("fare_unconfirmed", self.candidate()["unresolved"])

    def test_fare_must_match_date_and_direction(self):
        for key, value in (("date", "2030-01-14"), ("from_station", "テスト駅B")):
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                data["fares"][0][key] = value
                self.assertIsNone(core.build_preview(data)["candidates"][0]["amount_yen"])

    def test_conflicting_quotes_require_selection(self):
        second = copy.deepcopy(self.data["fares"][0])
        second["amount_yen"] = 999
        self.data["fares"].append(second)
        with self.assertRaises(ValueError):
            self.preview()

    def test_noninteger_negative_or_boolean_fares_are_refused(self):
        for amount in (True, 0, -1, 123.4, "123"):
            with self.subTest(amount=amount):
                self.data["fares"][0]["amount_yen"] = amount
                with self.assertRaises(ValueError):
                    self.preview()

    def test_missing_company_is_visible(self):
        self.data["company"] = ""
        self.assertIsNone(self.candidate()["company"])
        self.assertIn("company_unconfirmed", self.candidate()["unresolved"])

    def test_online_unknown_cancelled_missing_station_and_future_are_not_trips(self):
        cases = (
            ("mode", "online"),
            ("mode", "unknown"),
            ("status", "cancelled"),
            ("station", ""),
            ("end", "2030-01-17T12:00:00+09:00"),
        )
        for key, value in cases:
            with self.subTest(key=key, value=value):
                data = copy.deepcopy(self.data)
                data["events"][1][key] = value
                self.assertEqual(core.build_preview(data)["candidates"], [])

    def test_unknown_location_breaks_chain_instead_of_inventing_a_route(self):
        middle = copy.deepcopy(self.data["events"][0])
        middle.update(
            id="synthetic-unknown",
            start="2030-01-15T10:10:00+09:00",
            end="2030-01-15T10:30:00+09:00",
            station="",
        )
        self.data["events"].append(middle)
        self.assertEqual(self.preview()["candidates"], [])

    def test_overlapping_events_are_not_a_route(self):
        self.data["events"][1]["start"] = "2030-01-15T09:30:00+09:00"
        self.assertEqual(self.preview()["candidates"], [])
        self.assertIn("overlapping_events", [x["reason"] for x in self.preview()["skipped"]])

    def test_later_overlap_invalidates_an_earlier_arrival_candidate(self):
        third = copy.deepcopy(self.data["events"][1])
        third.update(
            id="synthetic-conflict",
            start="2030-01-15T11:30:00+09:00",
            end="2030-01-15T12:30:00+09:00",
            station="テスト駅C",
        )
        self.data["events"].append(third)
        self.assertEqual(self.preview()["candidates"], [])

    def test_overlap_cluster_cannot_leave_a_fake_origin_for_the_next_event(self):
        self.data["events"][0]["end"] = "2030-01-15T13:00:00+09:00"
        third = copy.deepcopy(self.data["events"][1])
        third.update(
            id="synthetic-third",
            start="2030-01-15T12:10:00+09:00",
            end="2030-01-15T12:30:00+09:00",
            station="テスト駅C",
        )
        fourth = copy.deepcopy(third)
        fourth.update(
            id="synthetic-fourth",
            start="2030-01-15T14:00:00+09:00",
            end="2030-01-15T15:00:00+09:00",
            station="テスト駅D",
        )
        self.data["events"].extend([third, fourth])
        self.assertEqual(self.preview()["candidates"], [])

    def test_day_boundary_does_not_invent_overnight_travel(self):
        self.data["date_to"] = "2030-01-16"
        self.data["as_of"] = "2030-01-17T12:00:00+09:00"
        self.data["events"][1].update(
            start="2030-01-16T11:00:00+09:00", end="2030-01-16T12:00:00+09:00"
        )
        self.assertEqual(self.preview()["candidates"], [])

    def test_all_day_entries_are_not_travel(self):
        self.data["events"][1].update(all_day=True, start="2030-01-15", end="2030-01-16")
        self.assertEqual(self.preview()["candidates"], [])

    def test_same_station_does_not_generate_a_fare(self):
        self.data["events"][1]["station"] = "テスト駅A"
        self.assertEqual(self.preview()["candidates"], [])

    def test_duplicate_occurrences_are_deduplicated_but_conflicts_refused(self):
        self.data["events"].append(copy.deepcopy(self.data["events"][1]))
        self.assertEqual(len(self.preview()["candidates"]), 1)
        self.data["events"][-1]["station"] = "テスト駅C"
        with self.assertRaises(ValueError):
            self.preview()

    def test_input_order_and_repeat_do_not_change_digest_or_mutate_input(self):
        before = copy.deepcopy(self.data)
        first = self.preview()
        self.assertEqual(self.data, before)
        self.data["events"].reverse()
        self.assertEqual(first, self.preview())
        self.assertEqual(first, self.preview())

    def test_naive_timestamps_and_bad_ranges_are_refused(self):
        self.data["as_of"] = "2030-01-16T12:00:00"
        with self.assertRaises(ValueError):
            self.preview()
        self.setUp()
        self.data["date_to"] = "2030-01-14"
        with self.assertRaises(ValueError):
            self.preview()

    def test_user_supplied_approval_is_not_accepted(self):
        self.data["approved"] = True
        with self.assertRaises(ValueError):
            self.preview()

    def test_no_network_even_when_called_as_a_library(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            self.assertEqual(self.preview()["writes_performed"], 0)

    def test_copied_folder_demo_and_stdin_work_without_other_repositories(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "standalone"
            shutil.copytree(HERE, folder, ignore=shutil.ignore_patterns(".deploy", "__pycache__"))
            result = subprocess.run(
                [sys.executable, str(folder / "preview.py"), "--demo"],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), self.preview())
            result = subprocess.run(
                [sys.executable, str(folder / "preview.py")],
                input=json.dumps(self.data),
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), self.preview())

    def test_invalid_cli_input_is_rejected_without_echoing_data(self):
        result = subprocess.run(
            [sys.executable, str(HERE / "preview.py")],
            input='{"private_input": "must-not-be-echoed"}',
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("must-not-be-echoed", result.stderr)


if __name__ == "__main__":
    unittest.main()
