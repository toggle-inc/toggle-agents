"""Source-owned human review is complete, plain text and tied to exact payload bytes."""

import collections
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_sa_approval as fixtures  # noqa: E402
from runtime.presentation import build_presentation  # noqa: E402
from runtime.state import ExpenseError  # noqa: E402


class PresentationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SAApprovalTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def payload(self):
        return json.loads(self.fixture.rows[0]["payload"])

    def verify_schema(self, presentation):
        self.assertEqual(set(presentation), {"title", "sections"})
        self.assertTrue(1 <= len(presentation["title"]) <= 200)
        self.assertTrue(1 <= len(presentation["sections"]) <= 100)
        rows = []
        for section in presentation["sections"]:
            self.assertEqual(set(section), {"title", "fields"})
            self.assertTrue(1 <= len(section["title"]) <= 200)
            self.assertTrue(1 <= len(section["fields"]) <= 200)
            for field in section["fields"]:
                self.assertEqual(set(field), {"label", "value"})
                self.assertIsInstance(field["label"], str)
                self.assertIsInstance(field["value"], str)
                self.assertTrue(1 <= len(field["label"]) <= 200)
                self.assertTrue(1 <= len(field["value"]) <= 16000)
                rows.append(field)
        return rows

    def test_create_has_named_company_all_fields_and_invoice(self):
        args = {**self.fixture.fixture.create, "invoice_registration_number": "T0000000000000"}
        preview = self.fixture.service.mf_create_transaction(**args)
        self.fixture.adapter.propose(preview["preview_id"])
        data = self.payload()
        rows = self.verify_schema(data["presentation"])
        values = [row["value"] for row in rows]
        self.assertIn("架空商事A", values)
        self.assertIn("321", values)
        self.assertIn("T0000000000000", values)
        self.assertTrue(any("適格請求書発行事業者登録番号" in row["label"] for row in rows))
        self.assertEqual(data["snapshot"]["payload"]["value"], 321)
        self.assertEqual(self.fixture.fixture.mf.writes, [])

    def test_update_shows_both_old_and_new_values(self):
        preview = self.fixture.service.mf_update_transaction(
            "office-a", "tx-a", value=654, memo="架空の変更"
        )
        self.fixture.adapter.propose(preview["preview_id"])
        data = self.payload()
        sections = data["presentation"]["sections"]
        before = next(row for row in sections if row["title"] == "変更・削除前の明細")
        after = next(row for row in sections if row["title"] == "実行する内容")
        self.assertIn("321", [row["value"] for row in before["fields"]])
        self.assertIn("654", [row["value"] for row in after["fields"]])
        self.assertIn(
            "架空商事A", [row["value"] for row in self.verify_schema(data["presentation"])]
        )

    def test_every_snapshot_leaf_and_unknown_future_field_remains_visible(self):
        self.fixture.propose(receipt=True)
        data = self.payload()
        data["snapshot"]["future"] = {"unknown": ["unique-future-value", None, False, 0, {}, []]}
        details = {
            "action": "create",
            "office": "office-a",
            "expires_at": self.fixture.fixture.now[0] + 100,
        }
        presentation = build_presentation(details, data["snapshot"], data["source_attachments"])
        rows = self.verify_schema(presentation)

        def leaves(value):
            if isinstance(value, dict):
                return (
                    [leaf for item in value.values() for leaf in leaves(item)]
                    if value
                    else ["項目なし"]
                )
            if isinstance(value, list):
                return [leaf for item in value for leaf in leaves(item)] if value else ["項目なし"]
            return [
                "（未設定）"
                if value is None
                else "（空欄）"
                if value == ""
                else "はい"
                if value is True
                else "いいえ"
                if value is False
                else str(value)
            ]

        expected = collections.Counter(
            leaves(data["snapshot"]) + leaves(data["source_attachments"])
        )
        actual = collections.Counter(row["value"] for row in rows)
        self.assertFalse(expected - actual)
        self.assertIn("unique-future-value", actual)

    def test_attachment_review_contains_original_name_size_type_and_hash(self):
        self.fixture.propose(receipt=True)
        data = self.payload()
        values = [row["value"] for row in self.verify_schema(data["presentation"])]
        source = data["source_attachments"][0]
        for key in ("filename", "contentType", "sha256", "size"):
            self.assertIn(str(source[key]), values)

    def test_display_changes_are_detected_even_when_snapshot_stays_identical(self):
        self.fixture.propose()
        self.fixture.decide()
        data = self.payload()
        data["presentation"]["sections"][0]["fields"][0]["value"] = "別の操作"
        self.fixture.rows[0]["payload"] = json.dumps(data, ensure_ascii=False)
        with self.assertRaises(ExpenseError):
            self.fixture.execute()
        self.assertEqual(self.fixture.fixture.mf.writes, [])

    def test_plain_text_numbers_are_not_rounded_or_interpreted(self):
        details = {
            "action": "create",
            "office": "office-a",
            "expires_at": self.fixture.fixture.now[0] + 100,
        }
        snapshot = {
            "payload": {
                "invoice_registration_number": "T0000000000000",
                "large_id": 12345678901234567890,
                "memo": "<script>架空</script>",
            }
        }
        rows = self.verify_schema(build_presentation(details, snapshot, []))
        self.assertIn("12345678901234567890", [row["value"] for row in rows])
        self.assertIn("<script>架空</script>", [row["value"] for row in rows])

    def test_large_review_is_split_without_omitting_fields_and_oversize_value_refused(self):
        details = {
            "action": "create",
            "office": "office-a",
            "expires_at": self.fixture.fixture.now[0] + 100,
        }
        snapshot = {"future": {f"key-{i}": f"value-{i}" for i in range(220)}}
        rows = self.verify_schema(build_presentation(details, snapshot, []))
        self.assertTrue({f"value-{i}" for i in range(220)}.issubset({row["value"] for row in rows}))
        with self.assertRaises(ExpenseError):
            build_presentation(details, {"payload": {"memo": "x" * 16001}}, [])


if __name__ == "__main__":
    unittest.main()
