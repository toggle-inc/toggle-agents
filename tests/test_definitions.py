"""Offline checks for this initial public definition catalog, not LLM evaluations."""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {"agent.json", "instructions.md", "tools.json", "skills.json", "qa.json"}


def source_files():
    """Do not treat ignored build receipts or Python bytecode as definitions."""
    for path in (ROOT / "agents").rglob("*"):
        if path.is_file() and not {".deploy", "__pycache__", ".venv"}.intersection(
            path.relative_to(ROOT / "agents").parts
        ):
            yield path


class DefinitionTests(unittest.TestCase):
    def test_expected_agents(self):
        self.assertEqual(
            {p.name for p in (ROOT / "agents").iterdir() if p.is_dir()},
            {"portable_qa", "expense_assistant"},
        )

    def test_basic_kit_format(self):
        for folder in (ROOT / "agents").iterdir():
            with self.subTest(agent=folder.name):
                self.assertTrue(REQUIRED.issubset({p.name for p in folder.iterdir()}))
                self.assertRegex(folder.name, r"^[a-z][a-z0-9_]*$")
                manifest = json.loads((folder / "agent.json").read_text())
                self.assertIsInstance(manifest["display_name"], str)
                self.assertTrue(manifest["display_name"].strip())
                self.assertTrue(manifest["description"].strip())
                self.assertFalse(manifest["allow_ask_human"])
                self.assertEqual(manifest["memory_mode"], "off")
                self.assertIsNone(manifest["llm_model"])
                for key in ("conn_ids", "ext_api_ids"):
                    self.assertEqual(manifest[key], [])
                self.assertTrue((folder / "instructions.md").read_text().strip())

    def test_capabilities_are_not_connected_in_initial_catalog(self):
        for folder in (ROOT / "agents").iterdir():
            for name in ("tools.json", "skills.json"):
                with self.subTest(agent=folder.name, file=name):
                    self.assertEqual(json.loads((folder / name).read_text()), [])

    def test_qa_is_an_input_and_expectation_not_a_live_receipt(self):
        for path in (ROOT / "agents").glob("*/qa.json"):
            with self.subTest(file=str(path.relative_to(ROOT))):
                qa = json.loads(path.read_text())
                self.assertEqual(set(qa), {"instruction", "expected_outcome"})
                self.assertTrue(all(isinstance(v, str) and v.strip() for v in qa.values()))

    def test_definitions_have_no_environment_bindings(self):
        forbidden = {
            "tenant_id",
            "agent_id",
            "version_id",
            "principal",
            "channel_id",
            "sender_id",
            "harness_url",
            "token",
            "private_key",
            "channels",
        }

        def keys(value):
            if isinstance(value, dict):
                return set(value).union(*(keys(v) for v in value.values()))
            if isinstance(value, list):
                return set().union(*(keys(v) for v in value))
            return set()

        for path in source_files():
            if path.suffix != ".json":
                continue
            with self.subTest(file=str(path.relative_to(ROOT))):
                self.assertFalse(keys(json.loads(path.read_text())) & forbidden)

    def test_no_machine_paths_or_credentials_in_definitions(self):
        patterns = (
            r"/Users/[^/]+/",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            r"sk-(?:proj-)?[A-Za-z0-9_-]{24,}",
            r"https://calendar\.google\.com/calendar/ical/",
        )
        for path in source_files():
            for pattern in patterns:
                with self.subTest(file=str(path.relative_to(ROOT)), pattern=pattern):
                    # Binary fixtures are scanned too: preserve ASCII secret
                    # markers instead of skipping images or failing to decode.
                    self.assertIsNone(re.search(pattern, path.read_bytes().decode("utf-8", errors="backslashreplace")))


if __name__ == "__main__":
    unittest.main()
