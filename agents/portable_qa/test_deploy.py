"""Run these tests from this folder, even after copying it outside the repository."""

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
spec = importlib.util.spec_from_file_location("agent_deploy", HERE / "deploy.py")
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class DeploymentTests(unittest.TestCase):
    def test_definition_is_valid(self):
        deploy.load_definition()

    def test_copied_folder_builds_without_repository_or_sibling_agent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copied = root / "renamed-agent"
            shutil.copytree(
                HERE,
                copied,
                ignore=shutil.ignore_patterns(".deploy", "__pycache__", ".env*", "*.sqlite*"),
            )
            output = root / "package"
            result = subprocess.run(
                [
                    sys.executable,
                    str(copied / "deploy.py"),
                    "--tenant-id",
                    "123",
                    "--agent-id",
                    "456",
                    "--output",
                    str(output),
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "agentize.managed-agent.json").read_text())
            self.assertEqual(manifest["tenant_id"], 123)
            self.assertEqual(manifest["agent_id"], 456)
            self.assertEqual(
                manifest["test_scenarios"], [json.loads((copied / "qa.json").read_text())]
            )
            self.assertEqual((output / "instructions.md").read_text(), deploy.load_definition()[1])
            self.assertEqual(
                {p.name for p in output.iterdir()},
                {
                    "agentize.managed-agent.json",
                    "instructions.md",
                    "skills",
                    "_foundation",
                    "mcp_server.py",
                    "requirements.txt",
                },
            )
            self.assertIn("read_conversation_context", (output / "instructions.md").read_text())
            self.assertEqual(
                (output / "_foundation" / "conversation.py").read_bytes(),
                (copied / "_foundation" / "conversation.py").read_bytes(),
            )
            imported = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-I",
                    "-c",
                    "import sys; sys.path.insert(0, sys.argv[1]); "
                    "from _foundation.conversation import ConversationReader; "
                    "from _foundation.history_sources import SuccessAssistHistory, BuzzHistory; "
                    "from mcp_server import create_server",
                    str(output),
                ],
                cwd=root,
                capture_output=True,
                text=True,
            )
            self.assertEqual(imported.returncode, 0, imported.stderr)
            # Existing receipts/packages must never be replaced.
            again = subprocess.run(
                [
                    sys.executable,
                    str(copied / "deploy.py"),
                    "--tenant-id",
                    "123",
                    "--output",
                    str(output),
                ],
                cwd=root,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(
                manifest, json.loads((output / "agentize.managed-agent.json").read_text())
            )

    def test_new_agent_has_no_invented_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            output = deploy.build(123, Path(directory) / "package")
            manifest = json.loads((output / "agentize.managed-agent.json").read_text())
            self.assertNotIn("agent_id", manifest)

    def test_verified_connection_is_only_bound_in_generated_package(self):
        with tempfile.TemporaryDirectory() as directory:
            output = deploy.build(123, Path(directory) / "package", connection_ids=(456,))
            manifest = json.loads((output / "agentize.managed-agent.json").read_text())
            self.assertEqual(manifest["conn_ids"], [456])
            self.assertEqual(deploy.load_definition()[0]["conn_ids"], [])

    def test_invalid_connection_binding_is_rejected(self):
        for values in ((0,), (-1,), (True,), ("123",), (123, 123)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                deploy.build(123, HERE / ".deploy" / "must-not-exist", connection_ids=values)

    def test_invalid_target_is_rejected(self):
        for value in (0, -1, True, "123"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                deploy.build(value, HERE / ".deploy" / "must-not-exist")

    def test_capabilities_cannot_be_silently_dropped(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "source"
            shutil.copytree(HERE, copied, ignore=shutil.ignore_patterns(".deploy", "__pycache__"))
            for filename in ("tools.json", "skills.json"):
                with self.subTest(filename=filename):
                    path = copied / filename
                    original = path.read_text()
                    path.write_text('["not-packaged"]')
                    with patch.object(deploy, "ROOT", copied), self.assertRaises(ValueError):
                        deploy.build(123, Path(directory) / filename)
                    path.write_text(original)

    def test_unknown_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "source"
            shutil.copytree(HERE, copied, ignore=shutil.ignore_patterns(".deploy", "__pycache__"))
            path = copied / "agent.json"
            config = json.loads(path.read_text())
            config["future_capability"] = True
            path.write_text(json.dumps(config))
            with patch.object(deploy, "ROOT", copied), self.assertRaises(ValueError):
                deploy.load_definition()


if __name__ == "__main__":
    unittest.main()
