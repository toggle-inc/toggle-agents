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
sys.path.insert(0, str(HERE))
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
                    "runtime",
                    "mcp_server.py",
                    "engine_mcp.py",
                    "connect.py",
                    "requirements.txt",
                    "expense_preview.py",
                    "delivery.json",
                },
            )
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

    def test_optional_connection_is_bound_only_in_generated_package(self):
        with tempfile.TemporaryDirectory() as directory:
            output = deploy.build(123, Path(directory) / "package", connection_ids=[456])
            manifest = json.loads((output / "agentize.managed-agent.json").read_text())
            self.assertEqual(manifest["conn_ids"], [456])
            self.assertEqual(json.loads((HERE / "agent.json").read_text())["conn_ids"], [])
            self.assertTrue((output / "runtime" / "service.py").is_file())
            self.assertEqual(
                (output / "delivery.json").read_bytes(), (HERE / "delivery.json").read_bytes()
            )
            self.assertIn(
                '"result_audience": "authenticated_requester_only"',
                (output / "instructions.md").read_text(),
            )


if __name__ == "__main__":
    unittest.main()
