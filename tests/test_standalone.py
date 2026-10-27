"""The repository test entry point delegates to independently runnable agent tests."""

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class StandaloneTests(unittest.TestCase):
    def test_each_agent_suite(self):
        for folder in sorted((ROOT / "agents").iterdir()):
            if not folder.is_dir():
                continue
            with self.subTest(agent=folder.name):
                self.assertTrue((folder / "test_deploy.py").is_file())
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "unittest",
                        "discover",
                        "-s",
                        ".",
                        "-p",
                        "test_*.py",
                        "-v",
                    ],
                    cwd=folder,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
