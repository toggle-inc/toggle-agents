"""Transport authorization checks use only synthetic state, never financial services."""

import asyncio
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from engine_mcp import OwnerAuthorization, issue_key, read_key, main  # noqa: E402
from runtime.state import ExpenseError  # noqa: E402


class EngineMCPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "key.json"
        issue_key(self.path, "synthetic-owner")
        self.secret = json.loads(self.path.read_text())["token"]
        self.called = 0

    def tearDown(self):
        self.temp.cleanup()

    def request(self, headers):
        async def downstream(scope, receive, send):
            self.called += 1
            await send({"type": "http.response.start", "status": 200, "headers": []})

        events = []

        async def send(event):
            events.append(event)

        middleware = OwnerAuthorization(downstream, self.path, "synthetic-owner")
        asyncio.run(middleware({"type": "http", "headers": headers}, None, send))
        return events[0]["status"]

    def test_key_is_private_scoped_short_lived_and_not_overwritten(self):
        key = read_key(self.path, "synthetic-owner")
        self.assertEqual(key["tenant_id"], 10)
        self.assertLessEqual(key["expires_at"], time.time() + 86400)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            issue_key(self.path, "another-owner")
        with self.assertRaises(ExpenseError):
            issue_key(Path(self.temp.name) / "other.json", "synthetic-owner", hours=49)

    def test_explicit_48_hour_key_expires_without_extending_on_read(self):
        path = Path(self.temp.name) / "48-hour.json"
        issue_key(path, "synthetic-owner", hours=48, clock=lambda: 100)
        self.assertEqual(read_key(path, "synthetic-owner", clock=lambda: 100)["expires_at"], 172900)
        self.assertEqual(read_key(path, "synthetic-owner", clock=lambda: 172899)["expires_at"], 172900)
        with self.assertRaises(ExpenseError):
            read_key(path, "synthetic-owner", clock=lambda: 172900)
        for index, hours in enumerate((0, 49, True, 1.5)):
            with self.subTest(hours=hours), self.assertRaises(ExpenseError):
                issue_key(Path(self.temp.name) / f"bad-{index}.json", "synthetic-owner", hours=hours)

    def test_read_only_serve_overrides_write_enabled_profile_without_editing_it(self):
        service = Mock(write_enabled=True)
        with patch.object(sys, "argv", [
            "engine_mcp.py", "serve", "--profile", "synthetic-profile.json",
            "--key-file", str(self.path), "--public-host", "qa.example.test", "--read-only",
        ]), patch("engine_mcp.connect", return_value=service), patch(
            "engine_mcp.create_app", return_value=Mock()
        ), patch("uvicorn.run") as run:
            main()
        self.assertFalse(service.write_enabled)
        self.assertEqual(run.call_args.kwargs["host"], "127.0.0.1")

    def test_missing_wrong_and_duplicate_headers_never_enter_mcp(self):
        header = (b"authorization", ("Bearer " + self.secret).encode())
        for headers in ([], [(b"authorization", b"Bearer incorrect")], [header, header]):
            self.assertEqual(self.request(headers), 401)
        self.assertEqual(self.called, 0)
        self.assertEqual(self.request([header]), 200)
        self.assertEqual(self.called, 1)

    def test_expired_revoked_wrong_owner_and_insecure_keys_fail_closed(self):
        original = json.loads(self.path.read_text())
        header = [(b"authorization", ("Bearer " + self.secret).encode())]
        for overrides in ({"expires_at": 0}, {"owner": "other"}, {"tenant_id": 1}):
            self.path.write_text(json.dumps({**original, **overrides}))
            self.assertEqual(self.request(header), 401)
        self.path.write_text(json.dumps(original))
        os.chmod(self.path, 0o644)
        self.assertEqual(self.request(header), 401)
        self.path.unlink()
        self.assertEqual(self.request(header), 401)
        self.assertEqual(self.called, 0)


if __name__ == "__main__":
    unittest.main()
