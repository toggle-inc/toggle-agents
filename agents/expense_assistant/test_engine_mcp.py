"""Transport authorization checks use only synthetic state, never financial services."""

import asyncio
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from engine_mcp import OwnerAuthorization, issue_key, read_key  # noqa: E402
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
            issue_key(Path(self.temp.name) / "other.json", "synthetic-owner", hours=25)

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
