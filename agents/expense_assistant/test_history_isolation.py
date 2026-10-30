"""Opt-in isolation, synthetic proofs and actual legacy HTTP; no external calls."""

import dataclasses
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime.history_invocation_gate import HistoryInvocationGate
from runtime.history_invocation import HistoryProofError
import test_history_invocation as proof_fixtures
import test_requester_mcp as http_fixtures


class HistoryGateTests(unittest.TestCase):
    def test_default_and_explicit_disabled_never_call_new_adapters(self):
        for options in ({}, {"enabled": False}):
            callbacks = {name: Mock(side_effect=AssertionError("legacy path touched new adapter"))
                         for name in ("validator_factory", "resolve_expected", "load_proofs")}
            gate = HistoryInvocationGate(**options, **callbacks)
            for context in (None, {}, object(), {"history_proof": "malformed"}):
                self.assertIsNone(gate.reference(context))
            for callback in callbacks.values():
                callback.assert_not_called()

    def test_disabled_import_needs_no_crypto_keys_network_or_new_definition_fields(self):
        script = """
import builtins, socket
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.startswith(('jwt', 'cryptography', 'runtime.history_invocation')) and name != 'runtime.history_invocation_gate':
        raise AssertionError('disabled history imported new dependency')
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
socket.socket = lambda *a, **kw: (_ for _ in ()).throw(AssertionError('network touched'))
from runtime.history_invocation_gate import HistoryInvocationGate
assert HistoryInvocationGate().reference(None) is None
"""
        reply = subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parent,
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(reply.returncode, 0, reply.stderr)

    def test_only_explicit_boolean_opt_in_accepts_complete_adapters(self):
        for enabled in ("true", 1, {}, None):
            with self.assertRaises(ValueError):
                HistoryInvocationGate(enabled=enabled)
        for missing in ("validator_factory", "resolve_expected", "load_proofs"):
            callbacks = dict.fromkeys(("validator_factory", "resolve_expected", "load_proofs"), lambda: None)
            callbacks.pop(missing)
            with self.assertRaises(ValueError):
                HistoryInvocationGate(enabled=True, **callbacks)

    def test_opt_in_does_not_mutate_other_gate_and_checks_binding_each_call(self):
        fixture = proof_fixtures.HistoryInvocationTests()
        fixture.source_key = proof_fixtures.HistoryInvocationTests.source_key
        fixture.call_key = proof_fixtures.HistoryInvocationTests.call_key
        fixture.setUp()
        current = {"expected": fixture.expected}
        proofs = fixture.tokens()
        expected = Mock(side_effect=lambda context: current["expected"])
        load = Mock(return_value=proofs)
        factory = Mock(return_value=fixture.validator)
        active = HistoryInvocationGate(enabled=True, validator_factory=factory,
                                      resolve_expected=expected, load_proofs=load)
        legacy = HistoryInvocationGate()
        context = object()
        self.assertEqual(active.reference(context).session_id, "session-a")
        current["expected"] = dataclasses.replace(fixture.expected, session_id="other-session")
        with self.assertRaises(HistoryProofError):
            active.reference(context)
        self.assertIsNone(legacy.reference(context))
        self.assertEqual(expected.call_count, 2)
        self.assertEqual(factory.call_count, 2)
        self.assertEqual(load.call_count, 2)

    def test_invalid_identity_fails_before_proof_and_trust_access(self):
        factory, load = Mock(), Mock()
        gate = HistoryInvocationGate(enabled=True, validator_factory=factory,
                                     resolve_expected=lambda _: None, load_proofs=load)
        with self.assertRaises(HistoryProofError):
            gate.reference(object())
        factory.assert_not_called()
        load.assert_not_called()

    @classmethod
    def setUpClass(cls):
        proof_fixtures.HistoryInvocationTests.setUpClass()


class LegacyHTTPHistoryIsolationTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = http_fixtures.RequesterMCPTests.asyncSetUp
    rpc = http_fixtures.RequesterMCPTests.rpc

    @http_fixtures.with_server
    async def test_unconfigured_legacy_auth_tools_and_result_ignore_new_proof_headers(self):
        from runtime.requester import OPERATIONS
        new_headers = {"x-agent-history-source": "invalid-new-proof",
                       "x-agent-history-call": "invalid-new-proof"}
        with patch("urllib.request.build_opener", side_effect=AssertionError("extra history HTTP")), \
             patch("httpx.Client.send", side_effect=AssertionError("extra synchronous HTTP")), \
             patch("runtime.history_invocation.HistoryInvocationValidator.validate",
                   side_effect=AssertionError("legacy proof validation")):
            catalog = (await self.rpc("alice", "tools/list", {})).json()["result"]
            baseline = (await self.rpc("alice")).json()["result"]
            self.assertEqual({t["name"] for t in catalog["tools"]}, set(OPERATIONS))
            self.assertFalse(baseline.get("isError"))
            for name in ("alice", "bob"):
                response = await self.client.post("/mcp", headers={
                    **self.headers, **new_headers, "authorization": "Bearer " + self.tokens[name],
                }, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "mf_offices", "arguments": {}}})
                self.assertEqual(response.status_code, 200)
                result = response.json()["result"]
                self.assertFalse(result.get("isError"))
                self.assertIn(name, json.dumps(result))
                self.assertNotIn("bob" if name == "alice" else "alice", json.dumps(result))
                if name == "alice":
                    self.assertEqual(result, baseline)
            for headers in (new_headers, {**new_headers, "authorization": "Bearer invalid"}):
                response = await self.client.post("/mcp", headers=headers, json={})
                self.assertEqual(response.status_code, 401)
        self.assertEqual(self.grants["alice"].service.mf.calls, 2)
        self.assertEqual(self.grants["bob"].service.mf.calls, 1)
