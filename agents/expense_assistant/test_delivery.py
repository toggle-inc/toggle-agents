"""The agent owns private routing semantics; no platform connection is simulated as live."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from runtime.delivery import load_contract, resolve_binding  # noqa: E402


class DeliveryTests(unittest.TestCase):
    def test_contract_covers_all_result_paths_and_has_reproducible_identity(self):
        contract = load_contract()
        self.assertEqual(
            contract["source_sha256"],
            hashlib.sha256((HERE / "delivery.json").read_bytes()).hexdigest(),
        )
        self.assertIn("tool_result", contract["policy"]["protected_outputs"])
        self.assertIn("completion_summary", contract["policy"]["protected_outputs"])
        self.assertNotIn("connection_id", str(contract))

    def test_same_agent_selects_private_surface_for_each_supported_entry(self):
        policy = load_contract()["policy"]
        for platform, binding in policy["platform_bindings"].items():
            decision = resolve_binding(
                platform,
                verified_capabilities={binding["capability"]},
                verified_guarantees=policy["required_guarantees"],
            )
            self.assertEqual(decision["binding"], binding)
            self.assertEqual(decision["recipient_source"], "verified_request_actor")
            self.assertEqual(
                decision["conversation_binding"], "verified_requester_and_invoked_agent"
            )
            self.assertEqual(decision["result_audience"], "authenticated_requester_only")
            self.assertEqual(decision["origin_notification"]["mode"], "fixed_receipt_only")

    def test_unknown_platform_missing_capability_and_missing_guarantee_withhold(self):
        policy = load_contract()["policy"]
        for platform, capabilities, guarantees in (
            ("unknown", {"requester_private_message"}, policy["required_guarantees"]),
            ("success_assist", set(), policy["required_guarantees"]),
            ("buzz", {"requester_private_message"}, []),
        ):
            with self.assertRaisesRegex(ValueError, "withhold"):
                resolve_binding(
                    platform, verified_capabilities=capabilities, verified_guarantees=guarantees
                )

    def test_public_fallback_or_model_chosen_recipient_is_refused(self):
        original = load_contract()["policy"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for change in (
                {"result_audience": "origin_channel"},
                {"recipient_source": "model"},
                {"conversation_binding": "requester_self_dm"},
                {"conversation_binding": "model_selected_agent"},
                {"conversation_binding": None},
                {"missing_private_delivery": "origin_channel"},
                {"protected_outputs": ["answer"]},
            ):
                (root / "delivery.json").write_text(json.dumps({**original, **change}))
                with self.assertRaises(ValueError):
                    load_contract(root)


if __name__ == "__main__":
    unittest.main()
