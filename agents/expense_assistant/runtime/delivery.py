"""Agent-owned delivery policy. Transport hosts implement, but do not choose, this policy."""

import hashlib
import json
from pathlib import Path


def load_contract(root=None):
    root = Path(root) if root is not None else Path(__file__).resolve().parents[1]
    raw = (root / "delivery.json").read_bytes()
    policy = json.loads(raw)
    if (
        policy.get("schema_version") != "agent-delivery-contract/v1"
        or policy.get("result_audience") != "authenticated_requester_only"
        or policy.get("recipient_source") != "verified_request_actor"
        or policy.get("missing_private_delivery") != "withhold_result_no_origin_fallback"
        or policy.get("origin_notification", {}).get("mode") != "fixed_receipt_only"
        or not isinstance(policy.get("origin_notification", {}).get("text"), str)
        or not policy["origin_notification"]["text"].strip()
        or set(policy.get("protected_outputs", []))
        != {
            "answer",
            "intermediate_result",
            "tool_result",
            "progress",
            "error",
            "attachment",
            "completion_summary",
        }
        or set(policy.get("required_guarantees", []))
        != {
            "authenticated_actor_binding",
            "requester_only_visibility",
            "no_origin_streaming",
            "idempotent_delivery",
        }
        or not isinstance(policy.get("platform_bindings"), dict)
        or not policy["platform_bindings"]
    ):
        raise ValueError("Unsupported or incomplete agent-owned delivery contract")
    for platform, binding in policy["platform_bindings"].items():
        if (
            not isinstance(platform, str)
            or not isinstance(binding, dict)
            or set(binding) != {"private_surface", "display_term", "connection_role", "capability"}
            or not all(isinstance(value, str) and value.strip() for value in binding.values())
        ):
            raise ValueError("Unsupported private conversation binding")
    return {"policy": policy, "source_sha256": hashlib.sha256(raw).hexdigest()}


def resolve_binding(platform, *, verified_capabilities, verified_guarantees, root=None):
    """Agent-owned choice; host inputs must come from verified transport capabilities.

    Never expose this as an LLM-authorized recipient selector. A host must still
    authenticate the actual request actor and resolve a requester-only target.
    Missing capability means withhold, never fall back to the origin channel.
    """
    contract = load_contract(root)
    policy = contract["policy"]
    binding = policy["platform_bindings"].get(platform)
    if (
        binding is None
        or binding["capability"] not in verified_capabilities
        or not set(policy["required_guarantees"]).issubset(verified_guarantees)
    ):
        raise ValueError("Private delivery unavailable; withhold result")
    return {
        "schema_version": policy["schema_version"],
        "source_sha256": contract["source_sha256"],
        "binding": binding,
        "recipient_source": policy["recipient_source"],
        "origin_notification": policy["origin_notification"],
        "result_audience": policy["result_audience"],
    }
