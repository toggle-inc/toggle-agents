"""Explicit runtime business profile, with private key/policy supplied outside Git.

No scope grants, policy source copies, credential migration, network or service
configuration changes. Missing policy never becomes a permissive default.
"""

import hashlib
import hmac
from pathlib import Path
import re

from cryptography.fernet import Fernet

from .execution_profile import CAPABILITIES, DurableExecutionProfile
from .providers import Fares, PrivatePolicy, SafeFetch
from .state import ExpenseError

BUSINESS_KEY_ENV = "EXPENSE_BUSINESS_ENCRYPTION_KEY"
POLICY_ENV = "EXPENSE_PRIVATE_POLICY"


def prepare_business_profile(value, *, environ, allowed_people):
    """Validate private configuration before any store opens; return a factory.

    Existing clients' scopes stay unchanged. Operator enables implementation
    only; the authority and initial company consent still gate each execution.
    """
    if isinstance(value, dict) and set(value) == {"enabled"} and value["enabled"] is False:
        return None
    try:
        if (not isinstance(value, dict) or set(value) != {
                "enabled", "namespace", "capabilities", "financial_writes", "policies"}
                or value["enabled"] is not True or type(value["financial_writes"]) is not bool
                or not isinstance(value["namespace"], str) or not 1 <= len(value["namespace"]) <= 512
                or value["namespace"] != value["namespace"].strip()
                or not isinstance(value["capabilities"], list) or not value["capabilities"]
                or any(not isinstance(v, str) for v in value["capabilities"])
                or len(set(value["capabilities"])) != len(value["capabilities"])):
            raise ValueError
        capabilities = frozenset(value["capabilities"])
        namespace, financial_writes = value["namespace"], value["financial_writes"]
        if not capabilities <= CAPABILITIES or "attachment:read" in capabilities:
            # Attachment import requires a request-bound, trusted source adapter.
            # Do not turn a static URL allowlist into private source authority.
            raise ValueError
        key = environ.get(BUSINESS_KEY_ENV, "").encode("ascii")
        Fernet(key)
        provider_key = environ.get("EXPENSE_PROVIDER_ENCRYPTION_KEY", "").encode("ascii")
        if provider_key and hmac.compare_digest(key, provider_key):
            raise ValueError
        policies = {}
        if not isinstance(value["policies"], list) or len(value["policies"]) > 256:
            raise ValueError
        needs_policy = bool(capabilities & {"mf:draft", "mf:write", "rules:read"})
        if needs_policy and not value["policies"]:
            raise ValueError
        path = None
        if value["policies"]:
            path = Path(environ[POLICY_ENV]).expanduser()
            if (not path.is_absolute() or path.is_symlink() or not path.is_file()
                    or path.resolve().is_relative_to(Path(__file__).resolve().parents[1])
                    or path.stat().st_size > 512 * 1024):
                raise ValueError
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            for item in value["policies"]:
                if (not isinstance(item, dict) or set(item) != {"person_id", "office_ids", "sha256", "position"}
                        or item["person_id"] not in allowed_people or item["person_id"] in policies
                        or not isinstance(item["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
                        or item["sha256"] != actual or not isinstance(item["position"], str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", item["position"])
                        or not isinstance(item["office_ids"], list) or not 1 <= len(item["office_ids"]) <= 50
                        or any(not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", v) for v in item["office_ids"])
                        or len(set(item["office_ids"])) != len(item["office_ids"])):
                    raise ValueError
                policies[item["person_id"]] = {**item, "office_ids": tuple(item["office_ids"])}

        def policy_factory(person):
            policy = policies.get(person.person_id)
            if policy is None:
                raise ExpenseError("本人・会社に適用する認可済み規則が未設定です。")
            instance = PrivatePolicy(path, policy["sha256"], position=policy["position"])
            instance.verify()
            instance.office_ids = policy["office_ids"]
            return instance

        def factory(settings, store):
            return DurableExecutionProfile(store, key, namespace, capabilities=capabilities,
                financial_writes=financial_writes, policy_factory=policy_factory if needs_policy else None,
                office_scope_factory=(lambda person: policies.get(person.person_id, {}).get("office_ids", ())) if needs_policy else None,
                fares_factory=(lambda _: Fares(SafeFetch(("transit.yahoo.co.jp",)))) if "fare:read" in capabilities else None)

        # Validate capability/composition requirements without opening a store.
        class ValidationStore:
            def transaction(self):
                raise AssertionError("configuration must not access the store")
        factory(None, ValidationStore())
        return factory
    except Exception:
        raise ValueError("Invalid explicit business profile configuration") from None
