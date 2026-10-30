"""Explicit durable business composition; never changes consent or cloud config.

Factories are trusted per-person deployment adapters. Financial writes require
both an explicit enabled profile and current authority-issued capability; the
service separately enforces initial company consent or exact individual approval.
"""

from .durable_receipts import DurableReceipts
from .durable_state import DurableState
from .service import ExpenseService
from .state import ExpenseError

CAPABILITIES = frozenset({"mf:read", "mf:draft", "mf:write", "calendar:read", "contract:read",
                          "memory:read", "memory:propose", "receipt:read", "attachment:read",
                          "fare:read", "rules:read"})


class _PersonalMFView:
    READ = frozenset({"offices", "list_transactions", "list_reports", "get_transaction", "download_receipt"})

    def __init__(self, owner, client, capability):
        self.owner, self._client = owner, client
        self.configured = client is not None
        self._methods = self.READ
        if capability == "mf:draft":
            self._methods |= {"create_transaction", "upload_receipt"}
        elif capability == "mf:write":
            self._methods |= {"create_transaction", "upload_receipt", "update_transaction", "delete_transaction"}

    def __getattr__(self, name):
        if self._client is None or name not in self._methods:
            raise ExpenseError("この操作の本人接続・提供能力を確認してください。")
        return getattr(self._client, name)


class DurableExecutionProfile:
    def __init__(self, store, encryption_key, namespace, *, capabilities,
                 financial_writes=False, policy_factory=None, fetcher_factory=None,
                 fares_factory=None, references_factory=None, office_scope_factory=None):
        if (not isinstance(capabilities, frozenset) or not capabilities <= CAPABILITIES
                or type(financial_writes) is not bool or not isinstance(namespace, str)
                or not namespace.strip() or not callable(getattr(store, "transaction", None))
                or any(v is not None and not callable(v) for v in (
                    policy_factory, fetcher_factory, fares_factory, references_factory, office_scope_factory))):
            raise ValueError("Explicit durable business profile required")
        from cryptography.fernet import Fernet
        Fernet(encryption_key)
        if capabilities & {"mf:draft", "mf:write"} and (not financial_writes or policy_factory is None):
            raise ValueError("Financial profile requires explicit enablement and private policy")
        if "attachment:read" in capabilities and fetcher_factory is None:
            raise ValueError("Authorized personal attachment adapter required")
        if "fare:read" in capabilities and fares_factory is None:
            raise ValueError("Explicit fare source required")
        if "rules:read" in capabilities and policy_factory is None:
            raise ValueError("Explicit private policy required")
        self.store, self._key, self.namespace = store, encryption_key, namespace
        self.capabilities, self.financial_writes = capabilities, financial_writes
        self.policy_factory, self.fetcher_factory = policy_factory, fetcher_factory
        self.fares_factory, self.references_factory = fares_factory, references_factory
        self.office_scope_factory = office_scope_factory

    @property
    def supported_operations(self):
        operations = set()
        groups = {
            "mf:read": {"mf_offices", "mf_list_transactions", "mf_list_reports", "mf_known_items",
                        "mf_payee_memory", "mf_get_receipt", "mf_receipt_status"},
            "mf:draft": {"mf_create_transaction", "mf_upload_receipt", "mf_save_draft"},
            "mf:write": {"mf_create_transaction", "mf_upload_receipt", "mf_update_transaction", "mf_delete_transaction"},
            "calendar:read": {"calendar_events"}, "contract:read": {"delivery_contract"},
            "memory:read": {"expense_context"}, "memory:propose": {"propose_teaching"},
            "attachment:read": {"fetch_attachment"}, "fare:read": {"fare_lookup"},
            "rules:read": {"check_rules"},
        }
        for capability in self.capabilities:
            operations |= groups.get(capability, set())
        if "rules:read" in self.capabilities and self.references_factory is not None:
            operations.add("read_reference")
        return frozenset(operations)

    def service(self, *, person, mf, calendar, clock, capability, consent_only=False):
        if consent_only:
            service = ExpenseService(
                mf=_PersonalMFView(person.owner, mf, "mf:read"),
                state=DurableState(self.store, self._key, person.owner, self.namespace, clock),
                write_enabled=False,
            )
            if self.office_scope_factory is not None:
                service.consent_office_ids = frozenset(self.office_scope_factory(person))
            return service
        fetcher = self.fetcher_factory(person) if capability == "attachment:read" and self.fetcher_factory is not None else None
        if fetcher is not None and getattr(fetcher, "owner", None) != person.owner:
            raise ExpenseError("本人専用の添付接続を確認できません。")
        policy = self.policy_factory(person) if capability in {"mf:draft", "mf:write", "rules:read"} and self.policy_factory is not None else None
        state = DurableState(self.store, self._key, person.owner, self.namespace, clock)
        receipts = DurableReceipts(self.store, self._key, person.owner, self.namespace, fetcher)
        return ExpenseService(
            mf=_PersonalMFView(person.owner, mf, capability if not consent_only else "mf:read"),
            state=state, receipts=receipts, calendar=calendar, policy=policy,
            fares=self.fares_factory(person) if capability == "fare:read" and self.fares_factory is not None else None,
            references=self.references_factory(person) if capability == "rules:read" and self.references_factory is not None else None,
            write_enabled=(not consent_only and self.financial_writes and capability in {"mf:draft", "mf:write"}),
        )
