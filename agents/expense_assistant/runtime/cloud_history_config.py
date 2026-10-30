"""Explicit cloud history trust/config; no source client, secrets, or default wiring."""

from dataclasses import dataclass, field
import re

from _foundation.execution_binding import ExecutionTarget, ExternalExecutionVerifier
from _foundation.history_runtime import create_conversation_runtime
from _foundation.platform_identity import PlatformPersonLink, _identifier, _origin
from .external_history_resolver import ExternalHistoryResolver


def _fields(value, required):
    if not isinstance(value, dict) or set(value) != set(required):
        raise ValueError("Invalid cloud history fields")


def _id(value):
    if not _identifier(value):
        raise ValueError("Explicit history identifier required")
    return value


SOURCE_READ_KEY_ENV = "AGENT_SA_SOURCE_READ_SIGNING_PRIVATE_KEY_PEM"


@dataclass(frozen=True, repr=False)
class SourceReadSettings:
    origin: str
    kid: str
    source_namespace: str
    source_actor: str
    target: ExecutionTarget
    agent_authors: tuple
    signing_key_env: str

    def __repr__(self):
        return "SourceReadSettings(<redacted>)"


@dataclass(frozen=True, repr=False)
class CloudHistorySettings:
    source_issuer: str
    source_public_keys: dict = field(repr=False)
    execution_issuer: str
    execution_public_keys: dict = field(repr=False)
    audience: str
    tenant_id: str
    targets: tuple
    identity_links: tuple = field(repr=False)
    source_read: SourceReadSettings | None = field(default=None, repr=False)

    def __repr__(self):
        return "CloudHistorySettings(<redacted>)"

    def resolve_person(self, issuer, namespace, subject):
        for configured_issuer, configured_namespace, configured_subject, person in self.identity_links:
            if (issuer, namespace, subject) == (configured_issuer, configured_namespace, configured_subject):
                return PlatformPersonLink(self.tenant_id, person)
        return None

    def verifier(self, store):
        return ExternalExecutionVerifier(
            store, self.resolve_person, source_issuer=self.source_issuer,
            source_keys=self.source_public_keys, execution_issuer=self.execution_issuer,
            execution_keys=self.execution_public_keys, audience=self.audience, targets=self.targets,
        )


def parse_cloud_history(value, *, audience, tenant_id, allowed_people, platform_issuer=None):
    """Pure validation. Disabled settings do not parse trust, keys or identities."""
    if isinstance(value, dict) and value == {"enabled": False} and type(value["enabled"]) is bool:
        return None
    try:
        if not isinstance(value, dict):
            raise ValueError
        _fields({k: v for k, v in value.items() if k != "source_read"},
                ("enabled", "source_issuer", "source_public_keys", "execution_issuer",
                 "execution_public_keys", "targets", "identity_links"))
        if value["enabled"] is not True:
            raise ValueError
        source, execution, audience = (_origin(value["source_issuer"]),
                                       _origin(value["execution_issuer"]), _origin(audience))
        tenant_id = _id(tenant_id)
        targets = []
        if not isinstance(value["targets"], list) or not 1 <= len(value["targets"]) <= 32:
            raise ValueError
        for target in value["targets"]:
            _fields(target, ("tenant_id", "agent_id", "version_id", "connection_id"))
            targets.append(ExecutionTarget(*(_id(target[k]) for k in (
                "tenant_id", "agent_id", "version_id", "connection_id"))))
        if len(set(targets)) != len(targets):
            raise ValueError
        links, seen = [], set()
        if not isinstance(value["identity_links"], list) or not 1 <= len(value["identity_links"]) <= 256:
            raise ValueError
        for link in value["identity_links"]:
            _fields(link, ("issuer", "namespace", "subject", "person_id"))
            actor = (_origin(link["issuer"]), _id(link["namespace"]), _id(link["subject"]))
            person = _id(link["person_id"])
            if actor in seen or person not in allowed_people:
                raise ValueError
            seen.add(actor)
            links.append((*actor, person))
        if not any(issuer == source for issuer, _, _, _ in links):
            raise ValueError
        source_read = None
        if "source_read" in value:
            item = value["source_read"]
            _fields(item, ("origin", "kid", "source_namespace", "source_actor", "target",
                           "agent_authors", "signing_key_env"))
            _fields(item["target"], ("tenant_id", "agent_id", "version_id", "connection_id"))
            read_target = ExecutionTarget(*(_id(item["target"][k]) for k in (
                "tenant_id", "agent_id", "version_id", "connection_id")))
            if (platform_issuer is None or _origin(item["origin"]) != source
                    or source != _origin(platform_issuer) or read_target not in targets
                    or any(not re.fullmatch(r"[1-9][0-9]{0,15}", v) or int(v) > 2**53-1 for v in (
                        read_target.tenant_id, read_target.agent_id, read_target.version_id, read_target.connection_id))
                    or not isinstance(item["kid"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", item["kid"])
                    or len(_id(item["source_namespace"])) > 128 or len(_id(item["source_actor"])) > 256
                    or item["signing_key_env"] != SOURCE_READ_KEY_ENV
                    or not isinstance(item["agent_authors"], list) or not 1 <= len(item["agent_authors"]) <= 16
                    or any(len(_id(v)) > 256 for v in item["agent_authors"])
                    or len(set(item["agent_authors"])) != len(item["agent_authors"])
                    or not any((issuer, namespace, subject) == (source, item["source_namespace"], item["source_actor"])
                               for issuer, namespace, subject, _ in links)):
                raise ValueError
            source_read = SourceReadSettings(source, item["kid"], item["source_namespace"], item["source_actor"],
                                             read_target, tuple(item["agent_authors"]), SOURCE_READ_KEY_ENV)
        settings = CloudHistorySettings(source, value["source_public_keys"], execution,
            value["execution_public_keys"], audience, tenant_id, tuple(targets), tuple(links), source_read)
        # Constructor parses pinned public keys and target trust only; no store or HTTP access.
        settings.verifier(None)
        return settings
    except Exception:
        raise ValueError("Invalid cloud history configuration") from None


def build_cloud_history(settings, store, source_factory):
    """Use existing auth_records for replay; source construction is trusted injection.

    source_factory(settings,store) returns (foundation-compatible source, verified
    source-reference resolver). No source route/authentication schema is guessed.
    Source must check pre-bound session and current ACL/anchor/revocation on reads.
    """
    if settings is None:
        return None
    if not isinstance(settings, CloudHistorySettings) or not callable(source_factory):
        raise ValueError("Enabled cloud history requires an explicit source adapter")
    if store is None or not callable(getattr(store, "transaction", None)):
        raise ValueError("Transactional history replay store required")
    verifier = settings.verifier(store)
    pair = source_factory(settings, store)
    if (not isinstance(pair, tuple) or len(pair) != 2
            or not callable(getattr(pair[0], "read", None)) or not callable(pair[1])):
        raise ValueError("Explicit history source and resolver required")
    source, resolve_source = pair
    runtime = create_conversation_runtime(enabled=True, sources_factory=lambda: {"success_assist": source})
    return runtime, ExternalHistoryResolver(
        verifier, resolve_source, agent_slug="expense_assistant", source_platform="success_assist")
