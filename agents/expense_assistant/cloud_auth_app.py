"""Dedicated auth/connections ASGI composition; all deployment inputs are explicit."""

import json
import logging
import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from types import SimpleNamespace

from cryptography.fernet import Fernet
from psycopg.conninfo import conninfo_to_dict
from starlette.responses import JSONResponse

from _foundation.platform_identity import PlatformIdentityVerifier, PlatformPersonLink, _identifier, _origin
from authorization_host import PlatformAuthorizationHostSettings, _network_hosts, create_platform_host
from runtime.authorization import AgentAuthorization, PublicClient
from runtime.connection_providers import build_service_connections
from runtime.personal_calendar import PersonalCalendar
from runtime.personal_mf import PersonalMF
from runtime.provider_host import ProviderHost, ProviderHostSettings
from runtime.provider_vault import EncryptedProviderVault
from runtime.provider_execution import ProviderExecutionResolver, READ_OPERATIONS


def _fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise ValueError("Invalid configuration fields")


def _text(value):
    if not _identifier(value):
        raise ValueError("Explicit identifier required")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate configuration field")
        result[key] = value
    return result


@dataclass(frozen=True, repr=False)
class CloudAuthSettings:
    host: PlatformAuthorizationHostSettings
    ingress_mode: str
    identity_links: tuple
    provider_namespace: str
    mf: dict | None
    google: dict | None
    encryption_key: bytes = field(repr=False)
    mf_secret: str = field(repr=False)
    google_secret: str = field(repr=False)
    history: object = field(default=None, repr=False)
    business_factory: object = field(default=None, repr=False)

    def __repr__(self):
        return "CloudAuthSettings(<redacted>)"

    def resolve_person(self, issuer, platform_tenant, subject):
        if issuer != self.host.platform_issuer:
            return None
        for tenant, linked_subject, person in self.identity_links:
            if (tenant, linked_subject) == (platform_tenant, subject):
                return PlatformPersonLink(self.host.tenant_id, person)
        return None


def settings_from_environment(environ=None):
    """Validate everything before opening a store; never include values in errors."""
    env = os.environ if environ is None else environ
    try:
        config = json.loads(env["EXPENSE_AUTH_CONFIG"], object_pairs_hook=_unique_object)
        _fields(config, ("origin", "tenant_id", "platform_issuer", "platform_public_keys", "clients",
                         "identity_links", "provider_namespace", "ingress_mode"), ("mf", "google", "history", "business"))
        origin, issuer = _origin(config["origin"]), _origin(config["platform_issuer"])
        tenant = _text(config["tenant_id"])
        if config["ingress_mode"] not in ("cloud_run_tls", "asgi_tls"):
            raise ValueError
        if not isinstance(config["clients"], list) or not config["clients"]:
            raise ValueError
        clients = []
        for client in config["clients"]:
            _fields(client, ("client_id", "display_name", "redirect_uris", "capabilities"))
            for name in ("redirect_uris", "capabilities"):
                if not isinstance(client[name], list) or not client[name] or any(not isinstance(v, str) for v in client[name]):
                    raise ValueError
            clients.append(PublicClient(_text(client["client_id"]), _text(client["display_name"]),
                                        tuple(client["redirect_uris"]), frozenset(client["capabilities"])))
        AgentAuthorization(None, lambda _: None, issuer=origin, tenant_id=tenant, clients=tuple(clients))
        if not isinstance(config["platform_public_keys"], dict):
            raise ValueError
        PlatformIdentityVerifier(None, lambda *_: None, issuer=issuer, audience=origin,
                                 tenant_id=tenant, public_keys=config["platform_public_keys"])
        if not isinstance(config["identity_links"], list) or not config["identity_links"]:
            raise ValueError
        links, identities, people = [], set(), set()
        for link in config["identity_links"]:
            _fields(link, ("platform_tenant_id", "subject", "person_id"))
            identity = (_text(link["platform_tenant_id"]), _text(link["subject"]))
            person = _text(link["person_id"])
            # Distinct external identities must not accidentally share a vault.
            if identity in identities or person in people:
                raise ValueError
            identities.add(identity)
            people.add(person)
            links.append((*identity, person))
        dsn = env["EXPENSE_AUTH_DATABASE_URL"]
        database = conninfo_to_dict(dsn)
        if (database.get("sslmode") != "verify-full" or database.get("service")
                or not all(database.get(k) for k in ("host", "dbname", "user", "password"))
                or not _network_hosts(database.get("host"))
                or (config["ingress_mode"] == "cloud_run_tls"
                    and database.get("sslrootcert") != "/etc/ssl/certs/ca-certificates.crt")):
            raise ValueError
        key = env["EXPENSE_PROVIDER_ENCRYPTION_KEY"].encode("ascii")
        Fernet(key)
        providers, secrets = {}, {}
        for name, provider, secret_name in (("mf", "mf", "EXPENSE_MF_CLIENT_SECRET"),
                                             ("google", "calendar", "EXPENSE_GOOGLE_CLIENT_SECRET")):
            metadata = config.get(name)
            secret = env.get(secret_name, "")
            if metadata is not None:
                _fields(metadata, ("client_id", "callback_uri"))
                _text(metadata["client_id"])
                callback = metadata["callback_uri"]
                parsed = urlsplit(callback)
                _origin("https://" + parsed.netloc)
                if (parsed.scheme != "https" or not parsed.path.startswith("/") or parsed.fragment
                        or parsed.query != "provider=" + provider or "\\" in callback
                        or any(ord(c) <= 32 or ord(c) >= 127 for c in callback)
                        or not isinstance(secret, str) or not secret.strip()):
                    raise ValueError
            elif secret:
                raise ValueError
            providers[name], secrets[name] = metadata, secret
        history = None
        if "history" in config and not (
            isinstance(config["history"], dict) and set(config["history"]) == {"enabled"}
            and config["history"]["enabled"] is False
        ):
            from runtime.cloud_history_config import parse_cloud_history
            history = parse_cloud_history(config["history"], audience=origin, tenant_id=tenant,
                                          allowed_people=people, platform_issuer=issuer)
        business_factory = None
        if "business" in config and not (
            isinstance(config["business"], dict) and set(config["business"]) == {"enabled"}
            and config["business"]["enabled"] is False
        ):
            from runtime.business_profile_config import prepare_business_profile
            business_factory = prepare_business_profile(config["business"], environ=env, allowed_people=people)
        return CloudAuthSettings(
            PlatformAuthorizationHostSettings(origin, tenant, issuer, config["platform_public_keys"], tuple(clients), dsn),
            config["ingress_mode"], tuple(links), _text(config["provider_namespace"]),
            providers["mf"], providers["google"], key, secrets["mf"], secrets["google"], history, business_factory,
        )
    except Exception:
        raise ValueError("Invalid dedicated expense auth configuration") from None


class _NotConfiguredProvider:
    """Explicit disabled adapter for an auth-only host with neither app configured."""

    def status(self, *_):
        return "not_configured"

    def begin(self, *_):
        raise ValueError("Provider deployment is unavailable")

    def complete(self, *_):
        raise ValueError("Provider deployment is unavailable")


def _close_resources(resources):
    """Drain once, in reverse order; continue closing after a cleanup failure."""
    seen, failed = set(), False
    while resources:
        resource = resources.pop()
        if id(resource) in seen:
            continue
        seen.add(id(resource))
        try:
            resource.close()
        except Exception:
            failed = True
    if failed:
        raise ValueError("Dedicated expense resource cleanup failed") from None


class _CloudAuthApp:
    def __init__(self, app, settings, resources):
        self.app, self._settings, self._resources = app, settings, resources

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            try:
                return await self.app(scope, receive, send)
            finally:
                _close_resources(self._resources)
        if scope["type"] == "http":
            # Only deployment's explicit TLS-terminator contract establishes TLS.
            # No remote address, Forwarded or X-Forwarded-* value establishes it.
            scope = {**scope, "headers": [(k, v) for k, v in scope.get("headers", ())
                     if k.lower() != b"forwarded" and not k.lower().startswith(b"x-forwarded-")]}
            if self._settings.ingress_mode == "cloud_run_tls":
                scope["scheme"] = "https"
            if scope.get("path") == "/connections/callback" and scope.get("method") == "GET":
                return await JSONResponse({"error": "method_not_allowed"}, status_code=405,
                                          headers={"allow": "POST", "cache-control": "no-store"})(scope, receive, send)
            if scope.get("path") == "/health":
                return await JSONResponse({"status": "ok"}, headers={"cache-control": "no-store"})(scope, receive, send)
        return await self.app(scope, receive, send)


def create_app(*, environ=None, store_factory=None, history_source_factory=None, business_profile_factory=None):
    """Uvicorn factory; no secret reads or database access at module import."""
    logging.disable(logging.CRITICAL)
    settings = settings_from_environment(environ)
    if business_profile_factory is None:
        business_profile_factory = settings.business_factory
    if business_profile_factory is not None and not callable(business_profile_factory):
        raise ValueError("Explicit business profile factory required")
    real_source = settings.history.source_read if settings.history is not None else None
    history_env = os.environ if environ is None else environ
    needs_attachments = getattr(business_profile_factory, "requires_source_attachments", False)
    if needs_attachments and real_source is None:
        raise ValueError("Receipt preparation requires configured verified source history")
    if settings.history is not None and history_source_factory is not None and not callable(history_source_factory):
        raise ValueError("Enabled cloud history requires an explicit source adapter")
    if settings.history is not None and history_source_factory is None:
        if real_source is None:
            raise ValueError("Enabled cloud history requires an explicit source adapter")
        from runtime.sa_history_client import SAHistoryClient, validate_source_read_key
        validate_source_read_key(history_env.get(real_source.signing_key_env, ""))
    resources = []
    if settings.history is not None and history_source_factory is None:
        def history_source_factory(history_settings, store):
            client = SAHistoryClient(
                origin=real_source.origin, agent_origin=settings.host.origin,
                source_namespace=real_source.source_namespace, source_actor=real_source.source_actor,
                target=real_source.target, kid=real_source.kid,
                signing_private_key=history_env.get(real_source.signing_key_env, ""),
                agent_authors=real_source.agent_authors,
            )
            resources.append(client)
            return client, client.resolve_source
    execution = {}
    attachment_clients = {}

    def attachment_factory(person):
        from runtime.sa_attachment_client import SAAttachmentClient
        resolver = execution.get("history_resolver")
        binding = resolver.current() if resolver is not None else None
        if binding is None or not binding.matches(person):
            raise ValueError("Verified current source required for personal attachments")
        if person.owner not in attachment_clients:
            client = SAAttachmentClient(
                origin=real_source.origin, agent_origin=settings.host.origin,
                source_namespace=real_source.source_namespace, source_actor=real_source.source_actor,
                target=real_source.target, kid=real_source.kid, owner=person.owner,
                signing_private_key=history_env.get(real_source.signing_key_env, ""),
                resolve_binding=resolver.current,
            )
            attachment_clients[person.owner] = client
            resources.append(client)
        return attachment_clients[person.owner]

    def resolve_connection(person, capability):
        resolver = execution.get("resolver")
        return resolver(person, capability) if resolver is not None else None

    resolve_connection.supported_operations = READ_OPERATIONS
    def readiness_reason(person, capability):
        resolver = execution.get("resolver")
        return resolver.readiness_reason(person, capability) if resolver is not None else "unavailable"
    resolve_connection.readiness_reason = readiness_reason
    if business_profile_factory is not None:
        def consent_service(person):
            resolver = execution.get("resolver")
            if resolver is None:
                raise ValueError("Business profile is not ready")
            return resolver.consent_service(person)
        resolve_connection.consent_service = consent_service

    def bind_execution(store, providers):
        execution["resolver"] = ProviderExecutionResolver(
            providers, store, settings.provider_namespace, tenant_id=settings.host.tenant_id,
            **({"profile": business_profile_factory(settings, store,
                **({"attachment_factory": attachment_factory} if needs_attachments else {}))}
               if business_profile_factory is not None else {}))
        resolve_connection.supported_operations = execution["resolver"].supported_operations
        if business_profile_factory is not None:
            resolve_connection.receipt_resources = execution["resolver"].receipt_resources

    def connections(store):
        resources.append(store)
        mf, google = settings.mf, settings.google
        if mf and google:
            providers = ProviderHost(store, ProviderHostSettings(
                namespace=settings.provider_namespace,
                mf_client_id=mf["client_id"], mf_callback_uri=mf["callback_uri"],
                google_client_id=google["client_id"], google_callback_uri=google["callback_uri"],
                encryption_key=settings.encryption_key, mf_client_secret=settings.mf_secret,
                google_client_secret=settings.google_secret,
            ))
            resources.append(providers)
            bind_execution(store, providers)
            return providers.connections
        vault = EncryptedProviderVault(store, settings.encryption_key, namespace=settings.provider_namespace)
        mf_adapter = PersonalMF(client_id=mf["client_id"], client_secret=settings.mf_secret,
                                redirect_uri=mf["callback_uri"], vault_store=vault) if mf else None
        calendar = PersonalCalendar(client_id=google["client_id"], client_secret=settings.google_secret,
                                    callback_uri=google["callback_uri"], vault_store=vault) if google else None
        if calendar:
            resources.append(calendar)
        bind_execution(store, SimpleNamespace(mf=mf_adapter, calendar=calendar))
        return build_service_connections(store, mf=mf_adapter if mf or google else _NotConfiguredProvider(), calendar=calendar)

    configured_store_factory = store_factory
    history_options = {}
    if settings.history is not None or business_profile_factory is not None:
        from runtime.postgres_auth_store import PostgresAuthorizationStore
        def tracked_store_factory(dsn):
            store = (store_factory or PostgresAuthorizationStore)(dsn)
            resources.append(store)
            return store
        configured_store_factory = tracked_store_factory
    if settings.history is not None:
        from runtime.cloud_history_config import build_cloud_history
        def history_factory(store):
            pair = build_cloud_history(settings.history, store, history_source_factory)
            execution["history_resolver"] = pair[1]
            return pair
        history_options["history_factory"] = history_factory
        history_options["history_boundary_migration"] = settings.history.boundary_migration

    try:
        app = create_platform_host(settings.host, resolve_person=settings.resolve_person,
                                   resolve_connection=resolve_connection, store_factory=configured_store_factory,
                                   service_connections_factory=connections, **history_options)
        return _CloudAuthApp(app, settings, resources)
    except Exception:
        try:
            _close_resources(resources)
        except Exception:
            pass
        raise ValueError("Dedicated expense auth startup failed") from None


def main():
    logging.disable(logging.CRITICAL)
    import uvicorn

    uvicorn.run("cloud_auth_app:create_app", factory=True, host="0.0.0.0",
                port=int(os.environ.get("PORT", "8080")), proxy_headers=False,
                access_log=False, log_level="critical")


if __name__ == "__main__":
    main()
