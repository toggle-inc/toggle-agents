"""Compose the agent-owned OAuth host from explicit private deployment settings.

No Engine/platform imports, default person, single-owner environment fallback or
automatic identity links. The deployment must provide both trusted resolvers.
"""

import ipaddress
import os
import re
from dataclasses import dataclass, field

from authorization_app import create_app
from runtime.authorization import AgentAuthorization, PublicClient
from runtime.draft_consent import DraftConsentBinding
from runtime.okta_oidc import OktaOIDCLogin
from runtime.postgres_auth_store import PostgresAuthorizationStore


def _network_hosts(value):
    if not isinstance(value, str) or not value:
        return False
    for host in value.split(","):
        if not host or host != host.strip() or host.startswith(("/", "@", "\\")):
            return False
        try:
            ipaddress.ip_address(host)
        except ValueError:
            labels = host.rstrip(".").split(".")
            if len(host) > 253 or any(
                not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in labels
            ):
                return False
    return True


@dataclass(frozen=True)
class AuthorizationHostSettings:
    origin: str
    tenant_id: str
    okta_issuer: str
    okta_client_id: str
    clients: tuple[PublicClient, ...]
    database_url: str = field(repr=False)
    okta_client_secret: str = field(repr=False)
    state_encryption_key: str = field(repr=False)


@dataclass(frozen=True)
class PlatformAuthorizationHostSettings:
    origin: str
    tenant_id: str
    platform_issuer: str
    platform_public_keys: dict[str, str] = field(repr=False)
    clients: tuple[PublicClient, ...]
    database_url: str = field(repr=False)


def settings_from_environment(*, origin, tenant_id, okta_issuer, okta_client_id, clients):
    """Read dedicated secrets only; public metadata comes from trusted config."""
    names = (
        "EXPENSE_AUTH_DATABASE_URL",
        "EXPENSE_OKTA_CLIENT_SECRET",
        "EXPENSE_OKTA_STATE_KEY",
    )
    values = [os.environ.get(name, "") for name in names]
    if not all(value.strip() for value in values):
        raise ValueError("Dedicated authorization host secrets are not configured")
    return AuthorizationHostSettings(
        origin=origin,
        tenant_id=tenant_id,
        okta_issuer=okta_issuer,
        okta_client_id=okta_client_id,
        clients=tuple(clients),
        database_url=values[0],
        okta_client_secret=values[1],
        state_encryption_key=values[2],
    )


def create_host(settings, *, resolve_person, resolve_connection, store_factory=None, service_connections_factory=None, history_factory=None, history_boundary_migration=False):
    """Compose SSO, consent, refresh/revocation and MCP with the SAME store.

    resolve_person(tenant, issuer, subject) is an administrator-managed account
    link resolver. resolve_connection(person, capability) returns only this
    person's current ConnectionGrant, or None. They are not model tool inputs.
    No database DDL or provider writes are performed by this constructor.
    """
    if not isinstance(settings, AuthorizationHostSettings):
        raise ValueError("Explicit authorization host settings required")
    if not callable(resolve_person) or not callable(resolve_connection):
        raise ValueError("Explicit identity and per-person connection resolvers required")
    if not isinstance(settings.clients, tuple) or not settings.clients:
        raise ValueError("Explicit OAuth clients required")
    if (type(history_boundary_migration) is not bool
            or (history_boundary_migration and history_factory is None)):
        raise ValueError("History boundary migration requires explicit configured history")
    store = _configured_store(settings, store_factory)
    okta = OktaOIDCLogin(
        store,
        resolve_person,
        issuer=settings.okta_issuer,
        client_id=settings.okta_client_id,
        client_secret=settings.okta_client_secret,
        callback_uri=settings.origin.rstrip("/") + "/login/callback",
        tenant_id=settings.tenant_id,
        state_encryption_key=settings.state_encryption_key,
    )
    authority = AgentAuthorization(
        store,
        okta.verify_login,
        issuer=settings.origin,
        tenant_id=settings.tenant_id,
        clients=settings.clients,
    )
    return create_app(
        authority,
        resolve_connection,
        login_adapter=okta,
        draft_consent=DraftConsentBinding(authority, resolve_connection),
        service_connections=service_connections_factory(store) if service_connections_factory else None,
        **({"history_factory": history_factory} if history_factory is not None else {}),
        **({"history_boundary_migration": True} if history_boundary_migration else {}),
    )


def _configured_store(settings, store_factory):
    # libpq can otherwise pick a broad local default, service or password file.
    # Reject a missing/weak TLS policy before opening any remote connection.
    from psycopg.conninfo import conninfo_to_dict

    try:
        database = conninfo_to_dict(settings.database_url)
    except Exception:
        raise ValueError("Invalid dedicated PostgreSQL configuration") from None
    if (
        database.get("sslmode") != "verify-full"
        or not all(database.get(name) for name in ("host", "dbname", "user", "password"))
        or database.get("service")
        or not _network_hosts(database.get("host"))
    ):
        raise ValueError("Dedicated PostgreSQL connection with verified TLS required")
    # Validate public OAuth configuration before constructing a connection store.
    AgentAuthorization(
        None,
        lambda _: None,
        issuer=settings.origin,
        tenant_id=settings.tenant_id,
        clients=settings.clients,
    )
    return (store_factory or PostgresAuthorizationStore)(settings.database_url)


def create_platform_host(settings, *, resolve_person, resolve_connection, store_factory=None, service_connections_factory=None, history_factory=None, history_boundary_migration=False):
    """Preferred route: platform authenticates humans, agent verifies each proof.

    No Okta client/secret/callback/session is needed. The deployment must provide
    a trusted platform BFF and pinned verification keys; this constructor alone
    does not deploy that platform endpoint or register a trust relationship.
    """
    from _foundation.platform_identity import PlatformIdentityVerifier
    from runtime.platform_login import PlatformLogin

    if not isinstance(settings, PlatformAuthorizationHostSettings):
        raise ValueError("Explicit platform authorization host settings required")
    if not callable(resolve_person) or not callable(resolve_connection):
        raise ValueError("Explicit identity and per-person connection resolvers required")
    if not isinstance(settings.clients, tuple) or not settings.clients:
        raise ValueError("Explicit OAuth clients required")
    if (type(history_boundary_migration) is not bool
            or (history_boundary_migration and history_factory is None)):
        raise ValueError("History boundary migration requires explicit configured history")
    store = _configured_store(settings, store_factory)
    verifier = PlatformIdentityVerifier(
        store,
        resolve_person,
        issuer=settings.platform_issuer,
        audience=settings.origin,
        tenant_id=settings.tenant_id,
        public_keys=settings.platform_public_keys,
    )
    login = PlatformLogin(verifier)
    authority = AgentAuthorization(
        store,
        login.verify_login,
        issuer=settings.origin,
        tenant_id=settings.tenant_id,
        clients=settings.clients,
    )
    return login.wrap(
        create_app(
            authority,
            resolve_connection,
            draft_consent=DraftConsentBinding(authority, resolve_connection),
            platform_login=login,
            service_connections=service_connections_factory(store) if service_connections_factory else None,
            **({"history_factory": history_factory} if history_factory is not None else {}),
            **({"history_boundary_migration": True} if history_boundary_migration else {}),
        )
    )
