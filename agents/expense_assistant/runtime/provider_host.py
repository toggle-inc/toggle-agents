"""Deployment composition for encrypted, per-person service OAuth.

Only trusted deployment code supplies secrets and callback destinations. This
does not create Cloud Run resources, grant access, or register OAuth clients.
"""

from dataclasses import dataclass, field

from .connection_providers import build_service_connections
from .personal_calendar import PersonalCalendar
from .personal_mf import PersonalMF
from .provider_vault import EncryptedProviderVault


@dataclass(frozen=True)
class ProviderHostSettings:
    namespace: str
    mf_client_id: str
    mf_callback_uri: str
    google_client_id: str
    google_callback_uri: str
    encryption_key: bytes = field(repr=False)
    mf_client_secret: str = field(repr=False)
    google_client_secret: str = field(repr=False)


class ProviderHost:
    def __init__(self, store, settings, *, mf_http=None, calendar_http=None, clock=None):
        if not isinstance(settings, ProviderHostSettings):
            raise ValueError("Explicit provider host settings required")
        self.vault = EncryptedProviderVault(store, settings.encryption_key, namespace=settings.namespace)
        timing = {"clock": clock} if clock is not None else {}
        self.mf = PersonalMF(
            client_id=settings.mf_client_id, client_secret=settings.mf_client_secret,
            redirect_uri=settings.mf_callback_uri, vault_store=self.vault,
            http=mf_http, **timing,
        )
        self.calendar = PersonalCalendar(
            client_id=settings.google_client_id, client_secret=settings.google_client_secret,
            callback_uri=settings.google_callback_uri, vault_store=self.vault,
            http_client=calendar_http, **timing,
        )
        self.connections = build_service_connections(store, mf=self.mf, calendar=self.calendar, **timing)

    def close(self):
        self.calendar.close()
