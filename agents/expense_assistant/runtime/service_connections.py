"""Agent-owned private connection UI; identity and providers come from trusted adapters.

The browser never supplies a person ID, credential, callback URL or provider URL.
This module starts authorization only; it never writes financial records.
"""

import hashlib
import html
import math
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from .requester import Requester


@dataclass(frozen=True)
class ConnectionProvider:
    id: str
    label: str
    authorization_origins: frozenset[str]


class ServiceConnections:
    """status(person, provider) -> state; begin(person, provider) -> authorization URL.

    Callbacks MUST freshly resolve only the verified person's provider vault.
    An unavailable provider is not an absent user consent. Neither callback is
    an LLM tool, and no legacy/shared credential fallback is permitted.
    """

    STATES = frozenset({"connected", "not_connected", "expired", "not_configured", "unavailable"})

    def __init__(self, store, *, providers, status, begin, complete=None, clock=time.time):
        self.store, self.status, self.begin, self.clock = store, status, begin, clock
        self.providers = {provider.id: provider for provider in providers}
        self._complete = complete
        if not self.providers or len(self.providers) != len(providers):
            raise ValueError("Explicit unique service providers required")
        for key, provider in self.providers.items():
            if key not in {"mf", "calendar"} or not provider.label.strip():
                raise ValueError("Unsupported connection provider")
            if not provider.authorization_origins or any(
                not self._origin(origin) or self._origin(origin) != origin
                for origin in provider.authorization_origins
            ):
                raise ValueError("Exact HTTPS provider origins required")
        if not callable(status) or not callable(begin):
            raise ValueError("Per-person service adapters required")

    @staticmethod
    def _origin(url):
        try:
            if not isinstance(url, str) or any(
                ord(character) <= 32 or ord(character) >= 127 or character in "'\";<>"
                for character in url
            ):
                return None
            value = urlsplit(url)
            if (
                value.scheme != "https" or not value.hostname or value.username
                or value.password or value.port not in (None, 443)
                or value.fragment or value.path not in ("", "/") or value.query
            ):
                return None
            return "https://" + value.netloc
        except (ValueError, TypeError):
            return None

    def _person(self, person):
        if (
            not isinstance(person, Requester) or person.kind != "human"
            or not person.tenant_id or not person.person_id
            or type(person.expires_at) not in (float, int)
            or not math.isfinite(person.expires_at) or person.expires_at <= self.clock()
        ):
            raise ValueError("Verified human session required")

    def view(self, person):
        self._person(person)
        result = []
        for provider in self.providers.values():
            try:
                state = self.status(person, provider.id)
                if state not in self.STATES:
                    state = "unavailable"
            except Exception:
                state = "unavailable"
            result.append({"id": provider.id, "label": provider.label, "status": state,
                           "authorization_origins": sorted(provider.authorization_origins)})
        nonce = secrets.token_urlsafe(32)
        expires_at = int(min(person.expires_at, self.clock() + 300))
        with self.store.transaction() as records:
            records.put("service-connect:" + hashlib.sha256(nonce.encode()).hexdigest(), {
                "owner": person.owner, "expires_at": expires_at,
                "used": False,
            })
        return {"schema_version": "agent-service-connections/v1", "csrf_token": nonce,
                "agent_slug": "expense_assistant", "expires_at": expires_at,
                "connections": result}

    def start(self, person, provider_id, nonce):
        self._person(person)
        if provider_id not in self.providers or not isinstance(nonce, str) or len(nonce) > 256:
            raise ValueError("Invalid connection request")
        key = "service-connect:" + hashlib.sha256(nonce.encode()).hexdigest()
        with self.store.transaction() as records:
            record = records.get(key)
            if (
                not record or record.get("owner") != person.owner or record.get("used")
                or record.get("expires_at", 0) <= self.clock()
            ):
                raise ValueError("Expired or invalid connection request")
            records.put(key, {**record, "used": True})
        state = self.status(person, provider_id)
        if state not in {"not_connected", "expired"}:
            raise ValueError("Connection does not require authorization")
        target = self.begin(person, provider_id)
        try:
            parsed = urlsplit(target)
            origin = "https://" + parsed.netloc
            if (
                parsed.scheme != "https" or parsed.username or parsed.password
                or parsed.port not in (None, 443) or parsed.fragment
                or origin not in self.providers[provider_id].authorization_origins
            ):
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError("Invalid configured authorization destination") from None
        return target

    def complete(self, person, provider_id, parameters):
        """Only a verified private callback, never a model-selected owner or URL."""
        self._person(person)
        if provider_id not in self.providers or not callable(self._complete):
            raise ValueError("Provider callback unavailable")
        if not isinstance(parameters, dict):
            raise ValueError("Invalid provider callback")
        if provider_id == "calendar":
            extra = {"scope", "authuser", "prompt", "hd", "iss"}
            if parameters.get("iss", "https://accounts.google.com") != "https://accounts.google.com":
                raise ValueError("Invalid provider issuer")
            if not set(parameters) <= {"code", "state", "error"} | extra:
                raise ValueError("Invalid provider callback")
            parameters = {key: value for key, value in parameters.items() if key not in extra}
        if set(parameters) not in (
            {"code", "state"}, {"error", "state"},
        ) or any(not isinstance(v, str) or not v or len(v) > 4096 for v in parameters.values()):
            raise ValueError("Invalid provider callback")
        # Provider adapter must check its own one-time state and exact person.
        self._complete(person, provider_id, parameters)
        state = self.status(person, provider_id)
        return {"schema_version": "agent-service-connection-result/v1",
                "provider": provider_id, "status": state if state in self.STATES else "unavailable"}

    def render(self, person, *, as_json=False):
        view = self.view(person)
        if as_json:
            return JSONResponse(view)
        states = {"connected": "接続済み", "not_connected": "未接続",
                  "expired": "再接続が必要", "not_configured": "設定未完了",
                  "unavailable": "一時的に利用できません"}
        cards = []
        for connection in view["connections"]:
            label, state = html.escape(connection["label"]), connection["status"]
            card = "<section><h2>" + label + "</h2><p>" + states[state] + "</p>"
            if state in {"not_connected", "expired"}:
                card += (
                    '<form method="post" action="/connections/start">'
                    '<input type="hidden" name="provider" value="' + connection["id"] + '">'
                    '<input type="hidden" name="csrf_token" value="' + view["csrf_token"] + '">'
                    '<button type="submit">' + label + "に接続する</button></form>"
                )
            elif state == "not_configured":
                card += "<p>管理者によるサービス連携の設定が必要です。</p>"
            elif state == "unavailable":
                card += "<p>接続サービスの復旧を待ってください。再認証やキー入力は不要です。</p>"
            cards.append(card + "</section>")
        return HTMLResponse(
            '<!doctype html><html lang="ja"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            "<title>経費アシスタントのサービス連携</title><h1>サービス連携</h1>"
            "<p>ログイン中のご本人のアカウントだけを接続します。"
            "APIキーや認可コードをチャットへ貼る必要はありません。</p>"
            + "".join(cards) + "</html>"
        )
