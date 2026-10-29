"""Per-person Google Calendar OAuth; invoked only by authenticated host code.

Never register begin/complete as model tools. The host must authenticate the
signed UI callback afresh and pass query parameters directly, without logging
codes/state. Google email claims are deliberately not identity selectors.

Production vault_store.transaction(owner, 'calendar') must lock across processes,
yield a private mutable dict, commit on normal exit and roll back on exceptions.
An explicit private_vault_root enables the local POSIX file implementation only.
"""

import base64
import copy
from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import stat
import time
from urllib.parse import urlencode, urlsplit
from zoneinfo import ZoneInfo

import httpx

from .requester import Requester
from .state import ExpenseError


SCOPE = "https://www.googleapis.com/auth/calendar.events.readonly"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
EVENTS_URL = "https://www.googleapis.com/calendar/v3/calendars/primary/events"


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


class _FileVault:
    """Private local storage with descriptor-relative I/O and process locks."""

    def __init__(self, root):
        self.root = Path(root).absolute()
        if ".." in self.root.parts:
            raise ValueError("Explicit private vault root required")

    @contextmanager
    def transaction(self, owner, provider):
        opened = []
        temporary = None
        try:
            fd = os.open(self.root.anchor, os.O_RDONLY | os.O_DIRECTORY)
            opened.append(fd)
            for component in self.root.parts[1:]:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                opened.append(fd)
            self._private(fd, directory=True)
            name = hashlib.sha256(owner.encode()).hexdigest() + "-" + provider
            try:
                os.mkdir(name, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            opened.append(fd)
            self._private(fd, directory=True)
            lock = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            opened.append(lock)
            self._private(lock)
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                token = os.open("vault.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                data = {}
            else:
                with os.fdopen(token) as stream:
                    self._private(stream.fileno())
                    data = json.load(stream)
                if not isinstance(data, dict):
                    raise ValueError("Invalid private vault")
            yield data
            # Refuse replacing a symlink or insecure existing token file.
            try:
                current = os.open("vault.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                pass
            else:
                try:
                    self._private(current)
                finally:
                    os.close(current)
            temporary = ".vault-" + secrets.token_hex(16)
            token = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=fd)
            with os.fdopen(token, "w") as stream:
                json.dump(data, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, "vault.json", src_dir_fd=fd, dst_dir_fd=fd)
            temporary = None
            os.fsync(fd)
        finally:
            if temporary is not None:
                os.unlink(temporary, dir_fd=fd)
            for descriptor in reversed(opened):
                os.close(descriptor)

    @staticmethod
    def _private(fd, *, directory=False):
        info = os.fstat(fd)
        correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if (not correct_type or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
                or (not directory and info.st_nlink != 1)):
            raise ValueError("Unsafe private vault permissions")


class PersonalCalendar:
    """Synchronous trusted adapter; run blocking calls outside the ASGI loop.

    status returns connected, not_connected, expired or unavailable. complete
    returns connected/expired; unavailable raises a safe error AFTER commit.
    expired includes refresh_unknown: the old refresh credential cannot be
    retried, so only fresh human authorization can restore the connection. Its
    fence survives begin and failed callbacks; only successful complete clears
    it. Ordinary read/provider outages remain unavailable, without reconsent.
    begin returns only Google's authorization URL. No method returns tokens.
    for_person(person).events(start, end) implements providers.Calendar's shape.
    The host must separately enforce current agent/service grants on every read.
    """

    def __init__(self, *, client_id, client_secret, callback_uri,
                 vault_store=None, private_vault_root=None, clock=time.time,
                 http_client=None):
        if not all(isinstance(v, str) and v.strip() for v in (client_id, client_secret)):
            raise ValueError("Google OAuth client configuration required")
        if not isinstance(callback_uri, str) or any(ord(c) <= 32 or ord(c) >= 127 for c in callback_uri):
            raise ValueError("Fixed HTTPS callback required")
        callback = urlsplit(callback_uri)
        if (callback.scheme != "https" or not callback.hostname or callback.username
                or callback.password or callback.port not in (None, 443)
                or callback.query not in ("", "provider=calendar") or "#" in callback_uri):
            raise ValueError("Fixed HTTPS callback required")
        if (vault_store is None) == (private_vault_root is None):
            raise ValueError("Supply exactly one private vault store or explicit root")
        self.vault_store = vault_store if vault_store is not None else _FileVault(private_vault_root)
        self.client_id, self._client_secret = client_id, client_secret
        self.callback_uri, self.clock = callback_uri, clock
        self._binding = hashlib.sha256(json.dumps([client_id, callback_uri, SCOPE]).encode()).hexdigest()
        self.http = http_client if http_client is not None else httpx.Client(
            timeout=15, follow_redirects=False, trust_env=False)
        self._owns_http = http_client is None

    def close(self):
        if self._owns_http:
            self.http.close()

    def _person(self, person, provider="calendar"):
        if (provider != "calendar" or not isinstance(person, Requester)
                or person.kind != "human" or not _number(person.expires_at)
                or person.expires_at <= self.clock()
                or not all(isinstance(v, str) and v.strip() and len(v) <= 512
                           for v in (person.tenant_id, person.person_id))):
            raise ValueError("Verified human calendar session required")

    @contextmanager
    def _vault(self, person):
        with self.vault_store.transaction(person.owner, "calendar") as data:
            if not isinstance(data, dict):
                raise ValueError("Invalid private vault")
            if data and (data.get("owner") != person.owner or data.get("binding") != self._binding):
                raise ValueError("Private calendar vault binding mismatch")
            data.update(owner=person.owner, binding=self._binding)
            yield data

    def begin(self, person, provider="calendar"):
        self._person(person, provider)
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        with self._vault(person) as data:
            data.pop("authorization_attempt", None)
            data["pending"] = {"state_hash": hashlib.sha256(state.encode()).hexdigest(),
                               "verifier": verifier,
                               "expires_at": min(person.expires_at, self.clock() + 300)}
        return AUTH_URL + "?" + urlencode({
            "client_id": self.client_id, "redirect_uri": self.callback_uri,
            "response_type": "code", "scope": SCOPE, "access_type": "offline",
            "prompt": "consent", "state": state,
            "code_challenge": challenge, "code_challenge_method": "S256",
        })

    @staticmethod
    def _param(params, name):
        values = params.getlist(name) if hasattr(params, "getlist") else [params.get(name)]
        if len(values) != 1 or not isinstance(values[0], str) or not 0 < len(values[0]) <= 4096:
            return None
        return values[0]

    def complete(self, person, provider, callback_params):
        self._person(person, provider)
        state = self._param(callback_params, "state")
        if not state:
            raise ValueError("Invalid calendar callback")
        attempt = secrets.token_urlsafe(32)
        with self._vault(person) as data:
            pending = data.get("pending")
            if (not isinstance(pending, dict) or not hmac.compare_digest(
                    pending.get("state_hash", ""), hashlib.sha256(state.encode()).hexdigest())
                    or pending.get("expires_at", 0) <= self.clock()):
                raise ValueError("Expired or invalid calendar callback")
            del data["pending"]
            data.pop("refresh_attempt", None)
            data["authorization_attempt"] = attempt
            data["reauthorize"] = True
        # Consumption must COMMIT before the provider sees a code. A later
        # credential-save failure cannot restore the code for a second exchange.
        with self._vault(person) as data:
            if data.get("authorization_attempt") != attempt:
                raise ValueError("Calendar authorization superseded")
            outcome = self._complete_locked(data, callback_params, pending)
            data.pop("authorization_attempt", None)
        if outcome == "unavailable":
            raise ExpenseError("Googleカレンダーの接続を一時的に確認できません。")
        return outcome

    def _complete_locked(self, data, callback_params, pending):
        code = self._param(callback_params, "code")
        if callback_params.get("error") or not code:
            return "expired"
        outcome, tokens = self._exchange({"grant_type": "authorization_code", "code": code,
            "code_verifier": pending["verifier"], "redirect_uri": self.callback_uri})
        if outcome != "connected":
            return outcome
        oauth = self._tokens(tokens)
        if oauth is None:
            return "unavailable"
        # Never combine an old account's refresh token with a new code grant.
        if not oauth.get("refresh_token"):
            data.pop("oauth", None)
            data["reauthorize"] = True
            return "expired"
        data["oauth"] = oauth
        data["reauthorize"] = False
        data.pop("refresh_unknown", None)
        data.pop("refresh_inflight_until", None)
        data.pop("refresh_attempt", None)
        return "connected"

    def _exchange(self, fields):
        try:
            response = self.http.post(TOKEN_URL, data={**fields, "client_id": self.client_id,
                                                      "client_secret": self._client_secret},
                                      follow_redirects=False)
            body = response.json()
            if not isinstance(body, dict):
                return "unavailable", None
            if response.status_code == 200:
                return "connected", body
            if response.status_code == 400 and body.get("error") == "invalid_grant":
                return "expired", None
            return "unavailable", None
        except Exception:
            return "unavailable", None

    def _tokens(self, tokens, previous=None):
        access, expires = tokens.get("access_token"), tokens.get("expires_in")
        if (not isinstance(access, str) or not access or not _number(expires) or expires <= 60
                or not isinstance(tokens.get("token_type"), str)
                or tokens["token_type"].lower() != "bearer"):
            return None
        scope = tokens.get("scope")
        if scope is not None and (not isinstance(scope, str) or SCOPE not in scope.split()):
            return None
        refresh = tokens.get("refresh_token", (previous or {}).get("refresh_token"))
        if refresh is not None and (not isinstance(refresh, str) or not refresh):
            return None
        return {"access_token": access, "refresh_token": refresh,
                "expires_at": self.clock() + expires}

    def _ready(self, data):
        # A lost refresh response may have rotated the credential. Persist this
        # fence so neither this process nor another replica retries the old one.
        if data.get("refresh_unknown"):
            if data.get("refresh_inflight_until", 0) > self.clock():
                return "unavailable"
            return "expired"
        if data.get("reauthorize"):
            return "expired"
        oauth = data.get("oauth")
        if not oauth:
            return "not_connected"
        if not oauth.get("refresh_token"):
            return "expired"
        if _number(oauth.get("expires_at")) and oauth["expires_at"] > self.clock() + 60:
            return "connected"
        return "refresh_required"

    def _ensure_ready(self, person):
        attempt = secrets.token_urlsafe(32)
        with self._vault(person) as data:
            outcome = self._ready(data)
            if outcome != "refresh_required":
                return outcome
            oauth = copy.deepcopy(data["oauth"])
            data["refresh_unknown"] = True
            data["refresh_attempt"] = attempt
            data["refresh_inflight_until"] = self.clock() + 60
        # The old credential is fenced durably, even if the exchange succeeds
        # but the next transaction/commit fails. Never replay it after a crash.
        with self._vault(person) as data:
            if data.get("refresh_attempt") != attempt:
                return "unavailable"
            outcome = self._refresh_locked(data, oauth)
            data.pop("refresh_inflight_until", None)
            data.pop("refresh_attempt", None)
            return outcome

    def _refresh_locked(self, data, oauth):
        outcome, tokens = self._exchange({"grant_type": "refresh_token",
                                          "refresh_token": oauth["refresh_token"]})
        if outcome == "expired":
            data.pop("oauth", None)
            data["reauthorize"] = True
        elif outcome == "connected":
            updated = self._tokens(tokens, oauth)
            if updated is None:
                data["refresh_unknown"] = True
                return "expired"
            data["oauth"] = updated
            data.pop("refresh_unknown", None)
        else:
            data["refresh_unknown"] = True
            return "expired"
        return outcome

    def status(self, person, provider="calendar"):
        self._person(person, provider)
        try:
            return self._ensure_ready(person)
        except Exception:
            return "unavailable"

    def for_person(self, person):
        self._person(person)
        return _BoundCalendar(self, person)

    def events(self, person, date_from, date_to):
        self._person(person)
        zone = ZoneInfo("Asia/Tokyo")
        try:
            first, last = dt.date.fromisoformat(date_from), dt.date.fromisoformat(date_to)
            if first > last or (last - first).days > 366:
                raise ValueError
            lower = dt.datetime.combine(first, dt.time.min, zone).isoformat()
            upper = dt.datetime.combine(last + dt.timedelta(days=1), dt.time.min, zone).isoformat()
        except (ValueError, TypeError, OverflowError):
            raise ExpenseError("カレンダーの期間は1年以内で指定してください。") from None
        outcome, result = "unavailable", []
        try:
            outcome = self._ensure_ready(person)
            with self._vault(person) as data:
                if self._ready(data) != "connected":
                    outcome = self._ready(data)
                if outcome == "connected":
                    # Keep refresh rotation committed even when the later read
                    # fails; an exception escaping the vault would roll it back.
                    try:
                        outcome, result = self._read_events(data, lower, upper, zone)
                    except Exception:
                        outcome = "unavailable"
        except Exception:
            outcome = "unavailable"
        if outcome != "connected":
            message = ("本人のGoogleカレンダーを認証画面で再接続してください。"
                       if outcome in {"expired", "not_connected"}
                       else "Googleカレンダーを一時的に利用できません。")
            raise ExpenseError(message)
        return sorted(result, key=lambda event: event["start"])

    def _read_events(self, data, lower, upper, zone):
        params = {"timeMin": lower, "timeMax": upper, "singleEvents": "true",
                  "orderBy": "startTime", "maxResults": 2500, "timeZone": "Asia/Tokyo"}
        seen, result = set(), []
        for _ in range(100):
            response = self.http.get(EVENTS_URL, params=params,
                headers={"Authorization": "Bearer " + data["oauth"]["access_token"]},
                follow_redirects=False)
            if response.status_code == 401:
                data.pop("oauth", None)
                data["reauthorize"] = True
                return "expired", []
            if response.status_code != 200:
                return "unavailable", []
            page = response.json()
            for event in page["items"]:
                if event.get("status") == "cancelled" or (
                        event.get("transparency") == "transparent" and not event.get("location")):
                    continue
                start, end = event["start"], event.get("end", {})

                def text(value):
                    if "date" in value:
                        return value["date"]
                    raw = value.get("dateTime")
                    if not raw:
                        return None
                    parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        raise ValueError("Calendar event timezone required")
                    return parsed.astimezone(zone).isoformat(timespec="minutes")

                result.append({"id": event["id"], "start": text(start), "end": text(end),
                    "all_day": "date" in start, "summary": event.get("summary", ""),
                    "location": event.get("location", ""),
                    "description": event.get("description", "")[:300]})
            next_page = page.get("nextPageToken")
            if not next_page:
                return "connected", result
            if not isinstance(next_page, str) or next_page in seen:
                return "unavailable", []
            seen.add(next_page)
            params["pageToken"] = next_page
        return "unavailable", []


class _BoundCalendar:
    def __init__(self, adapter, person):
        self._adapter, self._person = adapter, person
        self.owner = person.owner

    def events(self, start, end):
        return self._adapter.events(self._person, start, end)
