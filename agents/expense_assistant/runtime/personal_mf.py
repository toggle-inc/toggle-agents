"""Trusted per-requester MF connection adapter; never register as model tools.

Inject app credentials and the exact deployed HTTPS callback at construction.
Production vault_store.transaction(owner, 'mf') must yield a mutable dict and
serialize across processes through token exchange/refresh, committing only on
normal exit. It must encrypt credentials separately from AuthorizationStore.
An explicit private vault_root is a single-host fallback, not Cloud Run storage.
ServiceConnections can use this adapter's status/begin/complete directly.
"""

import contextlib
import copy
import fcntl
import hashlib
import json
import math
import os
import secrets
import stat
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from .providers import MFClient
from .requester import Requester, _unexpired, _valid_id
from .state import ExpenseError, OutcomeUnknownError


class _RefreshRequired(ExpenseError):
    pass


class _VaultClient(MFClient):
    """Reuse MFClient's actual OAuth schema against the locked private vault."""

    def __init__(self, *args, records, **kwargs):
        super().__init__(*args, **kwargs)
        self._records = records
        self.runtime = False

    def _token(self, *, refresh=False):
        if not self.runtime:
            raise ValueError("Use the adapter refresh protocol")
        oauth = self._load().get("oauth", {})
        if oauth.get("reconnect_required"):
            raise ExpenseError("MF連携をやり直してください。")
        if (refresh or self.clock() >= oauth.get("obtained_at", 0) + oauth.get("expires_in", 0) - 300):
            raise _RefreshRequired()
        token = oauth.get("access_token")
        if not isinstance(token, str) or not token:
            raise ExpenseError("本人のMF連携がまだです。")
        return token

    def _load(self):
        if self._records and self._records.get("owner") != self.owner:
            raise ValueError("Invalid vault owner")
        return copy.deepcopy(self._records) or {"owner": self.owner}

    def _save(self, data):
        self._records.clear()
        self._records.update(copy.deepcopy({**data, "owner": self.owner}))


class PersonalMF:
    """Identity must come from trusted host authentication, never browser fields.

    Runtime financial calls must not bypass this adapter's durable refresh
    consumption protocol; do not expose _client or MFClient._token directly.
    """

    def __init__(self, *, client_id, client_secret, redirect_uri,
                 vault_store=None, vault_root=None, http=None, clock=time.time):
        try:
            parsed = urlsplit(redirect_uri)
            valid = (
                isinstance(redirect_uri, str)
                and all(32 < ord(c) < 127 for c in redirect_uri)
                and parsed.scheme == "https" and parsed.hostname
                and not parsed.username and not parsed.password
                and parsed.port in (None, 443) and parsed.path.startswith("/")
                and parsed.query in ("", "provider=mf") and not parsed.fragment
                and "\\" not in redirect_uri
            )
        except (ValueError, TypeError):
            valid = False
        if not valid:
            raise ValueError("Exact deployed HTTPS callback required")
        if not all(isinstance(v, str) and v.strip() for v in (client_id, client_secret)):
            raise ValueError("Trusted MF app credentials required")
        if (vault_store is None) == (vault_root is None):
            raise ValueError("Supply one private vault store or explicit filesystem root")
        self.vault_store = vault_store
        self._client_id, self._secret = client_id, client_secret
        self.redirect_uri, self.http, self.clock = redirect_uri, http, clock
        self._root = None
        if vault_root is not None:
            root = Path(vault_root).expanduser().absolute()
            if root.is_symlink() or root.resolve().is_relative_to(Path(__file__).resolve().parents[3]):
                raise ValueError("Private vault root must be outside repository")
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not root.is_dir() or root.stat().st_mode & 0o077:
                raise ValueError("Private vault directory mode 0700 required")
            self._root = root.resolve()

    def _person(self, person, provider="mf"):
        if (provider != "mf" or not isinstance(person, Requester)
                or person.kind != "human" or not _valid_id(person.tenant_id)
                or not _valid_id(person.person_id)
                or not _unexpired(person.expires_at, self.clock())):
            raise ValueError("Verified human MF session required")

    @contextlib.contextmanager
    def _file_transaction(self, owner):
        # flock protects separate instances/processes, unlike an instance mutex.
        if self._root.is_symlink() or self._root.stat().st_mode & 0o077:
            raise ValueError("Invalid private vault root")
        name = hashlib.sha256(owner.encode()).hexdigest()
        path = self._root / (name + ".json")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self._root / (name + ".lock"), flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("Invalid vault lock")
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            if path.is_symlink():
                raise ValueError("Invalid vault")
            if path.exists():
                info = path.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_nlink != 1:
                    raise ValueError("Invalid vault")
                data = json.loads(path.read_text())
            else:
                data = {}
            before = copy.deepcopy(data)
            yield data
            if data == before:
                return
            temporary_fd, temporary = tempfile.mkstemp(prefix=".mf-", dir=self._root)
            try:
                with os.fdopen(temporary_fd, "w") as stream:
                    json.dump(data, stream, allow_nan=False)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
                directory_fd = os.open(self._root, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                Path(temporary).unlink(missing_ok=True)
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def _client(self, person):
        self._person(person)
        try:
            transaction = (self.vault_store.transaction(person.owner, "mf")
                           if self.vault_store is not None else self._file_transaction(person.owner))
            with transaction as records:
                self._person(person)
                if not isinstance(records, dict):
                    raise ValueError("Invalid vault")
                client = _VaultClient(
                    self._client_id, self._secret, ".", person.owner,
                    records=records, http=self.http, clock=self.clock,
                    redirect_uri=self.redirect_uri,
                )
                try:
                    client._load()  # Validate owner even for an otherwise empty OAuth record.
                    yield client
                finally:
                    if self.http is None:
                        client.http.close()
        except _RefreshRequired:
            raise
        except OutcomeUnknownError:
            raise OutcomeUnknownError("MF書き込みの結果が不明です。明細を照合してください。") from None
        except Exception:
            # No provider body, code, token, secret, path or chained exception to GUI.
            raise ExpenseError("本人のMF接続を確認できません。接続をやり直してください。") from None

    def status(self, person, provider):
        self._person(person, provider)
        try:
            with self._client(person) as client:
                data = client._load()
                if "oauth" not in data:
                    return "expired" if data.get("auth_outcome") == "unknown" else "not_connected"
                oauth = data["oauth"]
                if not isinstance(oauth, dict):
                    return "unavailable"
                for key in ("access_token", "refresh_token"):
                    if key in oauth and (not isinstance(oauth[key], str) or not oauth[key].strip()):
                        return "unavailable"
                if oauth.get("reconnect_required") is True:
                    return "expired"
                if oauth.get("refresh_token"):
                    return "connected"
                if not oauth.get("access_token"):
                    return "unavailable"
                obtained, duration = oauth.get("obtained_at"), oauth.get("expires_in")
                if any(type(v) not in (int, float) or not math.isfinite(v)
                       for v in (obtained, duration)) or duration <= 0:
                    return "unavailable"
                return "connected" if self.clock() < obtained + duration else "expired"
        except Exception:
            return "unavailable"

    def begin(self, person, provider):
        self._person(person, provider)
        with self._client(person) as client:
            target = client.authorize_url()
            data = client._load()
            pending = data["pending"]
            data["auth_attempt"] = pending["attempt"] = secrets.token_hex(32)
            data["auth_outcome"] = "pending"
            pending["expires"] = min(pending["expires"], person.expires_at)
            pending["state_hash"] = hashlib.sha256(pending.pop("state").encode()).hexdigest()
            client._save(data)
            return target

    def complete(self, person, provider, callback_params):
        self._person(person, provider)
        # Accept parsed parameters only; callback destination is deployment-fixed.
        if (not hasattr(callback_params, "items")
                or set(callback_params) not in ({"state", "code"}, {"state", "error"})):
            raise ValueError("Invalid MF callback")
        if hasattr(callback_params, "multi_items"):
            if len(list(callback_params.multi_items())) != 2:
                raise ValueError("Duplicate MF callback parameters")
        state = callback_params["state"]
        code = callback_params.get("code")
        error = callback_params.get("error")
        if (not isinstance(state, str) or not 1 <= len(state) <= 256
                or (code is not None and (not isinstance(code, str) or not 1 <= len(code) <= 4096
                    or any(c.isspace() or ord(c) < 32 for c in code)))
                or ("error" in callback_params and
                    (not isinstance(error, str) or not 1 <= len(error) <= 256))
                or ("code" in callback_params and code is None)):
            raise ValueError("Invalid MF callback")
        with self._client(person) as client:
            data = client._load()
            pending = data.get("pending", {})
            if (pending.get("state_hash") != hashlib.sha256(state.encode()).hexdigest()
                    or not _unexpired(pending.get("expires"), self.clock())):
                raise ValueError("Invalid or expired MF callback")
            # Commit consumption BEFORE HTTP; even ambiguous failures cannot retry.
            # This uses the vault's own transaction: encrypted vaults can share
            # AuthorizationStore without nested transactions or lock deadlocks.
            data.pop("pending")
            attempt = pending["attempt"]
            data["auth_outcome"] = "denied" if error is not None else "unknown"
            client._save(data)
        if error is not None:
            raise ExpenseError("MF連携が許可されませんでした。接続をやり直してください。")
        with self._client(person) as client:
            data = client._load()
            if data.get("auth_attempt") != attempt:
                raise ValueError("MF authorization superseded")
            oauth = client._exchange({"grant_type": "authorization_code", "code": code,
                                      "redirect_uri": self.redirect_uri})
            data = client._load()
            if data.get("auth_attempt") != attempt:
                raise ValueError("MF authorization superseded")
            client._save({**data, "oauth": oauth, "auth_outcome": "connected"})
        # Provider responses are deliberately not forwarded, including expires_in.
        return {"provider": "mf", "status": "connected"}

    def for_person(self, person):
        """ExpenseService-compatible facade; authorization completion is GUI-only."""
        self._person(person)
        return _PersonalMF(self, person)

    def refresh(self, person, provider="mf"):
        """Trusted runtime entry, never an LLM tool; no ambiguous-token retry.

        Removal is committed before exchange. A crash, timeout, rejected token,
        or failed credential commit requires new consent rather than replaying
        the old refresh token. The transaction also serializes successful saves.
        """
        self._person(person, provider)
        attempt = secrets.token_hex(32)
        with self._client(person) as client:
            data = client._load()
            oauth = data.get("oauth", {})
            refresh_token = oauth.get("refresh_token")
            if not isinstance(refresh_token, str) or not refresh_token.strip():
                raise ValueError("MF reconnection required")
            data["oauth"] = {"reconnect_required": True, "refresh_unknown": True,
                             "refresh_attempt": attempt}
            client._save(data)
        with self._client(person) as client:
            data = client._load()
            if data.get("oauth", {}).get("refresh_attempt") != attempt:
                raise ValueError("MF refresh superseded")
            oauth = client._exchange({"grant_type": "refresh_token", "refresh_token": refresh_token})
            oauth.setdefault("refresh_token", refresh_token)
            client._save({**data, "oauth": oauth})
        return {"provider": "mf", "status": "connected"}


class _PersonalMF:
    _METHODS = frozenset({
        "request", "offices", "list_transactions", "list_reports", "create_transaction",
        "get_transaction", "update_transaction", "delete_transaction", "upload_receipt",
        "download_receipt",
    })

    def __init__(self, adapter, person):
        self._adapter, self._person = adapter, person

    @property
    def owner(self):
        return self._person.owner

    def __getattr__(self, name):
        if name not in self._METHODS:
            raise AttributeError("MF authorization is available only in the private GUI")

        def invoke(*args, **kwargs):
            for retry in (False, True):
                self._adapter._person(self._person)
                try:
                    with self._adapter._client(self._person) as client:
                        client.runtime = True
                        return getattr(client, name)(*args, **kwargs)
                except _RefreshRequired:
                    if retry:
                        raise ExpenseError("MF連携をやり直してください。") from None
                    self._adapter.refresh(self._person)
        return invoke
