"""Opt-in link to one user's existing local expense settings; never source shell code."""

import hashlib
import json
import os
import re
import shlex
from pathlib import Path

from .providers import Calendar, Fares, MFClient, PrivatePolicy, Receipts, SafeFetch
from .service import ExpenseService
from .state import ExpenseError, State


def read_settings(path):
    result = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:]
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key.strip()):
            raise ExpenseError("設定ファイルの形式を確認してください。内容は表示しません。")
        value = value.strip()
        if value.startswith(('"', "'")):
            parts = shlex.split(value, comments=True)
            if len(parts) != 1:
                raise ExpenseError("引用された設定値の形式を確認してください。")
            value = parts[0]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        # Shell variables and command substitution remain literal, never executed.
        result[key.strip()] = value
    return result


class LinkedMFClient(MFClient):
    """Use the existing user's token file without making a divergent credential copy.

    Refresh results are atomically saved back to the original private token file.
    The new metadata vault holds owner/path binding and OAuth state, not a token copy.
    This link is established only by a trusted local setup action, never an LLM tool.
    """

    def __init__(self, *args, legacy_token_file, legacy_owner, **kwargs):
        super().__init__(*args, **kwargs)
        if legacy_owner != self.owner:
            raise ExpenseError("既存設定と共通ランタイムの本人が一致しません。")
        self.legacy = Path(legacy_token_file).resolve()
        self._binding = hashlib.sha256(str(self.legacy).encode()).hexdigest()

    def _load(self):
        data = super()._load()
        if data.get("legacy_binding") != self._binding:
            raise ExpenseError(
                "既存認証との接続が未確認です。信頼済みの設定手順を実行してください。"
            )
        if self.legacy.is_symlink() or self.legacy.stat().st_mode & 0o077:
            raise ExpenseError("既存認証ファイルのアクセス権を確認してください。")
        oauth = json.loads(self.legacy.read_text())
        if not isinstance(oauth, dict) or not oauth.get("access_token"):
            raise ExpenseError("本人の既存MF連携を確認できません。")
        return {**data, "oauth": oauth}

    def _save(self, data):
        oauth = data.get("oauth")
        if oauth is not None:
            # Reuse the core client's atomic/private writer, only for this existing vault.
            if self._load()["oauth"] != oauth:
                import tempfile

                fd, temp = tempfile.mkstemp(prefix=".oauth-", dir=self.legacy.parent)
                try:
                    with os.fdopen(fd, "w") as stream:
                        json.dump(oauth, stream)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temp, self.legacy)
                finally:
                    Path(temp).unlink(missing_ok=True)
        super()._save(
            {
                **{key: value for key, value in data.items() if key != "oauth"},
                "legacy_binding": self._binding,
            }
        )


def initialize_profile(env_file, directory):
    """Create local non-secret references; existing profiles are never overwritten."""
    env_file = Path(env_file).resolve()
    settings = read_settings(env_file)
    required = ("MF_CLIENT_ID", "MF_CLIENT_SECRET", "KEIHI_OWNER_PUBKEY")
    if not all(settings.get(key) for key in required):
        raise ExpenseError("既存のMF設定または本人設定が不足しています。")
    owner = settings["KEIHI_OWNER_PUBKEY"]
    token_file = Path(
        settings.get("MF_TOKEN_FILE") or env_file.parent / "tokens" / "mf.json"
    ).expanduser()
    if not token_file.is_absolute():
        token_file = env_file.parent / token_file
    if token_file.is_symlink() or not token_file.is_file() or token_file.stat().st_mode & 0o077:
        raise ExpenseError("既存の本人用認証ファイルを安全に参照できません。")
    oauth = json.loads(token_file.read_text())
    if not oauth.get("access_token"):
        raise ExpenseError("既存MF認証が見つかりません。")
    policy = env_file.parent / "keihi_mcp" / "rules.py"
    if not policy.is_file():
        raise ExpenseError("既存の非公開規則が見つかりません。")
    directory = Path(directory).expanduser().resolve()
    if directory.is_relative_to(Path(__file__).resolve().parents[1]):
        raise ExpenseError("接続設定は公開フォルダの外に保存してください。")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    profile = {
        "source_env": str(env_file),
        "owner": owner,
        "token_file": str(token_file.resolve()),
        "policy_file": str(policy.resolve()),
        "policy_sha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
        "write_enabled": False,
    }
    path = directory / "connection.json"
    if path.exists():
        if json.loads(path.read_text()) != profile:
            raise ExpenseError("異なる接続設定が存在します。上書きせず確認してください。")
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(profile, stream)
    vault = directory / "oauth-link.json"
    binding = hashlib.sha256(str(token_file.resolve()).encode()).hexdigest()
    client = MFClient(settings["MF_CLIENT_ID"], settings["MF_CLIENT_SECRET"], vault, owner)
    try:
        metadata = client._load()
        if metadata.get("legacy_binding") not in (None, binding):
            raise ExpenseError("異なる認証ファイルへの束縛が存在します。")
        client._save({**metadata, "legacy_binding": binding})
    finally:
        client.http.close()
    return path


def connect(profile_path):
    path = Path(profile_path).resolve()
    if path.stat().st_mode & 0o077:
        raise ExpenseError("接続プロファイルのアクセス権を確認してください。")
    profile = json.loads(path.read_text())
    settings = read_settings(profile["source_env"])
    if settings.get("KEIHI_OWNER_PUBKEY") != profile["owner"]:
        raise ExpenseError("既存設定の本人が変わっています。接続を停止します。")
    mf = LinkedMFClient(
        settings["MF_CLIENT_ID"],
        settings["MF_CLIENT_SECRET"],
        path.parent / "oauth-link.json",
        profile["owner"],
        legacy_token_file=profile["token_file"],
        legacy_owner=settings["KEIHI_OWNER_PUBKEY"],
        redirect_uri=settings.get("MF_REDIRECT_URI") or "urn:ietf:wg:oauth:2.0:oob",
    )
    state = State(path.parent / "state.sqlite", profile["owner"])
    calendar = (
        Calendar(settings["KEIHI_ICAL_URL"], SafeFetch(("calendar.google.com",)))
        if settings.get("KEIHI_ICAL_URL")
        else None
    )
    attachment_hosts = tuple(
        host.strip() for host in settings.get("KEIHI_MEDIA_HOSTS", "").split(",") if host.strip()
    )
    return ExpenseService(
        mf=mf,
        state=state,
        calendar=calendar,
        fares=Fares(SafeFetch(("transit.yahoo.co.jp",))),
        receipts=Receipts(path.parent / "receipts", SafeFetch(attachment_hosts), profile["owner"]),
        policy=PrivatePolicy(
            profile["policy_file"],
            profile["policy_sha256"],
            position=settings.get("KEIHI_POSITION") or "member",
        ),
        references=str(Path(profile["source_env"]).parent / "agent" / "refs" / "launchpad")
        if (
            Path(profile["source_env"]).parent / "agent" / "refs" / "launchpad" / "index.md"
        ).is_file()
        else None,
        write_enabled=profile.get("write_enabled") is True,
    )
