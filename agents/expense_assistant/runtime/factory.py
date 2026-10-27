"""Single-person stdio deployment profile. Environment is supplied by its trusted host."""

import os
from pathlib import Path

from .providers import Calendar, Fares, MFClient, PrivatePolicy, Receipts, SafeFetch
from .service import ExpenseService
from .state import ExpenseError, State


def create_service():
    owner = os.environ.get("EXPENSE_OWNER_KEY")
    root = os.environ.get("EXPENSE_STATE_ROOT")
    client_id = os.environ.get("MF_CLIENT_ID")
    client_secret = os.environ.get("MF_CLIENT_SECRET")
    if not all((owner, root, client_id, client_secret)):
        raise ExpenseError(
            "本人専用の実行設定とMFアプリ認証が必要です。チャットに秘密を貼らないでください。"
        )
    root = Path(root).expanduser().resolve()
    if root.is_relative_to(Path(__file__).resolve().parents[1]):
        raise ExpenseError("状態・認証は公開エージェントのフォルダ外に保存してください。")
    root.mkdir(parents=True, exist_ok=True)
    # Do not chmod an existing broad home/workspace directory.
    private = root / "expense-assistant-private"
    private.mkdir(mode=0o700, exist_ok=True)
    if private.is_symlink():
        raise ExpenseError("状態ディレクトリにシンボリックリンクは使えません。")
    os.chmod(private, 0o700)
    state = State(private / "state.sqlite", owner)
    mf = MFClient(
        client_id,
        client_secret,
        private / "oauth.json",
        owner,
        redirect_uri=os.environ.get("MF_REDIRECT_URI", "urn:ietf:wg:oauth:2.0:oob"),
    )
    attachment_hosts = tuple(
        host.strip()
        for host in os.environ.get("EXPENSE_ATTACHMENT_HOSTS", "").split(",")
        if host.strip()
    )
    receipts = Receipts(private / "receipts", SafeFetch(attachment_hosts), owner)
    url = os.environ.get("KEIHI_ICAL_URL")
    calendar = Calendar(url, SafeFetch(("calendar.google.com",))) if url else None
    path, checksum = (
        os.environ.get("EXPENSE_PRIVATE_POLICY"),
        os.environ.get("EXPENSE_POLICY_SHA256"),
    )
    policy = (
        PrivatePolicy(path, checksum, position=os.environ.get("KEIHI_POSITION", "member"))
        if path and checksum
        else None
    )
    return ExpenseService(
        mf=mf,
        state=state,
        calendar=calendar,
        fares=Fares(SafeFetch(("transit.yahoo.co.jp",))),
        receipts=receipts,
        policy=policy,
        references=os.environ.get("EXPENSE_PRIVATE_REFS"),
    )
