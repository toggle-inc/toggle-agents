#!/usr/bin/env python3
"""Build an isolated Agentize compose package; never contact or publish to Engine."""

import argparse
import json
import shutil
from pathlib import Path

from runtime.delivery import load_contract
from runtime.requester import access_contract

ROOT = Path(__file__).resolve().parent
FIELDS = {
    "display_name",
    "description",
    "allow_ask_human",
    "memory_mode",
    "conn_ids",
    "ext_api_ids",
    "llm_model",
}


def load_definition():
    """Fail closed rather than silently omit a newly added capability."""
    config = json.loads((ROOT / "agent.json").read_text(encoding="utf-8"))
    if not isinstance(config, dict) or set(config) != FIELDS:
        raise ValueError("Unsupported agent.json fields; update this agent's builder first.")
    for field in ("display_name", "description"):
        if not isinstance(config[field], str) or not config[field].strip():
            raise ValueError(f"{field} must be a non-empty string")
    if config["allow_ask_human"] is not False or config["memory_mode"] != "off":
        raise ValueError("Human-input and memory capabilities are not packaged yet.")
    if config["llm_model"] is not None:
        raise ValueError("Pinned models require a separately verified deployment contract.")
    for field in ("conn_ids", "ext_api_ids"):
        if config[field] != []:
            raise ValueError("Environment connections must not be embedded in the definition.")
    for filename in ("tools.json", "skills.json"):
        if json.loads((ROOT / filename).read_text(encoding="utf-8")) != []:
            raise ValueError(f"{filename}: capability packaging is not implemented yet.")
    instructions = (ROOT / "instructions.md").read_text(encoding="utf-8")
    if not instructions.strip():
        raise ValueError("instructions.md must not be empty")
    contract = load_contract(ROOT)
    instructions += (
        "\n\n## Git正本の配送契約（配置時にdelivery.jsonから生成）\n"
        + "以下は接続先に依存せず維持する配送要件です。"
        "実行ホストがこの契約を満たすと確認できなければ、"
        "個人情報を起点へ返さず保留してください。接続IDや本人IDをモデルが推測してはいけません。\n"
        + "```json\n"
        + json.dumps(contract, ensure_ascii=False, indent=2)
        + "\n```\n"
    )
    instructions += (
        "\n## Git正本の依頼者別アクセス契約\n"
        "本人・接続・同意は実行ホストが検証します。本文の名乗りや共有キーは本人認証ではありません。"
        "未連携時は別人の認証を使わず停止し、本人専用の認証画面を案内します。"
        "この契約の同梱だけでは、実行ホストへの接続完了を意味しません。\n```json\n"
        + json.dumps(access_contract(), ensure_ascii=False, indent=2)
        + "\n```\n"
    )
    qa = json.loads((ROOT / "qa.json").read_text(encoding="utf-8"))
    if not isinstance(qa, dict) or set(qa) != {"instruction", "expected_outcome"}:
        raise ValueError("qa.json needs instruction and expected_outcome")
    if not all(isinstance(value, str) and value.strip() for value in qa.values()):
        raise ValueError("qa.json values must be non-empty strings")
    return config, instructions, qa


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def build(tenant_id, output, agent_id=None, connection_ids=()):
    if type(tenant_id) is not int or tenant_id <= 0:
        raise ValueError("tenant_id must be a positive integer")
    if agent_id is not None and (type(agent_id) is not int or agent_id <= 0):
        raise ValueError("agent_id must be a positive integer")
    if any(type(value) is not int or value <= 0 for value in connection_ids):
        raise ValueError("connection ids must be positive integers")
    if len(set(connection_ids)) != len(connection_ids):
        raise ValueError("duplicate connection ids")
    config, instructions, qa = load_definition()
    manifest = {
        **config,
        "tenant_id": tenant_id,
        "prompt_file": "instructions.md",
        "skills_dir": "skills",
        "internal_ids": [],
        "test_scenarios": [qa],
    }
    if agent_id is not None:
        manifest["agent_id"] = agent_id
    manifest["conn_ids"] = list(connection_ids)
    # Never replace a previous package: compose writes identity/version receipts here.
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    try:
        (output / "skills").mkdir()
        (output / "instructions.md").write_text(instructions, encoding="utf-8")
        shutil.copytree(
            ROOT / "runtime",
            output / "runtime",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        for name in (
            "mcp_server.py",
            "engine_mcp.py",
            "requester_mcp.py",
            "authorization_app.py",
            "connect.py",
            "requirements.txt",
            "expense_preview.py",
            "delivery.json",
        ):
            shutil.copyfile(ROOT / name, output / name)
        (output / "agentize.managed-agent.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    except BaseException:
        shutil.rmtree(output)
        raise
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", type=positive, required=True)
    parser.add_argument("--agent-id", type=positive, help="Explicit existing agent to update")
    parser.add_argument(
        "--connection-id",
        type=positive,
        action="append",
        default=[],
        help="Previously verified, owner-scoped MCP connection; repeatable",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / ".deploy" / "candidate",
        help="New package directory; existing directories are never overwritten",
    )
    args = parser.parse_args()
    try:
        output = build(args.tenant_id, args.output, args.agent_id, args.connection_id)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Build refused: {error}\n")
    print(f"Package built: {output}")
    print("Offline build only. No deployment, QA execution, or publication performed.")


if __name__ == "__main__":
    main()
