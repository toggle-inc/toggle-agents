#!/usr/bin/env python3
"""Link one person's real local tools. Verification is GET-only and prints no business records."""

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from runtime.connection import configure_writes, connect, initialize_profile
from runtime.state import ExpenseError


def read_check(service, date, *, fare_from="", fare_to=""):
    report = {"mode": "read_only", "mf_writes_performed": 0, "checks": {}}

    def probe(name, callback):
        try:
            report["checks"][name] = {"ok": True, **callback()}
        except Exception as error:
            # Do not emit upstream responses, URLs, credentials or personal records.
            report["checks"][name] = {"ok": False, "error_type": type(error).__name__}

    offices = []

    def mf():
        offices.extend(service.mf_offices())
        return {"company_count": len(offices)}

    probe("mf_auth_and_offices", mf)
    if offices:
        probe(
            "mf_transactions",
            lambda: {
                "record_count": len(service.mf_list_transactions(offices[0]["id"], date, date))
            },
        )
        probe(
            "mf_reports",
            lambda: {"record_count": len(service.mf_list_reports(offices[0]["id"], pages=1))},
        )
    probe("calendar", lambda: {"event_count": len(service.calendar_events(date, date))})
    probe(
        "private_rules",
        lambda: {
            "warning_count": len(
                service.check_rules(
                    date,
                    1,
                    ex_item_name="旅費交通費",
                    remark="接続検査用の仮データ（登録しない）",
                    memo="接続検査",
                    has_receipt=False,
                )
            )
        },
    )
    if service.references:
        probe(
            "private_references",
            lambda: {"document_read": bool(service.read_reference()["text"]), "status": "readable"},
        )
    else:
        report["checks"]["private_references"] = {"ok": False, "status": "not_configured"}
    report["checks"]["attachments"] = {
        "ok": False,
        "status": "requires_actual_attachment",
        "allowed_host_count": len(service.receipts.fetcher.hosts),
    }
    if fare_from and fare_to:

        def fares():
            response = service.fare_lookup(fare_from, fare_to, date)
            if not response["routes"]:
                raise ExpenseError("運賃の結果を取得できません。")
            return {"route_count": len(response["routes"])}

        probe("fare", fares)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup")
    setup.add_argument("--legacy-env", type=Path, required=True)
    setup.add_argument("--directory", type=Path, required=True)
    check = commands.add_parser("check")
    check.add_argument("--profile", type=Path, required=True)
    check.add_argument(
        "--date", required=True, help="One explicit YYYY-MM-DD for bounded GET checks"
    )
    check.add_argument("--fare-from", default="")
    check.add_argument("--fare-to", default="")
    serve = commands.add_parser("serve")
    serve.add_argument("--profile", type=Path, required=True)
    writes = commands.add_parser(
        "writes", help="Trusted local capability setting; not per-write approval"
    )
    writes.add_argument("--profile", type=Path, required=True)
    mode = writes.add_mutually_exclusive_group(required=True)
    mode.add_argument("--enable", action="store_true")
    mode.add_argument("--disable", action="store_true")
    args = parser.parse_args()
    service = None
    try:
        if args.command == "writes":
            configure_writes(args.profile, args.enable)
            print(
                json.dumps(
                    {
                        "write_enabled": args.enable,
                        "per_write_human_approval_required": True,
                        "mf_writes_performed": 0,
                        "restart_existing_server": True,
                    }
                )
            )
            return
        if args.command == "setup":
            initialize_profile(args.legacy_env, args.directory)
            print(
                "Private connection profile created. Existing credentials are linked, not copied."
            )
            return
        if args.command == "check":
            dt.date.fromisoformat(args.date)
        service = connect(args.profile)
        if args.command == "serve":
            from mcp_server import create_server

            create_server(service).run(transport="stdio")
        else:
            report = read_check(service, args.date, fare_from=args.fare_from, fare_to=args.fare_to)
            print(json.dumps(report, ensure_ascii=False, indent=2))
            essential = (
                "mf_auth_and_offices",
                "mf_transactions",
                "mf_reports",
                "calendar",
                "private_rules",
            )
            if args.fare_from and args.fare_to:
                essential += ("fare",)
            if not all(report["checks"].get(key, {}).get("ok") for key in essential):
                sys.exit(1)
    except (ExpenseError, OSError, ValueError, KeyError):
        parser.exit(
            2,
            "接続を確認できません。本人専用の既存設定と保存先を確認してください。秘密は表示しません。\n",
        )
    finally:
        if service is not None:
            service.state.close()
            service.mf.http.close()


if __name__ == "__main__":
    main()
