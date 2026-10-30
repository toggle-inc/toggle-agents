#!/usr/bin/env python3
"""Run synthetic business acceptance checks and write a reviewable local report.

No live MF/SA calls, deploy, OAuth grants or production writes. This is a test
runner, not an expense registration command. Real acceptance remains separate.
"""

import argparse
import io
import json
from pathlib import Path
import unittest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=Path(__file__).parent / ".deploy" / "business-verification.json")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    target = args.report.resolve()
    if (args.report.is_symlink() or target.suffix != ".json"
            or target.is_relative_to(root) and not target.is_relative_to(root / ".deploy")):
        parser.error("Write JSON reports outside source files, or under this agent's .deploy folder")
    modules = ("test_durable_business", "test_durable_state", "test_business_profile_config",
               "test_execution_readiness", "test_operation_readiness_http", "test_receipt_workflow",
               "test_drafts", "test_expense_preview", "test_runtime", "test_synthetic_expense_scenario")
    suite = unittest.TestLoader().loadTestsFromNames(modules)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    report = {"schema_version": "expense-business-verification/v1", "synthetic_only": True,
              "live_service_operations": 0, "submitted": False,
              "passed": result.wasSuccessful() and result.testsRun > 0,
              "tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "modules": modules,
              "unverified": ["実画像OCR/視覚入力", "税率・税額の専用項目と照合（未対応）", "実SA添付の新署名経路", "実MF保存・OCR読戻し",
                             "実会社規則・運賃・個人カレンダー", "公開版と本人専用DMの一連動作"],
              "test_output": stream.getvalue()}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in report.items() if k != "test_output"}, ensure_ascii=False, indent=2))
    print("Report: " + str(args.report.resolve()))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
