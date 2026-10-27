#!/usr/bin/env python3
"""Offline preview entry point; not an authenticated runtime adapter or MF tool."""

import argparse
import json
import sys
from pathlib import Path

from expense_preview import build_preview


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true", help="Use the bundled synthetic fixture")
    args = parser.parse_args()
    try:
        if args.demo:
            path = Path(__file__).resolve().parent / "fixtures" / "synthetic_transport.json"
            request = json.loads(path.read_text(encoding="utf-8"))
        else:
            request = json.load(sys.stdin)
        result = build_preview(request)
    except (ValueError, TypeError, KeyError, OSError) as error:
        # Never echo caller-supplied event contents, calendar URLs or tokens on error.
        parser.exit(
            2, f"Preview refused ({type(error).__name__}). Check the documented input contract.\n"
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
