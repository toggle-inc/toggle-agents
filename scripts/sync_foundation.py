#!/usr/bin/env python3
"""Vendor the canonical foundation into standalone agents; check by default."""

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "__init__.py",
    "conversation.py",
    "instructions.md",
    "test_conversation.py",
    "history_sources.py",
    "test_history_sources.py",
    "history_runtime.py",
    "test_history_runtime.py",
    "HISTORY_CONNECTIONS.md",
    "platform_identity.py",
    "test_platform_identity.py",
    "PLATFORM_IDENTITY.md",
    "execution_binding.py",
    "test_execution_binding.py",
    "EXECUTION_BINDING.md",
)


def sync(*, write=False):
    mismatches = []
    for folder in sorted((ROOT / "agents").iterdir()):
        if not folder.is_dir():
            continue
        target = folder / "_foundation"
        if write:
            target.mkdir(exist_ok=True)
        for name in FILES:
            source, destination = ROOT / "foundation" / name, target / name
            if write:
                shutil.copyfile(source, destination)
            if not destination.is_file() or source.read_bytes() != destination.read_bytes():
                mismatches.append(str(destination.relative_to(ROOT)))
    return mismatches


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Refresh vendored source and tests")
    args = parser.parse_args()
    missing = sync(write=args.write)
    if missing:
        parser.exit(1, "Foundation differs: " + ", ".join(missing) + "\n")
    print("Foundation source and both standalone agents match.")
