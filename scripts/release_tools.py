#!/usr/bin/env python3
"""Release helper: keep versions in sync and extract changelog notes.

Usage:
    python scripts/release_tools.py check [TAG]    # manifests agree (and match TAG if given)
    python scripts/release_tools.py bump X.Y.Z     # bump __init__.py + package.json, roll CHANGELOG
    python scripts/release_tools.py notes X.Y.Z    # print the CHANGELOG section for a version
"""

from __future__ import annotations

import json
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INIT = ROOT / "src" / "trace_engine" / "__init__.py"
PKG = ROOT / "package.json"
CHANGELOG = ROOT / "CHANGELOG.md"
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.M)


def py_version() -> str:
    m = VERSION_RE.search(INIT.read_text(encoding="utf-8"))
    if not m:
        sys.exit("error: __version__ not found")
    return m.group(1)


def npm_version() -> str:
    return json.loads(PKG.read_text(encoding="utf-8"))["version"]


def check(tag: str | None) -> None:
    py, npm = py_version(), npm_version()
    print(f"python={py} npm={npm} tag={tag or '-'}")
    if py != npm:
        sys.exit(f"error: __version__ ({py}) != package.json ({npm})")
    if tag and tag.removeprefix("v") != py:
        sys.exit(f"error: tag ({tag}) != manifests ({py})")


def bump(new: str) -> None:
    if not SEMVER.match(new):
        sys.exit(f"error: '{new}' is not a valid semver version")
    INIT.write_text(
        VERSION_RE.sub(f'__version__ = "{new}"', INIT.read_text(encoding="utf-8"), count=1),
        encoding="utf-8",
    )
    PKG.write_text(
        re.sub(r'("version"\s*:\s*)"[^"]+"', rf'\1"{new}"', PKG.read_text(encoding="utf-8"), count=1),
        encoding="utf-8",
    )
    text = CHANGELOG.read_text(encoding="utf-8")
    if f"## [{new}]" in text:
        sys.exit(f"error: CHANGELOG already has {new}")
    text = text.replace(
        "## [Unreleased]\n", f"## [Unreleased]\n\n## [{new}] - {date.today().isoformat()}\n", 1
    )
    CHANGELOG.write_text(text, encoding="utf-8")
    print(f"bumped to {new}; review CHANGELOG.md, then commit and tag v{new}")


def notes(version: str) -> None:
    text = CHANGELOG.read_text(encoding="utf-8").replace("\r\n", "\n")
    m = re.search(
        rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.M | re.S
    )
    body = m.group(1).strip() if m else ""
    print(body or f"Release {version}. See CHANGELOG.md for details.")


def main(argv: list[str]) -> None:
    if len(argv) < 2 or argv[1] not in {"check", "bump", "notes"}:
        sys.exit(__doc__)
    cmd, arg = argv[1], (argv[2] if len(argv) > 2 else None)
    if cmd == "check":
        check(arg)
    elif arg is None:
        sys.exit(f"error: '{cmd}' needs a version")
    elif cmd == "bump":
        bump(arg.removeprefix("v"))
    else:
        notes(arg.removeprefix("v"))


if __name__ == "__main__":
    main(sys.argv)
