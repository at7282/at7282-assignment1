#!/usr/bin/env python3
"""Scan only the files in the pending commit for secrets.

The pre-commit hook must stay fast as the repository grows, so it never scans
the full history or working tree. This script asks Git for the files staged in
the index, copies their staged contents into a temporary directory, and runs
TruffleHog on that directory only.

TruffleHog is invoked with ``--no-verification`` so the hook works offline and
does not call cloud provider APIs for every candidate secret.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path


def _run_git(*args: str, text: bool = True) -> subprocess.CompletedProcess:
    # Fixed git command with a list of arguments and no shell.
    return subprocess.run(  # nosec B603 B607
        ["git", *args],
        capture_output=True,
        text=text,
        check=False,
    )


def staged_files() -> list[str]:
    """Return repository-relative paths added, copied, modified, or renamed."""
    completed = _run_git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    if completed.returncode != 0:
        stderr = completed.stderr if isinstance(completed.stderr, str) else ""
        raise RuntimeError(stderr.strip() or "git diff --cached failed")
    return [name for name in completed.stdout.split("\0") if name]


def find_trufflehog() -> str | None:
    """Locate the TruffleHog executable, including common local install paths."""
    candidates = [
        os.environ.get("TRUFFLEHOG_BIN"),
        shutil.which("trufflehog"),
        str(Path.home() / ".local" / "bin" / "trufflehog"),
        "/usr/local/bin/trufflehog",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def main() -> int:
    try:
        paths = staged_files()
    except (OSError, RuntimeError) as exc:
        print(f"TruffleHog: could not list staged files: {exc}", file=sys.stderr)
        return 1

    if not paths:
        print("TruffleHog: no staged files, nothing to scan")
        return 0

    trufflehog = find_trufflehog()
    if trufflehog is None:
        print(
            "TruffleHog: executable not found. Install it from "
            "https://github.com/trufflesecurity/trufflehog and retry.",
            file=sys.stderr,
        )
        return 1

    with tempfile.TemporaryDirectory(prefix="trufflehog-staged-") as directory:
        root = Path(directory)
        for name in paths:
            blob = _run_git("show", f":{name}", text=False)
            if blob.returncode != 0:
                continue
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(blob.stdout)

        # Fixed arguments, no shell, and a resolved executable path.
        completed = subprocess.run(  # nosec B603
            [
                trufflehog,
                "filesystem",
                str(root),
                "--no-verification",
                "--results=verified,unknown,unverified",
                "--no-update",
                "--no-color",
                "--fail",
            ],
            check=False,
        )
        return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
