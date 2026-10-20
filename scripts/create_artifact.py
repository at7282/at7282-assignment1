#!/usr/bin/env python3

import sys
from pathlib import Path

if len(sys.argv) != 2:
    sys.exit(f"Usage: {sys.argv[0]} NETID")

netid = sys.argv[1]
artifact = Path("examples") / "artifact.md"
artifact.parent.mkdir(parents=True, exist_ok=True)
artifact.write_text(f"{netid}\n", encoding="utf-8")

print(f"created {artifact}")
