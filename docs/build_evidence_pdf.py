#!/usr/bin/env python3
"""Build a dependency-free PDF from the captured terminal evidence.

Usage:
    python docs/build_evidence_pdf.py [evidence-dir] [output.pdf]

The script intentionally uses no third-party packages so anyone can rebuild the
submission PDF with a standard Python installation.
"""

from __future__ import annotations

import datetime
import sys
import textwrap
from pathlib import Path

PAGE_WIDTH = 612
PAGE_HEIGHT = 792
MARGIN = 45
FONT_SIZE = 8.5
LEADING = 11
MAX_COLUMNS = 94
LINES_PER_PAGE = 63

SECTIONS = [
    (
        "1-trufflehog-secret-detection.txt",
        "1. TruffleHog detects and blocks a staged secret",
    ),
    (
        "2-pytest-coverage.txt",
        "2. pytest test suite and coverage report",
    ),
    (
        "3-branch-protection.txt",
        "3. Branch protection rule for main",
    ),
]


def _cover_lines() -> list[str]:
    return [
        "PYTHON REKOR MONITOR",
        "Security and Testing Evidence",
        "",
        "Repository: at7282/at7282-assignment1",
        f"Generated: {datetime.date.today().isoformat()}",
        "",
        "Contents",
        "  1. TruffleHog detects and blocks a staged secret",
        "  2. pytest test suite and coverage report",
        "  3. Branch protection rule for main",
        "",
        "These pages are terminal captures of the commands used to produce the",
        "requested evidence. To capture equivalent screenshots, run the commands",
        "in docs/REPRODUCING-EVIDENCE.md and capture the terminal window.",
        "",
        "Section 1 uses a synthetic AWS credential and --no-verification.",
        "Section 2 shows 67 passing tests and 95.98% line coverage.",
        "Section 3 reads the live branch protection configuration from GitHub.",
    ]


def _ascii(text: str) -> str:
    return text.encode("ascii", "replace").decode("ascii")


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrapped(line: str) -> list[str]:
    line = _ascii(line.replace("\t", "    ").replace("\r", ""))
    if not line:
        return [""]
    wrapped = textwrap.wrap(
        line,
        width=MAX_COLUMNS,
        replace_whitespace=False,
        drop_whitespace=False,
        break_long_words=True,
        break_on_hyphens=False,
    )
    return wrapped or [""]


def _content_stream(lines: list[str]) -> bytes:
    commands = [
        "BT",
        f"/F1 {FONT_SIZE} Tf",
        f"{LEADING} TL",
        f"1 0 0 1 {MARGIN} {PAGE_HEIGHT - MARGIN - 5} Tm",
    ]
    for line in lines:
        commands.append(f"({_escape(line)}) Tj T*")
    commands.append("ET")
    return "\n".join(commands).encode("latin-1")


def _build_pdf(pages: list[list[str]]) -> bytes:
    page_ids = [4 + 2 * index for index in range(len(pages))]
    content_ids = [5 + 2 * index for index in range(len(pages))]

    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        (
            f"<< /Type /Pages /Kids [{' '.join(f'{page_id} 0 R' for page_id in page_ids)}] "
            f"/Count {len(pages)} >>"
        ).encode("ascii"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
    ]

    for index, lines in enumerate(pages):
        stream = _content_stream(lines)
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
                f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_ids[index]} 0 R >>"
            ).encode("ascii")
        )
        objects.append(
            f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream"
        )

    document = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0] * (len(objects) + 1)
    for object_id, body in enumerate(objects, start=1):
        offsets[object_id] = len(document)
        document += f"{object_id} 0 obj\n".encode("ascii")
        document += body
        document += b"\nendobj\n"

    xref_offset = len(document)
    document += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
    document += b"0000000000 65535 f \n"
    for object_id in range(1, len(objects) + 1):
        document += f"{offsets[object_id]:010d} 00000 n \n".encode("ascii")
    document += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
    ).encode("ascii")
    return bytes(document)


def _paginate(evidence_dir: Path) -> list[list[str]]:
    pages: list[list[str]] = []
    current: list[str] = []

    def add(line: str) -> None:
        for wrapped in _wrapped(line):
            current.append(wrapped)
            if len(current) == LINES_PER_PAGE:
                pages.append(current.copy())
                current.clear()

    def flush() -> None:
        if current:
            pages.append(current.copy())
            current.clear()

    for line in _cover_lines():
        add(line)
    flush()

    for filename, title in SECTIONS:
        path = evidence_dir / filename
        if not path.is_file():
            continue
        heading = "=" * 78
        add(heading)
        add(title)
        add(heading)
        add("")
        add(f"Source: {path.as_posix()}")
        add("")
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            add(line)
        flush()

    return pages or [["No evidence files were found."]]


def main(argv: list[str]) -> int:
    evidence_dir = Path(argv[1]) if len(argv) > 1 else Path("docs/evidence")
    output = Path(argv[2]) if len(argv) > 2 else Path("docs/evidence-report.pdf")

    if not evidence_dir.is_dir():
        print(f"Evidence directory not found: {evidence_dir}", file=sys.stderr)
        return 1

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_build_pdf(_paginate(evidence_dir)))
    print(f"wrote {output} ({output.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
