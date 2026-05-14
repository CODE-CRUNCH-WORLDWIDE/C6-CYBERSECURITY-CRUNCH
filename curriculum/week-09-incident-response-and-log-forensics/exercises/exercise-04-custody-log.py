"""Exercise 4 — chain-of-custody log generator and verifier.

Walks a directory of artefacts, computes SHA-256 (and MD5 for legacy
compatibility) for every file, writes a YAML-frontmatter Markdown custody
log, and on subsequent runs verifies that every artefact still matches its
recorded hash.

The custody log is the document that turns an artefact into evidence; the
purpose of this script is to make the discipline cheap enough to run on
every artefact, every time.

AUTHORIZED INVESTIGATION ONLY
=============================
This script operates on files in a directory you control. The integrity
log it produces is only as trustworthy as the operator who runs it; sign
the resulting commit, store the log in version control, and never edit a
prior entry (append corrections as new entries).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


CHUNK_BYTES = 1024 * 1024  # 1 MiB read chunks for large dumps.


@dataclass(frozen=True)
class Hashes:
    """The two hashes the custody log records."""

    sha256: str
    md5: str


@dataclass(frozen=True)
class CustodyEntry:
    """One artefact's row in the custody log."""

    relative_path: str
    size_bytes: int
    sha256: str
    md5: str
    acquired_at: str
    acquired_by: str
    system_id: str
    tool: str
    authorisation: str


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Generate or verify a chain-of-custody log for a directory of "
            "forensic artefacts."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    generate = sub.add_parser(
        "generate",
        help="Hash every file in --directory and write the custody log.",
    )
    generate.add_argument(
        "--directory",
        type=Path,
        required=True,
        help="Directory of artefacts to hash.",
    )
    generate.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to write the custody log (Markdown).",
    )
    generate.add_argument(
        "--acquired-by", required=True, help="Operator identity (a real name)."
    )
    generate.add_argument(
        "--system-id",
        required=True,
        help="System identifier (e.g. 'web-prod-02 machine-id=8c5d3a...').",
    )
    generate.add_argument(
        "--tool",
        default="exercise-04-custody-log.py",
        help="Tool name and version that produced the log.",
    )
    generate.add_argument(
        "--authorisation",
        required=True,
        help="Authorisation reference (engagement letter, ticket, statute).",
    )
    generate.add_argument(
        "--also-json",
        type=Path,
        help="Optional JSON-lines export alongside the Markdown log.",
    )

    verify = sub.add_parser(
        "verify",
        help="Verify the hashes in --custody-log against --directory.",
    )
    verify.add_argument(
        "--directory",
        type=Path,
        required=True,
        help="Directory of artefacts to re-hash.",
    )
    verify.add_argument(
        "--custody-log",
        type=Path,
        required=True,
        help="The Markdown custody log to verify against.",
    )

    return parser.parse_args()


def compute_hashes(path: Path) -> Hashes:
    """Compute SHA-256 and MD5 for ``path`` with a single read."""
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_BYTES)
            if not chunk:
                break
            sha.update(chunk)
            md5.update(chunk)
    return Hashes(sha256=sha.hexdigest(), md5=md5.hexdigest())


def now_iso_utc() -> str:
    """Return ISO 8601 UTC now()."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def walk_artefacts(directory: Path) -> list[Path]:
    """Return a stable-ordered list of regular files under ``directory``."""
    return sorted(p for p in directory.rglob("*") if p.is_file())


def build_entries(
    directory: Path,
    acquired_by: str,
    system_id: str,
    tool: str,
    authorisation: str,
) -> list[CustodyEntry]:
    """Hash every file under ``directory`` and return the custody entries."""
    entries: list[CustodyEntry] = []
    acquired_at = now_iso_utc()
    for path in walk_artefacts(directory):
        hashes = compute_hashes(path)
        entries.append(
            CustodyEntry(
                relative_path=str(path.relative_to(directory)),
                size_bytes=path.stat().st_size,
                sha256=hashes.sha256,
                md5=hashes.md5,
                acquired_at=acquired_at,
                acquired_by=acquired_by,
                system_id=system_id,
                tool=tool,
                authorisation=authorisation,
            )
        )
    return entries


def emit_markdown(entries: list[CustodyEntry]) -> str:
    """Render the custody log as YAML-frontmatter Markdown."""
    lines: list[str] = []
    lines.append("---")
    lines.append(f"generated_at: {now_iso_utc()}")
    lines.append(f"artefact_count: {len(entries)}")
    lines.append("---")
    lines.append("")
    lines.append("# Chain-of-custody log")
    lines.append("")
    lines.append(
        "| Artefact | Size (bytes) | SHA-256 | MD5 | Acquired at | "
        "Acquired by | System ID | Tool | Authorisation |"
    )
    lines.append(
        "|---|---:|---|---|---|---|---|---|---|"
    )
    for entry in entries:
        lines.append(
            "| "
            + " | ".join(
                [
                    entry.relative_path,
                    str(entry.size_bytes),
                    entry.sha256,
                    entry.md5,
                    entry.acquired_at,
                    entry.acquired_by,
                    entry.system_id,
                    entry.tool,
                    entry.authorisation,
                ]
            )
            + " |"
        )
    lines.append("")
    lines.append("## Transfers")
    lines.append("")
    lines.append("| Artefact | From | To | At | Verified SHA-256 |")
    lines.append("|---|---|---|---|---|")
    lines.append("")
    return "\n".join(lines)


def parse_existing_log(path: Path) -> dict[str, str]:
    """Parse the SHA-256 column out of an existing custody Markdown log.

    Returns a mapping ``relative_path -> sha256``. Lines that do not match
    the expected table layout are ignored.
    """
    mapping: dict[str, str] = {}
    in_table = False
    expected_header = (
        "| Artefact | Size (bytes) | SHA-256 | MD5 | Acquired at | "
        "Acquired by | System ID | Tool | Authorisation |"
    )
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            stripped = raw.rstrip("\n")
            if stripped == expected_header:
                in_table = True
                continue
            if not in_table:
                continue
            if not stripped.startswith("|"):
                in_table = False
                continue
            if stripped.startswith("|---"):
                continue
            cells = [cell.strip() for cell in stripped.strip("|").split("|")]
            if len(cells) < 4:
                continue
            mapping[cells[0]] = cells[2]
    return mapping


def verify(directory: Path, custody_log: Path) -> int:
    """Re-hash every file and compare against the recorded SHA-256.

    Returns 0 if every artefact matches; 1 if any artefact is missing, new,
    or mismatched.
    """
    expected = parse_existing_log(custody_log)
    if not expected:
        print(
            f"error: no parseable entries in {custody_log}",
            file=sys.stderr,
        )
        return 1
    mismatches: list[str] = []
    missing: list[str] = []
    extras: list[str] = []
    on_disk: dict[str, str] = {}
    for path in walk_artefacts(directory):
        rel = str(path.relative_to(directory))
        on_disk[rel] = compute_hashes(path).sha256
    for rel, recorded in expected.items():
        if rel not in on_disk:
            missing.append(rel)
            continue
        if on_disk[rel] != recorded:
            mismatches.append(
                f"{rel}: expected {recorded}, got {on_disk[rel]}"
            )
    for rel in on_disk:
        if rel not in expected:
            extras.append(rel)
    if not (mismatches or missing or extras):
        print(f"OK: all {len(expected)} artefact(s) verified.")
        return 0
    if mismatches:
        print("MISMATCH:")
        for line in mismatches:
            print(f"  {line}")
    if missing:
        print("MISSING:")
        for line in missing:
            print(f"  {line}")
    if extras:
        print("EXTRA (in directory but not in log):")
        for line in extras:
            print(f"  {line}")
    return 1


def emit_jsonl_export(entries: list[CustodyEntry], path: Path) -> None:
    """Write a JSON-lines export alongside the Markdown log."""
    with path.open("w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(json.dumps(entry.__dict__) + "\n")


def main() -> int:
    """Entry point."""
    args = parse_args()
    if args.command == "generate":
        entries = build_entries(
            args.directory,
            args.acquired_by,
            args.system_id,
            args.tool,
            args.authorisation,
        )
        args.output.write_text(emit_markdown(entries), encoding="utf-8")
        if args.also_json:
            emit_jsonl_export(entries, args.also_json)
        print(f"wrote custody log: {args.output} ({len(entries)} entries)")
        return 0
    if args.command == "verify":
        return verify(args.directory, args.custody_log)
    return 2


if __name__ == "__main__":
    sys.exit(main())
