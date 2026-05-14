"""Exercise 2 — log triage CLI.

Reads three log-source types found in the mini-project starter and emits a
ranked-frequency report for each:

    * ``auth.log``  — Debian/Ubuntu rsyslog authentication log.
    * ``nginx``     — combined-format access log.
    * ``journal``   — JSON-lines output from ``journalctl -o json``.

The script is intentionally self-contained: only the Python standard
library is imported. Run ``python3 exercise-02-log-triage.py --help`` for
the full flag list.

AUTHORIZED INVESTIGATION ONLY
=============================
This script reads files supplied on the command line. The operator is
responsible for ensuring the files were obtained under an authorised
investigation. Do not run against logs from a host you do not own and are
not authorised to investigate. See ``../README.md``'s banner for the legal
frame.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


# Default scanner-User-Agent fragments. The list is deliberately conservative;
# a richer list lives in the mini-project's IOC reference.
SCANNER_UA_PATTERNS: tuple[str, ...] = (
    "Nikto",
    "sqlmap",
    "Nmap Scripting Engine",
    "DirBuster",
    "gobuster",
    "WPScan",
    "zgrab",
    "feroxbuster",
    "masscan",
)

# Canonical SQL-injection probe regex (case-insensitive).
SQLI_PROBE_RE = re.compile(
    r"(union[+ ]select|or[+ ]1=1|'\s*or\s*'|sleep\(|benchmark\(|--\s|/\*)",
    re.IGNORECASE,
)

# Canonical path-traversal probe.
PATH_TRAVERSAL_RE = re.compile(r"(\.\./|%2e%2e|\.\.\\\\)", re.IGNORECASE)

# Canonical command-injection markers.
COMMAND_INJECTION_RE = re.compile(
    r"(;\s*(cat|wget|curl|id|bash|sh)\b|%3b\s*(cat|wget|curl|id))",
    re.IGNORECASE,
)

# Log4Shell-class JNDI lookups (Dec 2021 onwards).
LOG4SHELL_RE = re.compile(r"jndi:(ldap|rmi|dns|iiop|nis|nds|corba)", re.IGNORECASE)

# Dotfile / repo / configuration probing.
DOTFILE_RE = re.compile(
    r"/\.(env|git/|svn/|ssh/|aws/|npmrc|netrc)",
    re.IGNORECASE,
)

# WordPress brute-force endpoints.
WORDPRESS_RE = re.compile(r"/(wp-login\.php|xmlrpc\.php)", re.IGNORECASE)


@dataclass(frozen=True)
class TriageHit:
    """One classified suspicious row."""

    source: str
    line_number: int
    category: str
    detail: str


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Triage a Linux host's log files for suspicious patterns.",
    )
    parser.add_argument(
        "--auth",
        type=Path,
        help="Path to /var/log/auth.log (or secure).",
    )
    parser.add_argument(
        "--nginx",
        type=Path,
        help="Path to /var/log/nginx/access.log (combined format).",
    )
    parser.add_argument(
        "--journal",
        type=Path,
        help="Path to a journalctl JSON-lines export ('journalctl -o json').",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of rows to show per ranking (default 10).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit results as JSON to stdout instead of human-readable tables.",
    )
    return parser.parse_args()


def iter_lines(path: Path) -> Iterable[tuple[int, str]]:
    """Yield (1-based-line-number, line-without-newline) for path."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for index, raw in enumerate(handle, start=1):
            yield index, raw.rstrip("\n")


def triage_auth_log(path: Path) -> list[TriageHit]:
    """Surface SSH brute-force, sudo abuse, and account-creation patterns."""
    hits: list[TriageHit] = []
    for line_number, line in iter_lines(path):
        if "Failed password" in line or "Invalid user" in line:
            hits.append(TriageHit(str(path), line_number, "ssh-failed", line))
            continue
        if "Accepted publickey" in line or "Accepted password" in line:
            hits.append(TriageHit(str(path), line_number, "ssh-success", line))
            continue
        if "sudo:" in line and "COMMAND=" in line:
            hits.append(TriageHit(str(path), line_number, "sudo-cmd", line))
            continue
        if "new user" in line.lower() or "useradd" in line.lower():
            hits.append(TriageHit(str(path), line_number, "user-creation", line))
            continue
        if "session opened for user root" in line:
            hits.append(TriageHit(str(path), line_number, "root-session", line))
    return hits


def triage_nginx_access(path: Path) -> list[TriageHit]:
    """Surface scanner UAs, exploit-probe URLs, and abnormal status patterns."""
    hits: list[TriageHit] = []
    for line_number, line in iter_lines(path):
        for fragment in SCANNER_UA_PATTERNS:
            if fragment in line:
                hits.append(
                    TriageHit(str(path), line_number, f"scanner-ua:{fragment}", line)
                )
                break
        if SQLI_PROBE_RE.search(line):
            hits.append(TriageHit(str(path), line_number, "sqli-probe", line))
        if PATH_TRAVERSAL_RE.search(line):
            hits.append(TriageHit(str(path), line_number, "path-traversal", line))
        if COMMAND_INJECTION_RE.search(line):
            hits.append(TriageHit(str(path), line_number, "cmd-injection", line))
        if LOG4SHELL_RE.search(line):
            hits.append(TriageHit(str(path), line_number, "log4shell", line))
        if DOTFILE_RE.search(line):
            hits.append(TriageHit(str(path), line_number, "dotfile-probe", line))
        if WORDPRESS_RE.search(line):
            hits.append(TriageHit(str(path), line_number, "wp-bruteforce", line))
    return hits


def triage_journal_json(path: Path) -> list[TriageHit]:
    """Surface elevated-priority entries and root-as-actor events."""
    hits: list[TriageHit] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for index, raw in enumerate(handle, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            priority = entry.get("PRIORITY")
            message = entry.get("MESSAGE", "")
            uid = entry.get("_UID")
            comm = entry.get("_COMM", "")
            if priority is not None and str(priority).isdigit() and int(priority) <= 3:
                hits.append(
                    TriageHit(
                        str(path), index, f"priority-{priority}",
                        f"{comm}: {message}",
                    )
                )
            if uid == "0" and comm in {"useradd", "usermod", "passwd", "chpasswd"}:
                hits.append(
                    TriageHit(
                        str(path), index, f"root-account-mgmt:{comm}",
                        message,
                    )
                )
            if comm == "sshd" and "Accepted" in message:
                hits.append(
                    TriageHit(str(path), index, "journal-ssh-success", message)
                )
            if comm == "sshd" and ("Failed" in message or "Invalid" in message):
                hits.append(
                    TriageHit(str(path), index, "journal-ssh-failed", message)
                )
    return hits


def summarise(hits: list[TriageHit], top: int) -> dict[str, list[tuple[str, int]]]:
    """Return per-category counts; each category top-N."""
    by_category: dict[str, Counter[str]] = {}
    for hit in hits:
        by_category.setdefault(hit.category, Counter())[hit.detail[:160]] += 1
    return {
        category: counter.most_common(top)
        for category, counter in sorted(by_category.items())
    }


def format_human(summary: dict[str, list[tuple[str, int]]]) -> str:
    """Render summary as a Markdown-flavoured plain-text report."""
    lines: list[str] = []
    for category, rows in summary.items():
        lines.append(f"## {category} ({sum(count for _, count in rows)} hits)")
        for detail, count in rows:
            lines.append(f"  {count:>4d}  {detail}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    """Entry point."""
    args = parse_args()
    if not (args.auth or args.nginx or args.journal):
        print(
            "error: at least one of --auth, --nginx, --journal is required",
            file=sys.stderr,
        )
        return 2

    all_hits: list[TriageHit] = []
    if args.auth and args.auth.exists():
        all_hits.extend(triage_auth_log(args.auth))
    if args.nginx and args.nginx.exists():
        all_hits.extend(triage_nginx_access(args.nginx))
    if args.journal and args.journal.exists():
        all_hits.extend(triage_journal_json(args.journal))

    summary = summarise(all_hits, args.top)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(format_human(summary))

    # Emit a non-zero exit code if any high-signal category appeared, so the
    # script can be wired into a CI gate. The thresholds below are intentionally
    # conservative; tune to your environment.
    high_signal_categories = {
        "sqli-probe",
        "cmd-injection",
        "log4shell",
        "path-traversal",
        "root-account-mgmt:useradd",
        "root-account-mgmt:usermod",
    }
    if any(category in summary for category in high_signal_categories):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
