"""Exercise 3 — heterogeneous-source timeline builder.

Takes the same three log-source types as Exercise 2 plus a bash-history file
with ``HISTTIMEFORMAT`` timestamps and emits a single chronologically-sorted
timeline as Markdown (or JSON-lines on request). All timestamps are
normalised to ISO 8601 UTC (the suffix ``Z``).

The output is suitable as the *Incident timeline* section of the
post-incident report.

AUTHORIZED INVESTIGATION ONLY
=============================
This script reads files supplied on the command line. The operator is
responsible for ensuring the files were obtained under an authorised
investigation. See ``../README.md``'s banner for the legal frame.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


# Default origin year for auth.log lines that lack one (the canonical
# pitfall described in Lecture 2 § 3.4). The operator must supply the year
# the logs cover; we refuse to guess.
AUTH_LOG_LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$"
)

NGINX_COMBINED_RE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"
    r"\"(?P<req>[^\"]*)\"\s+(?P<status>\d+)\s+(?P<bytes>\S+)\s+"
    r"\"(?P<referer>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\""
)

NGINX_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

MONTH_TO_NUMBER: dict[str, int] = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass(order=True)
class TimelineEvent:
    """One event in the merged timeline."""

    timestamp: datetime
    source: str = field(compare=False)
    actor: str = field(compare=False)
    description: str = field(compare=False)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Build a unified chronological timeline from log artefacts.",
    )
    parser.add_argument(
        "--auth", type=Path, help="Path to /var/log/auth.log."
    )
    parser.add_argument(
        "--auth-year",
        type=int,
        help="Year the auth.log lines cover (auth.log lacks a year field).",
    )
    parser.add_argument(
        "--auth-timezone",
        default="UTC",
        help="Timezone of auth.log timestamps (default UTC). Use an IANA name.",
    )
    parser.add_argument(
        "--nginx", type=Path, help="Path to nginx access log (combined format)."
    )
    parser.add_argument(
        "--journal",
        type=Path,
        help="Path to journalctl JSON-lines export ('journalctl -o json').",
    )
    parser.add_argument(
        "--bash-history",
        type=Path,
        help="Path to a bash_history file with HISTTIMEFORMAT timestamps.",
    )
    parser.add_argument(
        "--bash-history-user",
        default="unknown",
        help="Username to attribute bash_history entries to.",
    )
    parser.add_argument(
        "--output",
        choices=("markdown", "jsonl"),
        default="markdown",
        help="Output format.",
    )
    return parser.parse_args()


def _resolve_timezone(name: str) -> timezone:
    """Return a tzinfo for ``name``. We accept ``UTC`` only to keep the script
    standard-library-only; richer parsing belongs in a downstream tool."""
    if name.upper() != "UTC":
        # The exercise's lab data is UTC-stamped. We refuse to invent a
        # conversion silently; the operator must convert beforehand.
        raise SystemExit(
            f"--auth-timezone must be 'UTC' in this script (got {name!r}); "
            "convert non-UTC logs before ingestion."
        )
    return timezone.utc


def parse_auth_log(
    path: Path, year: int, tz: timezone
) -> Iterable[TimelineEvent]:
    """Yield TimelineEvent for each line of an auth.log file."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            match = AUTH_LOG_LINE_RE.match(raw)
            if not match:
                continue
            month = MONTH_TO_NUMBER.get(match.group("month"))
            day = int(match.group("day"))
            hour, minute, second = (int(x) for x in match.group("time").split(":"))
            if month is None:
                continue
            timestamp = datetime(year, month, day, hour, minute, second, tzinfo=tz)
            yield TimelineEvent(
                timestamp=timestamp,
                source="auth.log",
                actor=match.group("host"),
                description=match.group("rest").strip(),
            )


def parse_nginx_log(path: Path) -> Iterable[TimelineEvent]:
    """Yield TimelineEvent for each line of an nginx combined-format log."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            match = NGINX_COMBINED_RE.match(raw)
            if not match:
                continue
            try:
                timestamp = datetime.strptime(
                    match.group("ts"), NGINX_TS_FORMAT
                ).astimezone(timezone.utc)
            except ValueError:
                continue
            description = (
                f"{match.group('req')} -> {match.group('status')} "
                f"({match.group('bytes')} bytes) UA=\"{match.group('ua')}\""
            )
            yield TimelineEvent(
                timestamp=timestamp,
                source="nginx-access",
                actor=match.group("ip"),
                description=description,
            )


def parse_journal_json(path: Path) -> Iterable[TimelineEvent]:
    """Yield TimelineEvent for each row of a journalctl JSON-lines export."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            usec = entry.get("__REALTIME_TIMESTAMP")
            if usec is None:
                continue
            try:
                seconds = int(usec) / 1_000_000.0
            except (TypeError, ValueError):
                continue
            timestamp = datetime.fromtimestamp(seconds, tz=timezone.utc)
            comm = entry.get("_COMM", "")
            unit = entry.get("_SYSTEMD_UNIT", "")
            message = entry.get("MESSAGE", "")
            actor = comm or unit or "journal"
            yield TimelineEvent(
                timestamp=timestamp,
                source="journal",
                actor=actor,
                description=str(message),
            )


def parse_bash_history(
    path: Path, user: str
) -> Iterable[TimelineEvent]:
    """Yield TimelineEvent for each timestamped bash_history entry.

    Expects ``HISTTIMEFORMAT`` lines of the form ``#1715662031`` immediately
    followed by the command line itself.
    """
    pending_ts: Optional[datetime] = None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            raw = raw.rstrip("\n")
            if raw.startswith("#") and raw[1:].isdigit():
                try:
                    pending_ts = datetime.fromtimestamp(
                        int(raw[1:]), tz=timezone.utc
                    )
                except (TypeError, ValueError, OSError):
                    pending_ts = None
                continue
            if pending_ts is None:
                continue
            yield TimelineEvent(
                timestamp=pending_ts,
                source="bash-history",
                actor=user,
                description=raw,
            )
            pending_ts = None


def emit_markdown(events: list[TimelineEvent]) -> str:
    """Render events as a Markdown table sorted by timestamp."""
    lines = [
        "# Incident timeline",
        "",
        "| Time (UTC) | Source | Actor | Event |",
        "|---|---|---|---|",
    ]
    for event in events:
        ts = event.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        description = event.description.replace("|", "\\|")
        lines.append(
            f"| {ts} | {event.source} | {event.actor} | {description} |"
        )
    return "\n".join(lines)


def emit_jsonl(events: list[TimelineEvent]) -> str:
    """Render events as JSON-lines for downstream tooling."""
    out_lines: list[str] = []
    for event in events:
        payload = asdict(event)
        payload["timestamp"] = (
            event.timestamp.astimezone(timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        out_lines.append(json.dumps(payload))
    return "\n".join(out_lines)


def main() -> int:
    """Entry point."""
    args = parse_args()
    events: list[TimelineEvent] = []

    if args.auth:
        if args.auth_year is None:
            print(
                "error: --auth-year is required when --auth is supplied",
                file=sys.stderr,
            )
            return 2
        tz = _resolve_timezone(args.auth_timezone)
        events.extend(parse_auth_log(args.auth, args.auth_year, tz))
    if args.nginx:
        events.extend(parse_nginx_log(args.nginx))
    if args.journal:
        events.extend(parse_journal_json(args.journal))
    if args.bash_history:
        events.extend(parse_bash_history(args.bash_history, args.bash_history_user))

    if not events:
        print("error: no events parsed; check the input paths.", file=sys.stderr)
        return 1

    events.sort()

    if args.output == "markdown":
        print(emit_markdown(events))
    else:
        print(emit_jsonl(events))
    return 0


if __name__ == "__main__":
    sys.exit(main())
