"""
Exercise 3 - Parse nmap -oX XML output with the Python standard library.

Estimated time: 60 minutes.

============================== AUTHORIZED USE ONLY =============================
This script parses XML files produced by nmap. The XML must come from a scan
you were authorised to conduct - typically the scan you ran in Exercise 1 or
Exercise 2 against a host you own. Do not run nmap against a host you do not
own to feed this script; that is the wrong direction of dependency. The script
is a consumer of authorised scan output, not an excuse to scan.
================================================================================

This script reads an `nmap -oX` XML report and produces three derived views:

1. A human-readable text summary printed to stdout.
2. A CSV file with one row per (host, port) tuple.
3. A JSON-Lines file with one object per host (suitable for ingest by a SIEM).

The point of the exercise is to internalise that `nmap -oX` output is a stable,
well-documented, machine-readable format, and that Python's stdlib `xml.etree`
module is sufficient for nearly every parsing task you will encounter without
needing third-party libraries.

References:
    - nmap XML DTD: https://nmap.org/book/nmap-dtd.html
    - Python xml.etree.ElementTree: https://docs.python.org/3/library/xml.etree.elementtree.html
    - CPE 2.3 specification: https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe
    - Python xml security note: https://docs.python.org/3/library/xml.html#xml-vulnerabilities

A note on XML security. Python's `xml.etree.ElementTree` in the stdlib is
documented as not safe against maliciously-constructed data (billion-laughs,
external-entity expansion, quadratic-blowup). For untrusted input the right
module is `defusedxml`. For our case the input is `nmap -oX` output produced
by `nmap` itself against a host we own, so we accept the risk and use the
stdlib. If you adapt this script for production ingest of third-party-supplied
XML, swap `xml.etree.ElementTree` for `defusedxml.ElementTree`.

Usage:
    python3 exercise-03-output-parsing-with-python.py <input.xml>
    python3 exercise-03-output-parsing-with-python.py <input.xml> --csv out.csv --jsonl out.jsonl

Run with `--help` for the full flag list.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator


# -----------------------------------------------------------------------------
# Data model
# -----------------------------------------------------------------------------


@dataclass
class PortRecord:
    """One open or closed port on one host."""

    protocol: str
    portid: int
    state: str
    state_reason: str
    service_name: str
    service_product: str
    service_version: str
    service_extrainfo: str
    cpes: list[str] = field(default_factory=list)
    script_outputs: dict[str, str] = field(default_factory=dict)


@dataclass
class HostRecord:
    """One host in the scan output."""

    address: str
    address_type: str
    hostname: str
    status: str
    status_reason: str
    os_name: str
    os_accuracy: str
    ports: list[PortRecord] = field(default_factory=list)


# -----------------------------------------------------------------------------
# Parsing
# -----------------------------------------------------------------------------


def parse_nmap_xml(xml_path: Path) -> list[HostRecord]:
    """
    Parse an nmap -oX XML file into a list of HostRecord.

    The function intentionally tolerates missing fields. Real nmap output
    omits elements when the underlying probe could not determine the value
    (e.g. no `<service>` block on a closed port). The right behaviour is
    to record the absence as an empty string rather than to raise.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    if root.tag != "nmaprun":
        raise ValueError(
            f"Expected root element <nmaprun>; got <{root.tag}>. "
            "Is this an nmap -oX XML file?"
        )

    return [_parse_host(host) for host in root.findall("host")]


def _parse_host(host_el: ET.Element) -> HostRecord:
    status_el = host_el.find("status")
    status = status_el.get("state", "") if status_el is not None else ""
    status_reason = status_el.get("reason", "") if status_el is not None else ""

    address_el = host_el.find("address")
    address = address_el.get("addr", "") if address_el is not None else ""
    addr_type = address_el.get("addrtype", "") if address_el is not None else ""

    hostname = ""
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        first = hostnames_el.find("hostname")
        if first is not None:
            hostname = first.get("name", "")

    os_name, os_accuracy = "", ""
    os_el = host_el.find("os")
    if os_el is not None:
        osmatch = os_el.find("osmatch")
        if osmatch is not None:
            os_name = osmatch.get("name", "")
            os_accuracy = osmatch.get("accuracy", "")

    ports: list[PortRecord] = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            ports.append(_parse_port(port_el))

    return HostRecord(
        address=address,
        address_type=addr_type,
        hostname=hostname,
        status=status,
        status_reason=status_reason,
        os_name=os_name,
        os_accuracy=os_accuracy,
        ports=ports,
    )


def _parse_port(port_el: ET.Element) -> PortRecord:
    protocol = port_el.get("protocol", "")
    try:
        portid = int(port_el.get("portid", "0"))
    except ValueError:
        portid = 0

    state, state_reason = "", ""
    state_el = port_el.find("state")
    if state_el is not None:
        state = state_el.get("state", "")
        state_reason = state_el.get("reason", "")

    service_name = ""
    service_product = ""
    service_version = ""
    service_extrainfo = ""
    cpes: list[str] = []
    service_el = port_el.find("service")
    if service_el is not None:
        service_name = service_el.get("name", "")
        service_product = service_el.get("product", "")
        service_version = service_el.get("version", "")
        service_extrainfo = service_el.get("extrainfo", "")
        for cpe_el in service_el.findall("cpe"):
            cpe_text = cpe_el.text or ""
            if cpe_text:
                cpes.append(cpe_text)

    script_outputs: dict[str, str] = {}
    for script_el in port_el.findall("script"):
        script_id = script_el.get("id", "")
        script_output = script_el.get("output", "")
        if script_id:
            script_outputs[script_id] = script_output

    return PortRecord(
        protocol=protocol,
        portid=portid,
        state=state,
        state_reason=state_reason,
        service_name=service_name,
        service_product=service_product,
        service_version=service_version,
        service_extrainfo=service_extrainfo,
        cpes=cpes,
        script_outputs=script_outputs,
    )


# -----------------------------------------------------------------------------
# Output renderers
# -----------------------------------------------------------------------------


def render_text_summary(hosts: list[HostRecord]) -> str:
    """
    Produce a human-readable summary suitable for stdout.

    The format is deliberately compact: one block per host, one line per
    open or open|filtered port. Closed and filtered-only ports are omitted
    from the summary because they rarely matter to the human reader; the
    CSV and JSONL outputs preserve them for downstream tooling.
    """
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("NMAP SCAN SUMMARY")
    lines.append("=" * 72)
    lines.append(f"Hosts in report: {len(hosts)}")
    lines.append("")
    for host in hosts:
        lines.append(f"Host: {host.address} ({host.hostname or '-'})")
        lines.append(f"  Status: {host.status} ({host.status_reason})")
        if host.os_name:
            lines.append(f"  OS: {host.os_name} (accuracy {host.os_accuracy}%)")
        open_ports = [p for p in host.ports if p.state.startswith("open")]
        lines.append(f"  Open ports: {len(open_ports)}")
        for port in open_ports:
            service_str = port.service_name or "(unknown)"
            if port.service_product:
                service_str += f" - {port.service_product}"
                if port.service_version:
                    service_str += f" {port.service_version}"
            lines.append(
                f"    {port.portid}/{port.protocol:3} {port.state:13} {service_str}"
            )
            for cpe in port.cpes:
                lines.append(f"      CPE: {cpe}")
            for script_id, script_output in port.script_outputs.items():
                first_line = script_output.split("\n", 1)[0].strip()
                lines.append(f"      [{script_id}] {first_line}")
        lines.append("")
    return "\n".join(lines)


def write_csv(hosts: list[HostRecord], csv_path: Path) -> int:
    """
    Write a flat CSV with one row per (host, port). Returns the row count.

    The CSV is the artifact most useful for spreadsheet review and for
    the kind of ad-hoc analysis that happens during a finding-triage
    meeting. It is intentionally lossy - the NSE script-output text and
    the full extrainfo are folded into single columns rather than each
    getting its own.
    """
    fieldnames = [
        "address",
        "address_type",
        "hostname",
        "status",
        "os_name",
        "os_accuracy",
        "protocol",
        "portid",
        "state",
        "state_reason",
        "service_name",
        "service_product",
        "service_version",
        "service_extrainfo",
        "cpes",
        "script_ids",
    ]
    rows_written = 0
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for host in hosts:
            for port in host.ports:
                writer.writerow(
                    {
                        "address": host.address,
                        "address_type": host.address_type,
                        "hostname": host.hostname,
                        "status": host.status,
                        "os_name": host.os_name,
                        "os_accuracy": host.os_accuracy,
                        "protocol": port.protocol,
                        "portid": port.portid,
                        "state": port.state,
                        "state_reason": port.state_reason,
                        "service_name": port.service_name,
                        "service_product": port.service_product,
                        "service_version": port.service_version,
                        "service_extrainfo": port.service_extrainfo,
                        "cpes": ";".join(port.cpes),
                        "script_ids": ";".join(sorted(port.script_outputs)),
                    }
                )
                rows_written += 1
    return rows_written


def write_jsonl(hosts: list[HostRecord], jsonl_path: Path) -> int:
    """
    Write JSON-Lines with one object per host. Returns the line count.

    JSON-Lines is the right format for SIEM ingest: each line is a complete
    JSON document, the file is appendable, and existing tooling (jq, Splunk,
    Elastic) consumes it directly. The schema is the HostRecord dataclass.
    """
    lines_written = 0
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for host in hosts:
            fh.write(json.dumps(asdict(host), sort_keys=True))
            fh.write("\n")
            lines_written += 1
    return lines_written


# -----------------------------------------------------------------------------
# Queries
# -----------------------------------------------------------------------------


def iter_findings_with_cve(hosts: list[HostRecord]) -> Iterator[tuple[str, int, str, str]]:
    """
    Yield (address, portid, script_id, output) tuples for NSE script outputs
    that mention CVE identifiers. Used by `--findings` to surface candidate
    high-signal results without re-reading the full XML.
    """
    for host in hosts:
        for port in host.ports:
            for script_id, output in port.script_outputs.items():
                if "CVE-" in output:
                    yield (host.address, port.portid, script_id, output.strip())


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse nmap -oX XML into summary text, CSV, and JSONL.",
    )
    parser.add_argument(
        "xml",
        type=Path,
        help="Path to the nmap -oX XML file (e.g. scan-for-parsing.xml).",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help="Optional. Write a CSV with one row per (host, port).",
    )
    parser.add_argument(
        "--jsonl",
        type=Path,
        default=None,
        help="Optional. Write JSON-Lines with one object per host.",
    )
    parser.add_argument(
        "--findings",
        action="store_true",
        help="Print only the NSE script outputs that mention CVE identifiers.",
    )
    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Suppress the human-readable summary on stdout.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    if not args.xml.exists():
        print(f"ERROR: input file not found: {args.xml}", file=sys.stderr)
        return 2

    try:
        hosts = parse_nmap_xml(args.xml)
    except ET.ParseError as exc:
        print(f"ERROR: failed to parse XML: {exc}", file=sys.stderr)
        return 3
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 4

    if not args.no_summary:
        print(render_text_summary(hosts))

    if args.csv is not None:
        rows = write_csv(hosts, args.csv)
        print(f"Wrote {rows} CSV rows to {args.csv}", file=sys.stderr)

    if args.jsonl is not None:
        lines = write_jsonl(hosts, args.jsonl)
        print(f"Wrote {lines} JSONL records to {args.jsonl}", file=sys.stderr)

    if args.findings:
        print("\nCVE-mentioning NSE script outputs")
        print("-" * 72)
        any_found = False
        for address, portid, script_id, output in iter_findings_with_cve(hosts):
            any_found = True
            print(f"{address}:{portid} [{script_id}]")
            for line in output.split("\n"):
                print(f"    {line}")
            print()
        if not any_found:
            print("(no NSE script outputs mention CVE identifiers)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
