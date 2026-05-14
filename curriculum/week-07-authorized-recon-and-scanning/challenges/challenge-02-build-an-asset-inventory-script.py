"""
Challenge 2 - Build an asset-inventory script.

Estimated time: 2 hours.

============================== AUTHORIZED USE ONLY =============================
This script consumes nmap -oX output from scans you were authorised to run.
It does not itself send packets to anyone; it is a pure parser and reporter.
Use the output to inform reports on hosts you own or have signed RoE access
to. Do not feed it XML from scans you were not authorised to perform.
================================================================================

Goal
----
Build a small, robust, reusable asset-inventory tool that:

1. Accepts one or more nmap -oX XML files on the command line (or a directory
   containing them).
2. Merges the records across files, deduplicating on (address, port, protocol).
3. Emits four output artifacts:
   - A flat CSV (one row per host x port).
   - A JSON-Lines feed (one object per host, suitable for SIEM ingest).
   - A Markdown summary suitable for pasting into a report.
   - A short stdout digest with the inventory totals.
4. Handles the realistic case where the same host appears in multiple scan
   files (an initial sweep plus an enrichment pass produce two XMLs for the
   same target; the union of the two is the right inventory).

This script extends Exercise 3 from a single-file reader to a small CLI tool
that fits cleanly into a recon runbook (Challenge 1).

References
----------
    - nmap XML DTD: https://nmap.org/book/nmap-dtd.html
    - Python xml.etree.ElementTree:
      https://docs.python.org/3/library/xml.etree.elementtree.html
    - argparse: https://docs.python.org/3/library/argparse.html
    - csv: https://docs.python.org/3/library/csv.html
    - json: https://docs.python.org/3/library/json.html

XML security: the same note as Exercise 3 applies. We use the stdlib
parser because the input is nmap output we produced ourselves. For
ingestion of third-party XML, swap in `defusedxml.ElementTree`.

Usage
-----
    python3 challenge-02-build-an-asset-inventory-script.py \\
        --inputs scan1.xml scan2.xml ... \\
        --csv inventory.csv \\
        --jsonl inventory.jsonl \\
        --markdown inventory.md

    # or, point at a directory and let the script find every *.xml inside:
    python3 challenge-02-build-an-asset-inventory-script.py \\
        --dir ~/c6-week-07/mini-project/scans/ \\
        --csv inventory.csv \\
        --jsonl inventory.jsonl \\
        --markdown inventory.md

Run with `--help` for the full flag list.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# -----------------------------------------------------------------------------
# Data model
# -----------------------------------------------------------------------------


@dataclass
class PortEntry:
    """One open or filtered port on one host, merged across input files."""

    protocol: str
    portid: int
    state: str
    service_name: str = ""
    service_product: str = ""
    service_version: str = ""
    service_extrainfo: str = ""
    cpes: set[str] = field(default_factory=set)
    script_ids: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)


@dataclass
class HostEntry:
    """One host across all input files."""

    address: str
    hostnames: set[str] = field(default_factory=set)
    os_guesses: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    ports: dict[tuple[str, int], PortEntry] = field(default_factory=dict)


# -----------------------------------------------------------------------------
# Parsing one XML file
# -----------------------------------------------------------------------------


def collect_xml_paths(input_files: list[Path], input_dir: Path | None) -> list[Path]:
    """
    Resolve the user's CLI selection to a concrete list of XML file paths.
    Files listed explicitly take priority; the directory is expanded last
    and de-duplicated against the explicit list.
    """
    seen: set[Path] = set()
    result: list[Path] = []
    for p in input_files:
        if p.is_file():
            ap = p.resolve()
            if ap not in seen:
                seen.add(ap)
                result.append(ap)
    if input_dir is not None and input_dir.is_dir():
        for p in sorted(input_dir.glob("*.xml")):
            ap = p.resolve()
            if ap not in seen:
                seen.add(ap)
                result.append(ap)
    return result


def parse_one_xml(xml_path: Path, accumulator: dict[str, HostEntry]) -> int:
    """
    Parse one nmap XML file, folding the records into the accumulator.
    Returns the number of <host> elements consumed.

    The accumulator is keyed by host address. A new host gets a new
    HostEntry; an existing host has its data merged.
    """
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        print(f"WARN: skipping {xml_path}: parse error: {exc}", file=sys.stderr)
        return 0

    root = tree.getroot()
    if root.tag != "nmaprun":
        print(
            f"WARN: skipping {xml_path}: root is <{root.tag}>, not <nmaprun>",
            file=sys.stderr,
        )
        return 0

    hosts_seen = 0
    source_label = xml_path.name
    for host_el in root.findall("host"):
        _ingest_host(host_el, accumulator, source_label)
        hosts_seen += 1
    return hosts_seen


def _ingest_host(
    host_el: ET.Element,
    accumulator: dict[str, HostEntry],
    source_label: str,
) -> None:
    address_el = host_el.find("address")
    if address_el is None:
        return
    address = address_el.get("addr", "")
    if not address:
        return

    entry = accumulator.get(address)
    if entry is None:
        entry = HostEntry(address=address)
        accumulator[address] = entry
    entry.sources.add(source_label)

    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        for h in hostnames_el.findall("hostname"):
            name = h.get("name", "")
            if name:
                entry.hostnames.add(name)

    os_el = host_el.find("os")
    if os_el is not None:
        for osmatch in os_el.findall("osmatch"):
            name = osmatch.get("name", "")
            accuracy = osmatch.get("accuracy", "")
            if name:
                entry.os_guesses.add(f"{name} ({accuracy}%)")

    ports_el = host_el.find("ports")
    if ports_el is None:
        return
    for port_el in ports_el.findall("port"):
        _ingest_port(port_el, entry, source_label)


def _ingest_port(
    port_el: ET.Element,
    host: HostEntry,
    source_label: str,
) -> None:
    protocol = port_el.get("protocol", "")
    try:
        portid = int(port_el.get("portid", "0"))
    except ValueError:
        return
    if not protocol or not portid:
        return

    key = (protocol, portid)

    state_el = port_el.find("state")
    state = state_el.get("state", "") if state_el is not None else ""

    port_entry = host.ports.get(key)
    if port_entry is None:
        port_entry = PortEntry(protocol=protocol, portid=portid, state=state)
        host.ports[key] = port_entry
    else:
        # The merge rule for state: prefer "open" if any source saw open;
        # otherwise keep the existing state. This makes the union view
        # err on the side of "the service is there" rather than against.
        if state == "open" and not port_entry.state.startswith("open"):
            port_entry.state = "open"

    port_entry.sources.add(source_label)

    service_el = port_el.find("service")
    if service_el is not None:
        # Merge rule: prefer non-empty values from the most-recent ingest,
        # but never overwrite a non-empty product/version with an empty one.
        for attr_name, current in (
            ("name", port_entry.service_name),
            ("product", port_entry.service_product),
            ("version", port_entry.service_version),
            ("extrainfo", port_entry.service_extrainfo),
        ):
            new_val = service_el.get(attr_name, "")
            if new_val and not current:
                if attr_name == "name":
                    port_entry.service_name = new_val
                elif attr_name == "product":
                    port_entry.service_product = new_val
                elif attr_name == "version":
                    port_entry.service_version = new_val
                else:
                    port_entry.service_extrainfo = new_val
        for cpe_el in service_el.findall("cpe"):
            cpe_text = cpe_el.text or ""
            if cpe_text:
                port_entry.cpes.add(cpe_text)

    for script_el in port_el.findall("script"):
        script_id = script_el.get("id", "")
        if script_id:
            port_entry.script_ids.add(script_id)


# -----------------------------------------------------------------------------
# Output renderers
# -----------------------------------------------------------------------------


def write_csv(hosts: dict[str, HostEntry], csv_path: Path) -> int:
    fieldnames = [
        "address",
        "hostnames",
        "os_guesses",
        "protocol",
        "portid",
        "state",
        "service_name",
        "service_product",
        "service_version",
        "service_extrainfo",
        "cpes",
        "script_ids",
        "sources",
    ]
    rows_written = 0
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for address in sorted(hosts):
            host = hosts[address]
            if not host.ports:
                writer.writerow(
                    {
                        "address": host.address,
                        "hostnames": ";".join(sorted(host.hostnames)),
                        "os_guesses": ";".join(sorted(host.os_guesses)),
                        "protocol": "",
                        "portid": "",
                        "state": "",
                        "service_name": "",
                        "service_product": "",
                        "service_version": "",
                        "service_extrainfo": "",
                        "cpes": "",
                        "script_ids": "",
                        "sources": ";".join(sorted(host.sources)),
                    }
                )
                rows_written += 1
                continue
            for _key, port in sorted(host.ports.items()):
                writer.writerow(
                    {
                        "address": host.address,
                        "hostnames": ";".join(sorted(host.hostnames)),
                        "os_guesses": ";".join(sorted(host.os_guesses)),
                        "protocol": port.protocol,
                        "portid": port.portid,
                        "state": port.state,
                        "service_name": port.service_name,
                        "service_product": port.service_product,
                        "service_version": port.service_version,
                        "service_extrainfo": port.service_extrainfo,
                        "cpes": ";".join(sorted(port.cpes)),
                        "script_ids": ";".join(sorted(port.script_ids)),
                        "sources": ";".join(sorted(port.sources)),
                    }
                )
                rows_written += 1
    return rows_written


def _host_to_jsonable(host: HostEntry) -> dict[str, object]:
    return {
        "address": host.address,
        "hostnames": sorted(host.hostnames),
        "os_guesses": sorted(host.os_guesses),
        "sources": sorted(host.sources),
        "ports": [
            {
                "protocol": port.protocol,
                "portid": port.portid,
                "state": port.state,
                "service_name": port.service_name,
                "service_product": port.service_product,
                "service_version": port.service_version,
                "service_extrainfo": port.service_extrainfo,
                "cpes": sorted(port.cpes),
                "script_ids": sorted(port.script_ids),
                "sources": sorted(port.sources),
            }
            for _key, port in sorted(host.ports.items())
        ],
    }


def write_jsonl(hosts: dict[str, HostEntry], jsonl_path: Path) -> int:
    lines_written = 0
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for address in sorted(hosts):
            fh.write(json.dumps(_host_to_jsonable(hosts[address]), sort_keys=True))
            fh.write("\n")
            lines_written += 1
    return lines_written


def write_markdown(hosts: dict[str, HostEntry], md_path: Path) -> None:
    """
    Markdown report. The shape is designed for paste-in to a recon report:
    a heading, an inventory totals block, a per-host table.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    open_port_count = sum(
        1 for h in hosts.values() for p in h.ports.values() if p.state.startswith("open")
    )
    service_count = defaultdict(int)
    for h in hosts.values():
        for p in h.ports.values():
            if p.state.startswith("open") and p.service_name:
                service_count[p.service_name] += 1

    with md_path.open("w", encoding="utf-8") as fh:
        fh.write("# Asset Inventory\n\n")
        fh.write(f"_Generated {timestamp}_\n\n")
        fh.write("## Totals\n\n")
        fh.write(f"- Hosts in inventory: **{len(hosts)}**\n")
        fh.write(f"- Open ports: **{open_port_count}**\n")
        fh.write(f"- Distinct services seen: **{len(service_count)}**\n\n")

        if service_count:
            fh.write("## Top services\n\n")
            fh.write("| Service | Count |\n")
            fh.write("|---------|-------|\n")
            for service, count in sorted(
                service_count.items(), key=lambda kv: (-kv[1], kv[0])
            )[:15]:
                fh.write(f"| {service} | {count} |\n")
            fh.write("\n")

        fh.write("## Hosts\n\n")
        for address in sorted(hosts):
            host = hosts[address]
            hostnames = ", ".join(sorted(host.hostnames)) or "-"
            fh.write(f"### {host.address}\n\n")
            fh.write(f"- **Hostnames:** {hostnames}\n")
            if host.os_guesses:
                fh.write(f"- **OS guesses:** {'; '.join(sorted(host.os_guesses))}\n")
            fh.write(f"- **Sources:** {', '.join(sorted(host.sources))}\n\n")

            open_ports = [p for p in host.ports.values() if p.state.startswith("open")]
            if not open_ports:
                fh.write("_No open ports observed in any source._\n\n")
                continue

            fh.write("| Port | Proto | Service | Product / version | CPEs |\n")
            fh.write("|------|-------|---------|--------------------|------|\n")
            for port in sorted(open_ports, key=lambda p: (p.protocol, p.portid)):
                product_version = port.service_product
                if port.service_version:
                    product_version = (
                        f"{product_version} {port.service_version}"
                        if product_version
                        else port.service_version
                    )
                cpes = ", ".join(sorted(port.cpes)) or "-"
                fh.write(
                    f"| {port.portid} | {port.protocol} | "
                    f"{port.service_name or '-'} | "
                    f"{product_version or '-'} | {cpes} |\n"
                )
            fh.write("\n")


def render_stdout_digest(hosts: dict[str, HostEntry]) -> str:
    open_port_count = sum(
        1 for h in hosts.values() for p in h.ports.values() if p.state.startswith("open")
    )
    lines: list[str] = []
    lines.append(f"Hosts in inventory: {len(hosts)}")
    lines.append(f"Open ports observed: {open_port_count}")
    lines.append("")
    for address in sorted(hosts):
        host = hosts[address]
        open_ports = [p for p in host.ports.values() if p.state.startswith("open")]
        lines.append(f"  {address:39s}  ({len(open_ports)} open)")
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a merged asset inventory from one or more nmap -oX XML files."
        ),
    )
    parser.add_argument(
        "--inputs",
        type=Path,
        nargs="*",
        default=[],
        help="One or more XML files to consume.",
    )
    parser.add_argument(
        "--dir",
        dest="input_dir",
        type=Path,
        default=None,
        help="Directory of *.xml files to consume.",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help="Optional. Write a flat CSV inventory to this path.",
    )
    parser.add_argument(
        "--jsonl",
        type=Path,
        default=None,
        help="Optional. Write a JSON-Lines feed to this path.",
    )
    parser.add_argument(
        "--markdown",
        type=Path,
        default=None,
        help="Optional. Write a Markdown summary to this path.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    xml_paths = collect_xml_paths(args.inputs, args.input_dir)
    if not xml_paths:
        print(
            "ERROR: no XML inputs specified. Pass --inputs <files> "
            "or --dir <directory>.",
            file=sys.stderr,
        )
        return 2

    accumulator: dict[str, HostEntry] = {}
    total_hosts_consumed = 0
    for xml_path in xml_paths:
        total_hosts_consumed += parse_one_xml(xml_path, accumulator)

    print(
        f"Consumed {total_hosts_consumed} <host> elements from "
        f"{len(xml_paths)} XML file(s).",
        file=sys.stderr,
    )

    print(render_stdout_digest(accumulator))

    if args.csv is not None:
        rows = write_csv(accumulator, args.csv)
        print(f"Wrote {rows} CSV rows to {args.csv}", file=sys.stderr)

    if args.jsonl is not None:
        lines = write_jsonl(accumulator, args.jsonl)
        print(f"Wrote {lines} JSONL records to {args.jsonl}", file=sys.stderr)

    if args.markdown is not None:
        write_markdown(accumulator, args.markdown)
        print(f"Wrote Markdown summary to {args.markdown}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
