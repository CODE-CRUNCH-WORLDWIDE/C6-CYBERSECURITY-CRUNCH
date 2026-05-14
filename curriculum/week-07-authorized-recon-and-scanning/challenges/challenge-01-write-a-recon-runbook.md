# Challenge 1 — Write a Recon Runbook

**Estimated time:** 2 hours. Written deliverable. No live scanning required for the runbook itself.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  This challenge produces a *document*. When the document is         │
│  exercised against real targets in future weeks or future           │
│  engagements, the AUTHORIZED USE rules of this curriculum and       │
│  the relevant Rules of Engagement apply. The runbook itself is      │
│  legal to write everywhere; the techniques it describes are         │
│  legal to *execute* only against authorised targets.                │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

A junior security engineer joins your team on Monday. Their first task is a recon engagement against a customer's external infrastructure. The lead is on holiday. You leave them a runbook — a step-by-step, no-judgment-required document that walks them from "I have just been handed the RoE" to "I have the scan output ready for the senior engineer's triage."

The runbook is a portable artifact. It outlives any single engagement; it is what your future self consults when the details of `nmap` flags have faded; it is what your firm's other engineers borrow when they cover your rotation.

This challenge covers:

- **Writing operational documentation** for technical work.
- **Structuring a procedure** so that it is auditable, repeatable, and resistant to step-skipping.
- **Encoding decision points** so that the runbook handles common deviations without panic.

---

## Deliverable

A single Markdown file, `recon-runbook.md`, structured as below. Length: roughly 800-1500 lines including the appendix. The runbook lives in your portfolio repo.

---

## Required sections

### 1. Header

- Title.
- Author (you).
- Version (`v1.0`).
- Date.
- Intended audience (a one-line description: "engineers conducting external network recon on a signed RoE").
- A `Changelog` placeholder for future versions.

### 2. Scope of this runbook

A 100-200 word section defining what the runbook covers and what it does not. Explicitly cover:

- The engagement type it handles (external network recon, internal recon, both, or one only).
- The targets it supports (single IP, small subnet, large subnet, internet-facing only, internal-only, both).
- The deliverable it produces (an output directory ready for triage; not a finished report).
- The activities it does *not* cover (web-app testing, social engineering, exploitation, etc.).

### 3. Pre-flight checklist

A checklist the engineer walks before any packet is sent. Each item is a `- [ ]` checkbox with a one-line description plus a sub-bullet of "how to verify." Minimum entries:

- The signed RoE is in hand and not expired.
- The in-scope asset list is recorded as a text file.
- The out-of-scope asset list is recorded as a text file.
- The source IPs to scan from are confirmed and the owner has whitelisted them.
- The rate cap from the RoE is recorded.
- The time-window restriction is checked against the current time.
- The emergency-stop contact info is recorded.
- The output directory is created with a date-stamped name.

### 4. Tool inventory and version check

A small command block that confirms the toolchain is installed and current:

```bash
nmap --version
masscan --version 2>/dev/null || echo "masscan not installed"
naabu -version 2>/dev/null || echo "naabu not installed"
xmllint --version
python3 --version
```

For each tool, document the *minimum acceptable version*. If a tool is below the minimum, link to the firm's standard install procedure (or the upstream install docs).

### 5. Step-by-step procedure

The body of the runbook. Each step is:

1. A short imperative title.
2. The command(s) to run, with `<placeholder>` markers for the inputs the engineer must substitute.
3. The expected output shape.
4. The "what to do if it goes wrong" sub-section.

Minimum steps:

1. **Confirm reachability.** Ping the target range; record which hosts responded.
2. **Host discovery.** `nmap -sn` against the in-scope range, output `-oA`.
3. **Initial port scan.** `nmap -sS --top-ports 1000 --max-rate <CAP>` against the live hosts, output `-oA`.
4. **Service detection.** `nmap -sS -sV -sC --max-rate <CAP>` against the live hosts, output `-oA`.
5. **Full port range.** `nmap -sS -p- --max-rate <CAP>` against high-value hosts identified in step 4, output `-oA`.
6. **UDP top-100.** `nmap -sU -sV --top-ports 100 --max-rate <CAP>` against the live hosts, output `-oA`.
7. **NSE `safe` category** against the live hosts, output `-oA`.
8. **NSE `vuln and safe`** against the live hosts, output `-oA` (RoE-gated; include the gating check).
9. **OS fingerprinting** with `--osscan-limit`, output `-oA`.
10. **Asset-inventory parse** (using the Challenge 2 script).
11. **Output verification** (list of files produced, byte-counts, etc.).
12. **Hand-off.** A pointer to the senior engineer's review queue.

### 6. Decision points

A subsection that handles common deviations. Each decision is "if X, then Y." Examples:

- *If* a host shows `filtered` on every port: try `-sA` to check whether the path is stateful-firewalled.
- *If* the scan stalls partway: pause, reduce `--max-rate` by half, resume.
- *If* `-sV` reports `tcpwrapped`: re-probe with `--version-intensity 0` and a longer per-host timeout.
- *If* `-O` reports low confidence: cross-check via `-sV` banner-derived OS.
- *If* the SOC contact reports increased load: pause immediately, communicate, agree a new rate, restart.

### 7. Output verification

Before declaring the run complete, the engineer must confirm:

- One `-oA` set per scan type (every `<name>.nmap`, `<name>.gnmap`, `<name>.xml` present).
- Every `.xml` parses (`xmllint --noout <file>` returns 0).
- The asset-inventory CSV exists and contains at least one row per live host.
- The runbook step-log has been populated (see § 8).

### 8. Step log template

A blank table the engineer fills as they go, recording each step's start time, end time, command, and output file. The table is the audit trail — the artifact that lets a future reader reconstruct what was done and when.

| Step | Start | End | Command | Output | Notes |
|------|-------|-----|---------|--------|-------|

### 9. Emergency procedures

- Emergency-stop: how to kill all running scans within 60 seconds. Example: `sudo pkill -INT nmap; sudo pkill -INT masscan; sudo pkill -INT naabu`.
- Network anomaly: how to confirm whether your traffic is the cause (`tcpdump`, source-IP check).
- Lost contact with owner: how to suspend cleanly, save state, and document the gap.

### 10. Hand-off package

What the engineer hands to the senior engineer for triage:

- The output directory.
- The asset-inventory CSV.
- The step-log table.
- A `summary.md` populated from a template (which the runbook also contains).
- The signed RoE attached for reference.

### 11. Appendix — RoE-gated steps

A subsection that lists the steps that require explicit RoE language to run. For each:

- The required RoE language.
- A "do not run if this language is missing" warning.
- Examples: NSE `vuln`, `intrusive`, `exploit`, `dos` categories; deliberate IDS-triggering; off-hours scanning.

### 12. Appendix — references

Inline links to:

- Nmap book chapters 5, 6, 7, 9.
- The relevant RFCs (793, 9293, 768, 792).
- The OWASP WSTG Information Gathering section.
- The firm's internal standard operating procedure for engagement closure (placeholder if the firm has not written it).

---

## Acceptance

- The runbook is in your portfolio repo as `recon-runbook.md`.
- All required sections (1-12 above) are present.
- The runbook is in *imperative* voice — "run X," not "you should consider running X."
- Every command block includes the `--max-rate` placeholder; no command runs uncapped.
- The step-log template is present even if blank.
- The RoE-gated steps section explicitly names `vuln`, `intrusive`, `exploit`, `dos`.

---

## Stretch

If you finish the core runbook with time left:

- **Add a YAML config** at the top of the runbook that captures the engagement parameters (in-scope, rate, time window) so that the engineer can copy-paste the config from the RoE rather than retype each command's placeholders.
- **Add a corresponding Python `Makefile`-style helper** that reads the YAML and emits the actual scan commands. This is the version of the runbook that becomes a script — closer to "tooling" than to "documentation," and the right shape for a firm running a recurring engagement.
- **Add a "blue-team mirror" section** that documents how the SOC will see each step of your scan, with example signatures the SOC would alert on. This is the kind of awareness that distinguishes engineers who think only as red team from engineers who think as both.

---

## Notes on style

The runbook is for someone tired, on Monday morning, after the lead has gone on holiday. It is *not* a tutorial. It does not explain *why* the steps exist — that is what the lecture notes are for. It explains *what to do*, in order, with clear sub-procedures for the common deviations.

Imperative voice. Short paragraphs. Every command-line example is one block. Every decision point is one `if X then Y` sentence. The reader should be able to skim the headings and find the section they need in under thirty seconds.

If you read your own runbook and find yourself adding adjectives, delete the adjectives. If you find yourself adding a "rationale" paragraph, delete the paragraph and link to the relevant lecture-note. The runbook is reference-grade documentation; it is not a teaching document.
