# Mini-Project — Full Authorised Recon Report on a Host You Own

> Conduct a complete authorised reconnaissance engagement against a host (or small set of hosts) that you own, end-to-end: write the Rules of Engagement, plan the scan, execute the scan inside the planned constraints, triage the output, and produce the written report. The artifact, at the end, is the document a hiring manager reads alongside your Week 4 OWASP, Week 5 toolchain-audit, and Week 6 code-review outputs to answer the question "can this candidate be handed a recon engagement on Monday?"

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The target for this mini-project is a host (or hosts) that you     │
│  own. Acceptable targets:                                           │
│  - your own loopback (127.0.0.1).                                   │
│  - a virtual machine you provisioned and own, on a host-only        │
│    network you provisioned and own (Metasploitable, a Kali lab,     │
│    a self-built target VM).                                         │
│  - a host on a network you own (your home server, a Raspberry Pi    │
│    you administer) PROVIDED the host is on your own internal        │
│    network and you have a clear ownership claim.                    │
│  - a small public-facing host you personally administer             │
│    (a personal VPS, a personal cloud instance) PROVIDED the cloud   │
│    provider's terms of service do not require notification and      │
│    you have read their current pentest policy.                      │
│                                                                     │
│  Not acceptable: your university's network, your employer's         │
│  network, a friend's website, anything that "should be fine."       │
│  When in doubt, drop back to the lab VM. The mini-project is        │
│  about producing a portfolio-grade report; the target need not      │
│  be glamorous, only authorised.                                     │
└─────────────────────────────────────────────────────────────────────┘
```

This mini-project is the synthesis of Week 7. The lectures named the method (authorise, plan, execute, triage, report). The exercises drilled each piece (own-host scan, NSE on the lab VM, XML parsing). The challenge ran the documentation arm (the runbook, the inventory script). The mini-project does the whole thing end-to-end at portfolio depth, with a public write-up.

**Estimated time:** 6.5 hours, spread across Friday and Saturday.

---

## 1. Pick the target

The target must satisfy all of:

- **Authorised.** You own it (or you have written authorisation that satisfies Lecture 1 § 2).
- **Network-isolated for testing.** If the target is on a network you share with others, your testing must not affect the others. The simplest path is a host-only network with VMs you provisioned.
- **Interesting enough.** A target with zero open ports gives you a one-page report; a target with twenty open ports gives you the full exercise. Metasploitable 2 / 3 is the canonical choice for this exercise because it is interesting by construction.
- **Small enough.** One to three hosts, not a `/24`. The point is the depth of the report, not the breadth of the scan.

Record in `target.md`:

```markdown
# Target

- **Host(s):** <IP or hostname list>
- **Ownership basis:** <how you own this; one sentence>
- **Network:** <the network the host(s) live on, with isolation notes>
- **Why I picked this target (2-3 sentences):**
- **Anticipated findings:** <what you expect to see, before running anything>
```

---

## 2. What you will produce

A directory (in your portfolio repo or a dedicated `c6-week-07-recon-<yourhandle>` repo) containing:

```text
c6-week-07-recon/
├── README.md                  # 1-page cover - what this is and how to read it
├── 01-roe.md                  # The signed Rules of Engagement
├── 02-target.md               # Target description
├── 03-scan-plan.md            # The scan plan, written before any scan ran
├── 04-step-log.md             # The chronological execution log
├── 05-asset-inventory.md      # The asset-inventory Markdown (from Challenge 2 script)
├── 06-findings.md             # The triaged findings
├── 07-executive-summary.md    # The 1-page exec summary
├── 08-methodology-and-tools.md # Tool versions and methodology
├── 09-references.md           # Cited sources for every claim
└── scans/                     # All raw nmap outputs (-oA sets)
    ├── 01-host-discovery.{nmap,gnmap,xml}
    ├── 02-top1000.{nmap,gnmap,xml}
    ├── 03-fullrange.{nmap,gnmap,xml}
    ├── 04-udp-top100.{nmap,gnmap,xml}
    ├── 05-default-scripts.{nmap,gnmap,xml}
    ├── 06-safe-scripts.{nmap,gnmap,xml}
    ├── 07-vuln-safe.{nmap,gnmap,xml}
    └── 08-os-scan.{nmap,gnmap,xml}
```

Every file is plain Markdown except the scan outputs. The repo is the portfolio artifact.

---

## 3. The Rules of Engagement (`01-roe.md`)

The first artifact, written before anything else. Use the skeleton from Lecture 1 § 7 as the starting point. Populate every section:

- **Parties** (engineer, owner — both you, in this case).
- **Authority basis** (you own the asset; record that explicitly).
- **Effective and expiration dates**.
- **In-scope assets** (be specific — IPs, hostnames).
- **Out-of-scope assets** (be specific — your LAN, your ISP gateway, anything not in-scope).
- **Allowed actions** (host discovery, TCP SYN, TCP connect, UDP top-100, `-sV`, `-sC`, `safe`, `vuln and safe`, `-O`).
- **Prohibited actions** (NSE `intrusive`, `exploit`, `dos`; anything that would generate traffic to a third party).
- **Time windows** (when you'll work; consider tying this to your study schedule).
- **Rate cap** (`--max-rate 1000` or lower).
- **Source IPs** (your laptop's IP on the test network).
- **Emergency stop** (your own discretion; what would trigger you to stop).
- **Data handling** (where the output lives; retention policy).
- **Deliverables** (this mini-project).
- **Safe-harbour** (a one-sentence note that this is self-engagement and the engineer indemnifies themselves).
- **Signatures** (engineer and owner, both you).

Sign and date the document. Treat your own signature seriously; the discipline of "the signed document exists before the scan" matters more than the literal signature graphic.

---

## 4. The scan plan (`03-scan-plan.md`)

Written *before* the first packet. The plan is a small document — half a page to two pages — that lists:

- **The phases** (host discovery, port scan, service detection, NSE, OS fingerprint, parse, triage, report).
- **The expected time per phase** (with a 25% slack margin).
- **The expected output files** per phase.
- **The decision points** where you might deviate from the plan and what would trigger the deviation.
- **The total time budget**.

A scan plan written before execution is *much* easier than one written after. It also gives the report a clean "this is what I planned vs. this is what I did" comparison in the methodology section.

---

## 5. Execution (Friday afternoon, ~2 hours)

Execute the plan. For each step, populate `04-step-log.md`:

| Step | Planned | Start | End | Command | Output | Notes |
|------|---------|-------|-----|---------|--------|-------|
| 01 host-discovery | 5 min | 14:00 | 14:02 | `sudo nmap -sn -oA scans/01-host-discovery <range>` | scans/01-host-discovery.* | All hosts up. |
| ... | ... | ... | ... | ... | ... | ... |

The step log is the audit trail. Write it as you go, not from memory afterward. The log is one of the artifacts the reviewer reads first to verify the work.

Run the canonical sequence from Lecture 3 § 7 plus the planned NSE categories. Save every `-oA` set under `scans/`.

---

## 6. Triage and parsing (Saturday morning, ~1.5 hours)

Run your Challenge 2 script (or Exercise 3 script) against the XML outputs:

```bash
python3 path/to/challenge-02-build-an-asset-inventory-script.py \
    --dir scans/ \
    --csv asset-inventory.csv \
    --jsonl asset-inventory.jsonl \
    --markdown 05-asset-inventory.md
```

`05-asset-inventory.md` is the auto-generated inventory.

For each candidate finding (every NSE `vuln`-script CVE hit; every end-of-life service version; every anonymous-access configuration; every weak crypto signal), produce a section in `06-findings.md` using the Lecture 3 § 6.5 format:

- Title and severity.
- Affected host(s) and port(s).
- Description.
- Reference (CVE / CWE / vendor advisory link).
- Recommendation.
- Evidence (the command line and the relevant scan-output snippet, with timestamp).

Use **CVSS v3.1** for severity. Score each finding from the CVE entry on NVD; do not invent scores. If the CVE is not in NVD (unusual for any post-1999 CVE), use the closest equivalent vendor advisory and note the source.

---

## 7. Executive summary (`07-executive-summary.md`, ~45 min)

One page, plain English, written for someone who will read it once and act on it. Four paragraphs:

1. **What was tested.** "This engagement assessed the network-facing services on <host>, conducted by <engineer>, between <date> and <date>, under the Rules of Engagement at § 01-roe.md."
2. **Headline findings.** "<N> services were identified across <H> hosts. <M> services run end-of-life or critically-vulnerable versions. <K> services are reachable from outside the host-only network, which is unintended and is the most-urgent item."
3. **What the owner should do.** Three or four specific, ranked recommendations.
4. **Confidence and caveats.** "This was a recon engagement. Vulnerability identification was based on version-matching against NVD; exploitation of any identified vulnerability was out of scope and was not attempted. The report distinguishes *confirmed* findings (NSE script verified) from *inferred* findings (version-matched only)."

The executive summary is the highest-leverage section. Write it last, when you know the actual findings.

---

## 8. Methodology and tools (`08-methodology-and-tools.md`, ~30 min)

A section that lists:

- Tool versions (`nmap --version`, `python3 --version`, etc.).
- The Operating environment (your laptop, OS version).
- The scanning commands used (a compact list, with each command annotated with its purpose).
- The Mark-up of each output file produced and its size in bytes.
- Any deviations from the scan plan, with the reason for each.

The methodology section is the verification artifact. A future reviewer should be able to re-run the engagement from this section alone.

---

## 9. References (`09-references.md`)

Every claim in the report should be backed by a citation. List each citation here, deduplicated:

- The Nmap book chapters cited.
- The RFCs cited.
- Each CVE / CWE referenced in `06-findings.md`.
- The CISA / NIST / OWASP documents cited.
- Any vendor advisories cited.

The references section is what makes the report a *document*, rather than a writeup. It is also what hiring managers look at first — a candidate who cites primary sources is doing the work seriously.

---

## 10. README.md cover

The repo's top-level `README.md`. One page covering:

- The engagement title.
- The dates.
- The engineer (you).
- A two-sentence summary of what is inside.
- A reading-order pointer: "Read in this order for the fastest understanding: README.md → 07-executive-summary.md → 06-findings.md → other artifacts as needed."
- A link to your Week 4, 5, 6, 7 repos / portfolio README.

---

## Acceptance criteria

- All ten files in § 2's tree exist and are populated.
- `01-roe.md` is signed and dated.
- `03-scan-plan.md` predates any scan (the file timestamps support this — commit the plan first).
- `04-step-log.md` has at least eight rows (one per scan phase).
- `06-findings.md` has at least three findings, each with the full five-anchor format and a CVE reference.
- `07-executive-summary.md` is one printed page.
- Every CVE referenced has a working NVD link.
- The asset-inventory file was produced by your Challenge 2 script (or the Exercise 3 script as a fallback).
- The `scans/` directory contains all `-oA` sets.

---

## Style and voice

- **Editorial, sober, professional.** This document goes in a portfolio that hiring managers read. Write it for them.
- **No emojis.** Same reason.
- **Cite primary sources** for every CVE, every protocol claim, every methodology assertion.
- **Distinguish confirmed from inferred** in every finding. A reviewer who finds you treated a version-match as a confirmed exploit will discount everything else in the report.
- **Imperative voice in recommendations.** "Patch OpenSSH to current," not "the customer may wish to consider patching."
- **No hyperbole.** "Critically vulnerable" is reserved for CVSS 9.0+. Everything else is "high," "medium," "low," or "informational."

---

## Common failure modes

1. **The RoE is dated after the first scan.** Reviewers notice. Write the document first.
2. **The findings reference CVEs that do not match the version reported by `-sV`.** Verify the version range on NVD; do not assume.
3. **The executive summary is a technical summary.** The exec summary is for non-technical readers; the technical summary belongs in `06-findings.md`.
4. **The methodology section is missing the deviations.** Real engagements always deviate from the plan. The deviation log is more credible than a too-clean "everything went exactly as planned."
5. **The references section is missing or under-populated.** Citations are not optional; they are the difference between "I read it on Stack Overflow" and "I cited the Nmap book chapter 7."

---

## Stretch

If you finish the core deliverable with time left:

- **Add a "blue-team mirror" section** to `06-findings.md`: for each finding, describe what the SOC would see (firewall log entries, IDS alerts) and what an alert tuned to your scan would look like. This is the kind of write-up that distinguishes engineers who think as both red and blue team from engineers who think as one.
- **Run the engagement on a second target type** (e.g. you ran against Metasploitable 2 the first time; also run against a Docker container of OWASP Juice Shop). The double-run is more work but produces a richer report.
- **Build a `Makefile`** or shell script that re-runs the whole engagement from scratch given the RoE inputs. This is the moment your recon work becomes *tooling*, not just a one-time engagement; the file is one of the most valuable artifacts in a portfolio.
- **Publish the report**. If your target is your own loopback or your own lab, there is no confidentiality risk; pushing the repo public lets future C6 learners see what good looks like. (Confirm your repo permissions before pushing.)
