# Week 7 Homework

Six problems, ~6 hours total. Commit each in your Week 7 repo. The exercises were guided drills on single methods; the homework is closer to the daily work of a recon-stage engineer operating under an RoE.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Every problem operates against your own loopback, a vulnerable     │
│  VM you own and isolated on a host-only network, or written         │
│  authorisations you hold. Problems 1, 3, and 6 are pure desk        │
│  work and require no live scanning. Problems 2, 4, and 5 require    │
│  the lab VM. If you do not have the lab VM set up, complete those   │
│  problems against your own loopback instead and note the            │
│  substitution in your write-up.                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Problem 1 — Author your personal recon checklist (45 min)

Create `notes/hw1-recon-checklist.md`. The file is your personal recon-stage checklist, distilled from Lectures 1-3 and the runbook from Challenge 1.

The deliverable:

- A pre-flight section with the items from the runbook's § 3.
- A per-target section with the technical steps from § 5 of the runbook.
- A post-scan section with the verification, parsing, and hand-off items.
- At least five **personal additions**, each with a one-sentence justification and a reference (a lecture section, a CWE, a CVE, or an audit-report citation).
- A "version" and "changelog" placeholder at top and bottom.

**Acceptance.** The personal additions are real and cited. The checklist fits in one to three printed pages. The pre-flight items include the signed-RoE check.

---

## Problem 2 — Scan a Metasploitable VM with the canonical mode set (60 min)

Using the lab VM you set up in Exercise 2, run *the full canonical sequence* with `-oA` outputs in one engagement-style run:

1. Host discovery.
2. Top-1000 TCP SYN scan, `-sV -sC`.
3. Full-range TCP SYN scan, `-sV -sC`, rate-capped at 1000 pps.
4. UDP top-100, `-sV`, rate-capped at 200 pps.
5. NSE `safe` category.
6. NSE `vuln and safe` selector.
7. `-O` with `--osscan-limit`.

Save all output sets under `~/c6-week-07/hw2/scans/`. Capture a step log in `notes/hw2-step-log.md` recording start time, end time, command, output file, and any anomalies for each step.

**Acceptance.** Seven `-oA` sets present. Step log filled. No commands ran uncapped.

---

## Problem 3 — Compare three scanners against the same target (60 min)

Pick one target from the lab — *your own loopback or the Metasploitable VM* (a host you own). Scan the *same* port range with three different tools and produce a comparison table.

1. `sudo nmap -sS -p 1-1000 --max-rate 1000 -oX nmap.xml <target>`.
2. `sudo masscan -p 1-1000 --rate 1000 -oX masscan.xml <target>` (if `masscan` is installed).
3. `naabu -host <target> -p 1-1000 -rate 1000 -o naabu.txt` (if `naabu` is installed).

If `masscan` or `naabu` is unavailable, document the absence and run the comparison with the two tools you have.

In `notes/hw3-comparison.md`, build a comparison table with columns:

| Tool | Time | Open ports found | Closed ports counted | False negatives (ports the other tools found that this missed) | Notes |

Then, ~200 words on the *role* each tool plays: which is the right tool for "I have a `/16` and 30 minutes," which for "I have one host and need the most accurate possible picture," which for "I want to feed results into a modern pipeline."

**Acceptance.** Three scans, one comparison table, the role discussion.

---

## Problem 4 — Triage three CVE findings from the Metasploitable scan (60 min)

From the `vuln and safe` output in Problem 2, pick three distinct CVE findings. For each, produce a `notes/hw4-finding-<N>.md` file with:

- **Title** of the finding.
- **Affected host and port**, with the service name, product, and version.
- **CVE ID** and a link to the NVD entry.
- **CVSS v3.1 score** from NVD, and a one-sentence justification of why the score is what it is (look at the vector: AV, AC, PR, UI, S, C, I, A).
- **Description** of what an attacker could do if the vulnerability were on a production host.
- **Recommendation** for the host owner.
- **Confidence** in the finding: did your scan *confirm* the vulnerability (a `vuln`-active script confirmed it), or did your scan *infer* the vulnerability (the version matches a known vulnerable range)?

**Acceptance.** Three findings, each with all bullet points populated. CVSS vectors are real.

---

## Problem 5 — Build a "scan plan" before scanning (45 min)

For a hypothetical engagement (you may invent the customer) where you have been handed:

- A `/24` of public IPs to test.
- A 48-hour testing window starting at 22:00 next Friday in the customer's local time zone.
- A rate cap of 2000 pps aggregate.
- A signed RoE allowing TCP SYN, UDP top-100, version detection, default scripts, and `vuln and safe` NSE.

Write `notes/hw5-scan-plan.md`. The plan covers:

- The host-discovery phase (estimated time, command, output destination).
- The port-scan phase (split into top-1000 first pass and full-range second pass on live hosts only).
- The service-detection phase.
- The NSE phase.
- A time-budget table summing to under 48 hours, with a 25% slack margin.
- A list of decision points where you would pause and check before continuing.
- A "what happens if we discover a critical 0-day mid-scan" sub-section referring to Week 3's disclosure flow.

**Acceptance.** The plan is operational, not aspirational. The time budget adds up. The decision points are specific.

---

## Problem 6 — Read one statute, write one summary (60 min)

Pick one of:

- 18 U.S.C. § 1030 (CFAA) — read § 1030(a)(2), (a)(5)(A), (a)(5)(B), and (g) (civil action).
- Computer Misuse Act 1990 — read §§ 1, 2, 3, 3ZA.
- Directive 2013/40/EU — read Articles 3-7 and the recitals.

In `notes/hw6-statute-summary.md`, ~600 words covering:

- A plain-English summary of what each read section criminalises.
- The maximum penalties for each.
- The *mental state* (mens rea) the statute requires for conviction (intent, knowledge, recklessness, negligence).
- One example, drawn from your own reading or a public news source, of a prosecution under that statute. Cite the case.
- One reflection on how the statute applies (or does not apply) to a *port scan* specifically, and how it applies once you cross any further threshold (banner grab, credential submit, exploit attempt).

The point of this problem is to read the *primary* source, not a summary of it. Cite the section numbers in your write-up.

**Acceptance.** The summary cites the actual statute sections. The example case is real and dated.

---

## Submission

Commit `notes/hw1-recon-checklist.md`, `notes/hw2-step-log.md`, `notes/hw3-comparison.md`, `notes/hw4-finding-1.md` through `notes/hw4-finding-3.md`, `notes/hw5-scan-plan.md`, and `notes/hw6-statute-summary.md`, plus the `~/c6-week-07/hw2/scans/` directory, to your Week 7 repo. The portfolio README links to each.

Total time budget: 6 hours. If you find a problem running over, write down where the time went; the reflection is useful in its own right.
