# Week 7 — Authorized Recon and Scanning

> *Week 6 closed the defensive arc: read someone else's diff, model the trust boundaries, write the comment that gets the bug fixed before it merges. Week 7 turns the lens around. You will scan hosts — but only hosts you own or have written permission to touch — and you will learn the small, careful set of tools (`nmap`, `masscan`, `naabu`) that produce a useful picture of a network without melting it. The hard, non-skippable lesson of the week is that running these tools against a host without authorization is a crime in most jurisdictions. The tools themselves are mundane; the discipline around when, where, against whom, and under what document you run them is the entire job.*

Welcome to Week 7 of **C6 · Cybersecurity Crunch**. Weeks 1 through 6 built the defensive side of the practitioner stack: the security mindset and Linux baseline, the network, the threat model, the OWASP Top 10 in Python, secure coding with the static-analysis toolchain, and PR-time code review. Week 7 is the first week in which you operate *on* a system rather than reading the code that runs on it. The tool list is short and the legal frame is long, and that ratio is deliberate. The purpose of this week is not to make you faster with `nmap`; it is to make you the kind of engineer who, when a director hands you an IP range and says "tell me what is out there," produces a written scope first and an output file second.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Every technique in this module is run against one of the           │
│  following, and nothing else:                                       │
│  - localhost (127.0.0.1) on a machine you own                       │
│  - a virtual machine you provisioned and own (Metasploitable,       │
│    a Kali lab, a vulnerable-by-design VM on your own hardware)      │
│  - a host range explicitly listed in a signed Rules-of-Engagement   │
│    document you hold, where the signature is from someone with      │
│    the authority to grant access (the owner of the host, the        │
│    CISO of the organisation, the bug bounty program's published     │
│    scope, etc.)                                                     │
│                                                                     │
│  Scanning a host that does not meet at least one of the three       │
│  conditions above is, in the United States, a violation of the      │
│  Computer Fraud and Abuse Act (18 U.S.C. § 1030); in the United     │
│  Kingdom, a violation of the Computer Misuse Act 1990; in the       │
│  European Union, a violation of Directive 2013/40/EU as             │
│  implemented in each member state. The penalties are real           │
│  (criminal prosecution, civil liability, professional               │
│  decertification) and the case law is settled.                      │
│                                                                     │
│  C6 does not teach crime. If you cannot point at the document       │
│  that authorises the scan, you do not run the scan.                 │
└─────────────────────────────────────────────────────────────────────┘
```

The banner appears on every page this week. Read it once carefully now; thereafter treat it as a contract. The exercises and the mini-project are written so you can complete every line of work without ever touching a host you do not own. The fallback target for every drill is the loopback interface on your own laptop or a vulnerable-by-design VM on your own hardware. If you ever feel uncertain about a target — *do not scan it* until you have written authorisation in your hand.

---

## Learning objectives

By the end of this week, you will be able to:

- **Write** a Rules-of-Engagement (RoE) document that meets the standard the major bug bounty platforms (HackerOne, Bugcrowd, Intigriti) and consultancies use: explicit in-scope and out-of-scope asset lists, explicit allowed and prohibited testing actions, explicit time windows, explicit point-of-contact for both sides, explicit emergency-stop procedure, explicit data-handling requirements, explicit deliverables and timeline.
- **Apply** the three primary legal frames a practitioner in the Anglosphere works under — the US **Computer Fraud and Abuse Act**, the UK **Computer Misuse Act 1990**, and the EU's **Directive 2013/40/EU** as transposed into national law — to a concrete decision about whether a given scan is authorised. Know the published **safe-harbor** clauses (e.g. the US DoJ's 2022 CFAA charging policy update; the EU **NIS2** vulnerability-disclosure provisions) and what they do and do not protect.
- **Distinguish** the major scanner families and pick the right one for the job: `nmap` for accurate, low-rate service detection with NSE plugins; `masscan` for very-fast TCP-SYN sweeps across enormous IP space; `naabu` for fast port discovery from the ProjectDiscovery toolchain; and *combinations* (`masscan` to find candidates, `nmap` to enrich them).
- **Run** the canonical `nmap` modes — TCP-SYN (`-sS`), TCP-connect (`-sT`), UDP (`-sU`), ping/host-discovery (`-sn`, `-Pn`), version-detection (`-sV`), OS-fingerprint (`-O`), default-script (`-sC`), and the targeted NSE categories (`--script vuln`, `--script safe`, `--script auth`) — and reason about which is appropriate for a given target, and which would generate too much traffic or too many alerts.
- **Operate** rate-limited and slow-and-steady. Reason about `--max-rate`, `--min-rate`, `-T0`..`-T5` (Paranoid through Insane), `--scan-delay`, `--host-timeout`, and `--max-retries`. Know what each does to packets-per-second on the wire, and what each costs in time. Know how to scan a network without bringing it down.
- **Interpret** scanner output formats and produce derived artifacts. Read normal text output (`-oN`), grepable output (`-oG`), and structured XML (`-oX`). Parse the XML with Python's `xml.etree.ElementTree` for an asset inventory, a CSV report, or a JSON-Lines stream into a SIEM.
- **Read** the canonical references as primary sources: the **Nmap Network Scanning** book (Lyon, the *nmap.org/book* free online edition), **RFC 793** (TCP), the **CISA / NSA scanning best-practice** guidance, the **OWASP Web Security Testing Guide** § 2.1-2.6, and the public **Bug Bounty Hunter's Methodology** talks (Jason Haddix). Each is free, primary, and recent enough to cite.
- **Triage** scan output the way a working consultant does: separate *informational* from *interesting* from *actionable*, write a one-page summary the client engineering lead can read in five minutes, and a longer technical appendix the client security lead can read in fifty.
- **Produce** a complete authorised-recon report on a host you own — a Rules-of-Engagement document, a scan plan, the scan execution log, the triaged findings list, and an executive summary — as the Week 7 portfolio artifact.

---

## Prerequisites

- **Weeks 1 through 6 completed.** You should be comfortable on a Linux command line, familiar with the OSI / TCP-IP layer model from Week 2, and able to read a threat model.
- **A Linux or macOS host where you have root.** Many `nmap` modes (`-sS`, `-O`, raw-IP scans) require `CAP_NET_RAW` / root. Windows works but the tooling story is rockier.
- **`nmap` installed.** Version 7.94 or later. Verify with `nmap --version`.
- **A virtual machine for offensive practice that you own.** Recommended: **Metasploitable 2** or **Metasploitable 3** (vulnerable-by-design Linux/Windows VMs published by Rapid7 for exactly this kind of education), or a **Kali Linux** VM bridged to a host-only network with the vulnerable VM. *Both VMs must be on a host-only or NAT-isolated network — never bridged to the LAN, never reachable from the public internet.*
- **`masscan` and `naabu` installed** (apt or brew). Optional for Exercise 2; required for Challenge 2 and the mini-project.
- **Python 3.11 with the standard library.** No third-party packages are required for the exercises. `xml.etree.ElementTree` is in the stdlib.
- **A bound notebook or a `notes/` directory.** Every scan you run this week is recorded: target, time, command line, expected duration, observed duration, output file, who authorised. The discipline starts now.

---

## Topics covered

- **The legal frame.** US CFAA, UK Computer Misuse Act 1990, EU Directive 2013/40/EU and NIS2, plus the safe-harbour clauses each carves out. The DoJ's **May 2022 CFAA Charging Policy** is the most-cited US clarification: good-faith security research is now *policy*-protected from federal prosecution under specified conditions. The conditions matter; we walk them in Lecture 1.
- **Rules of Engagement (RoE).** The signed document that converts "I have a target" into "I have authorisation." We walk the standard sections: scope (in/out), testing windows, allowed and prohibited techniques, escalation contacts, emergency-stop, data handling, deliverables, indemnification. We use the public **HackerOne policy template**, **Bugcrowd's "Standard Disclosure Terms,"** and the **PTES (Penetration Testing Execution Standard) Pre-Engagement** section as references.
- **Host discovery.** `nmap -sn` (ping sweep). ICMP echo, TCP-SYN to 443/80, ARP for local subnets, when each is appropriate. The `-Pn` flag (skip host discovery, assume up) and when it is necessary versus wasteful.
- **Port scanning.** TCP-SYN (`-sS`, the default for root) versus TCP-connect (`-sT`, the default unprivileged). UDP (`-sU`, slow and unreliable). The handful of less-used modes (`-sA`, `-sF`, `-sN`, `-sX`) and why most engagements never use them.
- **Service detection.** `-sV` (version probes) and what it costs in traffic; `-sC` (default scripts); the **NSE** (Nmap Scripting Engine) categories (`safe`, `default`, `discovery`, `version`, `vuln`, `auth`, `intrusive`, `exploit`, `dos`, `external`) and the rule of thumb that on a real engagement you run `safe` and `default` and only run `vuln` / `intrusive` with explicit RoE permission.
- **OS fingerprinting.** `-O`, what TCP/IP-stack signals it reads, what its accuracy is, when to trust it and when not to.
- **Rate limits and the "did we crash production?" problem.** `--max-rate`, `--min-rate`, `-T0` through `-T5`, `--scan-delay`, `--max-retries`, `--host-timeout`. The `masscan` rate parameter and the *why* of "we never let it default to a million packets per second on a production network." A separate section on how IDS / IPS / WAF systems alert on common scan signatures, and why the RoE should explicitly tell you whether to *avoid* tripping them or to *deliberately* trip them.
- **`masscan`, `naabu`, and the speed/accuracy trade.** `masscan` for huge IP space at hundreds of kpps with an independent TCP stack; `naabu` from ProjectDiscovery for medium-scale modern asynchronous scans with a friendlier output pipeline; `nmap` for the careful, accurate, NSE-enriched follow-up.
- **Output formats and parsing.** `-oN` (normal), `-oG` (grepable, deprecated but still used), `-oX` (XML, the right format for programmatic parsing). Python's `xml.etree.ElementTree` against `-oX`. Producing an asset inventory CSV / a JSON-Lines feed / a Markdown summary.
- **The recon report.** Cover page, scope, methodology, summary of findings, detailed findings, command-log appendix, raw-output appendix. The shape Trail of Bits, NCC, and the major consultancies use; you produce one this week at portfolio scale.

---

## Weekly schedule

The schedule below adds up to approximately **36 hours**. Treat it as a target.

| Day       | Focus                                                         | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Self-Study | Daily Total |
|-----------|---------------------------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|-----------:|------------:|
| Monday    | L1 — Rules of Engagement and the legal frame                  |    2h    |    1h     |     0h     |    0.5h   |   1h     |     0h       |    1h      |    5.5h     |
| Tuesday   | L2 — Host discovery and port scanning                         |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |    5.5h     |
| Wednesday | L3 — Service detection, NSE, and fingerprinting               |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0.5h     |    0.5h    |    6h       |
| Thursday  | Exercises polished; challenge launch                          |    0h    |    2h     |     1.5h   |    0.5h   |   1h     |     1h       |    0.5h    |    6.5h     |
| Friday    | Mini-project: write the RoE, build the scan plan              |    0h    |    1h     |     0.5h   |    0.5h   |   1h     |     2h       |    0.5h    |    5.5h     |
| Saturday  | Mini-project: execute, triage, write the report               |    0h    |    0h     |     0h     |    0h     |   1h     |     3h       |    0h      |    4h       |
| Sunday    | Quiz, review, polish, push                                    |    0h    |    0h     |     0h     |    0.5h   |   0h     |     0h       |    1h      |    1.5h     |
| **Total** |                                                               | **6h**   | **7h**    | **2h**     | **3h**    | **6h**   |   **6.5h**   |   **4h**   |  **34.5h**  |

---

## How to navigate this week

| File | What's inside |
|------|---------------|
| [README.md](./README.md) | This overview (you are here) |
| [resources.md](./resources.md) | Free primary sources — nmap.org book, RFCs, CISA guidance, OWASP WSTG, HackerOne / Bugcrowd / Intigriti policy templates, Haddix recon talks |
| [lecture-notes/01-rules-of-engagement-and-scope.md](./lecture-notes/01-rules-of-engagement-and-scope.md) | The legal frame, the RoE document, the authorisation chain, the emergency-stop procedure |
| [lecture-notes/02-host-discovery-and-port-scanning.md](./lecture-notes/02-host-discovery-and-port-scanning.md) | `-sn`, `-Pn`, `-sS` vs `-sT`, `-sU`, rate limits, the TCP three-way handshake, RFC 793 reminders |
| [lecture-notes/03-service-detection-and-fingerprinting.md](./lecture-notes/03-service-detection-and-fingerprinting.md) | `-sV`, `-sC`, the NSE categories, OS fingerprint accuracy, output formats |
| [exercises/exercise-01-scan-your-own-host.md](./exercises/exercise-01-scan-your-own-host.md) | Loopback and own-VM scan — the safe sandbox |
| [exercises/exercise-02-nse-scripts-on-vulnerable-vm.md](./exercises/exercise-02-nse-scripts-on-vulnerable-vm.md) | NSE script categories against an intentionally-vulnerable VM you own |
| [exercises/exercise-03-output-parsing-with-python.py](./exercises/exercise-03-output-parsing-with-python.py) | Parse `nmap -oX` output with `xml.etree.ElementTree`; runnable, compiles clean |
| [exercises/SOLUTIONS.md](./exercises/SOLUTIONS.md) | Worked solutions and discussion |
| [challenges/challenge-01-write-a-recon-runbook.md](./challenges/challenge-01-write-a-recon-runbook.md) | Write a portable recon runbook your future self can hand to a junior |
| [challenges/challenge-02-build-an-asset-inventory-script.py](./challenges/challenge-02-build-an-asset-inventory-script.py) | Build an asset-inventory CSV from multiple nmap XML outputs |
| [quiz.md](./quiz.md) | 10 questions on legality, scan-type trade-offs, and rate limits |
| [homework.md](./homework.md) | Six problems, ~6 hours total |
| [mini-project/README.md](./mini-project/README.md) | Full authorised-recon report on a host you own — the Week 7 portfolio artifact |

---

## Stretch goals

If you finish early, push further:

- Read the **full Nmap Network Scanning book** (Gordon Lyon, free at <https://nmap.org/book/>). At ~480 pages, it is a textbook; chapters 5-12 are the operationally important ones.
- Build a **Vagrant or Terraform lab** with three networks (red, blue, lab) and stand up Metasploitable, a Kali workstation, and a target Ubuntu host in the lab network. Run all this week's exercises against the lab. Commit the IaC files to your portfolio.
- Read the **CISA Scanning Best Practices** guidance (CISA's `MAR-10454006` and related joint advisories on adversary scanning behaviour) and write a one-page document mapping your own scan-rate choices to the *defender's* view of those scans.
- Read **three Trail of Bits or NCC Group external-recon engagement methodologies** (the *recon* sections, not the full reports) and compare to your own runbook from Challenge 1. Where their method is more disciplined, update your runbook.
- Replicate the **Jason Haddix "Bug Bounty Hunter's Methodology"** v4 talks' recon stack on a target you own. The *subdomain enumeration* step in particular (`amass`, `subfinder`, `assetfinder`) deserves its own afternoon.
- Sit in (read-only) on a public bug bounty program's published scope (HackerOne's public programs, Bugcrowd's public list). Read ten consecutive scope documents and note how each carves the boundary between in-scope and out-of-scope.
- Write a **`-oX` to SIEM** adapter — your asset-inventory script from Challenge 2 extended to emit JSON-Lines into Elastic / Splunk / OpenSearch in a shape an alerting rule could consume. This is the form of the script that lives in production at most consultancies.

---

## Up next

Continue to [Week 8 — Vulnerability Assessment and Reporting](../week-08/) once your mini-project recon report is pushed and your portfolio README links to all seven weeks. Week 8 picks up where Week 7 stops: you have a list of services on a host you own; now you triage them against a vulnerability database, validate each candidate finding by hand, and write the report that a remediation team can actually fix.

---

*Found an error? Open an issue or send a PR. The next learner will thank you.*
