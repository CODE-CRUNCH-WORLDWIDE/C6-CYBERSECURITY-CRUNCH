# Week 9 — Resources

Every resource here is **free** and, where possible, a primary source. The reading priority for this week is unusually clear: NIST SP 800-61 Rev. 2 is the spine; MITRE ATT&CK is the mapping vocabulary; SANS DFIR's free reading-room papers are the practitioner depth; the canonical tool documentation is the operational reference. Read the primary materials on each phase before you run the corresponding exercise, and re-read NIST SP 800-61 § 3.2.5 (lessons-learned) before you write the mini-project's post-incident report.

```
+---------------------------------------------------------------------+
|  AUTHORIZED INVESTIGATION ONLY                                      |
|                                                                     |
|  The procedures and tools referenced below are run only against:    |
|  - the simulated artefacts bundled with this week's mini-project    |
|    starter directory, OR                                            |
|  - hosts you personally own and administer, OR                      |
|  - hosts on which you hold a current, written, signed investigation |
|    authorisation from the system's owner.                           |
|                                                                     |
|  Reading about a memory-acquisition workflow is legal everywhere.   |
|  Running the same workflow against a host you are not authorised    |
|  to investigate is a crime in nearly every jurisdiction. The        |
|  reading list below assumes you know the difference.                |
+---------------------------------------------------------------------+
```

---

## Primary — NIST SP 800-61 Rev. 2 (the spine of the week)

The *Computer Security Incident Handling Guide* from the National Institute of Standards and Technology, revision 2 (August 2012, the current revision as of May 2026). The four-phase lifecycle in 800-61 is the vocabulary every regulated industry's IR runbook is written in. Read in full.

- **NIST SP 800-61 Rev. 2 landing page (free PDF):** <https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final>.
- **Direct PDF link:** <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf> (79 pages).
- **NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response*:** <https://csrc.nist.gov/publications/detail/sp/800-86/final> — the deep technical companion to 800-61. Read § 5 (data collection) and § 6 (data examination) in full this week.
- **NIST SP 800-184 — *Guide for Cybersecurity Event Recovery*:** <https://csrc.nist.gov/publications/detail/sp/800-184/final> — the dedicated guide for the *recovery* phase of 800-61.
- **NIST SP 800-150 — *Guide to Cyber Threat Information Sharing*:** <https://csrc.nist.gov/publications/detail/sp/800-150/final> — the right doctrine for the IOC-sharing element of post-incident activity.

### Sections of 800-61 to read before each lecture

- Before L1: **§ 2 — Organising a Computer Security Incident Response Capability** and **§ 3.1 — Preparation**. Roughly 25 pages, 60-75 minutes.
- Before L2: **§ 3.2 — Detection and Analysis** and the *signs of an incident* tables in § 3.2.2. Roughly 15 pages, 30-45 minutes.
- Before L3: **§ 3.3 — Containment, Eradication, and Recovery** and **§ 3.4 — Post-Incident Activity**. Roughly 15 pages, 30-45 minutes.

The remaining pages (appendices: handling scenarios, recommendations) make excellent stretch reading.

---

## Primary — MITRE ATT&CK (the mapping vocabulary)

MITRE ATT&CK is the standard taxonomy for adversary technique mapping. The mini-project requires every observed event in the timeline to be tagged with at least one ATT&CK technique ID. The framework is free, primary, and updated continually.

- **MITRE ATT&CK root:** <https://attack.mitre.org/>.
- **Enterprise matrix (the relevant matrix for this week):** <https://attack.mitre.org/matrices/enterprise/>.
- **Linux platform sub-matrix:** <https://attack.mitre.org/matrices/enterprise/linux/>.
- **The tactics index** (the column headers in the matrix — Initial Access, Execution, Persistence, ...): <https://attack.mitre.org/tactics/enterprise/>.
- **Techniques listed by tactic:** the columns in the enterprise matrix linked above each enumerate their techniques.
- **MITRE Engenuity ATT&CK Evaluations** (free evaluations of detection products against known threat groups; useful for understanding how techniques appear in real telemetry): <https://attackevals.mitre-engenuity.org/>.

### Techniques most relevant to this week's lab

The simulated intruder in `mini-project/starter/` exercises the following techniques. Every one of them has a free page on the ATT&CK site with sub-techniques, detections, and mitigations. Read each before tagging it in the report.

- **T1078 — Valid Accounts:** <https://attack.mitre.org/techniques/T1078/>.
- **T1190 — Exploit Public-Facing Application:** <https://attack.mitre.org/techniques/T1190/>.
- **T1059 — Command and Scripting Interpreter:** <https://attack.mitre.org/techniques/T1059/> and the Bash sub-technique **T1059.004** at <https://attack.mitre.org/techniques/T1059/004/>.
- **T1098 — Account Manipulation:** <https://attack.mitre.org/techniques/T1098/>.
- **T1136 — Create Account:** <https://attack.mitre.org/techniques/T1136/> (local sub-technique **T1136.001** at <https://attack.mitre.org/techniques/T1136/001/>).
- **T1543 — Create or Modify System Process:** <https://attack.mitre.org/techniques/T1543/> (systemd sub-technique **T1543.002** at <https://attack.mitre.org/techniques/T1543/002/>).
- **T1548 — Abuse Elevation Control Mechanism:** <https://attack.mitre.org/techniques/T1548/> (sudo/sudo-cache sub-technique **T1548.003** at <https://attack.mitre.org/techniques/T1548/003/>).
- **T1068 — Exploitation for Privilege Escalation:** <https://attack.mitre.org/techniques/T1068/>.
- **T1070 — Indicator Removal:** <https://attack.mitre.org/techniques/T1070/> (clear command history **T1070.003** at <https://attack.mitre.org/techniques/T1070/003/>; file deletion **T1070.004** at <https://attack.mitre.org/techniques/T1070/004/>).
- **T1057 — Process Discovery:** <https://attack.mitre.org/techniques/T1057/>.
- **T1003 — OS Credential Dumping:** <https://attack.mitre.org/techniques/T1003/> (`/etc/shadow` sub-technique **T1003.008** at <https://attack.mitre.org/techniques/T1003/008/>).
- **T1021 — Remote Services:** <https://attack.mitre.org/techniques/T1021/> (SSH sub-technique **T1021.004** at <https://attack.mitre.org/techniques/T1021/004/>).
- **T1005 — Data from Local System:** <https://attack.mitre.org/techniques/T1005/>.
- **T1041 — Exfiltration Over C2 Channel:** <https://attack.mitre.org/techniques/T1041/>.

---

## Primary — Linux logging and audit tooling

The canonical references for the log sources you will read this week. Pick up the man pages first; they are short and authoritative.

### journalctl and the systemd journal

- **`journalctl(1)` manual:** <https://man7.org/linux/man-pages/man1/journalctl.1.html>. Read in full; under 20 pages of dense flag reference. The flags that matter most for IR: `-u UNIT`, `--since`, `--until`, `-o short-iso` and `-o json`, `--no-pager`, `-x` (verbose explanations of catalogued messages), `-k` (kernel ring buffer).
- **`systemd-journald.service(8)`:** <https://man7.org/linux/man-pages/man8/systemd-journald.service.8.html> — the daemon that writes the journal.
- **`journald.conf(5)`:** <https://man7.org/linux/man-pages/man5/journald.conf.5.html> — retention, storage location, persistence configuration.
- **Lennart Poettering's *systemd for Administrators* — Part XVII: Using the Journal:** <https://0pointer.de/blog/projects/journalctl.html> — the original walkthrough; still accurate for current systemd.

### /var/log files (the pre-journald world, still everywhere)

- **`auth.log` and `secure`:** the rsyslog default routes for PAM and SSH messages; documented in the rsyslog defaults at `/etc/rsyslog.d/50-default.conf` (Debian/Ubuntu).
- **`rsyslog.conf(5)`:** <https://man7.org/linux/man-pages/man5/rsyslog.conf.5.html> — the syslog daemon's configuration.
- **`logger(1)`:** <https://man7.org/linux/man-pages/man1/logger.1.html> — how to write entries from the shell (used in our exercises to simulate events).
- **`last(1)`:** <https://man7.org/linux/man-pages/man1/last.1.html> — wtmp / btmp reader.
- **`who(1)` and `w(1)`:** <https://man7.org/linux/man-pages/man1/who.1.html> and <https://man7.org/linux/man-pages/man1/w.1.1.html>.
- **`lastcomm(1)` and the `acct(5)` accounting framework:** <https://man7.org/linux/man-pages/man1/lastcomm.1.html> — process accounting; off by default on most distros but worth knowing.

### auditd (the Linux Audit framework)

- **`auditd(8)`:** <https://man7.org/linux/man-pages/man8/auditd.8.html>.
- **`auditctl(8)` (the rule-loading CLI):** <https://man7.org/linux/man-pages/man8/auditctl.8.html>.
- **`ausearch(8)` (the canonical reader):** <https://man7.org/linux/man-pages/man8/ausearch.8.html>.
- **`aureport(8)`:** <https://man7.org/linux/man-pages/man8/aureport.8.html>.
- **Linux Audit System project:** <https://github.com/linux-audit/audit-documentation> — official documentation tree.
- **Florian Roth's `auditd-attack` ruleset (free, MITRE ATT&CK-aligned):** <https://github.com/Neo23x0/auditd-attack>.

### Filesystem timeline

- **`find(1)`:** <https://man7.org/linux/man-pages/man1/find.1.html> — `find -newer`, `-mtime`, `-ctime`, `-atime`, `-printf '%T@ %p\n'` for machine-readable timestamps.
- **`stat(1)`:** <https://man7.org/linux/man-pages/man1/stat.1.html> — reads atime/mtime/ctime; understand each field and which can be forged.
- **`touch(1)`:** <https://man7.org/linux/man-pages/man1/touch.1.html> — the canonical timestamp-rewriting tool; an attacker's friend.
- **`debugfs(8)`** (ext2/3/4 lower-level inspection): <https://man7.org/linux/man-pages/man8/debugfs.8.html>.

---

## Primary — web-server log formats and triage

- **`nginx` `combined` log format reference:** <https://nginx.org/en/docs/http/ngx_http_log_module.html>.
- **`apache` `combined` log format reference:** <https://httpd.apache.org/docs/current/logs.html#combined>.
- **OWASP Logging Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>.
- **OWASP Application Logging Vocabulary:** <https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html>.
- **SANS *Detecting Common Web Server Attacks Using Logs*:** <https://www.sans.org/white-papers/40197/> (search the SANS reading room for the latest version if the slug rotates).

---

## Primary — Sysmon (Windows awareness)

Sysmon is the canonical Windows endpoint telemetry source. The depth is owed to a Windows course; the awareness is owed to this one.

- **Sysmon download and documentation (Microsoft Sysinternals):** <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>.
- **Sysmon event ID reference (Microsoft Learn):** <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-creation> — the page anchors each event ID; scroll for IDs 1, 3, 7, 11.
- **SwiftOnSecurity's `sysmon-config`** (the most-cited free starter configuration): <https://github.com/SwiftOnSecurity/sysmon-config>.
- **Olaf Hartong's `sysmon-modular`** (the MITRE ATT&CK-mapped modular config): <https://github.com/olafhartong/sysmon-modular>.
- **Florian Roth's *Sysmon Threat Intel Feed*:** <https://github.com/Neo23x0/sigma> — Sigma rules, many keyed to Sysmon event IDs.

The four event IDs to memorise this week:

- **Event ID 1 — Process Creation.** Every new process; includes the full command line, parent process, image path, and hashes.
- **Event ID 3 — Network Connection.** Every outbound (and inbound, if so configured) connection.
- **Event ID 7 — Image Loaded.** Every DLL or image loaded into a process; the canonical source for catching DLL side-loading.
- **Event ID 11 — File Created.** Every file created on disk; the canonical source for catching dropped payloads.

---

## Primary — memory acquisition tools

The two free, primary tools used in this week's exercises and the canonical analysis framework.

### LiME (Linux Memory Extractor)

- **LiME repository:** <https://github.com/504ensicsLabs/LiME>.
- **LiME paper (the original 2011 paper by Joe Sylve et al., still the canonical reference):** <https://github.com/504ensicsLabs/LiME/raw/master/doc/lime_thesis.pdf>.
- **Building LiME against a target kernel:** the project README's "Installation" section; the canonical pitfall is that the kernel module must be built against headers matching the target kernel.

### AVML (Acquire Volatile Memory for Linux)

- **AVML repository (Microsoft, MIT-licensed):** <https://github.com/microsoft/avml>.
- **Pre-built static binaries** for major Linux platforms are published on the releases page: <https://github.com/microsoft/avml/releases>.
- **AVML usage walkthrough on the Microsoft Security blog:** <https://www.microsoft.com/en-us/security/blog/2020/01/30/avml-the-quest-for-volatile-data-acquisition-on-linux/>.

### Volatility 3 (the analysis framework)

- **Volatility 3 root:** <https://www.volatilityfoundation.org/>.
- **Volatility 3 documentation:** <https://volatility3.readthedocs.io/>.
- **Volatility 3 GitHub:** <https://github.com/volatilityfoundation/volatility3>.
- **Plugins used most for Linux triage:** `linux.pslist`, `linux.pstree`, `linux.bash` (recovers bash history from process memory even after `~/.bash_history` is wiped), `linux.netstat`, `linux.lsof`, `linux.malfind`. The plugin index is in the Volatility 3 docs.

### Order of volatility (RFC 3227)

- **RFC 3227 — *Guidelines for Evidence Collection and Archiving*:** <https://datatracker.ietf.org/doc/html/rfc3227>. Read in full; it is short. The order-of-volatility list in § 2.1 is the basis for every acquisition decision.

---

## Primary — chain of custody and forensic readiness

- **NIST SP 800-86 § 5 — *Data Collection*:** the chain-of-custody guidance is in 800-86 because it is the technical-companion document to 800-61. Linked above.
- **ENISA — *Good Practice Guide for Incident Management*:** <https://www.enisa.europa.eu/publications/good-practice-guide-for-incident-management> — the European Union counterpart to NIST SP 800-61; chain-of-custody coverage in the *Forensic Readiness* section.
- **ISO/IEC 27037:2012 — *Guidelines for identification, collection, acquisition and preservation of digital evidence*:** ISO standards are not free, but the abstract and table of contents are at <https://www.iso.org/standard/44381.html>. For free coverage of the same material, read NIST SP 800-86 and ENISA's guide instead.

---

## Primary — incident-response runbooks and playbooks (free, government and community)

- **CISA — *Federal Government Cybersecurity Incident and Vulnerability Response Playbooks* (November 2021):** <https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf>. The model federal IR playbook.
- **CISA Known Exploited Vulnerabilities (KEV) catalogue:** <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>. Cross-reference every CVE you cite as a likely root cause against KEV.
- **CISA Incident Reporting System:** <https://www.cisa.gov/report> — where US organisations report incidents to the government.
- **FIRST.org Common Vulnerability Scoring System (CVSS) v4.0:** <https://www.first.org/cvss/v4.0/> — the standard severity-scoring system the post-incident report cites.
- **Carnegie Mellon SEI CERT — *Defining Computer Security Incident Response Teams*:** <https://insights.sei.cmu.edu/library/defining-computer-security-incident-response-teams/>.

---

## Primary — SANS DFIR free reading room

SANS sells courses but publishes a substantial free reading room. The papers below are free to download (no registration required for direct PDF links in most cases; some require a free SANS account).

- **SANS Reading Room — Incident Response category:** <https://www.sans.org/white-papers/?focus-area=incident-response>.
- **SANS Reading Room — Digital Forensics category:** <https://www.sans.org/white-papers/?focus-area=digital-forensics>.
- **SANS DFIR posters (all free):** <https://www.sans.org/posters/?focus-area=digital-forensics>.
  - **Hunt Evil — Process Investigation:** <https://www.sans.org/posters/hunt-evil/>.
  - **Linux Shell Survival Guide:** <https://www.sans.org/posters/linux-shell-survival-guide/>.
  - **Windows Forensic Analysis** (cross-reference for the Sysmon awareness section): <https://www.sans.org/posters/windows-forensic-analysis/>.
- **SANS *Internet Storm Center* daily diaries:** <https://isc.sans.edu/diary.html> — practitioner journal; many entries are short post-incident walkthroughs of real cases.

---

## Primary — log-format and timestamp standards

- **ISO 8601 — Date and time format:** <https://www.iso.org/iso-8601-date-and-time-format.html>. Mini-project requires all timestamps in ISO 8601 UTC (`2026-05-14T19:30:00Z`); read the abstract.
- **RFC 3339 — *Date and Time on the Internet: Timestamps*:** <https://datatracker.ietf.org/doc/html/rfc3339>. The internet-engineering subset of ISO 8601; what most log libraries actually emit. Free.
- **RFC 5424 — *The Syslog Protocol*:** <https://datatracker.ietf.org/doc/html/rfc5424>. The current syslog standard.
- **OWASP Application Logging Vocabulary** (linked above) — the canonical vocabulary for security-relevant log entries from an application.

---

## Primary — Python references for the exercise scripts

The exercise scripts use only the Python standard library plus, optionally, `requests`. The references below are the canonical docs for each module used.

- **`argparse`:** <https://docs.python.org/3/library/argparse.html>.
- **`pathlib`:** <https://docs.python.org/3/library/pathlib.html>.
- **`hashlib`:** <https://docs.python.org/3/library/hashlib.html>.
- **`subprocess`:** <https://docs.python.org/3/library/subprocess.html>.
- **`datetime` and `zoneinfo`:** <https://docs.python.org/3/library/datetime.html> and <https://docs.python.org/3/library/zoneinfo.html>.
- **`re`:** <https://docs.python.org/3/library/re.html>.
- **`json`:** <https://docs.python.org/3/library/json.html>.
- **`csv`:** <https://docs.python.org/3/library/csv.html>.
- **`collections.Counter`:** <https://docs.python.org/3/library/collections.html#collections.Counter>.
- **`logging`:** <https://docs.python.org/3/library/logging.html>.

---

## Primary — legal frame (the same statutes from Weeks 7 and 8, restated)

Authorised acquisition is the same legal question as authorised reconnaissance and authorised exploitation — only the technical posture differs. The statutes that governed Weeks 7 and 8 govern Week 9 in exactly the same way.

- **18 U.S.C. § 1030 — Computer Fraud and Abuse Act:** <https://www.law.cornell.edu/uscode/text/18/1030>.
- **18 U.S.C. § 2701 — Unlawful Access to Stored Communications:** <https://www.law.cornell.edu/uscode/text/18/2701>. The SCA is the statute most often invoked when log or memory data containing stored communications is accessed without authority.
- **Computer Misuse Act 1990 (UK):** <https://www.legislation.gov.uk/ukpga/1990/18/contents>.
- **Directive 2013/40/EU:** <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32013L0040>.
- **GDPR (Regulation (EU) 2016/679) — Article 33 (notification of personal data breach to the supervisory authority) and Article 34 (communication to the data subject):** <https://eur-lex.europa.eu/eli/reg/2016/679/oj>. Read Articles 33 and 34 in full; they drive much of the *post-incident activity* phase for EU-touching organisations.
- **DoJ May 2022 charging-policy update (CFAA):** <https://www.justice.gov/opa/pr/department-justice-announces-new-policy-charging-cases-under-computer-fraud-and-abuse-act>.

Acquiring memory from a host you do not own is a CFAA / SCA / CMA / 2013/40/EU violation regardless of intent. Acquiring memory from your own laptop, or from the simulated artefacts in this directory, is the exercise.

---

## Secondary — practitioner notebooks and write-ups

These are useful supplements but should be read *after* the primary references above, not before.

- **Eric Zimmerman's tools** (Windows-focussed but the documentation is excellent for understanding what artefacts exist): <https://ericzimmerman.github.io/>.
- **The SANS Internet Storm Center daily diary** (linked above) — practitioner case studies, often a Linux box.
- **The Honeynet Project archives:** <https://www.honeynet.org/challenges/> — annotated incident artefacts dating back to 2001. The older ones are now historical curiosities; the techniques on display are still instructive.
- **DFIR Report** (free, weekly intrusion write-ups): <https://thedfirreport.com/>.

---

## Supporting — references for the report and the mini-project

- **GitHub Flavored Markdown spec:** <https://github.github.com/gfm/> — for the report template.
- **YAML 1.2 spec:** <https://yaml.org/spec/1.2.2/> — IOC files are often shared as YAML in MISP/STIX shape.
- **STIX 2.1 (the canonical IOC-sharing format):** <https://oasis-open.github.io/cti-documentation/stix/intro> — the mini-project's IOC export is a simplified STIX-flavoured JSON.
- **MISP (open-source threat-intel sharing platform):** <https://www.misp-project.org/> — the platform that consumes STIX-shaped feeds.

---

## How to choose what to read this week

You cannot read every linked resource in the seven days of Week 9. The recommended budget is:

1. **NIST SP 800-61 Rev. 2 § 2 and § 3** (the four-phase lifecycle in full). Read before L1. Roughly 90 minutes.
2. **The MITRE ATT&CK technique pages for every technique listed in this resources file's "Techniques most relevant to this week's lab" section.** Read before L2 and L3. Roughly 90 minutes.
3. **`journalctl(1)`, `last(1)`, `find(1)`, and `stat(1)` man pages** in full. Read before Exercise 2. Roughly 60 minutes.
4. **RFC 3227 (order of volatility) in full.** Read before L3. Roughly 15 minutes.
5. **The LiME README and the AVML README in full.** Read before Challenge 2. Roughly 45 minutes.
6. **NIST SP 800-86 § 5 and § 6** for the chain-of-custody guidance. Read before the mini-project. Roughly 60 minutes.
7. **One SANS DFIR poster (the Linux Shell Survival Guide is the most directly relevant).** Read once for orientation. Roughly 30 minutes.
8. **Skim the rest** as you need them during the exercises and mini-project.

Total reading budget: roughly 7-9 hours, spread across Mon-Wed. The exercises and the mini-project consume the remainder of the week.
