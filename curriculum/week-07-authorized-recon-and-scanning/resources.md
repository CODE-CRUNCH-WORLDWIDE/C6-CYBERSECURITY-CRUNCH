# Week 7 — Resources

Every resource here is **free** and, where possible, a primary source. This week is the *legality- and methodology-heavy* week; you will read more contractual documents (RoE templates, bug bounty terms, statute text) and more methodology documents (Nmap book chapters, OWASP WSTG, Haddix recon talks) than you will run scans. Read the primary materials first; the secondary commentary is supporting only.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The tools and techniques referenced below are run only against:    │
│  - hosts you own, or                                                │
│  - hosts explicitly named in a signed Rules-of-Engagement           │
│    document, or                                                     │
│  - hosts inside a published bug bounty scope you have read in       │
│    full and agreed to.                                              │
│                                                                     │
│  Reading about a tool is legal everywhere. Using a tool against     │
│  a system you are not authorised to touch is a crime in nearly      │
│  every jurisdiction. The reading list below assumes you know the    │
│  difference.                                                        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Primary — the canonical Nmap reference

`nmap` is the keystone tool of this week, and its author (Gordon Lyon, "Fyodor") wrote the canonical reference book and released it free online.

- **Nmap Network Scanning, Lyon (2011, with continual online updates):** <https://nmap.org/book/> — the entire book is free, well-organised, and current. Chapters 5 (Port Scanning Techniques), 6 (Optimizing Nmap Performance), 7 (Service and Application Version Detection), 8 (Remote OS Detection), 9 (NSE), 10 (Detecting Defenses), and 15 (Nmap Reference Guide) are the operationally important ones.
- **Nmap reference guide (man-page equivalent):** <https://nmap.org/book/man.html> — also shipped as `man nmap`. The flag list is canonical.
- **NSE script database:** <https://nmap.org/nsedoc/> — every NSE script, with description, categories, usage examples, and known limitations. Browse by category: `safe`, `default`, `discovery`, `version`, `vuln`, `auth`, `intrusive`, `exploit`, `dos`, `external`.
- **Nmap changelog:** <https://nmap.org/changelog.html> — read the recent entries; capabilities and defaults shift over releases.

---

## Primary — RFCs and protocol references

The scanner is a generator of carefully shaped network packets. Understanding the protocol it is exercising is what separates the practitioner from the script-runner.

- **RFC 793 — Transmission Control Protocol (1981):** <https://www.rfc-editor.org/rfc/rfc793> — the original TCP specification. Section 3.4 (Establishing a connection) and 3.5 (Closing a connection) are the entire foundation for what `-sS` is doing. Section 3.9 (Event Processing) defines what a stack does when it receives a SYN to a closed port.
- **RFC 9293 — Transmission Control Protocol (2022):** <https://www.rfc-editor.org/rfc/rfc9293> — the modern consolidated TCP RFC. Replaces RFC 793 formally and folds in dozens of clarifications. Read alongside RFC 793; cite RFC 9293 in modern documents.
- **RFC 791 — Internet Protocol:** <https://www.rfc-editor.org/rfc/rfc791> — the IPv4 header is what `nmap -O` is fingerprinting. Sections 3.1 and 3.2.
- **RFC 768 — User Datagram Protocol:** <https://www.rfc-editor.org/rfc/rfc768> — short, important. UDP scans are slow and unreliable precisely because UDP has no handshake; this RFC tells you why.
- **RFC 792 — Internet Control Message Protocol:** <https://www.rfc-editor.org/rfc/rfc792> — ICMP. `nmap -sn` host discovery rests on ICMP echo (type 8) and the various unreachable codes.
- **RFC 4949 — Internet Security Glossary v2:** <https://www.rfc-editor.org/rfc/rfc4949> — the canonical vocabulary. Use the terms it defines in your reports; do not invent synonyms.

---

## Primary — alternative scanners

`nmap` is the default; the alternatives have specific use-cases.

- **masscan (Robert Graham):** <https://github.com/robertdavidgraham/masscan> — the README is short and contains the entire operational model. Read the section on rates ("Transmit rate"); it explains why `--rate 1000` is sensible and `--rate 1000000` is catastrophic.
- **naabu (ProjectDiscovery):** <https://github.com/projectdiscovery/naabu> — modern asynchronous port scanner with a small, modern feature set. ProjectDiscovery publish a documentation site at <https://docs.projectdiscovery.io/tools/naabu/overview>.
- **ZMap (University of Michigan):** <https://github.com/zmap/zmap> — academic single-port internet-wide scanner. Background: <https://zmap.io/>. Useful to know about; not used in this week's exercises.
- **RustScan:** <https://github.com/RustScan/RustScan> — a fast wrapper that uses `nmap` for the per-port enrichment step. Pleasant to use; not a replacement for understanding `nmap`.

---

## Primary — legal frame and safe-harbour

You must read at least the linked sections of two of the three primary statutes below, and the DoJ charging policy, before running a single scan beyond your own loopback.

### United States — Computer Fraud and Abuse Act

- **18 U.S.C. § 1030 — Computer Fraud and Abuse Act:** <https://www.law.cornell.edu/uscode/text/18/1030> — the statute. Subsection (a)(2) ("intentionally accesses a computer without authorization") and (a)(5) ("knowingly causes the transmission of a program, information, code, or command, and as a result of such conduct, intentionally causes damage without authorization") are the most-cited.
- **DoJ Justice Manual 9-48.000, *Computer Fraud (CFAA)*:** <https://www.justice.gov/jm/jm-9-48000-computer-fraud> — DoJ's published charging policy.
- **DoJ press release, May 19, 2022 — *Computer Crime and Intellectual Property Section Announces Charging Policy Change*:** <https://www.justice.gov/opa/pr/department-justice-announces-new-policy-charging-cases-under-computer-fraud-and-abuse-act> — the *good-faith security research* policy clarification. The associated charging-policy memo is linked from the press release.
- **EFF, *Vulnerability Reporting FAQ*:** <https://www.eff.org/issues/coders/vulnerability-reporting-faq> — practitioner-readable summary, well-maintained.
- ***Van Buren v. United States*, 593 U.S. ___ (2021):** <https://www.supremecourt.gov/opinions/20pdf/19-783_k53l.pdf> — the Supreme Court narrowed "exceeds authorized access." Read pages 1-10 of the opinion; the syllabus suffices.

### United Kingdom — Computer Misuse Act 1990

- **Computer Misuse Act 1990:** <https://www.legislation.gov.uk/ukpga/1990/18/contents> — sections 1 (unauthorised access), 2 (unauthorised access with intent), 3 (unauthorised acts impairing operation), and 3ZA (unauthorised acts causing or creating risk of serious damage).
- **CMA Review and Reform consultation (Home Office, 2023):** <https://www.gov.uk/government/consultations/computer-misuse-act-1990-consultation-and-response-to-call-for-information> — the active reform proceeding. The CyberUp campaign (industry effort for a statutory defence for security researchers) is the relevant practitioner-side coverage.

### European Union — Directive 2013/40/EU and NIS2

- **Directive 2013/40/EU on attacks against information systems:** <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32013L0040> — the EU framework that each member state has transposed into national criminal law. Articles 3-7 are the substantive criminal-law provisions.
- **Directive (EU) 2022/2555 — NIS2:** <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555> — the network-and-information-security directive. Article 12 (Coordinated vulnerability disclosure) and recitals 58-61 give the formal European frame for vulnerability disclosure.
- **ENISA, *Good Practice Guide on Vulnerability Disclosure*:** <https://www.enisa.europa.eu/publications/vulnerability-disclosure> — ENISA's practitioner-readable guidance.

### Other jurisdictions worth knowing

- **Canada — Criminal Code § 342.1 (Unauthorized use of computer):** <https://laws-lois.justice.gc.ca/eng/acts/c-46/section-342.1.html>.
- **Australia — Criminal Code Act 1995, Part 10.7 (Computer offences):** <https://www.legislation.gov.au/Details/C2024C00050>.
- **Germany — Strafgesetzbuch § 202a (Ausspähen von Daten) and § 202c (Vorbereiten des Ausspähens und Abfangens von Daten, the "Hackerparagraf"):** read the Bundesamt für Justiz English translations.

If you operate in another jurisdiction, find the equivalent statute *before* the exercises this week.

---

## Primary — methodology and testing guides

- **OWASP Web Security Testing Guide (WSTG):** <https://owasp.org/www-project-web-security-testing-guide/> — version 4.2 current as of writing. Chapter 2 (Information Gathering) and its subsections 2.1-2.10 are the matching OWASP coverage for this week. Free, primary, and the de-facto methodology reference.
- **PTES — Penetration Testing Execution Standard:** <http://www.pentest-standard.org/> — the standard the major consultancies' methodologies derive from. The *Pre-Engagement Interactions* section is the RoE skeleton you will copy and adapt.
- **OSSTMM (Open Source Security Testing Methodology Manual):** <https://www.isecom.org/OSSTMM.3.pdf> — older, denser, and more formal. Read for the *measurement* discipline (RAV scoring) more than the technical procedures.
- **MITRE ATT&CK — Reconnaissance tactic (TA0043):** <https://attack.mitre.org/tactics/TA0043/> — the canonical taxonomy for what an attacker (and an authorised tester) does at this phase, by technique.
- **NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment:** <https://csrc.nist.gov/publications/detail/sp/800-115/final> — the NIST methodology document. Section 5 (Target Identification and Analysis Techniques) covers this week's content.

---

## Primary — bug bounty platform policies and disclosure guidance

These platforms publish the document templates you will adapt for your own RoE.

- **HackerOne — Vulnerability Disclosure Guidelines:** <https://www.hackerone.com/disclosure-guidelines>.
- **HackerOne — Code of Conduct:** <https://www.hackerone.com/code-of-conduct>.
- **HackerOne — Internet Bug Bounty programme:** <https://hackerone.com/ibb> — read several recent disclosed reports to see the *register* of professional disclosure.
- **HackerOne — example public program scopes:** browse <https://hackerone.com/directory/programs> and read five program pages end-to-end.
- **Bugcrowd — Vulnerability Rating Taxonomy (VRT):** <https://bugcrowd.com/vulnerability-rating-taxonomy>.
- **Bugcrowd — Standard Disclosure Terms:** <https://www.bugcrowd.com/resources/glossary/standard-disclosure-terms/>.
- **Intigriti — Researcher Code of Conduct:** <https://www.intigriti.com/researcher-code-of-conduct>.
- **disclose.io:** <https://disclose.io/> — the open standard for safe-harbour disclosure language. Adopt the `disclose.io` template by default.
- **CERT/CC Guide to Coordinated Vulnerability Disclosure:** <https://vuls.cert.org/confluence/display/CVD>.

---

## Primary — CISA and government scanning guidance

- **CISA Binding Operational Directive 23-01 — *Improving Asset Visibility and Vulnerability Detection on Federal Networks*:** <https://www.cisa.gov/news-events/directives/bod-23-01-improving-asset-visibility-and-vulnerability-detection-federal-networks> — the federal civilian requirement to scan and inventory. Read the directive and the implementation guidance.
- **CISA *Stuff Off Search* (SOS) campaign:** <https://www.cisa.gov/SOS> — CISA's public guidance on reducing internet-exposed services. Useful background on the *attacker's* asset-discovery perspective.
- **CISA / NSA / FBI joint cybersecurity advisories:** <https://www.cisa.gov/news-events/cybersecurity-advisories> — many advisories include scanner signatures and IOCs. Read three or four to see what a *defender* sees when an authorised scanner is misconfigured.
- **NSA / CISA / FBI / Five-Eyes joint advisories on adversary TTPs:** the *Reconnaissance* sections of these (e.g. AA22-110A on Russian state-sponsored cyber actors) describe what an attacker's recon looks like on the wire. The shape is similar to authorised testing; the defender's job is to distinguish.

---

## Primary — recon methodology talks and write-ups

These talks are free, recorded, and frequently cited.

- **Jason Haddix — *The Bug Hunter's Methodology v4* (DEF CON / multiple conferences):** the v4.0 talk and the older v3 talk are both worth a watch. Search "Jason Haddix Bug Hunter's Methodology" on YouTube; he releases updated slides on his GitHub. Slides: <https://github.com/jhaddix/tbhm>.
- **Jason Haddix — recon tooling lists:** <https://github.com/jhaddix> — `domain` and `tbhm` repositories include the canonical recon-tool checklists.
- **NahamSec — Bug Bounty Recon talks and YouTube channel:** <https://www.youtube.com/@NahamSec> — the *Recon* playlist is high-signal, free, modern.
- **STÖK — *The Bug Bounty Recon Sneak Peek*:** YouTube; multiple conferences.
- **Daniel Miessler — *The Difference Between Bug Bounty and Pentesting*:** <https://danielmiessler.com/p/the-difference-between-pen-tests-and-bug-bounties/> — short, frames the engagement-types you will operate inside.

---

## Primary — vulnerable-by-design VMs to practise on (you own them, so it is fine)

Set up at least one of these on your own hardware, in a host-only network, before Exercise 2.

- **Metasploitable 2 / 3 (Rapid7):** <https://github.com/rapid7/metasploitable3> — the canonical vulnerable Linux/Windows VM. Maintained, well-documented, perfect for this week.
- **VulnHub:** <https://www.vulnhub.com/> — the catalogue of community-published vulnerable VMs. Each is a downloadable `.ova`.
- **DVWA (Damn Vulnerable Web Application):** <https://github.com/digininja/DVWA> — primarily a web-app target but it lives on a VM you can scan.
- **OWASP Juice Shop:** <https://owasp.org/www-project-juice-shop/> — same.
- **HackTheBox / TryHackMe:** <https://www.hackthebox.com/> and <https://tryhackme.com/> — *hosted* labs you have explicit permission to attack. Useful supplements to your own VMs; check the platform's terms of use for the scope and the rate-limit policy. The scope on these platforms is the platform's *published* in-bounds list; do not scan platform infrastructure.

---

## Secondary — tutorials and operator's notes

These are useful supplements but should be read *after* the primary references above, not before.

- **HackTricks (Carlos Polop):** <https://book.hacktricks.xyz/> — practitioner notebook. The `Pentesting Network` and `Pentesting Methodology` sections cover this week's content with extensive command-line examples.
- **PayloadsAllTheThings (swisskyrepo):** <https://github.com/swisskyrepo/PayloadsAllTheThings> — useful payload index; less relevant to Week 7 than to later weeks but worth bookmarking.
- **Daniel Miessler — *SecLists*:** <https://github.com/danielmiessler/SecLists> — wordlists. Useful for service-detection follow-up.
- **Offensive Security — *PWK Course notes excerpts*:** the public PWK syllabus is at <https://www.offsec.com/courses/pen-200/> — the syllabus alone is useful as a topic map.
- **Pentester's Promiscuous Notebook (PEN Notebook):** various community notebooks. Read with a sceptic's eye; quality varies.

---

## Supporting — references for the parsing and reporting work

- **Python `xml.etree.ElementTree`:** <https://docs.python.org/3/library/xml.etree.elementtree.html> — the stdlib module you will use against `nmap -oX` output in Exercise 3 and Challenge 2.
- **Python `csv`:** <https://docs.python.org/3/library/csv.html> — for the inventory CSV in Challenge 2.
- **Python `json`:** <https://docs.python.org/3/library/json.html> — for JSON-Lines output.
- **`jq`:** <https://stedolan.github.io/jq/manual/> — pipe JSON-Lines through `jq` to query the asset inventory from the command line.
- **CVE Program:** <https://www.cve.org/> — the database your scanner output is eventually mapped against.
- **NIST NVD:** <https://nvd.nist.gov/> — the National Vulnerability Database, the canonical CVE-with-CVSS feed.
- **CPE dictionary:** <https://nvd.nist.gov/products/cpe> — the Common Platform Enumeration vocabulary. `nmap`'s service detection emits CPE strings (e.g. `cpe:/a:openbsd:openssh:9.6p1`) you can resolve against NVD.

---

## How to choose what to read this week

You cannot read every linked resource in the seven days of Week 7. The recommended budget is:

1. **The Nmap book chapters 5, 6, 7, 9** (read in full; the rest is reference).
2. **One full statute** — CFAA for US learners; CMA for UK; the EU directive for EU. Read the sections cited above; skim the rest.
3. **The DoJ charging policy press release** if you are US-based.
4. **OWASP WSTG Chapter 2** (information gathering) in full.
5. **One bug bounty platform's full policy** (HackerOne is the most-used in writing).
6. **One Haddix recon talk** in full (the v4 slides if you cannot watch video).
7. **Skim the rest** as you need them during the exercises and mini-project.

Total reading budget: roughly 10-12 hours, spread across Mon-Wed. The exercises and the mini-project consume the remainder of the week.
