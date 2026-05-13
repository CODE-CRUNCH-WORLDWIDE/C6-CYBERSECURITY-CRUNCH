# Week 1 — Resources

Every resource here is **free** and **publicly accessible**. Most are primary sources — read them in preference to the summaries.

## Primary sources — read first

- **NIST SP 800-30 Rev. 1 — Guide for Conducting Risk Assessments** (the U.S. federal reference for what "risk assessment" formally means):
  <https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final>
- **NIST SP 800-53 Rev. 5 — Security and Privacy Controls** (the control catalog every compliance regime borrows from):
  <https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final>
- **NIST Cybersecurity Framework 2.0** (the "Identify / Protect / Detect / Respond / Recover / Govern" wheel):
  <https://www.nist.gov/cyberframework>
- **OWASP Threat Modeling Cheat Sheet**:
  <https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html>
- **OWASP Top 10 (2021 + 2025 candidate)** — you will revisit this all of Phase 2:
  <https://owasp.org/www-project-top-ten/>
- **MITRE ATT&CK** — the canonical taxonomy of real-world attacker techniques:
  <https://attack.mitre.org/>
- **The Linux man pages**, always. `man 7 capabilities`, `man 5 sudoers`, `man 1 chmod`, `man 5 passwd`, `man 7 namespaces`. Read them on your own machine.

## On threat modeling and the security mindset

- **Adam Shostack — "The Four Question Framework"** (the canonical short statement; free):
  <https://shostack.org/resources/threat-modeling>
- **Bruce Schneier — "The Security Mindset"** (free essay, 2008, still definitive):
  <https://www.schneier.com/blog/archives/2008/03/the_security_mi_1.html>
- **STRIDE — original Microsoft write-up** (archived; the original 1999 framing):
  <https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats>
- **The "Threat Modeling Manifesto"** (community statement; principles, not process):
  <https://www.threatmodelingmanifesto.org/>

## Linux security model — primary

- **`man 7 capabilities`** — the authoritative reference on POSIX capabilities. Read it.
- **`man 5 sudoers`** — sudo's configuration syntax. Read it before you edit `/etc/sudoers`.
- **`man 7 namespaces`** and **`man 7 cgroups`** — the kernel primitives under containers.
- **Linux Standard Base — Filesystem Hierarchy Standard (FHS)**:
  <https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html>
- **The Linux Kernel docs — security subsystem**:
  <https://www.kernel.org/doc/html/latest/security/index.html>
- **SELinux Project — User Resources**:
  <https://github.com/SELinuxProject/selinux-notebook/blob/main/src/toc.md>
- **AppArmor — official documentation**:
  <https://gitlab.com/apparmor/apparmor/-/wikis/Documentation>

## CVEs worth reading this week

- **CVE-2021-3156** ("Baron Samedit") — heap overflow in `sudoedit` reachable by any local user. A textbook lesson in why `setuid` is dangerous:
  <https://nvd.nist.gov/vuln/detail/CVE-2021-3156>
- **CVE-2022-0847** ("Dirty Pipe") — pipe buffer flaw allowing arbitrary file overwrite by unprivileged users. A reminder that the kernel is part of your trust boundary:
  <https://nvd.nist.gov/vuln/detail/CVE-2022-0847>
- **CVE-2019-14287** — `sudo` user-ID bypass via `-u#-1`. Small misconfig, big consequence:
  <https://nvd.nist.gov/vuln/detail/CVE-2019-14287>

## Free CTF sites and wargames (used throughout C6)

- **OverTheWire** — wargames in the SSH shell. Bandit is the entry-point series. We use it Week 1.
  <https://overthewire.org/wargames/>
- **picoCTF** — Carnegie Mellon's free, year-round CTF aimed at beginners through intermediates.
  <https://picoctf.org/>
- **TryHackMe** — guided rooms; free tier is generous.
  <https://tryhackme.com/>
- **Hack The Box** — the "starting point" tier is free. Used in Week 8.
  <https://www.hackthebox.com/>
- **VulnHub** — downloadable intentionally vulnerable VMs.
  <https://www.vulnhub.com/>
- **pwn.college** — free, deep OS / binary exploitation curriculum (graduate-grade).
  <https://pwn.college/>

## Free books and write-ups

- **"Computer Security: Art and Science" — Matt Bishop** (the standard textbook; chapters 1-3 are the conceptual foundation. The first edition is widely available in libraries.)
- **"The Linux Hardening Guide" — Madaidan** (opinionated but specific; treat as one perspective):
  <https://madaidans-insecurities.github.io/guides/linux-hardening.html>
- **CIS Benchmarks** — concrete hardening checklists; free for non-commercial use:
  <https://www.cisecurity.org/cis-benchmarks>
- **The Phrack archive** — the historical record of how attackers thought; read responsibly, defensively:
  <http://www.phrack.org/>

## Tools you will use this week

- `chmod`, `chown`, `ls -l` — file permission basics
- `find / -perm -4000 -type f 2>/dev/null` — list all `setuid` binaries
- `getcap`, `setcap`, `getpcaps` — POSIX capabilities
- `id`, `groups`, `whoami` — identity inspection
- `sudo -l` — list your sudo privileges
- `getent passwd`, `getent group` — query NSS for users and groups
- `journalctl -u ssh`, `tail -f /var/log/auth.log` — auth events
- `lastb`, `last`, `lastlog` — login records
- `aa-status` (AppArmor) or `getenforce` (SELinux) — check MAC state
- `unshare`, `nsenter` — namespace tooling

## Glossary

| Term | One-line definition |
|------|---------------------|
| **Asset** | Anything worth protecting (data, capability, reputation, availability). |
| **Threat** | A *potential* cause of harm; an actor or event capable of harming an asset. |
| **Vulnerability** | A weakness in a system that a threat can exploit. |
| **Risk** | The combination of likelihood and impact of a threat exploiting a vulnerability. |
| **Control** | A safeguard that reduces risk (preventive, detective, or corrective). |
| **CIA triad** | Confidentiality, Integrity, Availability. The starter taxonomy of security properties. |
| **STRIDE** | Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege. |
| **`setuid`** | A file permission bit causing a binary to run with the file owner's UID rather than the caller's. |
| **POSIX capability** | A discrete root privilege (e.g., `CAP_NET_BIND_SERVICE`) that can be granted independently. |
| **DAC** | Discretionary Access Control — the owner decides (Unix `rwx`). |
| **MAC** | Mandatory Access Control — the policy decides (SELinux, AppArmor). |
| **Least privilege** | A principal should have only the access required to perform its function. |
