# Week 1 — The Security Mindset and the Linux Security Model

> *Security is not a feature you add. It is a property of the system you build. Week 1 is about learning to see the system the way an attacker does — and to defend it the way an engineer should.*

Welcome to **C6 · Cybersecurity Crunch**. Week 1 has two halves. The first is conceptual: what "security" actually means, why the CIA triad both helps and misleads, and how to threat-model anything in four questions. The second is mechanical: the Linux security model — users, groups, file permissions, `setuid`, capabilities, namespaces — because most servers you will ever defend run Linux, and most privilege-escalation findings reduce to "someone got the model wrong."

By Sunday you will have produced a working threat model of a real system you use, you will be able to read `ls -l` output including the awkward bits (`s`, `t`, capabilities), and you will have solved levels 0-5 of OverTheWire Bandit — the canonical free wargame designed for exactly this point in a security curriculum.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Practice the techniques in this module only on:                    │
│  - machines and networks you own                                    │
│  - legal training platforms (TryHackMe, HackTheBox, picoCTF,        │
│    VulnHub, OverTheWire, pwn.college)                               │
│  - systems with explicit written permission from the owner          │
│                                                                     │
│  Unauthorized testing is a crime. C6 does not teach crime.          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Learning objectives

By the end of this week, you will be able to:

- **Define** confidentiality, integrity, and availability — and name three real-world failures the triad does *not* cleanly cover (safety, non-repudiation, privacy as distinct from confidentiality).
- **Distinguish** the four words people misuse interchangeably: *asset*, *threat*, *vulnerability*, *risk*.
- **Produce** a threat model that answers the four questions: what are we building, what could go wrong, what are we doing about it, did we do a good job.
- **Apply** STRIDE to a system you actually use and identify at least one mitigation per category.
- **Read** Linux file permissions character by character, including `setuid`, `setgid`, and the sticky bit — and explain in one sentence why each exists.
- **Audit** `sudo` configuration on a Linux box you own: who can run what, with what password requirement, with what `NOPASSWD` exemptions.
- **Interpret** `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Fedora) and identify successful logins, failed logins, sudo escalations, and SSH session events.
- **List** the POSIX capabilities a typical service binary might need, and explain why "drop root, grant `CAP_NET_BIND_SERVICE`" is better than "run as root."
- **State** the principle of least privilege in your own words and apply it to a real configuration.
- **Solve** levels 0-5 of the OverTheWire Bandit wargame and write a short post-game note on what each level taught you.

---

## Prerequisites

- **C1 weeks 1-11** completed (Python, shell comfort).
- **C14 · Crunch Linux** completed, or equivalent. You must be comfortable with `ls`, `chmod`, `ps`, `grep`, `ssh`, `man`, and reading `/var/log` files.
- A Linux VM or working WSL2 install you have administrative access to. Any modern distribution (Ubuntu 24.04 LTS, Debian 12, Fedora 40, Kali — Kali optional, not required).
- An SSH client (every OS ships one).
- The willingness to read a few primary sources: NIST SP 800-30, the OWASP Top 10 page, and the OverTheWire site.

If you are not comfortable in a Linux terminal, **stop now** and complete [C14](../../../C14-CRUNCH-LINUX/). C6 will not slow down.

---

## Topics covered

- The CIA triad — confidentiality, integrity, availability — and what it leaves out (safety, privacy, non-repudiation, accountability)
- The vocabulary discipline: asset vs threat vs vulnerability vs risk; control vs mitigation vs compensating control
- Threat modeling 101: the four questions (Shostack), asset-driven vs attacker-driven approaches
- **STRIDE** as a checklist (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege)
- Attack trees as a complementary tool
- The "security mindset" — Schneier's framing; thinking adversarially without becoming an adversary
- **Authorized use only** — the legal and ethical frame for every offensive technique in this track
- Linux users, groups, and UIDs: `/etc/passwd`, `/etc/shadow`, `/etc/group`
- File permission bits: `rwx` for owner / group / other; the octal representation
- `setuid`, `setgid`, the sticky bit — what each does, why each is dangerous, how to find them (`find / -perm -4000`)
- The principle of least privilege and how Linux gives you primitives to apply it
- `sudo` and `/etc/sudoers`: the syntax, `NOPASSWD`, the `Defaults` directives, the audit trail (`/var/log/auth.log`)
- POSIX capabilities — `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_SYS_ADMIN`, and the rest; `getcap`, `setcap`
- Namespaces and cgroups as a security primitive (the foundation under containers)
- AppArmor and SELinux at a high level — mandatory access control as a layer above discretionary
- Reading `/var/log/auth.log` for successful and failed logins, sudo events, SSH session activity

---

## Weekly schedule

The schedule below adds up to approximately **36 hours**. Treat it as a target.

| Day       | Focus                                                | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Self-Study | Daily Total |
|-----------|------------------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|-----------:|------------:|
| Monday    | The security mindset; CIA triad; vocabulary          |    2h    |    1h     |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |     5h      |
| Tuesday   | Threat modeling; STRIDE; the four questions          |    2h    |    2h     |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |     6h      |
| Wednesday | Linux users, groups, file permissions deep           |    2h    |    2h     |     1h     |    0.5h   |   1h     |     0h       |    0h      |     6.5h    |
| Thursday  | `setuid`, `sudo`, capabilities, least privilege      |    0h    |    1h     |     1h     |    0.5h   |   1h     |     2h       |    0.5h    |     6h      |
| Friday    | Namespaces, MAC (AppArmor/SELinux), auth.log         |    0h    |    1h     |     1h     |    0.5h   |   1h     |     2h       |    0.5h    |     6h      |
| Saturday  | Mini-project deep work + Bandit 0-5                  |    0h    |    1h     |     1h     |    0h     |   1h     |     3h       |    0h      |     6h      |
| Sunday    | Quiz, review, polish, push                           |    0h    |    0h     |     0h     |    0.5h   |   0h     |     0h       |    0h      |     0.5h    |
| **Total** |                                                      | **6h**   | **8h**    | **4h**     | **3h**    | **6h**   |   **7h**     |   **2h**   |  **36h**    |

---

## How to navigate this week

| File | What's inside |
|------|---------------|
| [README.md](./README.md) | This overview (you are here) |
| [resources.md](./resources.md) | NIST, OWASP, MITRE ATT&CK, free CTF sites, the primary sources |
| [lecture-notes/01-the-security-mindset-and-the-cia-triad.md](./lecture-notes/01-the-security-mindset-and-the-cia-triad.md) | What security means; the CIA triad and its limits; threat modeling in four questions; STRIDE |
| [lecture-notes/02-the-linux-security-model.md](./lecture-notes/02-the-linux-security-model.md) | Users, groups, permissions, `setuid`, capabilities, namespaces, MAC |
| [exercises/README.md](./exercises/README.md) | Index of short hands-on drills |
| [exercises/exercise-01-threat-model-your-laptop.md](./exercises/exercise-01-threat-model-your-laptop.md) | A two-page threat model of the machine you are reading this on |
| [exercises/exercise-02-permissions-and-setuid.md](./exercises/exercise-02-permissions-and-setuid.md) | Hands-on with `chmod`, `setuid`, and `find -perm` |
| [exercises/exercise-03-read-the-auth-log.md](./exercises/exercise-03-read-the-auth-log.md) | Parse a real `/var/log/auth.log` and answer questions about it |
| [challenges/README.md](./challenges/README.md) | Index of weekly challenges |
| [challenges/challenge-01-overthewire-bandit.md](./challenges/challenge-01-overthewire-bandit.md) | Bandit levels 0-5 on OverTheWire (free, legal, designed for this) |
| [quiz.md](./quiz.md) | 10 multiple-choice questions |
| [homework.md](./homework.md) | Six practice problems |
| [mini-project/README.md](./mini-project/README.md) | Full threat model of a real system you use, delivered as a 2-page write-up |

---

## Stretch goals

If you finish early, push further:

- Read NIST SP 800-30 Rev. 1 ("Guide for Conducting Risk Assessments") cover to cover. It is dry. It is also the document every formal threat model in the United States Federal Government traces back to. Free PDF.
- Read Adam Shostack's *Threat Modeling: Designing for Security*, chapter 1 only (the four-questions chapter is the durable contribution). The rest of the book is good but optional.
- Solve OverTheWire Bandit through level 10. Levels 6-10 introduce file searching, `find` predicates, and netcat — useful background for Week 2.
- Read the SELinux Project's "User Resources" page and `man capabilities(7)` end-to-end.
- Read CVE-2021-3156 ("Baron Samedit," the `sudo` heap overflow). It is a textbook case of why `setuid` programs deserve more scrutiny than any other binary on the system.

---

## Up next

Continue to [Week 2 — Networking for Security](../week-02-networking-for-security/) once your mini-project is pushed and your Bandit progress is recorded.

---

*Found an error? Open an issue or send a PR. The next learner will thank you.*
