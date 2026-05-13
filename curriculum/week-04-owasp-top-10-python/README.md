# Week 4 — OWASP Top 10 in Python

> *The OWASP Top 10 is not a checklist. It is the post-mortem distilled. Every category is a class of bug that has shipped, broken something material, and earned its place on the list by recurring across thousands of audits. Week 4 walks all ten categories, shows each one in vulnerable Python, then shows the fix on the next page.*

Welcome to Week 4 of **C6 · Cybersecurity Crunch**. Weeks 1, 2, and 3 gave you the security mindset, the network, and the threat model. Week 4 is the first time the threat model meets a real codebase under attack. The categories on the OWASP Top 10 are the *vulnerabilities* that Week 3's *threats* exploit. By Sunday you will have read each category as written by OWASP, seen each one demonstrated in Python you can run, written the patch yourself, and produced a portfolio artifact — a deliberately vulnerable Python app you patched, category by category, with a write-up per fix.

This week is hands-on. You will read code, you will run code, you will break code on your own laptop, and you will fix code. The OWASP Top 10 2021 is the published list (`A01:2021` through `A10:2021`); the OWASP Top 10 2025 release candidate is in public review at the time of writing and the changes are noted in each lecture. You will cite both throughout.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Practice the techniques in this module only on:                    │
│  - the deliberately vulnerable Python app provided with this week   │
│  - machines and networks you own                                    │
│  - legal training platforms (OWASP Juice Shop, OWASP WebGoat,       │
│    DVWA, PortSwigger Web Security Academy, picoCTF, HackTheBox      │
│    starter tier, TryHackMe)                                         │
│  - systems with explicit written permission from the owner          │
│                                                                     │
│  Unauthorized testing is a crime. C6 does not teach crime.          │
└─────────────────────────────────────────────────────────────────────┘
```

The banner is mandatory on every page this week. Every lecture demonstrates an attack; every exercise asks you to run one against the provided lab; every challenge sends you into source you do not own to *read* (lawful) but never to *exercise* against a live deployment (a crime if you do not operate the deployment). The line you walked up to in Week 3 — read the source, reason about attacks, do not run them — is the line you walk along this week. Stay on the right side of it.

---

## Learning objectives

By the end of this week, you will be able to:

- **List** the ten categories of the OWASP Top 10 2021 in order, by ID and full name, and **explain how the 2025 release candidate reorganises and renames them**, citing OWASP's published rationale.
- **Recognise** at least one Python-flavoured concrete example of each category — a Flask, Django, FastAPI, or pure-Python pattern that demonstrably triggers the vulnerability.
- **Patch** each example with the idiomatic Python remediation — parameterised queries for `A03`, `argon2-cffi` for `A02`, `Authlib` or framework session middleware for `A07`, `defusedxml` for the XXE residue under `A05`, `urllib3` allow-list filters for `A10`, and so on.
- **Distinguish** *authentication*, *authorisation*, *session management*, and *identification*, and explain which OWASP category covers each failure mode.
- **Audit** a Flask or FastAPI application against the Top 10 by walking each category in turn, anchoring findings to lines of code, and writing a finding in the standard format — title, location, severity, CWE, OWASP category, proof-of-concept (in your own lab only), remediation.
- **Map** every Top 10 category to its **CWE** counterparts and to a **MITRE ATT&CK** technique where appropriate (e.g. `A03 Injection` ↔ CWE-89 SQL Injection ↔ `T1190 Exploit Public-Facing Application`).
- **Use** the OWASP **ASVS** (Application Security Verification Standard) Level 1 controls as the closing checklist for a Python service, citing specific ASVS section numbers.
- **Configure** Python security tooling — `bandit`, `semgrep` (with the OWASP Top 10 ruleset), `pip-audit`, `safety` — and read its findings without panic and without dismissal.
- **Write** a defender-side description of each Top 10 category: what log line, what metric, what WAF rule, what `nginx` config would have caught or prevented this attack.
- **Produce** a "vulnerable Python app, patched" repository as your Week 4 portfolio artifact — ten commits or ten PRs, one per category, each with a security write-up.

---

## Prerequisites

- **Weeks 1, 2, and 3 completed.** You should be comfortable in a Linux terminal, able to read a PCAP and an `nginx` config, and able to produce a small threat model without prompting.
- **Python 3.11+** installed locally. A virtualenv per project. `pip`, `pip-audit`, `bandit`, `semgrep` available on the path. If you have not used `semgrep` before, install via `pip install semgrep`; it works on Linux and macOS without Docker.
- **Flask, Django, or FastAPI familiarity** at the "I have built a small CRUD app" level. C1 graduates have this. If you do not, work through the Flask quickstart and the FastAPI tutorial first (about 4 hours total) before starting the lectures.
- **A working `git` and a GitHub account.** The mini-project produces ten commits or ten PRs.
- **The lab app cloned locally.** The link and setup steps are in [mini-project/README.md](./mini-project/README.md). The app is deliberately vulnerable. Run it on `127.0.0.1`. Do not expose it to the internet, even temporarily, even behind a "secret" port.

---

## Topics covered

- The **OWASP Top 10 2021** in order: `A01 Broken Access Control`, `A02 Cryptographic Failures`, `A03 Injection`, `A04 Insecure Design`, `A05 Security Misconfiguration`, `A06 Vulnerable and Outdated Components`, `A07 Identification and Authentication Failures`, `A08 Software and Data Integrity Failures`, `A09 Security Logging and Monitoring Failures`, `A10 Server-Side Request Forgery (SSRF)`.
- The **OWASP Top 10 2025 release candidate** — the proposed reorganisation, the new entries (notably the elevation of supply-chain integrity and the broader framing of misconfiguration), and OWASP's methodology for the change (CWE-weighted incidence data plus community survey). Cited per lecture.
- **`A03 Injection`** — SQL injection, NoSQL injection, command injection (`os.system`, `subprocess.run(shell=True)`), template injection (Jinja2 SSTI), LDAP injection. Parameterised queries, ORM use, the SQLAlchemy `text()` foot-gun, `subprocess.run(args=[...], shell=False)`, `shlex.quote`.
- **`A01 Broken Access Control`** — IDOR (insecure direct object reference), missing function-level authorisation, the difference between authentication and authorisation, deny-by-default routing, `flask-login` and Django permission decorators used correctly.
- **`A07 Identification and Authentication Failures`** — credential stuffing, weak password storage, broken session management, missing rate limiting, missing MFA. `argon2-cffi` over `bcrypt` over `pbkdf2`; never `md5`, `sha1`, `sha256` for passwords. Session ID entropy and rotation. HIBP password-check at registration.
- **`A02 Cryptographic Failures`** — TLS configuration, certificate pinning, the `cryptography` library vs. `pycryptodome`, what to use (Fernet, AES-GCM, X25519) and what to never touch (textbook RSA, ECB mode, custom MAC). Password hashing is a *different* concern (covered under A07).
- **`A05 Security Misconfiguration`** — `DEBUG=True` in production, default credentials, exposed `/.env`, permissive CORS, missing security headers (CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`), the residue of XXE (XML eXternal Entities, formerly its own 2017 category).
- **`A04 Insecure Design`** — the difference between a *missing control* and a *flawed design*. Why "we should encrypt this" is a control and "we should not store this at all" is a design choice. Threat-modelling integration with the SDLC. Sample design failures: password reset via email-only "magic link" with no expiry, "remember me" cookies that never rotate, multi-tenant systems sharing a database with no row-level security.
- **`A06 Vulnerable and Outdated Components`** — supply-chain hygiene for Python: `pip-audit`, `safety`, `pip-tools` for lockfiles, `dependabot`, `renovate`, the OSV database, GitHub's Dependabot alerts. The post-`event-stream` and post-`ua-parser-js` and post-`xz-utils` world.
- **`A09 Security Logging and Monitoring Failures`** — what to log (auth events, authz failures, admin actions, input validation rejections), what *never* to log (passwords, tokens, full PANs, full session cookies), how to structure logs (JSON, structured fields), how long to retain. The relationship between logging and Repudiation (Week 3's STRIDE R).
- **`A10 Server-Side Request Forgery (SSRF)`** — how `requests.get(user_url)` becomes a cloud-metadata exfiltration vector. The IMDSv2 mitigation. Allow-list URL filtering. The `urllib3` vs. `requests` vs. `httpx` choice and what each library does and does not protect against by default.
- **`A08 Software and Data Integrity Failures`** — `pickle.load` on untrusted input, `yaml.load` (vs. `yaml.safe_load`), JSON Web Tokens with `alg=none` or `HS256/RS256` confusion, signed-cookie tampering, package signature verification (PyPI's signing posture as of 2025, Sigstore for Python).
- **Defender-side coverage of all 10:** how each category surfaces in logs, what metric is appropriate, what WAF rule, what `nginx` or proxy config, what CSP directive, what alert.

---

## Weekly schedule

The schedule below adds up to approximately **36 hours**. Treat it as a target.

| Day       | Focus                                                  | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Self-Study | Daily Total |
|-----------|--------------------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|-----------:|------------:|
| Monday    | A03 Injection; A01 Broken Access; A07 Auth failures    |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |    5.5h     |
| Tuesday   | A02 Crypto; A05 Misconfig; A04 Insecure design         |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |    5.5h     |
| Wednesday | A06 Components; A09 Logging; A10 SSRF; A08 Integrity   |    2h    |    1h     |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |     5h      |
| Thursday  | Mini-project setup; exercises 1-3 polish               |    0h    |    2h     |     1h     |    0.5h   |   1h     |     2h       |    0.5h    |     7h      |
| Friday    | Mini-project: patch A01-A05                            |    0h    |    1h     |     1h     |    0.5h   |   1h     |     2h       |    0.5h    |     6h      |
| Saturday  | Mini-project: patch A06-A10; write-ups                 |    0h    |    0h     |     2h     |    0h     |   1h     |     3h       |    0h      |     6h      |
| Sunday    | Quiz, review, polish, push                             |    0h    |    0h     |     0h     |    0.5h   |   0h     |     0h       |    0.5h    |     1h      |
| **Total** |                                                        | **6h**   | **7h**    | **4h**     | **3h**    | **6h**   |   **7h**     |   **3h**   |  **36h**    |

---

## How to navigate this week

| File | What's inside |
|------|---------------|
| [README.md](./README.md) | This overview (you are here) |
| [resources.md](./resources.md) | OWASP Top 10 2021 + 2025-RC primary sources, CWE, ASVS, MITRE, Python tooling |
| [lecture-notes/01-injection-broken-access-broken-auth.md](./lecture-notes/01-injection-broken-access-broken-auth.md) | A03, A01, A07 — the three categories that ship the most CVEs against Python web apps |
| [lecture-notes/02-crypto-failures-and-misconfig.md](./lecture-notes/02-crypto-failures-and-misconfig.md) | A02, A05, A04 — cryptography you can use without breaking it, configuration you can ship without leaking, and the design choices that make both possible |
| [lecture-notes/03-the-rest-vulnerable-components-logging-ssrf.md](./lecture-notes/03-the-rest-vulnerable-components-logging-ssrf.md) | A06, A09, A10, A08 — the rest of the list, with supply chain front and centre |
| [exercises/README.md](./exercises/README.md) | Index of three Python exercises |
| [exercises/exercise-01-injection-and-access-control.md](./exercises/exercise-01-injection-and-access-control.md) | A03 + A01 — SQL injection in a Flask login, then IDOR on a `/orders/<id>` route |
| [exercises/exercise-02-crypto-and-auth.md](./exercises/exercise-02-crypto-and-auth.md) | A07 + A02 — `md5(password)` and a session ID generated from `time.time()`, both fixed |
| [exercises/exercise-03-ssrf-and-deserialisation.md](./exercises/exercise-03-ssrf-and-deserialisation.md) | A10 + A08 — a "URL preview" endpoint that hits `169.254.169.254`, and `pickle.load` on a Redis-stored cart |
| [challenges/README.md](./challenges/README.md) | Index of weekly challenges |
| [challenges/challenge-01-audit-flask-app.md](./challenges/challenge-01-audit-flask-app.md) | Audit a small Flask app for all 10 Top 10 categories and produce a report |
| [quiz.md](./quiz.md) | 10 multiple-choice questions |
| [homework.md](./homework.md) | Six practice problems, six hours total |
| [mini-project/README.md](./mini-project/README.md) | Patch all 10 OWASP Top 10 categories in a deliberately vulnerable Python app — the Week 4 portfolio artifact |

---

## Stretch goals

If you finish early, push further:

- Read the **OWASP Cheat Sheet Series** in full for the categories that bit you hardest in the mini-project. `Authentication_Cheat_Sheet`, `Session_Management_Cheat_Sheet`, `SQL_Injection_Prevention_Cheat_Sheet`, `Cross_Site_Scripting_Prevention_Cheat_Sheet`, `Server_Side_Request_Forgery_Prevention_Cheat_Sheet`. They are short and densely useful: <https://cheatsheetseries.owasp.org/>.
- Read the **PortSwigger Web Security Academy** labs for SQLi, XSS, and SSRF. Free, browser-only, and the cleanest interactive teaching material in the field: <https://portswigger.net/web-security>.
- Re-do the mini-project against a **different framework**. If you patched Flask, do it again against FastAPI; the auth and middleware idioms are different.
- Read the **MITRE CWE Top 25** (Common Weakness Enumeration, refreshed annually) and map every Top 10 category to its CWE entries: <https://cwe.mitre.org/top25/>.
- Read **NIST SP 800-63B Digital Identity Guidelines** §5 (authenticator types) and update your mini-project's authentication to be conformant with at least AAL2.
- Read **OWASP ASVS v4.0.3** Level 1 in full and produce a coverage matrix of your mini-project against it. ASVS is the closing checklist you should default to once the Top 10 is internalised: <https://owasp.org/www-project-application-security-verification-standard/>.

---

## Up next

Continue to [Week 5 — Secure Coding in Python](../week-05/) once your mini-project repo is pushed and your portfolio README links to all four weeks. Week 5 zooms in on the *Python-specific* coding hazards — `pickle`, `yaml`, ReDoS, insecure randomness, the `bandit` / `semgrep` / `pip-audit` toolchain — that overlap with but do not duplicate the OWASP Top 10.

---

*Found an error? Open an issue or send a PR. The next learner will thank you.*
