# Week 8 — Web Application Security, Hands-On

> *Week 4 walked you through the OWASP Top 10 in conceptual form: what each category is, where the bug class hides, the canonical mitigations. Week 7 taught you how to point a scanner at a host you own and produce a report that does not get you indicted. Week 8 closes the loop. You will stand up a deliberately vulnerable Flask 3.x application on your own laptop, exploit each Top-10 class against it with `curl`, with Burp Suite Community, and with OWASP ZAP, write up each finding, then ship the patched version. By Sunday night you will have done — by hand, against your own code, on your own machine — what a junior application-security engineer does in their first three months on the job.*

Welcome to Week 8 of **C6 · Cybersecurity Crunch**. Weeks 1 through 7 covered the foundations: the mindset, the Linux baseline, the network, the threat model, the OWASP Top 10 conceptually, the secure-coding toolchain, the code review at PR time, and the authorised recon engagement. Week 8 is the **lab week**. The tool list is short and the rule of engagement is simple: every exploit you run is against a Flask app you started on your own laptop seconds ago. The application is named `vuln_lab` and lives inside this week's `mini-project/starter/` directory. You will run it on `127.0.0.1:5000`, exploit it, patch it, and write up every step.

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  Every exploit technique in this module is run against:             |
|  - the vuln_lab Flask application running on your own laptop, on    |
|    localhost (127.0.0.1), on a port you bound yourself, started     |
|    inside this week's mini-project/starter/ directory.              |
|                                                                     |
|  Nothing else. Not your university's web portal. Not your           |
|  employer's intranet. Not a friend's website. Not "a small site     |
|  that probably has SQL injection." Not a public bug bounty target   |
|  outside the program's written scope.                               |
|                                                                     |
|  Running these payloads against a host you are not authorised to    |
|  touch is, in the United States, a violation of the Computer Fraud  |
|  and Abuse Act (18 U.S.C. § 1030); in the United Kingdom, a         |
|  violation of the Computer Misuse Act 1990; in the European Union,  |
|  a violation of Directive 2013/40/EU as implemented in each member  |
|  state. The penalties are real (criminal prosecution, civil         |
|  liability, professional decertification) and the case law is       |
|  settled. SQL injection is not a party trick; SSRF is not a         |
|  curiosity; the moment your payload leaves your own machine you     |
|  are operating under those statutes.                                |
|                                                                     |
|  If you cannot point at a document or an ownership claim that       |
|  authorises the test, you do not run the test.                      |
+---------------------------------------------------------------------+
```

The banner appears on every page this week. Read it once carefully now; thereafter treat it as a contract. Every exercise, every challenge, and every step of the mini-project is written so the only target is `127.0.0.1` on a port you bound yourself, inside an application whose source code lives in *this directory*. If a write-up ever instructs you to target anything else, stop and re-read the banner.

---

## Learning objectives

By the end of this week, you will be able to:

- **Stand up** a deliberately vulnerable Flask 3.x web application on `127.0.0.1` from a single starter directory, using only the Python standard library plus Flask, with no third-party services and no internet egress required to reproduce any vulnerability.
- **Exploit**, by hand, each of the relevant OWASP Top 10 2021 categories against the lab: **A01 Broken Access Control** (insecure direct object reference, missing function-level authorization), **A02 Cryptographic Failures** (plaintext password storage, weak session token generation), **A03 Injection** (SQL injection via string concatenation, command injection via `os.system`), **A05 Security Misconfiguration** (debug mode, verbose error pages, default credentials), **A07 Identification and Authentication Failures** (no rate limit on login, predictable session tokens, password reset via security question), **A08 Software and Data Integrity Failures** (insecure deserialization via `pickle.loads`), **A10 Server-Side Request Forgery** (SSRF via unrestricted `requests.get(url)`).
- **Cross-link** each finding to its **CWE** (Common Weakness Enumeration) identifier, the matching **OWASP Top 10 2021** category, the **PortSwigger Web Security Academy** free lab that mirrors the bug class, and at least one real-world **CVE** that exhibits the same class.
- **Operate** **Burp Suite Community Edition** as an intercepting HTTP proxy: configure the Firefox / Chromium proxy settings, install the Burp CA certificate, capture and modify a request mid-flight, replay captured requests through Repeater, and run a directed Intruder attack against a login endpoint within the rate-cap your own RoE allows.
- **Operate** **OWASP ZAP** as the open-source alternative to Burp Community: configure the same proxy intercept, run an automated baseline scan with ZAP's daemon-mode command-line interface (`zap.sh -cmd`), produce a ZAP HTML report, and reason about which finding classes each tool surfaces well and which it surfaces poorly.
- **Detect and reason about HTTP request smuggling** at the conceptual level: the CL.TE and TE.CL desync classes, why intermediary proxies plus origin servers create the disagreement, and the canonical PortSwigger labs that demonstrate each class. The mini-project does not require you to run a smuggling exploit (the conditions are environment-dependent and outside the single-host lab) but you must be able to write 200 words explaining what one is.
- **Defend** the lab application by writing, applying, and validating a **Content Security Policy** header that blocks the canonical reflected and stored XSS payloads from the exploit phase, then verifying with the browser dev-tools console that the policy fires. Reason about CSP's strengths (eliminates entire classes of inline-script execution) and limitations (no defence against authorization bugs, server-side injection, or SSRF).
- **Ship** the patched version of the lab. Each vulnerability has a `BEFORE` (the vulnerable code as-shipped in the starter) and an `AFTER` (the patched code you write). The mini-project deliverable is the full red-team write-up, the patched application, and a regression-test script that re-runs each exploit and confirms it now fails.
- **Read** the canonical references as primary sources: the **OWASP Top 10 2021** at <https://owasp.org/Top10/>, the **OWASP Cheat Sheet Series**, the **PortSwigger Web Security Academy** free curriculum, the **CWE-1003** "Weaknesses for Simplified Mapping of Published Vulnerabilities" view, and the **Mozilla Developer Network** documentation for HTTP headers and CSP.

---

## Prerequisites

- **Weeks 1 through 7 completed.** Weeks 4 (OWASP Top 10 conceptual), 5 (toolchain), 6 (code review), and 7 (authorised recon) are the closest dependencies. Week 4 named these bug classes; this week makes you put your hands on them.
- **A Linux or macOS host where you have administrative access** to install Python packages and run a local HTTP server bound to `127.0.0.1`. Windows works but the path conventions in this week's scripts are POSIX-flavoured.
- **Python 3.11 or later.** Verify with `python3 --version`. Flask 3.x requires Python 3.8+; we target 3.11 to keep type-hint syntax modern.
- **`pip` available**, with permission to install into a virtual environment (`python3 -m venv .venv`).
- **`curl`** on the path. Most exploit demonstrations are reproducible with `curl` alone, no GUI required.
- **A modern browser** — Firefox (recommended for Burp / ZAP integration; the Firefox profile-isolation model makes it easier to add and remove proxy certificates without contaminating your daily browsing) or Chromium.
- **Burp Suite Community Edition** (free) installed. Download from <https://portswigger.net/burp/communitydownload>. Burp Community requires a free PortSwigger account but no paid licence. (If you prefer not to register for a PortSwigger account, OWASP ZAP is a sufficient substitute for every exercise; the mini-project specifies both paths.)
- **OWASP ZAP** (free) installed. Download from <https://www.zaproxy.org/download/>. ZAP is a Java application; it requires a JRE 11+ which most laptops already have.
- **A text editor or IDE** with Python type-hint awareness (VS Code with Pylance, PyCharm Community, Vim with a Python LSP). The lab patches are easier to read with type hints on.
- **Network isolation discipline.** The lab binds to `127.0.0.1` exclusively. Do not change the bind address to `0.0.0.0`. If you must change it (you almost never must), unbind first from any network that is not host-only.

---

## Topics covered

- **The lab itself.** A single `app.py` of approximately 350 lines, plus templates and a SQLite database. Eight deliberately-vulnerable endpoints, one per bug class. Each endpoint has a `BEFORE` (vulnerable) and an `AFTER` (patched) version; you ship both, and the exercises walk you from one to the other.
- **The intercepting proxy as the application security practitioner's microscope.** Why every serious bug hunter has Burp or ZAP at hand at all times; what an "intercepting proxy" is at the network level (a man-in-the-middle the browser cooperates with); how to install the proxy CA, configure the browser, and not poison your daily browsing.
- **Burp Suite Community.** Proxy, Repeater, Intruder (rate-limited in Community Edition, which is fine for our lab), Decoder, Comparer. What is and is not in Community; what you give up by not running Professional; when "good enough for a lab" is good enough.
- **OWASP ZAP.** The open-source equivalent. Spider, automated scan, daemon mode, the ZAP API, the baseline and full-scan packaged scripts. The trade-off: ZAP's automated scan finds more low-hanging fruit out of the box; Burp's manual workflow is preferred for skilled hunters.
- **A01 Broken Access Control.** The two flavours we exploit: **insecure direct object reference (IDOR)** — `GET /invoices/<id>` returns any user's invoice — and **missing function-level authorization** — `GET /admin/users` returns the list to any authenticated user, not only admins.
- **A02 Cryptographic Failures.** Two flavours: passwords stored in plaintext in the database; session tokens generated with `random.random()` instead of `secrets.token_urlsafe()`. The first is a CWE-256 / CWE-257 family; the second is CWE-330 / CWE-338.
- **A03 Injection.** Two flavours: **SQL injection** via `cursor.execute("SELECT ... WHERE name='" + name + "'")` (CWE-89), and **command injection** via `os.system("convert " + user_filename + " out.png")` (CWE-78). Both are exploited with `curl`, both are patched with parameterized queries / `subprocess.run([list], shell=False)`.
- **A03 Injection (XSS subcategory).** Both **reflected XSS** via a search endpoint that echoes the unsanitised query parameter, and **stored XSS** via a comment endpoint that stores the unsanitised body and renders it on `/comments`. We exploit with `<script>alert(document.cookie)</script>` against the lab, then patch by switching from `Markup` to Jinja's default autoescape, then layer **Content Security Policy** as defence-in-depth.
- **A05 Security Misconfiguration.** Debug mode left on (Flask's interactive traceback console exposes RCE); verbose error pages leaking stack traces; default credentials `admin / admin`; missing security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Strict-Transport-Security` — though HSTS is moot on `127.0.0.1`, we note where it would apply in production).
- **A07 Authentication Failures.** No rate limit on `/login`; security-question password reset with the question stored alongside the answer in plaintext; session tokens regenerated only on login, not on privilege change.
- **A08 Insecure Deserialization.** A `/import-profile` endpoint that takes a base64-encoded pickle payload and calls `pickle.loads`. We construct a malicious payload that runs `os.system('id')` on the server when deserialised; we patch by replacing pickle with JSON.
- **A10 Server-Side Request Forgery.** A `/fetch-image` endpoint that takes a URL parameter and proxies the response. We exploit by pointing it at `http://169.254.169.254/latest/meta-data/` (the AWS metadata endpoint) — in our lab we point it at a mock metadata server running on `127.0.0.1:8080` that you also start, so the entire scenario is self-contained. We patch with an allow-list of hostnames.
- **HTTP request smuggling.** Conceptual only. CL.TE and TE.CL classes. Why CDNs plus origin servers create the desync. PortSwigger's labs walk you through one if you want to push further; the mini-project does not require a working smuggling exploit.
- **Content Security Policy.** The header, its directives (`default-src`, `script-src`, `style-src`, `img-src`, `connect-src`, `frame-ancestors`), the `nonce-` and `sha256-` source expressions, the `report-uri` / `report-to` mechanism, and what CSP does and does not protect against.

---

## Weekly schedule

The schedule below adds up to approximately **35 hours**. Treat it as a target.

| Day       | Focus                                                          | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Self-Study | Daily Total |
|-----------|----------------------------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|-----------:|------------:|
| Monday    | L1 — The intercepting proxy and the OWASP Top 10 in code       |    2h    |    1h     |     0h     |    0.5h   |   1h     |     0h       |    1h      |    5.5h     |
| Tuesday   | L2 — Exploit phase (A01, A03, A07, A10)                        |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |    5.5h     |
| Wednesday | L3 — Defence phase (CSP, patches, regression)                  |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0.5h     |    0.5h    |    6h       |
| Thursday  | Exercises polished; challenge launch                           |    0h    |    2h     |     1.5h   |    0.5h   |   1h     |     1h       |    0.5h    |    6.5h     |
| Friday    | Mini-project: stand up the lab, run the exploit walkthrough    |    0h    |    1h     |     0.5h   |    0.5h   |   1h     |     2h       |    0.5h    |    5.5h     |
| Saturday  | Mini-project: patch, regression test, write the report         |    0h    |    0h     |     0h     |    0h     |   1h     |     3h       |    0h      |    4h       |
| Sunday    | Quiz, review, polish, push                                     |    0h    |    0h     |     0h     |    0.5h   |   0h     |     0h       |    1h      |    1.5h     |
| **Total** |                                                                | **6h**   | **7h**    | **2h**     | **3h**    | **6h**   |   **6.5h**   |   **4h**   |  **34.5h**  |

---

## How to navigate this week

| File | What's inside |
|------|---------------|
| [README.md](./README.md) | This overview (you are here) |
| [resources.md](./resources.md) | Free primary sources — OWASP Top 10 2021, PortSwigger Web Security Academy, OWASP Cheat Sheets, MDN HTTP / CSP, CWE Top 25, the canonical Burp and ZAP docs |
| [lecture-notes/01-intercepting-proxy-and-the-lab.md](./lecture-notes/01-intercepting-proxy-and-the-lab.md) | Why the intercepting proxy exists, how Burp and ZAP fit, installing the proxy CA, the layout of the vuln_lab application |
| [lecture-notes/02-exploit-walkthrough.md](./lecture-notes/02-exploit-walkthrough.md) | Class-by-class exploitation: A01 IDOR, A03 SQLi and XSS and command injection, A07 auth failures, A08 deserialization, A10 SSRF |
| [lecture-notes/03-defence-csp-patches-and-regression.md](./lecture-notes/03-defence-csp-patches-and-regression.md) | Patching each bug class, layering CSP, request smuggling conceptual treatment, regression testing the patched lab |
| [exercises/exercise-01-stand-up-the-lab.md](./exercises/exercise-01-stand-up-the-lab.md) | Start the vuln_lab on 127.0.0.1, configure Burp or ZAP, intercept your first request |
| [exercises/exercise-02-exploit-the-top10-classes.md](./exercises/exercise-02-exploit-the-top10-classes.md) | Hands-on exploitation: IDOR, SQLi, XSS, SSRF, pickle deserialization. curl-only steps with optional Burp screenshots |
| [exercises/exercise-03-patch-and-regress.py](./exercises/exercise-03-patch-and-regress.py) | Apply each patch in `app.py` and run the regression script that re-tries every exploit; runnable, compiles clean |
| [exercises/SOLUTIONS.md](./exercises/SOLUTIONS.md) | Worked solutions, full exploit payloads, full patches |
| [challenges/challenge-01-csp-design.md](./challenges/challenge-01-csp-design.md) | Design a CSP for the patched lab from scratch; reason about each directive |
| [challenges/challenge-02-zap-vs-burp-finding-comparison.md](./challenges/challenge-02-zap-vs-burp-finding-comparison.md) | Run both ZAP and Burp against the vulnerable lab; compare findings; write up the deltas |
| [quiz.md](./quiz.md) | 10 questions on the OWASP classes, the proxy workflow, CSP, and patch verification |
| [homework.md](./homework.md) | Six problems, ~6 hours total |
| [mini-project/README.md](./mini-project/README.md) | Build the vulnerable lab, exploit every class, ship the patched version, write the report |
| [mini-project/starter/](./mini-project/starter/) | The starter directory — `app.py`, `templates/`, `init_db.py`, `regression_test.py` |

---

## Stretch goals

If you finish early, push further:

- Work through **all of the PortSwigger Web Security Academy's free labs** in the categories you covered this week (SQL injection, XSS, SSRF, access control, authentication, deserialization). The labs are free, primary, and graded by PortSwigger themselves. Reading list: <https://portswigger.net/web-security/all-labs>. Budget: roughly 40 hours if you do every lab in those categories; do as many as time allows.
- Read **the full OWASP Application Security Verification Standard (ASVS) v4.0.3** (or whatever the current version is when you read this) at <https://owasp.org/www-project-application-security-verification-standard/>. ASVS is the verification-requirements counterpart to the Top 10's awareness list. Pick five Level 1 requirements from each chapter and check the lab against them.
- Read the **OWASP Cheat Sheet Series** entry for each bug class you exploited this week (SQL Injection Prevention, XSS Prevention, SSRF Prevention, Authentication, Authorization, Deserialization). These are the highest-density, lowest-cost references in the OWASP catalogue.
- Build a **GitHub Actions workflow** that runs ZAP's baseline scan against the lab every commit and fails the build if a high-severity finding appears. Commit the workflow alongside the patched lab. This is the form of the work that lives in production CI/CD pipelines at most modern shops.
- Read the **PortSwigger Research blog** posts on HTTP request smuggling by James Kettle (the original 2019 USENIX-published research and the follow-up "HTTP/2" smuggling work). Run the PortSwigger labs that demonstrate each smuggling class. Smuggling does not work against a single-host Flask lab, so the validation has to happen in the academy labs, where PortSwigger has built the correct proxy-plus-origin topology.
- Extend `regression_test.py` so it runs all eight exploit attempts against both the **vulnerable** and **patched** versions of the lab and produces a JUnit-style XML report (`pytest --junitxml=`) that a CI runner can ingest.
- Replicate one **real-world CVE** that maps to one of the bug classes you exploited (e.g. a 2023 Flask app SSRF advisory) and write a one-page comparison: what the real-world advisory said, what your lab demonstrates, where the two differ.

---

## Up next

Continue to [Week 9 — Cryptography in Practice](../week-09/) once your mini-project is pushed and your portfolio README links to all eight weeks. Week 9 picks up the cryptographic-failures theme from this week's A02 exploration and goes deep: symmetric and asymmetric primitives, TLS in 2026, certificate-pinning, the operational mistakes that flatten cryptography in practice.

---

*Found an error? Open an issue or send a PR. The next learner will thank you.*
