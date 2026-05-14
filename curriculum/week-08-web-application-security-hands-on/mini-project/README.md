# Mini-Project — Build, Exploit, and Ship the Patched vuln_lab

> Stand up the deliberately vulnerable Flask application, exploit each of the eight OWASP-Top-10-class bugs documented in Lecture 2, ship the patched version per Lecture 3, and write the report. The artifact, at the end, is the document a hiring manager reads alongside your Week 4 OWASP, Week 5 toolchain-audit, Week 6 code-review, and Week 7 recon outputs to answer the question "can this candidate be handed an application-security finding on Monday?"

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  The target for this mini-project is the vuln_lab Flask             |
|  application bundled inside the starter/ directory. It runs on      |
|  127.0.0.1:5000 on your own laptop. The mock metadata server runs   |
|  on 127.0.0.1:8080. Both are loopback-only by design.               |
|                                                                     |
|  Do not change the bind address. Do not run the regression script   |
|  against any host except the lab. Do not transfer the payloads in   |
|  this project to any other application. The same payloads that      |
|  detonate happily on the lab are crimes under the CFAA, the CMA,    |
|  and Directive 2013/40/EU when sent to any other host.              |
+---------------------------------------------------------------------+
```

The mini-project synthesises the week. The lectures named the workflow (intercept, exploit, patch, regress). The exercises drilled each piece (lab setup, exploit walkthrough, patch sequence). The challenges took the supporting craft further (CSP design, ZAP-vs-Burp comparison). The mini-project ships the whole thing as a portfolio artifact.

**Estimated time:** 6.5 hours, spread across Friday and Saturday.

---

## 1. The starter

The `starter/` directory is the *as-shipped vulnerable* form of the lab. The files:

```text
starter/
├── app.py                 # 350-line Flask app with 8 vulnerable endpoints
├── init_db.py             # creates lab.db with seed data
├── metadata_server.py     # mock metadata server on 127.0.0.1:8080
├── regression_test.py     # the regression script (the rubric)
├── requirements.txt       # Flask, requests (and argon2-cffi for the patch)
├── templates/             # Jinja templates
└── README.md              # starter-level README
```

The starter is intentionally vulnerable. The task is to make it not.

### 1.1 First, confirm it works as shipped

```bash
cd starter/
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 init_db.py
```

In one terminal: `python3 metadata_server.py`.
In a second: `python3 app.py`.
In a third: `python3 regression_test.py`.

The regression script reports `0/9 exploits closed`. That is the correct starter state — every exploit succeeds. Your job is to flip every line to PASS.

---

## 2. What you will produce

A directory in your portfolio repo (or a dedicated `c6-week-08-vuln-lab-<yourhandle>` repo) containing:

```text
c6-week-08-vuln-lab/
├── README.md                    # 1-page cover: what this is, how to read it
├── 01-engagement-roe.md         # Rules of engagement (you authorise yourself)
├── 02-vulnerable-snapshot/      # Snapshot of the as-shipped vulnerable lab
│   ├── app.py                   # The vulnerable app.py from the starter
│   └── init_db.py               # The vulnerable init_db.py
├── 03-exploit-walkthrough/      # Your write-up of each exploit
│   ├── 01-sqli.md
│   ├── 02-reflected-xss.md
│   ├── 03-stored-xss.md
│   ├── 04-command-injection.md
│   ├── 05-idor.md
│   ├── 06-missing-authz.md
│   ├── 07-debug-rce.md
│   ├── 08-no-rate-limit.md
│   ├── 09-pickle-rce.md
│   └── 10-ssrf.md
├── 04-patched-application/      # The patched lab — the deliverable
│   ├── app.py
│   ├── init_db.py
│   ├── metadata_server.py
│   ├── regression_test.py
│   ├── requirements.txt
│   └── templates/
├── 05-csp-design.md             # The CSP design (from Challenge 1, polished)
├── 06-zap-vs-burp.md            # The tool comparison (from Challenge 2, polished)
├── 07-regression-report.md      # The regression-script output, before and after
├── 08-executive-summary.md      # The 1-page exec summary
├── 09-methodology-and-tools.md  # Tool versions and methodology
└── 10-references.md             # Cited sources for every claim
```

Every file is Markdown except the application files. The repo is the portfolio artifact.

---

## 3. The Rules of Engagement (`01-engagement-roe.md`)

The first artifact, written before any exploit. Use the Week 7 § 7 RoE skeleton as the starting point and adapt it to a *self-engagement against your own lab*. Populate every section:

- **Parties** — both engineer and owner are you.
- **Authority basis** — you own the laptop, you wrote the lab, you authorise yourself.
- **Effective and expiration dates** — the week.
- **In-scope assets** — `127.0.0.1:5000` (vuln_lab) and `127.0.0.1:8080` (mock metadata server) on your own laptop. Specify the hardware (laptop hostname or serial).
- **Out-of-scope assets** — everything else. Your home LAN's gateway. Your ISP. Any external host. Specify them.
- **Allowed actions** — all OWASP Top 10 payloads against the in-scope assets, including pickle deserialisation, SSRF probes against the mock metadata server, and the Werkzeug debugger RCE.
- **Prohibited actions** — any payload sent to an out-of-scope host. Any payload that persists outside the lab (e.g. modifying files outside `/tmp`).
- **Time windows** — the times you will work. Tie to your study schedule.
- **Rate cap** — no specific limit needed for loopback; specify "rate cap not applicable to loopback target."
- **Source IPs** — `127.0.0.1` (loopback).
- **Emergency stop** — if anything appears outside `/tmp` or your lab directory, stop and audit.
- **Data handling** — the lab's data is fake; the report goes in your portfolio repo; no real personal data is involved.
- **Deliverables** — this mini-project.
- **Safe-harbour** — self-indemnification.
- **Signatures** — engineer and owner, both you.

Sign and date. The discipline matters more than the literal signature.

---

## 4. The exploit walkthrough (Friday afternoon, ~2 hours)

`03-exploit-walkthrough/` contains one file per finding (ten files total: nine bug classes plus one for the missing-authz separate from IDOR).

Each file follows the same structure:

```markdown
# 03-NN — <bug class name>

**OWASP:** A0N <category>
**CWE:** CWE-<id> <name>
**Severity (CVSS v3.1):** <score> (<vector string>)
**Real-world CVE analogue:** CVE-YYYY-NNNNN (<one-line description>)

## Description

<2-3 paragraphs on the bug, in your own words. Cite OWASP and CWE entries.>

## Vulnerable code

<the relevant snippet from app.py, exactly as shipped in the starter>

## Exploit

### Payload

<the curl command or Burp Repeater request, with full URL-encoding>

### Observed response

<the relevant snippet of the response that demonstrates the exploit>

### What an attacker gains

<2-3 sentences on impact, in concrete terms>

## Patch

<the patched code, with the exact diff or the new function in full>

## Patch validation

<the curl or regression command that demonstrates the exploit no longer works, with the before/after status code or content>

## References

- OWASP A0N: <link>
- CWE-NNN: <link>
- OWASP Cheat Sheet: <link>
- CVE: <link>
- PortSwigger Academy: <link>
```

Each file is roughly one printed page. Ten files, ten pages of write-up.

---

## 5. The patch phase (Saturday morning, ~2 hours)

`04-patched-application/` is the patched lab. Copy `starter/` into `04-patched-application/` first; that is your starting point. Apply the patches from Lecture 3 in order:

1. SQLi at `/lookup`.
2. Reflected XSS at `/search`.
3. Stored XSS at `/comments` (a template change).
4. Command injection at `/thumbnail`.
5. IDOR at `/profile`.
6. Missing function-level authz at `/admin/users`.
7. A05 misconfiguration: `debug=False`, security headers, custom 500 handler.
8. A07 authentication: rate limit, Argon2id, `secrets.token_urlsafe`.
9. A08 deserialization: JSON in, pickle out.
10. A10 SSRF: allow-list with DNS rebinding resistance.

After each patch, restart `app.py` and re-run `regression_test.py`. The corresponding test flips from FAIL to PASS. By the end of the patch sequence, the suite reports `9/9 exploits closed`.

The patched application files in `04-patched-application/` are the deliverable.

---

## 6. The regression report (Saturday afternoon, ~30 min)

`07-regression-report.md` documents:

- The starter-state run: paste the `0/9` output, with timestamp.
- A patch-by-patch progress log: which test flipped to PASS after which patch.
- The final-state run: paste the `9/9` output, with timestamp.
- The `--check-db` output if you also ran the database verification.

This file is the verification artifact. A reviewer can re-run `regression_test.py` against your `04-patched-application/` and confirm the same result.

---

## 7. CSP design and tool comparison (carry over from challenges, ~45 min polish)

`05-csp-design.md` is your Challenge 1 deliverable, polished. `06-zap-vs-burp.md` is your Challenge 2 deliverable, polished. "Polished" means: edited for clarity, citations standardised, screenshots replaced with text where the text suffices, voice consistent with the rest of the report. The challenges produced the *first* draft; the mini-project produces the *portfolio* draft.

---

## 8. Executive summary (`08-executive-summary.md`, ~45 min)

One page, plain English, for someone who will read it once and act on it. Four paragraphs:

1. **What was done.** "This engagement assessed the vuln_lab Flask application bundled with C6 Week 8, conducted by <engineer>, between <start> and <end>, under the Rules of Engagement at `01-engagement-roe.md`. The lab is a teaching artifact; the findings demonstrate eight bug classes from the OWASP Top 10 2021."
2. **Headline findings.** "Eight bug classes were demonstrated and exploited, then patched. The most severe were the Werkzeug debugger remote-code-execution (A05), the pickle deserialization remote-code-execution (A08), and the server-side request forgery exfiltrating cloud-metadata-equivalent credentials (A10). All three are patched in the shipped application."
3. **What the patched application demonstrates.** Three or four specific patches with the references that justify them ("SQL injection is closed via parameterized queries per the OWASP SQL Injection Prevention Cheat Sheet").
4. **Confidence and caveats.** "All findings were demonstrated against `127.0.0.1` on the engineer's own laptop, with regression validated by an automated script (`regression_test.py`) that re-attempts each exploit and confirms the patch holds. The patched application is suitable as a teaching artifact, not as a production code base; production hardening would additionally require structured logging, container isolation, secrets management, and a production-grade WSGI server. See § 04-patched-application/README.md for the deployment caveats."

---

## 9. Methodology and tools (`09-methodology-and-tools.md`, ~30 min)

A section that lists:

- Tool versions (`python3 --version`, `pip freeze`, Burp Community version, ZAP version, browser version).
- The operating environment (your laptop, OS version).
- The patch sequence (P1 through P9 in the order you applied them; deviations noted).
- The output files produced and their sizes.
- Any deviations from the Lecture 3 patches, with the reason for each.

---

## 10. References (`10-references.md`)

Every claim in the report should be backed by a citation. List each here, deduplicated:

- The OWASP Top 10 2021 entries cited (A01, A03, A05, A07, A08, A10).
- The OWASP Cheat Sheets cited.
- The CWE entries cited (every CWE in the eight finding files).
- The CVEs cited (one or two per finding).
- The PortSwigger Academy topic pages cited.
- The MDN pages cited (HTTP, CSP, headers).
- The Python stdlib documentation cited (`subprocess`, `secrets`, `sqlite3`, `pickle`, `json`, `urllib.parse`).

---

## 11. README.md cover

The repo's top-level `README.md`. One page covering:

- The engagement title.
- The dates.
- The engineer (you).
- A two-sentence summary of what is inside.
- A reading-order pointer: "Read in this order for the fastest understanding: README.md → 08-executive-summary.md → 03-exploit-walkthrough/ → 04-patched-application/ → other artifacts as needed."
- A link to your Week 4, 5, 6, 7, 8 repos / portfolio README.

---

## Acceptance criteria

- All files in § 2's tree exist and are populated.
- `01-engagement-roe.md` is signed and dated.
- `02-vulnerable-snapshot/` contains the original starter files unmodified.
- `03-exploit-walkthrough/` has ten finding files, each in the structure of § 4.
- `04-patched-application/regression_test.py` (unchanged from the starter) reports `9/9 exploits closed` when run against the patched application.
- `04-patched-application/app.py` includes the security-headers after-request hook and the rate limiter.
- `04-patched-application/init_db.py` writes Argon2id password hashes, not plaintext.
- `05-csp-design.md` and `06-zap-vs-burp.md` are polished versions of the challenge deliverables.
- `07-regression-report.md` documents both runs (before and after) with timestamps.
- `08-executive-summary.md` is one printed page.
- Every CVE referenced has a working NVD link.
- The repo passes a "first-five-minutes" test: a reviewer can land on the README, follow the reading-order pointer, and have a clear picture of the engagement within five minutes.

---

## Style and voice

- **Editorial, sober, professional.** This document goes in a portfolio that hiring managers read. Write it for them.
- **No emojis.** Same reason.
- **Cite primary sources** for every CVE, every OWASP reference, every methodology claim.
- **Distinguish confirmed from inferred** in every finding. Every finding in this lab is *confirmed* (the regression script proves the exploit and proves the patch); say so explicitly.
- **Imperative voice in recommendations.** "Replace pickle with JSON," not "the developer may wish to consider replacing pickle."
- **No hyperbole.** The Werkzeug debugger RCE is "critical (CVSS 9.8)." Everything else is high, medium, or low. The CVSS scores in the findings should match the canonical OWASP / NVD severity for the class.

---

## Common failure modes

1. **The RoE is dated after the first exploit.** Reviewers notice file timestamps. Write the RoE first; commit it first.
2. **The findings reference CVEs that do not match the bug class.** Verify each CVE on NVD; the CWE on the CVE entry must match the CWE in the finding.
3. **The executive summary is a technical summary.** The exec summary is for non-technical readers; the technical summary belongs in `03-exploit-walkthrough/`.
4. **The patched lab still has `debug=True`.** Check the bottom of `04-patched-application/app.py`. This is the single most-common regression in past cohorts' submissions.
5. **The regression report claims 9/9 but pasted output shows 8/9 or 7/9.** Re-run, re-paste. The "9/9" line is the headline; if it is not there, the report is incomplete.
6. **The references section is missing.** Citations are not optional.

---

## Stretch

If you finish the core deliverable with time left:

- **Add a "blue-team mirror" section** to each finding in `03-exploit-walkthrough/`: for each finding, describe what a defender's logs / SIEM / WAF would see, and what an alert tuned to this attack would look like.
- **Run the ZAP baseline scan in CI.** Write a GitHub Actions workflow that, on every push to the repo, starts the patched lab in a container, runs `zap-baseline.py` against it, and fails the build if any high-severity finding appears. Commit the workflow file to the repo.
- **Containerise the lab.** Write a `Dockerfile` for the patched application. The container should run as a non-root user, expose only the lab port, and not bundle development tools. The Dockerfile is itself a finding-worthy artifact for the portfolio.
- **Publish the report.** Push the repo public (after verifying you have not committed real secrets). The lab is a teaching artifact; the patched version is genuinely useful as a reference; pushing it lets future C6 learners see what good looks like.
- **Write a one-page "what would I add for production"** appendix mapping the lab to a real production deployment. CSRF tokens; structured logging to a SIEM; rate limiting at the load-balancer tier; secrets in a vault; container hardening; OS hardening; alerting tuned to the finding classes. The appendix is the bridge between "the lab is patched" and "the application is production-ready."
