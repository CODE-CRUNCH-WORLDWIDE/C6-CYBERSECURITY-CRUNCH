# Week 8 Homework

Six problems, ~6 hours total. Commit each in your Week 8 repo. The exercises were guided drills against the lab; the homework is closer to the daily work of an application-security engineer reading a real codebase under an RoE.

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  Every problem operates against your own loopback (the vuln_lab     |
|  on 127.0.0.1:5000), your own working copy of an open-source        |
|  application you have downloaded for local review, or a             |
|  PortSwigger Web Security Academy lab (where PortSwigger explicitly |
|  authorises the activity in their published Terms of Service).      |
|  Problems 4 and 6 are desk work and require no live testing.        |
+---------------------------------------------------------------------+
```

---

## Problem 1 — Write a per-bug-class playbook (45 min)

Create `notes/hw1-playbook.md`. For each of the eight bug classes in the lab — SQLi, reflected XSS, stored XSS, command injection, IDOR, missing function-level authz, insecure deserialization, SSRF — produce a one-page section with:

- **Detection signal.** What in a code review (the grep, the audit, the lint rule) reveals the bug class.
- **Canonical payload.** The smallest payload that proves the bug. (The Lecture 2 payloads are fine.)
- **Canonical patch.** The smallest patch that closes the bug. (The Lecture 3 patches are fine.)
- **Anti-patches** — at least two well-meaning fixes for this class that *do not work* and why. (E.g. for XSS: blacklisting `<script>`. For SQLi: regex-filtering apostrophes.)
- **One real CVE in the wild** that exhibits this bug class. Cite the CVE ID and link to NVD.

**Acceptance.** Eight sections, each with the five anchors filled in. CVEs are real and dated.

---

## Problem 2 — Complete three PortSwigger Web Security Academy labs (90 min)

Pick three of the following labs from the free PortSwigger Web Security Academy:

- Any "SQL injection" lab from <https://portswigger.net/web-security/sql-injection/lab>. Start with "SQL injection vulnerability in WHERE clause allowing retrieval of hidden data" if you are new to the academy.
- Any "Cross-site scripting" lab from <https://portswigger.net/web-security/cross-site-scripting/lab>. Start with "Reflected XSS into HTML context with nothing encoded."
- Any "Access control" lab from <https://portswigger.net/web-security/access-control/lab>. Start with "Unprotected admin functionality."
- Any "SSRF" lab from <https://portswigger.net/web-security/ssrf/lab>. Start with "Basic SSRF against the local server."
- Any "Insecure deserialization" lab from <https://portswigger.net/web-security/deserialization/lab>. (Note: these are Java-based and more challenging than the lab; the in-week pickle exercise transfers conceptually.)

For each lab you complete, write `notes/hw2-lab-<slug>.md` containing:

- The lab URL.
- Your solution (the request and payload you used).
- The CWE the lab demonstrates.
- One sentence on what the lab taught you that vuln_lab did not.

**Acceptance.** Three solved labs, three write-ups. The lab's "Solved" indicator is the verification.

**RoE reminder.** The PortSwigger Academy explicitly authorises testing of *the academy's labs only* under their Terms of Service. You may not transfer the techniques to any other host.

---

## Problem 3 — Build a `pytest` version of the regression script (60 min)

The Exercise 3 script uses a hand-rolled assertion loop. Rewrite it as a pytest test suite:

- `notes/hw3/test_regression.py` (or wherever pytest discovers tests in your project layout).
- Each test function is decorated with `pytest.mark.regression`.
- Each test asserts the patched-lab behaviour using `assert` statements.
- A `conftest.py` provides a `lab_url` fixture (default `http://127.0.0.1:5000`, overridable via `--lab` CLI arg).
- A pytest plugin or marker enforces the "loopback only" guard from the Exercise 3 script.

Run with:

```bash
pytest notes/hw3/ --lab http://127.0.0.1:5000 -v
pytest notes/hw3/ --lab http://127.0.0.1:5000 --junitxml=hw3-results.xml
```

The JUnit-XML file is the artifact you commit alongside the test source.

**Acceptance.** `pytest` runs successfully against the patched lab; all eight tests PASS; the JUnit XML is committed.

---

## Problem 4 — Threat model the vuln_lab (60 min)

Apply the Week 3 threat-modelling method (STRIDE per element, or the data-flow-plus-trust-boundary technique you learned then) to vuln_lab as patched. Write `notes/hw4-threat-model.md`:

- A data-flow diagram (ASCII art is fine) of the lab: browser → Flask → SQLite, with the trust boundary on the network and the trust boundary at the database driver.
- A STRIDE-per-element table: for each of the seven endpoints (login, profile, search, comments, lookup, thumbnail, import-profile, fetch-image), list the STRIDE categories that apply and the mitigations in the *patched* lab that address them.
- A "residual risk" section: what threats remain even with all the Lecture 3 patches applied? Three or four specific ones, each with a CWE.
- A "what would I add for production" section: at least five specific changes you would make for a real production deployment (e.g. CSRF tokens, structured logging, container hardening, secrets in a vault, monitored alerting).

**Acceptance.** The threat model is concrete, not generic. Each STRIDE entry names the specific bug or mitigation, not the abstract category.

---

## Problem 5 — Read and summarise the OWASP SSRF Prevention Cheat Sheet (45 min)

Read <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> in full. In `notes/hw5-ssrf-summary.md`, ~600 words covering:

- A plain-English summary of the cheat sheet's structure (each top-level section in one sentence).
- The cheat sheet's "Defense Option 1: Application Layer" recommendations, summarised in your own words.
- The cheat sheet's "Defense Option 2: Network Layer" recommendations, summarised in your own words.
- An honest assessment of which of the cheat sheet's recommendations the *vuln_lab patch* (Lecture 3 § 8) implements and which it does not. Be specific.
- One real-world breach mechanism (the Capital One 2019 incident, the Microsoft Exchange ProxyLogon 2021 chain, or another SSRF-rooted breach you find) summarised in 100-150 words. Cite a primary source (a vendor postmortem, the SEC filing, a CISA advisory) — not a news article.

**Acceptance.** The summary is in your own words, not pasted. The breach summary cites a primary source.

---

## Problem 6 — Write a one-page disclosure email (45 min)

You have discovered a SQL injection on a website operated by Acme Corp, a fictional company you know nothing else about. The website has a `security.txt` (per RFC 9116) at `https://acme.example/.well-known/security.txt` listing a security contact email `security@acme.example`.

Write `notes/hw6-disclosure-email.md`: the email you would send to that address.

Include:

- A subject line.
- The technical finding: endpoint, payload, observed response, CWE. (Invent reasonable details; you have not actually scanned Acme.)
- The recommended fix (parameterised queries).
- A disclosure timeline you would propose (e.g. 90 days to public disclosure, the standard).
- An offer to coordinate.
- Your contact information (use a placeholder).
- A reminder that you have *not* exfiltrated data, *not* tested beyond the scope of `security.txt`, and *not* shared the finding with anyone else.

The voice should match what a real disclosure email looks like. Read at least three published disclosures from the CERT/CC archive or HackerOne's disclosed reports before writing. (The CERT/CC vulnerability notes are at <https://www.kb.cert.org/vuls/>; HackerOne's public disclosures at <https://hackerone.com/hacktivity>.) The disclose.io template at <https://disclose.io/> is the canonical starting point.

**Acceptance.** The email is one printed page, professional in register, factually specific in the technical section, and explicitly cites the `security.txt` as the authority for the contact. The proposed timeline is reasonable. The closing reminder language matches the safe-harbour language in the disclose.io template.

**RoE reminder.** This is a *desk exercise*. Acme is fictional. Do not actually send an email to any company saying you have found a vulnerability unless you actually have, you actually own the vulnerability disclosure, and the company actually invites the report. Doing otherwise — even in good faith — risks misunderstanding and legal exposure.

---

## Submission

Commit:

- `notes/hw1-playbook.md`.
- `notes/hw2-lab-<slug>.md` × 3 (one per PortSwigger lab).
- `notes/hw3/test_regression.py` and `notes/hw3-results.xml`.
- `notes/hw4-threat-model.md`.
- `notes/hw5-ssrf-summary.md`.
- `notes/hw6-disclosure-email.md`.

Total time budget: 6 hours. If you find a problem running over, write down where the time went; the reflection is useful in its own right.

---

## Grading rubric

Each problem is worth 1 point. Total: 6.

| Score | Standard |
|------:|----------|
|     1 | Meets every "Acceptance" criterion; voice is professional; sources cited primarily. |
|   0.5 | Meets most acceptance criteria; voice acceptable; sources mixed primary/secondary. |
|     0 | Missing, off-topic, or fundamentally unsound (e.g. exploits a host not authorised). |

A score of 0 on any problem because of unauthorised testing fails the *entire* homework. The RoE is non-negotiable.

Aim for 6/6. Submit before Sunday end-of-day.
