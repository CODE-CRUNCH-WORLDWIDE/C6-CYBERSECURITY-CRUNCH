# Week 4 Homework

Six problems, ~6 hours total. Commit each in your Week 4 repo. The exercises were guided drills; the homework is closer to the work an application-security engineer does on a Monday.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Run every payload, scanner, and proof-of-concept on machines you   │
│  own — the lab app, the exercise scripts, your own local copy of    │
│  any open-source project. Do not test any technique on a remote     │
│  service you do not operate.                                        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Problem 1 — Map all 10 categories to CWE and ATT&CK (30 min)

Write `notes/owasp-to-cwe-attack.md` containing a table:

| OWASP 2021 ID | Category name | OWASP 2025-RC mapping | Primary CWE(s) | ATT&CK technique(s) |
|---|---|---|---|---|
| A01:2021 | Broken Access Control | (note if the 2025-RC keeps, renames, merges) | CWE-285, CWE-639, CWE-862 | T1190, T1078 |
| ... |

All ten rows. The "2025-RC mapping" column may be partly speculative — track the OWASP project page and cite what the project says at the time of submission. Where the 2025-RC has not been finalised, say so.

**Acceptance.** All ten rows. Every cell is sourced — cite the OWASP page, the CWE page, and the ATT&CK page you took the mapping from.

---

## Problem 2 — Patch a real OWASP Cheat Sheet finding (45 min)

Pick *one* OWASP Cheat Sheet you have not yet read in depth:

- SQL Injection Prevention
- Authentication
- Password Storage
- Session Management
- Cross-Site Scripting Prevention
- Access Control
- Server-Side Request Forgery Prevention
- Deserialization
- Logging

Read it end to end. Then look at your **own** prior code — a C1 project, a C16 mini-project, anything you have written — and find one place where you violated a Cheat Sheet recommendation.

Write `notes/hw2-cheatsheet-finding.md`:

1. Name the Cheat Sheet and the specific recommendation you violated. Quote it (with the section number).
2. Show the *original* code (with a commit link if possible). Be honest about your past code; this is calibration, not judgement.
3. Show the *patched* code.
4. In 100-200 words, explain what you would do differently when writing similar code in the future.

**Acceptance.** Real personal code (not invented). The Cheat Sheet recommendation is quoted, not paraphrased. The patch is shown side-by-side with the original. The reflection is 100-200 words and is about your own habit, not about the abstract category.

---

## Problem 3 — `bandit` and `semgrep` on a real Python project (1 hour)

Pick a small Python project from GitHub — your own, or a public one you actually use (Flask is ~70 kLoC and *will* produce findings; pick something smaller like a single-developer CLI utility). Clone it. Run:

```bash
bandit -r .                                       > notes/hw3-bandit.txt
semgrep --config p/owasp-top-ten .                > notes/hw3-semgrep.txt
pip-audit -r requirements.txt --strict || true    > notes/hw3-pip-audit.txt
```

Write `notes/hw3-tooling.md`:

1. **The project.** Name, version (commit hash), language stats (`tokei .` or `scc .`).
2. **Bandit findings.** Bucket by severity (High / Medium / Low) and confidence. For *each* High finding, write a one-paragraph triage: is it a true positive, a false positive, a "won't fix" with documented reason, or a real bug to file? Cite line numbers.
3. **Semgrep findings.** Same triage shape. Note where Semgrep caught what Bandit missed (or vice versa).
4. **`pip-audit` findings.** For each CVE, name it, name the fixed version, and assess applicability — is the vulnerable code path reachable in *this* project's use, or is the vulnerable function unused?
5. **One paragraph of reflection.** What would you do differently if this project were yours from the start?

**Acceptance.** Tool outputs captured. At least three findings triaged in detail. The "applicability" assessment for `pip-audit` is *reasoned*, not just "yes/no." If the project produced zero findings, pick a larger or older project — zero findings means the tools were not exercised.

---

## Problem 4 — Write the "10 minutes of code I'd ship" against a fresh Flask scaffold (1 hour)

You are joining a new project on Monday. The CTO asks you for "the security baseline" — what code you would commit on day one to a fresh Flask scaffold to satisfy the easy 80% of the OWASP Top 10.

In `notes/hw4-flask-baseline/`, produce:

- `requirements.txt` — pinned, with `argon2-cffi`, `flask-talisman`, `flask-limiter`, `flask-login` (or `flask-session`), `defusedxml`, `structlog`, `cryptography`. No `pickle`, no raw `yaml.load`. Include `pip-audit` in a `requirements-dev.txt`.
- `app.py` — a minimal Flask app, ~100-200 lines, with: Talisman security headers, structured JSON logging via `structlog`, per-route `flask-limiter` rate limits on auth, `flask-login` with Argon2id passwords, deny-by-default auth-required, a CORS policy with a tight origin list, a `/healthz` opt-out.
- `settings.py` — env-driven `SECRET_KEY`, `DEBUG`, `DATABASE_URL`, `ALLOWED_HOSTS`. Fail closed on missing values.
- `README.md` — 200-400 words: which OWASP categories this baseline addresses, which it explicitly does not (A06 needs CI, A04 needs design review, A08 needs Sigstore at release time, A09 needs an aggregator), and what the *next* engineer should add.

**Acceptance.** The scaffold runs (`python app.py`). `bandit` and `semgrep` produce zero findings against it (or you document any that remain with a one-line justification). The README explicitly maps the baseline to OWASP categories.

---

## Problem 5 — One real CVE, reproduced and patched in your own lab (1.5 hours)

Pick one published Python CVE from the last 24 months. Suggestions (verify each is still in the OSV / NVD records before using):

- `Werkzeug` debugger PIN attacks
- `Jinja2` SSTI sandbox escapes (older but useful)
- `aiohttp` request smuggling
- `gunicorn` HTTP smuggling
- `PyYAML` "everything loaded" cases against old versions
- `lxml` XXE residue in older versions
- `requests` certificate verification edge cases
- `Flask` extension CVE of your choice

In `notes/hw5-cve.md`:

1. The CVE ID, the affected versions, the fixed version, and the OSV link.
2. The CWE the CVE is classified under, and the OWASP Top 10 category it maps to.
3. A *local* reproduction: install the vulnerable version in a venv, write the smallest reproducer that triggers the bug, run it, capture the output.
4. Install the fixed version. Re-run the reproducer. Capture the output showing the bug is gone.
5. A 200-400 word write-up: what the bug was, what the attacker gained, how the fix addresses it, and whether the fix is a *patch* (closes the bug class for this code path) or a *workaround* (closes this specific reproducer; further bypasses possible).

**Acceptance.** The CVE is real and verifiable. The reproducer runs in a fresh venv and demonstrates the bug. The before-and-after output is captured. The write-up distinguishes patch from workaround.

---

## Problem 6 — Threat model a real Python service through the Top 10 lens (1.5 hours)

Take one of the Python web services you produced earlier in C6 — your C1 project, your C16 capstone, your Week 4 mini-project once it is patched — and produce a Top-10-shaped audit memo of it.

In `notes/hw6-self-audit.md`:

1. **The service.** Name, repo link, commit hash, deployment model.
2. **The Top 10 walk.** For each category, in order: *is this category present in my service, and where?* For categories that apply, write a one-paragraph finding (location, severity, fix-status). For categories that do not apply, write a one-sentence negative result with reasoning ("A10 SSRF — service does not fetch any URL based on user input; not applicable").
3. **The compound findings.** Categories that *interact* in your code — e.g. an A01 bug that is only severe because of an A09 absence. List two or three.
4. **The "ship blocker."** If you were the security engineer on this team, what *single* finding would you mark as blocking deployment? Justify.
5. **The roadmap.** A short ordered list of the next five things you would fix.

**Acceptance.** Real service. All ten categories addressed (finding or negative result). The compound section names real interactions, not "A01 + A09 are both bad." The ship-blocker has a one-paragraph justification.

---

## Time budget

| Problem | Time |
|---------|------|
| 1 — Top 10 ↔ CWE ↔ ATT&CK | 30 min |
| 2 — Cheat-sheet finding in your own code | 45 min |
| 3 — bandit + semgrep + pip-audit on a real project | 1 h |
| 4 — Flask security baseline | 1 h |
| 5 — Real CVE reproduced and patched | 1.5 h |
| 6 — Top-10 self-audit of your own service | 1.5 h |
| **Total** | **~6 h** |

When done, push the Week 4 homework and start (or continue) the [mini-project](./mini-project/README.md).
