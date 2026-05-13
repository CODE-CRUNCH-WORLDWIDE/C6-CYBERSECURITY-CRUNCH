# Mini-Project — Patch the OWASP Top 10 in a Deliberately Vulnerable Python App

> Produce ten commits, or ten pull requests, against a deliberately vulnerable Python web application — one per OWASP Top 10 2021 category — with a security write-up per fix. The repo, at the end, is the artifact a hiring manager reads alongside your Week 1, 2, and 3 portfolio outputs.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The lab app is deliberately vulnerable. Bind to 127.0.0.1. Do not  │
│  expose it to the public internet at any point, even briefly, even  │
│  behind a "secret" port. Do not test the techniques in this         │
│  mini-project against any service you do not operate.               │
│                                                                     │
│  If during this work you find what you believe to be a real         │
│  exploitable vulnerability in an upstream open-source project,      │
│  follow that project's SECURITY.md and the coordinated-disclosure   │
│  rules from Week 3 before publishing anything specific.             │
└─────────────────────────────────────────────────────────────────────┘
```

This mini-project is the synthesis of Week 4. The lectures gave you the categories with side-by-side vulnerable and patched Python. The exercises gave you category pairs in small standalone scripts. The challenge had you audit a small Flask app for all ten categories. The mini-project asks you to *fix* all ten in a larger app — one commit per category, one write-up per fix, all on a public repo (or portfolio subfolder).

**Estimated time:** 7 hours, spread across Thursday-Saturday.

---

## The lab app — `c6-week-04-lab`

The lab app is a deliberately vulnerable Python web application, larger than the challenge target (~600-800 LoC of Flask, SQLAlchemy, Jinja2, plus a small HTML/CSS frontend). It implements a small marketplace — users, items, orders, an admin panel, a "URL preview" feature, a cart import/export — chosen because the surface area touches *every* one of the OWASP Top 10 categories.

A reference implementation will be provided in the C6 organisation repository as `c6-week-04-lab`. If a maintained lab repo is not yet linked from this page, follow the layout described below and build the app yourself from the spec — building the vulnerable app is itself worthwhile preparation.

### Required surface

The app must include, at minimum:

- **Authentication:** registration, login, logout, password reset.
- **Session management:** server-side sessions with an ID stored in a cookie.
- **CRUD on at least two resources:** `items` (public-readable, owner-writeable) and `orders` (private to the buyer).
- **An admin area:** list all users, list all orders, change roles.
- **A URL-fetching feature:** "URL preview" — the server fetches a URL and returns its `<title>`.
- **A serialised import/export:** cart import from JSON or pickle blob; cart export.
- **A "ping" diagnostic endpoint:** runs `ping` against a user-supplied host.
- **A file-upload feature:** avatar upload, stored on disk.
- **An XML import feature:** import items from a user-supplied XML file.
- **A logging story:** the app logs auth and admin events somewhere.

The app must ship *with each of the ten OWASP Top 10 2021 categories represented as at least one vulnerability*. The challenge in Week 4 was a 250-line micro-version of this same shape; the mini-project lab is the full version.

### Required pinned-and-vulnerable dependencies

`requirements.txt` must pin to versions with at least one known CVE (this is the `A06` surface):

- `Flask` to an older version with at least one CVE in OSV.
- `requests` to an older version (the certificate-handling and proxy-honouring edge cases of older `requests` produce real findings).
- `PyYAML` to an older version (the `yaml.load` default behaviour).
- `Jinja2` to an older version (sandbox-escape CVEs).

For each pinned-vulnerable dep, the patch (in the corresponding commit) bumps to the fixed version.

---

## What you will produce

A public GitHub repo named `c6-week-04-owasp-top10-<yourhandle>` (or a subfolder of your portfolio repo) containing:

- `app/` — the lab app source (the *patched* version at the end; commit history shows the journey).
- `README.md` — one-page intro, link to each finding, deployment notes for the local-only deploy.
- `SECURITY-WRITEUP.md` — the cover document (~800-1500 words) tying together the ten findings.
- `findings/` — ten Markdown files, one per OWASP category, each in the standard finding format.
- `tests/` — at least one test per finding that *demonstrates the bug exists* (pre-patch) and *demonstrates the bug is fixed* (post-patch). Pytest.
- `ci/` — GitHub Actions or equivalent: `bandit`, `semgrep`, `pip-audit`, `pytest` on every push.
- `LICENSE` — GPL-3.0 (consistent with C6) or a permissive licence of your choice for the document text.

### The commit / PR shape

The portfolio signal is the *commit history*. Each fix is one PR (or one commit, if you prefer the simpler workflow):

```
PR #1  — A01: enforce resource ownership on /orders/<id> and /admin/*
PR #2  — A02: replace md5(password) with argon2id; add password-rehash on login
PR #3  — A03: parameterise SQL; remove shell=True from /ping; sanitise template rendering
PR #4  — A04: redesign password reset flow with single-use, short-TTL tokens
PR #5  — A05: env-based config, DEBUG=False, security headers via flask-talisman, defusedxml
PR #6  — A06: bump Flask, requests, PyYAML, Jinja2 to patched versions; add pip-audit CI
PR #7  — A07: secrets.token_urlsafe sessions; per-account back-off; HIBP check; TOTP MFA
PR #8  — A08: replace pickle.loads with json+schema; sign cookies; pin CI actions by SHA
PR #9  — A09: structured JSON logs; auth/authz/admin event logging; password redaction
PR #10 — A10: allow-list URL preview; reject private/loopback/link-local; redirects-off
```

Each PR's description is the finding (or links to `findings/F-NN-...md`). Each PR's tests prove the fix works.

---

## The ten findings — required coverage

For each OWASP Top 10 2021 category, the lab app contains at least one finding you must patch and document. The minimum bar:

| ID | OWASP 2021 | Required finding (at minimum) |
|---|---|---|
| F-01 | `A01:2021` Broken Access Control | IDOR on `/orders/<id>` and missing admin check on `/admin/*` |
| F-02 | `A02:2021` Cryptographic Failures | `md5` password hashing; weak/predictable token generation |
| F-03 | `A03:2021` Injection | SQL injection in at least one query; OS command injection in `/ping`; one XSS path; (bonus) SSTI in a render endpoint |
| F-04 | `A04:2021` Insecure Design | Password reset flow with no token expiry, no single-use enforcement; default admin credential |
| F-05 | `A05:2021` Security Misconfiguration | `DEBUG=True`; missing security headers; XXE-permissive XML parser; permissive CORS |
| F-06 | `A06:2021` Vulnerable Components | At least two pinned-vulnerable dependencies with active CVEs |
| F-07 | `A07:2021` Auth Failures | Predictable session IDs; no rate limiting; no MFA path |
| F-08 | `A08:2021` Software & Data Integrity | `pickle.loads` on the cart import endpoint; unsigned client cookies for auth state |
| F-09 | `A09:2021` Logging & Monitoring | f-string string logs; passwords in logs; no auth-event logs; no retention strategy |
| F-10 | `A10:2021` SSRF | URL preview fetches without validation; able to reach `127.0.0.1`, RFC-1918, and metadata-service IPs |

You may add findings beyond these; you may *not* skip any of the ten.

---

## The cover document — `SECURITY-WRITEUP.md`

The cover document (~800-1500 words) ties the ten findings together. Required sections:

### 1. Executive summary (100-150 words)

The state of the application before your work, the state after. The single most-important fix. Whether you would deploy the patched app to production *as is* and what blockers remain.

### 2. Scope (100 words)

The version of the app you audited (commit hash of the *pre-patch* state). The version after (commit hash of the *post-patch* state). The OWASP edition you mapped against (2021, with 2025-RC notes where applicable). What you did *not* audit (out of scope).

### 3. Methodology (200-300 words)

How you walked the categories. What tools you used (`bandit`, `semgrep`, `pip-audit`, manual review). How you ordered the fixes (typically: stop-the-bleeding first — RCE-class fixes — then structural fixes, then defence-in-depth). How tests were written (per finding, demonstrating bug + demonstrating fix).

### 4. The ten findings — short form (200-400 words)

A table or list, one line per finding, linking into `findings/F-NN-*.md`. Include the OWASP ID, the CWE, the severity, the fix in one phrase.

### 5. Cross-cutting observations (100-200 words)

The compound findings. Examples: "the missing A09 logging meant the A07 brute-force was undetected"; "the A05 `DEBUG=True` exposed the A02 `SECRET_KEY` to anyone who triggered a server error." Two or three real interactions.

### 6. Lessons (100-200 words)

What you would change in your own future Python code starting from week one of a new project. Concrete — not "I will be more careful" but "I will start every Flask scaffold from a template with Talisman, Argon2id, structlog, and a `pip-audit` CI gate already wired in."

---

## Findings — `findings/F-NN-<category>-<short>.md`

Each finding is its own file, in the standard format from Challenge 1:

```markdown
# F-NN — <title>

**OWASP Top 10 2021:** A0X:2021 <category>
**OWASP Top 10 2025 (RC):** A0X:2025 (or note: kept / renamed / merged)
**CWE:** CWE-NN <name>
**MITRE ATT&CK:** TXXXX (if applicable)
**Severity:** Critical / High / Medium / Low
**Status:** Fixed in PR #N

## Location

File: `app/foo.py`
Line(s): NN-NN (pre-patch); see PR #N for the patch diff.

## Description

The bug, in 2-4 sentences. Anchored to the lines above.

## Proof of concept (local only)

```bash
curl ...
# expected output: the bug is demonstrated
```

## Impact

What the attacker gains. 1-3 sentences.

## Remediation

The fix, with side-by-side vulnerable vs. patched code (3-10 lines each side).

```python
# before
...

# after
...
```

## Defender-side detection

What log line, what metric, what tool would have caught this in production.

## Residual risk

What is *not* fully fixed by this patch, and what it would take to close it
fully. Examples: "the fix closes SQL injection on the search endpoint; SQL
injection in the admin search remains pending in PR #N+1"; or "the fix relies
on the request reaching the application, which means an in-network attacker
who can spoof the proxy header still bypasses it."

## References

- OWASP Top 10 2021 A0X: <link>
- OWASP Cheat Sheet (if applicable): <link>
- CWE-NN: <link>
- Relevant CVE / RFC / vendor advisory (if applicable).
```

---

## Suggested order of operations

### Phase 1 — Set up (30 min)

1. Clone or scaffold the lab app. Verify it runs on `127.0.0.1` only.
2. Run `bandit`, `semgrep`, `pip-audit` once against the pre-patch state. Save outputs to `notes/initial-scan/`.
3. Skim the source top-to-bottom *before* writing any patches.

### Phase 2 — Read and inventory (1 h)

1. Walk each OWASP Top 10 category against the source.
2. Build the candidate finding list in a scratch file. Aim for at least 10 (one per category), realistically 12-20 (categories with multiple instances).
3. *Do not patch yet.* The patches will be cleaner if you have the full inventory first.

### Phase 3 — Stop the bleeding (2 h)

1. Patch the RCE-class findings first (A08 pickle, A03 OS command injection, A03 SSTI). One PR each.
2. Tests per PR — `tests/test_F03_command_injection.py`, etc. Pre-patch the test fails (the bug exists); post-patch it passes.

### Phase 4 — Structural fixes (2 h)

1. A01 (access control), A02 (Argon2id), A07 (sessions and rate limit), A05 (config and headers). Each as a PR.
2. A04 (redesign the password reset flow) likely lands here too; it crosses A07 and A05 in practice.

### Phase 5 — Defence in depth (1 h)

1. A06 (dependency bumps + `pip-audit` CI).
2. A09 (structured logs, password redaction, auth-event logs).
3. A10 (allow-list URL preview).

### Phase 6 — Documentation (1 h)

1. Write `SECURITY-WRITEUP.md`.
2. Cross-link findings.
3. Re-run all scanners against the *post-patch* state. Save outputs to `notes/final-scan/`. Diff the two — your final scan should show meaningfully fewer findings.
4. Polish, push.

---

## Acceptance criteria

- [ ] Public GitHub repo or portfolio subfolder, named per the convention.
- [ ] Lab app present, runnable locally on `127.0.0.1`, deliberately vulnerable in the pre-patch state.
- [ ] Commit history shows ten distinct patch commits or PRs, one per OWASP Top 10 2021 category.
- [ ] `findings/` directory has ten Markdown files in the standard format.
- [ ] `tests/` directory has at least one test per finding; tests pass against the patched state and fail against the pre-patch state.
- [ ] `ci/` workflow runs `bandit`, `semgrep --config p/owasp-top-ten`, `pip-audit`, and `pytest` on push and on PR.
- [ ] `SECURITY-WRITEUP.md` is 800-1500 words and has the six sections.
- [ ] Every OWASP 2021 category is cited *and* its 2025-RC counterpart referenced where applicable.
- [ ] Every finding has a CWE ID and a MITRE ATT&CK technique ID (where applicable).
- [ ] No code is bound to anything other than `127.0.0.1`.
- [ ] Initial-scan and final-scan tool outputs captured for diffing.
- [ ] No emojis in the document text.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| Coverage of the ten categories | 25% | Every category has a finding; every finding has a real fix; no category is skipped or hand-waved. |
| Finding quality | 20% | Each finding has accurate location, working PoC, side-by-side fix, defender detection, residual risk. |
| Test discipline | 15% | One test per finding; tests fail on the pre-patch state and pass on the patched state; CI runs them. |
| Commit / PR hygiene | 10% | Atomic commits, one per finding; clear commit messages; PR descriptions are the findings. |
| Tool integration | 10% | `bandit`, `semgrep`, `pip-audit` are in CI; their outputs at the start and end are diffed. |
| Cover document quality | 10% | The write-up reads like an analyst memo, not a tutorial. Executive summary defends a position. |
| 2025-RC awareness | 5% | Citations to the 2025-RC are present and accurate as of submission date. |
| Voice and primary sources | 5% | Cite OWASP, CWE, ATT&CK, and primary advisories. No vague "experts say." |

---

## Why this matters

A junior application-security engineer who can produce *this artifact* — a deliberately vulnerable Python app, audited and patched against the OWASP Top 10, with tests, a CI gate, and an analyst-voice write-up — clears the most common technical interview screen at any application-security team. The artifact is also reusable: the same repository, with the lab swapped for a real product, is the shape of every audit memo you will write for the rest of your career.

Together with the Week 1 threat model, the Week 2 PCAP brief, and the Week 3 full threat model, this is the spine of your C6 portfolio at the end of Phase 2's first week.

---

## Submission

Push to GitHub. Link the repo from your C6 portfolio README. Make sure the repo is public, the README explains the (deliberately vulnerable) starting state, the lab is bound to `127.0.0.1` by default, and the security write-up reads cleanly cold.

Then return to the Week 4 [README](../README.md) and tick this off your checklist. Week 5 is Secure Coding in Python — zooming in on the Python-specific coding hazards (pickle, yaml, ReDoS, insecure randomness, the `bandit` / `semgrep` / `pip-audit` toolchain) that overlap with but do not duplicate the Top 10.
