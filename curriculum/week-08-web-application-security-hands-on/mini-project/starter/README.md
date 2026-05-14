# vuln_lab - starter

> The as-shipped vulnerable Flask application for C6 Week 8. Eight intentional OWASP-Top-10-class bugs across nine endpoints, all of which are exploited in Lecture 2 and patched in Lecture 3.

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  This application contains deliberate vulnerabilities. It binds to  |
|  127.0.0.1 only. Do not change the bind address. Do not deploy.     |
+---------------------------------------------------------------------+
```

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 init_db.py
# In separate terminals (with the venv activated):
python3 metadata_server.py
python3 app.py
# Then, from a fourth terminal:
python3 regression_test.py
```

The regression script reports `0/9 exploits closed` against the as-shipped lab. Apply the patches from `../../exercises/SOLUTIONS.md` (or follow the SOLUTIONS section of the mini-project guide) one at a time. After each patch, restart `app.py` and re-run the regression script. The corresponding test flips from FAIL to PASS. By the end the script reports `9/9 exploits closed`.

## The vulnerabilities (and what to look for)

| Endpoint           | Vulnerability                            | OWASP   | CWE     |
|--------------------|------------------------------------------|---------|---------|
| `/lookup`          | SQL injection via string concatenation   | A03     | CWE-89  |
| `/search`          | Reflected XSS via `Markup()` bypass      | A03     | CWE-79  |
| `/comments`        | Stored XSS via `|safe` template filter   | A03     | CWE-79  |
| `/thumbnail`       | Command injection via `os.system`        | A03     | CWE-78  |
| `/profile`         | IDOR (no ownership check)                | A01     | CWE-639 |
| `/admin/users`     | Missing function-level authorization     | A01     | CWE-306 |
| `/login`           | No rate limit, plaintext pw, weak token  | A07/A02 | CWE-307/256/330 |
| `/import-profile`  | Insecure deserialization via `pickle`    | A08     | CWE-502 |
| `/fetch-image`     | SSRF (no allow-list)                     | A10     | CWE-918 |
| `/debug-trigger`   | Werkzeug debugger RCE (with `debug=True`)| A05     | CWE-489 |

## Seed credentials

```
alice / password123    (role: user, id: 1)
bob   / letmein        (role: user, id: 2)
admin / admin          (role: admin, id: 3)
```

The plaintext-passwords-in-the-database is itself the A02 finding. The patched `init_db.py` writes Argon2id hashes instead.

## Files

```
app.py                 The 8-endpoint Flask application
init_db.py             Schema and seed creator
metadata_server.py     Mock cloud-metadata server (for /fetch-image SSRF)
regression_test.py     Regression suite - the patch rubric
requirements.txt       Flask 3.x, requests, argon2-cffi
templates/             Jinja templates (one per endpoint)
```

## Notes on the seed data

- The `users` table has 3 rows. The `id` column is the IDOR target.
- The `invoices` table has 6 rows (2 per user). The seed exists so the IDOR exploit has something to *return* if you decide to extend the lab.
- The `comments` table is empty at init time. Posts during the stored-XSS exploit populate it.

## Patching this lab

The patches are documented in three places, in increasing depth:

1. `../../lecture-notes/03-defence-csp-patches-and-regression.md` — the canonical write-up of each patch.
2. `../../exercises/SOLUTIONS.md` — exercise-tier patches with explanations.
3. `python3 ../../exercises/exercise-03-patch-and-regress.py --guide` — the patches as printed diffs.

Apply in order P1..P9. The regression script verifies each.

## RoE reminder

The lab is the only authorised target for the Lecture 2 exploit payloads. The same payloads against any other host are crimes under the CFAA (US), CMA (UK), and Directive 2013/40/EU (EU). Treat the script `regression_test.py` with the same care: it fires exploit payloads, and its `--lab` URL must be a loopback address. The script includes a safety guard that refuses non-loopback URLs.
