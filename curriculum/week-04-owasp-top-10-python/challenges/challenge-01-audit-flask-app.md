# Challenge 1 — Audit a Flask App for the OWASP Top 10

**Estimated time:** ~4 hours. Python 3.11. Local only.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The target application is deliberately vulnerable. Run it on       │
│  127.0.0.1 only. Do not expose it to the internet. Do not run the   │
│  attack payloads from this challenge against any service you do     │
│  not operate.                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

A small open-source project, `notebox` — a single-file Flask "shared notes" application a hypothetical company is considering deploying — is on your audit queue. The team has asked you for a Top-10 audit before they roll it out.

You will:

1. Stand the app up locally.
2. Read its source from top to bottom.
3. Walk each OWASP Top 10 2021 category against the source, noting every finding.
4. Confirm the highest-severity findings with a proof-of-concept on your local instance.
5. Produce an audit report and one finding file per finding.

This challenge covers all ten categories at once; you may not find every category in this codebase, but you must *check* every category and record the result.

---

## The application — `notebox.py`

Create the file `notebox.py`. This is the target code. Read it now — *before* the audit instructions — and form your own list of suspicious lines. The audit method will then ask you to walk the categories in order and confirm.

```python
import hashlib
import logging
import os
import pickle
import sqlite3
import subprocess
import time
from urllib.parse import urlparse
import requests
from flask import Flask, request, session, redirect, render_template_string, abort

app = Flask(__name__)
app.secret_key = "supersecret123"          # 1
app.config["DEBUG"] = True                  # 2

DB = "notebox.db"
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("notebox")

def get_db():
    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        )
    """)
    # Default admin — change-on-first-login is *not* enforced.
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password, is_admin) VALUES (1, 'admin', ?, 1)",
        (hashlib.md5(b"admin").hexdigest(),)  # 3
    )
    conn.commit()
    return conn

@app.route("/")
def index():
    name = request.args.get("name", "guest")
    return f"<h1>Welcome, {name}!</h1>"      # 4

@app.route("/register", methods=["POST"])
def register():
    u, p = request.form["username"], request.form["password"]
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (u, hashlib.md5(p.encode()).hexdigest()),   # 5
        )
        db.commit()
    except sqlite3.IntegrityError:
        return ("exists", 409)
    log.info(f"new user {u} registered with password {p}")   # 6
    return ("ok", 201)

@app.route("/login", methods=["POST"])
def login():
    u, p = request.form["username"], request.form["password"]
    db = get_db()
    q = f"SELECT id, is_admin FROM users WHERE username='{u}' AND password='{hashlib.md5(p.encode()).hexdigest()}'"  # 7
    row = db.execute(q).fetchone()
    if not row:
        return ("no", 401)
    session["uid"] = row[0]
    session["is_admin"] = bool(row[1])
    session["sid"] = f"{int(time.time())}-{row[0]}"   # 8
    return ("ok", 200)

@app.route("/note/<int:nid>")
def get_note(nid):
    if "uid" not in session:
        abort(401)
    db = get_db()
    # No ownership check.
    row = db.execute("SELECT id, user_id, title, body FROM notes WHERE id=?", (nid,)).fetchone()  # 9
    if not row:
        abort(404)
    return {"id": row[0], "user_id": row[1], "title": row[2], "body": row[3]}

@app.route("/admin/users")
def admin_users():
    if "uid" not in session:
        abort(401)
    # No is_admin check.
    db = get_db()
    rows = db.execute("SELECT id, username, password, is_admin FROM users").fetchall()  # 10
    return {"users": [{"id": r[0], "username": r[1], "password_md5": r[2], "is_admin": bool(r[3])} for r in rows]}

@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    r = requests.get(url, timeout=5)         # 11
    return r.text[:1024]

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)  # 12
    return out.stdout

@app.route("/cart/restore", methods=["POST"])
def restore_cart():
    blob = request.get_data()
    cart = pickle.loads(blob)               # 13
    return f"loaded {len(cart)} items"

@app.route("/render")
def render_snippet():
    s = request.args.get("s", "Hello")
    return render_template_string(s)         # 14

@app.errorhandler(500)
def err(e):
    # Returns full traceback to the client.
    import traceback
    return ("<pre>" + traceback.format_exc() + "</pre>", 500)   # 15

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)       # 16
```

Also create `requirements.txt`:

```
flask==2.0.0
requests==2.25.0
```

The pinned versions are old and known-vulnerable — that is part of the audit surface (`A06`).

Install and run (in a venv):

```bash
pip install -r requirements.txt
python notebox.py
```

(For the audit, *do not* `pip install` the latest versions — the point is to find the A06 finding against the pinned versions.)

---

## Audit method — walk all 10 categories

For each OWASP Top 10 2021 category, in order, do the following:

1. **Re-read** the relevant section of the lecture notes.
2. **Search** the source for the textual patterns associated with the category (see hints below per category).
3. **Reason** about the code paths.
4. **If a finding exists**, write it up. **If not**, record the negative result.

Per-category hints (do not look at the line-number comments in the source until you have done your own pass):

| Category | Search for / think about |
|---|---|
| `A01 Broken Access Control` | `session`, `uid`, `is_admin`, routes that should check ownership |
| `A02 Cryptographic Failures` | `hashlib.md5`, `hashlib.sha1`, plain-secret in `app.secret_key`, plaintext fields in DB |
| `A03 Injection` | f-strings into SQL (`q = f"..."`), `render_template_string`, `subprocess` with `shell=True` |
| `A04 Insecure Design` | The default admin / admin / md5(admin) credential is a design choice; missing rate limits; missing role separation |
| `A05 Security Misconfiguration` | `DEBUG=True`, `host=0.0.0.0`, missing CORS, missing security headers, error handler that returns tracebacks |
| `A06 Vulnerable and Outdated Components` | `requirements.txt` — run `pip-audit -r requirements.txt` |
| `A07 Identification and Authentication Failures` | Password hashing, session ID generation, lack of rate limiting, default admin |
| `A08 Software and Data Integrity Failures` | `pickle.loads` on `request.get_data()`; missing signed cookies |
| `A09 Security Logging and Monitoring Failures` | `log.info(f"... {p}")` — logging the plaintext password! Missing auth-event logs (success/fail), missing structured logs |
| `A10 Server-Side Request Forgery (SSRF)` | `requests.get(url)` with `url` from `request.args` |

---

## Deliverables

### `audit-report.md`

A single audit cover document, 600-1000 words, structured:

```markdown
# `notebox` — Application Security Audit, Week 4 Challenge

**Auditor:** <your name>
**Date:** YYYY-MM-DD
**Application version:** notebox.py (commit hash if you put it in a repo) plus requirements.txt
**Methodology:** OWASP Top 10 2021 walk, manual code review plus `bandit` / `semgrep` / `pip-audit`.

## Executive summary

One paragraph (60-100 words). What you found at the highest level. *Do not* hide
the bottom line — if the app should not be deployed, say so in the first sentence.

## Scope and method

One paragraph on what you looked at and how. Note explicitly that you did not
test against any live deployment and did not interact with any service you do
not operate.

## Findings summary table

| ID | Title | OWASP | CWE | Severity |
|---|---|---|---|---|
| F-01 | ... | A03:2021 | CWE-89 | Critical |
| F-02 | ... | A01:2021 | CWE-639 | High |
| ... |

## Risk-ordered finding list (one line each, linking to findings/)

| F-01 | <title>     | [findings/F-01-A03-injection.md](./findings/F-01-A03-injection.md) |

## Categories with no finding

For every OWASP Top 10 2021 category where you found *no* issue, record the
negative result with a sentence on why. ("A09: notebox does some logging but
it is f-string concatenation and logs plaintext passwords — finding F-09."
versus "A09: not applicable — this code does no logging at all.")

## Recommendations, ordered

A short ordered list (5-8 items) of what the team should do, in priority
order, before deploying the app.
```

### `findings/F-NN-<category>-<short>.md`

One file per finding. Standard format:

```markdown
# F-NN — <title>

**OWASP Top 10 2021:** A0X:2021 <category name>
**OWASP Top 10 2025 (RC):** A0X:2025 (or "category retained / renamed / merged — see notes")
**CWE:** CWE-NN <name>
**MITRE ATT&CK:** TXXXX (if applicable)
**Severity:** Critical / High / Medium / Low
**Status:** Open

## Location

File: `notebox.py`
Line(s): NN-NN

```python
# the vulnerable code, ~3-8 lines
```

## Description

What the vulnerability is, in 1-3 sentences. Anchor to the line(s) above.

## Proof of concept

The exact request, command, or input that demonstrates the bug. *On your local
127.0.0.1 instance only.*

```bash
curl ...
```

Expected output / observed output.

## Impact

What the attacker gains from this finding. 1-3 sentences. Tie to the asset
they reach (database row? credentials? RCE? other-tenant data?).

## Remediation

The fix, with the patched code side by side with the vulnerable code.

```python
# fixed version
```

## References

- OWASP Top 10 2021 A0X: <link>
- OWASP Cheat Sheet: <link>
- CWE-NN: <link>
- (If applicable) the relevant Cheat Sheet, RFC, or vendor advisory.
```

### `notes/`

Raw tool output as evidence:

```
notes/bandit-output.txt          # `bandit -r notebox.py > notes/bandit-output.txt`
notes/semgrep-output.txt          # `semgrep --config p/owasp-top-ten notebox.py`
notes/pip-audit-output.txt        # `pip-audit -r requirements.txt`
notes/manual-review.md            # 200-400 words on what you found by reading that the tools missed
```

---

## Expected severity distribution

This codebase is deliberately seeded; a reasonable audit will find at least:

- **2+ Critical** findings (RCE-class — `pickle.loads`, `subprocess shell=True`, SSTI).
- **3+ High** findings (SQLi, broken access control, default admin credential).
- **3+ Medium** findings (MD5 passwords, predictable session IDs, debug-mode-in-prod, missing headers).
- **1+ Low / Info** findings (logging plaintext, broad error responses).

If your audit produces fewer than ~10 findings, you missed some. If it produces ~15, you covered the ground. If it produces 25+, you are probably double-counting; merge variations of the same bug.

---

## Acceptance criteria

- [ ] `notebox.py` and `requirements.txt` cloned and runnable locally on `127.0.0.1`.
- [ ] At least one finding for at least seven of the ten OWASP categories (some categories may legitimately have no finding; that fact is *recorded* with a sentence).
- [ ] Every finding has a CWE ID and a MITRE ATT&CK ID where applicable.
- [ ] At least three findings have a working proof-of-concept against the local instance.
- [ ] Every finding has a remediation with side-by-side vulnerable vs. fixed code.
- [ ] `bandit`, `semgrep`, and `pip-audit` output captured.
- [ ] `audit-report.md` is 600-1000 words, with the sections above.
- [ ] No code or attack was run against a remote service.

## Why this challenge

The mini-project asks you to *patch* all ten categories; the challenge asks you to *find* them. The two are different skills — patching is editing, auditing is reading — and the audit is the harder one in a hiring interview. A finding written in the standard format (title, location, severity, CWE, OWASP, PoC, impact, remediation, references) is a finding any application-security team will accept as-is in their tracker. Practising the *format* is half the value of this challenge.
