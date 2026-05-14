# Lecture 3 — Defence, CSP, Patches, and Regression

> *Lecture 2 broke the lab. Lecture 3 ships it. We walk each of the eight findings in the same order Lecture 2 attacked them, write the patch, layer Content Security Policy as defence-in-depth, treat HTTP request smuggling at the conceptual level (the lab cannot demonstrate smuggling and is honest about that), and finish by running the regression script that proves every exploit has been closed. The patches are short — most are three to ten lines — but each one teaches a different lesson about the difference between code that compiles and code that survives an adversary. By the end of this lecture you have the patched application that becomes the deliverable for Friday and Saturday's mini-project.*

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  The patches and the regression script in this lecture run          |
|  against the vuln_lab application on your own laptop. Regression    |
|  tests are themselves exploit attempts; they fire the same          |
|  payloads from Lecture 2. The regression script must be run only    |
|  against the lab on 127.0.0.1:5000, not against any other host.     |
|  Treat the regression script with the same care you treat the       |
|  curl commands in Lecture 2: it is loopback-only.                   |
+---------------------------------------------------------------------+
```

This lecture covers:

1. **A03 SQLi patch** — parameterized queries.
2. **A03 XSS patches** — Jinja autoescape, output context, and `Markup` discipline.
3. **A03 Command injection patch** — `subprocess.run([list], shell=False)`.
4. **A01 IDOR and missing-function-level-authz patches** — ownership checks and role checks.
5. **A05 Security misconfiguration patches** — `debug=False`, credentials, headers.
6. **A07 Authentication patches** — Argon2id passwords, `secrets` tokens, rate limiting.
7. **A08 Insecure deserialization patch** — pickle out, JSON in.
8. **A10 SSRF patch** — allow-list with DNS rebinding resistance.
9. **Content Security Policy** — the header, the directives, the lab's policy.
10. **HTTP request smuggling** — what it is, why the lab cannot demonstrate it, what to read.
11. **The regression script** — how it works, how to run it, what each assertion checks.
12. **A short discussion of defence-in-depth** — why we add CSP on top of the autoescape fix, why we add `HttpOnly` on top of the session-token fix, why we add a WAF-style allow-list on top of the SSRF host-check fix.

Lecture 2's exploit walkthrough and Lecture 3's defence walkthrough are designed as a matched pair. Read them side-by-side if it helps.

---

## 1. A03 SQLi patch — parameterized queries

### 1.1 The fix

```python
@app.route("/lookup")
def lookup() -> str:
    name: str = request.args.get("name", "")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # AFTER: parameterized query — SQL Injection Prevention Cheat Sheet § Defense 1.
    sql: str = "SELECT id, username, email FROM users WHERE username = ?"
    rows: list = cursor.execute(sql, (name,)).fetchall()
    conn.close()
    return render_template("lookup.html", rows=rows, name=name)
```

The change is two characters of code plus one tuple argument: `WHERE username = ?` with `(name,)` passed as a parameter. The database driver — `sqlite3` from the stdlib, in this case — handles the substitution at the protocol level. The user's input never participates in SQL parsing; it is data, the query is syntax, and the two are kept apart.

### 1.2 Why this is the entire fix

Parameterized queries are not a partial defence. They are *the* defence against SQLi. Every well-supported database driver in every language supports them. The OWASP SQL Injection Prevention Cheat Sheet (<https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>) lists "Defense Option 1: Prepared Statements" first because it is the only one that works without surprises.

The variants:

- **Stored procedures** — also work, with the caveat that some procedural-language constructs (Oracle's `EXECUTE IMMEDIATE`, T-SQL's `sp_executesql` with concatenated SQL) can re-introduce injection inside the stored procedure. The defence is *parameterized SQL all the way down*.
- **Allow-list input validation** — works as a defence-in-depth but is fragile alone. Names can contain apostrophes (O'Brien); allowing apostrophes opens the door; the parameterized query is the only sound primary defence.
- **Escaping** — fragile, database-specific, and full of edge cases. Avoid as a primary defence.

### 1.3 What the patch does not fix

The patch fixes the SQL injection. It does not fix:

- **Enumeration via the existence channel.** The endpoint still tells the world "alice exists" with a populated response and "alixe does not exist" with an empty response. That is a username-enumeration bug and is its own finding. (We note it; we do not patch it in the lab. The fix is to return the same response shape for both cases.)
- **The endpoint being public.** No authentication is required to query `/lookup`. That is a separate access-control concern.

Each bug class is its own line item in the report. Do not let one patch claim to fix bugs it does not.

### 1.4 The regression check

`regression_test.py` sends the SQLi payload from Lecture 2:

```python
def test_sqli() -> bool:
    payload: str = "' OR 1=1 --"
    response = requests.get(LAB_URL + "/lookup", params={"name": payload}, timeout=5)
    # On the vulnerable lab, the response contains multiple usernames.
    # On the patched lab, the response shows no rows (the literal string is not a username).
    return "alice" not in response.text and "bob" not in response.text
```

`True` on the patched lab; `False` on the vulnerable lab.

---

## 2. A03 XSS patches — autoescape, context, and `Markup` discipline

### 2.1 The reflected XSS fix at `/search`

```python
@app.route("/search")
def search() -> str:
    q: str = request.args.get("q", "")
    # AFTER: do not wrap user input in Markup(); let Jinja autoescape do its job.
    return render_template("search.html", q=q, results=[])
```

The `Markup` wrapper is gone. Jinja's default autoescape — on for `.html` templates by default in Flask — handles every `<`, `>`, `&`, `"`, and `'` in the value, replacing each with the matching HTML entity. The `<script>` payload renders as `&lt;script&gt;` and the browser sees text, not a tag.

### 2.2 The stored XSS fix at `/comments`

The template change:

```jinja
{% for row in rows %}
  <li>{{ row.body }}</li>
{% endfor %}
```

The `|safe` filter is gone. The comment body is HTML-escaped on render. The server still stores the literal text; the *render* is what protects subsequent viewers.

### 2.3 Output context matters

A common XSS mistake is to assume "escape on output" means "HTML-escape on output." HTML-escape is the right move when the output context is HTML element content. There are other contexts:

- **HTML attribute value:** HTML-escape, but also strip double quotes if you are using double-quoted attributes (and avoid letting user input control the attribute name).
- **JavaScript string literal in a `<script>` block:** JavaScript-escape (e.g. `\x3c` for `<`). HTML-escape is wrong here; the browser parses the `<script>` block as JavaScript, not as HTML.
- **URL parameter:** URL-encode. `&amp;` is wrong; `%26` is right.
- **CSS string literal:** CSS-escape.
- **JSON inside a `<script>` block:** JSON-encode plus a few extra escapes for `<`, `>`, `&` that close-`script`-tag attacks rely on.

The OWASP XSS Prevention Cheat Sheet's "Output Encoding Rules" table (<https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>) is the canonical reference. In Jinja templates the right pattern is to use the appropriate filter for the context: `{{ value }}` for HTML element content, `{{ value | tojson }}` for JSON inside `<script>`, etc.

### 2.4 The `Markup` rule

The single highest-value rule for Flask developers: **never call `Markup()` on a string that contains, transitively, anything that came from a request.** `Markup` is for application-controlled HTML fragments (a footer template the application itself constructs), never for user input.

In code review, every call to `Markup()` and every `|safe` filter is a hotspot. The Week 6 code-review lecture covers exactly this; the Week 8 patch is the application of that lecture's lesson.

### 2.5 What the patches do not fix

The autoescape patches fix the XSS. They do not fix:

- **DOM-based XSS** (Cleve XSS that happens entirely in client-side JavaScript). The lab does not include client-side JS that reads from the URL and writes to the DOM; if it did, no server-side fix would help.
- **A future regression** where a new template uses `|safe` again. The fix is a lint rule.

### 2.6 The regression checks

```python
def test_reflected_xss() -> bool:
    payload: str = "<script>alert(1)</script>"
    response = requests.get(LAB_URL + "/search", params={"q": payload}, timeout=5)
    # On the vulnerable lab, the literal <script> appears in the response.
    # On the patched lab, &lt;script&gt; appears (or any encoded form).
    return "<script>alert(1)</script>" not in response.text


def test_stored_xss() -> bool:
    payload: str = "<script>alert(1)</script>"
    requests.post(LAB_URL + "/comments", data={"body": payload}, timeout=5)
    response = requests.get(LAB_URL + "/comments", timeout=5)
    return "<script>alert(1)</script>" not in response.text
```

`True` on patched; `False` on vulnerable.

---

## 3. A03 Command injection patch — `subprocess.run([list], shell=False)`

### 3.1 The fix

```python
import subprocess

@app.route("/thumbnail")
def thumbnail() -> str:
    filename: str = request.args.get("file", "")
    # AFTER: subprocess.run with shell=False; argv list, no shell parsing — CWE-78 prevented.
    # Plus: allow-list the filename to letters/digits/underscore/dash plus exactly one .
    if not _is_safe_filename(filename):
        return "invalid filename", 400
    result = subprocess.run(
        ["convert", filename, "/tmp/out.png"],
        shell=False,
        capture_output=True,
        timeout=5,
        check=False,
    )
    if result.returncode != 0:
        return "convert failed", 500
    return "done"


def _is_safe_filename(name: str) -> bool:
    """Allow-list filenames: letters, digits, underscore, dash, exactly one dot, no slashes."""
    if not name:
        return False
    if name.count(".") != 1:
        return False
    if "/" in name or ".." in name:
        return False
    stem, _, ext = name.partition(".")
    return stem.replace("_", "").replace("-", "").isalnum() and ext.isalnum()
```

Two layers of defence:

1. **`shell=False` with an argv list.** No shell interprets the argv; metacharacters in `filename` are literal characters to `convert`. `os.exec`-family system call, no shell.
2. **Allow-list validation.** Even with `shell=False`, `convert` might do something useful for an attacker if given an exotic filename (a path traversal to read a file `convert` is willing to read). The allow-list is conservative: alphanumeric stem, single dot, alphanumeric extension, no slashes, no `..`.

### 3.2 Why `shell=True` is the always-wrong choice

`subprocess.run("convert " + filename + " /tmp/out.png", shell=True)` is the `os.system` equivalent in `subprocess`. The Python docs warn: *"If `shell=True`, this is a security hazard if combined with untrusted input."* (<https://docs.python.org/3/library/subprocess.html#security-considerations>.) The rule: `shell=False` plus argv list, every time, no exceptions in production code.

### 3.3 The regression check

```python
def test_command_injection() -> bool:
    # Use a payload that, on the vulnerable lab, creates /tmp/c6-pwned.
    # On the patched lab, the filename is rejected as invalid.
    payload: str = "cat.png; touch /tmp/c6-pwned"
    requests.get(LAB_URL + "/thumbnail", params={"file": payload}, timeout=5)
    return not Path("/tmp/c6-pwned").exists()
```

The regression deliberately picks a probe file (`/tmp/c6-pwned`) and cleans it up at script start. On the patched lab the file is never created. On the vulnerable lab it is.

---

## 4. A01 IDOR and missing-function-level-authz patches

### 4.1 IDOR patch at `/profile`

```python
@app.route("/profile")
def profile() -> str:
    if "user_id" not in session:
        return redirect(url_for("login"))
    requested_id: int = int(request.args.get("id", "0"))
    session_user_id: int = session["user_id"]
    # AFTER: enforce ownership; admins may view any profile.
    if requested_id != session_user_id and not _is_admin(session_user_id):
        return "forbidden", 403
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    row = cursor.execute(
        "SELECT id, username, email FROM users WHERE id = ?",
        (requested_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return "no such user", 404
    return render_template("profile.html", user=row)


def _is_admin(user_id: int) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    row = cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row is not None and row[0] == "admin"
```

The ownership check is the smallest sound IDOR fix. Real applications often layer:

- **Indirect references.** Instead of `?id=2`, the URL is `?id=<random-uuid>`; the server maps the UUID back to the underlying id only if the session user owns it. This is a defence-in-depth posture.
- **Field-level access control.** Even when the user can read *some* of the row, they may not be able to read all fields. The `profile` endpoint here returns the user's own `id`, `username`, `email` — not their `password`. The query reflects this; in real applications the access-control rules are richer.

### 4.2 Missing-function-level-authz patch at `/admin/users`

```python
@app.route("/admin/users")
def admin_users() -> str:
    if "user_id" not in session:
        return redirect(url_for("login"))
    # AFTER: require admin role.
    if not _is_admin(session["user_id"]):
        return "forbidden", 403
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # AFTER: do not return the password column; even admins do not need plaintext passwords.
    rows = cursor.execute("SELECT id, username, email, role FROM users").fetchall()
    conn.close()
    return render_template("admin.html", rows=rows)
```

Two fixes: the role check, and the SELECT no longer pulls the `password` column. The latter is the "least information" rule — even an admin endpoint should not return data the consumer does not need.

### 4.3 The regression check

```python
def test_idor() -> bool:
    session_obj = requests.Session()
    session_obj.post(LAB_URL + "/login", data={"username": "alice", "password": "password123"})
    # Try to view bob's profile (id=2) while logged in as alice (id=1).
    response = session_obj.get(LAB_URL + "/profile", params={"id": 2}, timeout=5)
    # On vulnerable: 200 OK with bob's data.
    # On patched: 403 Forbidden.
    return response.status_code == 403


def test_missing_authz() -> bool:
    session_obj = requests.Session()
    session_obj.post(LAB_URL + "/login", data={"username": "alice", "password": "password123"})
    response = session_obj.get(LAB_URL + "/admin/users", timeout=5)
    return response.status_code == 403
```

---

## 5. A05 Security misconfiguration patches

### 5.1 Remove `debug=True`

```python
if __name__ == "__main__":
    # AFTER: debug=False; never run with debug=True outside the explicit-exploit demonstrations.
    app.run(host="127.0.0.1", port=5000, debug=False)
```

One line. The lecture is one line, the discussion above is a paragraph, the fix is one character. The discipline is the rule, not the code.

### 5.2 Remove default credentials

`init_db.py` is updated to generate a random admin password and print it once at init time:

```python
def _seed_admin(conn: sqlite3.Connection) -> str:
    import secrets
    pw: str = secrets.token_urlsafe(16)
    pw_hash: str = _hash_password(pw)  # Argon2id from the A02 patch.
    conn.execute(
        "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
        ("admin", pw_hash, "admin@lab.local", "admin"),
    )
    return pw
```

The admin password is printed to stdout exactly once at `init_db.py` time. The operator captures it from the terminal. In a real application the equivalent is an out-of-band one-time setup token, never a hard-coded default.

### 5.3 Add security headers

A Flask `@app.after_request` hook:

```python
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    # Strict-Transport-Security applies only over HTTPS; vacuous on 127.0.0.1.
    # response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response
```

Each header's purpose is in the OWASP HTTP Security Response Headers Cheat Sheet (<https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html>). The CSP is the heaviest of the headers and gets its own section below.

### 5.4 Custom 500 handler

```python
@app.errorhandler(500)
def server_error(exc: Exception):
    app.logger.exception("unhandled exception")
    return "internal error", 500
```

Verbose error pages out, structured logging in.

---

## 6. A07 Authentication patches — Argon2id, `secrets`, rate limiting

### 6.1 Argon2id password hashing

Add `argon2-cffi` to `requirements.txt`. The patched login:

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_HASHER: PasswordHasher = PasswordHasher()

def _hash_password(plaintext: str) -> str:
    return _HASHER.hash(plaintext)

def _verify_password(plaintext: str, stored_hash: str) -> bool:
    try:
        _HASHER.verify(stored_hash, plaintext)
        return True
    except VerifyMismatchError:
        return False
```

The login handler becomes:

```python
@app.route("/login", methods=["GET", "POST"])
def login() -> str:
    if request.method == "POST":
        username: str = request.form.get("username", "")
        password: str = request.form.get("password", "")
        if not _rate_limit_allow(request.remote_addr or "unknown"):
            return "too many attempts; try again later", 429
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        row = cursor.execute(
            "SELECT id, password FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()
        if row is None or not _verify_password(password, row[1]):
            return "bad credentials", 401
        # AFTER: cryptographically random session token.
        session["user_id"] = row[0]
        session["token"] = secrets.token_urlsafe(32)
        return redirect(url_for("index"))
    return render_template("login.html")
```

### 6.2 Rate limiting

A minimal in-memory rate limiter, sized for the lab:

```python
import time
from collections import defaultdict
from typing import DefaultDict

_LOGIN_ATTEMPTS: DefaultDict[str, list[float]] = defaultdict(list)
_LOGIN_WINDOW_SECONDS: float = 300.0  # 5 minutes
_LOGIN_MAX_ATTEMPTS: int = 5

def _rate_limit_allow(client_ip: str) -> bool:
    now: float = time.monotonic()
    attempts: list[float] = _LOGIN_ATTEMPTS[client_ip]
    # Drop old attempts outside the window.
    attempts[:] = [t for t in attempts if t > now - _LOGIN_WINDOW_SECONDS]
    if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
        return False
    attempts.append(now)
    return True
```

This is *minimal* — production rate limiters use a shared store (Redis, memcached) so the limit holds across multiple application instances and persists across restarts. The lab uses an in-memory dict because the lab is one instance, but the algorithm — sliding window — is correct.

### 6.3 `secrets.token_urlsafe(32)` for session tokens

Python's `secrets` module reads from the OS's cryptographically secure RNG (`/dev/urandom` on Unix, `BCryptGenRandom` on Windows). `secrets.token_urlsafe(32)` returns a URL-safe base64-encoded 32-byte random string. The Python `secrets` docs (<https://docs.python.org/3/library/secrets.html>) open with: *"The `secrets` module is used for generating cryptographically strong random numbers suitable for managing data such as passwords, account authentication, security tokens, and related secrets."* It is the right module for this. `random` is the wrong one.

### 6.4 The regression checks

```python
def test_no_rate_limit() -> bool:
    # Submit 10 bad passwords; on patched, the 6th onwards should return 429.
    statuses: list[int] = []
    for _ in range(10):
        r = requests.post(
            LAB_URL + "/login",
            data={"username": "admin", "password": "guess"},
            timeout=5,
        )
        statuses.append(r.status_code)
    return 429 in statuses


def test_plaintext_passwords() -> bool:
    # Connect directly to the lab.db and verify no plaintext passwords remain.
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    rows = cursor.execute("SELECT password FROM users").fetchall()
    conn.close()
    # Argon2 hashes start with $argon2id$
    return all(row[0].startswith("$argon2id$") for row in rows)


def test_predictable_token() -> bool:
    # Log in twice; tokens should be high-entropy and not parseable as a float in [0,1).
    session_obj = requests.Session()
    session_obj.post(LAB_URL + "/login", data={"username": "alice", "password": "password123"})
    r = session_obj.get(LAB_URL + "/whoami", timeout=5)
    token: str = r.json().get("token", "")
    try:
        f = float(token)
        # If the token parses as a float in [0, 1), it is the random.random() shape.
        return not (0.0 <= f < 1.0)
    except ValueError:
        return True  # Good: not parseable as a float.
```

---

## 7. A08 Insecure deserialization patch — JSON in, pickle out

### 7.1 The fix

```python
import json
from typing import Any

@app.route("/import-profile", methods=["POST"])
def import_profile() -> str:
    blob: str = request.form.get("blob", "")
    if len(blob) > 4096:
        return "blob too large", 413
    try:
        data: Any = json.loads(blob)
    except json.JSONDecodeError:
        return "invalid json", 400
    if not isinstance(data, dict):
        return "expected json object", 400
    username: Any = data.get("username", "")
    if not isinstance(username, str) or not username.isalnum() or len(username) > 64:
        return "invalid username", 400
    return f"imported profile for {username}"
```

Three changes:

1. **JSON instead of pickle.** `json.loads` cannot execute code; the parser produces only `dict`, `list`, `str`, `int`, `float`, `bool`, `None`. The malicious-`__reduce__` mechanism does not exist in JSON.
2. **Length cap.** Refuse blobs larger than the legitimate ceiling for the use case. This is defence-in-depth against DoS.
3. **Schema validation.** Check that the result is a dict, that `username` is a string of allowed characters and length. For richer schemas, use `jsonschema` or `pydantic`; for the lab, hand-validation suffices.

### 7.2 What if you must use pickle?

You should not. If the upstream constraint (a library you do not control, a legacy file format) forces pickle:

- **Constrain the unpickler.** `pickle.Unpickler` accepts a `find_class` override that can refuse all classes outside an allow-list. The Python docs walk this pattern at <https://docs.python.org/3/library/pickle.html#restricting-globals>.
- **HMAC-sign the pickle on production.** Sign every pickle with a server-side key. Verify the signature before unpickling. This stops an attacker from forging pickles but does not stop a malicious pickle the application itself emitted.

The right answer is: do not use pickle for data crossing a trust boundary. The lab's patch makes the right move.

### 7.3 The regression check

```python
def test_pickle_rce() -> bool:
    # Build the malicious pickle from Lecture 2 § 9.2.
    import pickle, base64, os, hashlib
    canary: str = hashlib.sha1(str(time.time()).encode()).hexdigest()[:12]
    canary_path: Path = Path(f"/tmp/c6-pickle-canary-{canary}")
    if canary_path.exists():
        canary_path.unlink()

    class Exploit:
        def __reduce__(self) -> tuple:
            return (os.system, (f"touch {canary_path}",))

    payload: bytes = pickle.dumps(Exploit())
    requests.post(LAB_URL + "/import-profile", data={"blob": base64.b64encode(payload).decode()}, timeout=5)
    # On vulnerable: file appears.
    # On patched: JSON rejects the blob, file does not appear.
    return not canary_path.exists()
```

---

## 8. A10 SSRF patch — allow-list with DNS rebinding resistance

### 8.1 The fix

```python
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_HOSTS: set[str] = {"images.lab.local", "trusted-cdn.example.com"}
BLOCKED_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # cloud metadata IPv4
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _validate_destination(url: str) -> tuple[str, str] | None:
    """Validate the URL and return (resolved_ip, hostname) or None if rejected."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.hostname:
        return None
    if parsed.hostname not in ALLOWED_HOSTS:
        return None
    # Resolve once. Pass the resolved IP to requests so DNS rebinding cannot
    # cause a different IP on the second resolve.
    try:
        infos = socket.getaddrinfo(parsed.hostname, None, family=socket.AF_INET)
    except socket.gaierror:
        return None
    if not infos:
        return None
    resolved_ip: str = infos[0][4][0]
    ip_obj = ipaddress.ip_address(resolved_ip)
    for net in BLOCKED_NETS:
        if ip_obj in net:
            return None
    return resolved_ip, parsed.hostname


@app.route("/fetch-image")
def fetch_image() -> str:
    url: str = request.args.get("url", "")
    validated = _validate_destination(url)
    if validated is None:
        return "destination not allowed", 400
    resolved_ip, hostname = validated
    # Rewrite URL to use the resolved IP, with Host header set to the original hostname.
    # This prevents DNS rebinding because the IP we just validated is the IP we connect to.
    parsed = urlparse(url)
    rewritten = parsed._replace(netloc=resolved_ip).geturl()
    response = requests.get(
        rewritten,
        headers={"Host": hostname},
        timeout=5,
        allow_redirects=False,
    )
    return response.content
```

Four defences:

1. **Allow-list of permitted hostnames.** Not a deny-list. Allow-lists fail safely (an unlisted host is rejected); deny-lists fail open (a host not in the list is allowed, which is the wrong default).
2. **Scheme allow-list.** Only `http` and `https`. No `file://`, no `gopher://`, no `dict://`.
3. **Blocked destination networks.** RFC 1918 private space, loopback, link-local, cloud metadata. Even if a hostname accidentally makes it past the allow-list and resolves to an internal IP, the IP check rejects it.
4. **DNS rebinding resistance.** Resolve once, pass the resolved IP to `requests` with the original Host header. The IP we validated is the IP we connect to.

`allow_redirects=False` is a fifth subtle defence: an allow-listed host might redirect to a not-allow-listed host, and `requests` would follow without re-validating. Disable redirects, or validate each redirect manually.

### 8.2 The regression check

```python
def test_ssrf() -> bool:
    # Try to reach the mock metadata server.
    response = requests.get(
        LAB_URL + "/fetch-image",
        params={"url": "http://127.0.0.1:8080/latest/meta-data/iam/security-credentials/lab-role"},
        timeout=5,
    )
    # On vulnerable: 200 with the fake-creds JSON in the body.
    # On patched: 400 "destination not allowed".
    return response.status_code == 400 or "AccessKeyId" not in response.text
```

---

## 9. Content Security Policy — the header, the directives, the lab's policy

### 9.1 What CSP is

A **Content Security Policy** is a response header that tells the browser: *"this page may load resources only from these origins, and may execute scripts only from these origins."* The browser enforces the policy at the parse-and-execute layer. A `<script>` tag whose `src` is not allow-listed will not run. An inline `<script>` block whose hash or nonce is not allow-listed will not run.

The MDN reference is the canonical primary source: <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>. The OWASP cheat sheet (<https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>) is the working-engineer's guide.

### 9.2 Why CSP after the autoescape patch?

The autoescape patch fixes the XSS bugs in the lab. CSP is *defence-in-depth* — it catches XSS that escapes the encoding layer (an unknown future bug in a template, a `|safe` filter someone adds in code review without realising the implications, a third-party include).

The XSS Prevention cheat sheet recommends CSP as a backstop in every case. The OWASP rule of thumb: encode first, CSP second; never CSP-only.

### 9.3 The lab's CSP

```
default-src 'self';
script-src 'self';
style-src 'self';
img-src 'self';
object-src 'none';
frame-ancestors 'none';
base-uri 'self';
form-action 'self'
```

Reading each directive:

- **`default-src 'self'`** — the fallback for any resource type not explicitly listed. Only this origin is allowed.
- **`script-src 'self'`** — JavaScript may load from the same origin only. No inline `<script>` (we have none). No external CDN.
- **`style-src 'self'`** — CSS, same.
- **`img-src 'self'`** — images, same.
- **`object-src 'none'`** — `<object>`, `<embed>`, `<applet>` tags blocked outright. Almost no modern site needs them.
- **`frame-ancestors 'none'`** — no other site may embed this page in an `<iframe>`. The modern replacement for `X-Frame-Options: DENY`.
- **`base-uri 'self'`** — restrict the `<base href>` so an injected `<base>` tag cannot redirect relative URLs to an attacker's site.
- **`form-action 'self'`** — forms may submit only to this origin. Prevents an injected form from submitting credentials to an attacker.

What is *not* in the policy:

- **`'unsafe-inline'`** — inline `<script>` is forbidden. If we needed inline scripts (we do not in the lab), we would use `nonce-<random>` or `sha256-<hash>` source expressions.
- **`'unsafe-eval'`** — `eval()`, `Function()`, `setTimeout("...")` (as a string) are all forbidden. If we needed `eval` (we should not), we would have to either allow `'unsafe-eval'` or refactor the code.
- **`report-uri` / `report-to`** — production CSPs include a reporting endpoint so violation reports come back to the server. The lab does not; the OWASP cheat sheet has the canonical reporting pattern.

### 9.4 Validating the CSP

After the patch:

```bash
curl -sI http://127.0.0.1:5000/ | grep -i content-security-policy
```

You should see the CSP header. Re-run the reflected-XSS payload from Lecture 2 in the browser:

```
http://127.0.0.1:5000/search?q=<script>alert(1)</script>
```

Open the browser's developer-tools console. You see a **CSP violation** error: *"Refused to execute inline script because it violates the following Content Security Policy directive: 'script-src 'self'.'"* The script does not execute. The autoescape patch *also* prevents the `<script>` from rendering, so the CSP is belt-and-braces here.

### 9.5 CSP's limits

CSP does not defend against:

- Server-side injection (SQLi, command injection, SSRF). CSP operates in the browser.
- Authorization bugs (IDOR, missing function-level authz). Same reason.
- Credential theft via legitimate forms (a phishing-style submission to a CSP-allow-listed origin). CSP allows what the policy says.
- Most native-mobile-app classes of bug.

CSP is the right defence for one category — script execution control in the browser — and it is excellent at that category. It is not a general-purpose web defence.

---

## 10. HTTP request smuggling — what it is, why the lab cannot demonstrate it

### 10.1 What smuggling is

**HTTP request smuggling** is a class of vulnerability that arises when two HTTP processors — typically a CDN or reverse proxy and the origin server — disagree about where one request ends and the next begins. The attacker crafts a request that the proxy parses one way and the origin parses a different way; bytes "smuggled" past the proxy land on the origin as a separate request that the proxy never saw.

The two canonical classes:

- **CL.TE** — the proxy honours `Content-Length`, the origin honours `Transfer-Encoding: chunked`. The attacker sends a request with *both* headers and a body that, under CL parsing, is one request, but under TE parsing is one request followed by a smuggled second.
- **TE.CL** — the reverse: the proxy honours TE, the origin honours CL.

James Kettle's 2019 PortSwigger paper "HTTP Desync Attacks: Request Smuggling Reborn" (<https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn>) is the canonical reference. The 2021 "HTTP/2: The Sequel is Always Worse" paper (<https://portswigger.net/research/http2>) extends the technique to HTTP/2 downgrade scenarios.

### 10.2 Why vuln_lab cannot demonstrate it

Smuggling requires two HTTP processors in series with disagreeing parsers. The lab has one — the Flask development server. There is no CDN, no reverse proxy. The architecture cannot support the bug.

The lab is honest about this. The OWASP A09 / A06 vacuum here is filled by reading the PortSwigger Academy labs, which build the correct two-processor topology in a hosted environment. The Academy labs are at <https://portswigger.net/web-security/request-smuggling/lab>; they are free, graded, and the canonical "actually do a smuggling attack" exercise.

### 10.3 What to read

- Kettle 2019 paper.
- Kettle 2021 paper.
- PortSwigger Academy request-smuggling labs.
- The OWASP entry on request smuggling: <https://owasp.org/www-community/attacks/HTTP_Request_Smuggling>.

The quiz this week includes one short-answer smuggling question. Read enough to answer it; if smuggling interests you, the Kettle papers are a weekend of high-quality reading.

---

## 11. The regression script

`regression_test.py` lives in `mini-project/starter/`. The shape:

```python
"""Regression script for the vuln_lab.

Runs each of the eight exploit attempts from Lecture 2 against the lab on
127.0.0.1:5000. Prints PASS (the patch holds; the exploit fails) or FAIL
(the patch is missing; the exploit succeeds) for each.

USAGE:
    python3 regression_test.py
    python3 regression_test.py --lab http://127.0.0.1:5000 --metadata http://127.0.0.1:8080

AUTHORIZED USE ONLY: this script attempts the Lecture 2 exploit payloads.
It must be run only against vuln_lab on your own loopback.
"""
```

The eight `test_*` functions return `True` if the patch holds (exploit fails) and `False` if the exploit succeeds. The script tallies passes and fails and exits `0` if all eight pass, non-zero otherwise.

You run the script against the **vulnerable** lab first to confirm the exploits work (eight FAILs). Apply the patches one at a time. Re-run. Each fix flips one assertion to PASS. When all eight pass, the lab is patched.

The script is the *acceptance test* for the mini-project. It is also the file you commit unchanged — the assertions are the rubric.

---

## 12. Defence-in-depth: the closing argument

Many of the patches in this lecture stack layers:

- The XSS fix has **autoescape** (the primary defence) plus **CSP** (the defence-in-depth backstop).
- The session-token fix has **`secrets.token_urlsafe`** (the primary defence) plus **`HttpOnly` cookie** (defence against XSS-stolen tokens) plus **`SameSite=Strict`** (defence against CSRF-stolen tokens).
- The SSRF fix has **scheme allow-list** plus **hostname allow-list** plus **resolved-IP blocklist** plus **DNS rebinding resistance** plus **no redirects**.
- The deserialization fix has **JSON instead of pickle** plus **length cap** plus **schema validation**.

Why bother? Two reasons:

1. **Single-layer defences fail to one bug.** The XSS encoding layer fails the day a developer adds `|safe` to a template. CSP catches the failure. The session-token randomness layer fails the day someone refactors the login handler and forgets to call `secrets.token_urlsafe`. `HttpOnly` does not save you, but it bounds the impact: a leaked token cannot be stolen by an XSS that does happen.
2. **The cost of layers is small; the cost of a single-bug catastrophe is large.** CSP is one header. `HttpOnly` is one cookie attribute. `SameSite=Strict` is one cookie attribute. The patches are short, the audit is straightforward, and the catastrophe scenarios — RCE via debug mode, credential theft via XSS — are eliminated by the second layer when the first layer fails.

The application-security engineer's mantra: **fix the bug; harden the surrounding code.** The bug is the primary fix; the hardening is the rest of the patch. Lecture 3's patches are written in this register; the mini-project report should match.

---

## 13. Where this lecture goes

Exercise 3 (the runnable Python script) walks you through applying each patch and re-running the regression. The mini-project is the synthesis: stand up the vulnerable lab, exploit each class, patch each class, ship the patched lab plus the report.

Week 9 picks up the A02 thread — cryptography in practice. The Argon2id-vs-bcrypt-vs-scrypt-vs-PBKDF2 discussion from this lecture is shallow on purpose; Week 9 goes deep.

For now: read the OWASP Top 10 entries you skipped, read at least one OWASP Cheat Sheet end-to-end, and start Exercise 1.
