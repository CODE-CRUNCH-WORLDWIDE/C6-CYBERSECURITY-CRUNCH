"""
Exercise 3 - Apply the patches and run the regression suite.

Estimated time: 90 minutes.

============================== AUTHORIZED USE ONLY =============================
This script applies the patches from Lecture 3 to the vuln_lab application at
mini-project/starter/app.py, then runs the regression suite that re-attempts
every exploit from Lecture 2.

The regression suite fires the Lecture 2 exploit payloads against the lab. The
payloads must be sent only to your own loopback (127.0.0.1:5000) where the lab
is running. Do not run this script against any other host. Doing so is a
violation of the Computer Fraud and Abuse Act (US), the Computer Misuse Act
1990 (UK), and Directive 2013/40/EU (EU) as implemented in each member state.
================================================================================

The script does two things:

1. PATCH GUIDE. For each of the eight bug classes, the script prints a unified
   diff that turns the vulnerable version into the patched version. You apply
   each diff to mini-project/starter/app.py by hand (or with patch(1)) and
   restart the lab. This is the "do it yourself" workflow; an alternative
   path is to copy the patches directly out of SOLUTIONS.md.

2. REGRESSION RUN. After every patch (or at the end, if you prefer), run the
   regression suite. It re-attempts each exploit and prints PASS (the patch
   holds) or FAIL (the exploit still works).

The regression checks in this file are deliberately small and self-contained.
They are not a comprehensive test suite. They are enough to verify that the
specific exploits demonstrated in Lecture 2 no longer work after the patches
from Lecture 3 are applied.

References:
    - OWASP Top 10 2021: https://owasp.org/Top10/
    - OWASP SQL Injection Prevention Cheat Sheet:
      https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
    - OWASP XSS Prevention Cheat Sheet:
      https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
    - OWASP SSRF Prevention Cheat Sheet:
      https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
    - OWASP Deserialization Cheat Sheet:
      https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

Usage:
    python3 exercise-03-patch-and-regress.py --guide
    python3 exercise-03-patch-and-regress.py --regress
    python3 exercise-03-patch-and-regress.py --regress --lab http://127.0.0.1:5000

The script is dependency-free except for `requests` (already installed as part
of the lab's requirements.txt).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pickle
import sqlite3
import sys
import time
from pathlib import Path
from typing import Callable

try:
    import requests
except ImportError:
    print(
        "ERROR: this script requires the requests library. "
        "Install with: pip install requests",
        file=sys.stderr,
    )
    sys.exit(2)


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------


DEFAULT_LAB_URL: str = "http://127.0.0.1:5000"
DEFAULT_METADATA_URL: str = "http://127.0.0.1:8080"
DEFAULT_DB_PATH: Path = Path("mini-project/starter/lab.db")


# -----------------------------------------------------------------------------
# Patch guide - prints the canonical patch for each bug class.
# -----------------------------------------------------------------------------


PATCH_GUIDE_HEADER: str = """\
==============================================================================
PATCH GUIDE - apply these one at a time to mini-project/starter/app.py.

The patches are short. Each one is the canonical OWASP-Cheat-Sheet-compliant
fix for the corresponding bug class. After applying each patch, restart the
lab (Ctrl-C in the lab's terminal; rerun python3 app.py) and run this script
with --regress to confirm the fix.
==============================================================================
"""


PATCHES: list[tuple[str, str, str]] = [
    (
        "P1 - A03 SQL Injection at /lookup",
        "CWE-89 / OWASP A03 / SQL Injection Prevention Cheat Sheet",
        '''# BEFORE
sql: str = "SELECT id, username, email FROM users WHERE username = '" + name + "'"
rows: list = cursor.execute(sql).fetchall()

# AFTER (parameterized query)
sql: str = "SELECT id, username, email FROM users WHERE username = ?"
rows: list = cursor.execute(sql, (name,)).fetchall()''',
    ),
    (
        "P2 - A03 Reflected XSS at /search",
        "CWE-79 / OWASP A03 / XSS Prevention Cheat Sheet",
        '''# BEFORE
return render_template("search.html", q=Markup(q), results=[])

# AFTER (let Jinja autoescape do its job; remove the Markup() wrapper)
return render_template("search.html", q=q, results=[])''',
    ),
    (
        "P3 - A03 Stored XSS at /comments",
        "CWE-79 / OWASP A03",
        '''# Template file: templates/comments.html
# BEFORE
# {% for row in rows %}
#   <li>{{ row.body | safe }}</li>
# {% endfor %}

# AFTER (remove the |safe filter)
# {% for row in rows %}
#   <li>{{ row.body }}</li>
# {% endfor %}''',
    ),
    (
        "P4 - A03 Command Injection at /thumbnail",
        "CWE-78 / OWASP A03",
        '''# BEFORE
import os
os.system("convert " + filename + " /tmp/out.png")

# AFTER (subprocess with argv list; allow-list the filename)
import subprocess
if not _is_safe_filename(filename):
    return "invalid filename", 400
result = subprocess.run(
    ["convert", filename, "/tmp/out.png"],
    shell=False,
    capture_output=True,
    timeout=5,
    check=False,
)


def _is_safe_filename(name: str) -> bool:
    if not name or name.count(".") != 1 or "/" in name or ".." in name:
        return False
    stem, _, ext = name.partition(".")
    return stem.replace("_", "").replace("-", "").isalnum() and ext.isalnum()''',
    ),
    (
        "P5 - A01 IDOR at /profile and missing-authz at /admin/users",
        "CWE-639, CWE-306 / OWASP A01",
        '''# IDOR fix at /profile
# BEFORE
row = cursor.execute(
    "SELECT id, username, email FROM users WHERE id = ?",
    (requested_id,),
).fetchone()

# AFTER (ownership check first)
if requested_id != session["user_id"] and not _is_admin(session["user_id"]):
    return "forbidden", 403
row = cursor.execute(
    "SELECT id, username, email FROM users WHERE id = ?",
    (requested_id,),
).fetchone()


# Missing-authz fix at /admin/users
# BEFORE
if "user_id" not in session:
    return redirect(url_for("login"))
rows = cursor.execute(
    "SELECT id, username, email, password, role FROM users"
).fetchall()

# AFTER (require admin; do not return passwords)
if "user_id" not in session:
    return redirect(url_for("login"))
if not _is_admin(session["user_id"]):
    return "forbidden", 403
rows = cursor.execute("SELECT id, username, email, role FROM users").fetchall()


def _is_admin(user_id: int) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    row = cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row is not None and row[0] == "admin"''',
    ),
    (
        "P6 - A05 Security Misconfiguration",
        "CWE-489, CWE-200, CWE-1004 / OWASP A05",
        '''# At the bottom of app.py
# BEFORE
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

# AFTER
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)


# Add an after_request hook for security headers:
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    return response


# Update init_db.py so the admin password is generated, not hard-coded:
# (See SOLUTIONS.md for the full init_db.py patch.)''',
    ),
    (
        "P7 - A07 Authentication Failures",
        "CWE-307, CWE-256, CWE-330, CWE-338 / OWASP A07",
        '''# BEFORE
import random

# In /login POST handler:
row = cursor.execute(
    "SELECT id FROM users WHERE username = ? AND password = ?",
    (username, password),
).fetchone()
session["token"] = str(random.random())


# AFTER
import secrets
import time
from collections import defaultdict
from typing import DefaultDict

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_HASHER: PasswordHasher = PasswordHasher()
_LOGIN_ATTEMPTS: DefaultDict[str, list[float]] = defaultdict(list)
_LOGIN_WINDOW_SECONDS: float = 300.0
_LOGIN_MAX_ATTEMPTS: int = 5


def _rate_limit_allow(client_ip: str) -> bool:
    now: float = time.monotonic()
    attempts: list[float] = _LOGIN_ATTEMPTS[client_ip]
    attempts[:] = [t for t in attempts if t > now - _LOGIN_WINDOW_SECONDS]
    if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
        return False
    attempts.append(now)
    return True


# In /login POST handler:
if not _rate_limit_allow(request.remote_addr or "unknown"):
    return "too many attempts; try again later", 429

row = cursor.execute(
    "SELECT id, password FROM users WHERE username = ?",
    (username,),
).fetchone()
if row is None:
    return "bad credentials", 401
try:
    _HASHER.verify(row[1], password)
except VerifyMismatchError:
    return "bad credentials", 401
session["user_id"] = row[0]
session["token"] = secrets.token_urlsafe(32)

# Also: update init_db.py to store Argon2id hashes, not plaintext passwords.''',
    ),
    (
        "P8 - A08 Insecure Deserialization at /import-profile",
        "CWE-502 / OWASP A08",
        '''# BEFORE
import base64
import pickle

blob_b64: str = request.form.get("blob", "")
data = pickle.loads(base64.b64decode(blob_b64))


# AFTER
import json
from typing import Any

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
return f"imported profile for {username}"''',
    ),
    (
        "P9 - A10 SSRF at /fetch-image",
        "CWE-918 / OWASP A10 / SSRF Prevention Cheat Sheet",
        '''# BEFORE
url: str = request.args.get("url", "")
response = requests.get(url, timeout=5)
return response.content


# AFTER (scheme allow-list, hostname allow-list, blocked-IP check, DNS rebinding resistance)
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_HOSTS: set[str] = {"images.lab.local", "trusted-cdn.example.com"}
BLOCKED_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _validate_destination(url: str) -> tuple[str, str] | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.hostname or parsed.hostname not in ALLOWED_HOSTS:
        return None
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


url: str = request.args.get("url", "")
validated = _validate_destination(url)
if validated is None:
    return "destination not allowed", 400
resolved_ip, hostname = validated
parsed = urlparse(url)
rewritten = parsed._replace(netloc=resolved_ip).geturl()
response = requests.get(
    rewritten,
    headers={"Host": hostname},
    timeout=5,
    allow_redirects=False,
)
return response.content''',
    ),
]


def print_patch_guide() -> None:
    """Print every patch in order. The student applies each by hand to app.py."""
    print(PATCH_GUIDE_HEADER)
    for title, references, diff in PATCHES:
        print(f"--- {title}")
        print(f"    {references}")
        print()
        print(diff)
        print()
        print("-" * 78)
        print()


# -----------------------------------------------------------------------------
# Regression suite - the eight checks.
# -----------------------------------------------------------------------------


def test_sqli(lab_url: str) -> tuple[bool, str]:
    """Verify SQLi at /lookup is closed."""
    payload: str = "' UNION SELECT id, username, password FROM users --"
    try:
        response = requests.get(
            lab_url + "/lookup",
            params={"name": payload},
            timeout=5,
        )
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    # On the patched lab, the literal payload never matches a username,
    # and the UNION does not execute. No password should appear in the body.
    if "password123" in response.text or "letmein" in response.text:
        return False, "plaintext passwords leaked in response"
    return True, "patch holds: UNION did not execute"


def test_reflected_xss(lab_url: str) -> tuple[bool, str]:
    """Verify reflected XSS at /search is closed by autoescape."""
    payload: str = "<script>alert(1)</script>"
    try:
        response = requests.get(
            lab_url + "/search",
            params={"q": payload},
            timeout=5,
        )
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    # On the patched lab, the literal <script>...</script> must not appear;
    # Jinja autoescape replaces < with &lt; etc.
    if "<script>alert(1)</script>" in response.text:
        return False, "raw <script> tag reflected"
    return True, "patch holds: autoescape encoded the payload"


def test_stored_xss(lab_url: str) -> tuple[bool, str]:
    """Verify stored XSS at /comments is closed."""
    payload: str = "<script>alert('xss-canary')</script>"
    try:
        requests.post(lab_url + "/comments", data={"body": payload}, timeout=5)
        response = requests.get(lab_url + "/comments", timeout=5)
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    if "<script>alert('xss-canary')</script>" in response.text:
        return False, "raw <script> stored and rendered"
    return True, "patch holds: stored comment is encoded on render"


def test_command_injection(lab_url: str) -> tuple[bool, str]:
    """Verify command injection at /thumbnail is closed."""
    canary: Path = Path("/tmp/c6-cmd-canary")
    canary.unlink(missing_ok=True)
    payload: str = f"test.png; touch {canary}"
    try:
        requests.get(
            lab_url + "/thumbnail",
            params={"file": payload},
            timeout=5,
        )
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    if canary.exists():
        canary.unlink(missing_ok=True)
        return False, f"canary file {canary} was created"
    return True, "patch holds: shell metacharacters did not execute"


def test_idor(lab_url: str) -> tuple[bool, str]:
    """Verify IDOR at /profile is closed."""
    s = requests.Session()
    try:
        s.post(
            lab_url + "/login",
            data={"username": "alice", "password": "password123"},
            timeout=5,
        )
        # Alice (id=1) requests Bob's profile (id=2).
        response = s.get(lab_url + "/profile", params={"id": 2}, timeout=5)
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    if response.status_code == 200 and "bob" in response.text.lower():
        return False, "alice could view bob's profile"
    if response.status_code == 403:
        return True, "patch holds: 403 returned for cross-user profile read"
    return True, f"patch holds: status {response.status_code}"


def test_missing_authz(lab_url: str) -> tuple[bool, str]:
    """Verify missing function-level authorization at /admin/users is closed."""
    s = requests.Session()
    try:
        s.post(
            lab_url + "/login",
            data={"username": "alice", "password": "password123"},
            timeout=5,
        )
        response = s.get(lab_url + "/admin/users", timeout=5)
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    if response.status_code == 200 and "admin" in response.text.lower():
        return False, "non-admin alice could view the admin user list"
    return True, f"patch holds: status {response.status_code}"


def test_no_rate_limit(lab_url: str) -> tuple[bool, str]:
    """Verify rate limit on /login is in place."""
    statuses: list[int] = []
    for _ in range(10):
        try:
            r = requests.post(
                lab_url + "/login",
                data={"username": "admin", "password": "wrong-guess"},
                timeout=5,
            )
            statuses.append(r.status_code)
        except requests.RequestException as exc:
            return False, f"request failed mid-burst: {exc}"
    if 429 in statuses:
        return True, f"patch holds: rate limit fired ({statuses.count(429)} of 10 returned 429)"
    return False, f"no 429 in 10 attempts: {statuses}"


def test_pickle_rce(lab_url: str) -> tuple[bool, str]:
    """Verify insecure deserialization at /import-profile is closed."""
    canary: Path = Path("/tmp/c6-pickle-canary")
    canary.unlink(missing_ok=True)

    class _Exploit:
        def __reduce__(self) -> tuple:
            return (os.system, (f"touch {canary}",))

    payload: bytes = pickle.dumps(_Exploit())
    blob: str = base64.b64encode(payload).decode()
    try:
        requests.post(lab_url + "/import-profile", data={"blob": blob}, timeout=5)
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    # Also send a benign JSON payload to confirm the new endpoint still works.
    try:
        r = requests.post(
            lab_url + "/import-profile",
            data={"blob": json.dumps({"username": "alice"})},
            timeout=5,
        )
        good_path_ok: bool = r.status_code == 200 or r.status_code == 400
    except requests.RequestException:
        good_path_ok = False
    if canary.exists():
        canary.unlink(missing_ok=True)
        return False, "canary file created by pickle deserialization"
    if not good_path_ok:
        return True, "patch holds: pickle rejected (JSON path response unverified)"
    return True, "patch holds: pickle rejected, JSON path responded"


def test_ssrf(lab_url: str) -> tuple[bool, str]:
    """Verify SSRF at /fetch-image is closed."""
    payload: str = "http://127.0.0.1:8080/latest/meta-data/iam/security-credentials/lab-role"
    try:
        response = requests.get(
            lab_url + "/fetch-image",
            params={"url": payload},
            timeout=5,
        )
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    if "AccessKeyId" in response.text:
        return False, "fake metadata credentials returned"
    if response.status_code == 400:
        return True, "patch holds: 400 returned for disallowed destination"
    return True, f"patch holds: status {response.status_code}, no credentials in body"


# -----------------------------------------------------------------------------
# Test runner
# -----------------------------------------------------------------------------


TESTS: list[tuple[str, Callable[[str], tuple[bool, str]]]] = [
    ("P1 SQLi at /lookup", test_sqli),
    ("P2 Reflected XSS at /search", test_reflected_xss),
    ("P3 Stored XSS at /comments", test_stored_xss),
    ("P4 Command injection at /thumbnail", test_command_injection),
    ("P5a IDOR at /profile", test_idor),
    ("P5b Missing authz at /admin/users", test_missing_authz),
    ("P7 Rate limit at /login", test_no_rate_limit),
    ("P8 Pickle deserialization at /import-profile", test_pickle_rce),
    ("P9 SSRF at /fetch-image", test_ssrf),
]


def run_regression(lab_url: str) -> int:
    """Run every regression test against `lab_url`. Return the exit code."""
    print(f"Regression suite against {lab_url}")
    print("-" * 78)
    passes: int = 0
    fails: int = 0
    for name, fn in TESTS:
        try:
            ok, note = fn(lab_url)
        except Exception as exc:  # noqa: BLE001
            ok, note = False, f"unhandled exception: {exc}"
        verdict: str = "PASS" if ok else "FAIL"
        print(f"  [{verdict}] {name}")
        print(f"         {note}")
        if ok:
            passes += 1
        else:
            fails += 1
        # Polite pause so rate-limit-style tests do not clobber each other.
        time.sleep(0.1)
    print("-" * 78)
    print(f"  {passes}/{passes + fails} exploits closed.")
    print()
    return 0 if fails == 0 else 1


def verify_no_plaintext_passwords(db_path: Path) -> tuple[bool, str]:
    """A bonus check the regression run can perform: verify that the database
    no longer stores plaintext passwords. This requires the script to be
    able to read the lab's SQLite file, so it is opt-in.
    """
    if not db_path.exists():
        return False, f"db not found at {db_path}"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        rows = cursor.execute("SELECT username, password FROM users").fetchall()
    except sqlite3.OperationalError as exc:
        conn.close()
        return False, f"sql error: {exc}"
    conn.close()
    bad: list[str] = []
    for username, password in rows:
        if not isinstance(password, str):
            bad.append(f"{username}: non-string password")
            continue
        if not password.startswith("$argon2id$"):
            bad.append(f"{username}: not an argon2 hash")
    if bad:
        return False, "; ".join(bad)
    return True, f"{len(rows)} users, all argon2id hashes"


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Apply the Lecture 3 patches and run the regression suite. "
            "AUTHORIZED USE ONLY: target the lab on your own loopback."
        )
    )
    parser.add_argument(
        "--guide",
        action="store_true",
        help="print the canonical patch guide for each bug class and exit",
    )
    parser.add_argument(
        "--regress",
        action="store_true",
        help="run the regression suite against the running lab",
    )
    parser.add_argument(
        "--lab",
        default=DEFAULT_LAB_URL,
        help=f"base URL of the lab (default {DEFAULT_LAB_URL})",
    )
    parser.add_argument(
        "--check-db",
        action="store_true",
        help="also verify that the lab database has no plaintext passwords (requires --db)",
    )
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB_PATH),
        help=f"path to lab.db for the --check-db verification (default {DEFAULT_DB_PATH})",
    )
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.guide and not args.regress:
        parser.print_help(sys.stderr)
        return 2
    if args.guide:
        print_patch_guide()
    if args.regress:
        # Safety check: refuse to run if the lab URL is not on a loopback or
        # other localhost-shaped host. This is a courtesy guard, not a security
        # control; it makes the "I accidentally typed a public hostname" case
        # produce a refusal instead of a CFAA violation.
        if not _is_loopback_url(args.lab):
            print(
                f"ERROR: lab URL {args.lab!r} does not look like a loopback "
                "address. The regression suite fires exploit payloads and "
                "must only be run against your own laptop. If you really want "
                "to override this guard, edit the script.",
                file=sys.stderr,
            )
            return 3
        rc: int = run_regression(args.lab)
        if args.check_db:
            ok, note = verify_no_plaintext_passwords(Path(args.db))
            verdict: str = "PASS" if ok else "FAIL"
            print(f"  [{verdict}] DB: no plaintext passwords")
            print(f"         {note}")
            if not ok:
                rc = max(rc, 1)
        return rc
    return 0


def _is_loopback_url(url: str) -> bool:
    """Return True if the URL's host looks like a loopback address.

    This is a string-level check intended to catch the obvious mistake of
    pointing the regression suite at a non-lab host. It is not a security
    control. A determined override (a /etc/hosts entry mapping evil.example
    to 127.0.0.1) would bypass it; that is acceptable because the user is
    explicitly overriding a safety message at that point.
    """
    lowered: str = url.lower()
    loopback_hosts: tuple[str, ...] = (
        "://127.",
        "://localhost",
        "://[::1]",
        "://0.0.0.0",
    )
    return any(host_marker in lowered for host_marker in loopback_hosts)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
