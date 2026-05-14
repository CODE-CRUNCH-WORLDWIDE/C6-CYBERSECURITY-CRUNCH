"""
regression_test.py - regression suite for the vuln_lab patches.

============================== AUTHORIZED USE ONLY =============================
This script fires the Lecture 2 exploit payloads against the lab on your own
loopback (127.0.0.1:5000 by default). It must not be run against any other
host. The script includes a safety guard that refuses non-loopback URLs.
================================================================================

Run against the as-shipped vulnerable lab:
    $ python3 regression_test.py
    -> 0/9 exploits closed (every exploit succeeds)

Run against the patched lab (after applying P1..P9 from SOLUTIONS.md):
    $ python3 regression_test.py
    -> 9/9 exploits closed (every exploit fails - the patches hold)

The nine tests are:

    P1  SQL injection at /lookup                     (A03, CWE-89)
    P2  Reflected XSS at /search                     (A03, CWE-79)
    P3  Stored XSS at /comments                      (A03, CWE-79)
    P4  Command injection at /thumbnail              (A03, CWE-78)
    P5a IDOR at /profile                             (A01, CWE-639)
    P5b Missing function-level authz at /admin/users (A01, CWE-306)
    P7  Rate limit at /login                         (A07, CWE-307)
    P8  Pickle deserialization at /import-profile    (A08, CWE-502)
    P9  SSRF at /fetch-image                         (A10, CWE-918)

References:
    - OWASP Top 10 2021: https://owasp.org/Top10/
    - CWE: https://cwe.mitre.org/
    - PortSwigger Web Security Academy: https://portswigger.net/web-security
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


DEFAULT_LAB_URL: str = "http://127.0.0.1:5000"
DEFAULT_DB_PATH: Path = Path(__file__).parent / "lab.db"


# -----------------------------------------------------------------------------
# The nine regression checks.
# -----------------------------------------------------------------------------


def test_sqli(lab_url: str) -> tuple[bool, str]:
    """Patched if the UNION-based payload does not leak plaintext passwords."""
    payload: str = "' UNION SELECT id, username, password FROM users --"
    try:
        response = requests.get(
            lab_url + "/lookup", params={"name": payload}, timeout=5
        )
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    if "password123" in response.text or "letmein" in response.text:
        return False, "UNION-based SQLi leaked plaintext password"
    return True, "UNION did not execute"


def test_reflected_xss(lab_url: str) -> tuple[bool, str]:
    """Patched if the literal <script>...</script> is not reflected."""
    payload: str = "<script>alert(1)</script>"
    try:
        response = requests.get(
            lab_url + "/search", params={"q": payload}, timeout=5
        )
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    if "<script>alert(1)</script>" in response.text:
        return False, "raw <script> tag reflected"
    return True, "autoescape encoded the payload"


def test_stored_xss(lab_url: str) -> tuple[bool, str]:
    """Patched if the stored comment is not rendered as raw HTML."""
    payload: str = "<script>alert('xss-canary')</script>"
    try:
        requests.post(lab_url + "/comments", data={"body": payload}, timeout=5)
        response = requests.get(lab_url + "/comments", timeout=5)
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    if "<script>alert('xss-canary')</script>" in response.text:
        return False, "raw <script> stored and rendered"
    return True, "stored comment is encoded on render"


def test_command_injection(lab_url: str) -> tuple[bool, str]:
    """Patched if the shell metacharacter does not execute a second command."""
    canary: Path = Path("/tmp/c6-cmd-canary")
    canary.unlink(missing_ok=True)
    payload: str = f"test.png; touch {canary}"
    try:
        requests.get(lab_url + "/thumbnail", params={"file": payload}, timeout=5)
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    if canary.exists():
        canary.unlink(missing_ok=True)
        return False, f"canary file {canary} was created"
    return True, "shell metacharacters did not execute"


def test_idor(lab_url: str) -> tuple[bool, str]:
    """Patched if alice cannot view bob's profile (returns 403 or no bob data)."""
    s = requests.Session()
    try:
        s.post(
            lab_url + "/login",
            data={"username": "alice", "password": "password123"},
            timeout=5,
        )
        response = s.get(lab_url + "/profile", params={"id": 2}, timeout=5)
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    if response.status_code == 200 and "bob" in response.text.lower():
        return False, "alice could view bob's profile"
    if response.status_code == 403:
        return True, "403 returned for cross-user profile read"
    return True, f"status {response.status_code} with no bob data"


def test_missing_authz(lab_url: str) -> tuple[bool, str]:
    """Patched if non-admin alice cannot list users."""
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
    body_lower: str = response.text.lower()
    if response.status_code == 200 and "admin@lab.local" in body_lower:
        return False, "alice could view the admin user list"
    return True, f"status {response.status_code}"


def test_no_rate_limit(lab_url: str) -> tuple[bool, str]:
    """Patched if 10 rapid bad-credential attempts trigger at least one 429."""
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
        n: int = statuses.count(429)
        return True, f"rate limit fired ({n} of 10 returned 429)"
    return False, f"no 429 in 10 attempts: {statuses}"


def test_pickle_rce(lab_url: str) -> tuple[bool, str]:
    """Patched if the malicious pickle does not create the canary file."""
    canary: Path = Path("/tmp/c6-pickle-canary")
    canary.unlink(missing_ok=True)

    class _Exploit:
        """Pickle exploit: __reduce__ triggers os.system on unpickling."""

        def __reduce__(self) -> tuple:
            return (os.system, (f"touch {canary}",))

    payload: bytes = pickle.dumps(_Exploit())
    blob: str = base64.b64encode(payload).decode()
    try:
        requests.post(lab_url + "/import-profile", data={"blob": blob}, timeout=5)
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    if canary.exists():
        canary.unlink(missing_ok=True)
        return False, "canary file created by pickle deserialization"
    return True, "pickle payload rejected or ignored"


def test_ssrf(lab_url: str) -> tuple[bool, str]:
    """Patched if the SSRF target does not return the mock IMDS credentials."""
    payload: str = "http://127.0.0.1:8080/latest/meta-data/iam/security-credentials/lab-role"
    try:
        response = requests.get(
            lab_url + "/fetch-image", params={"url": payload}, timeout=5
        )
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    if "AccessKeyId" in response.text:
        return False, "mock-IMDS credentials returned"
    return True, f"status {response.status_code}, no credentials in body"


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


# -----------------------------------------------------------------------------
# Optional DB check
# -----------------------------------------------------------------------------


def verify_no_plaintext_passwords(db_path: Path) -> tuple[bool, str]:
    """Verify that the lab database stores Argon2id hashes, not plaintext."""
    if not db_path.exists():
        return False, f"db not found at {db_path}"
    conn = sqlite3.connect(str(db_path))
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
# Runner
# -----------------------------------------------------------------------------


def _is_loopback_url(url: str) -> bool:
    """Return True if the URL looks like it points to loopback.

    Safety guard, not a security control. The point is to catch the case
    where the user accidentally types a non-loopback URL on the command
    line. A user determined to override the check can do so by editing
    the script; that is acceptable because the override is explicit.
    """
    lowered: str = url.lower()
    loopback_markers: tuple[str, ...] = (
        "://127.",
        "://localhost",
        "://[::1]",
        "://0.0.0.0",
    )
    return any(marker in lowered for marker in loopback_markers)


def run(lab_url: str, also_check_db: bool, db_path: Path) -> int:
    """Run every regression test against `lab_url`. Return the exit code."""
    if not _is_loopback_url(lab_url):
        print(
            f"ERROR: refusing to run against {lab_url!r}; "
            "regression_test.py is loopback-only by design.",
            file=sys.stderr,
        )
        return 3

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
        # A small pause so the rate-limit test does not affect later tests.
        time.sleep(0.1)
    print("-" * 78)
    print(f"  {passes}/{passes + fails} exploits closed.")
    rc: int = 0 if fails == 0 else 1
    if also_check_db:
        ok, note = verify_no_plaintext_passwords(db_path)
        verdict = "PASS" if ok else "FAIL"
        print(f"  [{verdict}] DB: no plaintext passwords")
        print(f"         {note}")
        if not ok:
            rc = max(rc, 1)
    return rc


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Regression suite for the vuln_lab patches. "
            "AUTHORIZED USE ONLY: this script fires exploit payloads at the "
            "lab on your own loopback."
        )
    )
    parser.add_argument(
        "--lab",
        default=DEFAULT_LAB_URL,
        help=f"base URL of the lab (default {DEFAULT_LAB_URL})",
    )
    parser.add_argument(
        "--check-db",
        action="store_true",
        help="also verify that the lab database stores Argon2id hashes",
    )
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB_PATH),
        help=f"path to lab.db (default {DEFAULT_DB_PATH})",
    )
    args = parser.parse_args(argv)
    return run(args.lab, args.check_db, Path(args.db))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
