"""
vuln_lab - deliberately vulnerable Flask 3.x application for C6 Week 8.

============================== AUTHORIZED USE ONLY =============================
This application contains deliberate vulnerabilities. It binds to 127.0.0.1
only. Do not change the bind address. Do not deploy this application
anywhere except your own laptop. Do not expose the lab port to a network
you share with others.

The lab is the only authorised target for the Lecture 2 exploit payloads.
================================================================================

The eight intentional vulnerabilities (OWASP Top 10 2021):

  /lookup          - SQL injection via string concatenation             (A03, CWE-89)
  /search          - Reflected XSS via Markup() bypass of autoescape    (A03, CWE-79)
  /comments        - Stored XSS via |safe filter in the template        (A03, CWE-79)
  /thumbnail       - OS command injection via os.system + shell parsing (A03, CWE-78)
  /profile         - IDOR (object-level authz missing)                  (A01, CWE-639)
  /admin/users     - Missing function-level authorization               (A01, CWE-306)
  /login           - Plaintext passwords, no rate limit, weak tokens    (A07, CWE-256/307/330)
  /import-profile  - Insecure deserialization via pickle.loads          (A08, CWE-502)
  /fetch-image     - Server-Side Request Forgery (no allow-list)        (A10, CWE-918)

Plus a security misconfiguration sample at /debug-trigger that, with debug=True,
exposes the Werkzeug interactive debugger and yields RCE (A05).

Patches are applied during the Week 8 mini-project. See ../README.md for the
patch sequence. SOLUTIONS.md has each patch in full.
"""

from __future__ import annotations

import base64
import os
import pickle
import random
import sqlite3
from pathlib import Path

import requests
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------


DB_PATH: Path = Path(__file__).parent / "lab.db"

app: Flask = Flask(__name__)
# Static, predictable secret key - itself a finding worth noting (CWE-798:
# Use of Hard-coded Credentials). Patched to secrets.token_urlsafe() per
# Lecture 3.
app.secret_key = "lab-only-static-key-do-not-use-in-production"


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def _connect() -> sqlite3.Connection:
    """Open a connection to the lab database."""
    return sqlite3.connect(str(DB_PATH))


def _current_user() -> dict | None:
    """Return the session user as a dict, or None if not logged in."""
    user_id: int | None = session.get("user_id")
    if user_id is None:
        return None
    conn = _connect()
    cursor = conn.cursor()
    row = cursor.execute(
        "SELECT id, username, email, role FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    return {"id": row[0], "username": row[1], "email": row[2], "role": row[3]}


def _save_comment(body: str) -> None:
    """Append a comment to the comments table."""
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO comments (body) VALUES (?)", (body,))
    conn.commit()
    conn.close()


def _load_comments() -> list[dict]:
    """Read all comments in insertion order."""
    conn = _connect()
    cursor = conn.cursor()
    rows = cursor.execute(
        "SELECT id, body FROM comments ORDER BY id ASC"
    ).fetchall()
    conn.close()
    return [{"id": row[0], "body": row[1]} for row in rows]


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------


@app.route("/")
def index() -> str:
    """Public homepage. No vulnerabilities here on purpose."""
    return render_template("index.html", user=_current_user())


@app.route("/login", methods=["GET", "POST"])
def login() -> object:
    """Login endpoint.

    Vulnerabilities (A07, A02):
      - Plaintext password comparison; no Argon2id / bcrypt.
      - No rate limit; brute force is unconstrained.
      - Session token generated with random.random() - CWE-330 / CWE-338.
    """
    if request.method == "POST":
        username: str = request.form.get("username", "")
        password: str = request.form.get("password", "")
        conn = _connect()
        cursor = conn.cursor()
        row = cursor.execute(
            "SELECT id FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        conn.close()
        if row is None:
            return "bad credentials", 401
        session["user_id"] = row[0]
        # CWE-330: random.random() is the Mersenne Twister - predictable.
        session["token"] = str(random.random())
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout")
def logout() -> object:
    session.clear()
    return redirect(url_for("index"))


@app.route("/whoami")
def whoami() -> dict:
    """Diagnostic endpoint exposing session contents (lab convenience)."""
    return {
        "user_id": session.get("user_id"),
        "token": session.get("token"),
    }


@app.route("/profile")
def profile() -> object:
    """Profile page.

    Vulnerability (A01, CWE-639): the `id` query parameter is not validated
    against the session user's id. Any authenticated user can view any other
    user's profile by changing the `id` in the URL.
    """
    if "user_id" not in session:
        return redirect(url_for("login"))
    requested_id: int = int(request.args.get("id", "0"))
    conn = _connect()
    cursor = conn.cursor()
    row = cursor.execute(
        "SELECT id, username, email FROM users WHERE id = ?",
        (requested_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return "no such user", 404
    user_row: dict = {"id": row[0], "username": row[1], "email": row[2]}
    return render_template("profile.html", user=user_row)


@app.route("/admin/users")
def admin_users() -> object:
    """Admin user list.

    Vulnerability (A01, CWE-306): the endpoint checks "is a user logged in?"
    but does not check "is the user an admin?" Any authenticated user can
    list all users including plaintext passwords.
    """
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = _connect()
    cursor = conn.cursor()
    rows = cursor.execute(
        "SELECT id, username, email, password, role FROM users"
    ).fetchall()
    conn.close()
    user_rows: list[dict] = [
        {
            "id": r[0],
            "username": r[1],
            "email": r[2],
            "password": r[3],
            "role": r[4],
        }
        for r in rows
    ]
    return render_template("admin.html", rows=user_rows)


@app.route("/search")
def search() -> str:
    """Search page.

    Vulnerability (A03, CWE-79 reflected): Markup() wraps the user-supplied
    query, telling Jinja "do not escape this string." The reflected query
    renders as raw HTML; injected <script> tags execute in the browser.
    """
    q: str = request.args.get("q", "")
    return render_template("search.html", q=Markup(q), results=[])


@app.route("/comments", methods=["GET", "POST"])
def comments() -> object:
    """Comments page.

    Vulnerability (A03, CWE-79 stored): the body of each comment is stored
    verbatim and the template renders it with |safe, which bypasses
    autoescape. Every visitor to /comments runs whatever the previous poster
    submitted.
    """
    if request.method == "POST":
        body: str = request.form.get("body", "")
        _save_comment(body)
        return redirect(url_for("comments"))
    rows: list[dict] = _load_comments()
    return render_template("comments.html", rows=rows)


@app.route("/lookup")
def lookup() -> str:
    """User-lookup page.

    Vulnerability (A03, CWE-89): the SQL query is built by string concatenation.
    A payload of `' OR 1=1 --` returns every row; a UNION-based payload can
    exfiltrate the password column.
    """
    name: str = request.args.get("name", "")
    conn = _connect()
    cursor = conn.cursor()
    # CWE-89: never do this.
    sql: str = (
        "SELECT id, username, email FROM users WHERE username = '" + name + "'"
    )
    try:
        rows = cursor.execute(sql).fetchall()
    except sqlite3.Error as exc:
        conn.close()
        return f"sql error: {exc}", 500
    conn.close()
    row_dicts: list[dict] = [
        {"id": r[0], "username": r[1], "email": r[2]} for r in rows
    ]
    return render_template("lookup.html", rows=row_dicts, name=name)


@app.route("/thumbnail")
def thumbnail() -> object:
    """Thumbnail-conversion endpoint.

    Vulnerability (A03, CWE-78): os.system invokes /bin/sh -c, which parses
    shell metacharacters in the user-supplied filename. A payload of
    `cat.png; id > /tmp/c6-pwned` runs `id` after the (failed) convert.
    """
    filename: str = request.args.get("file", "")
    # CWE-78: never do this.
    os.system("convert " + filename + " /tmp/out.png")
    return "done"


@app.route("/debug-trigger")
def debug_trigger() -> str:
    """Intentionally raise an exception.

    Vulnerability (A05): with debug=True, the response is the Werkzeug
    interactive debugger, which exposes a Python REPL gated by a PIN that
    is printed to stdout at server start. RCE in one page-load.
    """
    raise ValueError("intentional exception for the debug-mode demo")


@app.route("/import-profile", methods=["POST"])
def import_profile() -> str:
    """Profile-import endpoint.

    Vulnerability (A08, CWE-502): pickle.loads on attacker-controlled bytes.
    A malicious pickle's __reduce__ executes during deserialisation.
    """
    blob_b64: str = request.form.get("blob", "")
    if not blob_b64:
        return "no blob", 400
    try:
        decoded: bytes = base64.b64decode(blob_b64)
    except Exception as exc:  # noqa: BLE001
        return f"bad base64: {exc}", 400
    # CWE-502: never do this on data from a trust boundary.
    try:
        data = pickle.loads(decoded)
    except Exception as exc:  # noqa: BLE001
        return f"pickle error: {exc}", 400
    username: object = "unknown"
    if isinstance(data, dict):
        username = data.get("username", "unknown")
    return f"imported profile for {username}"


@app.route("/fetch-image")
def fetch_image() -> object:
    """Fetch an image by URL.

    Vulnerability (A10, CWE-918): no allow-list, no scheme check, no
    destination-IP validation. The server fetches arbitrary URLs the
    attacker supplies, including loopback / RFC-1918 / cloud-metadata
    addresses.
    """
    url: str = request.args.get("url", "")
    if not url:
        return "no url", 400
    try:
        response = requests.get(url, timeout=5)
    except requests.RequestException as exc:
        return f"fetch failed: {exc}", 502
    # Return the body and the upstream content type.
    return (
        response.content,
        response.status_code,
        {"Content-Type": response.headers.get("Content-Type", "application/octet-stream")},
    )


# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------


if __name__ == "__main__":
    # AUTHORIZED USE ONLY: bind to loopback. Do not change to 0.0.0.0.
    # CWE-489 (A05): debug=True exposes the Werkzeug interactive debugger.
    app.run(host="127.0.0.1", port=5000, debug=True)
