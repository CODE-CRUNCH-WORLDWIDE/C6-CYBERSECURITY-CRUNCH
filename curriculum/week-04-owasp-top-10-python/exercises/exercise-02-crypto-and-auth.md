# Exercise 2 — Cryptographic Failures and Authentication Failures

**Estimated time:** 60 minutes. Python 3.11, Flask, `argon2-cffi`. Local only.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Bind to 127.0.0.1. The vulnerable code is for your own machine.    │
│  Do not deploy any of this to a public service. Do not use the      │
│  attack scripts on a system you do not own.                         │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

A small notes app stores user passwords with `md5`, and generates session IDs from `int(time.time())`. You will demonstrate why both choices are vulnerable, then migrate the application to Argon2id passwords and `secrets`-based session IDs.

This exercise covers:

- **`A02:2021 Cryptographic Failures`** (CWE-327, CWE-916, CWE-330)
- **`A07:2021 Identification and Authentication Failures`** (CWE-287, CWE-916, CWE-384)

---

## Step 1 — The vulnerable app (10 min)

Write `auth_bad.py`:

```python
import hashlib
import sqlite3
import time
import random
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev-only-not-for-prod"

DB = "notes.db"

def get_db():
    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_md5 TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    return conn

def hash_password(pw: str) -> str:
    # VULNERABLE — A02, A07. md5 is broken; even sha256 would be wrong here.
    return hashlib.md5(pw.encode()).hexdigest()

def make_session_id() -> str:
    # VULNERABLE — A07. Predictable. An attacker who knows roughly when the
    # session was issued can enumerate the small space.
    return f"{int(time.time())}-{random.randint(0, 999)}"

@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_md5) VALUES (?, ?)",
            (username, hash_password(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return ("user exists", 409)
    return ("registered", 201)

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    db = get_db()
    row = db.execute(
        "SELECT id, password_md5 FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if row is None or row[1] != hash_password(password):
        return ("login failed", 401)
    sid = make_session_id()
    db.execute(
        "INSERT INTO sessions (session_id, user_id, created_at) VALUES (?, ?, ?)",
        (sid, row[0], int(time.time())),
    )
    db.commit()
    return (sid, 200)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)
```

Run: `python auth_bad.py`.

Register a user and log in:

```bash
curl -X POST http://127.0.0.1:5002/register \
    -d "username=alice" -d "password=correct horse battery staple"

curl -X POST http://127.0.0.1:5002/login \
    -d "username=alice" -d "password=correct horse battery staple"
# Note the session ID returned — looks like 1715616123-456
```

---

## Step 2 — Demonstrate the A02 (15 min)

The MD5 hashes in `users.password_md5` are crackable in seconds with a wordlist. Write `crack_md5.py`:

```python
import hashlib
import sqlite3

# A small wordlist — in reality, `rockyou.txt` (~14M passwords) cracks the majority
# of leaked password DBs in under a minute on a modern CPU.
WORDLIST = [
    "password", "123456", "qwerty", "letmein", "monkey",
    "correct horse battery staple", "alice", "bob",
    "password1", "12345678", "abc123",
]

conn = sqlite3.connect("notes.db")
for username, h in conn.execute("SELECT username, password_md5 FROM users"):
    for word in WORDLIST:
        if hashlib.md5(word.encode()).hexdigest() == h:
            print(f"CRACKED: {username} -> {word!r}")
            break
    else:
        print(f"NOT CRACKED: {username}")
```

Run: `python crack_md5.py`.

Alice's password is in the wordlist; the script prints the plaintext in milliseconds. The reason is structural: `md5` is **fast** — billions of guesses per second on GPU. Argon2id is **slow** by design — tunable to ~50 ms per attempt, which makes a wordlist attack take *years* per user instead of seconds.

**Capture the output** for the write-up.

---

## Step 3 — Demonstrate the A07 (10 min)

Write `predict_sid.py`. The session ID is `<unix_timestamp>-<0-999>`. If we observe a recent session ID (e.g. from a leaked log line, a Referer header, or a captured network packet) we know the timestamp window; brute-forcing the 0-999 suffix is trivial:

```python
import time

# Suppose we saw a session ID in a log:
seen_sid = "1715616123-456"
seen_ts = int(seen_sid.split("-")[0])

# We know sessions were issued near `seen_ts`. The space of plausible session IDs
# for a window of, say, 60 seconds before and after is:
candidates = []
for ts in range(seen_ts - 60, seen_ts + 60 + 1):
    for r in range(1000):
        candidates.append(f"{ts}-{r}")

print(f"candidate space: {len(candidates):,} session IDs")
# That's 121,000 candidates — a 5-minute curl loop, far inside the attack budget.
```

The attack: an attacker who knows the rough issuance time of a target session can enumerate the entire issuance space in under a minute. A real session ID space should be ≥ 2^128, which is 10^28 *times* the entire age of the universe to enumerate at a billion guesses per second.

---

## Step 4 — Patch the app (15 min)

Write `auth_good.py`:

```python
import secrets
import sqlite3
import time
from flask import Flask, request
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
app.secret_key = "dev-only-not-for-prod"

DB = "notes_good.db"

# Argon2id with defaults — ~50 ms / verify on a modern CPU. Tune via memory_cost,
# time_cost, parallelism for your deployment.
ph = PasswordHasher()

def get_db():
    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """)
    return conn

def make_session_id() -> str:
    # 256 bits of entropy from os.urandom. Unguessable in the heat death of the universe.
    return secrets.token_urlsafe(32)

@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    if len(password) < 8:
        return ("password too short", 400)
    # NIST SP 800-63B §5.1.1.2 — no composition rules, no rotation, allow long passphrases.
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, ph.hash(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return ("user exists", 409)
    return ("registered", 201)

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    db = get_db()
    row = db.execute(
        "SELECT id, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if row is None:
        # Constant-time-ish: still run a verify against a dummy hash so the
        # timing oracle cannot distinguish "user exists" from "user does not."
        try:
            ph.verify(ph.hash("dummy"), password)
        except VerifyMismatchError:
            pass
        return ("login failed", 401)
    try:
        ph.verify(row[1], password)
    except VerifyMismatchError:
        return ("login failed", 401)
    # If parameters have changed since this user registered, rehash.
    if ph.check_needs_rehash(row[1]):
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (ph.hash(password), row[0]),
        )
    now = int(time.time())
    sid = make_session_id()
    db.execute(
        "INSERT INTO sessions (session_id, user_id, created_at, expires_at) "
        "VALUES (?, ?, ?, ?)",
        (sid, row[0], now, now + 24 * 3600),
    )
    db.commit()
    return (sid, 200)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)
```

Three substantive changes from the bad version:

1. **`argon2.PasswordHasher`** for hashing and verification. The hash stored in the DB is a self-describing `$argon2id$...` string that records the parameters.
2. **`secrets.token_urlsafe(32)`** for session IDs. 256 bits of cryptographic entropy.
3. **`check_needs_rehash`** to transparently upgrade users on login when you raise the cost parameters.

Add a fourth: **expiry on the session row** (`expires_at`). Sessions that live forever are an A07 risk; a 24-hour default is conservative for a notes app.

Run it, register a user, log in. The session ID now looks like `4ZK7QzN2-pCqAh3WrPYjkBxmL5gFcw1XdR0E_NHTYVo`.

Re-run `crack_md5.py` (rename DB to `notes_good.db`, switch column to `password_hash`, and try to crack the Argon2 hash). Most wordlists will not crack it because each guess takes 50 ms; the cracker that completes in milliseconds against md5 will take *years* against Argon2id at default parameters.

---

## Step 5 — HIBP check (optional, 5 min)

Add an HIBP (Have I Been Pwned) check to `register`:

```python
import hashlib
import requests

def is_breached(password: str) -> bool:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
    r.raise_for_status()
    for line in r.text.splitlines():
        h, count = line.split(":")
        if h == suffix and int(count) > 0:
            return True
    return False
```

In `register`, after the length check:

```python
if is_breached(password):
    return ("password has appeared in a breach; choose a different one", 400)
```

The k-anonymity API never sees the full hash; only the 5-character SHA1 prefix is sent. Test with `password=password` — the API knows this one.

---

## Step 6 — Write up (5 min)

Run `bandit auth_bad.py` and `semgrep --config p/owasp-top-ten auth_bad.py` and note the findings.

Write `writeup.md` covering both vulnerabilities (md5 password storage; predictable session ID) with: categories (A02 / A07, CWE IDs), bug, fix, detection, residual risk.

---

## Acceptance criteria

- [ ] `auth_bad.py` runs; register and login work; session ID is in the predictable format.
- [ ] `crack_md5.py` cracks Alice's password in under one second.
- [ ] `predict_sid.py` shows the candidate-space calculation.
- [ ] `auth_good.py` runs; passwords are Argon2id; session IDs are `secrets.token_urlsafe(32)`.
- [ ] Sessions have an expiry; `check_needs_rehash` is wired up.
- [ ] (Optional) HIBP check added; tested with `password=password`.
- [ ] `writeup.md` covers categories, bug, fix, detection, residual risk for both A02 and A07.
- [ ] No code is bound to anything other than `127.0.0.1`.

## Why this exercise

The MD5/password lesson has been taught for fifteen years and it still ships in production code every week. The reason is that `hashlib.md5` is in the standard library and Argon2id is a `pip install`. The session-ID lesson is younger but recurs — `random.random()` and `time.time()` are right there in the standard library; `secrets` is also right there, half an import away, and never the one a tutorial recommends. The exercise is muscle memory: every time you reach for a password hash, reach for Argon2id; every time you reach for "a random ID," reach for `secrets`.
