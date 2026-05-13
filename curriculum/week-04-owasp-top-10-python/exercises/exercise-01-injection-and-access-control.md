# Exercise 1 — Injection and Broken Access Control

**Estimated time:** 60 minutes. Python 3.11, Flask, sqlite3. Local only.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Bind to 127.0.0.1. Run the vulnerable code on your own machine.    │
│  Do not deploy any of this code to a public service. Do not run     │
│  the attack payloads against a service you do not operate.          │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

You are reviewing the code of a small Flask app — a personal expense tracker. The app has two routes you have flagged in your reading: `/login` (authenticates a user against a SQLite database) and `/expense/<id>` (returns a single expense record by ID).

Your task is to reproduce the vulnerability in each, write the patched version, and document both.

This exercise covers:

- **`A03:2021 Injection`** (CWE-89 SQL Injection)
- **`A01:2021 Broken Access Control`** (CWE-639 Authorisation Bypass through User-Controlled Key — the IDOR family)

---

## Step 1 — Set up the database (5 min)

Create `init_db.py`:

```python
import sqlite3
from argon2 import PasswordHasher

ph = PasswordHasher()
conn = sqlite3.connect("expense.db")
cur = conn.cursor()
cur.executescript("""
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS expenses;

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE expenses (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    description TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
""")
for username, pw in [("alice", "alice-pw-12345"), ("bob", "bob-pw-67890")]:
    cur.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, ph.hash(pw)),
    )

# Alice's expenses
cur.execute("INSERT INTO expenses (user_id, description, amount_cents) VALUES (1, 'coffee', 450)")
cur.execute("INSERT INTO expenses (user_id, description, amount_cents) VALUES (1, 'lunch', 1800)")
# Bob's expenses — should not be visible to Alice
cur.execute("INSERT INTO expenses (user_id, description, amount_cents) VALUES (2, 'subscription', 9900)")
cur.execute("INSERT INTO expenses (user_id, description, amount_cents) VALUES (2, 'taxi', 2300)")

conn.commit()
print("seeded.")
```

Run:

```bash
python init_db.py
```

---

## Step 2 — Reproduce the SQL injection (15 min)

Write `sqli_bad.py`:

```python
import sqlite3
from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = "dev-only-not-for-prod"

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect("expense.db")
    cur = conn.cursor()
    # VULNERABLE — A03 Injection.
    query = f"SELECT id FROM users WHERE username = '{username}' AND password_hash = '{password}'"
    cur.execute(query)
    row = cur.fetchone()
    if row is None:
        return ("login failed", 401)
    session["user_id"] = row[0]
    return ("logged in", 200)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
```

Run it: `python sqli_bad.py`.

From a second terminal, demonstrate the bypass:

```bash
# Normal login fails (the password_hash column does not contain the plaintext password)
curl -i -X POST http://127.0.0.1:5001/login \
    -d "username=alice" -d "password=alice-pw-12345"

# Injection succeeds — comment out the password check
curl -i -X POST http://127.0.0.1:5001/login \
    --data-urlencode "username=alice' --" \
    --data-urlencode "password=anything"
```

You should see `HTTP/1.0 200 OK` on the injection request. **Take a screenshot or capture the terminal output** for the write-up; you will reference this as the proof-of-concept.

Stop the server with `Ctrl-C`.

---

## Step 3 — Patch the SQL injection (10 min)

Write `sqli_good.py`. The two fixes: parameterised query, and Argon2id verification.

```python
import sqlite3
from flask import Flask, request, session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
app.secret_key = "dev-only-not-for-prod"
ph = PasswordHasher()

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect("expense.db")
    cur = conn.cursor()
    # FIXED — parameter binding.
    cur.execute(
        "SELECT id, password_hash FROM users WHERE username = ?",
        (username,),
    )
    row = cur.fetchone()
    if row is None:
        return ("login failed", 401)
    try:
        ph.verify(row[1], password)
    except VerifyMismatchError:
        return ("login failed", 401)
    session["user_id"] = row[0]
    return ("logged in", 200)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
```

Run it and re-run the attack curl. You should see `HTTP/1.0 401 UNAUTHORIZED`. The legitimate login with the correct password should now succeed.

---

## Step 4 — Reproduce the IDOR (10 min)

Write `idor_bad.py`:

```python
import sqlite3
from flask import Flask, request, session, jsonify, abort

app = Flask(__name__)
app.secret_key = "dev-only-not-for-prod"

@app.before_request
def fake_login():
    # For the exercise — pretend Alice (user_id=1) is logged in via a query param.
    # Real code would use session middleware; this is the simulation.
    if request.args.get("as") == "alice":
        session["user_id"] = 1
    elif request.args.get("as") == "bob":
        session["user_id"] = 2

def login_required():
    if "user_id" not in session:
        abort(401)

@app.route("/expense/<int:expense_id>")
def get_expense(expense_id):
    login_required()
    conn = sqlite3.connect("expense.db")
    cur = conn.cursor()
    # VULNERABLE — A01 Broken Access Control.
    # The query does not check that the expense belongs to the current user.
    cur.execute(
        "SELECT id, user_id, description, amount_cents FROM expenses WHERE id = ?",
        (expense_id,),
    )
    row = cur.fetchone()
    if row is None:
        abort(404)
    return jsonify({"id": row[0], "user_id": row[1], "description": row[2], "amount_cents": row[3]})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
```

Run it. Demonstrate the IDOR:

```bash
# Alice reading her own expense — fine
curl -i "http://127.0.0.1:5001/expense/1?as=alice"

# Alice reading Bob's expense — leaks!
curl -i "http://127.0.0.1:5001/expense/3?as=alice"
```

Both return `200 OK` with the expense body. Alice is reading Bob's `subscription` charge. **Capture the output.**

---

## Step 5 — Patch the IDOR (10 min)

Write `idor_good.py`. The fix is to scope the query to `current_user`:

```python
import sqlite3
from flask import Flask, request, session, jsonify, abort

app = Flask(__name__)
app.secret_key = "dev-only-not-for-prod"

@app.before_request
def fake_login():
    if request.args.get("as") == "alice":
        session["user_id"] = 1
    elif request.args.get("as") == "bob":
        session["user_id"] = 2

def current_user_id():
    uid = session.get("user_id")
    if uid is None:
        abort(401)
    return uid

@app.route("/expense/<int:expense_id>")
def get_expense(expense_id):
    uid = current_user_id()
    conn = sqlite3.connect("expense.db")
    cur = conn.cursor()
    # FIXED — query scoped to the authenticated user.
    cur.execute(
        "SELECT id, user_id, description, amount_cents "
        "FROM expenses WHERE id = ? AND user_id = ?",
        (expense_id, uid),
    )
    row = cur.fetchone()
    if row is None:
        # 404 (not 403) — do not leak existence of resources the user does not own.
        abort(404)
    return jsonify({"id": row[0], "user_id": row[1], "description": row[2], "amount_cents": row[3]})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
```

Re-run the curls:

```bash
curl -i "http://127.0.0.1:5001/expense/1?as=alice"   # 200
curl -i "http://127.0.0.1:5001/expense/3?as=alice"   # 404, as if it doesn't exist
curl -i "http://127.0.0.1:5001/expense/3?as=bob"     # 200 — Bob can read his own
```

The authorisation is now structural: the query itself filters by `user_id`, so there is no code path that returns another user's expense.

---

## Step 6 — Static-analyse and write up (10 min)

Run `bandit` and `semgrep` against both `_bad.py` files:

```bash
bandit sqli_bad.py idor_bad.py
semgrep --config p/owasp-top-ten sqli_bad.py idor_bad.py
```

Note which findings each tool catches and which it misses. (`bandit` will catch the f-string-into-SQL pattern; `semgrep`'s OWASP ruleset catches more.)

Write `writeup.md` with the sections from the exercises README — categories, bug, fix, detection, residual risk.

---

## Acceptance criteria

- [ ] `init_db.py` seeds the database with two users and four expenses.
- [ ] `sqli_bad.py` and `sqli_good.py` both run; the bypass works against the first and fails against the second.
- [ ] `idor_bad.py` and `idor_good.py` both run; cross-user read works against the first and fails against the second.
- [ ] Captured terminal output (in the write-up or as `pocs.txt`) demonstrates both vulnerabilities.
- [ ] `bandit` and `semgrep` outputs noted in the write-up (one paragraph each on coverage).
- [ ] `writeup.md` covers categories (OWASP IDs + CWE IDs), bug, fix, detection, residual risk for *each* of the two vulnerabilities (two short blocks).
- [ ] No code is bound to anything other than `127.0.0.1`.

## Why this exercise

These are the two categories the security engineer sees most often in code review. SQL injection because parameterisation is one keystroke away and developers under deadline still ship the f-string. Broken access control because `@login_required` is *visible* on every route and the developer assumes the authorisation check is implicit when it is not. Both have the property that the fix is small, the defect is obvious in hindsight, and the next learner of this exercise will read the patched version and not understand why anyone would ship the broken one — that recognition is what you are training.
