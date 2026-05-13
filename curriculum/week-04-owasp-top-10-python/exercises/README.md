# Week 4 — Exercises

Three hands-on exercises in Python. Each one walks a pair of OWASP Top 10 categories on small, runnable code you write yourself, with the vulnerable version and the fix side by side. The exercises are warm-up for the mini-project, which patches all ten categories in a larger vulnerable app.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Run the vulnerable code in this exercise set on your own machine   │
│  only. Bind to 127.0.0.1. Do not expose any exercise app to the     │
│  public internet, even briefly, even behind a "secret" port. Do     │
│  not run the attack payloads against a service you do not operate.  │
└─────────────────────────────────────────────────────────────────────┘
```

## Index

| Exercise | Categories | Time | Deliverable |
|---|---|---|---|
| [exercise-01-injection-and-access-control.md](./exercise-01-injection-and-access-control.md) | `A03 Injection`, `A01 Broken Access Control` | 60 min | Patched Flask login + patched IDOR route, write-up |
| [exercise-02-crypto-and-auth.md](./exercise-02-crypto-and-auth.md) | `A02 Cryptographic Failures`, `A07 Auth Failures` | 60 min | Argon2id migration, `secrets`-based session IDs, write-up |
| [exercise-03-ssrf-and-deserialisation.md](./exercise-03-ssrf-and-deserialisation.md) | `A10 SSRF`, `A08 Software & Data Integrity` | 45 min | Allow-listed URL preview, JSON-instead-of-pickle, write-up |

## Setup — once per machine

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install flask sqlalchemy argon2-cffi requests defusedxml pyyaml structlog
pip install bandit semgrep pip-audit
```

Verify:

```bash
python -c "import flask, argon2, requests; print('ok')"
bandit --version
semgrep --version
pip-audit --version
```

## How to run each exercise

Each exercise has two files: `<topic>_bad.py` (vulnerable) and `<topic>_good.py` (patched). You will write both. Run with:

```bash
python <topic>_bad.py    # exposes the bug; you reproduce it from another terminal
python <topic>_good.py   # the fix; you verify the bug is gone
```

Bind to `127.0.0.1`. Use a non-default port (`5001`, `5002`, `5003`) to avoid colliding with the mini-project app.

## Submission

Commit each exercise as a directory in your `c6-week-04` repo:

```
exercise-01-injection-and-access-control/
    sqli_bad.py
    sqli_good.py
    idor_bad.py
    idor_good.py
    writeup.md
exercise-02-crypto-and-auth/
    ...
exercise-03-ssrf-and-deserialisation/
    ...
```

Each `writeup.md` is short — 200-400 words — covering:

1. The OWASP Top 10 category IDs (2021 and 2025-RC if applicable) and the CWE IDs.
2. The bug, in one sentence anchored to the vulnerable line.
3. The fix, in one sentence anchored to the patched line.
4. The defender-side detection — what log line, what metric, what tooling would catch this.
5. One residual risk after the fix.

The write-up is the artifact a hiring manager reads. The code is the evidence behind it.
