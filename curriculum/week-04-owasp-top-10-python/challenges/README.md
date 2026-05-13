# Week 4 — Challenges

One scoped, multi-hour challenge this week. The exercises trained you on category pairs in isolated code. The challenge sends you into a single Flask application and asks you to audit it against all ten OWASP Top 10 categories, anchoring each finding to a specific line of code.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The challenge app is deliberately vulnerable and ships in this     │
│  repository. Run it on 127.0.0.1 only. Do not deploy it anywhere    │
│  else, even briefly. Do not test the techniques in this challenge   │
│  against any service you do not operate.                            │
└─────────────────────────────────────────────────────────────────────┘
```

## Index

| Challenge | Time | Deliverable |
|---|---|---|
| [challenge-01-audit-flask-app.md](./challenge-01-audit-flask-app.md) | ~4 hours | Audit report covering all 10 OWASP Top 10 2021 categories on a small Flask application |

## How challenges differ from exercises

| Exercises | Challenges |
|---|---|
| Single category, single shape | Multiple categories, one codebase |
| Bug pre-named in the brief | Bugs you find by reading and probing |
| ~45-60 min each | ~4 hours |
| Code-and-write-up output | Audit-report-style write-up |

The challenge is the *on-ramp* to the mini-project. It uses a smaller codebase (~250 lines of Flask) than the mini-project, so you can practise the audit *method* before you face the mini-project's larger app.

## Submission

Commit the challenge as a directory in your `c6-week-04` repo:

```
challenge-01/
    audit-report.md
    findings/
        F-01-A03-injection.md
        F-02-A01-idor.md
        ...
    notes/
        bandit-output.txt
        semgrep-output.txt
        pip-audit-output.txt
```

The audit report is the cover document; each finding is its own file in the standard format (title, category, CWE, severity, location, proof-of-concept, remediation, references). The notes directory captures the raw tool output you used as evidence.
