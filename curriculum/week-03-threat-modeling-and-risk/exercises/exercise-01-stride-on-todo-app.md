# Exercise 1 — STRIDE on a Todo-list Web App

**Estimated time:** 50 minutes. Pen and paper for the diagram; Markdown for the threat list.

## Scenario

You are the security engineer brought in to threat-model a small web application before its first public release. The product team has described it as follows:

> *A self-hosted todo-list web app. Users register with email and password. Once logged in, they create, edit, delete, and mark complete a list of todo items. There is a single shared "team" mode (optional) where multiple users see the same list. The app is deployed as a single container behind a reverse proxy; the database is a PostgreSQL instance on the same host. Backups run nightly to an S3-compatible object store.*

Your task is to draw a data-flow diagram, walk STRIDE per element, and produce a candidate threat list.

---

## Step 1 — Draw the DFD (15 minutes)

On paper, draw a Level 1 DFD with at minimum:

- **External entities:** User (browser); Backup destination (the S3-compatible store).
- **Processes:** Reverse proxy; Web app; Backup worker.
- **Data stores:** PostgreSQL DB; Object store backups.
- **Data flows:** label every one. *credentials*, *session cookie*, *todo CRUD JSON*, *SQL queries*, *DB dumps*, *backup objects*.
- **Trust boundaries:** at least three. The internet ↔ reverse proxy boundary; the host process ↔ DB boundary (loopback or VPC); the host ↔ object-store boundary.

Photograph or scan the DFD. Commit as `exercise-01-dfd.png` (or `.jpg`). It does not need to be pretty; it needs to be legible.

**Acceptance for step 1:** the DFD has all five element types, every flow is labelled with *what data* is flowing, and the trust boundaries are dashed lines crossing flows (not just enclosing components).

---

## Step 2 — Walk STRIDE per element (25 minutes)

In `exercise-01-threats.md`, produce a table:

| ID | Element | STRIDE letter | Threat (one sentence) | Vulnerability (if known) | Likely mitigation |
|---|---|---|---|---|---|
| T-01 | User | S | An attacker logs in as another user. | Login form has no rate limiting or breached-password block. | Rate-limit at proxy; HIBP password check on register/change. |
| T-02 | User | R | A user later denies having deleted a todo. | No application-level audit log records *who* did *what*, *when*. | Append-only action log keyed by user ID. |
| ... | ... | ... | ... | ... | ... |

Walk through each element of the DFD systematically. Use the STRIDE-per-element prompt table from Lecture 1:

| DFD element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| External entity | ✓ |  | ✓ |  |  |  |
| Process | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data store |  | ✓ | ✓ | ✓ | ✓ |  |
| Data flow |  | ✓ |  | ✓ | ✓ |  |

**Minimum row count:** 18. Each threat must anchor to a specific element on your DFD; "general SQL injection" is not anchored — "SQL injection at the Web-app process via the todo-CRUD JSON flow" is.

**Required coverage:** every STRIDE letter appears at least twice across the table. If you have zero R (Repudiation) threats, you skipped a letter; go back and ask, of every process and every data store, *if a user later denies having done this, can we prove they did?*

---

## Step 3 — Mark the trust-boundary threats (5 minutes)

In a second short section of `exercise-01-threats.md`, list which of your threats *materially depend on a trust boundary being crossed*. These are usually the most important ones — they describe attacks on the boundary itself.

For each, name the boundary explicitly:

- *T-01 (Spoofing) crosses the internet ↔ reverse proxy boundary.*
- *T-09 (Information disclosure) crosses the host ↔ object-store boundary; cleartext backup uploaded over an unauthenticated channel would be visible to a network observer.*

**Acceptance for step 3:** at least three trust-boundary-crossing threats named.

---

## Step 4 — Self-review (5 minutes)

Re-read the threat list cold. Three checks:

1. **The "scary list" check.** Could you remove the DFD from in front of you and still see where each threat lives? If a threat is not anchored, fix it.
2. **The "all green" check.** Are all your mitigations specific (a rule, a check, a configuration)? Or are some of them "we use TLS" / "we have a firewall"? Specify.
3. **The Repudiation check.** Did the R threats get the same care as the S and the I? Most beginners under-attend R; check yours.

---

## Deliverables

In a directory `exercise-01/`:

- `exercise-01-dfd.png` — your hand- or tool-drawn DFD.
- `exercise-01-threats.md` — the threat table, the trust-boundary list, and a short paragraph (3-4 sentences) of self-review reflecting on what surprised you, what was hardest to fill in, and what STRIDE letter you almost missed.

## Acceptance criteria

- [ ] DFD present, all five element types, flows labelled, trust boundaries dashed.
- [ ] At least 18 threats in the table.
- [ ] Every STRIDE letter appears at least twice.
- [ ] At least three trust-boundary-crossing threats explicitly named.
- [ ] Every threat is anchored to a specific element or flow on the DFD.
- [ ] Every mitigation is a specific control, not a vague reassurance.
- [ ] Self-review paragraph names at least one surprise.

## Why this exercise

STRIDE only works as a habit. The first time you walk it, it feels mechanical and slow; the third time, the prompts are internalised and you walk a DFD in 30 minutes. This is the first walk. The second is the mini-project. The third — and every one after — is the rest of your career as a security engineer.
