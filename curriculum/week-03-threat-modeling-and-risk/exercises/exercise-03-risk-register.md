# Exercise 3 — Build a Risk Register

**Estimated time:** 45 minutes. Requires the outputs of Exercises 1 and 2.

This exercise turns the two prior outputs — a STRIDE threat list (exercise 1) and an attack tree with hardening recommendations (exercise 2) — into a single working risk register. The register is the artifact you would actually hand to a senior engineer, an auditor, or your own future self in six months.

---

## Step 1 — Define the buckets in writing (10 minutes)

Before you score anything, define what *Low*, *Medium*, and *High* mean for both likelihood and impact. These definitions live in the preamble of the register and govern every row.

Write them in `exercise-03-register.md` under a heading `## Scoring scale`. Sample bucket definitions for the combined "todo app + SSH server" scope; *write your own; do not copy*:

> ### Likelihood
> - **Low.** No evidence of active exploitation against this class of system; requires non-trivial attacker effort, specific positioning, or a known-difficult precondition.
> - **Medium.** Documented exploitation against similar systems in the last 12 months; off-the-shelf tooling exists; an attacker with a few hours of effort and a public PoC can attempt it.
> - **High.** Observed daily against systems with this exposure profile (e.g. internet-exposed SSH); commodity automated tooling routinely succeeds; no special positioning required.
>
> ### Impact
> - **Low.** A single user's data is exposed; service partially degraded; recoverable from backup with negligible business consequence.
> - **Medium.** Multiple users' data exposed; service unavailable for hours; trust degradation requires user-facing disclosure.
> - **High.** All users' data or credentials exposed; service unavailable for days; regulatory disclosure obligation; the project may not retain its user base.

**Acceptance for step 1:** the definitions are written, are concrete (mention numbers or examples), and would let a second analyst score the same finding to the same bucket without consulting you.

---

## Step 2 — Map the 3 × 3 priority matrix (5 minutes)

State, in the same preamble, how likelihood-impact pairs map to priority. The C6-recommended default:

| L↓ / I → | Low | Medium | High |
|---|---|---|---|
| **High** | Medium | High | High |
| **Medium** | Low | Medium | High |
| **Low** | Low | Low | Medium |

State explicitly: *Low-likelihood/High-impact findings are Medium priority (not Low), to mitigate tail-risk underweighting (cf. Taleb, The Black Swan).*

State the override convention: *individual findings may be escalated above the matrix default with a written justification in the row's `Priority override` field.*

---

## Step 3 — Build the register (20 minutes)

Combine the findings from Exercises 1 and 2 into a single register table. Use the following columns (or a verbose vertical layout, one finding per section):

| ID | Title | Source | STRIDE | ATT&CK | Likelihood | Impact | Priority | Owner | Status | Mitigation | Residual | Review |
|----|-------|--------|--------|--------|-----------|--------|----------|-------|--------|------------|----------|--------|

Notes on each column:

- **ID.** `R-0001` through `R-NN`. Stable identifiers; do not renumber.
- **Title.** One line, in the form *"\<asset\> \<verb\> by \<actor\> via \<path\>"*.
- **Source.** "Ex-01 T-03" or "Ex-02 leaf 'sudo NOPASSWD on apt'" — link back so the lineage is auditable.
- **STRIDE.** The letter(s) the finding maps to.
- **ATT&CK.** The technique ID if applicable; blank if not.
- **Likelihood / Impact / Priority.** Per the buckets and the matrix.
- **Owner.** A named individual. ("Me" is acceptable for an exercise; for a real register, name a real person.)
- **Status.** Open / Mitigating / Mitigated / Accepted / Transferred / Avoided.
- **Mitigation.** What is being done. Specific.
- **Residual.** What remains after the mitigation. *"L/L; targeted slow-roll attacks below rate-limit threshold remain possible"* is a complete entry.
- **Review.** Cadence and next-review date.

**Minimum size:** at least 12 register entries, drawn from the union of Exercises 1 and 2. Each entry must trace back to a specific finding via the *Source* column.

**Required:** at least one entry per disposition category (Mitigate, Transfer, Avoid, Accept), where the entry can plausibly support that disposition. If no entry in your set could plausibly be *transferred* (e.g. via insurance) or *avoided* (e.g. by removing the feature), say so in writing — the exercise is to engage with the four dispositions, not to assign them artificially.

---

## Step 4 — Identify the compounds (5 minutes)

After populating the register, walk the highest-priority entries and ask, of each pair, *does this combine with that one to enable an attack neither does alone?* For each pair where the answer is yes, add a new row to the register describing the compound.

Example, from a real engagement: a *Low* finding ("the admin panel is exposed on a separate subdomain with no IP allowlist") and a *Medium* finding ("the admin password rotation policy is annual") combine into a *High* compound finding (a stable, internet-exposed administrative login surface — exactly the surface credential stuffing succeeds against).

**Acceptance for step 4:** at least one compound finding identified or, if none apply, a one-paragraph written argument that the highest-priority findings are genuinely independent.

---

## Step 5 — Self-review (5 minutes)

In a final section of the register, the self-review paragraph. Three questions to answer in writing:

1. **Disposition discipline.** Did you assign each row a real disposition, or did some rows quietly remain "open" without a plan? (If yes, the register is incomplete.)
2. **Tail-risk discipline.** Did any of your *Low likelihood* findings have a written worst-case scenario? (If not, sample two of them and write one.)
3. **The "did we do a good job" question.** What evidence would tell you, six months from now, that this register was an effective artifact? Detection telemetry? Successful audits? The absence of an incident the register predicted?

---

## Deliverable

`exercise-03-register.md` containing:

- The scoring scale (step 1).
- The priority matrix and override convention (step 2).
- The register table or per-finding sections (step 3).
- The compound-findings section (step 4).
- The self-review paragraph (step 5).

## Acceptance criteria

- [ ] Likelihood and Impact buckets defined in writing with concrete criteria.
- [ ] 3 × 3 priority matrix stated, with the explicit Low-likelihood/High-impact → Medium escalation.
- [ ] At least 12 register entries.
- [ ] Every entry has all the required columns filled — no `TODO` cells.
- [ ] Every entry has a named owner and a residual-risk note.
- [ ] At least one Mitigate, one Transfer-or-Avoid, and one Accept entry — or a written argument explaining why one is impossible to assign in this scope.
- [ ] At least one compound finding identified, or a written argument that none apply.
- [ ] Self-review paragraph addresses all three required questions.

## Why this exercise

The threat model becomes a working artifact when it produces a register. Without a register, the analysis is a one-time document that ages out. With a register — owned, reviewed, updated post-incident — the analysis is an organisational asset. Every senior security engineer can walk a STRIDE pass; the practitioners who stand out are the ones whose registers are *clean*, *current*, and *demonstrably tied to the operational reality* of the system. This exercise is your first one.
