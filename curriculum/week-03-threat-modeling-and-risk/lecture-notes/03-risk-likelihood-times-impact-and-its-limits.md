# Lecture 3 — `Risk = Likelihood × Impact` and its Limits

> *Multiplying two squishy numbers does not produce a precise third one. The "risk equals likelihood times impact" formula is the most-quoted, most-misused tool in our field. Use it as a sorting heuristic, write down the assumptions, and never let it stand alone as a decision.*

Lectures 1 and 2 produced threats. This lecture turns threats into *decisions*. You will not fix every threat; you cannot, and you should not pretend you can. The artifact that drives prioritisation, ongoing tracking, and accountability is the **risk register**. The formula that most teams reach for first is `Risk = Likelihood × Impact`. This lecture covers both — the register as a working artifact and the formula as a useful but brittle scoring tool.

It also covers DREAD (deprecated by Microsoft, partially salvageable), qualitative bucketing (Shostack's preferred alternative), and the tail-risk problem that no multiplied-ordinals approach can solve. By the end you will be able to score a finding without producing false precision and explain to a stakeholder why your number is the number, and where it should not be trusted.

---

## 1. The formula

The formula every introductory security text reproduces:

```
Risk = Likelihood × Impact
```

with each factor on some scale — often 1 to 5, sometimes Low / Medium / High mapped to integers, sometimes a probability and a dollar value, sometimes a heat-map cell color.

The formula's appeal is real:

- **It produces a single number.** A risk register sorted by that number gives a defensible priority order.
- **It separates *whether* an attack happens from *how bad* it is.** That separation is conceptually correct; an unlikely catastrophe and a daily nuisance are different problems.
- **It is easy to teach.** A junior analyst can apply it to a new finding the day they read about it.

The formula's failure modes are also real, and this lecture is mostly about those.

---

## 2. Where the formula works as a heuristic

For a *sorting* purpose, on a *bounded* set of *comparable* threats, the formula is fine — even useful. The use case is:

- You have produced 30 threats from a STRIDE pass.
- You need to communicate to a non-security stakeholder which ones the team should address first.
- You have to do this in a one-page document, in language the stakeholder will read.

A Low / Medium / High likelihood and Low / Medium / High impact, mapped to a 3 × 3 matrix with the cells coloured, gives the stakeholder a tractable ordering. Eight Low-Low threats below the line, three High-High threats above the line: the conversation goes where it needs to go.

The formula is, in this case, a *communication* tool, not a measurement.

---

## 3. Where the formula fails — the documented modes

### Failure mode 1 — false precision

When the inputs are ordinals (1 to 5, Low to High), the multiplied output looks like a number on a ratio scale but is not. "A risk of 12" feels meaningfully larger than "a risk of 9". It is not. The 12 was produced by `4 × 3` from inputs that were never themselves meaningful on a ratio scale; the 9 was produced by `3 × 3`. The difference is rounding noise dressed as analysis.

The fix: do not display the multiplied number to stakeholders. Display the heat-map cell instead. The cell encodes "high likelihood, medium impact" — which is what the inputs actually said.

### Failure mode 2 — the squishy inputs problem

Both likelihood and impact, in real threat models, are estimates produced by analysts under uncertainty. *Either of them being off by one bucket can flip the conclusion.* And the buckets are themselves ill-defined; "Medium likelihood" means different things to different analysts even on the same team.

The fix: define your buckets in writing, at the start of the engagement. *Low likelihood* might mean "we are aware of no observed exploit attempts in the past 12 months"; *High likelihood* might mean "we have observed daily attempts". Now two analysts can disagree about which bucket a finding goes in, but they can disagree *meaningfully* — over the evidence, not the vocabulary.

### Failure mode 3 — the tail-risk problem

The formula's worst failure is **at the tail**: rare, catastrophic events. Nassim Taleb's *The Black Swan* (Random House, 2007) is the durable reference on why. The argument is simple: when the impact distribution has a long tail — when the worst-case is *much* worse than the typical case — multiplying the central likelihood by the central impact systematically understates the risk.

In security terms: a low-likelihood breach of a customer-credential database, multiplied by a "typical incident" impact, produces a moderate risk number. The *actual* impact distribution includes regulatory disclosure costs, class-action lawsuits, the cost of credential rotation for every user, an executive resignation, and brand damage that takes a decade to recover. The multiplied number does not see any of this; it sees an average.

The fix: at the tail, complement the formula with a **named, written worst-case scenario**. "The likelihood is low, but the worst-case is the public disclosure of every user's credential history; we are unwilling to accept this even at low likelihood." A written scenario forces the conversation past the multiplied number.

### Failure mode 4 — likelihood is harder than impact

Impact, given an incident, is *somewhat* estimable: the analyst can model the data exposed, the systems unavailable, the regulatory consequence. Likelihood is much harder. It depends on the threat actor's interest, the cost-of-attack, the attacker's competing options — all things the analyst typically has no data on.

The fix: separate the two estimates explicitly. Be specific about impact ("if this happens, here is what is lost"). Be honest about likelihood ("we do not know; here is what we would have to know to estimate it"). A "We do not know" likelihood is a finding in its own right, and one of the most actionable: it indicates a measurement gap to close (telemetry, intelligence, monitoring).

### Failure mode 5 — risk is not additive across independent findings

Even when each finding is scored correctly, the *sum* of risks is not a sum. Two medium-risk findings on the same component can interact to produce a high-risk *compound* finding the register does not see. The register sees them as independent rows.

The fix: at the end of a STRIDE pass, walk the highest-risk findings and ask, of each pair, "does this combine with that one to enable an attack neither does alone?" The answer is sometimes yes, and the combined attack belongs in the register as its own row.

---

## 4. DREAD — history and partial rehabilitation

DREAD was introduced inside Microsoft alongside STRIDE in the late 1990s. The acronym names five factors:

| DREAD letter | Factor | What it asks |
|---|---|---|
| **D** | **Damage** potential | If this is exploited, how bad is it? |
| **R** | **Reproducibility** | How reliably does the exploit work? |
| **E** | **Exploitability** | How much skill, time, or tooling is required? |
| **A** | **Affected users** | What fraction of the user base is touched? |
| **D** | **Discoverability** | How likely is the vulnerability to be found by an attacker? |

Each factor is scored, traditionally 1 to 10 (some variants 1 to 3). The five scores are summed or averaged to produce a DREAD score, and findings are sorted by the score.

### Why DREAD has fallen out of favour

Microsoft itself moved away from DREAD over the 2010s. The reasons are the same as the failure modes above, plus two specific to DREAD:

- **The factors are not independent.** Exploitability and Discoverability move together (an exploit kit existing increases both). Damage and Affected users overlap. Summing or averaging correlated factors compounds the noise.
- **Discoverability is a moral hazard.** Scoring a finding as "low discoverability" because it requires source-code access encourages security-through-obscurity reasoning. Real attackers obtain source code (open-source projects, leaks, insider extraction). The Microsoft retrospective is explicit: *do not score discoverability as a risk-reducer*.

### What is salvageable

DREAD's prompt structure — five named factors — is still useful as a *checklist for thinking about a finding*, even if you do not sum the scores. When triaging a finding, asking yourself five questions ("damage? reproducibility? exploit cost? affected users? how likely to be found?") and writing the answers narratively is a fine practice. The error is to multiply or sum the answers and treat the result as a measurement.

Shostack's recommendation, which this course follows: **use DREAD's prompts but do not produce DREAD scores**. Use a qualitative L/M/H likelihood and impact for the register; record the DREAD-style narrative in the finding's body.

---

## 5. Qualitative bucketing — the practical alternative

The C6 risk register format, drawn from Shostack and the OWASP cheat sheet, is qualitative:

- **Likelihood: Low / Medium / High.** Each defined in writing at the start of the engagement, with concrete criteria.
- **Impact: Low / Medium / High.** Likewise defined, with examples relevant to the system under analysis.
- **Risk: a 3 × 3 cell** (Low/Low through High/High), with a documented mapping from cell to priority.

### Defining the buckets — sample wording

For likelihood, in a small open-source self-hosted application threat model:

- **Low.** No evidence of active exploitation in the wild against this class of system. Requires non-trivial attacker effort or specific positioning.
- **Medium.** Documented exploitation against similar systems in the past 12 months; off-the-shelf tooling exists.
- **High.** Observed in the wild against this exact system or close analogues; commodity exploitation; automated tooling routinely succeeds.

For impact, on the same system:

- **Low.** A single user's content is exposed or corrupted; recoverable by restore.
- **Medium.** Multiple users' content; service availability degraded for hours; trust erosion requires public disclosure.
- **High.** All users' content or credentials; service down for days; regulatory disclosure obligation; the project may not recover its user base.

These definitions are *not universal*. Each threat model writes its own, in its preamble. The exercise of writing them is itself part of the threat-modeling discipline: it forces the team to decide what they consider catastrophic for *this* system.

### The 3 × 3 priority mapping

| Likelihood ↓ / Impact → | Low | Medium | High |
|---|---|---|---|
| **High** | M | H | H |
| **Medium** | L | M | H |
| **Low** | L | L | M |

Three priority bands — Low, Medium, High — emerge. The mapping is asymmetric on purpose: a High-impact-Low-likelihood finding lands at Medium priority, not Low, because the tail-risk problem (failure mode 3 above) makes that combination dangerous to dismiss.

The team is free to override the mapping for specific findings ("this is technically Medium priority but it concerns the master signing key — escalate to High"). The mapping is a default; the override is a documented decision.

---

## 6. The risk register

The artifact that lives beyond the threat model is the **risk register**. It is the place identified risks live, get tracked, get reviewed, and get closed. A minimal register has the following columns:

| Field | What it contains |
|---|---|
| **ID** | A stable identifier (`R-0001`). Used in commit messages, PRs, post-mortems. |
| **Title** | One line, in the form *"\<asset\> \<verb\> by \<threat actor\> via \<vulnerability or path\>"*. |
| **Description** | Two or three sentences. The threat in writing, with enough detail that the reader does not need the source threat model open. |
| **STRIDE / category** | Which letter(s) of STRIDE this maps to, or another categorisation. |
| **Likelihood** | L / M / H, per the definitions in the model's preamble. |
| **Impact** | L / M / H, likewise. |
| **Priority** | Derived from the 3 × 3 cell, with override notes if any. |
| **Owner** | The named individual responsible for the disposition. Not a team — a person. |
| **Status** | Open / Mitigating / Mitigated / Accepted / Transferred / Avoided. |
| **Mitigation** | What is being done. A link to a PR, a configuration change, a contract clause. |
| **Residual risk** | What remains after the mitigation. "L/L; users on legacy clients unaffected" is a complete entry. |
| **Review cadence** | Quarterly / Annually / On change. With the next-review date. |
| **References** | Links to STRIDE finding, attack tree, ATT&CK technique, CVE, vendor advisory. |

### Disposition — the four answers

For each register entry, the eventual disposition is one of four — and only four. Lecture 1 named them; here they are with notes:

- **Mitigate.** Implement a change that reduces likelihood, impact, or both. The most common disposition. The register records *what changed*, with a link.
- **Transfer.** Shift the consequence to a third party. Insurance is one form. A contract that places liability on a vendor is another. Transfer does not remove the risk; it reassigns it.
- **Avoid.** Remove the feature or system that introduces the risk. The simplest and most-overlooked option. If the risk of a feature exceeds its business value, do not ship the feature.
- **Accept.** Acknowledge the risk and proceed without mitigating it. Always paired with a named, dated sign-off ("Accepted by \<owner\> on \<date\> with annual review"). Acceptance is not a default; it is an active choice.

"Defer" is *not* a disposition. A risk in the register without a disposition is an open risk. The register's discipline is that every row has a disposition or a scheduled re-review date.

### Review cadence

A register that is built once and never revisited becomes wrong. New code, new dependencies, new attackers, new public exploits all shift the picture. The C6-recommended cadences:

- **Per significant change** — new endpoint, new third-party integration, new auth flow. The PR introducing the change references the affected register entries.
- **Quarterly** — sweep the open rows, re-score, re-prioritise.
- **Post-incident** — every incident must produce at least one register update: either a new row (a risk we did not see), a re-scoring (a risk we underestimated), or a closure (a mitigation we proved works).

The post-incident discipline is the most important. It is the answer to Shostack's fourth question — *did we do a good job?* — and the only way the model improves over time.

---

## 7. When to upgrade from L/M/H to numbers

The qualitative L/M/H register is the right starting point. Some organisations eventually outgrow it. The signals that you are ready to upgrade:

- **Capital allocation arguments.** "Spend $250K on remediation A or $250K on remediation B?" is hard to answer with L/M/H. Quantitative methods (FAIR — Factor Analysis of Information Risk; Hubbard's calibrated probability methods) produce $-denominated answers that can be compared to remediation cost.
- **Insurance underwriting.** Cyber-insurance carriers expect quantified loss estimates. L/M/H does not translate.
- **Board-level reporting at large organisations.** The board wants a dollar figure of "loss exposure" against which to evaluate the security program's budget.

The standard quantitative references are:

- **Jack Freund and Jack Jones, *Measuring and Managing Information Risk: A FAIR Approach*** (Butterworth-Heinemann, 2014).
- **Douglas W. Hubbard and Richard Seiersen, *How to Measure Anything in Cybersecurity Risk*** (Wiley, 2016; 2nd edition 2023).

The Hubbard book is the strongest critique of ordinal risk matrices in the literature; read it after you have used the matrices for a year, so the critique resonates.

---

## 8. MITRE ATT&CK as a behaviour vocabulary

A practical note. The risk register is more useful when its entries cite the *technique IDs* of the adversary behaviours they describe. MITRE ATT&CK is the de-facto vocabulary for adversary techniques in modern security writing — every major vendor's incident reports cite it; CISA advisories cite it; the SOC tools cite it.

When you write a register entry that describes attacker behaviour, link the ATT&CK technique ID:

- Credential stuffing → **T1110.004** (Brute Force: Credential Stuffing).
- A web shell uploaded after an RCE → **T1505.003** (Server Software Component: Web Shell).
- DNS-based exfiltration → **T1071.004** (Application Layer Protocol: DNS).
- Phishing as initial access → **T1566** (Phishing).

The reason is operational: the SOC team can search detections by technique ID, the IR team can reference techniques in playbooks, and the threat model and the operational tooling end up speaking the same language.

Not every register entry has an ATT&CK technique. Misconfigurations, architectural weaknesses, supply-chain risks — these are vulnerabilities in *the system*, not behaviours *of an attacker*, and ATT&CK does not cover them well. Use the link where it fits; do not force it where it does not.

---

## 9. Worked example — one register entry, end to end

Drawing from the lecture-1 todo-list app:

```
ID: R-0007
Title: Account takeover by credential stuffing against the login endpoint
Description:
  The /login endpoint accepts username/password without rate limiting,
  lockout, or breach-password checking. An attacker armed with a public
  credential dump (e.g. HIBP) can submit candidate pairs at line rate
  and will compromise any user whose password is reused.
STRIDE: S (Spoofing — authentication bypass).
ATT&CK: T1110.004 (Brute Force: Credential Stuffing).
Likelihood: High.
  (Observed against every internet-exposed login form; commodity tooling
  routinely succeeds; no special positioning required.)
Impact: Medium.
  (Per-user; an attacker who succeeds reads and modifies that user's
  todos but does not access other users or the host. Aggregated impact
  if many users are compromised crosses into High.)
Priority: High. (Override from Medium per the 3x3, on aggregate impact.)
Owner: <named individual>.
Status: Mitigating.
Mitigation:
  1. Implement per-IP and per-username rate limiting at the reverse
     proxy (10 attempts / 5 min / IP; 5 attempts / 30 min / username).
  2. Block known-breached passwords on registration and on password
     change (k-anonymity API).
  3. Implement account lockout after 10 failures, with administrator
     unlock and user notification email.
  4. Add a "suspicious-login" alert when the IP geo or User-Agent
     deviates from the user's prior pattern.
Residual risk: Medium/Low.
  Targeted slow-roll attacks against a small set of users below the
  rate-limiting thresholds remain possible. Mitigated indirectly by
  the breached-password block.
Review cadence: Quarterly; immediately after any login-related code change.
References:
  - STRIDE finding 03 in /threat-model/02-threats.md
  - Attack tree leaf in /threat-model/03-attack-trees.md (under "auth as another user")
  - ATT&CK T1110.004
  - OWASP ASVS V2.2 (authentication-throttling controls)
```

That entry is roughly 200 words and tells a reviewer everything they need to know to (a) decide whether to fund the work, (b) verify when the work is done, and (c) re-score next quarter. The score is qualitative; the *argument* is concrete.

---

## 10. The questions to ask of any risk number

When someone hands you a risk score — yours, a vendor's, an auditor's — ask in order:

1. **What are the buckets?** Are likelihood and impact defined, with criteria?
2. **What is the multiplied number doing?** Is it being shown to stakeholders as a ratio-scale measurement? (If yes, push back.)
3. **What is the tail-risk scenario?** Is there a written worst-case scenario the formula could miss?
4. **Who is the named owner?** A score without an owner is a complaint, not a risk.
5. **When is the next review?** A score without a review cadence will go stale.
6. **What is the residual risk after the proposed mitigation?** A score without a residual is incomplete.

A risk register that survives those six questions is a risk register that drives real decisions. One that does not is a security-theatre artifact.

---

## Recap

- **`Risk = Likelihood × Impact`** is a useful heuristic for sorting threats and a misleading measurement when treated as a precise number. The failure modes — false precision, squishy inputs, tail risk, hard-to-estimate likelihood, non-additive risks — are documented; design your register to avoid each.
- **DREAD** is deprecated as a scoring scheme. Its five prompts (Damage, Reproducibility, Exploitability, Affected users, Discoverability) remain useful as a *checklist for thinking* about a finding; do not sum or average them. Do not credit "low discoverability" — that is security through obscurity.
- **Qualitative L/M/H** with written bucket definitions, mapped through a 3 × 3 priority matrix with documented overrides, is the C6-recommended default.
- The **risk register** is the artifact that drives prioritisation and tracking. Every row has a named owner, a disposition (mitigate / transfer / avoid / accept), a residual risk, and a review cadence.
- **MITRE ATT&CK** technique IDs make register entries operational; cite them where the entry describes adversary behaviour.
- Upgrade to quantitative methods (FAIR, Hubbard) when capital allocation, insurance, or board reporting demands it — not before.

The lectures end here. The exercises this week turn the framework into practice (STRIDE on a todo app, an attack tree for an SSH-accessible server, a risk register built from both). The mini-project turns the practice into a deliverable: a written threat model of a real open-source project, in the form a hiring manager will read and a senior engineer will defend.
