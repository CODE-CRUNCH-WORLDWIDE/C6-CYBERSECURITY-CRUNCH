# Mini-Project — A Full Threat Model of a Real System You Use

> Produce a written threat-model document, in the form Shostack recommends, of a real open-source project you actually use. The document is structured around the four questions — *what are we building, what can go wrong, what are we going to do about it, did we do a good job?* — and it is the third artifact in your portfolio after the Week 1 threat model of your own system and the Week 2 PCAP brief.

This mini-project is the synthesis of Week 3. The lectures gave you STRIDE, attack trees, the three lenses, the risk register, and the limits of the multiplied score. The exercises trained the muscle on a synthetic todo app and an SSH workflow. The challenge produced one finding on a real project. Now you produce the *whole* document for the same (or a different) real project — the artifact a hiring manager will read alongside your Week 1 and Week 2 outputs.

**Estimated time:** 7 hours, spread across Thursday-Saturday.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  This is a paper exercise. Read the project's source. Read its      │
│  documentation. Reason about attacks. Write the document.           │
│                                                                     │
│  Do not interact with any live deployment you do not operate. Do    │
│  not scan, probe, or send crafted payloads against a service you    │
│  do not own. If you want to exercise the project, deploy your own   │
│  instance locally and test against that instance only.              │
│                                                                     │
│  If during the work you believe you have found an exploitable       │
│  vulnerability in the project as released, report it privately to   │
│  the maintainers per their SECURITY.md before publishing.           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## What you will produce

A public GitHub repo named `c6-week-03-threat-model-<yourhandle>` (or a subfolder of your portfolio repo) containing:

- `README.md` — one-paragraph intro and links into the document.
- `threat-model.md` — the full document, ~2500-4000 words, structured per the four questions below.
- `dfd.png` (or `.svg`) — at least one DFD; ideally a Level-0 context diagram and a Level-1 component diagram.
- `risk-register.md` — the tracked-risk artifact, separately, so it can be referenced and updated independently of the threat-model body.
- `attack-trees/` — one or more attack-tree documents for the highest-priority adversary goals.
- `LICENSE` — GPL-3.0 (consistent with C6) or a permissive license of your choice for the document itself.

The threat-model document is the deliverable. The DFDs, attack trees, and register are *evidence* behind it.

---

## Choosing your project

Choose a project that meets **all** of these criteria:

1. **You actually use it.** A project you do not use will produce a thin document. Pick a wiki, a notes app, a feed reader, a Git server, a small SaaS-style tool, or a CLI utility you have a working relationship with.
2. **The source is open and readable in your strongest languages.** You will need to read non-trivial parts of it. Python, JavaScript, TypeScript, Go, Rust — pick what you can read fluently.
3. **It is small enough to scope.** A 5-50 kLoC project is the sweet spot. Kubernetes is too large for one week. A 200-line Python script is too small to threat-model meaningfully.
4. **You can deploy it locally.** Test scenarios against your own instance, not against anyone else's. If the project is "library only," you can run it inside a small wrapper of your own.
5. **You have not already produced a threat model for it.** If you did the challenge on the same project, you can build the mini-project as an expansion — but acknowledge that lineage in the document.

Some candidate categories:

- **Self-hosted notes / wiki:** Bookstack, TriliumNext, Memos, Shaarli, MediaWiki (small wiki).
- **Self-hosted feed reader:** Miniflux, FreshRSS.
- **Self-hosted Git server:** Gitea, Forgejo.
- **Small SaaS-style tools:** Plausible Analytics, Umami, Listmonk, Mailcow (smaller pieces).
- **CLI utility you depend on:** yt-dlp, ripgrep, fd, bat, pre-commit. (Different DFD shape — no server; the trust boundary is between the user's input/files and the binary.)
- **A protocol implementation:** a small TLS library, a WebSocket library, a JSON parser. (Different again — model the attack surface in terms of inputs to the parser.)

If you cannot decide in 30 minutes, pick one of these: Miniflux (Go; ~30 kLoC; clean architecture; widely deployed; small enough to read). Memos (Go + TypeScript; ~20 kLoC; small notes-app; full-stack; useful DFD). Both have published `SECURITY.md` files; both are actively maintained.

---

## The document — structure (Shostack's four questions)

### 1. What are we building?

The first major section. Three to five pages of writing, anchored on the DFD(s). Includes:

#### 1.1 Project introduction

- One paragraph: what the project is, who uses it, what business / personal need it serves.
- The version (tag, commit hash) you analysed. **Pin precisely.** A threat model of "miniflux latest" is not a real artifact; a threat model of "miniflux v2.1.3 at commit `abc1234`" is.
- The deployment model you are modelling, in writing. (E.g. "Miniflux single-container Docker behind a Caddy reverse proxy with TLS; PostgreSQL on a separate container on the same host network; no external object storage." If the project supports multiple deployments, pick one and say so.)

#### 1.2 Architecture

- A Level-0 (context) DFD: the system as a single process with its external entities — the user, third parties (RSS feed servers, OAuth providers if any, mail relays if any).
- A Level-1 DFD: the system opened into its top-level components (web server, worker, DB, scheduler).
- A short narrative walking the reader through both diagrams. Every component named on the diagram is named in the narrative; every flow is named.

#### 1.3 Trust boundaries

- An explicit list of trust boundaries on the Level-1 DFD, each with a one-sentence description of *what trust assumption changes* at the boundary.
- An explicit list of the *assumptions* made about each side. ("We assume the host operator is trusted to administer the box; we do not assume the user's browser is trusted to refrain from XSS payloads.")

#### 1.4 Assets

- A list of the assets the system protects. The C/I/A categories — confidentiality, integrity, availability — for each.
- Be specific: not "user data" but "the rendered HTML of feed items each user has read," "the user's account credentials," "the user's API tokens to third-party RSS providers."
- For each asset, name *how exposure of that asset would harm whom*. A threat model that conflates "the user's data" and "the project's reputation" misses real prioritisation.

#### 1.5 Threat actors in scope

- Two to four named actor archetypes, each with capabilities, motivations, and constraints. (See Lecture 2.) Anchor each to observed reality where possible — cite a vendor advisory, a CISA report, a research paper.
- An *explicit list of actors and threats out of scope*. ("Nation-state with physical access to the host is out of scope. Side-channel attacks on the host's CPU are out of scope. Supply-chain attacks on Go itself are out of scope, but supply-chain attacks on direct dependencies are in scope.")

### 2. What can go wrong?

The second major section. Five to ten pages. This is the bulk of the document.

#### 2.1 STRIDE pass

A full STRIDE pass against the DFD. Use the per-element table format. **Minimum 30 candidate threats**, anchored to elements or flows on the DFD. Every threat must:

- Anchor to a specific DFD element or trust boundary.
- State the STRIDE letter(s) it falls under.
- Name the *vulnerability* (the specific weakness) where one is known; otherwise state "(potential — no specific vulnerability identified)" and explain the residual concern.
- Provide one sentence of justification — why this threat is worth recording rather than dismissing.

A table of 30+ threats is the right size for a mid-sized project. A larger project may produce 60+. Do not pad; do not under-record.

#### 2.2 Attack trees for the top three goals

Identify the three highest-priority adversary goals against the system. For each:

- The goal stated as an attacker would state it. ("Read every user's feed-reading history." "Cause the service to be unavailable for one or more days." "Ship malicious code into the next release.")
- An attack tree, three levels deep, with cost annotations and AND/OR decomposition.
- The cheapest path identified, and the second-cheapest.
- A short narrative paragraph for each tree, naming what surprised you in building it and what the cheapest path implies for prioritisation.

Save each attack tree in `attack-trees/`, one Markdown file per goal.

#### 2.3 Threat catalogue (optional but recommended)

If your project has well-known threat classes — XSS for a web app, deserialization for a Python service that takes user-supplied YAML, parser-confusion for a network protocol implementation — name them as a small numbered list, each with a one-sentence why-this-applies-here. Link to OWASP, CWE, or research papers as primary sources.

### 3. What are we going to do about it?

The third major section. Three to six pages. This is where the analysis becomes a *plan*.

#### 3.1 The risk register

Present the register as a Markdown table, with the columns from Lecture 3:

| ID | Title | STRIDE | ATT&CK | Likelihood | Impact | Priority | Owner | Status | Mitigation | Residual | Review |

**Minimum 15 register entries**, drawn from the STRIDE pass and the attack trees. Each entry must:

- Have all columns filled. No `TODO` cells.
- Use the **qualitative L/M/H** scoring, with the bucket definitions documented in section 0.5 (scoring scale).
- Have a *named owner*. For an OSS-project threat model, "the maintainer team" is acceptable if the project has no obvious single owner; for a self-hosted deployment-specific finding, name yourself or the role.
- Have a *real disposition* — Mitigate / Transfer / Avoid / Accept. At least one Mitigate, at least one Accept (or a written argument that no Accept is appropriate).

The register lives in `risk-register.md` as well as in the document body. The body version is a snapshot; the standalone file is the working copy you will update going forward.

#### 3.2 Hardening recommendations

A list of concrete recommendations grouped by who must act on them:

- **For the project maintainers** — code changes, configuration defaults, documentation improvements. If any of these are not yet filed as issues or PRs, *consider doing so*, citing this threat model. (Do this only after the coordinated-disclosure check below.)
- **For the deployer** — configuration changes the operator should make when deploying the project. Sample `nftables` / reverse-proxy / TLS / monitoring configurations belong here.
- **For the user** — habits or settings the end user should adopt. Use a password manager, enable 2FA if the project supports it, etc.

Each recommendation: one to three sentences; one to three numbered concrete actions; a residual-risk note.

#### 3.3 Acceptances and out-of-scope

A short subsection listing what you are *accepting* (and why) and what is *out of scope* (and why). "We accept that a maintainer with merge rights can ship arbitrary code" is a legitimate acceptance for a small OSS project; "we accept any vulnerability the maintainer chooses not to fix" is not.

### 4. Did we do a good job?

The fourth and shortest section. One to two pages. It is the section most documents skip; the discipline of writing it separates real threat-modelling from going-through-the-motions threat-modelling.

#### 4.1 Self-assessment

In writing, against each of the four questions: how confident are you in your answer? What is the largest assumption you made that, if wrong, would invalidate the document? What part of the system did you find hardest to model, and what would you need to feel confident about it?

#### 4.2 Validation plan

Name at least three things that, in the next 6-12 months, would tell you whether the document is *right*:

- A monitoring signal that would catch one of the predicted threats if it occurred.
- An external review — a Trail-of-Bits-style audit, a maintainer review, a peer review.
- A scheduled re-walk after a major version change.

#### 4.3 Coordinated disclosure note

State, in writing, whether you encountered anything during the analysis that you believe to be a specific exploitable vulnerability in a current released version. If you did:

- *Do not publish until you have followed the project's `SECURITY.md` and given the maintainers a reasonable window to patch.* 90 days is the standard floor.
- The mini-project document can describe the *threat class* and the *defensive recommendation* without disclosing the exploitation path.
- After patch and CVE assignment, you may update the document with the full detail and the CVE link.

If you did not, state that. The reader needs to know whether the document is gated on a disclosure timeline.

---

## Suggested order of operations

### Phase 1 — Choose, scope, deploy (1 h)

1. Choose the project against the criteria above. Write down your reasoning in `scope-decision.md`.
2. Pin the version. Clone the repo at that exact commit.
3. Deploy locally if relevant. (Docker compose is usually fastest. Document the deployment in section 1.1.)
4. Read the `SECURITY.md`, the `README.md`, and the architecture documentation. Note the maintainers' own framing of the threat model — they will have addressed some threats already.

### Phase 2 — Draw the DFDs (1.5 h)

1. Sketch the Level-0 (context) diagram first.
2. Open it into a Level-1 diagram.
3. Walk every component named in the Level-1 diagram against the actual source. Verify each is real. Adjust the diagram.
4. Draw the trust boundaries. Each boundary gets a justification in the document.

### Phase 3 — STRIDE pass (1.5 h)

1. Walk STRIDE per element on the Level-1 DFD. Aim for 30+ threats.
2. For each threat, fill the table row. Resist the temptation to drill down too early — get the breadth first.

### Phase 4 — Attack trees (1 h)

1. Pick the three highest-priority adversary goals from the STRIDE pass.
2. Build a tree for each, three levels deep, with cost annotations.
3. Save each in `attack-trees/`.

### Phase 5 — Risk register (1 h)

1. Define the scoring scale in section 0.5.
2. Walk the STRIDE pass and the attack trees; populate the register with 15+ entries.
3. Assign a real disposition to each. Identify compounds.

### Phase 6 — Hardening recommendations (30 min)

1. Group by audience (maintainer / deployer / user).
2. Each recommendation gets a concrete action and a residual-risk note.
3. Decide which (if any) should be filed as upstream issues or PRs, applying the coordinated-disclosure check.

### Phase 7 — "Did we do a good job?" + polish (30 min)

1. Write the self-assessment honestly. Name the largest assumption.
2. Write the validation plan with at least three items.
3. Re-read the whole document cold. Tighten the prose. Verify every claim has either a citation or a defensible argument.
4. Push.

---

## Acceptance criteria

- [ ] Public GitHub repo or portfolio subfolder, named per the convention, with the required files.
- [ ] The project chosen meets the five criteria (used, readable, scoped, deployable, fresh).
- [ ] Version pinned precisely (tag and commit).
- [ ] Deployment model documented.
- [ ] At least two DFDs (Level-0 context and Level-1 component).
- [ ] Trust boundaries explicitly listed, each justified.
- [ ] Asset list is specific (not "user data").
- [ ] At least two named threat actor archetypes in scope; explicit out-of-scope list.
- [ ] STRIDE pass with at least 30 threats, each anchored to a DFD element.
- [ ] At least three attack trees, each three levels deep with cost annotations.
- [ ] Risk register with at least 15 entries, all columns filled, qualitative L/M/H scoring per documented buckets.
- [ ] Hardening recommendations grouped by audience.
- [ ] "Did we do a good job?" section with self-assessment and a 3+-item validation plan.
- [ ] Coordinated-disclosure check applied and result stated.
- [ ] All primary sources cited (project source, ATT&CK techniques, CVEs, OWASP guidance).
- [ ] Word count 2500-4000 for `threat-model.md`.
- [ ] No emojis.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| Project choice and scope discipline | 10% | A real, used, well-scoped project; version pinned; scope statement crisp. |
| DFD quality | 15% | Two diagrams (context + Level-1); trust boundaries on the L1; every element traceable to source. |
| STRIDE breadth and anchoring | 20% | 30+ threats, each anchored to a DFD element; every STRIDE letter represented; no "scary list" entries. |
| Attack-tree depth | 15% | Three trees, three levels deep, cost-annotated; cheapest path called out. |
| Risk register quality | 20% | 15+ entries; real dispositions; specific mitigations; residual risk on each row; one compound identified. |
| "Did we do a good job?" honesty | 10% | The self-assessment names a real assumption; the validation plan is concrete. |
| Writing quality and primary sources | 10% | The voice of an analyst, not a marketer. Every claim cited or defended. |

---

## Why this matters

A complete threat model — DFDs, STRIDE, attack trees, register, hardening recommendations, self-assessment — is the most-asked-for artifact in the junior security engineer interview. Producing one cleanly, in a week, on a project you actually use, is what separates a candidate who has read Shostack from a candidate who can *apply* him. Together with the Week 1 model and the Week 2 PCAP brief, this is the spine of your C6 portfolio at the end of Phase 1; the rest of the program builds on the discipline this week instils.

---

## Submission

Push to GitHub. Link the repo from your C6 portfolio README. Make sure the repo is public, the document reads cleanly cold, and any sensitive-disclosure content is gated behind the coordinated-disclosure check.

Then return to the Week 3 [README](../README.md) and tick this off your checklist. Week 4 is OWASP Top 10 — the threats this week's models hand-wave around become the vulnerabilities you patch in code next week.
