# Mini-Project — A Threat Model of a System You Actually Use

> Produce a two-page threat model of a real system that you operate or rely on. By the end of the week it lives in a public GitHub repository and is the first deliverable in your `crunch-sec-portfolio-<yourhandle>`.

This is the practical synthesis of Week 1. The lectures gave you the framework; the exercises gave you the muscle; the mini-project produces an artifact that a hiring manager can read.

**Estimated time:** 7 hours, spread across Thursday-Saturday.

---

## What you will produce

A single Markdown document, `threat-model.md`, in a public GitHub repo named `c6-week-01-threat-model-<yourhandle>`. The document is approximately two pages when rendered (roughly 1500-2500 words) and answers the four Shostack questions in disciplined order:

1. **What are we building?** (Description of the system, in plain language, with a diagram.)
2. **What can go wrong?** (STRIDE applied per component or per data flow; the highest-likelihood attack tree drawn.)
3. **What are we going to do about it?** (One named mitigation per significant threat. Preventive, detective, or corrective.)
4. **Did we do a good job?** (Self-review: what is the weakest part of the model? What did you almost miss?)

---

## Picking the system

The system you choose must be:

- **Real.** Something you actually operate or rely on, not a fictional scenario.
- **Bounded.** Small enough that two pages can do it justice. A whole company's network is too big. A single self-hosted service is right.
- **Yours, or yours to model.** Either you operate it (best), or you depend on it heavily enough that modeling it improves your decisions.

Good candidates:

- A side project you have deployed (a web app, a Discord bot, a Python script that runs from cron and posts to an API).
- A home server: a NAS, Home Assistant, Pi-hole, a self-hosted Nextcloud or Vaultwarden.
- The deployment of a personal blog (static site + DNS + GitHub Pages + Cloudflare).
- A Raspberry Pi running a single service on your home network.
- A repository under your control on GitHub with CI/CD that has secrets.

Avoid:

- "My company's infrastructure" — too large, and you may not have authorization to publish a threat model of it. *Confidentiality of your model is part of its threat model.*
- A system you do not actually use — the analysis will be hollow.
- A system you operate jointly with someone who has not consented to having it written about publicly.

---

## Required sections

### Section 1 — System description (4 paragraphs maximum)

- **What it is.** One paragraph in plain language. A non-technical reader should understand what it does.
- **Architecture diagram.** One image — hand-drawn, drawn in Excalidraw, drawn in Mermaid, drawn however. The diagram must show: components, data flows (with direction), and **at least one trust boundary** explicitly marked.
- **Assets.** A bulleted list of what is worth protecting: data, capability, reputation, availability. Be specific: "the SQLite database at `/var/lib/myapp/db.sqlite3` containing 4,200 user email/hash pairs," not "user data."
- **Actors.** Who interacts with the system, and from where: you, your users, the internet at large, automated bots, your cloud provider, your CI runner, your dependencies.

### Section 2 — STRIDE pass (the bulk of the document)

A table, applying STRIDE to **each major component or data flow**. Aim for 4-8 components, and 1-2 threats per STRIDE letter per component (not all 6 — only the letters that meaningfully apply).

| Component | Threat | STRIDE letter | Likelihood | Impact |
|-----------|--------|---------------|------------|--------|
| (e.g. SSH ingress on the VPS) | Brute-force credential guessing from public internet | S | High | Medium |
| ... | ... | ... | ... | ... |

Likelihood and impact may be qualitative (Low/Medium/High) — that is fine. The point is not the precision of the rating but the deliberate weighing of each threat.

Add a small attack tree (4-8 nodes) for the *one* threat scenario you judge most significant. Use ASCII art, Mermaid, or a hand-drawn image. Show the path of least resistance.

### Section 3 — Mitigations

For each significant threat from Section 2, a row:

| Threat | Mitigation | Type (Preventive/Detective/Corrective) | Implemented today? |
|--------|------------|----------------------------------------|--------------------|
| Brute-force SSH | `fail2ban`, key-only auth, port not exposed publicly | Preventive + Detective | Yes (key-only); will add fail2ban this week |
| ... | ... | ... | ... |

The last column is the honest one. The whole point of writing this is to find the *gap* between the controls you have and the controls you should have.

Mitigations must be **specific**. Not "harden SSH" — "set `PasswordAuthentication no` and `PermitRootLogin no` in `/etc/ssh/sshd_config`, restart sshd, verify with `ssh -v` that public-key is the only accepted method." A reader should be able to act on it.

### Section 4 — Did we do a good job?

Three short paragraphs:

- **The weakest part of this model.** Where is the analysis thinnest? Often it is the supply chain (your dependencies, your CI provider, your DNS host). Name the weakness.
- **What I almost missed.** A junior engineer always misses something. Document it. Future-you reading this is the audience.
- **Review schedule.** When will this document next be re-read and updated? A threat model written and never revisited is decoration.

### Section 5 — Resources used

A short bibliography. Required: at least one primary source (NIST, OWASP, MITRE ATT&CK, or a vendor advisory) you consulted to support a specific claim. Cite it precisely.

---

## Acceptance criteria

- [ ] Public GitHub repo `c6-week-01-threat-model-<yourhandle>`.
- [ ] `threat-model.md` in the repo root.
- [ ] All five required sections present.
- [ ] At least one diagram with at least one trust boundary marked.
- [ ] The STRIDE table covers at least four components.
- [ ] At least one attack-tree fragment, four-to-eight nodes.
- [ ] Mitigations are specific enough to be acted on.
- [ ] Section 4 is honest about gaps — a section that claims "no weaknesses" is *not accepted*. Every real model has weaknesses; the discipline is finding them.
- [ ] At least one primary source cited.
- [ ] Document is roughly 1500-2500 words. (We measure with `wc -w` on the rendered text; minor variance is fine.)
- [ ] No personally-identifying detail of *other* people: IPs, names, account handles of users who did not consent. Your own infrastructure can be described.
- [ ] No emojis.

---

## Suggested order of operations

### Phase 1 — Picking and sketching (1 hour)

1. Pick the system. Write the one-sentence description.
2. Sketch the architecture on paper. Identify the trust boundaries.
3. List assets and actors.
4. Push the empty `threat-model.md` and the sketch as a first commit so you have a baseline.

### Phase 2 — STRIDE pass (2-3 hours)

Slow and deliberate. For each component, walk through all six letters. Many cells will be `n/a` with a one-line justification; that is fine. The output should feel exhaustive within the small bounded system you chose.

When you have the table, pick the one or two threats that *scare you most* (highest likelihood × highest impact). Draw the attack tree for one of them.

### Phase 3 — Mitigations (1.5 hours)

For each significant threat, name a control. Be honest about which are implemented today.

### Phase 4 — Self-review (1 hour)

Write Section 4. Re-read sections 1-3 with fresh eyes. What is missing? What is hand-wavy? Name those things in Section 4 rather than papering over them.

### Phase 5 — Polish and push (30 min)

- README in the repo root with one-paragraph intro and a link to `threat-model.md`.
- Sources cited.
- `wc -w threat-model.md` is within 1500-2500.
- Push. Open the repo in a fresh browser tab and read it as if you were a hiring manager — *does this convince a reader that the writer can think structurally about security?*

---

## Stretch goals

- Add a *separate*, second STRIDE pass written from the perspective of a non-malicious failure (e.g., a hardware failure, an accidental commit of a secret, a configuration drift). This forces you to widen your threat model beyond adversarial actors.
- Map your threats to MITRE ATT&CK technique IDs (e.g., T1110 for brute force). The mapping is what real SOC documentation looks like.
- For each mitigation, link to the upstream documentation or the specific config line that implements it.
- Open a *second* file, `threat-model-revisions.md`, and commit a re-review of the document one month after the original.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| Question 1 — System described clearly with a diagram and a trust boundary | 15% | Diagram is unambiguous; a non-technical reader could understand the system. |
| Question 2 — STRIDE pass covers at least 4 components, with at least one attack tree | 25% | Each STRIDE row is a real threat, not a placeholder. Attack tree shows the realistic path. |
| Question 3 — Mitigations are specific and implementable | 25% | Each mitigation names a config line, a tool, or a procedure — not "harden the system." |
| Question 4 — Self-review is honest | 15% | The author identifies real gaps. A reader would trust this writer's other work. |
| Citations and primary sources | 10% | At least one NIST/OWASP/MITRE/vendor advisory cited precisely. |
| Writing quality | 10% | Specific, not dramatic. Cybersecurity industry voice. |

---

## Why this matters

A threat model is the single document a junior security engineer is most likely to be asked to produce in their first month. It is also the deliverable most often asked of bug-bounty hunters writing a proper report. Doing it well, on a small bounded system, builds the muscle for doing it well on a larger one. The portfolio repo this produces is *the artifact* you will point a hiring manager at.

---

## Submission

Push to GitHub. Link the repo from your C6 portfolio README. Make sure the repo is public. Open it in a fresh browser tab and read it cold — if anything reads as hand-wavy, fix it before considering the mini-project done.

Then return to the Week 1 [README](../README.md) and tick this off your checklist.
