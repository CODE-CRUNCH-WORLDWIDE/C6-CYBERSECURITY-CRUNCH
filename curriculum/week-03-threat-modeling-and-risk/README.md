# Week 3 — Threat Modeling and Risk

> *Threat modeling is the discipline of asking "what can go wrong?" before the code is written, the contract is signed, or the network is plugged in. Week 3 teaches you to do it on paper, to do it methodically, and to do it without either of the two failure modes — the fevered list of every possible attack, and the bland reassurance that "we have a firewall."*

Welcome to Week 3 of **C6 · Cybersecurity Crunch**. Week 1 gave you the security mindset and the Linux security model. Week 2 gave you the network. Week 3 gives you the *method* — STRIDE, attack trees, asset-driven and attacker-driven analysis, and the formula `Risk = Likelihood × Impact` along with its very real limits. By Sunday you will be able to produce a written threat model for a real system you use, defensible in front of a senior engineer who has not seen it before.

This week is mostly paper. There is a small amount of tooling at the end (the OWASP Threat Dragon and Microsoft Threat Modeling Tool are touched briefly). The substance is the *thinking*. A threat model is a written argument: here is the system, here is what an attacker can do to it, here is what we will and will not defend against, here is why.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Practice the techniques in this module only on:                    │
│  - machines and networks you own                                    │
│  - legal training platforms (TryHackMe, HackTheBox, picoCTF,        │
│    VulnHub, OverTheWire, pwn.college)                               │
│  - systems with explicit written permission from the owner          │
│                                                                     │
│  Unauthorized testing is a crime. C6 does not teach crime.          │
└─────────────────────────────────────────────────────────────────────┘
```

Threat modeling itself is a paper exercise and is not "offensive." The banner appears because the mini-project asks you to threat-model a real open-source project — and the boundary between "I read the source and reasoned about attacks" (lawful) and "I tested the live service" (a crime if you do not own it) is a boundary you will encounter this week for the first time. Read the source. Reason about attacks. Do not run them.

---

## Learning objectives

By the end of this week, you will be able to:

- **Define** a threat, a vulnerability, a risk, and an asset, and use the four words correctly in writing without sliding between them.
- **Apply** STRIDE — Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege — to each component and data flow of a system you draw.
- **Draw** a data-flow diagram (DFD) at the level that a threat model requires (entities, processes, data stores, data flows, trust boundaries) and explain what each element means.
- **Construct** an attack tree for a stated goal, decomposing it into AND / OR sub-goals down to leaf-level actions, with cost or feasibility annotations.
- **Contrast** asset-driven, attacker-driven, and software-driven threat modeling — Shostack's three approaches in "Threat Modeling: Designing for Security" — and pick the right one for a given engagement.
- **Compute** a DREAD score for a finding and **state, in writing, why DREAD's numerical aggregation is brittle** and where Shostack and modern practice recommend qualitative bucketing instead.
- **Outline** the PASTA process (Process for Attack Simulation and Threat Analysis) at the level of its seven stages and state when it is appropriate (regulated, business-critical systems) versus overkill.
- **Build** a risk register: a tracked list of identified risks, with owner, status, mitigation, residual risk, and a review cadence.
- **Recognise** the documented failure modes of `Risk = Likelihood × Impact` as a multiplied number — the false precision, the unknown unknowns, the tail-risk underweighting (Taleb, *The Black Swan*) — and use the formula as a *sorting heuristic*, not as an oracle.
- **Map** a finding from your threat model to a MITRE ATT&CK technique ID when the finding describes an adversary behaviour with a known classification.
- **Produce** a written threat-model document of the standard four sections: *what you are building*, *what can go wrong*, *what you will do about it*, *did you do a good job?* — Shostack's four questions.

---

## Prerequisites

- **Weeks 1 and 2 completed.** You should know what `setuid`, `iptables`, and `tcpdump` are without looking them up.
- A real open-source project in mind for the mini-project. Pick one you actually use (a CLI tool, a small web app, a self-hosted service). Suggestions in the mini-project README. **Read-only**: you will not interact with anything you do not run yourself.
- A text editor and a drawing tool. Pen-and-paper is acceptable and often *better* than digital tooling at this stage. If you want a diagram tool: [draw.io / diagrams.net](https://www.drawio.com/) is free, runs offline, and produces clean DFDs. [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) is the open-source threat-modeling tool of record; install it if you want, but pen-and-paper first.
- Comfort with reading code in two languages of your choice. The mini-project requires you to skim a real codebase.

---

## Topics covered

- The four questions of threat modeling (Shostack): *What are we building? What can go wrong? What are we going to do about it? Did we do a good job?*
- Definitions, precisely: **asset**, **threat**, **vulnerability**, **risk**, **exposure**, **threat actor**, **attack surface**, **trust boundary**.
- The data-flow diagram (DFD) as the workhorse representation — entities, processes, data stores, data flows, trust boundaries.
- **STRIDE** — Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege — applied per element and per flow.
- Attack trees (Schneier, 1999) — root goal, AND/OR decomposition, leaf actions, cost/feasibility annotations, and how to use them as a thinking tool.
- Asset-driven vs. attacker-driven vs. software-driven modeling — when each is the right lens.
- **DREAD** — Damage, Reproducibility, Exploitability, Affected users, Discoverability — its history, why Microsoft itself moved away from it, what is salvageable.
- **PASTA** — the seven-stage business-risk-centric process for regulated systems.
- The risk register as an artifact: columns, owners, residual risk, review cadence.
- `Risk = Likelihood × Impact` — the formula, where it sorts well, and where the multiplication of two squishy numbers becomes false precision.
- Tail-risk underweighting — why the rare-and-catastrophic combination breaks the formula. Threat modeling vs. risk *quantification* (FAIR, Monte Carlo) as the next step up.
- MITRE ATT&CK as a shared vocabulary for attacker behaviours — when to link a finding to a technique ID, and when not to.
- Threat-model documents — Shostack's recommended structure, how long they should be, who reads them, when they are revised.

---

## Weekly schedule

The schedule below adds up to approximately **36 hours**. Treat it as a target.

| Day       | Focus                                                  | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Self-Study | Daily Total |
|-----------|--------------------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|-----------:|------------:|
| Monday    | The four questions; STRIDE; DFDs                       |    2h    |    1h     |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |     5h      |
| Tuesday   | Attack trees; asset vs. attacker vs. software-driven   |    2h    |    2h     |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |     6h      |
| Wednesday | Risk: likelihood, impact, the limits of multiplication |    2h    |    2h     |     0h     |    0.5h   |   1h     |     0h       |    0h      |     5.5h    |
| Thursday  | DREAD, PASTA, the risk register                        |    0h    |    2h     |     1h     |    0.5h   |   1h     |     2h       |    0.5h    |     7h      |
| Friday    | Mini-project: scope the system, draw the DFD           |    0h    |    1h     |     1h     |    0.5h   |   1h     |     2h       |    0.5h    |     6h      |
| Saturday  | Mini-project deep work — STRIDE pass, risks, mitigations |    0h    |    0h     |     2h     |    0h     |   1h     |     3h       |    0h      |     6h      |
| Sunday    | Quiz, review, polish, push                             |    0h    |    0h     |     0h     |    0.5h   |   0h     |     0h       |    0h      |     0.5h    |
| **Total** |                                                        | **6h**   | **8h**    | **4h**     | **3h**    | **6h**   |   **7h**     |   **2h**   |  **36h**    |

---

## How to navigate this week

| File | What's inside |
|------|---------------|
| [README.md](./README.md) | This overview (you are here) |
| [resources.md](./resources.md) | Primary sources: Shostack, OWASP, MITRE ATT&CK, Schneier on attack trees |
| [lecture-notes/01-stride-and-attack-trees.md](./lecture-notes/01-stride-and-attack-trees.md) | STRIDE per element and per flow; attack trees with worked examples |
| [lecture-notes/02-asset-vs-attacker-driven-models.md](./lecture-notes/02-asset-vs-attacker-driven-models.md) | The three lenses, when each applies, PASTA as a process |
| [lecture-notes/03-risk-likelihood-times-impact-and-its-limits.md](./lecture-notes/03-risk-likelihood-times-impact-and-its-limits.md) | The formula, DREAD, qualitative bucketing, tail-risk, the risk register |
| [exercises/README.md](./exercises/README.md) | Index of short hands-on drills |
| [exercises/exercise-01-stride-on-todo-app.md](./exercises/exercise-01-stride-on-todo-app.md) | STRIDE applied to a minimal todo-list web app |
| [exercises/exercise-02-attack-tree-for-ssh.md](./exercises/exercise-02-attack-tree-for-ssh.md) | Attack tree: "compromise an SSH-accessible Linux server" |
| [exercises/exercise-03-risk-register.md](./exercises/exercise-03-risk-register.md) | Build a risk register from the previous two exercises |
| [challenges/README.md](./challenges/README.md) | Index of weekly challenges |
| [challenges/challenge-01-threat-model-real-oss-project.md](./challenges/challenge-01-threat-model-real-oss-project.md) | A scoped threat-model of a real OSS project — the on-ramp to the mini-project |
| [quiz.md](./quiz.md) | 10 multiple-choice questions |
| [homework.md](./homework.md) | Six practice problems |
| [mini-project/README.md](./mini-project/README.md) | The full threat-model document — Week 3's portfolio artifact |

---

## Stretch goals

If you finish early, push further:

- Read all of Adam Shostack, *Threat Modeling: Designing for Security* (Wiley, 2014). It is the canonical text; this week samples chapters 1, 3, 5, and 8 only.
- Read the original Microsoft STRIDE paper (Loren Kohnfelder and Praerit Garg, *The threats to our products*, Microsoft Interface Security memorandum, 1999) — the historical primary source.
- Read Bruce Schneier, *Attack Trees* (Dr. Dobb's Journal, December 1999) — the article that introduced attack trees into mainstream security writing.
- Read the OWASP **Threat Modeling Manifesto** and contrast it with Shostack's four questions. They are aligned but not identical.
- Pick one CVE that affected a product you use this year. Reverse-engineer the threat model the vendor *should have had* such that the CVE would have surfaced as an identified risk. (This exercise is humbling.)
- Skim NIST SP 800-30 Rev. 1 (Guide for Conducting Risk Assessments) — the public-sector formalism, useful as a contrast to Shostack's pragmatic approach.

---

## Up next

Continue to [Week 4 — OWASP Top 10 (2025 edition) for Python](../week-04/) once your threat-model document is pushed and your portfolio README links to Week 1, Week 2, and Week 3 artifacts. Week 4 is the first time the threat model meets a real codebase under attack.

---

*Found an error? Open an issue or send a PR. The next learner will thank you.*
