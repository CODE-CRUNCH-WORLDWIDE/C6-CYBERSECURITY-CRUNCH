# Challenge 1 — Threat-model a Real Open-source Project

**Estimated time:** 3 hours. Produces a focused one-finding write-up that serves as the on-ramp to the mini-project.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  This is a paper exercise on the project's source code and          │
│  documentation. Do not interact with any live service you do not    │
│  operate. Do not send crafted requests, scan ports, or test         │
│  payloads against a deployed instance unless you own the deployment │
│  or have explicit written authorization.                            │
│                                                                     │
│  If you want to exercise the project, deploy your own instance      │
│  locally and test against that instance only.                       │
└─────────────────────────────────────────────────────────────────────┘
```

## Goal

Pick one real open-source project. Produce a 700-1000-word write-up of *one* significant threat against it, including a STRIDE-anchored finding, an attack-tree sketch, a risk-register entry, and a mitigation recommendation. The output is one Markdown file plus one diagram.

This is *not* a vulnerability report. You are not claiming you have found a 0-day. You are producing a *threat-modeling artifact* — an argument about a category of risk and how the project's current design addresses or fails to address it. If during the exercise you genuinely believe you have found an unreported vulnerability, see the "Coordinated disclosure" section below before publishing anything.

---

## Step 1 — Pick a project (15 minutes)

Pick something **you actually use** and whose source you can **read in an afternoon**. Some categories with good candidates:

- **A self-hosted notes / wiki / bookmark app.** Examples: [Bookstack](https://github.com/BookStackApp/BookStack), [Trilium](https://github.com/zadam/trilium) (now [TriliumNext](https://github.com/TriliumNext/Notes)), [Memos](https://github.com/usememos/memos), [Shaarli](https://github.com/shaarli/Shaarli). All small enough to scope; all internet-exposable.
- **A self-hosted feed reader.** [Miniflux](https://github.com/miniflux/v2), [FreshRSS](https://github.com/FreshRSS/FreshRSS), [Tiny Tiny RSS](https://tt-rss.org/).
- **A self-hosted CI / dev tool.** [Gitea](https://github.com/go-gitea/gitea) (larger), [Forgejo](https://codeberg.org/forgejo/forgejo).
- **A CLI utility.** [`yt-dlp`](https://github.com/yt-dlp/yt-dlp), [`ripgrep`](https://github.com/BurntSushi/ripgrep), a Python library you depend on. (Different DFD — there is no server; the user is the trust boundary.)
- **A small protocol implementation.** A WebSocket library, a small TLS implementation, an IRC server.

Avoid this round: any project where you do not understand the language, anything over ~50 kLoC (out of scope for three hours), anything you do not actually use (you will produce thin work).

---

## Step 2 — Scope statement (15 minutes)

In your write-up, the first short section is the *Scope statement*. It contains:

- The project name, its repository URL, the version (tag or commit hash) you analysed.
- The **deployment model** you are modelling: "single-host docker container behind a reverse proxy"; "PyPI library imported by user code"; "binary the user runs from their terminal." If the project supports multiple deployment models, pick one and say so.
- The threat actors **in scope**. ("Internet-exposed opportunist; authenticated low-privilege user attempting to escalate; insider with maintainer access.")
- The threat actors **out of scope** and the assets **out of scope.** ("Nation-state with on-prem physical access is out of scope. The integrity of the user's host OS outside this application is out of scope.")
- The trust boundaries you will work at.

A *good* scope statement is 4-6 short paragraphs. It is the part of the write-up a reviewer reads first to decide whether they trust the rest.

---

## Step 3 — Sketch a Level-1 DFD (30 minutes)

A minimal DFD of the project as deployed, on paper or in [draw.io](https://www.drawio.com/):

- The external entities (the user; any third-party services the project depends on; the OS).
- The processes (the application; any auxiliary workers; the reverse proxy if part of the model).
- The data stores (database; filesystem; cache).
- The flows, *labelled* with what is flowing.
- The trust boundaries, *dashed*, crossing flows.

Save as `dfd.png` in your write-up directory.

**Acceptance for step 3:** you can point at every element on the DFD and find the line of code (or the config file, or the deployment manifest) that creates it. If you cannot, the DFD is fiction.

---

## Step 4 — One STRIDE pass (30 minutes)

Walk STRIDE per element. Produce a *brief* threat list (10-20 entries) in a single table in your write-up, with the same columns as Exercise 1.

You are not aiming for completeness; you are aiming to *surface the highest-priority threats*. If a STRIDE letter prompts no interesting threat for a given element, write "(none worth recording — \<reason\>)" in the table. The "(none)" is itself a finding; it forces you to justify the absence.

---

## Step 5 — Pick *one* threat and drill (45 minutes)

From the table, pick the **single most interesting threat** — the one that is either highest priority, most surprising, or most representative of a class of risk the project should be aware of. Drill into it:

1. **A short attack-tree sketch** for the chosen threat's adversary goal. Three levels deep. Cost-annotated at the leaves. (Same format as Exercise 2.)
2. **A risk-register entry** — the full ID, title, scoring, owner, status, mitigation, residual, references. (Same format as Exercise 3.)
3. **The defender's view** — one paragraph in writing, naming what the project *currently* does to mitigate this threat (or notably fails to do), and what *additional* control would meaningfully reduce the residual risk. Be specific: a config setting, a code change, a piece of documentation, a CI check. Link to the line of code or the config file you have in mind.

If you cite a CVE that has affected this project or a similar one, link the NVD entry. If you cite an ATT&CK technique, link the technique page.

---

## Step 6 — Coordinated disclosure check (15 minutes)

Before you publish anything, re-read your write-up against the following test:

> **Does this write-up describe a specific exploitable flaw, currently present in a current released version, that an attacker could weaponise against existing deployments?**

If **no** (the write-up is a threat-modelling artifact about a class of risk, the project's design choices, or generally hardening), publish freely.

If **yes** (you believe you have found a specific exploitable flaw):

- **Do not publish the write-up yet.** Even if the finding is "obvious in hindsight," prematurely publishing it gives an attacker a working exploit before defenders have a patch.
- **Read the project's `SECURITY.md`.** Most established projects have one; follow its instructions. If it does not exist, check the project's website or `README.md` for a security contact.
- **Report the finding privately** to the project maintainers. Provide enough detail that they can reproduce it. Offer a reasonable disclosure timeline (90 days is common; some projects ask 30; very large projects can request more).
- **After the project has patched and disclosed**, publish your write-up, citing the CVE if one was issued.

Week 11 covers coordinated disclosure in depth. For now: when in doubt, report privately first.

The vast majority of Week-3 challenge write-ups will be in the "no" category — *threat-modelling artifacts*, not vulnerability reports.

---

## Deliverable

A directory `challenge-01/` containing:

- `README.md` — the write-up. 700-1000 words. Sections: Scope, DFD, STRIDE table, the drilled threat (with attack-tree sketch, risk-register entry, defender's view), Coordinated-disclosure note (one sentence stating that you applied the check above and the result).
- `dfd.png` (or `.svg`) — the diagram.

## Acceptance criteria

- [ ] A real OSS project named, with a repo URL and a commit hash or version tag.
- [ ] A scope statement naming in- and out-of-scope actors and assets.
- [ ] A DFD of the project as deployed, with all five element types.
- [ ] A STRIDE table with at least 10 entries.
- [ ] One drilled threat with: attack tree sketch, risk-register entry, defender's view paragraph.
- [ ] At least one primary source cited (the project's source, a CVE, an ATT&CK technique, a vendor advisory).
- [ ] Coordinated-disclosure check applied; result stated in writing.
- [ ] Word count 700-1000 for the write-up body.
- [ ] No emojis.

## Why this challenge

The mini-project this week asks for a full threat model. The challenge is a focused dry run that lets you make the *project-choice* mistake (picked something too large; picked something you do not actually understand; picked something whose source is opaque) before you commit a week of mini-project time to it. Doing this challenge well means the mini-project becomes the *expansion* of a known-good first finding, not a from-scratch undertaking.

It is also the first time most learners face the *coordinated-disclosure* decision. Doing the check in the small case (here, on a finding you may or may not have made) builds the discipline you will need every time you find something serious for the rest of your career. Read [Week 11](../../week-11/) when it is available; until then, *report privately, publish after patch*.
