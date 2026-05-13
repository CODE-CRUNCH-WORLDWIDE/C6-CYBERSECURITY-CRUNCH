# Exercise 1 — Threat-model your laptop

**Time:** ~45 minutes.
**Outcome:** A one-page STRIDE threat model of your own laptop, in your own words, that you could hand to a peer.

This is a warm-up for the Week 1 mini-project. The mini-project will threat-model a system you *operate* (a side project, a home server, a self-hosted app). This exercise gets the muscle of "what are we building, what can go wrong, what are we doing about it, did we do a good job" working on the easiest possible target: the device you already understand.

## Problem statement

Produce `exercise-01-laptop-threat-model.md` in your Week 1 notes folder. The document must answer the four questions from Lecture 1 about *your laptop*, applying STRIDE to at least three of its components, and finishing with at least four mitigations you have actually implemented (or will implement this week).

## Step 1 — What are we building? (5 min)

Write a paragraph describing your laptop *as a system*:

- Operating system and version.
- Disk encryption: on or off? Which mechanism (FileVault, LUKS, BitLocker)?
- Who else has physical or remote access to it?
- What sensitive material lives on it: source code, customer data, personal documents, password manager database, SSH keys, browser cookies, cloud-CLI credentials in `~/.aws/credentials` or `~/.config/gcloud/`?
- What does it connect to that you would not want an attacker to reach next: a corporate VPN, a personal cloud account, GitHub with push access to private repos?

Draw a trust-boundary sketch. Even a five-line ASCII diagram counts. The boundaries are: the disk (encrypted vs not), the user session (locked vs not), the network (home, coffee shop, corporate), the cloud (your accounts behind it).

## Step 2 — What can go wrong? Apply STRIDE. (15 min)

For at least three components — pick from disk, user session, browser, SSH key, cloud-CLI credential file, password manager — fill in this table:

| Component | S | T | R | I | D | E |
|-----------|---|---|---|---|---|---|
| (e.g. SSH private key in `~/.ssh/id_ed25519`) | Attacker uses the key to impersonate me to GitHub | Attacker swaps in their key to gain push access | I cannot prove a push that signed me out was not me | Key file is readable to a snooping process | n/a (single key, not a service) | Whoever has the key has my GitHub identity |

You do not have to fill every cell — leave `n/a` where the letter genuinely does not apply, and justify in one sentence. (Most cells *will* apply once you think it through.)

## Step 3 — What are we going to do about it? (15 min)

For each row, name *at least one mitigation* you have already enabled, or commit to enabling this week. Be specific. "Use strong passwords" is not a mitigation; "configured `pam_pwquality` minlen=14, plus password manager-generated 20-char passwords for every account" is.

Required: at least one mitigation per row. Useful: a column noting whether the mitigation is preventive, detective, or corrective.

## Step 4 — Did we do a good job? (10 min)

Self-review in a closing paragraph:

- Which component did you almost forget? (For most people: the browser. Sessions and stored autofill data are an enormous credential cache.)
- Which STRIDE category has the weakest mitigations? What would it cost — in time or in money — to strengthen it?
- What single change, if you made it tomorrow, would most reduce risk? Why have you not made it yet?
- If the laptop were stolen unlocked from a café table right now, what would the attacker get? List the data, the accounts, the keys.

## Acceptance criteria

- [ ] `exercise-01-laptop-threat-model.md` committed to your Week 1 notes folder.
- [ ] Section 1 describes the laptop as a system, with at least one trust boundary named.
- [ ] Section 2 applies STRIDE to at least three components in a table.
- [ ] Section 3 names a specific mitigation for every non-`n/a` STRIDE cell.
- [ ] Section 4 contains a self-review paragraph answering all four bullets above.
- [ ] The document is ≤ 2 pages when rendered (roughly 800-1200 words). Threat models that drone on are not read; the discipline is to be brief.

## Hints

<details>
<summary>If you cannot think of more than one component</summary>

A laptop has at least: the encrypted disk, the user session (whether your screen is locked), the browser (cookies, autofill, extensions), the OS keychain, your SSH agent and key files, your shell history, your cloud CLI credential files, your locally-running editors (and their plugins), your locally-running Docker daemon (if any), your physical USB ports, your camera and microphone. Pick three.

</details>

<details>
<summary>If you cannot think of a Repudiation case</summary>

Repudiation is "can you prove who did it later?" On a single-user laptop with no centralized log, the answer is usually "no" — and that *is* the finding. Most personal devices repudiate by default. The mitigation is rarely "implement an audit log on your laptop"; usually it is "ensure the *downstream* systems (GitHub, cloud, password manager) have audit logs whose attribution you trust."

</details>

<details>
<summary>If your laptop is locked-down corporate</summary>

You may not have administrative control over many of these settings. That is itself a finding — the trust boundary is "you" vs "your IT department." Your threat model is then about what *you* can see and influence: which extensions are installed, which corporate VPN you connect to, which corporate audit can be subpoenaed by whom. The exercise still applies; the mitigations just live at a different layer.

</details>

## Why this matters

The Week 1 mini-project is harder. The discipline rehearsed here — name the components, apply STRIDE per component, name a mitigation per cell, self-review — is the same discipline you will apply for the rest of your career, on systems an order of magnitude larger. Practice it on the simplest system you have access to.

## Submission

Commit the file. The mini-project at the end of the week reuses this exact structure on a larger target.
