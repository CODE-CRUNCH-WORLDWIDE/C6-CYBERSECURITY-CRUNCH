# Week 3 Homework

Six problems, ~6 hours total. Commit each in your Week 3 repo. This is paper work — pen, terminal, Markdown. No live targets.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Threat modeling is paper work. Read source, read docs, reason      │
│  about attacks, write your findings. Do not interact with any       │
│  service you do not operate. Do not scan, probe, or send payloads   │
│  to a live deployment unless it is your own.                        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Problem 1 — Vocabulary drill, written precisely (30 min)

Write `notes/vocabulary.md` answering these, each in 1-2 sentences, with a worked example drawn from a real system you use (name it):

1. **Asset**, with an example. (Not "data" — be specific. *"The encrypted backups of customer projects stored in our S3 bucket"* is an asset; *"data"* is not.)
2. **Threat**, with an example. (Phrased as an adversary action, not a vulnerability.)
3. **Vulnerability**, with an example. (Phrased as a specific weakness in a specific component.)
4. **Risk**, with an example. (Show the multiplication of likelihood and impact, qualitatively.)
5. **Threat actor**, with an example. (Name one and describe their capabilities, motivations, and constraints in 2 sentences.)
6. **Attack surface**, with one concrete example of how reducing it would have prevented a recent (publicly disclosed) incident.
7. **Trust boundary**, with an example from a system you have actually used. (Draw the line if you need to.)

**Acceptance.** All seven entries present. Every example is concrete and drawn from a real system. No definitions are circular ("a threat is when a threat actor poses a threat" is unacceptable).

---

## Problem 2 — Apply STRIDE to your laptop's SSH key workflow (45 min)

Your engineering laptop holds your SSH private key. You use it daily, sometimes with `ssh-agent`, sometimes via a forwarded agent into a remote shell. The key authenticates you to a handful of internet-exposed servers and to your Git remote.

Draw a small DFD (it can be very small — three or four elements) and walk STRIDE per element.

In `notes/hw2-stride.md`:

1. The DFD (photographed or drawn in a tool; commit as `notes/hw2-dfd.png`).
2. A STRIDE table — at least 12 threats — anchored to elements on the DFD.
3. A short paragraph identifying the **top three threats** to your SSH key's confidentiality, in priority order, with one-sentence justifications.
4. A short paragraph naming one mitigation you will actually implement this week. (Hardware-backed keys with `-sk`, agent timeout, per-host key separation, audit of authorized destinations, etc.)

**Acceptance.** DFD present. STRIDE table at least 12 entries. Top-three threats explicitly ordered and justified. One named, scheduled mitigation. The mitigation is something you *will do*, not "we should."

---

## Problem 3 — Build an attack tree for "ship malicious code into the build" (1 hour)

Choose a real software project you contribute to (your C1 mini-project, an open-source repo you maintain, your portfolio repo). Build a Schneier-style attack tree for the goal **"an attacker ships malicious code into a release build."**

In `notes/hw3-supply-chain-tree.md`:

1. The tree, three levels deep on each primary branch. Use markdown nested bullets or the `├──` `└──` ASCII convention.
2. Cost annotations (`$`, `$$`, `$$$`, `$$$$`) at the leaves.
3. The cheapest path identified explicitly.
4. **At least five hardening recommendations**, prioritised by cost-to-defender against severity-of-leaves-defeated.

Primary branches to include at minimum:

- Compromise a maintainer's account (token, password, SSH key, MFA bypass).
- Subvert a dependency (typosquat, name-confusion, malicious update, compromised maintainer of a transitive dep).
- Subvert the build infrastructure (CI runner compromise, build-script tampering, supply-chain of CI dependencies).
- Subvert the release artifact (registry tampering, mirror compromise, signature bypass).

**Acceptance.** Tree includes all four primary branches. At least 15 leaves. Five hardening recommendations, in priority order, with one-line residual risk each. Reference at least one real supply-chain incident as ground truth (XZ Utils CVE-2024-3094; SolarWinds SUNBURST; event-stream `flatmap-stream`; ua-parser-js; the PyPI `colorama` typosquat; etc.).

---

## Problem 4 — Score a finding qualitatively without producing false precision (45 min)

Pick *one* of your threats from problem 2 or problem 3. Write a single full risk-register entry for it in `notes/hw4-register-entry.md`, using all the columns from Lecture 3.

In a second part of the file:

1. **Try to assign a numeric DREAD score** (1-10 on each of the five factors; sum or average). Show your reasoning.
2. **Then write 200-300 words critiquing your own numeric score**: where the squishy-inputs problem bites, where the discoverability factor would have rewarded security-through-obscurity, where the correlated factors compound noise.
3. **End with one paragraph** explaining why the qualitative L/M/H register entry is the disposition you would defend in writing, and why the numeric DREAD is the artifact you would not put on a roadmap document.

**Acceptance.** Full register entry, all columns filled. DREAD score worked out with reasoning. Critique of the score is specific to *your* finding (not a general critique of DREAD). The closing paragraph defends a position rather than reciting one.

---

## Problem 5 — Map a personal threat model to MITRE ATT&CK (1 hour)

Take a real concern you have about *your own* digital life — your password reuse, your home network, your cloud accounts, your laptop's physical security, your backups. Pick one.

In `notes/hw5-personal-attck.md`:

1. **Name the concern in one paragraph**, framed as an attacker goal.
2. **Build a short attack tree** (one level of decomposition is enough — list the major paths to the goal).
3. **For each leaf**, identify the MITRE ATT&CK technique ID(s) that match the leaf, with a link. If a leaf does not match any ATT&CK technique, write "(not in ATT&CK; \<explanation\>)" — most non-behaviour findings are configurations or supply-chain choices, not adversary techniques.
4. **For at least three leaves**, browse the MITRE D3FEND counterpart (<https://d3fend.mitre.org/>) and name one defensive countermeasure it suggests for that technique.

**Acceptance.** At least six leaves identified. At least four ATT&CK technique IDs cited, with links. At least three D3FEND countermeasures cited. The closing sentence makes a real defensive commitment for *yourself* (a password manager migration, a 2FA rollout, a key rotation).

---

## Problem 6 — Find a published threat model and review it (2 hours)

Open-source projects increasingly publish threat models. Find one and review it. Suggestions:

- **The Kubernetes Threat Model** (commissioned by the CNCF; published in 2022): <https://github.com/kubernetes/community/blob/master/sig-security/security-audit-2022/findings/Kubernetes%20Threat%20Model.pdf>
- **Trail of Bits audit reports** (many include sections that are essentially threat models of the reviewed code): <https://github.com/trailofbits/publications>
- **CNCF Security TAG reports** (Cilium, etcd, Argo, others have published threat models): <https://github.com/cncf/tag-security>
- **The Tor design paper and subsequent threat-model documents**: <https://www.torproject.org/docs/documentation.html>
- **The Signal protocol's documents** at <https://signal.org/docs/> include a model.

Pick one. Read it. In `notes/hw6-review.md`:

1. **Identify the four Shostack questions** in the document. For each, quote the section that answers it (or write "not addressed" with a citation to where you would have expected it).
2. **Identify the methodology** the document uses: STRIDE, PASTA, attack trees, asset-driven, attacker-driven, software-driven, or a hybrid. Cite the section that reveals which.
3. **Identify the strongest finding** in the document — the one a senior engineer would act on first. Explain in 2-3 sentences why that one.
4. **Identify the weakest finding** — the most generic, the most "scary list," the most under-justified. Be specific about why.
5. **In 300-500 words, write a critique** of the document as a *document*: structure, voice, hand-offs to readers (engineers? auditors? regulators?), and what you would change.

**Acceptance.** All five sections present. Quotes from the document are exact and cited (page or section). The critique reads as analyst commentary, not as marketing for the project. At least one suggestion for improvement is concrete enough to PR.

---

## Time budget

| Problem | Time |
|---------|------|
| 1 — Vocabulary drill | 30 min |
| 2 — STRIDE on your SSH workflow | 45 min |
| 3 — Supply-chain attack tree | 1 h |
| 4 — Qualitative scoring + DREAD critique | 45 min |
| 5 — Personal model mapped to ATT&CK + D3FEND | 1 h |
| 6 — Read and review a published threat model | 2 h |
| **Total** | **~6 h** |

When done, push the Week 3 homework and start (or continue) the [mini-project](./mini-project/README.md).
