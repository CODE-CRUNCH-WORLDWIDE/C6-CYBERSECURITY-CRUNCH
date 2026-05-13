# Lecture 2 — Asset-Driven vs. Attacker-Driven Models

> *Where you start a threat model changes what you see. Shostack identifies three starting points — assets, attackers, software. Each gives a different ranking of the same threats. The mature practitioner knows which lens to apply, in which order, and how to recognise the failure mode of each.*

Lecture 1 introduced STRIDE and attack trees as analytical *tools*. This lecture takes a step back: regardless of the tool, you have to *start somewhere*, and the starting point determines what you find first. Adam Shostack, in *Threat Modeling: Designing for Security* (Wiley, 2014), argues that there are three principal starting points — asset-driven, attacker-driven, and software-driven — and that most engineering teams should start software-driven, working out toward the other two.

The mini-project this week asks for a threat model of a real open-source project. By the end of this lecture, you will know which lens to start with for *your* project, why, and how to add the other lenses as you iterate.

This lecture also introduces PASTA — Process for Attack Simulation and Threat Analysis (UcedaVélez and Morana, 2015) — at the level of its seven stages. PASTA is a heavy, business-risk-centric process: appropriate in regulated industries, overkill for a side project. You should know it exists and what it does, even if you do not run it this week.

---

## 1. The three lenses

Shostack's framing, expanded:

**Asset-driven (also: "what are we protecting?").** Start with what is valuable to the defender. Enumerate the assets — customer data, build artifacts, regulatory standing, brand reputation. For each asset, ask: who would want it, what could they do to it, how do they get there?

**Attacker-driven (also: "who is going to attack us?").** Start with the threat actors. Model each one — capabilities, motivations, resources, patience, willingness to be noisy. For each, ask: what would they go after, how would they get in, what is their typical TTP set?

**Software-driven (also: "what does the code do?").** Start with the system. Draw the DFD; walk STRIDE per element and per interaction; let the threats fall out of the structure.

Shostack's recommendation, defended at length in chapter 2 of the 2014 book, is that **engineering teams should start software-driven**. The reasons are practical:

- Software is the artifact engineers actually have. Asset lists and attacker profiles are produced; software is *there*.
- Software-driven analysis surfaces threats that asset-driven analysis misses. Many real exploits have nothing to do with the "important" assets in the abstract — they involve a forgotten admin endpoint, a default credential in an unimportant subsystem, a debug interface left in production.
- Attacker-driven analysis without significant intelligence-gathering quickly becomes fiction. "What would a nation-state do" is unanswerable without a real intelligence budget. "What does our software do, and what can go wrong at each boundary" is answerable in an afternoon.

That said, *all three lenses surface different threats*, and a thorough threat model uses all three. The disagreement is about the *order*.

---

## 2. Asset-driven modeling

### What it is

Make a list of what you would not want lost, leaked, or made unavailable. Group the list. For each group, ask the three questions:

1. **Who would want this?**
2. **What would they do to it?** (Take it? Modify it? Make it unavailable? Use it to reach something else?)
3. **What paths exist for them to reach it?**

### Where it works

Asset-driven modeling is the right starting point in two situations:

- **Regulated industries** — finance, healthcare, defence — where the *asset categories* are the basis of the regulation. PCI-DSS is structured around protecting cardholder data; HIPAA around protected health information; GDPR around personal data. If your regulator names assets, the regulator has effectively chosen your starting point.
- **Mature programs at the program level.** The CISO's annual threat model is asset-driven by default — it has to be, because the asset list is what justifies the program's budget to the board. The engineering team's threat model of a single service can be software-driven; the program-level model that aggregates them is asset-driven.

### Where it fails

The classic failure modes:

- **The asset list itself is wrong.** It contains the obvious assets and misses the load-bearing-but-boring ones. The CI/CD pipeline is an asset (compromise it once and you ship malware to every customer); the build secrets store is an asset; the dependency mirror is an asset. New analysts list "customer data" and miss the supply chain.
- **The granularity is wrong.** "Our data" is too coarse to threat-model usefully; you need "customer PII", "customer credentials (hashed)", "customer credentials (raw, in-flight during the auth flow)", and so on, each with its own threat picture.
- **The "important" lens biases away from where attacks actually start.** An attacker rarely starts at the asset; they start at the perimeter, work inward, and reach the asset through a chain. Asset-driven modeling sees the destination clearly and the path unclearly.

### Worked example

A small open-source notes app, asset-driven:

- **Asset A1 — Users' note content.** Who would want it? An ex-partner, a journalist's source, a competitor with corporate notes. What would they do? Read it (info disclosure), modify it (tampering), or destroy it (DoS / availability). Paths: account takeover, server compromise, backup leak, host operator with DB access.
- **Asset A2 — Service availability.** Who would want it down? A petty disgruntled user, a competing service, a botnet operator using the host. Paths: application DoS, infrastructure DoS, billing-account suspension, hosting-provider abuse complaint.
- **Asset A3 — Brand / "trust" reputation.** Who would damage it? Anyone with a grievance. Paths: defacement, customer-data leak, public exposure of poor security practices.
- **Asset A4 — The build pipeline.** Who would want this? A supply-chain attacker. Paths: dependency confusion, a maintainer's PAT leaked, a malicious PR merged without review. (This asset is the one new analysts miss.)

For each asset, the analyst proceeds to STRIDE (lecture 1) and attack trees (lecture 1) — the *tools* are the same regardless of the starting *lens*.

---

## 3. Attacker-driven modeling

### What it is

Build a small set of threat-actor profiles — Shostack calls these "personas," borrowing the UX term. For each, articulate:

- **Capabilities.** Technical sophistication, tooling, footprint, available zero-days, infrastructure.
- **Motivations.** Money, ideology, coercion, ego, accident, sport.
- **Constraints.** Patience, willingness to be detected, attribution sensitivity, budget.
- **Typical TTPs.** What attacks does this actor characteristically run?

Then walk each actor against the system: what would they do first, what would they do next, where do their TTPs hit your DFD?

### Useful archetype set

A small, useful starter set for most internet-facing systems:

- **Opportunist.** Automated scanner running off a botnet. Sees the system because everyone's port 22 is being scanned. Goal: install a cryptominer. TTPs: default credentials, known CVEs in exposed software, drive-by vulnerability scanning. Constraint: noisy, gives up on hardened targets within seconds.
- **Disgruntled insider.** A current or former employee with legitimate access. Goal: data exfiltration, sabotage, embarrassment. TTPs: abuse of legitimate access, slow exfil under the radar, knowledge of the alerting blind spots. Constraint: limited to what their access permits, but knows the gaps well.
- **Organised criminal.** Financially motivated, capable, patient enough for a multi-step intrusion if the payoff is large. Goal: ransomware, BEC, payment-card theft, account takeover at scale. TTPs: phishing, credential theft, lateral movement, exploit kits. Constraint: cost-of-attack must be less than expected return.
- **Hacktivist.** Ideologically motivated. Goal: defacement, leak, public disruption. TTPs: web-app attacks, credential stuffing, public shaming on the result. Constraint: willing to be noisy and identifiable.
- **Nation-state.** Strategic intelligence or strategic disruption. Goal: long-term access, comprehensive collection, optional pre-positioning. TTPs: full kill chain, custom tooling, supply-chain attacks. Constraint: there usually is none worth mentioning at the technical level; the question is scope.

### Where it works

- **Industries with known active adversaries** — defence, finance, journalism, dissident infrastructure — where the actor profile is *known* rather than imagined.
- **When evaluating defensive investment.** "Will this detection rule catch the actors we care about?" is an attacker-driven question; the answer requires modelling the actors.
- **Combined with MITRE ATT&CK** as the *vocabulary* for TTPs. ATT&CK is essentially a structured catalogue of attacker techniques used by named actor groups; using it grounds the persona work in observed reality.

### Where it fails

- **Fiction trap.** Without intelligence, the personas are invented, and the resulting analysis tells you what the *author* fears, not what attackers do. The fix is to anchor every persona claim ("APT-X uses spear-phishing as initial access") to a primary source: a vendor incident report, a CISA advisory, an academic paper.
- **The wrong actor.** Many breaches involve actors the model never named — script kiddies running automated tools against a target chosen at random. A model that only profiles the "sophisticated" actors misses the ones that actually compromise the system.
- **All-actor blur.** When the model says "we defend against everything from script kiddies to nation-states," the analyst has avoided the actor-prioritisation question. Real models name a *bounded* set of actors and explicitly exclude others.

---

## 4. Software-driven modeling

### What it is

Start with the software. Draw the DFD (lecture 1). Walk STRIDE per element or per interaction. Surface threats from the *structure of the system*, not from a list of valuables or a list of attackers.

This is the lens Shostack defends as the right default for engineering teams. The mini-project this week is software-driven (you start with a real codebase). The exercises this week are software-driven (you walk STRIDE on a sketched app).

### Why it is the default

- **Engineers have the software.** They have it as code, as architecture documents, as deployment manifests. They do not have a current asset list, and they do not have an intelligence-grade actor profile. Use what you have.
- **The DFD makes threats *locatable*.** Every threat surfaces *at* an element or *across* a flow. The analyst can say "this threat lives here, in this component" — which makes it easier to assign an owner, easier to test, easier to verify the fix.
- **It scales to incremental change.** A new endpoint, a new service-to-service flow, a new third-party integration: the analyst updates the DFD locally and re-walks STRIDE locally. Asset-driven and attacker-driven analyses do not localise in the same way.

### Where it fails

- **Surfaces threats; does not prioritise them.** Software-driven analysis can produce a list of 100 candidate threats with no internal sense of which one matters most. Asset-driven and attacker-driven lenses provide the prioritisation that software-driven analysis lacks.
- **Misses out-of-system threats.** A backup process not on the DFD, a forgotten admin console reachable from a different network, a third-party integration not yet drawn: software-driven analysis is only as complete as the DFD it walks. (Attack trees, drilled into specific goals, often reveal what the DFD missed; that is one of their secondary uses.)
- **Misses business-context threats.** "What if the company is acquired and the acquirer's identity-provider integration replaces ours?" is not a software-driven question; it is a business-context question. A purely software-driven model misses it.

### The recommended composition

Shostack's recommended composition for an engineering threat model:

1. **Start software-driven.** Draw the DFD; walk STRIDE; produce a candidate threat list.
2. **Overlay asset-driven prioritisation.** Map each candidate threat to the asset(s) it touches; threats that touch the most valuable assets rise to the top.
3. **Sanity-check against attacker-driven analysis.** Pick two or three actor archetypes that plausibly target this system; for each, ask whether the top threats are the threats *they* would pursue. If not, either the threats are mis-prioritised, or the actor list is wrong.

The mini-project this week follows this composition.

---

## 5. PASTA — Process for Attack Simulation and Threat Analysis

PASTA was introduced by Tony UcedaVélez and Marco M. Morana in *Risk Centric Threat Modeling* (Wiley, 2015). It is a *process*, not a tool: a defined seven-stage workflow that produces a business-risk-centric threat model. The seven stages:

1. **Define Objectives.** Business objectives, security objectives, compliance scope. The output is a list of the business outcomes the threat model exists to protect.
2. **Define Technical Scope.** Application architecture, deployment, dependencies, third parties. The DFD lives here.
3. **Application Decomposition.** Components, data flows, trust boundaries, use cases. Conceptually overlaps with stage 2; in practice, this is the deep technical breakdown.
4. **Threat Analysis.** Threat intelligence relevant to the application's industry and asset class. The output is a prioritised threat list grounded in observed adversary behaviour.
5. **Vulnerability Analysis.** Mapping threats to specific weaknesses in the application. Static analysis, dynamic analysis, manual review.
6. **Attack Modeling.** Attack trees, attack patterns (CAPEC), simulated attacks. The output is a concrete picture of how the threats become incidents.
7. **Risk Analysis and Management.** Likelihood, impact, residual risk, mitigation recommendations, sign-off.

### When to use PASTA

- **Regulated environments** where the threat model is an audit artifact.
- **Business-critical systems** where the cost of incident materially threatens the organisation.
- **Mature security programs** with the staffing to run the full process and the standing intelligence inputs to feed stage 4.

### When *not* to use PASTA

- **A one-week mini-project on an open-source app.** PASTA's seven stages are weeks of work each. The right approximation for this week is "software-driven STRIDE, asset overlay, attacker sanity check" — call that "PASTA-lite" if you must, but do not call it PASTA.
- **Greenfield development where the threat model needs to keep up with the code.** PASTA is heavy enough that it tends to become an annual artifact, not a continuous one. Shostack-style lightweight threat modeling is the alternative.

PASTA is in the resource list because you should know it exists. The C6 mini-project does not run PASTA end-to-end.

---

## 6. Other named methodologies — briefly

Worth knowing the names of; not running this week:

- **LINDDUN** — privacy-focused (Linkability, Identifiability, Non-repudiation, Detectability, Disclosure of information, Unawareness, Non-compliance). Use when privacy is the primary concern; GDPR-regulated systems often start here.
- **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation) — an organisational-risk methodology from Carnegie Mellon SEI; predates STRIDE in some respects; heavy.
- **Trike** — an open-source methodology focused on requirements and risk; less widely used today.
- **VAST** (Visual, Agile, Simple Threat) — the ThreatModeler-tool methodology; vendor-anchored; mentioned for completeness.

The SEI's 2018 white paper *Threat Modeling: A Summary of Available Methods* (linked in resources.md) is the right read if you want a comparative map.

---

## 7. Choosing a lens for the mini-project

The mini-project asks you to threat-model a real open-source project. Choose your starting lens deliberately:

- **If the project is a library or a tool with no central operator** (e.g. a Python CLI), the natural lens is *software-driven*. The DFD is the codebase's input-output structure. STRIDE walks the boundaries between trust zones (the program and its caller, the program and a file it parses, the program and a network it queries).
- **If the project is a self-hosted service** (e.g. a notes app, a wiki, a small SaaS-style project), use *software-driven* as the primary lens and overlay *asset-driven* prioritisation. The DFD is the service. The assets are users' data and service availability.
- **If the project is security-sensitive infrastructure** (a TLS proxy, a password manager, a cryptographic library), overlay *attacker-driven* analysis explicitly — at minimum the opportunist and the organised criminal personas, and credible APT inclusion if the project is widely deployed.

The mini-project README walks through the choice for you, with checklists.

---

## Recap

- Three lenses: **asset-driven** (what are we protecting?), **attacker-driven** (who is attacking?), **software-driven** (what does the code do?). Each surfaces different threats; each has documented failure modes.
- Shostack's recommended default for engineering teams is **software-driven first, asset overlay, attacker sanity check**. The mini-project follows this composition.
- **PASTA** is the seven-stage business-risk-centric process for regulated, business-critical systems; know it, do not run it this week.
- Other named methods (LINDDUN, OCTAVE, Trike, VAST) exist; the SEI's 2018 paper compares them.
- The choice of lens is itself a *threat-modeling decision*. Make it deliberately, write it down in the model's preamble, and revisit it if the model is missing threats you would expect to see.

The next lecture takes the threats you have surfaced and turns them into a *risk register* — the artifact that drives prioritisation and ongoing tracking. It also explains why `Risk = Likelihood × Impact` is a useful sorting heuristic and a misleading number, and what to do about that.
