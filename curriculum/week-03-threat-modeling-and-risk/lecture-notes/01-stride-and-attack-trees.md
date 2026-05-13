# Lecture 1 — STRIDE and Attack Trees

> *Threat modeling is not a checklist. It is a structured argument. STRIDE and attack trees are the two tools that make the argument tractable: STRIDE for breadth across categories of threat, attack trees for depth into a particular adversary goal.*

This lecture sets up the workhorse representation of the week — the data-flow diagram (DFD) — and the two complementary analytical lenses applied to it. STRIDE walks every element and every flow on the diagram and asks the same six questions of each. Attack trees take one stated adversary goal and walk it the other way — *how* could the adversary achieve it, decomposed all the way down to actions an attacker can actually take.

A practitioner uses both. STRIDE is the broad sweep; attack trees are the focused drill. Neither alone is enough.

---

## 1. The four questions

Adam Shostack, in *Threat Modeling: Designing for Security* (Wiley, 2014), frames threat modeling around four questions, in order:

1. **What are we building?**
2. **What can go wrong?**
3. **What are we going to do about it?**
4. **Did we do a good job?**

Every method this week — STRIDE, attack trees, asset-driven, attacker-driven, DREAD, PASTA — is a tool that helps answer one or more of those four questions. The questions are not optional. A threat model that skips question 1 is unmoored ("what can go wrong" *with what*?). A threat model that skips question 4 is unreviewed.

The four questions also define the shape of the threat-model *document*. The mini-project this week produces such a document, with sections that map to the four questions exactly. Lecture 2 returns to question 1 (asset vs. attacker vs. software-driven approaches); lecture 3 returns to question 3 (risk, prioritisation, the register).

---

## 2. Vocabulary — get this right

Loose use of the words below is the single most common failure mode in junior threat-modeling work. Memorise the distinctions.

**Asset.** Something of value to the defender. *Examples:* the user database; the ability to ship a release; the company's reputation; uptime of the payments page; the integrity of a build pipeline. Assets are concrete and finite.

**Threat.** A *potential adversary action* capable of harming an asset. A threat exists independent of any specific flaw. *Example:* "an unauthenticated remote attacker reads the user database" is a threat. It is meaningful even before any vulnerability is identified.

**Vulnerability.** A specific weakness in the system that a threat can exploit. *Example:* "the `/api/users` endpoint does not check the session cookie" is a vulnerability. It is the gap that makes the threat exploitable in this system.

**Risk.** The combination of (a) the probability the vulnerability is exploited and (b) the impact if it is. Risk is the quantity decisions are made on. A high-impact threat against an unexploitable system is low-*risk*; a low-impact threat exploited daily is also low-risk; the risks worth fixing first are the products of plausible likelihood and material impact.

**Threat actor.** The party that may carry out the threat. Common archetypes: the insider (privileged user gone bad), the opportunist (script kiddie scanning the internet), the organised criminal (financially motivated, capable of multi-step intrusion), the nation-state (resourced, patient, deniable). The model should *name* the actors it defends against — and the actors it explicitly *does not*. "We do not defend against a nation-state with physical access" is a legitimate scope statement; "we defend against everything" is not.

**Attack surface.** The sum of points at which an attacker can attempt entry or extraction. Reducing attack surface (closing ports, removing unused endpoints, dropping privileges) is the most cost-effective defensive activity per unit of effort.

**Trust boundary.** A line on the DFD where data crosses between zones of differing trust assumptions. *Examples:* the boundary between the public internet and your reverse proxy; the boundary between your application and its database (the DB trusts the app to authenticate users); the boundary between two microservices that authenticate to each other. STRIDE is most productively applied *at* trust boundaries — that is where threats actually surface.

---

## 3. The data-flow diagram (DFD)

Threat modeling needs a picture to argue over. The picture is the DFD. Its elements are deliberately few:

- **External entity (a rectangle).** Something outside the system that interacts with it. The user. A third-party API the system calls. A scheduler. These are *not* under the defender's control.
- **Process (a circle, sometimes a rounded rectangle).** A computation that runs inside the system. A web server. A worker. A function.
- **Data store (two parallel lines, or an open-ended rectangle).** Anything that persists state. A database. A file on disk. A cache. A queue.
- **Data flow (an arrow with a label).** Data moving between elements. The label names *what* is flowing (e.g. "login credentials", "session token", "user profile JSON"), and the direction matters.
- **Trust boundary (a dashed line crossing flows).** The line between zones of differing trust assumptions.

A DFD is *not* an architecture diagram. It is not concerned with technology choices except where the technology determines the trust boundary. It is also not concerned with sequence; if you need a sequence diagram, draw one separately. The DFD's job is to make the *flow of data* and the *boundaries between trust zones* visible.

**Levelling.** Real systems do not fit on one DFD. The convention from Shostack and from older systems-analysis literature is to level: a "Level 0" or "context" diagram shows the whole system as a single process with its external entities; a "Level 1" diagram opens that process into its top-level components; a "Level 2" diagram opens one of those components further; and so on. *Stop levelling when the next level would not change the set of threats you can see.* Most real threat models are Level 1 with Level 2 zooms on the highest-risk components.

**Worked DFD — a minimal web application.** A todo-list app:

- External entity: *User* (web browser).
- Process: *Web server* (the Flask / FastAPI / Django app).
- Data store: *Todos DB* (SQLite or PostgreSQL).
- Data flows: *credentials* (User → Web server), *session cookie* (Web server → User), *todo CRUD* (User ↔ Web server), *SQL* (Web server ↔ Todos DB).
- Trust boundaries: between *User* and *Web server* (the network — public internet); between *Web server* and *Todos DB* (the loopback or VPC boundary; the DB trusts the app to have authenticated the user already).

That five-element diagram is enough to drive a full STRIDE pass and surface the textbook web-application threats. Do not let yourself draw more before you have walked STRIDE across this much.

---

## 4. STRIDE

STRIDE was introduced inside Microsoft by Loren Kohnfelder and Praerit Garg in their April 1999 internal memorandum *The Threats to Our Products*. The acronym names six categories of threat — and crucially, each category is the *negation of a security property* you want to hold:

| STRIDE letter | Threat category | Property it violates |
|---|---|---|
| **S** | **Spoofing** identity | Authentication |
| **T** | **Tampering** with data | Integrity |
| **R** | **Repudiation** | Non-repudiation |
| **I** | **Information disclosure** | Confidentiality |
| **D** | **Denial of service** | Availability |
| **E** | **Elevation of privilege** | Authorisation |

The pairing of *threat* with *property* is the source of STRIDE's value. The analyst does not have to invent threats from scratch; they walk each element of the DFD and ask, of each element, *which of these six properties is at stake here, and which threats violate it*?

### STRIDE per element

Shostack's *Threat Modeling* documents which STRIDE categories typically apply to which DFD element type:

| DFD element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| **External entity** | ✓ |  | ✓ |  |  |  |
| **Process** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Data store** |  | ✓ | ✓ (in some accounting contexts) | ✓ | ✓ |  |
| **Data flow** |  | ✓ |  | ✓ | ✓ |  |

This is a *prompt* table, not a rule. It says: when you walk to an external entity, prompt yourself with S (could the entity be impersonated?) and R (could the entity deny having acted?). When you walk to a process, prompt yourself with all six. When you walk to a data store, do not prompt yourself with E (a data store cannot be "escalated"; it is acted upon, not acting).

### STRIDE per element — worked

On the todo-list DFD above:

- **External entity: User.** Spoofing — could an attacker log in as another user? (Password stuffing, session hijacking, MFA bypass, magic-link replay.) Repudiation — if a user later claims "I did not delete that todo", can we prove they did? (Application audit logs; user-action attribution.)
- **Process: Web server.** All six. Spoofing — could a malicious client impersonate the legitimate web app to a peer service? Tampering — could an attacker modify the running process (in-memory, via code injection, via a tampered package in the supply chain)? Repudiation — does the server log enough to attribute the actions it takes? Information disclosure — does the process leak stack traces, environment variables, internal hostnames in error responses? Denial of service — what request, sent enough times or shaped unusually, will exhaust CPU or memory? Elevation of privilege — does the server run as a non-root user; if it is compromised, what is reachable from its process credentials?
- **Data store: Todos DB.** Tampering — can the DB be written to outside the app's intended write paths (e.g. a co-tenant on the same host)? Information disclosure — at rest, on backups, in logs that include query text? Denial of service — can the disk be filled, the connection pool exhausted, the long-query lock acquired? (Skip E: data stores do not escalate.)
- **Data flow: credentials (User → Web server).** Tampering — could the credential be modified in transit? Information disclosure — is the flow encrypted (TLS) and authenticated? Denial of service — can the flow be flooded or hijacked at the network layer?

The exercise is mechanical, by design. The value is not in originality; it is in *completeness*. STRIDE prevents the most common failure mode of unguided threat modeling: noticing the colorful threats and missing the boring ones. (Repudiation, in particular, is the most commonly skipped letter, and the source of the most painful auditor findings.)

### STRIDE per interaction

A refinement, also from Shostack: rather than walking elements, walk *interactions* — every (element, flow, element) triple where the flow crosses a trust boundary. Apply STRIDE at the crossing. This produces fewer total prompts and locates the threats where the boundary actually is.

The "per element" and "per interaction" variants are complementary, not exclusive. Use per-element for systems you do not yet understand. Use per-interaction when you have already mapped the trust boundaries cleanly.

### How long should STRIDE take?

For the todo-list DFD: 30 to 45 minutes, producing 15 to 25 candidate threats. For a real microservice with one upstream and one downstream peer: 1 to 2 hours, producing 30 to 60 candidate threats. If you walked STRIDE on a real DFD and produced 3 threats, you skipped letters; if you produced 300, you are not filtering — every other prompt should yield "yes, this is a real concern" or "no, mitigated by [X]". The discipline is in the *written justification*, not the count.

---

## 5. Attack trees

Bruce Schneier's December 1999 *Dr. Dobb's Journal* article, *Attack Trees*, introduced the second tool of this lecture. An attack tree starts with an attacker goal at the root and decomposes the goal into sub-goals — and those into sub-sub-goals — until the leaves are actions an attacker can actually take.

**Structure.** Each non-leaf node has children. The children combine in one of two ways:

- **OR:** any one child achieves the parent. (Multiple paths to the same goal.)
- **AND:** all children, together, achieve the parent. (A multi-step attack.)

Conventionally, AND is drawn with a small arc connecting the children's edges; OR is the default.

**Worked attack tree — "read another user's todos".** Goal: *attacker reads the contents of another user's todo list on the demo todo-list web app*. One decomposition:

```
Read another user's todos                          (OR)
├── Authenticate as that user                      (OR)
│   ├── Guess / brute force the user's password    (OR)
│   │   ├── Common-password dictionary attack
│   │   ├── Credential-stuffing from a public leak
│   │   └── Targeted dictionary (employer, hobby leaks)
│   ├── Reset the user's password                  (OR)
│   │   ├── Reset-flow takeover (predictable token)
│   │   ├── Account-recovery via support social-eng
│   │   └── Email account takeover (out of scope?)
│   └── Steal the session cookie                   (OR)
│       ├── XSS in the app
│       ├── MITM of unprotected HTTP request
│       └── Local malware on the user's device
├── Read directly from the database                (OR)
│   ├── SQL injection from the app's endpoints
│   ├── Direct DB access (port exposed?)
│   └── Backup file accessible (S3 misconfigured?)
├── Read from a server-side process                (OR)
│   ├── SSRF that returns DB rows
│   ├── Server-side logs that include todo bodies
│   └── Server-side cache that does not segregate users
└── Read in transit                                (OR)
    ├── MITM of unprotected HTTP
    └── TLS downgrade / cert-validation bypass
```

The tree above is incomplete (deliberately — making it complete is an exercise). But notice what it *already* gives you:

1. **It surfaces classes of attack the DFD did not.** "Backup file accessible (S3 misconfigured)" is invisible on the DFD because the DFD did not include the backup process; the attack tree exposes the missing element, and the DFD should be updated.
2. **It exposes shared sub-goals.** "MITM of unprotected HTTP" appears under both "Steal the session cookie" and "Read in transit." Mitigating it (enforce HTTPS, HSTS, certificate pinning where appropriate) addresses both branches at once.
3. **It locates *cheap* leaves.** "Common-password dictionary attack" is, for many systems, by far the cheapest leaf. Defending the root by closing this leaf (password-strength requirements, rate limiting, breach-password blocking) is much higher-leverage than defending against, say, a TLS downgrade.

### Cost annotation

Schneier's original article suggests annotating leaves with cost or feasibility — a small integer scale, monetary cost, or Boolean (cheap / expensive). Then the cost of a sub-goal is *the minimum cost across OR children* and *the sum of costs across AND children*. Propagated up to the root, the result is an estimate of the cheapest attack.

A cost-annotated tree is the right artifact for arguing with stakeholders about which defences matter most. The argument is no longer "we should fix XSS because XSS is bad"; it is "the cheapest path to reading another user's todos costs $50 and runs through the XSS leaf; the next-cheapest path costs $5000 and runs through the AWS-misconfiguration leaf; fixing the XSS raises the floor to $5000."

### When to use attack trees

- **When STRIDE has surfaced a class of threats and you want to drill into one.** STRIDE gives breadth; attack trees give depth.
- **When you are arguing about prioritisation.** A tree with annotated leaves is concrete in a way a STRIDE list is not.
- **When a particular goal is uniquely important.** "Steal a private key" or "ship malicious code into the build" deserves its own tree even if STRIDE already mentions it under several letters.

Attack trees are *not* the right tool when you do not yet know the system. STRIDE first; trees second.

---

## 6. Anti-patterns

A short list of common mistakes — call them out in review, including in your own:

- **The "scary list".** A long enumeration of every attack the author has heard of, untethered from any specific element of the system. The fix is to walk the DFD; threats that do not anchor to an element or a flow are not yet threats.
- **The "all green" model.** Every threat is "mitigated by our firewall" or "covered by TLS." The fix is to require specific mitigations: which firewall rule, which TLS configuration, on which interface.
- **Confusing threats and vulnerabilities.** "SQL injection" is a vulnerability class; "an attacker reads the todos DB" is a threat. The threat is the same whether the vulnerability is SQLi, an SSRF, or a backup misconfiguration. STRIDE prompts threats; vulnerability scanning prompts vulnerabilities.
- **Stopping at "we will fix it later."** Question 3 — *what are we going to do about it* — has four answers and only four: mitigate, transfer (insurance, contract), avoid (remove the feature), or accept (record the residual risk with sign-off). "Defer" is not on the list.
- **Skipping question 4.** *Did we do a good job?* The most common skip. Lecture 3 returns to this; the answer involves the risk register, a review cadence, and a way to learn from incidents.

---

## 7. Tooling — briefly

You will write your threat model in Markdown. The DFD can be hand-drawn (photograph, commit the PNG), drawn in [draw.io](https://www.drawio.com/) (free, exports SVG and PNG), or built in [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) (open-source threat-modeling tool; the diagrams are first-class artifacts you can version-control). Microsoft's *Threat Modeling Tool* (free, Windows-only) generates a STRIDE-based report from a DFD; if you have a Windows host, it is worth a trial; the report is verbose but a good check on your own pass.

For programmatic threat modeling — useful when the architecture itself is in code (Terraform, Pulumi) and you want the threat model to update with it — see [OWASP pytm](https://github.com/izar/pytm). It is overkill for this week's mini-project but worth knowing exists.

---

## Recap

- The four questions of threat modeling: *what are we building, what can go wrong, what are we going to do, did we do a good job*. Every method serves one of these.
- The DFD — entities, processes, data stores, flows, trust boundaries — is the workhorse representation.
- **STRIDE** gives breadth: six categories of threat, walked against each element or interaction, with the per-element prompt table to keep you honest.
- **Attack trees** give depth: a single goal, decomposed via AND / OR down to leaf actions, optionally cost-annotated.
- Use both. STRIDE first (you do not yet know which goals are even important to the attacker); trees second (once you do).
- Vocabulary precision matters. Asset, threat, vulnerability, risk are four different words.

The next lecture takes a step back from the techniques to the *lens* — asset-driven, attacker-driven, and software-driven threat modeling are three different starting points, and Shostack argues most engineering teams should start software-driven and work outward.
