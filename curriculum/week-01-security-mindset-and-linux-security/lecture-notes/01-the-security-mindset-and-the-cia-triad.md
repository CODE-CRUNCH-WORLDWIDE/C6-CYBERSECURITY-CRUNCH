# Lecture 1 — The Security Mindset and the CIA Triad

> **Outcome:** You can define confidentiality, integrity, and availability; explain three things the triad does *not* cover; distinguish asset from threat from vulnerability from risk; and produce a working STRIDE threat model in one sitting.

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

## 1. What "security" actually means

When an engineer says a system is "secure," they usually mean one of three things, often without specifying which:

1. **It preserves the properties we care about** (confidentiality, integrity, availability, and others) **even when someone is actively trying to violate them.**
2. **It enforces a stated policy** — the rules about who can do what to what data.
3. **It costs more to attack than the attacker is willing to spend.**

Notice that each definition is comparative and adversarial. "Secure" is not a checkbox. A locked front door is "secure" against a casual passer-by and "insecure" against a determined attacker with a $40 lock-pick kit. A system is secure *against a specified threat model* — never in the abstract.

This is the first habit Week 1 wants you to build: **never say "is this secure?" without also saying "against whom, for what asset, to what cost."** The answer to the first question is meaningless without the other two.

---

## 2. The CIA triad

The classical starter taxonomy of security properties is **CIA**:

- **Confidentiality** — information is disclosed only to authorized parties. *Encryption at rest and in transit, access controls, redaction, classification labels.*
- **Integrity** — information and systems are modified only by authorized parties, in authorized ways. *Cryptographic signatures, checksums, write-protected media, transactional databases.*
- **Availability** — systems and information are accessible to authorized parties when they need them. *Redundancy, rate limiting, capacity planning, DDoS protection, backups.*

These three pull against each other in normal engineering:

- The most confidential system is the one with no users. (Confidentiality at the expense of availability.)
- The highest-integrity database is the read-only one. (Integrity at the expense of availability.)
- A maximally-available system replicates everywhere — and now your data is on more disks, in more jurisdictions, with more attack surface. (Availability at the expense of confidentiality.)

Real systems trade these off deliberately. A backup is a confidentiality risk (now your secrets live in two places) traded for an availability gain (you can recover from a ransomware event). A signed Git commit gives you integrity but does nothing for confidentiality. You will be making CIA trade-offs in every design review you ever attend.

### What the triad does *not* cover

The triad is a starter framework, not the whole field. Things it leaves out:

| Property | Why it matters | The CIA reading is wrong |
|----------|----------------|--------------------------|
| **Non-repudiation** | "Did this party actually send this message?" Required for audit, forensics, contracts. | Confidentiality and integrity together do not establish identity. You need authentication plus a signature with a key tied to a real principal. |
| **Authenticity** | "Is this the real source?" | Integrity says "unchanged since signing." It does not say "the signer is who we think." |
| **Privacy** | A property of *people*, not just information. Includes the right to be forgotten, purpose-limitation, consent. | Confidentiality is necessary but not sufficient for privacy. Encrypted PII held without legal basis is still a violation. |
| **Safety** | Will this system kill, injure, or harm someone in the physical world? | The triad is silent on whether the *correct* response of a CIA-perfect system would still cause physical harm. |
| **Accountability** | Can you prove, after the fact, what happened and who is responsible? | Requires immutable logs, identity, and clock synchronization — not directly in CIA. |
| **Resilience / recoverability** | After a compromise, can you bring the system back? In what time? | Availability covers steady-state; recovery is a separate engineering discipline (Week 11). |

Real frameworks layer these on. **NIST SP 800-53** uses CIA plus a long control catalog. **The NIST Cybersecurity Framework 2.0** uses *six* functions (Govern, Identify, Protect, Detect, Respond, Recover). You will see CIA on every certification exam; you will see CSF in every real boardroom slide deck. Both are right; CIA is just the smaller subset.

---

## 3. Vocabulary discipline: asset, threat, vulnerability, risk

Imprecise vocabulary is the most common defect in junior security writing. The four words below are **not** synonyms. Use them precisely or you will mislead the people who read your reports.

- **Asset.** Something worth protecting. A customer record, a private key, the database's uptime, your company's reputation. *Assets are nouns.*
- **Threat.** A potential cause of harm to an asset. A ransomware crew, a disgruntled employee, a power outage, an earthquake. *Threats are actors or events.*
- **Vulnerability.** A weakness that a threat can exploit. An unpatched CVE, a misconfigured `sudoers`, a weak password, a missing input validation. *Vulnerabilities are properties of your system.*
- **Risk.** The combination of likelihood and impact: roughly, "how probable is it that this threat exploits this vulnerability against this asset, and how bad would it be?" *Risks are scenarios with magnitudes.*

A common formulation:

> **Risk = (Threat × Vulnerability × Impact on Asset) - Controls**

This formula is more useful as a sanity check than as arithmetic. Likelihood is rarely a real number. Impact is rarely a single dollar value. But the *shape* — risks reduce when you remove threats, remove vulnerabilities, reduce impact, or add controls — is correct, and it is the shape of every remediation conversation you will ever have.

### Example

A misconfigured S3 bucket holding production customer email addresses is **not** a risk by itself. The risk is:

> *A motivated attacker (threat) discovers the public bucket via certificate transparency log scraping (the vulnerability is public ACL plus discoverable URL); exfiltrates 4 million records (impact); we owe GDPR fines, customer notification, and reputational damage (consequence). Likelihood: high — public S3 buckets are scanned within minutes of being made public.*

That is a risk statement. It names the threat, the vulnerability, the asset, the impact, and the likelihood. A bullet that says "S3 bucket is misconfigured" is a vulnerability statement — useful, but not yet a risk. Hiring managers will notice the difference in your write-ups.

---

## 4. The four-question threat model (Shostack)

The shortest correct definition of threat modeling, from Adam Shostack, is four questions:

1. **What are we building / working on?**
2. **What can go wrong?**
3. **What are we going to do about it?**
4. **Did we do a good job?**

That is the entire framework. Everything else — STRIDE, attack trees, PASTA, DREAD — is a technique for answering one of those four questions more rigorously.

Each question deserves a paragraph in your write-up:

- **Question 1 — What are we building.** A diagram (a hand sketch is fine), a list of components, the trust boundaries (where data crosses from one principal to another), the data the system holds, the actors who interact with it. If your diagram has no trust boundaries, you have not finished it; every system has at least one.
- **Question 2 — What can go wrong.** Apply STRIDE (next section) to each component or data flow. Don't try to enumerate every imaginable attack; aim for the highest-likelihood and the highest-impact ones.
- **Question 3 — What are we going to do.** For each meaningful threat: mitigate (add a control), transfer (insurance, a contract), accept (and document the acceptance, with a name), or eliminate (remove the feature that introduces the threat).
- **Question 4 — Did we do a good job.** This is the question most teams skip. Self-review: did we miss a trust boundary? Did we name an asset whose threats we never analyzed? Will we know if a mitigation fails? In a year, will this document still describe the system?

A threat model that answers all four well is *better than* a threat model that uses every fancy framework but skips question 4. The C6 mini-project requires you to answer all four.

---

## 5. STRIDE

STRIDE is a mnemonic from Microsoft (1999, Loren Kohnfelder and Praerit Garg) that turns "what can go wrong" into a six-item checklist. Apply it to each component and each data flow.

| Letter | Threat | The property it violates |
|---|---|---|
| **S** | **Spoofing** of identity. "Who am I talking to?" | Authenticity |
| **T** | **Tampering** with data. "Has this been modified?" | Integrity |
| **R** | **Repudiation** of action. "Can I prove who did this?" | Non-repudiation |
| **I** | **Information disclosure**. "Who else saw this?" | Confidentiality |
| **D** | **Denial of service**. "Can I still use this?" | Availability |
| **E** | **Elevation of privilege**. "Did the attacker get more than they should?" | Authorization |

The discipline: for each component of your system, ask whether *each* letter applies. Most will. Most will have an obvious mitigation. The few that have non-obvious mitigations are where your design effort should focus.

### A worked example: an SSH server

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| **S** | Attacker logs in as the user, using a stolen password. | Disable password auth; require keys. Add hardware-key requirement for sensitive accounts. |
| **T** | Attacker modifies authorized_keys via a separate vulnerability. | File integrity monitoring (`auditd`, AIDE). Read-only `/root` via overlay. |
| **R** | Operator disputes that they ran `rm -rf /` on the box. | Centralized session logging; commands shipped to a SIEM beyond operator reach. |
| **I** | SSH session traffic intercepted on an untrusted network. | Modern key exchange (already enabled by default); host-key fingerprint verification on first connect. |
| **D** | Attacker floods port 22 to lock out operators. | Rate limit with `fail2ban` / `crowdsec`; reachable only via a bastion or VPN. |
| **E** | Logged-in user pivots to root via a kernel CVE or misconfigured `sudo`. | Patch promptly; least-privilege sudoers; AppArmor / SELinux. |

That table is a threat model. It is small. It is also *real* — every line corresponds to a configuration change a defender can make. A reader of your write-up can act on it.

---

## 6. Attack trees: the complementary tool

STRIDE asks "what can go wrong, by category." **Attack trees** (Schneier, 1999) ask "how would a specific attacker reach a specific goal."

You start with a goal at the root — say, "exfiltrate the production database" — and recursively break it into the ways to achieve it (`OR` nodes) and the steps required for each (`AND` nodes). Annotate leaves with cost, skill, detectability, time. The tree exposes the path of least resistance, which is almost always the path an attacker will take.

```
Goal: exfiltrate prod database
├── OR  Compromise a developer with shell access
│       ├── AND Phish credentials       (cost: low,  detection: medium)
│       ├── AND Bypass MFA              (cost: high, detection: medium)
│       └── AND Pivot to prod from dev  (cost: low,  detection: low — !)
├── OR  Find a public-facing SQLi in the app
│       └── AND Discover the endpoint    (cost: low,  detection: high — WAF)
└── OR  Subvert a backup pipeline
        ├── AND Compromise the CI/CD vendor (cost: very high)
        └── AND Read backup at rest         (cost: depends on encryption)
```

The lowest-cost-lowest-detection path here is "pivot to prod from dev" — and that is exactly the kind of finding that, when listed in your threat model, drives engineering work (network segmentation, separate credentials, jump hosts). STRIDE would have flagged "elevation of privilege" but the attack tree gives you the *story*.

Use STRIDE for completeness. Use attack trees for prioritization.

---

## 7. The security mindset

Bruce Schneier coined the phrase "the security mindset" in a 2008 essay. The shortest summary: **a security person looks at a system and asks how it can fail, not how it works.** Normal engineering asks "does this run?" Security asks "what does an adversary do when it runs?"

A few habits that constitute the mindset:

- **Assume the input is hostile.** Every byte that crosses a trust boundary may have been written by an attacker. Validate. Canonicalize. Reject early.
- **Distinguish symptom from cause.** "The login page is slow" might be a capacity issue or a credential-stuffing attack in progress. The defender investigates both. A novice fixes the symptom.
- **Defense in depth.** Assume each layer will fail. Plan for the failure mode of the layer below.
- **Fail closed for confidentiality and integrity; fail open for availability** — and *know which you chose, for which subsystem.* The wrong choice is often the bug.
- **Beware of the obvious threat model.** Real attackers rarely use the technique you anticipated. They use the one you forgot to look at.
- **Read the post-mortem.** Every published post-mortem is a free lesson. Read at least one a week.

The mindset is **not** paranoia. Paranoid engineers ship nothing. The mindset is *the discipline of asking adversarial questions* alongside the normal engineering questions. You still ship; you ship a system you can defend.

---

## 8. The authorization frame — the non-negotiable

Almost every technique in C6 — beginning Week 2, when we start `nmap`-ing — can be turned against the wrong target by a careless or unethical practitioner. This is the entire reason the C6 brand is what it is, and why every offensive-touching page in this curriculum opens with the AUTHORIZED USE ONLY banner.

The rules are not negotiable:

1. **You may exercise these techniques only on systems you own**, on legal training platforms (OverTheWire, HackTheBox, TryHackMe, picoCTF, VulnHub, pwn.college), or with **explicit written permission** from the system owner naming the scope and the dates.
2. **A bug-bounty scope is permission**, but only inside the named scope and within the program rules. The scope file is short. Read it. Then read it again.
3. **A friend saying "yeah, go ahead, test it" verbally is not permission.** Get it in writing. From the actual owner, not just the operator.
4. **"They had it coming" is not a defense.** Neither is "I was just curious." Neither is "the bug is real and I told them after." Many jurisdictions criminalize unauthorized testing regardless of intent or outcome.
5. **If you find yourself thinking "no one will know" — stop.** That is the thought process whose absence is the field's most important professional trait. Practitioners who lose authorization discipline lose their careers.

This is not bureaucratic theater. The cybersecurity industry's credibility — and your future career — rests on practitioners taking authorization seriously. C6 will repeat this in every relevant lecture, every relevant exercise, every relevant challenge. The redundancy is the point.

---

## 9. Self-check

Without re-reading:

1. State the CIA triad. Name three properties it does not cover.
2. Define *threat* and *vulnerability* in one sentence each, and give an example of each from a system you use.
3. Recite the four questions of the Shostack framework.
4. What does each letter of STRIDE stand for, and which CIA-or-related property does each violate?
5. Give one example each of: a control that improves confidentiality at the cost of availability; a control that improves availability at the cost of confidentiality.
6. State, in your own words, the authorization rule that governs every offensive technique in C6.

---

## Further reading

- **Bruce Schneier, "The Security Mindset"** (2008):
  <https://www.schneier.com/blog/archives/2008/03/the_security_mi_1.html>
- **Adam Shostack, threat modeling resources** (the four-question framing):
  <https://shostack.org/resources/threat-modeling>
- **NIST SP 800-30 Rev. 1 — Guide for Conducting Risk Assessments**:
  <https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final>
- **OWASP Threat Modeling Cheat Sheet**:
  <https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html>

Next: [Lecture 2 — The Linux Security Model](./02-the-linux-security-model.md).
