# Lecture 1 — Rules of Engagement and Scope

> *Before you point a packet at a host, you need a document that says you are allowed to. The document has a name — the Rules of Engagement, the RoE — and a small, settled set of clauses, and a signature from someone with the authority to grant the access. Engineers fresh out of a CTF often treat the RoE as administrative friction; experienced practitioners treat it as the only thing standing between a paid engagement and a federal indictment. This lecture is about why that posture is correct, what the document looks like, and how to write one for the mini-project at the end of the week.*

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  This lecture is about the document that authorises a scan. Until   │
│  you have that document, the only host you scan is one you own.     │
│  No exceptions. Reading the statute is not authorisation. A         │
│  professor's lab assignment is not authorisation unless the lab     │
│  is on machines the school owns and the assignment names them.      │
│  An email saying "feel free to look" is not authorisation. The      │
│  RoE format below is the authorisation.                             │
└─────────────────────────────────────────────────────────────────────┘
```

This lecture covers:

- The **legal frame**: CFAA, CMA, and the EU directive, what they prohibit, and what good-faith research is and is not protected from.
- The **authorisation chain**: who can authorise a scan, what authority they need, how you verify it, and what a defective chain looks like.
- The **Rules of Engagement (RoE)** document: the standard sections, how to write each, and the public templates we will start from.
- The **scope** of an engagement: in-scope and out-of-scope assets, allowed and prohibited testing actions, time windows, and emergency-stop procedure.
- The **bug bounty model** versus the **consultancy engagement** versus the **internal red team**: three different operating models with three different authorisation shapes, and what changes about your RoE in each.
- The **practical workflow**: what you do when you are handed a CIDR range and told "go." The first email, the kickoff call, the document review, the verification of the verifier, the dry-run on a controlled subset, the production scan.

---

## 1. The legal frame: three statutes that cover most of where you work

You are very likely operating in one of three legal frames: the United States under the **Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030)**, the United Kingdom under the **Computer Misuse Act 1990 (CMA)**, or the European Union under the various national transpositions of **Directive 2013/40/EU on attacks against information systems**. The statutes share a common core: unauthorised access to a computer system is a crime, and the threshold for "unauthorised" is lower than newcomers expect.

This section is not legal advice. If you face a real legal question, hire a lawyer. The purpose of this section is to give you enough background to *recognise* when you are about to cross a line, so you can stop and consult before, not after.

### 1.1 The United States — Computer Fraud and Abuse Act

The CFAA is the federal statute at **18 U.S.C. § 1030**. Read the actual statute text once (Cornell LII has a clean version); the operative subsections for security practitioners are:

- **§ 1030(a)(2)** — "intentionally accesses a computer without authorization or exceeds authorized access, and thereby obtains ... information from any protected computer." A "protected computer" includes essentially every computer used in or affecting interstate commerce, which means essentially every computer connected to the internet. This is the subsection cited in most scanning prosecutions.
- **§ 1030(a)(5)(A)** — "knowingly causes the transmission of a program, information, code, or command, and as a result of such conduct, intentionally causes damage without authorization to a protected computer." A scanner that crashes a service is a candidate for this subsection.
- **§ 1030(a)(5)(B)** — "intentionally accesses a protected computer without authorization, and as a result of such conduct, recklessly causes damage." The recklessness threshold matters; running an unrated scan against a known-fragile target is a candidate.

A **port scan** alone, in 2026, is almost never charged on its own — the case law is murky, the prosecution unlikely, and the DoJ's published policy explicitly disfavours such charges. But "almost never charged on its own" is not "legal," and the moment the scan crosses any other threshold (a credential is submitted, a captcha is bypassed, a vulnerability is exercised) the calculus changes.

The **Supreme Court's *Van Buren v. United States* (2021)** narrowed the meaning of "exceeds authorized access": you "exceed authorized access" when you access files or folders the system permits you to enter but for an *unauthorised purpose*, not when you violate a use policy in a way the system permits. The opinion narrowed CFAA's reach but did not eliminate it; the case law continues to develop.

The **DoJ's May 2022 charging-policy update** declared that good-faith security research should not be prosecuted under the CFAA. The DoJ defined "good-faith security research" with specific elements:

1. Carried out *to promote the security or safety of the class of devices, machines, or online services to which the accessed computer belongs, or those who use such devices*.
2. *Solely* for that purpose.
3. *Avoiding* any use of the information obtained except to promote the security or safety of the class of devices.

This is **prosecutorial policy, not statutory immunity**. A US Attorney's office is *directed* not to charge good-faith research; you can still be sued civilly, you can still be charged by state prosecutors, you can still be charged if the DoJ decides your conduct falls outside their definition. The policy is a strong signal but not a guarantee, and it does not bind a private plaintiff in civil court.

### 1.2 The United Kingdom — Computer Misuse Act 1990

The CMA is the UK statute, with the most-cited operative sections being:

- **§ 1 — Unauthorised access to computer material.** The base offence. Up to two years in prison.
- **§ 2 — Unauthorised access with intent to commit or facilitate commission of further offences.** Up to five years.
- **§ 3 — Unauthorised acts with intent to impair operation of computer, etc.** Up to ten years. Covers DoS, malware deployment, and *intentionally* disruptive scans.
- **§ 3ZA — Unauthorised acts causing or creating risk of serious damage.** Up to life imprisonment for the most-serious cases (catastrophic harm to critical national infrastructure). Rare but real.

The CMA does **not** include a statutory defence for security researchers acting in good faith. The **CyberUp campaign** has lobbied for such a defence since 2020; the Home Office is consulting (2023-2024) but had not enacted one as of the most-recent public update before this curriculum was written. UK practitioners must therefore operate with explicit written authorisation; "good faith" alone is not a legal shield in the UK.

### 1.3 The European Union — Directive 2013/40/EU and the NIS2 frame

**Directive 2013/40/EU** is the EU's framework directive on attacks against information systems. Each member state transposes it into national criminal law (in Germany, the StGB §§ 202a-c; in France, the relevant articles of the Code pénal; in Italy, Codice penale art. 615-ter; and so on). The directive criminalises:

- **Article 3** — Illegal access to information systems.
- **Article 4** — Illegal system interference.
- **Article 5** — Illegal data interference.
- **Article 6** — Illegal interception.
- **Article 7** — Tools used for committing offences. This article — the "hacker-tools" provision — is the one practitioners watch most carefully. National transpositions vary in how broadly they criminalise possession or distribution of dual-use tools.

**Germany's StGB § 202c** ("Hackerparagraf") is the most-cited example: it criminalises the production, acquisition, or distribution of computer programs *primarily designed* to commit certain offences. In practice the courts have read "primarily designed" narrowly enough that `nmap` itself is not banned, but the chilling effect on practitioner culture has been significant.

**NIS2 (Directive (EU) 2022/2555)** introduces, in Article 12, a *coordinated vulnerability disclosure* framework. Each member state must designate a coordinator (typically the national CSIRT) and provide a process for researchers to disclose vulnerabilities to the coordinator without civil or criminal liability under the disclosure act *itself*. NIS2 does not retroactively legalise unauthorised access; it provides a safe channel for what to do *after* you have found something.

### 1.4 The common rule across all three frames

Different statute, same rule: **you must have authorisation before you scan**. The authorisation must come from someone with the authority to grant it. The authorisation must be in writing. The authorisation must specify what you are allowed to do, against what targets, in what time window. If any of those pieces is missing, the legal protection — such as it is — is missing.

The remainder of this lecture is about how to obtain and document that authorisation properly.

---

## 2. The authorisation chain: who can say "yes"

An authorisation chain has three links: the **owner of the asset**, the **person granting access**, and the **engineer running the scan**. Each link must be verifiable.

### 2.1 The asset owner

The **asset owner** is the legal person — the company, the government agency, the individual — who owns or operates the system you intend to scan. The owner is the only party who can authorise testing of that system. Authorisation flows from the owner; everyone else is a delegate.

You verify ownership by:

- **For corporate targets**: a domain WHOIS lookup, the legal entity's registered office, the contract signatory's email address matching the company's domain, the contract signatory being authorised to bind the company (typically a director, an officer, or a person with explicit delegated authority).
- **For cloud-hosted targets**: the IP is in the customer's allocated VPC range, *not* the cloud provider's shared infrastructure. AWS, GCP, and Azure each have separate pen-test notification policies; some no longer require notification, others still do; check each cloud's current guidance.
- **For SaaS targets**: the SaaS provider — not the SaaS customer — is the owner of the multi-tenant infrastructure. A customer cannot authorise you to scan Salesforce's infrastructure because Salesforce is the owner. A bug bounty scope from the SaaS *provider* is the only valid authorisation for that infrastructure.

### 2.2 The person granting access

The person who *signs* the RoE is not always the asset owner; usually they are the asset owner's authorised representative. For a corporate engagement, this is typically:

- The **CISO** or **head of security**.
- The **head of IT** for smaller organisations.
- A **product owner** for a specific product, if the engagement is product-scoped.
- A **director** or **C-level officer** with explicit signing authority.

For a bug bounty program, the *program* itself is the authorisation: the published scope, the published terms, the platform's standard disclosure terms, the program's safe-harbour clause. The platform (HackerOne, Bugcrowd, Intigriti) acts as the intermediary, but the underlying authority is the asset owner's, expressed through the program.

For a personal lab on your own hardware, you are both the owner and the signer. You should still write a one-line "I, X, on date Y, authorise myself to test the following hosts" note — not for legal effect, but for the discipline. If you cannot write that note without feeling silly, you have built the right reflex.

### 2.3 The engineer

You. The engineer running the scan needs to:

- **Read** the RoE in full.
- **Verify** that the signer has the authority they claim.
- **Ask** for clarification on any ambiguity *before* the scan, not during.
- **Operate** strictly inside the documented scope.
- **Stop** the moment you suspect you have crossed the scope, and report what you observed.

A defective authorisation chain — a signer without the authority to sign, a scope that contradicts the owner's intent, an unwritten "verbal yes" — does not give you cover. The first question a prosecutor or a civil plaintiff asks is "what authorised this scan"; the only answer that survives is "this signed document, signed by this authorised person."

---

## 3. The Rules of Engagement document: the standard sections

The RoE is the contract between the engineer and the asset owner. The document is not magic; it is a structured statement of who, what, when, where, and how, signed by both sides. The standard sections, drawn from PTES, NIST SP 800-115, and the public bug bounty platform templates, follow.

### 3.1 Parties and authority

- The **engineer**, by name and contact information.
- The **asset owner**, by legal name (the legal entity, not the brand).
- The **signing authority**'s name, title, and authority basis (officer of the company, with the authority to bind the company; or a delegate, with the underlying authorisation attached).
- The **date** of signing.
- The **effective date** of the engagement (when scanning may begin).
- The **expiration date** of the engagement (when authorisation lapses).

The expiration date matters: an RoE without a stated end-date is sloppy and arguably overbroad. Two to four weeks is a typical engagement window.

### 3.2 Scope — in-scope assets

The list of assets you are authorised to scan. Each entry is unambiguous:

- **IPs and CIDR ranges**: `203.0.113.0/24`, `198.51.100.42`. Not "the production network"; the actual ranges.
- **Hostnames and domains**: `*.example.com` (with explicit wildcard semantics — does it include subdomains owned by third parties? state explicitly), `api.example.com`, etc.
- **Cloud account IDs**: the AWS account, the GCP project, the Azure subscription.
- **Specific applications**: the web app at `https://shop.example.com`, the mobile app published as `com.example.shop` v3.14.

Use the format the owner uses internally; do not invent your own asset names. A scope that does not match the owner's CMDB is a scope you cannot enforce later.

### 3.3 Scope — out-of-scope assets

Equally important. Common out-of-scope items:

- Production financial systems, billing infrastructure, payment processors.
- Third-party SaaS the owner does not own (Salesforce, Workday, etc.).
- Cloud-provider shared infrastructure (the metadata service is sometimes excluded; sometimes explicitly in-scope; the RoE must specify).
- Mail servers, especially shared third-party mail providers.
- Customer data stores in production.

A common pattern: "Everything in the IP ranges listed in § 3.2, except: the hosts at `203.0.113.10-203.0.113.20`, which are the production database; the host at `203.0.113.99`, which is the SIEM (testing against the SIEM is out of scope to avoid alert-storm)."

### 3.4 Allowed testing actions

The actions you are permitted to take. For a Week 7-style recon engagement, this section is usually:

- Passive reconnaissance (DNS, WHOIS, certificate-transparency searches).
- Port scanning (TCP SYN, TCP connect, UDP).
- Service enumeration (banner grabbing, NSE `safe` and `default` scripts).
- OS fingerprinting.
- Version detection.

The list grows in later weeks: authentication-flow testing, web-application testing with automated tools, manual exploitation, lateral movement, etc. Each line of allowed action is *explicit*; the absence of authorisation for an action means the action is not authorised.

### 3.5 Prohibited testing actions

The actions you are explicitly forbidden from taking. Common entries:

- **Denial-of-service**: explicit prohibition on any test that aims to or is reasonably likely to cause service unavailability.
- **Destructive testing**: no `DROP TABLE`, no malware deployment, no data deletion.
- **Social engineering** unless explicitly named in allowed actions.
- **Physical intrusion** unless explicitly named.
- **Testing during high-impact business hours** (often defined in § 3.6).
- **Pivoting to systems out of scope** even if a pivot is technically possible.

The discipline here is *belt-and-braces*: even where prohibition seems obvious, write it down. "I assumed it was obvious" is not a defence.

### 3.6 Time windows

When you are permitted to scan. Several typical patterns:

- **24/7 throughout the engagement window**. Common for resilience-tested infrastructure.
- **Business hours only**, defined as e.g. 09:00-17:00 in a specified time zone, weekdays excluding national holidays.
- **Off-hours only**, e.g. 22:00-06:00 in a specified time zone. Common for production e-commerce.
- **Specific scheduled windows** announced in advance to the SOC, e.g. "Tuesday 2026-05-19, 14:00-18:00 UTC."

Specifying the time zone matters. "9 to 5" without a time zone is unenforceable.

### 3.7 Rate limits and resource caps

You commit to operating below a stated traffic ceiling. Typical entries:

- **Maximum aggregate scan rate**, e.g. "1000 packets per second per source IP, across all sources combined."
- **Per-host scan rate**, e.g. "no more than 100 requests per second to any single host."
- **Connection caps**, e.g. "no more than 50 concurrent TCP connections to any single host."
- **Bandwidth caps**, e.g. "the test traffic shall not exceed 10 Mbps aggregate."

The RoE often references the scanner flags you will use to enforce the cap: `nmap --max-rate 1000`, `masscan --rate 1000`. The reference is informative; the *commitment* is the cap.

### 3.8 Source IPs

The IP addresses your traffic will originate from. The owner whitelists these in their IDS / WAF so that your traffic is recognisable and not mistaken for an attacker.

You commit to scanning *only* from these source IPs. If you need to scan from a different source (a new VPS, a relocated workstation), you notify the owner first and amend the source-IP list.

### 3.9 Contact points and emergency stop

- **Engineer-side contact**: you, plus a backup engineer if the engagement is team-based.
- **Owner-side contact**: typically the security operations centre (SOC) duty engineer on the owner's side, plus the named signing authority.
- **Emergency-stop procedure**: a documented mechanism (phone, signal, encrypted email) for the owner to tell you "stop immediately." When that mechanism is exercised, the engineer commits to:
  - Stop all active scans within a stated time window (typically 15 minutes).
  - Acknowledge the stop request in writing within a stated time window (typically 1 hour).
  - Investigate what triggered the stop and report the cause.
  - Resume only with new written authorisation.

This section is not optional. Real engagements have been stopped mid-scan when a customer system began misbehaving for reasons unrelated to the test; the stop procedure exists so the engineer is not the obstacle to fast incident resolution.

### 3.10 Data handling

The scan output contains information the owner considers sensitive. You commit to:

- **Storing** scan output on encrypted media.
- **Transmitting** scan output only over encrypted channels.
- **Retaining** scan output only for the stated period (typically 90 days after engagement close).
- **Destroying** scan output after the retention period.
- **Not disclosing** any specific finding to third parties without owner consent.

If the owner has stricter requirements — HIPAA, PCI-DSS, GDPR-derived obligations — those requirements are stapled to the RoE as an annex.

### 3.11 Deliverables and timeline

What you will produce, and when:

- **Status updates** during the engagement, typically daily or every-other-day.
- **A preliminary findings document** at the end of the active testing phase.
- **A final report** at a stated date after the testing window ends.
- **A debrief meeting** to walk the owner through the findings.

For a bug bounty engagement, the deliverable is a per-finding report submitted through the platform; the RoE-equivalent is the program's published terms.

### 3.12 Safe-harbour clause

The clause that affirms, in writing, that the owner will not pursue legal action against the engineer for conduct that falls within the RoE. Modern templates use the **disclose.io** standard language:

> *Authorization. The Asset Owner authorizes Researcher to perform the actions described in § 3.4 against the in-scope assets listed in § 3.2 during the time windows in § 3.6 and at rates not exceeding § 3.7, subject to the prohibitions in § 3.5. The Asset Owner agrees not to pursue civil or criminal action against Researcher for acts undertaken in good faith and within the scope of this authorization, even where such acts would otherwise violate the Computer Fraud and Abuse Act, the Computer Misuse Act 1990, the Digital Millennium Copyright Act, or analogous foreign law.*

The wording above is illustrative; use the current disclose.io standard text when drafting. The clause does not bind third parties; if you accidentally scan a third party's host, you are not protected by the owner's safe-harbour.

### 3.13 Signatures

Both parties sign. Two signatures: the engineer (acknowledging the scope and the commitments) and the owner's authorised representative (granting the authorisation). Both signatures are dated. The fully-signed document is kept by both parties for the engagement's retention period.

---

## 4. The three operating models and what changes about the RoE in each

The standard RoE above is the shape for a *consultancy engagement*. Two adjacent operating models change the document slightly.

### 4.1 The consultancy engagement

You are an external party hired to test an owner's systems. The RoE is the model above. The document is bespoke per engagement, negotiated, signed by both sides, and lives in the consultancy's records as well as the owner's. The Statement of Work (SoW), the Master Services Agreement (MSA), and the RoE are typically three separate documents; the SoW and MSA cover the commercial terms, the RoE covers the technical scope.

### 4.2 The bug bounty engagement

You are an external researcher participating in a published program. The "RoE" is the **program scope and terms** published on HackerOne, Bugcrowd, Intigriti, or the program's self-hosted page. There is no per-researcher document; the program terms are the contract, and your participation is your agreement to them.

Read the program scope **in full** before the first packet. Pay particular attention to:

- The **in-scope** asset list (often with wildcard semantics that need careful reading).
- The **out-of-scope** asset list.
- The **prohibited testing actions** (DoS, social engineering, physical, automated scanners — programs vary widely on this last one).
- The **safe-harbour** clause (most programs now include disclose.io-compatible language).
- The **disclosure** policy (private until fixed; coordinated public disclosure; or never-public).
- The **payment** structure (bounty ranges, swag, hall-of-fame, or no monetary reward).

The RoE for bug bounty is **read-only**: you take it or you do not participate. If the scope is unclear, ask the program owner through the platform's question mechanism *before* testing.

### 4.3 The internal red team

You are an employee of the asset owner, conducting an authorised offensive engagement against the owner's own systems. The RoE is internal, often shorter, and usually maintained by the red team and the blue team jointly. The document still includes scope, time, rate, contacts, and emergency-stop; the safe-harbour clause is usually replaced by an internal acknowledgement that the testing is authorised by the CISO and is part of the security program.

Internal red-team RoEs are more flexible than external ones — the team has standing authorisation to test most of the estate — but the *discipline* of the document is identical. Internal red teams that skip the RoE habit are the ones that eventually scan a system they should not have, and the conversation with the COO afterward is unpleasant.

---

## 5. The practical workflow: from "go scan these hosts" to first packet

A concrete sequence for a first-week consultancy engagement.

### 5.1 The kickoff (Day 1)

You are introduced to the owner's contact. The contact may be a CISO, a head of IT, or a product manager. Establish:

- **Who you are scanning**: get the legal entity name, the CMDB-format asset list, the IP ranges.
- **Why**: regulatory requirement, board-level request, post-incident review, recurring program.
- **What** is in and out of scope.
- **When** you can scan.
- **How fast**: the rate cap, the bandwidth cap.
- **Who** to contact for emergency stop, and how.

You leave the kickoff with notes, not a signed document. The signed document is iteration 3 or 4 of the kickoff notes.

### 5.2 The draft RoE (Day 2-3)

You draft the RoE using a template (PTES pre-engagement, NIST SP 800-115 Appendix A, your firm's standard template, or the disclose.io examples). The first draft is a strawman the owner edits; expect three or four rounds of edits before signature.

Common adjustments in the edit cycle:

- The IP range is wider than you initially understood — add the missing ranges.
- A specific host is added to out-of-scope after the owner consults their SREs ("the legacy mail server, please do not poke that").
- The rate limit is lowered after the network team weighs in.
- The time window narrows after the e-commerce team weighs in.
- An additional internal contact is added.

### 5.3 The signature (Day 3-5)

Both parties sign. The signature is recorded with a verifiable timestamp (a counter-signed PDF with a signing-service like DocuSign, or PGP-signed e-mail, or physical signatures scanned). The signed RoE is stored on both sides for the retention period.

### 5.4 The pre-scan dry run (Day 5-6)

Before the production scan, you run a *controlled dry run* against a stated subset of the scope. The dry run validates:

- Your source IPs are reachable from your scanning host.
- The owner's IDS / WAF is whitelisting your source IPs.
- Your scanner is configured with the agreed rate cap.
- The owner's SOC sees the dry-run traffic and recognises it as authorised.
- The agreed output format is being generated.

If the dry run reveals a problem — your traffic is getting blocked, the rate cap is more restrictive than your scanner respects, the SOC is alerting — you stop and resolve before continuing.

### 5.5 The production scan (Day 6-N)

The full scan, executed inside the agreed time windows, at the agreed rate, against the agreed scope. Status updates to the owner contact at the agreed cadence. Findings logged.

### 5.6 The wrap (Day N+1 through N+5)

Preliminary findings to the owner within the agreed window. Final report at the agreed date. Debrief meeting. Scan output retained per the retention policy; destroyed at the retention horizon.

The entire workflow is two to four weeks for a small engagement; longer for larger or recurring engagements. The proportion of *document* time to *scan* time is roughly 60/40 for a first engagement, dropping to 30/70 for recurring engagements where the RoE is a renewal of a prior document.

---

## 6. Common mistakes and how to avoid them

### 6.1 "We have a verbal authorisation."

Unsafe. Verbal authorisations are not enforceable, are not memorable to a future prosecutor or plaintiff, and are not testable in dispute. Until it is written and signed, the only host you scan is your own.

### 6.2 "The CISO said it was fine."

Possibly safe. Depends on whether the CISO has the authority to bind the legal entity that owns the asset (usually yes for the CISO's own employer; often no for subsidiaries, joint ventures, partner organisations). Verify the authority and document it in the RoE's authority-basis line.

### 6.3 "The bug bounty scope mentions 'all our infrastructure.'"

Read it again. "All our infrastructure" almost always has carve-outs in the next paragraph, and the carve-outs are the rules. If the scope is genuinely "all infrastructure with no exclusions," that is unusual enough to confirm with the program owner before scanning.

### 6.4 "The IP range was given to me; I assume it is theirs."

Verify. A misconfigured customer asset list once led to a major consultancy scanning a *competitor's* infrastructure for an entire afternoon before someone noticed; the firm settled the resulting civil suit out of court. WHOIS each range; cross-check against the owner's CMDB; verify with the owner's signing authority before the first packet.

### 6.5 "The previous RoE for this client is still valid."

Probably not. Check the effective and expiration dates on the prior document. Many RoEs are explicitly engagement-bound; the expiration is the end of the engagement. A fresh engagement needs a fresh RoE, even if 95% of the content is identical to the prior one.

### 6.6 "I am only doing a quick TCP-SYN; that is not really testing."

There is no statutory carve-out for "quick" scanning. The threshold for *unauthorized access* under all three statutes is the *access*, not the depth of it. A single TCP-SYN to a closed port has been treated as access in some prosecutions; the prudent rule is to treat every packet as testing, and to document accordingly.

### 6.7 "The owner has stopped responding to emails; I will keep going."

Stop. An unresponsive owner is a signal something has changed. If the engagement is mid-flight and you cannot reach the owner, pause active scanning at the next agreed checkpoint, document the gap, and wait for re-establishment before resuming. The cost of pausing is small; the cost of continuing without an authority you can reach is, by definition, unbounded.

---

## 7. A worked example: drafting the mini-project RoE in advance

The Week 7 mini-project asks you to scan a host you own. The owner is you. The signer is you. The document is small but the discipline matters.

Draft now, in your notes:

```text
# Rules of Engagement — Week 7 Mini-Project

## Parties
- Engineer: <your name>, <your email>.
- Asset Owner: <your name>, the same individual.
- Signing Authority: <your name>, by virtue of legal ownership of the
  asset(s) listed below.
- Effective date: <date you start the mini-project>.
- Expiration date: <one week later>.

## In-scope assets
- Host: 127.0.0.1 (loopback on the engineer's own laptop).
- Host: 10.0.2.15 (Metasploitable 2 VM on the engineer's own laptop,
  bridged only to the host-only network "vboxnet0").
- The host-only network 10.0.2.0/24, which contains only VMs owned
  by the engineer.

## Out-of-scope assets
- Every IP not listed above.
- The engineer's home LAN (192.168.1.0/24).
- The engineer's ISP-provided gateway (192.168.1.1).
- Every host on the public internet.

## Allowed testing actions
- TCP SYN scans (`nmap -sS`).
- TCP connect scans (`nmap -sT`).
- UDP scans (`nmap -sU`) limited to the top-100 UDP ports.
- Service version detection (`-sV`).
- OS fingerprinting (`-O`).
- NSE default and safe script categories (`-sC`, `--script safe`).
- NSE `vuln` script category against the Metasploitable VM only.

## Prohibited testing actions
- Any test against any host not listed in § In-scope.
- Any actual exploitation; NSE `exploit` and `intrusive` categories
  are forbidden by this RoE.
- Any test that, by design or by accident, generates traffic to a
  third party (cloud metadata service, DNS recursion, NTP, etc.).

## Time windows
- 24 hours, but only when the engineer is at the keyboard. No
  background scans.
- All testing must be complete before the expiration date.

## Rate limits
- `nmap --max-rate 1000` (one thousand packets per second
  aggregate, across all sources).
- `masscan --rate 1000` if masscan is used.

## Source IPs
- 127.0.0.1 (for loopback work).
- 10.0.2.1 (the host's vboxnet0 gateway IP, for scans of the VM).

## Emergency stop
- The engineer may stop any scan at any time.
- If the engineer's laptop battery drops below 20%, scans pause
  until the laptop is on mains power.
- If a scan causes the host system to become unresponsive, the
  engineer powers down the affected VM and reboots before resuming.

## Data handling
- Scan output stored under `~/c6-week-07/scans/`, on the engineer's
  encrypted laptop disk.
- Retention: indefinite (this is a study artifact, kept for the
  portfolio).
- No transmission to third parties.

## Deliverables
- The Week 7 mini-project README and supporting artifacts.

## Signatures
- Engineer: <signed and dated>
- Owner: <signed and dated>
```

The document is short because the engagement is small; the *structure* is identical to a consultancy RoE. When you write your first paid engagement's RoE next year, you will start from this skeleton and expand.

---

## 8. Closing

Two things to take from this lecture, in order of importance:

1. **You do not run a scan against any system without written authorisation.** Not against your university's network, not against your former employer's network, not against a friend's website. The cost of asking and being told no is small. The cost of running the scan and being prosecuted, sued, or expelled is unbounded.

2. **Authorisation is a document, not a feeling.** The document has a name (Rules of Engagement). The document has a structure (Lecture 1 § 3). The document is signed by someone with the authority to sign it. Until you have the document, the only host you scan is one you own.

The rest of the week — the host discovery, the service detection, the NSE scripts, the rate-limit reasoning, the report writing — is technique. The technique is real, the technique matters, and the technique is genuinely interesting. But the technique presupposes the authorisation. Without the authorisation, the technique is criminal regardless of how cleanly executed.

Read Lecture 2 once you can write the RoE for the mini-project in your sleep.

---

## References

- 18 U.S.C. § 1030 — Computer Fraud and Abuse Act: <https://www.law.cornell.edu/uscode/text/18/1030>.
- DoJ Justice Manual 9-48.000: <https://www.justice.gov/jm/jm-9-48000-computer-fraud>.
- DoJ press release, May 19, 2022 (CFAA charging policy update): <https://www.justice.gov/opa/pr/department-justice-announces-new-policy-charging-cases-under-computer-fraud-and-abuse-act>.
- *Van Buren v. United States*, 593 U.S. ___ (2021): <https://www.supremecourt.gov/opinions/20pdf/19-783_k53l.pdf>.
- Computer Misuse Act 1990: <https://www.legislation.gov.uk/ukpga/1990/18/contents>.
- Directive 2013/40/EU: <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32013L0040>.
- Directive (EU) 2022/2555 (NIS2), Article 12: <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555>.
- PTES Pre-Engagement Interactions: <http://www.pentest-standard.org/index.php/Pre-engagement>.
- NIST SP 800-115: <https://csrc.nist.gov/publications/detail/sp/800-115/final>.
- disclose.io: <https://disclose.io/>.
- HackerOne Vulnerability Disclosure Guidelines: <https://www.hackerone.com/disclosure-guidelines>.
- Bugcrowd Standard Disclosure Terms: <https://www.bugcrowd.com/resources/glossary/standard-disclosure-terms/>.
