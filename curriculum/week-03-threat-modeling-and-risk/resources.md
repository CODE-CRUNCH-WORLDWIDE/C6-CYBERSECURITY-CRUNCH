# Week 3 — Resources

Every resource here is **free** or available via a major library / publisher. Most are primary sources — read them in preference to summaries.

## Primary text — read first

- **Adam Shostack, *Threat Modeling: Designing for Security*** (Wiley, 2014). The canonical text in modern threat modeling. Chapter 1 ("Dive In and Threat Model") and Chapter 3 ("STRIDE") are the durable parts. Chapter 8 ("Defensive Tactics and Technologies") is what most analysts skip and shouldn't. Available via most university and public libraries.
- **Adam Shostack, *Threats: What Every Engineer Should Learn from Star Wars*** (Wiley, 2023). The "field guide" companion to the 2014 textbook; less reference-heavy, more example-driven. Read after the 2014 book, not before.

## Foundational papers

- **Loren Kohnfelder and Praerit Garg, *The Threats to Our Products*** (Microsoft internal memorandum, April 1999). The paper that introduced STRIDE. Microsoft has reproduced it in security retrospectives; search for "Kohnfelder Garg STRIDE memo" to find a hosted copy.
- **Bruce Schneier, *Attack Trees*** (Dr. Dobb's Journal, December 1999):
  <https://www.schneier.com/academic/archives/1999/12/attack_trees.html>
  The article that put attack trees on the map. Twenty-six years old; still the cleanest explanation.

## OWASP resources

- **OWASP Threat Modeling Cheat Sheet** (the practitioner's quick reference):
  <https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html>
- **OWASP Threat Modeling Process** (the longer guide):
  <https://owasp.org/www-community/Threat_Modeling_Process>
- **OWASP Threat Modeling Manifesto** (a short, well-argued statement of values):
  <https://www.threatmodelingmanifesto.org/>
- **OWASP Threat Dragon** (open-source threat-modeling tool; DFDs, STRIDE prompts, exportable diagrams):
  <https://owasp.org/www-project-threat-dragon/>
- **OWASP pytm** (Python-based threat-modeling-as-code library — `pip install pytm`; useful for engineers who want diagrams generated from source):
  <https://github.com/izar/pytm>

## MITRE ATT&CK

- **MITRE ATT&CK Enterprise** (the matrix of adversary tactics, techniques, and procedures — the shared vocabulary used in modern threat models for *behaviour* findings):
  <https://attack.mitre.org/>
- **MITRE ATT&CK Navigator** (interactive matrix viewer; useful for highlighting techniques a given mitigation covers):
  <https://mitre-attack.github.io/attack-navigator/>
- **MITRE D3FEND** (the defensive counterpart to ATT&CK; maps techniques to defensive countermeasures):
  <https://d3fend.mitre.org/>
- **MITRE CAPEC** (Common Attack Pattern Enumeration and Classification — at a higher level than ATT&CK techniques; useful for attack-tree leaves):
  <https://capec.mitre.org/>

## PASTA and tabletop methodologies

- **Tony UcedaVélez and Marco M. Morana, *Risk Centric Threat Modeling: Process for Attack Simulation and Threat Analysis*** (Wiley, 2015). The PASTA reference. Heavy; read selectively unless you work in regulated finance, healthcare, or similar.
- **Carnegie Mellon SEI, *Threat Modeling: A Summary of Available Methods*** (white paper, 2018):
  <https://insights.sei.cmu.edu/library/threat-modeling-a-summary-of-available-methods/>
  Compares STRIDE, PASTA, LINDDUN, OCTAVE, Trike, VAST. Useful map of the territory.
- **LINDDUN** (privacy-focused threat modeling — Linkability, Identifiability, Non-repudiation, Detectability, Disclosure of information, Unawareness, Non-compliance):
  <https://linddun.org/>

## On risk and its limits

- **NIST SP 800-30 Rev. 1, *Guide for Conducting Risk Assessments*** (2012; the public-sector formalism for risk management):
  <https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final>
- **NIST SP 800-39, *Managing Information Security Risk*** (the organisation-level framing):
  <https://csrc.nist.gov/publications/detail/sp/800-39/final>
- **Douglas W. Hubbard and Richard Seiersen, *How to Measure Anything in Cybersecurity Risk*** (Wiley, 2016, second edition 2023). The case against ordinal risk matrices and for calibrated probabilistic estimates. Read it after you have done a few risk registers the ordinal way, so the critique lands.
- **Jack Freund and Jack Jones, *Measuring and Managing Information Risk: A FAIR Approach*** (Butterworth-Heinemann, 2014). The FAIR (Factor Analysis of Information Risk) framework — quantitative risk for those who need numbers.
- **Nassim Nicholas Taleb, *The Black Swan*** (Random House, 2007), Chapter 9 — *The Ludic Fallacy*. Why "probability times impact" misleads when the impact distribution has a long tail.

## On documentation

- **Google, *Engineering a Safer World: Threat Modeling at Google*** (talks and blog posts from Google's security engineering team — search for "threat modeling at Google" via the Google Security Engineering blog).
- **Microsoft SDL Threat Modeling** (the official Microsoft Security Development Lifecycle guidance):
  <https://learn.microsoft.com/en-us/security/sdl/threat-modeling>
- **Microsoft Threat Modeling Tool** (free Windows tool; produces STRIDE-based reports from a DFD):
  <https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool>

## Glossary

| Term | One-line definition |
|------|---------------------|
| **Asset** | Something of value to the defender — data, functionality, availability, reputation. |
| **Threat** | A potential adversary action with the *capacity* to harm an asset (independent of any specific flaw). |
| **Vulnerability** | A specific weakness in the system that a threat can exploit. |
| **Risk** | The combination of a vulnerability being exploited and the resulting impact, weighted by likelihood. |
| **Threat actor** | The party that may carry out a threat: insider, opportunist, organised criminal, nation-state. |
| **Attack surface** | The sum of points at which an unauthorised user can attempt to enter or extract data. |
| **Trust boundary** | A line on a DFD where data crosses between zones of differing trust assumptions. |
| **DFD** | Data-flow diagram — entities, processes, data stores, data flows, trust boundaries. |
| **STRIDE** | Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege. |
| **DREAD** | Damage, Reproducibility, Exploitability, Affected users, Discoverability — a deprecated scoring scheme. |
| **PASTA** | Process for Attack Simulation and Threat Analysis — a seven-stage business-risk-centric method. |
| **Attack tree** | A graph with a root attacker goal decomposed via AND / OR into sub-goals down to leaf actions. |
| **Residual risk** | The risk that remains after a chosen mitigation is applied. |
| **TTP** | Tactics, Techniques, and Procedures — the ATT&CK vocabulary for adversary behaviour. |
