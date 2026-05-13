# Week 3 — Quiz

Ten questions. Lectures closed. Aim for 9/10. The questions are written to be unambiguous; if a question seems to allow more than one answer, re-read the lecture.

---

**Q1.** Which sentence uses the words *threat*, *vulnerability*, *risk*, and *asset* correctly?

- A) "The risk in our system is that the login form has a vulnerability; the threat is the user database, which is our asset."
- B) "The asset is the user database; the threat is an unauthenticated attacker reading it; the vulnerability is the unprotected `/api/users` endpoint; the risk is the combination of the two."
- C) "The vulnerability is the asset that an attacker risks; the threat is what we model."
- D) "Threat, vulnerability, risk, and asset all mean roughly the same thing in modern usage."

---

**Q2.** STRIDE was introduced by:

- A) Bruce Schneier in *Applied Cryptography* (1996).
- B) Loren Kohnfelder and Praerit Garg in a Microsoft internal memorandum (1999).
- C) Adam Shostack in *Threat Modeling: Designing for Security* (2014).
- D) The OWASP Threat Modeling Working Group (2010).

---

**Q3.** In a data-flow diagram, a *trust boundary* is best described as:

- A) The outline drawn around the entire system.
- B) A dashed line crossing flows where data moves between zones of differing trust assumptions.
- C) The boundary between the user's browser and the server, regardless of any other boundaries.
- D) The line between authenticated and unauthenticated parts of the application.

---

**Q4.** Which STRIDE letter is the negation of *non-repudiation*?

- A) S
- B) T
- C) R
- D) I

---

**Q5.** In an attack tree, an *AND* node means:

- A) Any one of the children achieves the parent goal.
- B) All children must be achieved together to achieve the parent goal.
- C) The children are mutually exclusive options for the attacker.
- D) The children are alternative defences against the parent attack.

---

**Q6.** Adam Shostack recommends that engineering teams start a threat model:

- A) Asset-driven — list the valuables first.
- B) Attacker-driven — profile the threat actors first.
- C) Software-driven — draw the DFD and walk STRIDE, then overlay asset and attacker analysis.
- D) PASTA — run the full seven-stage business-risk-centric process before any other lens.

---

**Q7.** Which of the following is the strongest critique of `Risk = Likelihood × Impact` when both are 1-5 ordinal scores?

- A) The formula is too simple to capture sophisticated attacks.
- B) Ordinal scores multiplied produce a value that looks like a ratio-scale measurement but is not, and the multiplication systematically underweights tail-risk catastrophic scenarios.
- C) The formula cannot be applied to web applications because they have too many components.
- D) The formula was never used in practice and is purely academic.

---

**Q8.** Microsoft moved away from DREAD scoring largely because:

- A) DREAD was patented by another company.
- B) DREAD required specialised tooling that became unavailable.
- C) The five DREAD factors are correlated rather than independent, summing them compounds noise, and *Discoverability* rewards security-through-obscurity reasoning.
- D) DREAD was superseded by `Risk = Likelihood × Impact`, which is more accurate.

---

**Q9.** Which is **not** one of the four valid dispositions for a risk-register entry?

- A) Mitigate.
- B) Transfer.
- C) Defer.
- D) Accept.

---

**Q10.** A risk-register entry describes the threat *"credential stuffing against the login endpoint."* Which MITRE ATT&CK technique ID is the right link?

- A) T1071.004 (Application Layer Protocol: DNS).
- B) T1110.004 (Brute Force: Credential Stuffing).
- C) T1505.003 (Server Software Component: Web Shell).
- D) T1566 (Phishing).

---

## Answer key

<details>
<summary>Click to reveal</summary>

1. **B** — The asset is the thing of value (database); the threat is the adversary action (unauthenticated read); the vulnerability is the specific weakness (unprotected endpoint); the risk is the combination (probability × impact). Loose use of these four words is the most common error in junior threat-modeling.
2. **B** — Kohnfelder and Garg, *The Threats to Our Products*, Microsoft internal memorandum, April 1999. Schneier introduced attack trees the same year (December 1999, Dr. Dobb's Journal); Shostack's book consolidated and extended these but did not invent STRIDE.
3. **B** — A trust boundary is the line between zones of differing trust *assumptions*. It is not necessarily the system perimeter, and it is not specifically the auth boundary; any flow where data crosses a trust assumption — internet to proxy, app to DB, two microservices, the user to their browser's local storage — is a candidate.
4. **C** — R is Repudiation, the negation of *non-repudiation*. (S=auth, T=integrity, R=non-repudiation, I=confidentiality, D=availability, E=authorisation.)
5. **B** — AND: all children together. OR: any one child. The default in Schneier's notation is OR; AND is drawn explicitly with a small arc joining the children's edges.
6. **C** — Software-driven first, *then* asset overlay, *then* attacker sanity check. Shostack defends this at length in chapter 2 of *Threat Modeling: Designing for Security* (Wiley, 2014). Software-driven works because engineers have the software; asset and attacker analyses, without an intelligence budget, tend to be invented rather than observed.
7. **B** — The ordinal-multiplied-to-fake-ratio problem is the strongest formal critique; tail-risk underweighting is the practical consequence (Taleb, *The Black Swan*). The formula is fine as a heuristic for sorting; it is wrong as a *measurement* of risk.
8. **C** — The Microsoft retrospective on DREAD names the correlated factors, the summing-correlated-things problem, and especially the Discoverability moral hazard. The prompts remain useful as a checklist for thinking; the scoring is the part that is deprecated.
9. **C** — *Defer* is not a disposition. The four are Mitigate, Transfer, Avoid, Accept. A row in the register without a disposition is open work, not deferred work. ("On hold" is acceptable if paired with a re-review date, but it is still tracked as Open.)
10. **B** — T1110.004 (Brute Force: Credential Stuffing). T1071.004 is DNS-based C2 / exfiltration. T1505.003 is web shells (post-compromise). T1566 is phishing.

</details>

If under 7, re-read the lectures. If 9+, you are ready for the [homework](./homework.md) and the [mini-project](./mini-project/README.md).
