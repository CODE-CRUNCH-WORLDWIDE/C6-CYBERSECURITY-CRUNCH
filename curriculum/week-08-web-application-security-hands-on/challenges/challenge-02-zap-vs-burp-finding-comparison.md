# Challenge 2 — ZAP vs Burp Community: A Comparative Finding Report

**Estimated time:** 90 minutes.

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  Both scanners in this challenge are run against the vuln_lab on    |
|  127.0.0.1:5000 - your own laptop, with the application running     |
|  inside this week's mini-project/starter/ directory. ZAP's          |
|  automated scan in particular fires hundreds of probe requests per  |
|  endpoint; that is the right behaviour against a vulnerable lab     |
|  you own, and a crime against any host you do not. Confirm the      |
|  target URL before launching either scan. If your fingers are       |
|  about to type a non-loopback URL, stop and reread this banner.     |
+---------------------------------------------------------------------+
```

Lecture 1 § 2 set the stage: Burp and ZAP achieve the same thing but with different strengths — Burp's manual workflow is cleaner for skilled hunters, ZAP's automated scanner is cleaner for surveying an unknown application. This challenge is the empirical exercise that makes that claim concrete. You will run each tool against the *vulnerable* lab (before any of the Lecture 3 patches), collect the findings, and write up a side-by-side comparison.

The deliverable is `tool-comparison.md`, three findings exports, and a 1500-2500 word analysis.

---

## What you ship

1. `tool-comparison.md`, the analysis document.
2. `zap-report.html`, the HTML report ZAP produces from the automated scan.
3. `burp-history.json` (or a comparable export of your Burp HTTP history; the Community Edition does not export to JSON natively, so a screen-capture of the history table is acceptable).
4. `findings-table.md`, the side-by-side comparison table.

---

## Setup

The lab must be in its **vulnerable** state for this challenge — *not* the patched state from Exercise 3. If you have already patched, either reset to the starter or `git stash` your patches and reapply them after the comparison.

Confirm:

- `app.py` has `debug=True`.
- `/lookup` uses string concatenation.
- `/search` uses `Markup(q)`.
- `/fetch-image` has no allow-list.

If any of those have been patched, revert before running the scans.

---

## Part 1 — ZAP automated scan (30 min)

### Option A: GUI

1. In ZAP, open the *Manual Explore* dialog (Quick Start tab → Manual Explore). Enter `http://127.0.0.1:5000` as the URL to explore. Click Launch Browser.
2. A new Firefox window opens with the lab. Click through every endpoint to populate ZAP's Sites tree: home, login, search (with a benign query), profile (after logging in as alice), comments, the lookup page, the import-profile page, the fetch-image page.
3. Close the Firefox window.
4. Right-click `http://127.0.0.1:5000` in ZAP's Sites tree → Attack → Active Scan. Confirm the dialog (scope: `127.0.0.1:5000` only; policy: Default Policy or Light, your choice). Click Start Scan.
5. The scan takes 5-15 minutes. ZAP fires hundreds of probe requests against each endpoint. Watch the Alerts tab populate.
6. When the scan completes, Report → Generate Report. Pick the "Traditional HTML Report" template. Save as `zap-report.html`.

### Option B: Command line (daemon mode)

```bash
# Start ZAP in daemon mode bound to localhost
zap.sh -daemon -port 8090 -config api.disablekey=true &
# Wait for it to come up
sleep 10
# Run the baseline scan
zap-baseline.py -t http://127.0.0.1:5000 -r zap-report.html
```

The baseline scan is faster but lighter. For the full active scan use `zap-full-scan.py` instead. The output is the same HTML report file.

### What ZAP should find

The automated scan flags roughly these classes against the vulnerable lab (your exact list will vary slightly with the policy):

- SQL injection (high).
- Cross-Site Scripting reflected (high).
- Cross-Site Scripting persistent (high).
- Application Error Disclosure (medium).
- Missing security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, CSP (low/info).
- Cookie no `HttpOnly` (low).
- Cookie no `SameSite` (low).
- Information Disclosure - Debug Error Messages (medium).

What ZAP probably will *not* find without human help:

- IDOR (requires understanding what user the session belongs to and that a different `id` returns the wrong user's data).
- Missing function-level authorization (same — requires understanding the role model).
- The pickle deserialization endpoint (it parses base64 from a form field; the scanner does not synthesise valid pickle payloads).
- SSRF (the scanner may flag the open URL parameter but typically does not validate that the response is the metadata).

The automated scan is good at the *injection-class* bugs because it fuzzes inputs with attack payloads. It is bad at the *business-logic class* bugs because those require understanding what the application means.

---

## Part 2 — Burp Community manual session (30 min)

1. In the Burp-configured Firefox profile, browse to <http://127.0.0.1:5000> and click through every endpoint in the same order you populated ZAP's Sites tree.
2. In Burp Proxy → HTTP history, you have one row per request. Note that Burp Community has *no automated scanner* — the bug discovery here is your manual workflow.
3. For each of the eight endpoints, send a representative request to Repeater and manually try the payloads from Exercise 2. Confirm each exploit works.
4. For one or two endpoints, also use Intruder: a wordlist-based password guess against `/login` (Intruder Sniper attack, payload position on the `password` parameter, payload set: a small `top-100` wordlist from SecLists). Document the number of attempts and the time to a hit.

### What Burp Community surfaces

The findings from the Burp session match exactly the eight bug classes from Exercise 2 — because the bug class is the same regardless of tool; only the workflow changes. Burp's contribution to the comparison is:

- A precise, replayable record of each request that demonstrated the bug.
- The Repeater workflow for iterating on payloads in seconds, not minutes.
- The Intruder workflow for at least one bug class (auth brute force).

What you have to *bring* to Burp Community: the hypotheses. The tool does not generate them for you.

---

## Part 3 — Build the comparison table (15 min)

`findings-table.md` is a table with columns:

| Finding | Severity | CWE | OWASP | ZAP found | Burp Community found | Notes |
|---------|---------:|-----|-------|-----------|----------------------|-------|

One row per finding, plus a "Total findings" row at the bottom.

For the "found" columns, use:

- "Yes (auto)" — the tool surfaced the finding without operator help.
- "Yes (with operator help)" — the operator found it using the tool's manual workflow.
- "No" — the tool could not have found it given its mode of operation.

Be honest. Burp Community has no automated scanner; every "found" in its column is "with operator help." ZAP's automated scan flags many things without operator help but misses business-logic flaws.

---

## Part 4 — Write the analysis (60 min)

`tool-comparison.md` is 1500-2500 words covering:

### § 1 — Methodology (200-300 words)

Describe what you ran. Both tools' versions; the lab's commit (or "the unpatched starter as shipped"); the policies / scan profiles you used; the duration of each scan; the date and time. The reader should be able to reproduce your run.

### § 2 — Findings summary (200-300 words)

The bullet-list summary of the comparison table. Which tool flagged how many bugs. Which classes of bug each tool dominated.

### § 3 — Where each tool excels (400-600 words)

This is the analytical core. Write specifically:

- **The strengths of ZAP's automated scan.** What it caught that you might have missed by hand. The cost-benefit math for shops that run ZAP in CI/CD.
- **The strengths of Burp's manual workflow.** What it caught that ZAP missed. Why a skilled hunter prefers Burp's UX. The Intruder workflow specifically (with concrete payloads).
- **The classes neither tool catches well alone.** Business-logic bugs, IDOR, missing-authz, race conditions. Why these require human reasoning.

### § 4 — Where each tool struggles (200-400 words)

The mirror image. Each tool's blind spots, false-positive shape, and noise-on-the-wire footprint.

### § 5 — Choosing between them (200-400 words)

For each of these scenarios, which tool would you reach for, and why?

- "I have a single application and four hours to find as many bugs as possible."
- "I want to scan the application on every commit in CI."
- "I have a specific hypothesis about a SSRF bug and need to test it carefully."
- "I am bug-bounty hunting against a target with a published scope and a strict rate limit."
- "I am training a junior on web-app testing and want them to see automated findings before they learn manual."

### § 6 — A note on the paid tier (100-200 words)

Burp Pro adds the automated scanner that closes most of the ZAP-Community-Burp gap. Discuss whether the gap is worth the licence fee for the kind of engineering work you anticipate doing. ZAP plus Burp Community plus operator skill is a defensible posture for many engagements; Pro buys you time and breadth.

### § 7 — Closing recommendation (100-200 words)

A one-paragraph recommendation for the C6 cohort: which tool to install first, which to install second, which to upgrade later. Justify with reference to the comparison.

---

## Acceptance criteria

- `tool-comparison.md` exists with all seven sections.
- `zap-report.html` is the actual HTML report from the ZAP scan.
- `findings-table.md` has at least eight rows (one per bug class in the lab), plus a totals row.
- The report cites at least two MDN pages, two OWASP pages, and the canonical Burp and ZAP documentation pages from the resources list.
- The analysis identifies at least one finding ZAP caught that Burp Community missed in operator-free mode, and at least one Burp Community caught (with operator help) that ZAP's automated scan missed.

---

## Stretch

- **Run the same comparison with Burp Pro** if you have access through a school or employer license. Add a third column to the table.
- **Run the comparison after the Lecture 3 patches.** Both tools should find drastically fewer bugs (ideally zero of the original eight). Compare the *false positives* both tools generate against the patched lab.
- **Integrate the ZAP baseline scan into a GitHub Actions workflow** that runs against the patched lab on every commit. The workflow file should fail the build if any high-severity finding appears. This is the form of the work that lives in production CI/CD pipelines.

---

## Common failures

- **You run the scan against the patched lab.** The scan finds nothing exciting. You write a 1500-word report about how secure the lab is. Revert to the starter, re-run.
- **The scan times out.** ZAP's active scan can run for hours on a real application. On the lab, ten minutes is typical; thirty minutes is fine; if it has run for more than forty-five minutes something is wrong (a stuck request, a missing timeout). Stop the scan, review the active-scan rules in use, restart with a lighter policy.
- **You report ZAP findings verbatim.** ZAP's HTML report is a starting point, not an end product. The analysis is what makes this a *write-up* rather than a *paste-up*. Triage the findings; group duplicates; note false positives.
- **The comparison table is unbalanced.** If every row says "Yes" in both columns, you have not done the comparison; you have just listed the bugs. The interesting row is the one where the columns disagree.

---

## What the C6 instructor will look at

1. **Honesty in the table.** "Yes (with operator help)" is the most-common honest answer. Calling everything "Yes (auto)" because you did the operator work in advance and forgot to record it is the most-common dishonest answer.
2. **§ 3 specificity.** Where each tool excels should name specific findings, specific payloads, specific Repeater / Intruder steps, specific ZAP rule IDs. Generalities ("Burp is good for manual work") are a signal you did not actually use the tool.
3. **§ 6 honesty about the paid tier.** The C6 instructor recognises that Pro is a real product with real advantages. They also recognise that the marketing copy for Pro overstates the gap. Write the assessment you actually believe.

The challenge does not have a "right answer." Both tools are good; both have gaps; the right tool depends on the task. The exercise asks you to articulate, with evidence, *which task suits which tool*.
