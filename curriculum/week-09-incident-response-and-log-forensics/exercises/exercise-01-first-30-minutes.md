# Exercise 1 — Walk the First-Thirty-Minutes Checklist

> Estimated time: 60-75 minutes.
> Prerequisite: Lecture 1 read.
> Output: a completed checklist plus an incident-log opening entry, both in this file's appendix.

---

## Scenario

It is **2026-05-14 at 02:47:13 UTC**. You are the on-call SOC analyst for a 40-person company. The SIEM has just fired alert **SIEM-2026-14771**:

```
Alert ID:   SIEM-2026-14771
Severity:   high (per SIEM rule)
Fired at:   2026-05-14T02:47:13Z
Rule:       SSH-BruteForce-Then-Success
Description: 14 SSH failed-login attempts from a single source IP
             within a 60-second window, followed by exactly one
             successful publickey authentication by that same source
             IP within 90 seconds.
Host:       web-prod-02
Host IP:    192.168.42.42
Source IP:  198.51.100.7
Account:    deploy
First fail: 2026-05-14T02:45:32Z
Last fail:  2026-05-14T02:46:21Z
Success:    2026-05-14T02:46:58Z
```

The inventory shows `web-prod-02` is a production web server hosting the company's main customer-facing application. The `deploy` account is a service account used by the CI/CD pipeline to run releases; it has `sudo` privileges restricted (via `sudoers`) to the deployment script and a small list of related commands. The account has SSH access via a publickey that is supposed to be held only on the CI host (`ci-runner-01`, IP `192.168.42.10`).

Your runbook is the one from Lecture 1 § 2.1. Your phone is in your hand. The clock is running.

---

## Task

For each of the five checklist phases (CONFIRM, CLASSIFY, CONTAIN, NOTIFY, LOG), do the following:

1. **Decide.** Read the runbook for that phase. Decide what you do, given the scenario.
2. **Defend.** Write one paragraph explaining *why* you made that decision, citing the relevant section of NIST SP 800-61 Rev. 2 if your defence rests on it.
3. **Record.** Append the decision to the incident-log template at the end of this file, with a plausible UTC timestamp.

Use the four-step severity scale from Lecture 1 § 3.2. Use the three containment options from § 3.3. Use ISO 8601 UTC timestamps throughout.

---

## Optional extension

If you have additional time, write a **runbook delta**: a list of three changes to the runbook in Lecture 1 § 2.1 that would have made the response to this specific alert faster, clearer, or less error-prone. Each change is one sentence; defend it in one paragraph. The delta is the form most lessons-learned action items take in real engagements.

---

## Deliverable

Fill in the blanks below. Commit the completed file to the week's exercises directory in your fork.

---

## Appendix A — Completed checklist

### CONFIRM (target: T+00:00 to T+05:00)

- Host in inventory: __________
- SIEM/source telemetry healthy: __________
- Known false-positive class: __________
- Decision: __________

Defence (≤ 100 words):

> ...

### CLASSIFY (target: T+05:00 to T+10:00)

- Severity: __________ (S1 / S2 / S3 / S4)

Defence (≤ 100 words):

> ...

### CONTAIN (target: T+10:00 to T+15:00)

- Containment choice: __________ (Leave running / Network isolate / Pull the plug)

Defence (≤ 100 words):

> ...

### NOTIFY (target: T+15:00 to T+20:00)

- Paged: __________ (IR primary / IR secondary / Legal / Communications / Executive / Hosting provider / Other)

Defence (≤ 100 words):

> ...

### LOG (target: T+20:00 to T+30:00)

- Incident log opened in: __________ (GitHub issue, ticketing system, secure shared note, ...)
- First entry timestamp (ISO 8601 UTC): __________

---

## Appendix B — Incident-log opening entry (template)

Replace each `<...>` with your own decision. The format is freeform Markdown.

```markdown
# IR-2026-014 — Suspected compromise of web-prod-02

## Opening entries

| Time (UTC) | Actor | Entry |
|---|---|---|
| 2026-05-14T02:47:13Z | <your-name> | Alert SIEM-2026-14771 opened. Host web-prod-02 (192.168.42.42). Trigger: 14 SSH failed-login attempts in 60s from 198.51.100.7 followed by one successful publickey login as `deploy` at 02:46:58Z. |
| 2026-05-14T02:<...>Z | <your-name> | Host confirmed in inventory. SIEM health <...>. Not in known-FP list. Proceeding to classify. |
| 2026-05-14T02:<...>Z | <your-name> | Classified S<...> (<reason>). Paging <...>. |
| 2026-05-14T02:<...>Z | <your-name> | Containment: <choice>. <reason>. |
| 2026-05-14T02:<...>Z | <your-name> | Paged <list>. Acknowledgements pending. |
| 2026-05-14T02:<...>Z | <your-name> | Continuing analysis. Next steps: <one-line plan>. |
```

---

## Appendix C — Runbook delta (optional)

Three proposed changes to the Lecture 1 § 2.1 runbook in light of this incident. Each change is one sentence; the defence is one paragraph.

1. __________

   > ...

2. __________

   > ...

3. __________

   > ...

---

## Self-check

Before you commit, ensure each of the following is true.

- [ ] Every appendix is filled in.
- [ ] Every timestamp is ISO 8601 UTC (the `Z` suffix is mandatory).
- [ ] Every decision has a defence of ≤ 100 words.
- [ ] At least one defence cites NIST SP 800-61 Rev. 2 by section.
- [ ] Your incident-log opening entry plausibly matches the response sequence.

When all five are true, commit. The worked solution is in `SOLUTIONS.md`; review only after you have committed your own version.
