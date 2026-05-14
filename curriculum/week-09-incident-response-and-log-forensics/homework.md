# Week 9 — Homework

Six problems, roughly six hours total. Treat the time estimates as targets, not ceilings. The point of homework in C6 is to put the lecture material into your hands; if a problem takes you two hours instead of one, that is the correct outcome as long as the deliverable is good.

The deliverables are all committed alongside the rest of the week's work in your fork of the curriculum. Use Markdown for prose; Python for scripts; ISO 8601 UTC for every timestamp.

---

## Problem 1 — Write the IR runbook for your own laptop (60 minutes)

Take the runbook skeleton from Lecture 1 § 2.1 and adapt it to your own laptop. The deliverable is `homework/runbook-personal.md` in your fork. The runbook must include:

- Your own contact list (one row per role: yourself as primary, a second person you trust as secondary, your laptop's hosting provider's emergency contact if relevant, the nearest law-enforcement cyber unit, the cyber-insurance broker if you have one).
- The list of accounts on your laptop that *would be a problem* if compromised (email, cloud storage, password manager, code-repository access, banking, social media).
- The containment options applicable to a personal laptop: turn off Wi-Fi, pull the Ethernet, shut down (least invasive to most invasive in order), and the criteria for choosing each.
- The acquisition options if memory or disk preservation is in scope: AVML for memory, `dd` for disk imaging, the path to write to (a USB drive you keep in your IR jump kit).
- The notification path: who you tell first, who you tell second.

Length: 100-200 lines. Print it. Pin it.

### Authorisation note

Personal-laptop IR is one of the few cases where the authorisation question is trivial — you own the laptop, you can investigate it, full stop. The runbook still belongs to a regime where the legal frame matters because the same procedure adapted slightly is what you would run at a job tomorrow.

---

## Problem 2 — Read NIST SP 800-61 Rev. 2 § 3 (Detection and Analysis) in full and answer five questions (45 minutes)

The text is at <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf>. Read § 3 (pages 21-44 in the published version; the section starts at "3. Handling an Incident"). Then answer the following five questions, each in 75 words or fewer. Cite the section of 800-61 your answer rests on.

1. NIST distinguishes between *precursors* and *indicators* of an incident. State the distinction in your own words, and give one example of each that the lab's events from Lecture 2 § 9 fit into.
2. The *containment strategy considerations* list in § 3.3.1 names six factors. Name at least four of them; for each, explain in one sentence why it bears on the containment decision.
3. § 3.4.1 covers "Lessons Learned". What three questions does NIST recommend the post-incident review specifically address? (NIST lists more than three; pick the three you consider most important and defend the choice.)
4. § 3.2.3 lists "common sources of precursors and indicators". Which three of those sources do you have on your own laptop, and which three do you *not* have? Defend the inventory honestly.
5. § 3.2.5 covers "Incident Documentation". What is the minimum information NIST recommends an organisation log for each incident? Compare to the incident-log template from Lecture 1 § 3.5 — what is the overlap, and what is missing?

Deliverable: `homework/nist-800-61-section-3-questions.md`.

---

## Problem 3 — Triage script extension (45 minutes)

Extend `exercises/exercise-02-log-triage.py` to recognise three additional patterns:

1. **Reverse-shell egress signatures.** Lines that contain the canonical `bash -i >& /dev/tcp/...` pattern, the `nc -e /bin/sh` pattern, the `python -c 'import socket,subprocess,os...'` pattern, or `0<&NNN-;exec NNN<>/dev/tcp/...`.
2. **systemd unit drops.** Auth/journal lines that record the creation of a new systemd unit file, especially one in `/etc/systemd/system/` or `~/.config/systemd/user/`.
3. **Cron entry additions.** Journal lines that record `crontab` activity, especially `crontab -u <other-user>` (an attacker installing a cron entry under a user other than themselves to fragment forensic evidence).

Add three corresponding regex constants at the top of the file. Add three corresponding hit categories. Update the high-signal exit-code list. Add unit-test-style assertions inside an `if __name__ == "__main__":` block at the bottom — or, better, create a separate `tests/test_triage_extensions.py` if you have a test runner installed.

Deliverable: an updated `exercise-02-log-triage.py` in `homework/` (do not overwrite the original in `exercises/`). Confirm the script compiles cleanly: `python3 -m py_compile homework/exercise-02-log-triage.py`.

---

## Problem 4 — Map a real-world incident to NIST SP 800-61 (90 minutes)

Pick one of the four real-world incidents below — all have substantial free public after-action reports:

- **The 2013 Target breach.** US Senate Commerce Committee report at <https://www.commerce.senate.gov/services/files/24d3c229-4f2f-405d-b8db-a3a67f183883>.
- **The 2017 Equifax breach.** US Government Accountability Office report GAO-18-559 at <https://www.gao.gov/products/gao-18-559>.
- **The 2020 SolarWinds compromise.** CISA Alert AA21-008A at <https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a> and the GAO testimony at <https://www.gao.gov/products/gao-21-105287>.
- **The 2021 Colonial Pipeline ransomware incident.** US Congressional Research Service report R46915 at <https://crsreports.congress.gov/product/pdf/R/R46915>.

Write a 600-800 word essay that:

- Briefly summarises the incident (one paragraph).
- Maps the public timeline to the NIST SP 800-61 four-phase lifecycle. Which phases went well? Which failed?
- Identifies, from the public record, one *preparation*-phase action that, had it been taken before the incident, would have changed the outcome materially.
- Identifies one *post-incident-activity*-phase output the public record shows the affected organisation actually produced. Cite the URL.
- Concludes with a paragraph on what your own team's runbook should learn from the incident.

Deliverable: `homework/real-incident-essay.md`. Cite every URL inline. Do not paraphrase from secondary sources (news articles); use the primary after-action reports.

---

## Problem 5 — Chain-of-custody discipline against your own laptop (45 minutes)

Use `exercises/exercise-04-custody-log.py` against a directory of your own choosing on your own laptop. The directory should contain at least ten files (your `~/Documents/` is fine; do not include anything sensitive that you would not be comfortable hashing).

The deliverables are three files in `homework/`:

- `custody-log-initial.md` — the custody log produced by `generate`.
- `custody-log-verification.txt` — the output of a `verify` run immediately after `generate`, captured with `... > custody-log-verification.txt 2>&1`. Expected: `OK: all N artefact(s) verified.`.
- `custody-log-tampered.txt` — the output of `verify` after you have appended a single byte to one file in the directory. Expected: a `MISMATCH:` line for the tampered file.

Then write a 200-word reflection in `homework/custody-reflection.md` answering: what is the operational cost of running the verifier nightly (in minutes per day, in storage, in attention), and is the cost worth the discipline for your own laptop? Defend either answer; the point is the defence, not the conclusion.

---

## Problem 6 — Tabletop exercise (60 minutes)

Pick a friend, a study partner, or a member of your study cohort. Run a 45-minute tabletop with them.

Roles:

- **You** are the on-call SOC analyst.
- **Your partner** is the *injects* operator: they read the scenario, time-stamp each inject, and add new information at decision points.

Scenario (give your partner this paragraph and nothing else):

> At 02:47 UTC the SIEM fires alert SIEM-2026-14771: 14 SSH failed-login attempts from 198.51.100.7 followed by a successful publickey login as `deploy` on host `web-prod-02`. As the analyst works through the runbook, add the following injects at your discretion: at T+12 the analyst discovers a new `support` user; at T+18 the egress firewall logs show 4.2 GB exfiltrated to 198.51.100.7:8443 between 02:49 and 02:51; at T+24 a customer support ticket comes in reporting that customer data is being posted to a public paste site; at T+30 the CEO joins the call.

Run the tabletop. Take notes on:

- Where the analyst (you) hesitated or had to look something up.
- Where the runbook was unclear or contradicted itself.
- What the analyst did *not* do that they should have.
- What new injects the operator (your partner) wishes the runbook had instructed them to add.

After the tabletop, write a 400-500 word retrospective in `homework/tabletop-retrospective.md`. Include three specific runbook changes you would commit to the runbook in Problem 1.

Optional but encouraged: record audio of the tabletop (with consent). Listening back is the single most useful learning tool for IR practice.

---

## Submission

Commit all of `homework/runbook-personal.md`, `homework/nist-800-61-section-3-questions.md`, `homework/exercise-02-log-triage.py`, `homework/real-incident-essay.md`, `homework/custody-log-initial.md`, `homework/custody-log-verification.txt`, `homework/custody-log-tampered.txt`, `homework/custody-reflection.md`, and `homework/tabletop-retrospective.md` in a single commit titled `Week 9 homework`.

Confirm before commit:

- [ ] Every timestamp is ISO 8601 UTC.
- [ ] Every script compiles: `python3 -m py_compile homework/*.py`.
- [ ] Every authorisation-related claim ("I own this", "this is my own laptop", etc.) is accurate.
- [ ] The total commit is between 1,500 and 3,500 added lines (roughly the density of the rest of this week's work).
