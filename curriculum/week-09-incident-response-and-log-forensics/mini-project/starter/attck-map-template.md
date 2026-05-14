# MITRE ATT&CK Mapping Template — IR-2026-014

This file is a curriculum template students complete as part of the mini-project. The starter rows below are partial; the deliverable extends the table to cover every event in the produced timeline.

For each row: the technique ID must hyperlink to <https://attack.mitre.org/techniques/TXXXX/> (or `TXXXX/NNN/` for a sub-technique); the evidence pointer must resolve to a specific line in a specific source artefact; confidence is one of *high*, *medium*, or *low*.

---

## Mapping table

| # | Time (UTC) | Observed event | Tactic | Technique ID | Sub-technique | Confidence | Evidence pointer | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | 2026-05-14T02:46:14Z | `GET /admin/login.php` from 198.51.100.7 with UA `zgrab/0.x`, 404 | Reconnaissance | [T1595](https://attack.mitre.org/techniques/T1595/) | [T1595.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/) | high | access.log:11 | Active scanning prior to foothold. |
| 2 | 2026-05-14T02:46:35Z | `GET /.env` (404) | Reconnaissance | [T1595](https://attack.mitre.org/techniques/T1595/) | T1595.002 | high | access.log:18 | Dotfile probing. |
| 3 | 2026-05-14T02:46:36Z | `GET /.git/HEAD` (200) | Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | n/a | high | access.log:19 | Exposed `.git/` directory; the source repository — including the deploy private key committed in error — became accessible. |
| 4 | 2026-05-14T02:46:58Z | SSH publickey accepted for `deploy` from 198.51.100.7 | Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) | [T1078.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003/) | high | auth.log:14 | Stolen-credential foothold. |
| 5 | 2026-05-14T02:47:32Z | sudo `deploy → root /bin/bash` | Privilege Escalation | [T1548](https://attack.mitre.org/techniques/T1548/) | [T1548.003 Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) | high | auth.log:18 | Buggy `sudoers` rule permitted arbitrary shell. |
| 6 | <fill> | <fill> | <tactic> | <technique> | <sub> | <conf> | <pointer> | <notes> |
| ... | ... | ... | ... | ... | ... | ... | ... | ... |

---

## How to complete this template

1. Open `timeline.md` (produced by `exercise-03-timeline-builder.py`).
2. For each row in the timeline that the partial table above does not cover, append a new row here.
3. For each new row, open <https://attack.mitre.org/matrices/enterprise/linux/> and find the matching technique.
4. Set confidence honestly. If the observation is consistent with the technique but other interpretations are plausible, set *medium*.
5. Set the evidence pointer to a specific source-and-line tuple. Verify the line by opening the source file and reading the line; do not write down a pointer you have not verified.
6. Add a *Notes* cell only where the choice is non-obvious.

A complete mapping covers roughly 25-35 rows for this incident.
