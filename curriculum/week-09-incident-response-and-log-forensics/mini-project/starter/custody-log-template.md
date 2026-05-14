---
generated_at: <YYYY-MM-DDTHH:MM:SSZ>
artefact_count: <N>
---

# Chain-of-custody log — IR-2026-014

This file is a curriculum template. In practice you do not hand-edit this template; you run `exercise-04-custody-log.py generate` and the script produces the file. After generation, append at least one *Transfer* row to record the artefacts being transferred from `starter/logs/` to your analysis workspace.

---

## Artefacts

| Artefact | Size (bytes) | SHA-256 | MD5 | Acquired at | Acquired by | System ID | Tool | Authorisation |
|---|---:|---|---|---|---|---|---|---|
| logs/auth.log | <N> | <hash> | <hash> | <ts> | <you> | lab-simulated | exercise-04-custody-log.py | training exercise (week-09) |
| ... | ... | ... | ... | ... | ... | ... | ... | ... |

---

## Transfers

| Artefact | From | To | At | Verified SHA-256 |
|---|---|---|---|---|
| logs/auth.log | host:lab-simulated | host:<your-analysis-host> | <YYYY-MM-DDTHH:MM:SSZ> | match |
| ... | ... | ... | ... | ... |

---

## Notes

- The custody log is append-only. Corrections are new rows, never edits to prior rows.
- Re-run `exercise-04-custody-log.py verify` after every transfer; the verifier compares the on-disk hash to the recorded hash and surfaces any mismatch.
- The custody log lives in version control alongside the rest of the IR artefacts. Sign your commits (`git commit -S`) where possible.
