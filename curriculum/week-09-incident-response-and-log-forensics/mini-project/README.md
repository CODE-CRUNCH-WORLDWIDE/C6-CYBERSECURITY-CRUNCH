# Mini-Project — IR Drill on the Simulated Compromise of `web-prod-02`

> *The lab is a simulated incident. The artefacts you will work with — a tarball of `/var/log/` contents, a `journalctl -o json` export, a `~/.bash_history` file, a small synthetic memory-strings file — were generated to tell a coherent compromise story. Your job is to reconstruct the story from the artefacts, write the report a real engagement would expect, and ship the chain-of-custody log and ATT&CK map alongside.*

---

## Authorised use

The artefacts in `starter/logs/` are **entirely synthetic** and contain only RFC 5737 test-net IP addresses (`198.51.100.0/24`) and RFC 2606 example domains. There is no real customer or operator data anywhere. Run any analysis you like against them.

Do not, however, treat this lab's procedures as a licence to triage logs from any system you do not own. The same authorisation banner that governed Weeks 7 and 8 governs this week: authorised investigation only. See the week's `README.md` banner.

---

## Scenario

It is **2026-05-14**. The on-call SOC analyst at a 40-person SaaS company has just received alert **SIEM-2026-14771** against host `web-prod-02`. The runbook is in your hands. The first thirty minutes were walked in `exercises/exercise-01-first-30-minutes.md`. The IR primary (you, for the rest of this project) has now joined the call.

Over the next 90 minutes the team has containerised the host (network-isolated to the IR management VLAN, kept powered on), pulled the logs (a tarball of `/var/log/`, the journal as JSON-lines, the deploy user's `bash_history`, a memory-strings snippet from a partial AVML acquisition), and committed them into the artefact directory. **That artefact directory is `starter/logs/`**.

Your job, as the mini-project, is to:

1. Reconstruct the timeline from the artefacts.
2. Produce the indicators-of-compromise list.
3. Complete the MITRE ATT&CK map.
4. Write the post-incident report.
5. Commit the chain-of-custody log.
6. Ship the regression artefacts so the next responder can verify your work.

The full work, end to end, is roughly **6-7 hours**. Friday and Saturday in the weekly schedule are the budgeted time.

---

## What is in `starter/`

```text
starter/
├── README.md                  -- a one-page brief written in-character as
│                                 the IR primary handing the artefacts to you
├── post-incident-template.md  -- the post-incident write-up template
├── iocs-template.json         -- the STIX-flavoured IOC export template
├── attck-map-template.md      -- the MITRE ATT&CK mapping table template
├── custody-log-template.md    -- the chain-of-custody log template
└── logs/
    ├── auth.log               -- /var/log/auth.log content for the incident window
    ├── access.log             -- nginx combined-format access log (incident window)
    ├── error.log              -- nginx error log
    ├── journal.jsonl          -- journalctl -o json export
    ├── bash_history.txt       -- deploy user's ~/.bash_history with HISTTIMEFORMAT
    ├── crontab-support.txt    -- contents of /var/spool/cron/crontabs/support
    ├── memory-strings.txt     -- a curated strings dump from the partial AVML image
    └── find-mtime-7d.txt      -- output of `find / -mtime -7 -printf '%T+ %p\n'`
                                  taken immediately post-acquisition
```

The artefacts are coherent: every event in `bash_history.txt` has a corresponding `journal.jsonl` or `auth.log` line; every `access.log` request that produced a file write produces a corresponding `find-mtime-7d.txt` entry; the `memory-strings.txt` recovers the cleared post-`history -c` commands.

---

## Deliverables

By the end of the mini-project you commit:

1. **`timeline.md`** — the full chronological timeline, produced by `exercises/exercise-03-timeline-builder.py` ingesting every relevant artefact and then manually annotated with the events that are not in any single log (filesystem timestamps, the cron entry, the new user account).
2. **`iocs.json`** — the indicators-of-compromise export, populated from `iocs-template.json`. Required fields per IOC: `type`, `value`, `first_seen`, `last_seen`, `confidence`, `sharing_tlp`. Aim for 8-15 IOCs covering network, host, and behaviour.
3. **`attck-map.md`** — the full ATT&CK mapping, extending the partial map in `attck-map-template.md`. Every event in `timeline.md` has at least one technique citation.
4. **`post-incident-writeup.md`** — the post-incident write-up, completed from `post-incident-template.md`. Eight sections, each populated.
5. **`custody-log.md`** — the chain-of-custody log produced by `exercises/exercise-04-custody-log.py generate`, with at least one *transfer* row recorded (showing the artefacts being transferred from `starter/logs/` to your analysis workspace).
6. **`runbook-delta.md`** — three specific runbook changes you would commit to your team's runbook based on this incident.

---

## Workflow

A reasonable order, with rough time budget:

1. **Triage (30 min).** Run `exercise-02-log-triage.py` against the log directory. Read the output. Form a hypothesis about what happened.
2. **Build the timeline (60 min).** Run `exercise-03-timeline-builder.py` against the logs. Produce `TIMELINE.md`. Manually add the events that are not in the run output (the new user creation from `auth.log` if not already captured; the cron-entry creation from `crontab-support.txt`; the filesystem timestamps from `find-mtime-7d.txt`; the memory-recovered commands from `memory-strings.txt`).
3. **Extract IOCs (45 min).** Walk the timeline, pulling out the source IP, the dropped-file SHA-256, the cron entry, the new user account, the egress destination, and the distinctive command sequences. Populate `IOCs.json`.
4. **Complete the ATT&CK map (60 min).** Map every event in the timeline to at least one technique. Use the partial map in `ATTCK_MAP_TEMPLATE.md` as the starting point. Verify every technique ID resolves on <https://attack.mitre.org/>.
5. **Generate the custody log (15 min).** Run `exercise-04-custody-log.py generate` against `starter/logs/`. Add one transfer row.
6. **Write the report (90 min).** Fill in `REPORT_TEMPLATE.md`. The executive summary is the hardest 200 words you will write this week; write it last. The narrative sections lean heavily on the timeline; do not duplicate, refer to the timeline.
7. **Write the runbook delta (30 min).** Three changes. Each is one sentence; the defence is one paragraph.
8. **Final check (15 min).** Commit. Run the self-check below.

---

## Self-check before submission

- [ ] Every deliverable in the list above is present in the project's `submission/` directory.
- [ ] Every timestamp in every deliverable is ISO 8601 UTC.
- [ ] `iocs.json` parses as valid JSON: `python3 -c 'import json,sys; json.load(open(sys.argv[1]))' submission/iocs.json`.
- [ ] `custody-log.md` verifies cleanly: `python3 ../exercises/exercise-04-custody-log.py verify --directory starter/logs --custody-log submission/custody-log.md`.
- [ ] The ATT&CK map has at least one row at *medium* confidence; an all-*high* map suggests insufficient self-criticism.
- [ ] The executive summary is between 150 and 220 words.
- [ ] The root-cause analysis identifies a *systemic* cause, not only a *proximate* cause.
- [ ] The runbook delta proposes three changes, no more and no less.

When all eight are true, commit. Push.

---

## Optional extensions (do these for credit if you have time)

- **Run Volatility 3 against a real memory image.** Capture memory from a throwaway VM you own using AVML; run `vol -f memory.lime linux.pslist linux.bash linux.netstat`. Compare the `linux.bash` output to your own `~/.bash_history` on the same VM. Write a short note on what Volatility recovered that the on-disk file did not.
- **Stand up Wazuh or Security Onion** on a separate VM you own. Ingest the lab's log files. Compare the SIEM's automated correlation view to your hand-built timeline. Write a short note on what the SIEM caught and what it missed.
- **Configure `auditd` with the Florian Roth ATT&CK rule set** on a throwaway VM you own. Re-run the attacker's command sequence (`useradd support`, `crontab -u support`, `cat /etc/shadow`, etc.). Compare what `auditd` caught against what `journalctl` and `auth.log` together caught. Write a short note on what `auditd` adds.
- **Share the IOCs with a peer team.** Send the `IOCs.json` to a study partner; have them ingest into MISP or a similar tool; have them confirm the format parses cleanly. Note any feedback in the runbook delta.

---

## Grading criteria (for the curriculum's instructor self-rubric)

Each deliverable is graded out of 5; the total is out of 30.

- **timeline.md.** Completeness, correctness, ordering, source labelling. Penalty for any missing event that the artefact set supports.
- **iocs.json.** Format validity, coverage (network/host/behaviour all represented), confidence honesty, TLP labelling.
- **attck-map.md.** Every event mapped; sub-techniques used where applicable; confidence varied; evidence pointers resolve.
- **post-incident-writeup.md.** All eight sections populated; executive summary is non-technical and self-contained; root-cause analysis reaches the systemic layer.
- **custody-log.md.** Generated by the script (not by hand); verifies cleanly; at least one transfer row present.
- **runbook-delta.md.** Three changes; each defensible; each addresses a real gap the incident exposed.

A submission at 24/30 or above is portfolio-quality. A submission at 20/30 is passing. Below 20/30 indicates a gap worth revisiting before moving to Week 10.

---

*Begin with [starter/README.md](./starter/README.md).*
