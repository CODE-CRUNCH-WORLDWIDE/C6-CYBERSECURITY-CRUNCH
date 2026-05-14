# Lecture 1 — The Incident Response Lifecycle and the First Thirty Minutes

> *The alert fires at 02:47 local. The on-call SOC analyst has thirty minutes — not because anyone wrote that number down, but because at the end of those thirty minutes the customer-success organisation, the legal team, and the CEO's chief of staff are all going to be in the same Zoom call asking what is happening. This lecture is about what the analyst does in those thirty minutes, and about the framework that decides what they do in the next thirty hours and the next thirty days.*

---

## 1. Why NIST SP 800-61 Rev. 2 is the spine of this week

Every regulated industry has an incident-response standard. The Payment Card Industry has PCI-DSS § 12.10. Healthcare has HIPAA's Security Rule § 164.308(a)(6). Federal civilian agencies have OMB Circular A-130 and CISA's playbooks. The European Union has the NIS2 Directive. What every one of those standards has in common is that they all *quote* — usually word-for-word — the four-phase incident-response lifecycle from **NIST SP 800-61 Rev. 2**, the *Computer Security Incident Handling Guide*, second revision, published August 2012, still the current revision as of May 2026.

The document is **free, 79 pages, primary**, and lives at <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf>. Open it, save it, and re-read the relevant section before each phase of an actual incident response. The lifecycle is short enough to memorise:

1. **Preparation.** The phase that determines whether the next three phases succeed or fail. Includes the runbook, the on-call rotation, the IR-tool inventory, the contact list, the legal escalation chart, the tabletop-exercise cadence, and the data-classification scheme that tells the responder which logs and artefacts are sensitive.
2. **Detection and Analysis.** The phase that begins when an alert fires and ends when the responder has answered three questions: *is this a real incident*, *what is its scope*, and *what is its severity*. Drives the decision on initial containment.
3. **Containment, Eradication, and Recovery.** The phase that stops the bleeding, then removes the cause, then returns the affected systems to normal operation. NIST groups these three because they overlap: long-term containment and eradication blur, eradication and recovery blur.
4. **Post-Incident Activity.** The phase nobody loves and every mature programme insists on. The lessons-learned meeting, the runbook update, the IOC sharing, the disclosure to regulators where required, the engineering ticket that fixes whatever made the incident possible.

The phases are sequential at the macro level and looped at the micro level: the analyst loops between detection and containment as the scope expands; the engineering team loops between eradication and recovery as new compromised artefacts surface. The arrow that closes the loop runs from *post-incident activity* back to *preparation* — every incident, no matter how small, should improve the runbook.

```
+----------------+        +--------------------+        +-----------------------+        +--------------------+
| 1. Preparation | -----> | 2. Detection &     | -----> | 3. Containment,       | -----> | 4. Post-Incident   |
|                |        |    Analysis        |        |    Eradication,       |        |    Activity        |
| Runbook        |        | Confirm the alert  |        |    Recovery           |        | Lessons learned    |
| On-call        |        | Determine scope    |        | Stop the bleeding     |        | Update runbook     |
| Contacts       |        | Determine severity |        | Remove root cause     |        | Share IOCs         |
| Tabletops      |        | Notify             |        | Restore service       |        | Disclose if req.   |
+----------------+        +--------------------+        +-----------------------+        +--------------------+
        ^                                                                                            |
        |                                                                                            |
        +--------------------- improvements feed back into preparation ------------------------------+
```

The remainder of this lecture walks each phase. The next lecture (L2) operationalises the *Detection and Analysis* phase against Linux logs; L3 operationalises *Containment, Eradication, Recovery* and *Post-Incident Activity* against the simulated lab.

---

## 2. Phase 1 — Preparation

### 2.1 The runbook

A runbook is a checklist. The runbook is not the place for nuance, judgement, or context. The runbook is the place for *the exact command an analyst types at 02:47 in the morning when their brain is half asleep and the alert tells them production is on fire*. It must be short, unambiguous, and runnable.

A small environment's IR runbook looks like this:

```text
1. CONFIRM
   - Open the alert. Read the alert ID, source IP, target host, time.
   - Verify the host in the inventory: is this host one of ours?
     Command: grep -i "<host>" /ops/inventory.txt
   - Verify the alert source: is the SIEM healthy? Is this a known false-positive class?
     Command: curl -s http://siem.internal/health
   - If alert is a known false positive: tag, close, end.
   - Otherwise: continue.

2. CLASSIFY
   - Pick severity from the matrix below (NIST SP 800-61 § 2.4):
     S1 - critical: confirmed compromise on production, customer data at risk
     S2 - high: probable compromise; non-production but business-critical
     S3 - medium: suspicious activity; awaiting confirmation
     S4 - low: noise; tag and observe
   - Record severity in the incident log.

3. CONTAIN (decide which path)
   - Network isolate the host (preferred for S1/S2): apply quarantine VLAN
     OR drop firewall rules to allow only the IR team's bastion.
   - Leave running: required if memory acquisition is on the table.
   - Pull the plug: last resort; destroys volatile evidence.

4. NOTIFY
   - On-call IR lead: page via PagerDuty service "IR-Primary"
   - On-call legal: page via PagerDuty service "Legal-IR"
   - Document the page time in the incident log.

5. LOG
   - Open the incident log: gh issue create --label incident -t "..."
   - First entry: timestamp (ISO 8601 UTC), alert ID, severity, your name.
   - Every subsequent action gets a timestamped entry.
```

Notice what is *not* in this runbook. It does not say "do a forensic investigation". It does not say "find the root cause". Those are activities; activities take judgement; judgement does not belong in the first-thirty-minutes runbook. The runbook gets the responder to a defensible *state*: confirmed, classified, contained, notified, logged. Investigation begins after.

The mini-project deliverable this week includes a runbook for the lab. The homework asks you to write one for your own laptop. Both must follow the structure above.

### 2.2 The on-call rotation

A rotation works if and only if every shift has exactly one primary, exactly one secondary, and a posted handoff time. PagerDuty, Opsgenie, and the open-source `nagios`/`icinga` rotations all support this; in a tiny environment, a calendar invite with `[On-call Primary]` in the title and your phone number works. What does not work: "we will figure it out when something fires" — the figuring takes ten of the thirty minutes you have, and the figuring happens without context because the person who can answer is asleep.

The runbook lives in the rotation. When the rotation rolls over at, say, Monday 09:00, the incoming primary reads the runbook. If they spot something out of date, they fix it before the shift begins. This is part of *preparation*.

### 2.3 The contact list

Print it. Keep a hard copy. The day the IR runbook is most useful is the day the laptop that holds it is the one that is on fire. The contact list contains:

- IR primary, secondary, manager.
- Legal lead, deputy.
- Communications / PR lead.
- CISO or equivalent executive.
- The hosting provider's incident contact (AWS, GCP, Azure all have one; their contact pages are listed in the resources file).
- The cyber-insurance broker.
- Outside counsel for cyber matters.
- Two government contacts: in the US, the local FBI field office's cyber squad and CISA's reporting line; in the UK, NCSC's incident-reporting line; in the EU, the national CSIRT for the affected country.
- An out-of-band communication channel (Signal group, Matrix room) that does not depend on the affected infrastructure.

The list looks long. The list is short compared to the cost of not having it. Every name has an email, a phone number, and a backup. Update the list quarterly.

### 2.4 The IR tool inventory

What tools live on the responder's laptop, in the IR jump kit, in the network: `curl`, `jq`, `journalctl`, `auditctl`, `find`, `stat`, `sha256sum`, `dd` (for raw disk acquisition), `LiME` or `AVML` (for memory acquisition), `Volatility 3` (for memory analysis), `tcpdump` or `tshark` (for network capture, if the topology permits), the SIEM web UI, the cloud provider's console, a Git repository where the incident log lives. The inventory exists so that no responder ever has to remember "do I have memory acquisition installed". The answer is recorded.

### 2.5 The data-classification scheme

When the responder begins pulling artefacts off the affected host, some of those artefacts contain personally identifiable information (PII), payment-card data, protected health information, or material non-public information. The classification scheme tells the responder which artefacts can leave the affected host, which require encryption in transit, and which require encryption at rest in the analysis environment. Without the scheme, the responder either pulls everything (and creates a second incident — uncontrolled sensitive data) or pulls nothing (and fails the investigation). The scheme is part of preparation.

### 2.6 Tabletop exercises

A tabletop exercise is a 90-minute meeting where the team walks through a hypothetical incident with the runbook in hand. The facilitator reads a scenario; the team walks the runbook step by step; somebody takes notes; the team reviews what was unclear, what was missing, and what was wrong. NIST SP 800-61 § 3.1.2 ("Preventing Incidents") and Appendix A (Incident Handling Scenarios) provide a starter library of scenarios. The recommended cadence is quarterly. Tabletops cost nothing except calendar time and surface roughly twice as many runbook bugs as real incidents do.

---

## 3. Phase 2 — Detection and Analysis

### 3.1 What an "alert" actually is

An alert is a row in some database that says: *the rules engine matched a condition that was configured to be alert-worthy*. The condition might be "SSH login from a country we have never seen this account log in from", or "outbound traffic to a known C2 IP address", or "a process named `mimikatz.exe` started", or "the integrity check on `/etc/passwd` failed". The alert says *match*; the alert does *not* say *attack*.

The first analytical step is therefore: *is the alert real*? In every mature environment, between 60% and 90% of alerts are false positives. The first-thirty-minutes runbook is shaped to fail-fast on false positives so that real incidents get the full attention.

A false positive can come from many sources. The most common: a user who travelled and logged in from a new country, a backup job that runs at a new time and trips a rate threshold, a developer testing a new endpoint that looks like enumeration to the IDS, a misconfigured time source that makes a host's clock skew look like a brute-force pattern.

The runbook's CONFIRM step (§ 2.1 above) is built for this. The analyst checks three things in sequence:

1. **Is the host in the inventory?** If the alert says `db-prod-7` and the inventory has no host named `db-prod-7`, either the alert is wrong (an asset-management bug) or the alert is right and the inventory is wrong (a shadow-IT problem). Either way, the analyst escalates.
2. **Is the source telemetry healthy?** A SIEM that is feeding stale data raises pseudo-alerts. A log forwarder that has been silently failing for a week makes the absence of alerts itself an alert.
3. **Is this alert in the known-false-positive list?** Every mature environment maintains a list of alerts the team has already triaged as benign. Match against the list; if matched, tag, close, end.

If none of the three resolves the alert, it is real-until-proven-otherwise and the analyst moves to classification.

### 3.2 Severity classification (NIST SP 800-61 § 2.4)

NIST SP 800-61 defines severity along three axes: **functional impact** (what does the incident do to the system's ability to perform its function), **information impact** (what kind of information is exposed or modified), and **recoverability** (how much effort recovery will take). The text of § 2.4 is short and worth reading verbatim.

The lab's runbook collapses NIST's three-axis grid into a four-step severity scale because in a small environment a four-step scale is the most a responder can hold in their head at 02:47:

- **S1 critical.** Confirmed compromise of a production system holding customer data, OR confirmed credential theft for a privileged account, OR active data exfiltration in progress. Triggers full IR team mobilisation; legal involvement immediate; communications team on standby.
- **S2 high.** Probable compromise of a non-production but business-critical system, OR confirmed compromise of a non-privileged production account, OR malware infection on a production endpoint. IR primary leads; legal informed; communications on standby.
- **S3 medium.** Suspicious activity awaiting confirmation: unusual login pattern, unexplained service crash, modest volume of failed-authentication attempts. IR primary investigates; legal notified through normal channels.
- **S4 low.** Noise; tag for trend analysis. No further action beyond logging.

Severity can change in either direction during the response. An S3 that, on investigation, reveals an active exfiltration channel becomes an S1. An S1 that turns out to have been a misconfigured backup job dropping to S4 is just as common. The runbook entry for severity change is: *update the incident log, page anyone whose responsibility changes, continue*.

### 3.3 Initial containment decision (the most consequential thirty seconds)

Three options, ordered from least to most invasive:

- **Leave the host running, untouched.** Suitable when the investigation requires live memory or running process state, and when the threat is judged controllable (limited network egress, no spreading mechanism observed). The cost is that the intruder continues to operate on the host during analysis. The benefit is that *every* volatile artefact survives.
- **Network isolate.** Disconnect the host from the production network; allow only an IR-team management channel. Stops outbound exfiltration and lateral movement. Preserves running memory and processes. This is the default choice for the vast majority of S1 and S2 incidents.
- **Pull the plug.** Power off without graceful shutdown. Destroys all volatile evidence: memory contents, network connections, ephemeral file descriptors, processes that exist only in RAM. Only justified when the live system poses an immediate threat that isolation cannot stop (active destructive payload running, ransomware encryption in progress, the host is being used as a pivot to attack other production systems and isolation cannot be applied fast enough).

In the lab this week the choice is made for you: the host is already powered down by the time you receive the artefacts, so the question is academic. Outside the lab the choice matters enormously and is owed to a checklist, not to improvisation.

### 3.4 Notification

The runbook lists who is paged for which severity. The notification step exists not because the on-call needs help in the first thirty minutes (they usually do not) but because the affected business needs lead time. The customer-success team needs to know that an alert exists before customers ask why their service is degraded. The legal team needs to know that an incident may have started before regulators' notification clocks begin running (GDPR Article 33 requires notification within 72 hours of becoming *aware* of a personal-data breach — the clock starts at "aware", not at "concluded").

Notification is *information*, not *handoff*. The responder keeps responding; the notification simply makes sure the next people who need to know are in the loop.

### 3.5 The incident log

The single most important artefact produced during the response is the incident log. The log is a chronologically ordered list of every observation, every decision, every action, with timestamps in ISO 8601 UTC. The log lives somewhere durable (a Git repository, a ticketing system, a secure shared note). The log is appended to, never edited; corrections become new entries with a reference to the entry being corrected.

A reasonable opening entry looks like this:

```text
2026-05-14T07:47:13Z  jstephane  Alert SIEM-2026-14771 opened.
                                 Host: web-prod-02 (192.168.42.42).
                                 Trigger: 14 SSH failed-login attempts in
                                 60s from 198.51.100.7 followed by one
                                 successful login as `deploy` at 07:46:58Z.
2026-05-14T07:48:02Z  jstephane  Host confirmed in inventory.
                                 SIEM health green. Not in known-FP list.
                                 Proceeding to classify.
2026-05-14T07:49:30Z  jstephane  Classified S2 (probable compromise of
                                 privileged service account on prod web).
                                 Paging IR-Primary and Legal.
2026-05-14T07:50:45Z  jstephane  IR-Primary (lopez) acknowledged.
                                 Legal (huang) acknowledged.
2026-05-14T07:51:12Z  lopez      Joining. Recommend network isolate
                                 web-prod-02 to IR mgmt VLAN before
                                 acquisition. Keep host powered on.
2026-05-14T07:52:33Z  jstephane  Applied isolate. ACL push successful;
                                 host reachable only from 10.0.99.0/24
                                 (IR mgmt). Continuing analysis.
```

Every entry has a timestamp, an actor, and an observation or decision. The log is the spine the post-incident report will be written from. The mini-project provides a template; the homework asks you to start one for a synthetic incident.

---

## 4. Phase 3 — Containment, Eradication, and Recovery

### 4.1 Short-term vs. long-term containment

NIST distinguishes between short-term containment (the network-isolation decision above) and long-term containment (the changes the team makes to allow the affected systems to continue operating while the eradication phase proceeds). Long-term containment in a small environment might look like: a rebuilt service running in parallel with the compromised one, with traffic shifted by DNS or load-balancer config; a snapshot of the compromised system preserved as evidence while the working copy is wiped.

The L3 lecture and the mini-project walk a worked example. The short-term containment was performed in § 3.3 above; long-term containment is part of the response narrative for the rest of the response.

### 4.2 Eradication

Eradication means removing the cause. If the cause was a stolen credential, eradication means rotating the credential, revoking all sessions, and auditing every action taken under the credential since the suspected theft. If the cause was a vulnerable endpoint, eradication means deploying the patch (or, if no patch exists, removing the endpoint or applying a virtual patch via the WAF). If the cause was a malicious package in the dependency tree, eradication means removing the package, identifying every system that pulled the package, and rebuilding each from a known-good source.

The L3 lecture walks the eradication of the simulated intruder. The principle: eradication is not over until every host that was, or could have been, affected is verified clean. *Verified clean* means specifically: the analyst has positive evidence the host no longer exhibits the indicators of compromise. Absence of indicators is not sufficient evidence of cleanliness; the analyst must actively look.

### 4.3 Recovery

Recovery means returning systems to normal operation, validating that they perform their function, and watching for re-infection. Recovery is the phase most often shortened by management pressure ("are we done yet"); the team's defence against the pressure is the runbook, which specifies the validation criteria up front.

The validation criteria for the lab's recovery: the rebuilt web server passes its standard health checks, no SSH sessions remain from suspicious source IPs, no users exist in `/etc/passwd` that should not, no `cron`/`systemd` units schedule jobs that were not present before the incident, and the IR team's monitoring rule for the indicators of compromise has been live for at least 72 hours with no hits.

---

## 5. Phase 4 — Post-Incident Activity

### 5.1 The lessons-learned meeting

The meeting happens within two weeks of the incident's closure. The agenda is fixed and short:

1. Read the timeline aloud. Anyone who was present can correct details; corrections go into the report as updates.
2. What worked. The team identifies actions that should be repeated. These become positive entries in the runbook.
3. What did not work. The team identifies actions that should not be repeated, or actions that should have happened but did not. These become engineering tickets, runbook updates, or training items.
4. What we did not know. The team identifies information the responders wished they had during the response. This becomes a preparation-phase action item.
5. Action items. Every finding has an owner and a due date. The list is short; long lists are abandoned.

The meeting is *blameless*. The purpose is to improve the system, not to punish individuals. Blame discourages honest reporting in future incidents.

### 5.2 The report

The report is the durable artefact. It is written for at least three audiences:

- **The executive audience.** A 200-word executive summary at the top, written in non-technical language: what happened, when, what we did, what is the impact, what is the status now, what we are changing. Many executives read no further. The summary must be self-contained.
- **The technical audience.** A full timeline, an IOC list, a MITRE ATT&CK mapping, a root-cause analysis, a containment/eradication/recovery narrative, and a *lessons learned* section. This is the section other responders will read when a similar alert fires next year.
- **The regulatory audience.** Where applicable: a section structured to satisfy GDPR Article 33/34, HIPAA breach-notification rule, state breach-notification laws, sector regulators. The legal team owns the structure of this section; the IR team supplies the facts.

The mini-project deliverable is a full report. The template is in `mini-project/starter/REPORT_TEMPLATE.md`.

### 5.3 IOC sharing

Indicators of compromise (IOCs) are the artefacts that identify the threat: source IP addresses, file hashes, domain names, command-and-control URLs, the specific user-agent strings used by the malware, the strings in the registry or the filesystem that the malware writes. IOCs are valuable to peer organisations because if the same threat actor targets another organisation tomorrow, the IOCs let that organisation's defenders catch the attack early.

The mature behaviour is to share IOCs. Sharing channels include: industry-specific information sharing and analysis centres (ISACs), the MISP open-source threat-intel platform, CISA's automated indicator-sharing programme, the FBI's InfraGard. Sharing is not legally compelled in most cases (the US Cybersecurity Information Sharing Act of 2015 provides immunity for sharing in good faith); it is a professional norm.

The mini-project's IOC export is a small JSON file in a STIX-flavoured shape. The template is in `mini-project/starter/IOCs_TEMPLATE.json`.

### 5.4 Regulatory disclosure

The legal team owns the disclosure decision. The IR team supplies the facts. The factual decisions that drive disclosure: was personal data involved (GDPR, US state breach laws, HIPAA), was payment-card data involved (PCI-DSS § 12.10.5), was protected health information involved (HIPAA), was material non-public information involved (US securities law). The IR team must be able to answer each question definitively from the timeline and the artefact inventory. *Cannot determine* is an acceptable answer if it is documented; *did not look* is not.

---

## 6. The first-thirty-minutes checklist (the one-page version)

Print this. Pin it.

```
+---------------------------------------------------------------------+
|  FIRST 30 MINUTES — INCIDENT RESPONSE CHECKLIST                     |
|                                                                     |
|  T+00:00  CONFIRM                                                   |
|           [ ] Host in inventory?           [ ] yes  [ ] no -> esc   |
|           [ ] SIEM/source telemetry green? [ ] yes  [ ] no -> esc   |
|           [ ] Known false-positive class?  [ ] yes -> close         |
|                                                                     |
|  T+05:00  CLASSIFY (NIST SP 800-61 § 2.4)                           |
|           [ ] S1 critical    [ ] S2 high                            |
|           [ ] S3 medium      [ ] S4 low                             |
|                                                                     |
|  T+10:00  CONTAIN                                                   |
|           [ ] Leave running (memory acq planned)                    |
|           [ ] Network isolate to IR mgmt VLAN  <-- usual default    |
|           [ ] Pull the plug (last resort)                           |
|                                                                     |
|  T+15:00  NOTIFY                                                    |
|           [ ] IR primary paged                                      |
|           [ ] Legal paged (S1, S2 always; S3 if PII suspected)      |
|           [ ] Communications paged (S1 only)                        |
|                                                                     |
|  T+20:00  LOG                                                       |
|           [ ] Incident log opened                                   |
|           [ ] First entry timestamped (ISO 8601 UTC)                |
|           [ ] Alert ID, host, severity, your name recorded          |
|                                                                     |
|  T+30:00  HANDOFF / CONTINUE                                        |
|           [ ] IR primary engaged and reading the log                |
|           [ ] You continue analysis OR hand off to incoming primary |
+---------------------------------------------------------------------+
```

Notice what is and is not on the list. The list is not "investigate the incident". The list is "get the response to a defensible state so the investigation can proceed with the right people, the right authority, and the right preservation of evidence". The investigation is the next thirty minutes, and the next thirty hours, and is the subject of L2 and L3.

---

## 7. A worked example from a small environment

A consulting friend of mine runs IT for a 40-person accounting firm. In April 2025 they received an alert: a Windows file server had a process named `7z.exe` running from `%TEMP%` with command line that included `-p<password>` and a wildcard pattern covering most of the customer-engagement folders. The SIEM rule that fired was a custom one written for that environment: "compression tools running from non-standard paths against customer data directories".

T+00:00. The on-call analyst opened the alert. Host: in the inventory, confirmed. SIEM health: green. Not in the false-positive list (it was a rule the SOC had only written six weeks earlier and had not yet fired).

T+04:00. Classified S1. A compression tool running from a temp directory against customer data, especially with a password, is the canonical *staging for exfiltration* pattern (MITRE ATT&CK T1560 *Archive Collected Data*). The analyst did not wait to see if exfiltration had started before classifying.

T+07:00. Contained. The analyst pushed a firewall rule denying outbound traffic from the file server to anywhere except the firm's known SaaS providers' IP ranges. They did not network-isolate fully; they wanted the existing SMB connections to clients to continue functioning while they preserved memory.

T+11:00. Notified. The IR primary (a managed service provider's on-call) was paged; the firm's outside counsel was paged; the managing partner was emailed but not paged. The communications path was unusual because the firm did not have a communications function; the outside counsel handled it.

T+19:00. The incident log was opened in a private GitHub issue in the firm's IT repo. First entry as above. The MSP joined the call at T+22:00 and took over primary; the original analyst continued as scribe.

The eventual analysis showed an HR contractor's credential had been phished a week earlier, the attacker had used the credential to log into VPN, had moved laterally to the file server, and was indeed staging customer data for exfiltration when the rule fired. Eradication: credential rotated, MFA enforced on VPN (it had been optional), the staged archives wiped, the host rebuilt. Recovery: business continued, customers were not notified because the analysis showed no data had left the network (the exfiltration was pre-staged but not yet started); state regulators were notified because the relevant state's breach-notification law has an acquisition standard, not an exfiltration standard, and the analyst's IR-engagement letter authorised the conservative interpretation.

The whole response, from alert to close-of-incident, took eleven days. The lessons-learned meeting produced four engineering tickets, two runbook updates, and one training item. None of them, individually, was glamorous. Collectively, they made the same attack three months later (yes, the same actor came back) a non-event.

That story is the shape of every well-run IR. The work is the checklist. The output is the next checklist.

---

## 8. What to read before Lecture 2

- **NIST SP 800-61 Rev. 2 § 2 and § 3.1** in full. If you have not read it yet, read it now. Roughly 30 pages, 60-75 minutes.
- **The MITRE ATT&CK *Initial Access* tactic page** at <https://attack.mitre.org/tactics/TA0001/>. Skim every technique listed; in real incidents most of them recur.
- The runbook in § 2.1 above. Treat it as the skeleton you will flesh out in the homework for your own environment.

Lecture 2 picks up at the start of *Detection and Analysis* and goes deep: which logs to read, which commands to type, how to reconstruct the timeline.

---

*Continue to [Lecture 2 — Linux Log Forensics](./02-linux-log-forensics.md).*
