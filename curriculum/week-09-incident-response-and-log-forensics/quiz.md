# Week 9 — Quiz

Ten questions. Closed-book. Aim for 25 minutes. Answers and reasoning at the bottom; do not scroll until you have written your own.

---

## Question 1

The NIST SP 800-61 Rev. 2 incident-response lifecycle has four phases. Name them, in order, and write one sentence per phase about what the phase produces (its primary output artefact).

---

## Question 2

In the first-thirty-minutes runbook from Lecture 1 § 2.1, the order of steps is **CONFIRM → CLASSIFY → CONTAIN → NOTIFY → LOG**. Why is *CONTAIN* placed before *NOTIFY* rather than the reverse? Defend the ordering in 75 words or fewer.

---

## Question 3

RFC 3227 § 2.1 lists evidence in order from most volatile to least. Place the following four artefact classes in the correct order from *most volatile* (acquire first) to *least volatile* (acquire last):

A. The current contents of the `/etc/passwd` file on the affected host.
B. The on-disk contents of `~/.bash_history` for the compromised user.
C. The list of TCP connections currently open on the affected host.
D. The host's `wtmp` file.

---

## Question 4

You acquire a memory image with AVML on an Ubuntu 24.04 host. You then move the image to a separate analysis host and attempt to open it with `vol -f memory.lime linux.pslist`. Volatility 3 fails with "no suitable symbol table found".

Which of the following is the **most likely** cause, and what is the canonical resolution?

A. The dump file is corrupt; re-acquire.
B. Volatility 3 needs a symbol table for the specific kernel version of the host the dump was taken from; install or generate the symbol table.
C. AVML and Volatility 3 are incompatible; use LiME instead.
D. The analysis host needs to be running the same Ubuntu version as the target.

---

## Question 5

The `auth.log` line below appears in a host's log:

```text
May 14 02:47:32 web-prod-02 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
```

State, in plain language, what the line says — who, what, where, when, with what privilege. Identify one significant *gap* in the information the line provides relative to what an IR analyst would want to know.

---

## Question 6

You are reading an `nginx` `access.log` and you find the following request:

```text
198.51.100.7 - - [14/May/2026:02:46:36 +0000] "GET /.git/HEAD HTTP/1.1" 200 23 "-" "Mozilla/5.0 zgrab/0.x"
```

(a) What is the attacker probably trying to discover with this request?

(b) Which OWASP Top 10 2021 category does the success of this request implicate?

(c) Cite the matching MITRE ATT&CK technique by ID and name.

---

## Question 7

A Sysmon event with ID **1** records what kind of event on a Windows host? Sysmon event ID **3** records what kind of event? Why are these two specifically the highest-cited Sysmon events for incident response?

---

## Question 8

Your team's incident-log policy is "every entry has a timestamp, an actor, and a description; entries are appended, never edited." A junior analyst proposes that, when a fact in an earlier entry turns out to be wrong, the entry should simply be corrected so the log reads cleanly.

Write a 75-word rebuttal explaining why the append-only rule is correct and what the alternative *would have to* sacrifice. Reference one specific consequence in a regulated industry.

---

## Question 9

The mini-project's attacker, after gaining root, ran the sequence `history -c && rm ~/.bash_history && exit`. The on-disk bash_history file is therefore empty by the time the analyst arrives.

(a) Name one tool, and one specific plugin within that tool, that can sometimes recover the cleared bash history from a memory image of the affected host.

(b) State one precondition for the recovery to succeed.

---

## Question 10

You are writing the *Executive Summary* section of a post-incident report for an audience of three executives and one outside lawyer. The summary is capped at 200 words and must answer exactly five questions. State the five questions in the order the summary should answer them, and justify the order in one sentence.

---

## Answers

### Q1

The four phases, in order: **Preparation**, **Detection and Analysis**, **Containment, Eradication, and Recovery**, **Post-Incident Activity**. Outputs:

- Preparation produces the **runbook** (and the on-call rotation, contact list, tool inventory, tabletop cadence, data-classification scheme — all upstream artefacts that make response possible).
- Detection and Analysis produces a **confirmed-classified-contained-notified-logged state**: the response has begun, the scope and severity are known, and an incident log is open.
- Containment, Eradication, and Recovery produces a **system returned to known-good state**: the bleeding has stopped, the cause has been removed, the service is back to normal operation, and the validation criteria have been met.
- Post-Incident Activity produces the **report, the IOC export, and the lessons-learned action items** that feed back into Preparation for next time.

### Q2

CONTAIN comes before NOTIFY because containment stops ongoing damage (data exfiltration in flight, lateral movement still spreading), and the people we are about to notify cannot help us with that. NOTIFY is *information*, not handoff — the IR primary, legal, and comms add value over hours and days, not seconds. The few minutes saved by containing first can be the difference between scoped-incident and breach-of-millions-of-records; NIST SP 800-61 § 3.3.1 codifies "the primary goal of containment is to stop the incident before it overwhelms resources or increases damage".

### Q3

Most volatile → least volatile: **C, A, D, B** (TCP connection table → in-memory page cache of /etc/passwd → wtmp file → bash_history file).

Reasoning: C is in-kernel state that disappears the instant the host's network stack quiesces. A and B are both on-disk text files, but A's *cached* in-memory representation can be displaced before its on-disk copy. D and B are both on-disk; D is wtmp, which is updated on every login, and B is bash_history, which only writes on shell exit by default — so wtmp is more likely to be overwritten by ongoing activity than bash_history. (Real RFC 3227 § 2.1 collapses all "filesystem" into one bucket; the relative ordering of in-bucket items is a question of which is being most-actively rewritten.)

### Q4

**B.** Volatility 3 needs an ISF (Intermediate Symbol File) for the exact kernel version of the host the dump was taken from. The canonical resolution: download the matching ISF from the Volatility symbols repository at <https://github.com/Abyss-W4tcher/volatility3-symbols>, or generate one yourself with `dwarf2json` from the same project using the target kernel's `vmlinux` (or kernel `.deb`'s debug symbols). The pitfall is enumerated in Lecture 3 § 5.2 and is the most common cause of "I acquired memory and I cannot read it".

### Q5

The line says: at 02:47:32 on May 14 (local timezone of the log; year inferred from rotation policy — see Lecture 2 § 3.4) on the host `web-prod-02`, the user `deploy` invoked `sudo`. They were on TTY `pts/0` (an SSH-allocated pseudo-terminal). Their current working directory was `/home/deploy`. They invoked `sudo` with target user `root` and the command `/bin/bash` — that is, they obtained an interactive root shell.

The most significant **gap**: the line does not record *what `deploy` then did inside that root bash shell*. Sudo logs the sudo invocation; it does not log the commands typed inside the shell sudo spawned. The matching information lives in `~deploy/.bash_history` (if it was not cleared), in `auditd` (if it was configured), or in a process-execution log like Sysmon-equivalent `execsnoop`/`bcc-tools` (if it was running).

### Q6

(a) The attacker is trying to discover whether the host has an exposed `.git/` directory — a `200` response to `GET /.git/HEAD` means the application's source repository is directory-listable, which exposes the repository contents (and therefore secrets that were ever committed and not fully scrubbed: AWS keys, SSH keys, database passwords, the application's secret signing key, ...).

(b) **A05 Security Misconfiguration** is the primary OWASP Top 10 2021 category — a misconfigured web server is exposing a directory it should not.

(c) **MITRE ATT&CK T1190** *Exploit Public-Facing Application* — the attacker is exploiting a misconfiguration in a public-facing application to obtain information. A defensible secondary mapping is **T1083** *File and Directory Discovery*.

### Q7

Sysmon **event 1** records **process creation**: each new process that starts is logged with its full command line, parent process, image path, and hashes (MD5, SHA-1, SHA-256, IMPHASH).

Sysmon **event 3** records **network connections**: each outbound (and optionally inbound) TCP/UDP connection made by any process.

These two events together cover most of the visibility required to detect modern Windows intrusions: event 1 catches Living-Off-The-Land techniques (an attacker running `powershell.exe -enc <base64-payload>` shows up at event 1 with the full command line, which most rules can match); event 3 catches the network half of C2 traffic. They are also the two events whose volume an EDR or SIEM can handle without being overwhelmed; the other event IDs (image loads, registry writes) generate much higher volume and require careful filtering.

### Q8

Editing prior entries breaks the log's evidentiary value. The append-only rule means the log can be cryptographically attested at any point in time: a `git log -p` will show every change to the log file in order, with the actor and timestamp of each change. An edited prior entry cannot be distinguished from a forged prior entry. In a regulated industry — for example, a HIPAA-covered entity — the breach-notification timeline runs from the moment the team became *aware* of the incident; if the log can be edited, regulators have no way to confirm the awareness timestamp, and the safest assumption (the earliest possible awareness) is also the worst for the organisation.

### Q9

(a) **Volatility 3**, plugin **`linux.bash`**. The plugin walks every running bash process's heap, finds the readline history buffer, and prints the commands typed at the prompt — including commands typed *after* `history -c` was run, because `history -c` clears only the on-disk history buffer's flush queue, not the in-memory history list.

(b) The bash process must still be running at the time of memory acquisition. If the attacker ran `exit` and the shell process terminated *before* the memory image was captured, the process's heap has been reclaimed and the history is unrecoverable. (Another precondition: the kernel and ISF symbol table must match, per Q4.)

### Q9 alternative

(a) **Volatility 3 / `linux.bash`** as above is the standard. An honourable mention is the `bashhistory` plugin in older Volatility 2 and the equivalent in Rekall.

### Q10

The five questions, in order:

1. **What happened?** (one sentence, plain language, no jargon)
2. **When did it happen, and when did we find out?** (timestamps, simple — "the attacker was on our network from X to Y; we detected at Z")
3. **What is the impact?** (customer-data exposure scope, downtime, financial estimate if known)
4. **What did we do?** (containment, eradication, recovery — one sentence each)
5. **What is the status now, and what are we changing?** (closed / monitoring; the two or three top action items)

Order rationale: executives read top-to-bottom and often stop after the first 50 words; the order maximises the value of the first 50 words. *Impact* before *what we did* is deliberate — the audience needs to size the problem before reading the response. *Status now* last because it is the question the audience will ask next and the summary answers before they have to.
