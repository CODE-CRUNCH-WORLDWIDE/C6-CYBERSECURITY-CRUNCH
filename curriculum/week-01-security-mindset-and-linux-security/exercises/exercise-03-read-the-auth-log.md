# Exercise 3 — Read the auth log

**Time:** ~40 minutes.
**Outcome:** You can pull useful security signal out of a real auth log — successful logins, failed logins, sudo events, SSH session opens and closes — using only `grep`, `awk`, and `journalctl`.

## Problem statement

Take a real `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Fedora), or the systemd journal on either, and answer five questions about its contents. You will deliver `exercise-03-auth-log.md` containing your commands, the output snippets that support each answer, and a one-sentence interpretation per question.

## Setup

Pick a source. In order of preference:

1. **Your own Linux server.** A VPS, a home server, anything that has been on the internet long enough to have a non-empty auth log. This is the best practice for the exercise: real data, your machine.
2. **A VM where you can generate events.** Open a fresh Ubuntu VM, SSH in once correctly, SSH in once with a wrong password, run `sudo true` and `sudo false`, log out. Now your log has a few representative entries.
3. **The provided sample log.** If you have access to neither of the above, a synthetic but realistic sample is included in this repo at [`sample-auth.log`](./sample-auth.log) (see Hints if it is not present yet — you can generate one yourself using the steps in option 2).

```bash
# Debian/Ubuntu
ls -l /var/log/auth.log
sudo less /var/log/auth.log

# RHEL/Fedora
ls -l /var/log/secure
sudo less /var/log/secure

# Anywhere modern
journalctl _COMM=sshd --since "1 day ago"
journalctl _COMM=sudo --since "1 day ago"
```

## The five questions

For each question, paste the command(s) you used, two-to-three representative output lines, and your one-sentence interpretation.

### Q1 — How many successful SSH logins are recorded? Who logged in?

```bash
sudo grep "Accepted" /var/log/auth.log | wc -l
sudo grep "Accepted" /var/log/auth.log | awk '{print $9, "from", $11}'
```

Interpret: which usernames are appearing? Any service account that should *not* be receiving interactive SSH?

### Q2 — How many failed SSH login attempts? From how many distinct source IPs?

```bash
sudo grep "Failed password" /var/log/auth.log | wc -l
sudo grep "Failed password" /var/log/auth.log | awk '{print $NF}' | head    # the port
sudo grep "Failed password" /var/log/auth.log \
  | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | wc -l
```

Interpret: a server reachable on port 22/tcp from the public internet routinely sees thousands of failed attempts a day from hundreds of IPs. That is background noise, not an incident — unless one of those IPs subsequently succeeds.

### Q3 — Did any source IP both *fail* and then *succeed*?

This is the question that turns the log from "noise" into "signal."

```bash
sudo grep -E "Failed password|Accepted" /var/log/auth.log \
  | grep -oE 'Failed password.*from [0-9.]+|Accepted .*from [0-9.]+' \
  | awk '{print $1, $NF}' \
  | sort -u
```

(You may want to refine the parse for your distribution's log format.) Cross-reference: any IP that fails repeatedly and then succeeds within minutes is a *strong* signal of either a successful brute force or a legitimate user who first mistyped their password. Investigate every such match.

### Q4 — What sudo commands were run, by whom, and where from?

```bash
sudo grep "sudo:" /var/log/auth.log \
  | grep "COMMAND="
```

Interpret: for each entry, you can read the user, the TTY, the working directory, the target user, and the command. Any command that does not match an expected operator activity is a finding.

### Q5 — Did any account receive an unusual session activity pattern?

```bash
sudo grep "session opened" /var/log/auth.log
sudo grep "session closed" /var/log/auth.log
```

Look for: sessions opened in the middle of the night for a user who normally logs in during business hours; very-short-lived sessions (open and close within a second — possibly an automated check, possibly a probe); a session opened with no preceding `Accepted` line (very unusual; investigate the kernel and PAM).

## Step 6 — Your one-paragraph summary

At the bottom of your notes file, write a single paragraph (4-6 sentences) interpreting the log as a whole. Treat it as a stand-up report:

> *"In the last 24 hours on `box-01`, we observed 47 successful SSH logins (all from known IPs of operators X, Y, Z), and 6,142 failed attempts from 312 distinct source IPs. None of the failing IPs subsequently succeeded. Operator Y ran two `sudo apt update` invocations at 09:14 and 09:32 UTC. No anomalous session patterns. Nothing actionable in this window."*

That is the model. The information is specific; the conclusion is supported; the language commits to a finding.

## Acceptance criteria

- [ ] `exercise-03-auth-log.md` committed to your Week 1 notes folder.
- [ ] All five questions are answered with command + output excerpt + one-sentence interpretation.
- [ ] The closing paragraph is in stand-up-report style: specific numbers, named users, named sources, a defensible conclusion.
- [ ] If the source was a real server: you have not pasted IPs that would deanonymize someone. (Redact your own egress IP if it appears.)

## Hints

<details>
<summary>If `/var/log/auth.log` is empty on a fresh VM</summary>

That is normal on a brand-new machine. Either let the box live on the public internet for an hour with port 22 open (you will get plenty of noise) or *generate* events yourself: log out, log back in, run a few `sudo` commands. Use option 2 above.

</details>

<details>
<summary>If you only have systemd journal, no `/var/log/auth.log`</summary>

Most modern Debian and Ubuntu still write `auth.log`. If yours does not, use `journalctl _COMM=sshd` and `journalctl _COMM=sudo`. The field semantics are identical; only the formatting differs.

</details>

<details>
<summary>If you do not have a Linux box available</summary>

A free option: spin up a fresh Multipass VM (`multipass launch --name lab1`) on your laptop, SSH into it a couple of times, and use its auth.log. Multipass is free and runs on macOS, Linux, and Windows.

</details>

## Why this matters

Every incident-response engagement starts by reading the auth log of the affected host. Knowing where it lives, how to filter it for signal, and how to write a defensible one-paragraph interpretation is the entry-level skill of every blue-team role.

## Submission

Commit the file. You are now ready for the challenge and the mini-project.
