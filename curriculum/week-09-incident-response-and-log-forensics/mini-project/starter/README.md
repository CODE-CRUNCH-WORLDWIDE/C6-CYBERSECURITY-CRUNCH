# Starter — IR primary handoff brief

> *Written in-character as the IR primary handing the artefacts to the analyst who will produce the report.*

---

## Handoff

The artefacts in `logs/` were collected from `web-prod-02` between **02:47 and 04:30 UTC on 2026-05-14** by the IR team. The acquisition sequence was:

1. **02:54:01Z** — host network-isolated to the IR management VLAN (ACL change).
2. **02:54:30Z** — `tar czvf /tmp/varlog.tar.gz /var/log/` (the responder's first action on the host after isolation; preserves the rsyslog text logs before any further analysis disturbs them).
3. **02:55:10Z** — `journalctl -o json --no-pager > /tmp/journal.jsonl` (the journal exported in machine-readable form).
4. **02:56:00Z** — `find / -xdev -mtime -7 -printf '%T+ %p\n' 2>/dev/null > /tmp/find-mtime-7d.txt` (filesystem timeline).
5. **02:57:33Z** — `cat /home/deploy/.bash_history > /tmp/bash_history.txt` (the user's history file, preserved as-is — the file *is* empty on disk because the attacker ran `history -c`; what is preserved here is the empty file plus a note from the responder).
6. **03:01:11Z** — `cat /var/spool/cron/crontabs/support > /tmp/crontab-support.txt` (the cron entry the attacker installed under the `support` user).
7. **03:05:00Z** — `avml /tmp/memory.lime` (memory acquisition; the responder later ran `vol -f /tmp/memory.lime linux.bash > /tmp/memory-strings.txt` against it on the analysis host, which is the file you have).
8. **03:21:44Z** — every artefact hashed (SHA-256 and MD5). Hashes recorded in the field custody-log notebook.
9. **03:25:42Z** — artefacts transferred via `scp` to the IR analysis host.
10. **03:40:11Z** — re-hashing on the analysis host; all matches confirmed.

The full custody log is *not* yet written. **Producing it is one of your deliverables.** Run `../exercises/exercise-04-custody-log.py generate` against `logs/`.

---

## Artefact catalogue

- **`logs/auth.log`** — `/var/log/auth.log` for the incident day. 60 minutes pre-alert through 90 minutes post-alert. SSH and sudo events.
- **`logs/access.log`** — `nginx` `combined`-format access log. Same window.
- **`logs/error.log`** — `nginx` error log. Same window. Useful for one detail.
- **`logs/journal.jsonl`** — `journalctl -o json --no-pager` export, same window.
- **`logs/bash_history.txt`** — the on-disk `~deploy/.bash_history`. Empty. The first line is a comment from the responder noting the file was empty at acquisition time and the memory-strings file contains the recovered commands.
- **`logs/crontab-support.txt`** — `/var/spool/cron/crontabs/support`. The cron entry the attacker installed.
- **`logs/memory-strings.txt`** — output of `vol -f memory.lime linux.bash` on the analysis host. Recovers the bash history from the running shell process's heap.
- **`logs/find-mtime-7d.txt`** — output of `find / -xdev -mtime -7 -printf '%T+ %p\n'`. The filesystem timeline; the attacker-staged files appear here.

---

## What you know already (the IR primary's summary)

The alert fired at 02:47:13Z. The triage by the on-call analyst (you, in Exercise 1) classified as S2 and isolated the host. The first deep look at the artefacts suggests:

- The attacker scanned the host's web tier with `zgrab` starting around 02:46.
- The attacker discovered `/.git/HEAD` was accessible and recovered the application's repository.
- The repository contained a public-key file at `deploy/keys/deploy.pub` that the developer had accidentally committed *alongside* the matching private key in a sibling file. The attacker recovered the private key from `.git` objects.
- The attacker used the private key to SSH in as `deploy` (the SSH brute-force was a head-fake: 14 quick failed attempts at common admin names, then the publickey login).
- Post-foothold, the attacker `sudo`'d to root using the deploy user's restricted sudo path (the sudo rule is buggy in a way that allows arbitrary shells; see the original `sudoers` snippet inside `find-mtime-7d.txt`'s file list).
- The attacker dropped `/tmp/.x` (a 4.2 MB ELF binary; the SHA-256 is recoverable from your filesystem timeline), set up persistence via a new user `support` plus a cron entry, dumped `/etc/shadow`, archived `/home/customers/`, exfiltrated the archive via `curl POST`, and cleared the bash history.
- The attacker's source IP throughout was `198.51.100.7`. The egress destination was `198.51.100.7:8443` (same IP, different port — they ran a small receiver on a non-standard port on the same VPS).

---

## What you do not know yet

- The attacker's bash history *between* the `history -c` and the SSH disconnect. Volatility's `linux.bash` recovered most of it (in `memory-strings.txt`); but the recovery is partial because the shell exited cleanly and the heap was reclaimed. Some of the post-exfiltration commands are not recoverable.
- Whether the attacker accessed any host *other* than `web-prod-02`. The team checked the SSH logs on the bastion (where the attacker was *not* present) and on `ci-runner-01` (where they *were not* present); no lateral movement is evidenced. The mini-project assumes the compromise was confined to `web-prod-02`.
- Whether `/home/customers/` actually contained customer PII. The directory existed; the archive was created; the size suggests substantial content; whether the content is in-scope for breach-notification clocks is the legal team's call, not yours. Your job is to surface the *facts*; the legal team makes the *disclosure decision*.

---

## What you do next

Open the mini-project's `README.md` if you have not already; the deliverable list is there. Then begin with the timeline. Open the artefact directory; run the triage and timeline-builder scripts; let the output drive your investigation.

The expected output of a good 6-hour mini-project: a 200-word executive summary that an executive could read once and understand; a 150-line full timeline; an 8-15 IOC export; an ATT&CK map covering every timeline event; a 1500-2500 word report; a clean custody log; a runbook delta with three concrete changes.

Good hunting.

---

*— IR primary, 04:30Z*
