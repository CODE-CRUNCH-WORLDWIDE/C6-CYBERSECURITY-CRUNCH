# Lecture 2 — The Linux Security Model

> **Outcome:** You can read any line of `ls -l` output character by character, audit a `sudoers` file, list the capabilities of a running process, and explain in one paragraph how namespaces, capabilities, and MAC stack together to limit what a compromised process can do.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Practice the techniques in this module only on:                    │
│  - machines and networks you own                                    │
│  - legal training platforms (TryHackMe, HackTheBox, picoCTF,        │
│    VulnHub, OverTheWire, pwn.college)                               │
│  - systems with explicit written permission from the owner          │
│                                                                     │
│  Unauthorized testing is a crime. C6 does not teach crime.          │
└─────────────────────────────────────────────────────────────────────┘
```

This lecture is hands-on. Have a Linux shell open. Type the commands. Read what the system tells you.

## 1. Why the Linux security model matters

Most servers you will ever defend run Linux. Most container runtimes run on Linux. Most cloud workloads run on Linux. Most privilege-escalation findings in penetration tests and CTFs reduce to "someone got the Linux security model wrong" — a stray world-writable file, a forgotten `setuid` binary, a `sudoers` rule that grants more than the author realized, a service running as root that did not need to.

The Linux model has four interlocking layers, each one a backstop for the layer above:

1. **Users and groups (Discretionary Access Control).** Every file has an owner and a group. Every process runs as a user. The owner gets to set permissions. This is the layer you spent most of C14 on.
2. **POSIX capabilities.** Root's all-powerful UID-0 privilege is split into ~40 discrete capabilities that can be granted independently. A binary can listen on port 80 without ever being root.
3. **Namespaces and cgroups.** The kernel can pretend, to a particular process, that it has its own root filesystem, its own PID space, its own network. This is how containers work; it is also a security boundary.
4. **Mandatory Access Control (SELinux, AppArmor).** A system-wide policy that constrains *everyone*, including root, beyond what DAC permits. The owner cannot override it.

We will walk through each. By the end you will be able to read a server's security posture without running anything more exotic than `ls`, `id`, `getcap`, `aa-status`, and `cat`.

---

## 2. Users, groups, and UIDs

A **user** on Linux is an entry in `/etc/passwd`. A **group** is an entry in `/etc/group`. Every running process has a numeric **user ID (UID)** and one or more numeric **group IDs (GIDs)**.

```bash
$ id
uid=1000(alice) gid=1000(alice) groups=1000(alice),27(sudo),100(users)
```

A few things worth knowing about UIDs:

- **UID 0 is root.** The kernel checks `uid == 0` in many code paths. "Becoming root" is becoming UID 0 (subject to capabilities, namespaces, MAC).
- **UIDs below 1000** are typically system accounts (`bin`, `daemon`, `sshd`, `_apt`). They exist so that long-running services can run as a non-root user with no shell and no home directory.
- **UIDs from 1000 up** are typically real human users on a desktop system; on a server, usually only one or two — `ubuntu`, `ec2-user`, your own.
- A user's *effective* UID can differ from their *real* UID, thanks to `setuid` (Section 4). This is a frequent source of bugs.

`/etc/passwd` is world-readable. It contains usernames, UIDs, GIDs, the home directory, and the login shell. It does **not** contain password hashes — those live in `/etc/shadow`, which is readable only by root, exactly because a world-readable hash gives an attacker an offline cracking target.

```bash
$ getent passwd alice
alice:x:1000:1000:Alice Example,,,:/home/alice:/bin/bash

$ sudo getent shadow alice
alice:$y$j9T$...:19412:0:99999:7:::
```

The `$y$` prefix is yescrypt; you may also see `$6$` (SHA-512), `$2b$` (bcrypt), `$1$` (legacy MD5 — never on a modern box). If you ever see `$1$` in production, that is a finding.

---

## 3. File permissions, character by character

```bash
$ ls -l /etc/shadow /usr/bin/passwd /tmp
-rw-r-----  1 root shadow  1789 Mar  3 09:12 /etc/shadow
-rwsr-xr-x  1 root root   59976 Apr 11 14:00 /usr/bin/passwd
drwxrwxrwt 18 root root    4096 May 13 09:30 /tmp
```

Each line begins with ten characters. Read them in three groups of three, plus the leading type:

| Position | Meaning |
|----------|---------|
| 1 | File type: `-` regular, `d` directory, `l` symlink, `b` block device, `c` character device, `s` socket, `p` named pipe |
| 2-4 | **Owner's** rights: `r` read, `w` write, `x` execute (or `s` / `S` if `setuid`) |
| 5-7 | **Group's** rights: `r` read, `w` write, `x` execute (or `s` / `S` if `setgid`) |
| 8-10 | **Other's** rights: `r` read, `w` write, `x` execute (or `t` / `T` if sticky) |

The same bits, octally:

| Octal | Binary | Symbolic |
|---|---|---|
| 4 | 100 | r |
| 2 | 010 | w |
| 1 | 001 | x |

So `0644` is `rw-r--r--`; `0755` is `rwxr-xr-x`; `0600` is `rw-------`. **Memorize these three.**

### What `x` means depends on the file type

- For a **regular file**, `x` allows the kernel to load and execute it (assuming the file is a binary or has a `#!` shebang).
- For a **directory**, `x` allows you to *enter* it (traverse, `cd` into it). Without `x` on a directory, even with `r`, you can list entries but cannot `stat` them.

That asymmetry trips junior engineers. A common bug:

```bash
$ ls -ld /home/alice /home/alice/.ssh
drwx------ 8 alice alice 4096 May 13 10:01 /home/alice
drwxr--r-- 2 alice alice 4096 May 13 10:01 /home/alice/.ssh   # r without x
```

`/home/alice/.ssh` is `r--` — readable but not traversable by `alice` herself (the missing `x` on `.ssh` blocks `ssh`'s own access to `authorized_keys`). SSH fails with an opaque error. The fix is `chmod 700 ~/.ssh`.

---

## 4. setuid, setgid, and the sticky bit

The three "special" permission bits live in the high octal digit (the fourth digit, before the usual three):

| Bit | Octal | Symbolic | What it does |
|---|---:|---|---|
| `setuid` | 4000 | `s` in owner-`x` slot | When the file is executed, the process runs with the file owner's **effective UID** instead of the caller's. |
| `setgid` | 2000 | `s` in group-`x` slot | On a binary: process runs with the file's group EGID. On a directory: files created inside inherit the directory's group. |
| sticky  | 1000 | `t` in other-`x` slot | On a directory: only the file's owner (or root) can delete or rename files inside, regardless of write permissions on the directory. |

### `setuid` — the dangerous bit

`/usr/bin/passwd` is `setuid`-root. It has to be: it has to rewrite `/etc/shadow`, which only root can write, but it must be executable by ordinary users so they can change their own password. The bit lets an unprivileged user run a tightly-controlled program that briefly becomes root inside the program's logic.

The trade-off: every `setuid`-root binary is a tiny privilege-escalation foothold *waiting to be found.* Any bug in such a binary — a buffer overflow, a `$PATH` injection, a missing sanity check on environment variables, a race condition — is a local privilege escalation. The history of `sudo` itself includes CVE-2021-3156 ("Baron Samedit"), a heap overflow reachable by *any* local user simply by invoking `sudoedit` with a crafted argument. That CVE got a 7.8 CVSS score. The bug had been latent for ten years.

**Find every `setuid` binary on a box you administer.** This is a routine defensive task:

```bash
$ find / -xdev -perm -4000 -type f 2>/dev/null
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/lib/openssh/ssh-keysign
...
```

Anything in that list that is **not** part of your distribution's standard install is a finding. Anything in `/home`, `/tmp`, `/opt`, or `/usr/local` is *especially* a finding. Document the list. Diff it weekly. Investigate new entries the day they appear.

### `setgid` on a directory

`setgid` on a directory makes new files inherit the directory's group. This is how shared-project directories work:

```bash
$ sudo mkdir /srv/project
$ sudo chown alice:engineers /srv/project
$ sudo chmod 2770 /srv/project          # the leading 2 is setgid
```

Any file `alice` creates in `/srv/project` is owned by group `engineers`, not by group `alice`. Everyone in `engineers` can collaborate. No one outside can read.

### The sticky bit on `/tmp`

`/tmp` is world-writable (`drwxrwxrwt`) — every user must be able to create files there. Without the sticky bit, every user could also *delete* every other user's files, since directory write permission alone grants the right to remove entries. The `t` prevents that: in a sticky directory, only the file owner (or root) may unlink. Look for the `t` on `/tmp`, `/var/tmp`, `/dev/shm` — if it is missing, that is a finding.

---

## 5. The principle of least privilege

**Every principal should have only the privileges required to perform its function, for only as long as it needs them.**

That sentence is the entire principle. It has three operational consequences:

1. **Run services as their own non-root user.** `nginx` runs as `www-data`. `postgresql` runs as `postgres`. If `nginx` is compromised, the attacker gets `www-data`, not root.
2. **Drop privileges as early as possible.** A daemon that needs to bind port 80 starts as root, binds the socket, then calls `setuid()` to become its service user. From that moment on, even if exploited, the process has no UID-0 power.
3. **Grant only the specific capability needed.** Better still, skip the "start as root" step entirely by giving the binary `CAP_NET_BIND_SERVICE` (Section 7) and letting it bind low ports without ever being root.

Examples of failures of the principle, all common:

- A web app's database user is `GRANT ALL PRIVILEGES`. It needs `SELECT` on three tables. SQLi → full database compromise instead of a contained leak.
- A backup script runs from cron as root because it was "easier than getting permissions right." A bug in the script lets an attacker write to `/root/.ssh/authorized_keys`.
- A developer's laptop sudo entry is `ALL=(ALL) NOPASSWD: ALL`. A malicious npm package executes one `sudo` command and the laptop is owned.

Every C6 graduate should be the engineer in the code review who asks "what is the smallest privilege this could run with?" — and then says nothing else, because the question itself usually finds the bug.

---

## 6. `sudo` and `/etc/sudoers`

`sudo` is the mechanism by which an unprivileged user is granted the ability to run *specific* commands as *specific* other users, with *specific* requirements. It is also a `setuid`-root binary, which is why every sudo CVE is a serious one.

The configuration lives in `/etc/sudoers` and the drop-in directory `/etc/sudoers.d/`. Edit **only** via `visudo`, which validates the file before saving — a syntax error in `sudoers` can lock everyone out of sudo on the box.

A representative `sudoers` line:

```
alice  ALL=(ALL:ALL) ALL
```

Read this as: "User `alice`, on `ALL` hosts, may run `ALL` commands as `(ALL` users `:ALL` groups), the command being `ALL`." Effectively: alice can do anything.

A safer line:

```
deployer  ALL=(www-data) NOPASSWD: /usr/bin/systemctl reload nginx
```

`deployer` may, as `www-data`, with no password prompt, run **only** `systemctl reload nginx`. The narrower the rule, the smaller the attack surface.

### What to look for in a `sudoers` audit

- **`NOPASSWD`** entries — every one is a finding unless you can defend it. The password requirement is the second factor on a stolen developer account.
- **Wildcards** in command paths (`/usr/bin/systemctl *`). Wildcards on `sudo` rules have caused privilege-escalation vulnerabilities in the past — e.g., `*` matching `--something-dangerous`.
- **`Defaults targetpw`** — if absent, `sudo` accepts the *invoker's* password, not the target user's. Almost always you want the default behavior; targetpw is unusual.
- **`Defaults !requiretty`** — sometimes needed for scripts, but harmless rules sometimes get added "to make it work" without anyone reconsidering the security implications.
- **Drop-in files** in `/etc/sudoers.d/`. Vendor scripts add files there. Read every one.

Your own privileges:

```bash
$ sudo -l
User alice may run the following commands on this host:
    (ALL : ALL) ALL
```

Run this on every server you administer. Be surprised at what you find.

---

## 7. POSIX capabilities

The classical Linux model has exactly one privilege boundary: root or not root. That is too coarse. A program that binds port 80 should not also be able to load arbitrary kernel modules. POSIX capabilities, introduced in kernel 2.2 (1999) and refined in 2.6+, split root's power into ~40 discrete privileges that can be granted independently.

The capabilities you will most often see:

| Capability | What it grants |
|------------|----------------|
| `CAP_NET_BIND_SERVICE` | Bind to TCP/UDP ports < 1024 |
| `CAP_NET_RAW` | Open raw sockets (ping, traceroute) |
| `CAP_NET_ADMIN` | Configure network interfaces, routes, firewall |
| `CAP_SYS_ADMIN` | The "kitchen-sink" capability; nearly equivalent to root. Avoid. |
| `CAP_SYS_PTRACE` | Trace any process (`strace`, `gdb -p`) |
| `CAP_DAC_OVERRIDE` | Bypass file read/write/execute permission checks |
| `CAP_CHOWN` | Change file ownership |
| `CAP_KILL` | Send signals to processes not owned by the caller |
| `CAP_SETUID` | Manipulate UIDs |
| `CAP_AUDIT_WRITE` | Write records to the kernel auditing log |

Read the full list with `man 7 capabilities`.

The canonical example: instead of running an HTTP server as root just to bind port 80, give the binary the capability:

```bash
$ sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/mywebserver
$ getcap /usr/local/bin/mywebserver
/usr/local/bin/mywebserver = cap_net_bind_service+ep
```

Now `mywebserver` can be started by an unprivileged user and bind port 80. If the process is compromised, the attacker has the rights of that unprivileged user *plus* `CAP_NET_BIND_SERVICE` — a much smaller blast radius than "is root."

You can inspect a running process's capabilities:

```bash
$ getpcaps $(pgrep -f mywebserver)
2417: cap_net_bind_service+ep
```

A `setuid`-root binary is a sledgehammer. A capability is a chisel. Modern security engineering prefers the chisel.

---

## 8. Namespaces and cgroups

If capabilities subdivide root, **namespaces** subdivide the system itself. A namespace makes the kernel pretend, to a particular process, that some part of the system is exclusively its own:

| Namespace | What it isolates |
|-----------|------------------|
| `mnt` | Mount points (the filesystem view) |
| `pid` | Process IDs (PID 1 inside is some other PID outside) |
| `net` | Network interfaces, routing tables, firewall rules |
| `ipc` | System V IPC, POSIX message queues |
| `uts` | Hostname, NIS domain name |
| `user` | UID/GID mappings (a process can be UID 0 inside, UID 1000 outside) |
| `cgroup` | The cgroup hierarchy view |
| `time` | The system clock (kernel 5.6+) |

A **container** is, roughly, a process started inside a fresh set of these namespaces, with a few capabilities dropped and a cgroup-imposed resource limit attached. Docker, podman, systemd-nspawn, LXC — different orchestrators, same kernel primitives.

**cgroups** (control groups) limit and account for resource usage by a group of processes: CPU, memory, IO, network, devices. The security angle: a cgroup limit on memory and PIDs prevents a fork-bomb or a memory-exhaustion DoS from a single misbehaving service from taking down the box.

You can play with namespaces directly:

```bash
$ sudo unshare --pid --fork --mount-proc bash
# (you are now in a new PID namespace; ps will see only the processes inside it)
# ps -ef
UID  PID  PPID  CMD
root   1     0  bash
root   2     1  ps -ef
```

Containers are not a hard security boundary in the same sense a VM is — a kernel CVE compromises the kernel that all containers share. But namespaces + capabilities + seccomp + MAC (next section) layered together provide a meaningful one. The defender's view: assume any single layer can fail, plan for it.

---

## 9. Mandatory Access Control: SELinux and AppArmor

DAC — the `rwx` model — is *discretionary*: the file owner decides who gets what. That is fine for normal user data, and it is exactly wrong for system policy: an attacker who compromises a service as that service's user should not be able to read every file that service's user can read.

**Mandatory Access Control (MAC)** is a system-wide policy, set by the administrator, that constrains *every* process — including root — beyond DAC. Two implementations dominate Linux:

- **SELinux** (NSA, Red Hat) — label-based. Every file and process has a context like `system_u:object_r:httpd_sys_content_t:s0`. Policy says which contexts can access which. Powerful, granular, hard to write from scratch — almost always you use the distribution's reference policy.
- **AppArmor** (Canonical, SUSE) — path-based. Profiles say "this binary, at this path, may read these paths and execute these binaries." Simpler than SELinux, less granular, easier to write.

Most Red Hat / Fedora / CentOS Stream boxes run SELinux. Most Ubuntu boxes run AppArmor. Both ship default profiles for common services.

Inspect:

```bash
# Red Hat family
$ getenforce
Enforcing
$ ls -Z /etc/shadow
system_u:object_r:shadow_t:s0 /etc/shadow

# Debian / Ubuntu family
$ sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
40 profiles are in enforce mode.
   ...
1 process is in enforce mode.
   /usr/sbin/cupsd (1437)
```

The defender's view: MAC is the layer that catches the bugs in the layer below. A web server compromised inside its AppArmor profile cannot read `/etc/shadow` even if the server is running as root — because the profile forbids it, and the kernel enforces the profile.

A common anti-pattern in incident response: an investigator finds the breach was prevented from escalating *because* SELinux denied a forbidden operation; the engineer's first instinct is to add an `allow` rule "to make the warning go away." Resist this. Every SELinux denial in `/var/log/audit/audit.log` deserves investigation, not suppression.

---

## 10. Auth logs: where authentication and authorization events are recorded

When a user logs in, runs `sudo`, fails a password, or opens an SSH session, that event is written to a system log. The location depends on distribution:

| Distribution | File |
|---|---|
| Debian / Ubuntu | `/var/log/auth.log` |
| RHEL / Fedora / CentOS Stream | `/var/log/secure` |
| systemd journal (any modern distro) | `journalctl _COMM=sshd`, `journalctl _COMM=sudo` |

A real `auth.log` entry for a successful SSH login:

```
May 13 09:23:14 box sshd[3142]: Accepted publickey for alice from 198.51.100.42 port 51234 ssh2: ED25519 SHA256:abc...
May 13 09:23:14 box sshd[3142]: pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)
```

For a failed password:

```
May 13 09:24:01 box sshd[3158]: Failed password for invalid user admin from 203.0.113.7 port 44012 ssh2
May 13 09:24:01 box sshd[3158]: Connection closed by invalid user admin 203.0.113.7 port 44012 [preauth]
```

For `sudo`:

```
May 13 09:25:33 box sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update
```

Three things to look for routinely:

1. **`Failed password`** spikes — a brute force in progress. Cross-check the source IP against your normal access patterns.
2. **`Accepted publickey`** for accounts that should not be receiving SSH logins. A service account with a successful interactive login is a finding.
3. **`sudo`** entries that do not correspond to a known operator activity. Every sudo invocation should be explicable.

Exercise 3 this week asks you to do exactly this on a real (or provided) log.

---

## 11. Self-check

Without re-reading:

1. What does the leading `s` in `-rwsr-xr-x` mean? What is the security risk it introduces?
2. State the principle of least privilege in one sentence.
3. Give two reasons `/etc/shadow` is mode `0640` and not `0644`.
4. What is the difference between a `setuid`-root binary and a binary with `CAP_NET_BIND_SERVICE`?
5. Why does enabling `NOPASSWD` in `sudoers` weaken the security posture, even for a user who is "already trusted"?
6. Name three namespaces and what each isolates.
7. On a Debian/Ubuntu box, where do `sshd` and `sudo` write their event logs?
8. An SELinux denial appears in `audit.log`. A junior engineer suggests adding an `allow` rule. What is your response?

---

## Further reading

- **`man 7 capabilities`** — the authoritative reference. Read it.
- **`man 5 sudoers`** — every line.
- **CVE-2021-3156 — "Baron Samedit"**: <https://nvd.nist.gov/vuln/detail/CVE-2021-3156>
- **Linux Kernel docs — security subsystem**: <https://www.kernel.org/doc/html/latest/security/index.html>
- **SELinux Notebook**: <https://github.com/SELinuxProject/selinux-notebook/blob/main/src/toc.md>
- **AppArmor wiki**: <https://gitlab.com/apparmor/apparmor/-/wikis/Documentation>

Next, the [exercises](../exercises/README.md). Then [Bandit levels 0-5](../challenges/challenge-01-overthewire-bandit.md). Then the [mini-project](../mini-project/README.md).
