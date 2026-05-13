# Exercise 2 — Permissions and `setuid`

**Time:** ~50 minutes.
**Outcome:** You have set, inspected, and removed each of the special permission bits (`setuid`, `setgid`, sticky) by hand; you have used `find` to locate every `setuid` binary on a Linux box; and you understand, from a tested example, why a world-writable `setuid` binary is the worst combination of bits in Unix.

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

> **Where to do this.** Use a Linux VM you own (Ubuntu 24.04, Debian 12, Fedora 40 — all fine), or WSL2, or a personal Linux box. **Do not** create `setuid` binaries on a multi-user system. A scratch directory `~/c6-week01-perms/` is sufficient.

## Problem statement

You will work through five short tasks. Capture each command and its output in a single note file `exercise-02-permissions.md`. The notes must include both *what you ran* and *the system's response*.

## Setup

```bash
mkdir -p ~/c6-week01-perms && cd ~/c6-week01-perms
echo "hello" > file.txt
ls -l file.txt
```

Record the output. Note the mode string. You should see `-rw-r--r--` or `-rw-rw-r--` depending on your umask. Note your `umask` value: `umask`.

## Task 1 — Read a mode by hand (5 min)

Without using `chmod`, write out the binary, octal, and symbolic forms of the following modes:

| Symbolic | Octal | Binary (owner / group / other) |
|----------|-------|--------------------------------|
| `rw-r--r--` | ? | ? |
| `rwxr-xr-x` | ? | ? |
| `rw-------` | ? | ? |
| `rwxr-x---` | ? | ? |
| `rws--x--x` | ? | ? |
| `rwxrwxrwt` | ? | ? |

Put your answers in the notes file. (Yes, the last two have special bits.)

## Task 2 — `chmod` the four representations (10 min)

For each of these four invocations, predict the resulting mode, then run it and verify:

```bash
chmod 640 file.txt && ls -l file.txt
chmod u+x,g-r,o= file.txt && ls -l file.txt
chmod 0755 file.txt && ls -l file.txt
chmod a=r file.txt && ls -l file.txt
```

Note the difference between octal (absolute) and symbolic (relative). Symbolic only changes the bits you mention. Octal sets the entire mode.

## Task 3 — Inventory every `setuid` binary on the box (10 min)

```bash
find / -xdev -perm -4000 -type f 2>/dev/null
```

Save the output to `setuid-inventory.txt`. Then in your notes file:

1. List the count.
2. Pick *two* binaries from the list. For each, look up its man page and explain in one sentence why it needs to be `setuid`-root.
3. Identify any path that surprises you. (Common surprises: a vendor's `*-wrapper` script under `/opt`, an old `ping` binary still `setuid` even on a system whose kernel accepts `CAP_NET_RAW`.)

Now run the same against `setgid`:

```bash
find / -xdev -perm -2000 -type f 2>/dev/null
```

Note any binary that has both `setuid` and `setgid` set.

## Task 4 — Build a tiny `setuid` demo in a directory you own (15 min)

> Read the AUTHORIZED USE banner above before you do this. It applies to your own VM.

In your scratch directory:

```bash
cat > whoami_demo.c <<'EOF'
#include <stdio.h>
#include <unistd.h>
int main(void) {
    printf("real uid:      %d\n", getuid());
    printf("effective uid: %d\n", geteuid());
    return 0;
}
EOF
cc -o whoami_demo whoami_demo.c
./whoami_demo
```

You should see `real == effective`. Now make the binary `setuid`-root (requires sudo on your own box):

```bash
sudo chown root:root whoami_demo
sudo chmod 4755 whoami_demo
ls -l whoami_demo
./whoami_demo
```

Capture the output. Note that the effective UID is now `0`, even though the real UID is your normal user. This is the entire `setuid` mechanic in one screen.

Now answer in your notes:

1. If `whoami_demo` had a buffer-overflow bug, what would an attacker who exploits it obtain?
2. If `whoami_demo` were world-writable (`-rwsrwxrwx`), what could *any local user* do?
3. After the experiment, clean up: `sudo chmod 0755 whoami_demo && sudo chown $USER:$USER whoami_demo`. Why is "leave no `setuid` binaries lying around your home directory" itself a hygiene rule?

## Task 5 — Sticky bit on `/tmp` (10 min)

```bash
ls -ld /tmp
```

You should see `drwxrwxrwt`. The trailing `t` is the sticky bit. In your notes, answer:

1. Why does `/tmp` need to be world-writable?
2. Without the sticky bit, what could user `alice` do to user `bob`'s file under `/tmp`?
3. What does the sticky bit prevent? (Hint: it prevents one specific operation — name it precisely.)
4. Run `ls -ld /var/tmp /dev/shm`. Are they sticky? If any are not, that is a finding on this box.

## Acceptance criteria

- [ ] `exercise-02-permissions.md` committed to your Week 1 notes folder.
- [ ] Task 1 table is filled in with correct binary, octal, and symbolic values for all six rows.
- [ ] Task 2 includes pre-run *prediction* of each mode, then the actual `ls -l` output.
- [ ] Task 3 names the `setuid` count, two binaries with their justification, and any surprises.
- [ ] Task 4 includes the compile, the `setuid`-grant, the `./whoami_demo` output, and the three-question reflection.
- [ ] Task 5 answers all four sticky-bit questions.
- [ ] The scratch directory is *cleaned up*: no `setuid` binary left behind.

## Hints

<details>
<summary>If `cc` is not installed</summary>

`sudo apt install build-essential` on Debian/Ubuntu; `sudo dnf groupinstall "Development Tools"` on Fedora; `xcode-select --install` on macOS (though this exercise expects Linux).

</details>

<details>
<summary>If `chmod 4755` does not "stick" — the bit disappears on the next `chown`</summary>

`chown` clears the `setuid` and `setgid` bits as a safety measure. Always `chown` *before* `chmod` when setting these bits, or re-apply `chmod` afterward. This is a subtle bit of Unix history you will see again.

</details>

<details>
<summary>If `find` floods stderr with permission-denied warnings</summary>

`2>/dev/null` suppresses them. We do that throughout this track because the warnings are not the finding; the *matches* are.

</details>

## Why this matters

`setuid` is the most-audited construct on a Linux system in any privilege-escalation engagement. Knowing it from the inside — that you can grant it, that the kernel honors it on `exec`, that any bug becomes a privesc — turns "what is this `-rws` thing" from trivia into a defensive instinct.

## Submission

Commit the notes file. Move on to Exercise 3.
