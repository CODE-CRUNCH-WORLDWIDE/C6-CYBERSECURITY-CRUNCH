# Challenge 1 — OverTheWire Bandit, levels 0-5

**Time estimate:** ~3 hours (faster if you are already comfortable in a shell).

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

OverTheWire Bandit (<https://overthewire.org/wargames/bandit/>) is a free public SSH-based wargame, intentionally vulnerable, **expressly designed for exactly this kind of curriculum**. The OverTheWire project authorizes use; that is what "wargame" means in this context. There is no ethics question to navigate here, only your own progress.

## Problem statement

Solve **Bandit levels 0 through 5** (Bandit0 → Bandit6). For each level, produce:

- The command(s) you used.
- The password / flag you recovered (so you can re-verify and so a peer can audit).
- A one-sentence note: *what this level taught me.*

Submit `notes/bandit-0-to-5.md` containing all six levels.

## Acceptance criteria

- [ ] You have SSH-ed into `bandit.labs.overthewire.org` on port 2220 as `bandit0`.
- [ ] You have advanced to `bandit6` (i.e., you have the password for `bandit6` recorded in your notes).
- [ ] Your notes file contains, for each level 0-5: the command(s), the recovered secret, and the one-line lesson.
- [ ] You have not pasted Bandit passwords on a public forum — the OverTheWire site asks you not to, and your notes file should live in a *private* notes repo until you redact the passwords. (When you push your homework, *redact the passwords* — leave the commands and the lessons.)

## Why each level is in this challenge

Bandit 0-5 is not "five random Unix puzzles." Each level rehearses a specific defensive skill:

| Level | Skill rehearsed | Defensive parallel |
|---|---|---|
| 0 | Connect via SSH on a non-standard port; read a file in your home directory | Standard operator workflow on a managed host |
| 1 | Read a file named `-` | Quoting; not relying on argv interpretation. Bugs hide here. |
| 2 | Read a file with spaces in its name | Filename hygiene; injection through filenames |
| 3 | Find a hidden (`.`-prefixed) file | Attackers love hidden directories; defenders learn to enumerate them |
| 4 | Pick out the only human-readable file from a directory of binaries (`file`) | Triaging an unknown directory in incident response |
| 5 | Use `find` predicates to locate a file matching size, type, and not-readable-by-others | The defender's primary tool for "what files match this property on my system" — and what every privesc enumeration script uses |

By the end of level 5 you have used `find -size`, `find -type`, `find ! -executable`, and `find -readable` — and you will use those exact predicates again in Exercise 2's `find / -perm -4000` and again in Week 8's privilege-escalation labs.

## Walkthrough scaffolding

> *Do **not** read the spoilers under the `<details>` blocks until you have spent at least 15 minutes on the level.*

### Level 0 — Connecting

The site tells you the host (`bandit.labs.overthewire.org`), the port (`2220`), and that the level-0 user is `bandit0`, password `bandit0`.

```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```

Then read the file in your home directory called `readme`. The contents are the password to `bandit1`.

<details>
<summary>Solution</summary>

```bash
cat readme
```

</details>

### Level 1 — A file literally called `-`

`bandit1`'s home directory contains a single file named `-`. Try `cat -` and observe that it does *not* do what you expect (it reads stdin). You need to refer to the file by a path that does not start with `-`.

<details>
<summary>Solution</summary>

```bash
cat ./-
# or
cat < -
```

The lesson: any time a filename starts with a `-`, programs are likely to interpret it as a flag. `./` is the universal escape.

</details>

### Level 2 — A file with spaces in its name

```bash
ls
# spaces in this filename
```

<details>
<summary>Solution</summary>

```bash
cat "spaces in this filename"
# or
cat spaces\ in\ this\ filename
```

</details>

### Level 3 — Hidden file in a directory

`ls` shows an empty `inhere/`. It is not empty.

<details>
<summary>Solution</summary>

```bash
cd inhere
ls -la
cat .hidden    # or whatever the dotfile is named
```

`-a` to `ls` shows dotfiles. Hidden does not mean secure.

</details>

### Level 4 — One readable file among many

`inhere/` has ten files, named like `-file00`, `-file01`, ... Most contain binary. One contains the password.

<details>
<summary>Solution</summary>

```bash
cd inhere
file ./*
# read the one labeled "ASCII text"
cat ./-file07     # or whichever one was ASCII
```

`file` is your friend whenever you have a directory of unknown blobs.

</details>

### Level 5 — `find` with predicates

`inhere/` contains many subdirectories. The password file is, per the level description: human-readable, 1033 bytes in size, and not executable.

<details>
<summary>Solution</summary>

```bash
find inhere/ -type f -size 1033c ! -executable -readable
# then read the single match with cat
```

`c` after a size means bytes. The `!` negates `-executable`. This combination is exactly the kind of predicate combination used by enumeration scripts on real engagements (linpeas, linenum, etc.).

</details>

## Stretch

- Continue through level 10. Levels 6-10 introduce `find` over the whole filesystem, `nc` (netcat — see Week 2), and base64 decoding. All useful.
- Read the levels' source on the OverTheWire wiki and ask yourself: what defensive control would have prevented each level's solution? (Often: file permissions; sometimes: better hygiene around hidden files; once or twice: nothing — the level is deliberately permissive to teach the technique.)

## Notes on submission

Your `notes/bandit-0-to-5.md` should contain, per level:

```
### Level N → Level N+1
Command(s):
    ...
Secret: <REDACTED — see private notes>
Lesson: ...
```

That is enough for a peer to confirm you did the work without spreading the Bandit answers further than the OverTheWire community asks them to be spread.

## Why this matters

Bandit is the single most-recommended starting CTF in the field. Every junior security engineer interview that asks "have you done any wargames?" expects, at minimum, "yes, OverTheWire Bandit, through level X." You are doing it because every reasonable person agrees it works.

## Submission

Commit the (redacted) notes file. Update your portfolio README with the level you reached.
