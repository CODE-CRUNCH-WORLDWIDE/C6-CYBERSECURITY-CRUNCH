# Week 1 — Exercises

Three hands-on drills. Each one takes 30-50 minutes. Do them in order.

1. **[Exercise 1 — Threat-model your laptop](exercise-01-threat-model-your-laptop.md)** — a one-page STRIDE pass on the machine you are reading this on. (~45 min)
2. **[Exercise 2 — Permissions and `setuid`](exercise-02-permissions-and-setuid.md)** — hands-on with `chmod`, `find -perm`, and an experimental `setuid` binary in a directory you own. (~50 min)
3. **[Exercise 3 — Read the auth log](exercise-03-read-the-auth-log.md)** — parse `/var/log/auth.log` (or `/var/log/secure`) and answer five questions about its contents. (~40 min)

## Workflow

- Type, don't paste. Muscle memory is a defensive skill.
- Run, observe, explain in your own notes before moving on.
- If you are on a shared system, do destructive experiments only in a directory you own — never in `/`, `/etc`, or anyone else's home directory.
- The `setuid` work in Exercise 2 must be done in a VM or a directory you control. **Do not** create `setuid` binaries on a multi-user box without authorization.

## Self-grading

After each exercise, ask yourself: "Could I explain this to a junior engineer in three minutes?" If yes, move on. If no, re-read the lecture material that covered it.
