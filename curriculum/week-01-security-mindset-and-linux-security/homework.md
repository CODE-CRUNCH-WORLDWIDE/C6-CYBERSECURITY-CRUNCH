# Week 1 Homework

Six problems, ~6 hours total. Commit each in your Week 1 repo. Some require a Linux VM; do not run destructive experiments on a shared machine.

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

---

## Problem 1 — Re-state the CIA triad's limits in your own words (45 min)

Write `notes/cia-limits.md` (300-500 words) answering, in your own writing:

1. State the CIA triad.
2. Pick **three** properties from this list and give a real example, from a system you have used, where the property is *necessary* but the triad alone does not cover it: *safety, privacy, non-repudiation, accountability, recoverability, authenticity.*
3. Conclude with one sentence: "When I use the CIA triad on this track, I will also explicitly check ____, ____, and ____."

**Acceptance.** The document is 300-500 words. The examples are concrete (named system, named property, one-sentence justification). The closing sentence is unambiguous. No bullet-listing the entire alphabet of properties; pick three and be specific.

---

## Problem 2 — STRIDE pass on a public-facing service (1 h)

Pick a real public-facing service you actually use — *not* one you operate. Examples that work well: your bank's web login, a GitHub OAuth flow, a SaaS dashboard, your email provider's login page. You will **not** test it; you will only analyze its visible behavior.

Produce `notes/stride-public-service.md` containing:

1. A two-sentence description of the service and the asset(s) it protects.
2. A STRIDE table with at least one threat per letter.
3. For each threat, the *mitigation you can observe* (e.g., "MFA prompt visible," "rate limit visible after N failures," "HSTS header set," "CSRF token in form"). Use only observation — no scanning, no payloads.
4. One paragraph naming a STRIDE letter where you *cannot* tell from outside whether the mitigation is in place. Discuss what you would ask the provider in a security questionnaire.

**Acceptance.** The table has six rows (one per STRIDE letter), each with a threat and an observed-or-unknown mitigation. The closing paragraph specifies which letter is opaque from outside.

**No testing of any kind.** "Observation" means: looking at headers in DevTools, reading the login page, reading the provider's published documentation. Do not click anything you would not click as a normal user.

---

## Problem 3 — Audit one Linux box you own (45 min)

On a Linux box you administer (your VM is fine), capture and commit each of the following to `notes/box-audit.md`:

```bash
# identity
id; whoami; groups

# sudoers
sudo -l

# every setuid binary on the box
sudo find / -xdev -perm -4000 -type f 2>/dev/null

# every setgid binary
sudo find / -xdev -perm -2000 -type f 2>/dev/null

# MAC state
( command -v aa-status >/dev/null && sudo aa-status ) || \
  ( command -v getenforce >/dev/null && getenforce )

# kernel version (because Dirty Pipe / Dirty COW etc. are version-bounded)
uname -r
```

Add a one-paragraph commentary at the bottom: any binary in the `setuid` list that surprised you, any sudoers entry you would tighten, any MAC state that is not "enforcing" / "loaded."

**Acceptance.** All command outputs captured. Commentary identifies *at least one finding or non-finding with justification*. ("Nothing surprising" is acceptable iff the writer demonstrates they inspected the list, not just ran the command.)

---

## Problem 4 — Capability vs `setuid` write-up (45 min)

Write `notes/capability-vs-setuid.md` (300-500 words) answering:

1. Explain, in plain English, why `setuid`-root is a coarser privilege grant than a POSIX capability.
2. Pick a service that historically required root (`ping`, `tcpdump`, an HTTP server binding port 80). Show the exact `setcap` invocation that would let you run it without `setuid`-root. Note the specific capability granted.
3. Discuss one downside of the capability approach. (Hint: capabilities are attached to *files* on a filesystem; what happens if the binary is moved, copied, repackaged, updated by `apt`? See `man 8 setcap` for the gotcha.)

**Acceptance.** The piece names the capability, shows the `setcap` command precisely, and addresses the inheritance gotcha (the filesystem xattr does *not* survive most copies, and `apt` upgrades will replace the binary without re-applying the capability).

---

## Problem 5 — CVE deep read: pick one (1.5 h)

Pick **one** CVE from the following list. Read the advisory, the NVD entry, and at least one technical analysis (Qualys, the original researcher's blog post, or the upstream commit).

- **CVE-2021-3156 (Baron Samedit)** — sudo heap overflow.
- **CVE-2022-0847 (Dirty Pipe)** — pipe buffer arbitrary write.
- **CVE-2019-14287** — sudo user-ID bypass via `-u#-1`.

Produce `notes/cve-<id>.md` containing:

1. **The vulnerability in one paragraph.** What is the flaw, in the code, in plain English.
2. **The preconditions.** What does the attacker need (local shell? specific sudo config? specific kernel version?).
3. **The impact.** Specific privilege gained, with the CVSS score.
4. **The patch.** Link to the upstream commit. One sentence on the fix.
5. **The defender's view.** What detection or hardening would have prevented or detected exploitation: SELinux, MAC, file-integrity monitoring, kernel version pinning, sudo version pinning.

**Acceptance.** All five sections present. Direct links to NVD and to a primary technical source. The defender's view contains *at least one specific* control, not "patch faster."

---

## Problem 6 — Reflection (30 min)

Write `notes/week-01-reflection.md` (300-400 words) answering:

1. Which lecture or section changed your mental model the most?
2. What is one habit you noticed in your own thinking this week that was *not* the security mindset (e.g., "I assumed input was valid"; "I assumed the operator was honest"; "I assumed the supply chain was clean")?
3. Did Bandit teach you anything about the *defender's* view, not just the attacker's?
4. What single mitigation will you implement, on a system you own, in the next 7 days as a direct result of this week's material?

**Acceptance.** All four questions answered. Question 4 names a specific, dated commitment.

---

## Time budget

| Problem | Time |
|--------:|----:|
| 1 | 45 min |
| 2 | 1 h |
| 3 | 45 min |
| 4 | 45 min |
| 5 | 1.5 h |
| 6 | 30 min |
| **Total** | **~5 h 15 min** |

When done, push the Week 1 repo and start (or continue) the [mini-project](./mini-project/README.md).
