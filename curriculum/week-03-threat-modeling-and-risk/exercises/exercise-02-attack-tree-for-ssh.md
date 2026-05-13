# Exercise 2 — Attack Tree for "Compromise an SSH-accessible Linux Server"

**Estimated time:** 45 minutes. Pen and paper preferred for the first pass; transcribe to Markdown for the deliverable.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  This is a paper exercise. Build the attack tree on paper. Do not   │
│  test any of these techniques against a host you do not own or have │
│  written authorization for. The tree is the deliverable — not a     │
│  successful exploit.                                                │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

You are threat-modeling the SSH access path to a Linux server you operate on the public internet. The server has:

- A single non-root administrative user account (e.g. `admin`), used for all administration.
- Root login *disabled* over SSH (`PermitRootLogin no`).
- Password authentication and public-key authentication both *enabled* (`PasswordAuthentication yes`, `PubkeyAuthentication yes`).
- Default port 22 exposed to the public internet, no IP allowlist.
- The standard sshd shipped with the distribution; no `fail2ban` or `crowdsec`.
- The administrator uses an SSH key passphrase-protected but stored on a personal laptop, also used for web browsing and a wide variety of unrelated tasks.

Your task is to build an attack tree for the attacker goal **"obtain interactive shell access on the server as `admin` or escalate to `root` from such a shell"**, with the decompositions taken at least three levels deep on the primary branches, cost-annotated at the leaves, and used to recommend a *prioritised* set of hardening changes.

---

## Step 1 — Sketch the tree on paper (15 minutes)

Start with the root goal. Decompose it via OR (multiple paths to the goal) and AND (multiple steps required).

A useful starter decomposition for the root:

```
Obtain shell on server as admin OR escalate to root              (OR)
├── Obtain shell as admin                                        (OR)
│   ├── Authenticate as admin over SSH                           (OR)
│   │   ├── Password authentication                              (OR)
│   │   │   ├── Guess the password (dictionary / brute force)
│   │   │   ├── Credential stuffing from a public dump
│   │   │   └── ... (continue)
│   │   ├── Public-key authentication                            (OR)
│   │   │   ├── Steal the admin's private key from the laptop    (AND)
│   │   │   │   ├── Initial access to the laptop
│   │   │   │   └── Recover the passphrase OR exfiltrate ssh-agent
│   │   │   ├── ... (continue)
│   │   │   └── ...
│   │   └── ...
│   ├── Bypass authentication entirely (sshd CVE)                (OR)
│   │   ├── Known sshd CVE applicable to this version
│   │   ├── 0-day sshd CVE
│   │   └── Mis-config: `PermitEmptyPasswords yes` or similar
│   └── ... (further OR branches)
├── Escalate to root from an admin shell                         (OR)
│   ├── sudo misconfig (NOPASSWD on a privileged binary)
│   ├── world-writable script run by root
│   ├── Local kernel CVE (e.g. dirty-pipe class)
│   ├── setuid binary with known exploit chain
│   └── ... (continue)
└── Obtain root shell directly without going through admin       (OR)
    ├── Service running as root has an exposed RCE (web server, agent, ...)
    ├── Physical access to the host (out of scope?)
    └── Cloud-control-plane access (IAM compromise that grants console root)
```

Expand the tree to at least **three levels deep** on each of the primary branches. Use AND when the attacker needs *both* of two conditions; use OR when *either* is enough.

**Scope note in writing.** At the start of your deliverable, name explicitly which threat actors and which attack categories are *in scope* and which are *out of scope*. "Physical access by a determined nation-state with on-prem presence" can legitimately be out of scope; saying so in writing is part of the discipline.

---

## Step 2 — Cost-annotate the leaves (10 minutes)

For each leaf in your tree, annotate with one of:

- **`$`** — cheap; commodity tooling; minutes to hours of attacker effort.
- **`$$`** — moderate; targeted effort, some tooling investment; days of effort.
- **`$$$`** — expensive; specialised access or capabilities; weeks of effort.
- **`$$$$`** — nation-state-tier; bespoke 0-days, supply-chain operations, multi-month operations.

The cost of a sub-goal is **the minimum** across OR children and **the sum** across AND children. Propagate upward; the root has an estimated cost equal to the cheapest path.

This is rough. Do not pretend the cost is precise. It is a *relative ordering* — `$` leaves are exploitable by a bored teenager, `$$$$` leaves are not.

---

## Step 3 — Identify the cheapest path (5 minutes)

In your deliverable, name explicitly the cheapest path from root to leaf — the path an attacker following the *expected* shortest route would take. This is the attack you are most likely to face.

Then name the *second-cheapest* path, which is what you face once you defend the cheapest. The discipline is to think one move ahead of where you are: by the time you have defended the first path, the second is the new first.

---

## Step 4 — Recommend hardening, in priority order (10 minutes)

For each of the two or three cheapest paths, write one to three concrete hardening recommendations. The format:

| Recommendation | Defeats which leaf(s)? | Cost to defender (rough) | Residual risk |
|---|---|---|---|
| Disable password authentication; require public keys (`PasswordAuthentication no`) | All password-guess leaves | 0 (config change) | Attacker now needs the key |
| Set up `fail2ban` or `crowdsec` for sshd | Brute-force attempts in general | 1 hour install + tuning | Slow brute-force below the rate threshold still possible |
| Move sshd to a non-standard port behind a VPN | Drive-by scanning | 2-4 hours + ongoing operational cost | A determined attacker who finds the port is unaffected |
| Enforce passphrase-protected keys on engineering laptops | Steal-the-private-key leaf | Policy + onboarding | The laptop being compromised remains a single point of failure |
| Use a hardware-backed key (`ssh-keygen -t ed25519-sk`) | Keys extracted from disk | Cost of hardware tokens + key rotation | Token loss / break-glass procedure must be designed |

Note the *priority order*: cheap-to-defender, high-leverage recommendations first. A recommendation that defeats a `$$` leaf and costs the defender 30 minutes of config beats a recommendation that defeats a `$$$$` leaf at the cost of a hardware purchase for every engineer. Both might be right; the order matters.

---

## Step 5 — Self-review (5 minutes)

Two checks:

1. **Did you skip the *out-of-band* branches?** Many real SSH compromises happen by routes that are not "attacker SSHes to the box". A laptop running `ssh-agent` whose keys are forwarded to a compromised intermediate host, a CI runner with the SSH key in an environment variable, a backup tarball containing `.ssh/id_rsa`. If you missed these, add them now.
2. **Did your tree assume "the attacker is on the internet"?** Insider threats — the disgruntled employee with legitimate shell access who escalates — are a substantial fraction of real incidents. Your "escalate to root from an admin shell" branch should be at least as developed as your "authenticate as admin" branch. If it is not, you are imagining the attacker as exclusively external.

---

## Deliverables

In a directory `exercise-02/`:

- `exercise-02-tree.md` — the attack tree in Markdown (use indentation with `├──` and `└──` characters as in the example above, or use nested bullets; either is acceptable) with cost annotations.
- `exercise-02-recommendations.md` — the cheapest-path identification and the prioritised hardening table.

## Acceptance criteria

- [ ] Tree has the stated root and is at least three levels deep on each primary branch.
- [ ] Both AND and OR decompositions appear in the tree.
- [ ] At least 15 leaves, cost-annotated.
- [ ] Scope statement names what is out of scope.
- [ ] Cheapest path explicitly identified and named.
- [ ] Second-cheapest path also identified.
- [ ] At least five hardening recommendations, in priority order, with residual-risk column filled.
- [ ] Self-review addresses both "out-of-band branches" and "insider perspective".

## Why this exercise

SSH is the front door to most Linux servers. Threat-modelling it is the most-rehearsed exercise in defensive engineering; if you can do this one cleanly, the muscle generalises to every other authenticated network service. The exercise is also a useful preview of Week 8 (exploitation in a lab) — when you exploit a lab Linux box in Week 8, you will be walking exactly this tree from leaf to root.
