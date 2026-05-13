# Week 2 Homework

Six problems, ~6 hours total. Commit each in your Week 2 repo. Some require a Linux VM; do not run captures on a network you do not own.

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

## Problem 1 — Subnetting drills (45 min)

Write `notes/subnetting.md` answering these:

1. For each CIDR, give the network address, the broadcast address, the usable host count, and one realistic use case: `10.42.0.0/24`, `172.20.16.0/20`, `192.0.2.0/29`, `198.51.100.42/32`.
2. Given the host `192.168.7.83/22`, what is the network address and what is the broadcast?
3. Convert these dotted-decimal masks to CIDR: `255.255.255.0`, `255.255.255.240`, `255.255.252.0`.
4. Name the three RFC 1918 ranges in CIDR. For each, give the dotted-decimal mask.
5. In one sentence: why is a `/30` typically used between two routers rather than a `/24`?

**Acceptance.** All answers numeric and unambiguous. Show working for the trickier ones (the host bits, the broadcast computation). No copy-pasted calculator output without explanation.

---

## Problem 2 — `tcpdump` cheat-sheet from memory (45 min)

Write `notes/tcpdump-cheatsheet.md` from memory (then check against `man pcap-filter`). Required entries:

| Need | BPF filter |
|------|------------|
| All traffic to or from one host | ? |
| Only DNS traffic | ? |
| Only TCP SYNs (no ACKs) — port-scan signature | ? |
| Everything except SSH from this box | ? |
| Traffic between two specific hosts | ? |
| All ICMP echo (ping) | ? |
| Only TCP traffic on ports 80 and 443 | ? |
| Anything from a `/16` subnet | ? |
| Only TCP RSTs | ? |
| IPv6-only | ? |

Add one short paragraph below the table answering: *what is the difference between a BPF capture filter and a Wireshark display filter, and when would I reach for which?*

**Acceptance.** All ten rows filled. The filters parse (test each one against a live capture for a few seconds). The paragraph distinguishes the two filter dialects.

---

## Problem 3 — A short capture, fully annotated (1 hour)

On a VM you own, capture 60 seconds of your own traffic while generating a deliberate mix: `curl https://example.com`, `dig +short github.com`, `ssh -o ConnectTimeout=2 root@127.0.0.1 || true` (will refuse), `ping -c 3 1.1.1.1`.

```bash
sudo tcpdump -i any -nn -w ~/c6-week02-hw3.pcap -G 60 -W 1
```

Open the resulting PCAP in Wireshark. In `notes/hw3-annotation.md`, document at least **six** distinct flows. For each flow:

- Source and destination IPs and ports.
- Protocol.
- What command on your machine caused it.
- One sentence of analyst interpretation.

**Acceptance.** Six flows annotated. Each flow links a packet to a deliberate action of yours. Anything you cannot explain is named explicitly (and *that is fine* — naming the gap is the discipline).

---

## Problem 4 — Read a TLS ClientHello, end-to-end (1 hour)

Generate a TLS connection and capture it:

```bash
sudo tcpdump -i any -nn -w ~/c6-week02-hw4.pcap -c 30 'host github.com and tcp port 443'
curl -sS https://github.com/ -o /dev/null
```

Open in Wireshark. Locate the ClientHello (display filter: `tls.handshake.type == 1`). In `notes/hw4-clienthello.md`:

1. Paste a screenshot or text dump of the *Transport Layer Security* tree, expanded.
2. Name the TLS version in the *record-layer* header and the TLS version inside the ClientHello.
3. Name the SNI value (`server_name` extension).
4. List the *cipher suites* the client offered, in order. (This list, hashed deterministically, is the JA3 fingerprint.)
5. List the extensions the client offered (you do not need to expand each — the count and the order are the fingerprint).
6. In one paragraph: explain what a defender learns from the ClientHello, and what they do *not* learn (despite TLS being on the wire).

**Acceptance.** All six answered. The SNI is correctly identified. The "what the defender learns / does not learn" paragraph names at least two specific things in each category.

---

## Problem 5 — Audit your own box's listening sockets (45 min)

On a Linux box you own, run:

```bash
sudo ss -ltnp
sudo ss -lunp
```

For each listening socket, in `notes/hw5-listening.md`:

- The port and protocol.
- The bound address (`127.0.0.1`, `0.0.0.0`, or specific).
- The owning process (the `users:` field from `ss`).
- An assessment: is this port supposed to be open? Should it be bound to `0.0.0.0` (every interface) or `127.0.0.1` (local only)?

End with a one-paragraph commentary: were there any open ports you did not recognise? Any service bound to `0.0.0.0` that should be bound to `127.0.0.1`? Any service you would remove?

**Acceptance.** Every listening port is named, owning process identified, and assessed. The commentary contains at least one finding-or-defended non-finding ("nothing surprising" is acceptable iff the writer demonstrates they inspected each entry).

---

## Problem 6 — CVE deep read: Heartbleed or Kaminsky (1.5 h)

Pick **one**. Read the advisory, the NVD entry, and at least one technical analysis (the original researcher's writeup, Qualys, or a vendor advisory).

- **CVE-2014-0160 (Heartbleed)** — OpenSSL heartbeat extension read overflow. The TLS implementation bug that taught a generation of defenders that "we have TLS" does not mean "we have confidentiality."
- **CVE-2008-1447 (Kaminsky DNS cache poisoning)** — the DNS bug that retrofitted source-port randomization across every resolver on the internet. The textbook case of how DNS's protocol-level assumptions broke under a clever attack.

Produce `notes/cve-<id>.md` containing:

1. **The vulnerability in one paragraph.** What is the flaw, in plain English. What protocol or implementation property failed.
2. **The preconditions.** What does the attacker need (network position? specific software version? known target?).
3. **The impact.** What does the attacker gain. CVSS score if assigned.
4. **The patch.** Link to the upstream fix. One sentence on what the fix changes.
5. **The defender's view.** What detection or hardening would have prevented or detected exploitation: pinned versions, monitoring, network egress controls, certificate transparency, registration discipline. Be specific.

**Acceptance.** All five sections present. Direct links to NVD and to a primary technical source (a researcher's blog post, the upstream commit, or a CERT advisory). The defender's view contains *at least one specific* control, not "patch faster."

---

## Time budget

| Problem | Time |
|--------:|----:|
| 1 | 45 min |
| 2 | 45 min |
| 3 | 1 h |
| 4 | 1 h |
| 5 | 45 min |
| 6 | 1.5 h |
| **Total** | **~5 h 45 min** |

When done, push the Week 2 homework and start (or continue) the [mini-project](./mini-project/README.md).
