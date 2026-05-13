# Week 2 — Networking for Security

> *Every interesting attack crosses a wire. Week 2 teaches you to read the wire — the addresses, the ports, the handshakes, the protocols — so that when a packet capture lands on your desk you can answer "what is this, where is it going, and should it be happening?" without guessing.*

Welcome back to **C6 · Cybersecurity Crunch**. Week 1 was about how the box itself fails. Week 2 is about how boxes talk to each other and how that conversation is monitored, filtered, and forged. By Sunday you will be able to read a `tcpdump` capture line by line, identify the major application protocols by their on-the-wire signature, and write a small `nftables` ruleset that implements default-deny on a Linux box you own.

Networking is the substrate of every remote attack and every remote defense. The defender who cannot read packets is guessing. The defender who can read packets is reading the evidence directly.

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

Packet capture on a network you do not own — even "passive listening" on an open coffee-shop Wi-Fi — is illegal in many jurisdictions (in the United States, see 18 U.S.C. § 2511 — the Wiretap Act). Every capture exercise this week is on **your own** traffic, on **your own** equipment, on **your own** network. There are no exceptions.

---

## Learning objectives

By the end of this week, you will be able to:

- **Distinguish** IPv4 and IPv6 addressing, read CIDR notation fluently, and explain what a `/24` versus a `/16` versus a `/32` means operationally.
- **Recite** the canonical ports — 22, 53, 80, 443, 3389, 5432, 6379, 27017 — and state, for each, what it does and what an unexpected open instance of it suggests.
- **Walk** through the TCP three-way handshake at the flag level (SYN, SYN-ACK, ACK) and explain the half-open / RST cases that distinguish a normal connection from a port scan.
- **Read** a DNS query and response in `tcpdump` output and explain why DNS is *both* essential infrastructure and the most-abused exfiltration channel.
- **State** precisely what TLS does and does not protect (it encrypts the body; it does not hide the SNI on the wire by default, the destination IP, or the timing pattern).
- **Construct** a useful `tcpdump` filter using BPF syntax: by host, by port, by direction, by TCP flag.
- **Open** a PCAP in Wireshark, follow a TCP stream, identify protocols by their first bytes, and export a single conversation as a sub-PCAP.
- **Write** a small `nftables` ruleset that implements default-deny on input, allows established connections, and permits a named set of services.
- **Explain** the difference between a stateful and a stateless firewall, and why egress filtering is the often-forgotten direction.
- **Apply** the principle of network segmentation: name three trust boundaries on a small home network and the rule that enforces each.

---

## Prerequisites

- **Week 1** completed. The threat-modeling vocabulary (asset, threat, vulnerability, risk; STRIDE) is assumed.
- A Linux VM you have administrative access to, with `tcpdump`, `wireshark` (or `tshark`), and either `nftables` or `iptables` available. Ubuntu 24.04, Debian 12, Fedora 40 — any will do.
- A second host you can communicate with for the captures: a second VM, a Raspberry Pi, your phone on the same LAN — anything that generates traffic you have the right to capture.
- Wireshark installed locally (free, open source — `apt install wireshark` on Debian/Ubuntu; the official installer on macOS / Windows).
- Familiarity with the OSI / TCP-IP layer model from C14 or equivalent. If "layer 3" and "layer 7" do not parse for you, skim a primer before starting.

---

## Topics covered

- IPv4 addressing, subnet masks, CIDR notation, RFC 1918 private ranges, link-local, multicast
- IPv6 in brief: addressing, the elimination of NAT for most use cases, the SLAAC default
- TCP versus UDP — connection state, ordering guarantees, when each is used
- The TCP state machine — `LISTEN`, `SYN-SENT`, `SYN-RECEIVED`, `ESTABLISHED`, `FIN-WAIT`, `TIME-WAIT`, `CLOSED`
- The TCP three-way handshake and the SYN-scan / SYN-flood failure modes
- DNS: query types (A, AAAA, MX, TXT, CNAME), recursive vs authoritative, DoH / DoT, the exfiltration channel
- TLS: what it does (confidentiality + integrity of body, server authentication), what it does not (SNI, destination, timing, traffic-analysis)
- Common services and ports — 22 (SSH), 53 (DNS), 80 (HTTP), 443 (HTTPS), 3389 (RDP), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB)
- `tcpdump` syntax: capture filters in BPF, the most useful flags (`-i`, `-n`, `-vv`, `-X`, `-w`, `-r`)
- Wireshark layout: the three panes, the color rules, the protocol dissector, Follow TCP Stream
- The PCAP and PCAPNG file formats
- `iptables` (legacy) vs `nftables` (modern) — tables, chains, hooks, sets
- `ufw` (Debian/Ubuntu) and `firewalld` (RHEL/Fedora) as wrappers
- Default-deny as a posture; egress filtering as the forgotten direction
- Network segmentation: VLANs, host firewalls, jump hosts, the principle of least connectivity

---

## Weekly schedule

The schedule below adds up to approximately **36 hours**. Treat it as a target.

| Day       | Focus                                                | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Self-Study | Daily Total |
|-----------|------------------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|-----------:|------------:|
| Monday    | TCP/IP from a security angle; ports; TCP state       |    2h    |    1h     |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |     5h      |
| Tuesday   | DNS; TLS; the often-forgotten layers                 |    1h    |    2h     |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |     5h      |
| Wednesday | `tcpdump` and Wireshark — reading packets            |    2h    |    2h     |     1h     |    0.5h   |   1h     |     0h       |    0h      |     6.5h    |
| Thursday  | PCAP analysis; protocol identification               |    1h    |    1h     |     1h     |    0.5h   |   1h     |     2h       |    0.5h    |     7h      |
| Friday    | Firewalls; `nftables`; segmentation; egress          |    0h    |    1h     |     1h     |    0.5h   |   1h     |     2h       |    0.5h    |     6h      |
| Saturday  | Mini-project deep work — annotate your home capture  |    0h    |    1h     |     1h     |    0h     |   1h     |     3h       |    0h      |     6h      |
| Sunday    | Quiz, review, polish, push                           |    0h    |    0h     |     0h     |    0.5h   |   0h     |     0h       |    0h      |     0.5h    |
| **Total** |                                                      | **6h**   | **8h**    | **4h**     | **2.5h**  | **6h**   |   **7h**     |   **2h**   |  **36h**    |

---

## How to navigate this week

| File | What's inside |
|------|---------------|
| [README.md](./README.md) | This overview (you are here) |
| [resources.md](./resources.md) | RFCs, advisories, Wireshark docs, sample PCAP repositories, primary sources |
| [lecture-notes/01-tcp-ip-from-a-security-angle.md](./lecture-notes/01-tcp-ip-from-a-security-angle.md) | IPv4/IPv6, CIDR, the canonical ports, TCP state, DNS, TLS |
| [lecture-notes/02-reading-packets-with-tcpdump-and-wireshark.md](./lecture-notes/02-reading-packets-with-tcpdump-and-wireshark.md) | `tcpdump`, BPF filters, Wireshark, protocol signatures, the PCAP format |
| [lecture-notes/03-firewalls-and-segmentation.md](./lecture-notes/03-firewalls-and-segmentation.md) | `iptables` vs `nftables`, wrappers, default-deny, egress, segmentation |
| [exercises/README.md](./exercises/README.md) | Index of short hands-on drills |
| [exercises/exercise-01-capture-your-own-traffic.md](./exercises/exercise-01-capture-your-own-traffic.md) | First `tcpdump` capture on your own loopback and LAN |
| [exercises/exercise-02-tcpdump-puzzles.md](./exercises/exercise-02-tcpdump-puzzles.md) | Six BPF filter puzzles against captures you produce yourself |
| [exercises/exercise-03-nftables-rules.md](./exercises/exercise-03-nftables-rules.md) | Build a default-deny `nftables` ruleset and test it |
| [challenges/README.md](./challenges/README.md) | Index of weekly challenges |
| [challenges/challenge-01-decode-a-pcap.md](./challenges/challenge-01-decode-a-pcap.md) | Decode a publicly-distributed sample PCAP and write a one-page brief |
| [quiz.md](./quiz.md) | 10 multiple-choice questions |
| [homework.md](./homework.md) | Six practice problems |
| [mini-project/README.md](./mini-project/README.md) | Annotated PCAP of your own home network for 10 minutes — the second portfolio artifact |

---

## Stretch goals

If you finish early, push further:

- Read **RFC 9293** (the consolidated TCP specification, August 2022) end-to-end. It supersedes RFC 793 and is the modern primary source. You will not memorize it; you will know where to look.
- Read **RFC 8446** (TLS 1.3). Section 2 ("Protocol Overview") and Section 4 ("Handshake Protocol") are the durable parts.
- Run `tcpdump` on a busy host for an hour, save the PCAP, and grep through it for any plaintext credential or token. (On your own system only.) The point is to feel, viscerally, how much escapes encryption when one application is misconfigured.
- Read the Snort or Suricata starter rules — even if you do not run an IDS this week, the rule syntax forces you to think in "the signature is on the wire, where exactly."
- Set up `nftables` logging on your own box and watch what hits it for 24 hours. You will be surprised at the scanning baseline.

---

## Up next

Continue to [Week 3 — Threat Modeling and Risk](../week-03-threat-modeling-and-risk/) once your annotated PCAP is pushed and your portfolio README links to both Week 1 and Week 2 artifacts.

---

*Found an error? Open an issue or send a PR. The next learner will thank you.*
