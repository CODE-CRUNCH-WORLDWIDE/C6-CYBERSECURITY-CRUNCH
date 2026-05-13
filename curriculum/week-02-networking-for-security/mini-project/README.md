# Mini-Project — An Annotated PCAP of Your Own Home Network

> Capture ten minutes of traffic on a network you own. Identify every protocol you see. Flag what surprises you. Commit the annotated capture and the brief to your `crunch-sec-portfolio-<yourhandle>` repository — the second artifact in the portfolio after Week 1's threat model.

This is the practical synthesis of Week 2. The lectures gave you the framework; the exercises gave you the muscle; the mini-project produces an artifact a hiring manager can read alongside the Week 1 threat model.

**Estimated time:** 7 hours, spread across Thursday-Saturday.

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

> **Capture only your own traffic, on your own network.** This is non-negotiable. If you live in a shared household, *inform every adult who uses the network* that you are running a capture, and give them the option to opt out. Capture from a host *you* own, on a network *you* operate. Do not capture from a hotel, a coffee shop, an employer, a school, or a friend's house — even passively, even with consent expressed verbally. Get explicit written authorization or do not capture.

---

## What you will produce

A public GitHub repo named `c6-week-02-pcap-<yourhandle>` (or a subfolder of your portfolio repo) containing:

- `capture.pcapng` — the 10-minute capture file. **Sanitised first** (see below). Tracked with Git LFS if larger than ~50 MB.
- `capture.sha256` — the hash of the original (pre-sanitisation) file.
- `brief.md` — your analyst annotation, ~1500-2500 words, structured as below.
- `README.md` — a one-paragraph intro and a link to `brief.md`.

The brief is the deliverable. The PCAP is the evidence behind it.

---

## Sanitisation — read before capturing

A PCAP from your home network contains:

- The IP and MAC of every device on your LAN.
- The hostnames your devices are looking up — *which* services your household uses, by name.
- Possibly cleartext credentials, session cookies, or tokens, depending on what applications were active.
- Possibly *family members'* traffic if anyone else uses the same network during the capture window.

Before publishing:

1. **Decide what you will capture before you start.** Capture only from your own host's interface, not the whole LAN. `tcpdump -i <your-laptop-iface>` not `tcpdump -i <mirrored-switch-port>`. This naturally scopes the capture to *your* traffic.
2. **Tell household members.** "I am running a network capture from my laptop for the next ten minutes. It only sees my own traffic, but I want you to know." Document this in your brief.
3. **Take a private copy and a public copy.** The private copy is the original. Hash it and keep it offline. The public copy is for the repo.
4. **Sanitise the public copy** with `tcpprivacy`, `pcap-anon`, or `tcprewrite --pnat=...`. At minimum:
   - Anonymise external IP addresses you queried (so your destination history is not published).
   - Redact any cleartext credential or token (run `tshark -r capture.pcapng -Y http.authorization` first; if anything appears, redact it).
   - Remove your public IP from packets that captured it (it is on the box's egress interface — `egrep "<your-public-ip>" capture.pcapng -a` will find it for redaction).
5. **Re-hash and document.** The sanitised PCAP gets its own `sha256`. Note in the brief that the original was sanitised and the method used.

If you cannot confidently sanitise, **do not publish the PCAP** — publish only the brief, and keep the PCAP private. The brief alone, with clean screenshots, is still a valid portfolio artifact.

---

## Capture procedure

1. Pick a window where you are the only person actively using the network — early morning, late at night.
2. On your host, run:

   ```bash
   sudo tcpdump -i <your-iface> -nn -s 0 -w ~/c6-mini-capture.pcapng -G 600 -W 1
   ```

   `-G 600` rotates after 600 seconds; `-W 1` keeps one file. So this captures exactly 10 minutes, then exits.

3. While the capture runs, do a *deliberate mix* of normal activity from your host: open a web browser to two or three sites you regularly use, run a `git pull` against a remote you regularly use, run `ping 1.1.1.1`, leave the box idle for two minutes. Note what you did and when.

4. When the capture ends, hash it:

   ```bash
   sha256sum ~/c6-mini-capture.pcapng > ~/c6-mini-capture.sha256
   ```

5. Sanitise into a public copy. Hash the sanitised copy.

---

## The brief — required sections

### Section 1 — Context

Two or three paragraphs. What network was captured (your home LAN; do not name a real ISP if you do not want to). What host (its OS and role: "personal laptop, no servers running"). What 10-minute window (date, approximate time, timezone). What deliberate activity you performed during the capture. Who else was on the network at the time.

### Section 2 — Top-level survey

Open `capture.pcapng` in Wireshark. Run *Statistics → Protocol Hierarchy*. Reproduce the protocol breakdown in a small table or screenshot. Cite the total packet count, total bytes, and duration.

Then list every distinct *Endpoint* (host) the capture saw, classified:

- **My host.** The one running `tcpdump`.
- **Local LAN.** Other hosts on the same RFC 1918 subnet.
- **Default gateway / router.**
- **External.** Hosts outside the LAN.

For each external endpoint, do a reverse DNS lookup (`dig -x <ip>`) and identify which application caused traffic to it. If you cannot, write "unidentified" — that is itself a finding.

### Section 3 — Conversations — annotated

Open *Statistics → Conversations → IPv4*. Pick the top 8-12 conversations by bytes. For each, document:

| # | Source | Destination | Protocol | Bytes | What caused it | Defender's read |
|---|--------|-------------|----------|------:|----------------|-----------------|
| 1 | my-laptop | github.com | HTTPS | 482 KiB | `git pull origin main` at 09:14 | Normal; SNI confirms; nothing unexpected |
| 2 | my-laptop | (internal router) | DNS | 12 KiB | every DNS query I made | Normal; queries enumerated in §4 |
| ... | ... | ... | ... | ... | ... | ... |

Aim for honesty in the "Defender's read" column. If a flow surprises you, say so — that is the point of the exercise.

### Section 4 — Protocols observed

For each major protocol you saw, write one paragraph: what it was doing, what you learned, what was visible vs. encrypted.

Required: at least HTTP (or HTTPS), DNS, TCP, and *something else of your choice* (mDNS, SSDP, NTP, DHCP, ICMP, ARP, IPv6 neighbor discovery, QUIC — most home captures contain several of these).

For each, name *one specific packet* (cite the packet number) that exemplifies it.

### Section 5 — Surprises and findings

This is the analyst section that makes the brief worth reading. Two to five bullet points. Examples of "surprise" you might find:

- A device on your LAN you forgot about (an old IoT thing, a Chromecast).
- A service connecting to an external host you did not expect (a phone-home from an app you do not use much).
- A protocol you have never seen before (mDNS to `_googlecast._tcp.local`, SSDP to `239.255.255.250:1900`).
- Plaintext traffic where you assumed encryption (HTTP rather than HTTPS for a captive-portal probe; cleartext mDNS that reveals device hostnames).
- A DNS query for a hostname that has nothing to do with the application that should have made it.

For each surprise, name a *defensive next step*: a configuration change, an audit, a removal. "Why is my smart TV reaching 13 different externals" is a legitimate finding, and "I will move it to the guest VLAN" is a legitimate response.

### Section 6 — What I did not see

A short paragraph. What protocols would have been present on a different network or with different applications running, but were *not* in this capture? Examples: SMB on a Windows-heavy LAN; LDAP on a corporate network; STUN/TURN if you had not started a video call. Naming the *absence* is part of the analysis.

### Section 7 — Resources used

A short bibliography. Required: at least one primary source (RFC, Wireshark documentation, MITRE ATT&CK, or a vendor advisory) you consulted to support a specific claim in the brief. Cite it precisely.

---

## Acceptance criteria

- [ ] Public GitHub repo or portfolio subfolder with `brief.md`, `capture.pcapng` (sanitised), and the two sha256 files.
- [ ] All seven sections present.
- [ ] Section 1 names the capture window and the deliberate activity.
- [ ] Section 2 has a protocol-hierarchy summary and an endpoint classification.
- [ ] Section 3's conversations table has at least 8 rows.
- [ ] Section 4 covers at least four protocols with one specific packet cited per protocol.
- [ ] Section 5 has at least two genuine findings with a defensive next step for each.
- [ ] Section 6 names at least one protocol absent from the capture and explains why.
- [ ] At least one primary source cited.
- [ ] The PCAP is sanitised (or absent, with the brief alone). No raw credentials. No third-party personal data.
- [ ] Document is roughly 1500-2500 words.
- [ ] No emojis.

---

## Suggested order of operations

### Phase 1 — Plan and inform (30 min)

1. Pick a capture window when you are the only active user.
2. Inform household members. Document the conversation in your brief.
3. Decide your deliberate activity script (web, git, ping, idle).

### Phase 2 — Capture (10 min)

Run the capture. Hash the original. Move the original to a private location.

### Phase 3 — Sanitise (1 h)

Open the capture; identify any cleartext credential or sensitive token. Anonymise external IPs you would prefer not to publish. Re-hash the sanitised file.

### Phase 4 — Analyse (3 h)

Work through Sections 1-7 of the brief. Slow and deliberate; do not rush past the conversations you do not understand — those are the most interesting.

### Phase 5 — Self-review (1 h)

Re-read the brief as if you were a hiring manager. Does it convince a reader that the writer can read a PCAP? Does Section 5 contain real findings or just placeholder bullets?

### Phase 6 — Polish and push (30 min)

- README in the repo / folder root with one-paragraph intro and a link to `brief.md`.
- Sources cited.
- `wc -w brief.md` is within 1500-2500.
- Push. Open in a fresh browser tab and read cold.

---

## Stretch goals

- Run the capture twice — once during deliberate use, once while idle. Compare. The idle capture is the **baseline** of your home network: every flow there is something your devices do *on their own*. That comparison is more revealing than either capture alone.
- Map each external destination to its owning organisation (`whois` on the IP gets you the ASN). Build a table; note any organisation you did not expect to be talking to.
- Map your findings to MITRE ATT&CK technique IDs where applicable (T1071.001 — application-layer protocol over web; T1071.004 — DNS; T1095 — non-application-layer protocols).
- Run the capture with `tcpdump -G 60 -W 60 -w c6-rotating-%Y%m%d-%H%M%S.pcapng` for a full hour, rotating every minute. Analyse the variation between minutes.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| Capture scope and sanitisation | 15% | The brief shows responsible scoping. The PCAP is clean. |
| Section 3 — Conversations table is real and useful | 20% | Each row cites a real flow with a real "what caused it." |
| Section 4 — Protocol coverage | 15% | At least four protocols, each with a cited packet. |
| Section 5 — Findings | 25% | At least two genuine findings with a specific defensive next step each. |
| Citations and primary sources | 10% | At least one RFC / NIST / MITRE / vendor reference. |
| Writing quality | 15% | Specific, not dramatic. The voice of an analyst, not a marketer. |

---

## Why this matters

A PCAP analysis is the second most common artifact a junior security engineer is asked to produce, after a threat model. Doing one on your own network produces a deliverable that is *uniquely yours* — no other candidate has the same capture — and that demonstrates the discipline of "I observed, I documented, I drew defensible conclusions." A clean Week 1 threat model plus a clean Week 2 PCAP brief is half of a credible junior portfolio.

---

## Submission

Push to GitHub. Link the repo from your C6 portfolio README. Make sure the repo is public, the sanitisation is complete, and the brief reads cleanly cold.

Then return to the Week 2 [README](../README.md) and tick this off your checklist.
