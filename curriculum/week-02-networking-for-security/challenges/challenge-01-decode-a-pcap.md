# Challenge 1 — Decode a Public Sample PCAP

**Time estimate:** ~3 hours.

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

> **Open the file in a sandbox.** Sample PCAPs from malware-traffic collections are not themselves malware, but the analysis tools (Wireshark) have had parser CVEs. A VM you can throw away is the safe place to do this work.

## Problem statement

Choose **one** PCAP from the curated public samples listed below. Open it in Wireshark, analyse it, and produce a one-page analyst brief (`challenge-01-pcap-brief.md`) that a peer or a hiring manager can read in five minutes and understand the capture.

## Pick one PCAP

**Easier, single-protocol captures (recommended first):**

- **Wireshark Sample Captures — `http.cap`** — a small plain-HTTP capture, ideal for a first pass.
  <https://wiki.wireshark.org/SampleCaptures>
- **Wireshark Sample Captures — `dns.cap`** — a minimal DNS capture; identify the queries, the response records, and the resolver involved.
- **Wireshark Sample Captures — `telnet-cooked.pcap`** — a Telnet login session in cleartext. The lesson is "Telnet is unencrypted; here is the credential in your hand." (Read responsibly — the credential is on the wire by design of the sample.)

**Harder, multi-protocol captures (recommended after the first):**

- **Wireshark Sample Captures — `nb6-startup.pcap`** — a freshly-booted device's first network behavior. DHCP, ARP, mDNS, the lot.
- **Malware-Traffic-Analysis exercises** — Brad Duncan's training exercises, each with a writeup-style question set and an answer key:
  <https://www.malware-traffic-analysis.net/training-exercises.html>
  Pick a `pcap` (and **only** the `pcap`, not the malware-sample download) and work from there. Read the host page's terms first.

Choose deliberately. Note your choice and why at the top of your brief.

## Analyst brief structure

Your `challenge-01-pcap-brief.md` follows this template. Roughly one page when rendered.

### Header

- **Capture source.** URL, file name, sha256.
- **File metadata.** `tcpdump -r <file> -nn | wc -l` — total packet count. First and last timestamps. Duration. Total bytes.

```bash
file <file>.pcap
sha256sum <file>.pcap
tcpdump -r <file>.pcap -nn 2>/dev/null | wc -l
```

### Section 1 — Top-level survey (5 sentences max)

Open *Statistics → Protocol Hierarchy* in Wireshark. Describe in plain language what protocols are present, in what proportion. Examples:

> *"The capture contains 1,247 packets over 4 minutes 12 seconds. ~62% is TCP (HTTP, predominantly), ~18% is DNS, ~12% is ARP, the remainder TLS handshakes and ICMP."*

### Section 2 — Conversations

Open *Statistics → Conversations → IPv4*. List the top 5 conversations by bytes. For each, name the parties (resolve hostnames where possible — `dig -x` on internal IPs is rarely useful for a capture from someone else's network, but the published examples often have memorable names).

| # | Source | Destination | Bytes | Notes |
|---|--------|-------------|------:|-------|
| 1 | ... | ... | ... | "Plain HTTP request to /index.html; user-agent looks like curl" |
| ... | ... | ... | ... | ... |

### Section 3 — Notable packets

Pick **three** packets that are individually interesting and explain each in one sentence. Examples of "interesting":

- The TCP three-way handshake of the first significant flow.
- A TLS ClientHello, with the SNI extension visible.
- A DNS query for an unusual subdomain.
- An HTTP request whose User-Agent is informative.
- A TCP RST that ends a connection abruptly.
- An ICMP destination-unreachable that explains a missing service.

Cite the packet number from Wireshark.

### Section 4 — Interpretation

Two to four sentences answering: **what is this capture, and what would a defender want to know about it?** This is the analyst's "so what." A model:

> *"This is a synthetic capture of a single host fetching a small HTML page over plain HTTP. The credential exchange would have been entirely visible on the wire — this is a useful demonstration of why Telnet was deprecated, and a useful counterexample for a Week 2 student learning to identify cleartext protocols. A defender on the network would have seen the username 'fake' and password 'user' in packets 50 and 56."*

### Section 5 — One technique you used and one you almost missed

The reflective close. Two sentences each.

- *"Technique I used:"* the BPF or display filter that let you pull the signal out. Cite the exact filter syntax.
- *"Technique I almost missed:"* something you nearly overlooked on first pass — a small flow buried under a noisy one, an unexpected protocol, a hostname encoded in a TLS extension.

## Acceptance criteria

- [ ] `challenge-01-pcap-brief.md` committed to your Week 2 notes folder.
- [ ] The PCAP itself is *not* committed (it is someone else's file; link to the source).
- [ ] The brief includes the sha256 of the PCAP file used.
- [ ] All five sections present.
- [ ] At least three packets are cited by packet number.
- [ ] At least one cleartext protocol is named, with one specific observation about it.
- [ ] Section 4 answers "what is this capture and what would a defender want to know about it" in two-to-four sentences.
- [ ] The whole brief is roughly one rendered page (500-800 words).

## Hints

<details>
<summary>If Wireshark is overwhelming on a busy capture</summary>

Start with *Statistics → Conversations* — sort by bytes; the top 3 conversations are usually 80% of what is interesting. Apply *Apply as Filter → Selected* to one of them to isolate it. Then *Statistics → Protocol Hierarchy* on the filtered view to see what protocols that conversation uses.

</details>

<details>
<summary>If the capture has TLS and you cannot read the body</summary>

That is the point of TLS. You can still observe the IPs, the SNI, the cipher suites, the timing, and the sizes. Cite what you *can* see; note explicitly what is hidden.

</details>

<details>
<summary>If you cannot identify a protocol</summary>

Right-click the packet → *Decode As...* and try common protocols. If the packet is HTTP on a non-standard port, this is how you tell Wireshark to dissect it. If you genuinely cannot identify it, that is itself a finding — write "unidentified protocol on TCP/N, suspect X based on payload bytes" and explain your guess.

</details>

<details>
<summary>If you want a much harder capture</summary>

The Malware-Traffic-Analysis exercises step up the difficulty steadily. Brad's "first capture" exercises walk you through every Wireshark feature in service of one investigation. Use them when you want a deeper challenge than the Wireshark sample collection offers.

</details>

## Why this matters

Every blue-team interview includes a "we will show you a PCAP for ten minutes; tell us what you see" stage. Doing this exercise once gives you the muscle memory for that interview. Doing it twice is the difference between "I have seen Wireshark" and "I can use Wireshark."

## Submission

Commit the brief. Make sure the source link is present and the sha256 of the PCAP file is cited. Move on to the homework and the mini-project.
