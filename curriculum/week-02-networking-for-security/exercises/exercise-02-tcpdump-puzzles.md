# Exercise 2 — `tcpdump` Puzzles

**Time:** ~50 minutes.
**Outcome:** You can write BPF capture filters from memory for six common analyst questions: by host, by port, by direction, by TCP flag, by network, and by application protocol via port.

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

> **Own-traffic only.** Every capture in this exercise is on a network you own, generating traffic *you cause*. If you do not have a personal Linux box and a willing endpoint, do this exercise inside a single VM where the "endpoint" is a loopback service.

## Problem statement

Solve six BPF filter puzzles. For each, write the filter, run the capture, generate the traffic the filter should match (and some it should *not*), and confirm in Wireshark that the capture contains only the expected packets.

Produce `exercise-02-tcpdump.md` containing, for each puzzle: the question, your BPF expression, the `tcpdump` command in full, two or three representative output lines, and a one-sentence justification.

## Setup

A single Linux VM is sufficient. Open three terminals: one for capture, one for generating traffic, one for analysis.

Make a working directory:

```bash
mkdir -p ~/c6-week02-bpf && cd ~/c6-week02-bpf
ip route get 1.1.1.1 | awk '{print $5; exit}'    # note your egress interface
```

In all examples below, replace `<iface>` with the interface name you noted. Use `-i any` if you prefer; it works for all puzzles but loses link-layer detail.

## Puzzle 1 — All traffic to or from one specific host (5 min)

**Question:** capture every packet to or from `1.1.1.1` (Cloudflare's public DNS resolver — a deliberate target you have the right to query).

```bash
sudo tcpdump -i <iface> -nn -w puzzle-01.pcap -c 20 'host 1.1.1.1'
```

Generate matching traffic:

```bash
dig @1.1.1.1 +short example.com
```

Confirm in `tcpdump -r puzzle-01.pcap -nn` that every packet has `1.1.1.1` as source or destination.

## Puzzle 2 — Only traffic to a specific port, only in one direction (8 min)

**Question:** capture only TCP SYNs going *to* port 443 (i.e., the *opening* packet of every outbound HTTPS connection from this box).

```bash
sudo tcpdump -i <iface> -nn -w puzzle-02.pcap -c 10 \
  'tcp dst port 443 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'
```

Generate matching traffic:

```bash
curl -sS https://example.com/ > /dev/null
curl -sS https://github.com/ > /dev/null
```

Confirm: every captured packet has `Flags [S]`, destination port 443, and *no* `[S.]` (which would be a response).

## Puzzle 3 — All DNS traffic, both UDP and TCP (6 min)

**Question:** capture DNS comprehensively — UDP/53 for queries and small responses, TCP/53 for large responses and zone transfers.

```bash
sudo tcpdump -i <iface> -nn -w puzzle-03.pcap -c 20 'port 53'
```

(Note: omitting `tcp` and `udp` means "either.")

Generate traffic:

```bash
dig +short google.com
dig +short -t TXT example.com
dig +tcp @1.1.1.1 example.com           # forces TCP
```

Confirm the capture contains both UDP and TCP packets on port 53.

## Puzzle 4 — All traffic on the LAN except SSH (8 min)

**Question:** you are administering the box over SSH. You want a capture of *everything else* so the capture is not dominated by your own SSH session.

```bash
sudo tcpdump -i <iface> -nn -w puzzle-04.pcap -c 30 'not (tcp port 22)'
```

Generate other traffic in another terminal while the capture runs:

```bash
ping -c 3 1.1.1.1
dig +short example.com
curl -sS https://example.com/ > /dev/null
```

Confirm: no port-22 packets in the resulting PCAP. (Open it in Wireshark and check the *Statistics → Endpoints → TCP* tab. There should be no entry for `:22`.)

## Puzzle 5 — Traffic between a host and a whole subnet (8 min)

**Question:** capture every packet between `192.168.1.10` (your laptop) and *any* host in `192.168.1.0/24` (your LAN). Useful for "what is my laptop chatting with on the LAN?"

```bash
sudo tcpdump -i <iface> -nn -w puzzle-05.pcap -c 50 \
  '(host 192.168.1.10) and (net 192.168.1.0/24)'
```

Adjust the IP and the subnet to match your own LAN. Generate traffic with `ping <another-lan-host>` or by browsing to a LAN web UI you own.

If your LAN is `10.0.0.0/24` or different, substitute the right CIDR. The puzzle is the *shape* of the filter, not the specific addresses.

## Puzzle 6 — TCP RSTs only (the "connection refused" indicator) (10 min)

**Question:** capture every TCP packet with the RST flag set. RSTs indicate a connection that was refused, dropped mid-stream, or torn down by an attacker.

```bash
sudo tcpdump -i <iface> -nn -w puzzle-06.pcap -c 20 \
  'tcp[tcpflags] & tcp-rst != 0'
```

Generate a few RSTs deliberately:

```bash
# A connection to a closed port on a host that is up; the host will RST.
curl -sS --connect-timeout 3 http://127.0.0.1:65500/ ; true
```

Confirm: every captured packet has `Flags [R]` or `Flags [R.]` in the `tcpdump -r` output, or "[RST, ACK]" in Wireshark's Info column.

## Acceptance criteria

- [ ] `exercise-02-tcpdump.md` committed.
- [ ] Six PCAPs committed (`puzzle-01.pcap` through `puzzle-06.pcap`).
- [ ] Each puzzle in the notes file has: the question, the BPF expression, the full `tcpdump` command, and a one-sentence justification of why your filter matches only the intended packets.
- [ ] Wireshark or `tcpdump -r` confirms each PCAP contains only matching packets (no false positives).
- [ ] Every capture was on your own equipment, of your own traffic.

## Hints

<details>
<summary>If your filter expression is rejected with a syntax error</summary>

BPF is fussy about parentheses and quoting. Wrap the whole expression in single quotes so the shell does not expand `!` or `*`. The man page `pcap-filter(7)` is the canonical reference.

</details>

<details>
<summary>If you cannot remember the `tcp-syn` / `tcp-ack` mnemonics</summary>

They are: `tcp-fin` (0x01), `tcp-syn` (0x02), `tcp-rst` (0x04), `tcp-push` (0x08), `tcp-ack` (0x10), `tcp-urg` (0x20). The numeric form `tcp[13] & 2 != 0` is equivalent to `tcp[tcpflags] & tcp-syn != 0` — older scripts use the numeric form.

</details>

<details>
<summary>If `host 192.168.1.10` matches nothing on your LAN</summary>

Confirm your LAN with `ip -4 addr` and adjust to your actual subnet. RFC 1918 ranges are common but not universal. Some carrier-grade NAT deployments use `100.64.0.0/10`.

</details>

## Why this matters

BPF fluency is the difference between "let me capture everything and grep through it" and "I will capture exactly the question I am asking." On a busy interface the difference is between a 5 GB PCAP and a 5 MB one. On an incident-response engagement it is the difference between a usable evidence file and a coffin.

## Submission

Commit the notes and the six PCAPs. Move on to Exercise 3.
