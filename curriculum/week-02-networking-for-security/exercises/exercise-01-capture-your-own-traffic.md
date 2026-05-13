# Exercise 1 — Capture Your Own Traffic

**Time:** ~45 minutes.
**Outcome:** You have produced two PCAPs — one on loopback, one on your LAN interface — opened them in Wireshark, identified the three-way handshake of a TLS connection you initiated, and written one paragraph interpreting each capture.

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

> **Own-traffic only.** Every packet captured this week is your own, on your own network, on your own equipment. Capturing on a shared network you do not own is illegal in most jurisdictions even if the traffic is yours.

## Problem statement

Produce `exercise-01-capture.md` containing your commands, the resulting PCAPs (committed alongside the notes), and a one-paragraph interpretation per capture.

## Setup

- A Linux VM you own, or a Linux laptop. Macs are fine if you have `tcpdump` available (it ships).
- `tcpdump` and `wireshark` installed.
- Network reachability: you can reach the public internet.

```bash
sudo tcpdump --version
which wireshark || sudo apt install -y wireshark
sudo usermod -aG wireshark "$USER"   # so non-root can capture (Debian/Ubuntu); log out / in after
```

## Task 1 — A loopback capture (15 min)

Open two terminals.

**Terminal A** (the capture):

```bash
sudo tcpdump -i lo -nn -w /tmp/loopback.pcap -c 30
```

**Terminal B** (the traffic generator):

```bash
python3 -m http.server 8080 &      # start a tiny local HTTP server
curl -sS http://127.0.0.1:8080/ > /dev/null
kill %1                            # stop the server
```

Return to Terminal A — `tcpdump` should have exited after 30 packets. Open `/tmp/loopback.pcap` in Wireshark:

```bash
wireshark /tmp/loopback.pcap &
```

Answer in your notes:

1. Identify the three packets of the TCP three-way handshake. Paste the row info column for each.
2. After the handshake, find the first packet containing the bytes `GET / HTTP/1.1`. What did the HTTP request look like?
3. How does loopback differ from "real" network traffic? (Hint: no link-layer frame; the kernel does not put your packet on a NIC.)

## Task 2 — A LAN capture of a TLS connection (15 min)

Pick the interface that reaches the internet:

```bash
ip route get 1.1.1.1 | awk '{print $5; exit}'
# example output: wlp3s0
```

Use it (replace `wlp3s0` below):

**Terminal A:**

```bash
sudo tcpdump -i wlp3s0 -nn -w /tmp/lan-tls.pcap -c 50 'host example.com and tcp port 443'
```

**Terminal B:**

```bash
curl -sS https://example.com/ > /dev/null
```

Open in Wireshark. Answer in your notes:

1. The first three packets are the TCP handshake. Confirm: SYN, SYN-ACK, ACK.
2. Packet 4 (typically) is the **TLS ClientHello**. Expand the *Transport Layer Security* tree in the packet details pane. Find the `server_name` extension. What hostname does it contain?
3. Find the *Server Hello* packet. What TLS version does the server select? What cipher suite?
4. Right-click the first TCP packet → *Follow → TCP Stream*. You will see encrypted bytes after the handshake. Confirm in one sentence that the body of the conversation is not readable in cleartext.

## Task 3 — A DNS capture (15 min)

DNS is small, fast, and almost everything in your day-to-day generates it. Capture some:

```bash
sudo tcpdump -i any -nn -w /tmp/dns.pcap -c 20 'udp port 53'
```

In another terminal:

```bash
dig +short example.com
dig +short github.com
dig +short -t MX example.com
```

Open `/tmp/dns.pcap` in Wireshark. Answer in your notes:

1. For each of the three `dig` commands, identify the query packet and the response packet. (Match on the transaction ID in the DNS header.)
2. What record types were requested? (Look at the *Queries* subtree in each query.)
3. In the response to `dig +short example.com`, what IPv4 addresses were returned?
4. Could a defender on the network learn, from this PCAP, *what hostnames you queried*? Why is that significant even when the subsequent HTTPS connection is encrypted?

## Acceptance criteria

- [ ] `exercise-01-capture.md` committed to your Week 2 notes folder.
- [ ] Three PCAPs committed: `loopback.pcap`, `lan-tls.pcap`, `dns.pcap`.
- [ ] Each capture has a paragraph in the notes file describing what is in it and what you learned.
- [ ] Task 2 explicitly identifies the SNI hostname in the ClientHello.
- [ ] Task 3 explicitly answers the "defender on the network" question — the point that SNI plus DNS together effectively de-anonymise the destination of an "encrypted" connection.

## Hints

<details>
<summary>If `tcpdump` complains "no suitable device found"</summary>

You need root: `sudo tcpdump ...`. Or, on Debian/Ubuntu, add yourself to the `wireshark` group (Task 0) and re-login. On macOS, `tcpdump` does not need root for some interfaces but does for others; `sudo` is the simple answer.

</details>

<details>
<summary>If the LAN capture is empty</summary>

Either you used the wrong interface (run `ip route get 1.1.1.1` again), or your filter excluded everything (typo in the host name?), or you exited `tcpdump` before generating traffic. Restart the capture and run `curl` while `tcpdump` is still running.

</details>

<details>
<summary>If Wireshark cannot open the PCAP because of permissions</summary>

The file was written by root. `sudo chown $USER /tmp/loopback.pcap`. Or capture as the right user from the start (the `wireshark` group on Debian/Ubuntu makes this work).

</details>

## Why this matters

The first capture is the moment "packet" stops being an abstract noun and becomes a concrete unit of evidence on your screen. Every defender's career starts here. Save the PCAPs — they become reference data the next time you forget what a SYN-ACK looks like.

## Submission

Commit the notes and the PCAPs. Move on to Exercise 2.
