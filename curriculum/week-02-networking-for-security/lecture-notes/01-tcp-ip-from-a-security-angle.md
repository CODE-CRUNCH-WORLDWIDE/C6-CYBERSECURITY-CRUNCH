# Lecture 1 — TCP/IP from a Security Angle

> **Outcome:** You can read an IPv4 or IPv6 address with its CIDR mask; you can name the canonical ports and what an unexpected open one means; you can walk the TCP three-way handshake at the flag level; you can explain why DNS is both essential infrastructure and the most-abused exfiltration channel; and you can state precisely what TLS does and does not protect.

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

This lecture refreshes the TCP/IP material a C14 graduate already knows, and re-frames it from the defender's perspective. The goal is not to re-teach networking; the goal is to make you fluent in the layer where attackers operate and defenders must read evidence.

## 1. Why a security engineer reads networking

The reason every interesting attack crosses a wire is that almost every system worth attacking is reachable across a wire. The defender's job is to know what is supposed to be on the wire, recognise what is not, and have the controls to refuse the difference. That requires fluency in three things — addresses, transport, and application protocols — at a level above "I know what an IP address is" and below "I can recite the RFC."

A working bar to aim for this week:

- Given a `tcpdump` line, you can identify the layer-3 protocol, the source and destination, the layer-4 protocol, the ports, and at least one application-protocol hint.
- Given a port number from the small list below, you can name the canonical service and one common misconfiguration that exposes it.
- Given a packet trace of a TCP connection, you can find the SYN, the SYN-ACK, the ACK, the data, and the close — and tell a normal close from a reset.

If those three feel comfortable by the weekend, you have hit the week's targets.

---

## 2. IPv4 addressing in one page

An IPv4 address is 32 bits, written as four dotted decimals — `192.168.1.42`. A subnet mask divides those 32 bits into a *network* portion and a *host* portion. Modern notation writes this as CIDR — `192.168.1.0/24` means "the first 24 bits are the network, the remaining 8 are host." That `/24` is a block of 256 addresses (254 usable), the kind of subnet a small home LAN typically uses.

CIDR you should recognise on sight:

| CIDR | Hosts | Typical use |
|------|------:|-------------|
| `/32` | 1 | A single specific host. Firewall rules, ACL whitelisting. |
| `/30` | 4 (2 usable) | A point-to-point link between two routers. |
| `/29` | 8 (6 usable) | A tiny DMZ or jump-host subnet. |
| `/24` | 256 (254 usable) | A small LAN. The default home network. |
| `/16` | 65,536 | A campus or large enterprise segment. |
| `/8` | ~16.7 million | A whole legacy class-A block; also `10.0.0.0/8` private. |
| `/0` | All | "Any IPv4 address," used for default routes and "deny all" rules. |

The RFC 1918 private ranges — the addresses that are not routed on the public internet, used inside every home and most enterprise LANs — are:

```
10.0.0.0/8        — 10.0.0.0     - 10.255.255.255
172.16.0.0/12     — 172.16.0.0   - 172.31.255.255
192.168.0.0/16    — 192.168.0.0  - 192.168.255.255
```

A handful of other reserved ranges you will see in captures and should recognise:

- `127.0.0.0/8` — loopback. Anything `127.*.*.*` is the local host.
- `169.254.0.0/16` — link-local (IPv4 autoconfiguration; the address a host gives itself when DHCP fails).
- `224.0.0.0/4` — multicast. `224.0.0.251` is mDNS, `239.255.255.250` is SSDP. Both are noisy on home LANs.
- `255.255.255.255` — limited broadcast.
- `100.64.0.0/10` — carrier-grade NAT (CGNAT), increasingly common between you and your ISP.

If your home LAN traffic in Wireshark shows a destination outside `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, multicast, or broadcast, the traffic is leaving your house. Knowing which packets leave the LAN — and to where — is the first defensive question.

---

## 3. IPv6 in brief

IPv6 addresses are 128 bits, written as eight colon-separated 16-bit hex groups: `2001:db8:85a3::8a2e:370:7334`. Consecutive groups of zeros collapse to `::` (once per address). The `/64` prefix is the standard host-subnet size; smaller subnets are unusual and break stateless address autoconfiguration (SLAAC).

The security-relevant differences from IPv4:

- **There is usually no NAT.** Every host typically has a globally routable IPv6 address. The defensive boundary becomes the *firewall*, not the absence of routing. Most consumer routers default to a permissive IPv6 firewall — assume yours does, and check.
- **Address scopes are explicit.** `fe80::/10` is link-local (per-interface), `fc00::/7` is unique-local (the private-network equivalent), `2000::/3` is the current global unicast space.
- **SLAAC means a host's IPv6 address can encode its MAC.** Modern OSes use *privacy extensions* (RFC 8981) to rotate the lower 64 bits, but legacy or misconfigured hosts may still leak MAC.
- **The same host has many IPv6 addresses simultaneously.** A link-local, one or more SLAAC, possibly a DHCPv6, possibly several temporary privacy addresses. Firewall rules must account for this.

You will see IPv6 in your home capture this week. Do not pretend it is not there.

---

## 4. The canonical ports — and what an unexpected open one means

Ports are 16-bit identifiers in TCP and UDP headers, 0-65535. The IANA registry assigns names to well-known ports (0-1023) and registers many more above. For the defender, a small list deserves muscle-memory.

| Port | Service | What it does | What an unexpected open one suggests |
|-----:|---------|--------------|--------------------------------------|
| **22** | SSH | Remote shell, secure file transfer. | Either a deliberate admin path or a forgotten one. Audit `sudoers`, key auth, fail2ban presence. |
| **53** | DNS | Name resolution (UDP and TCP). | Internal DNS resolver: fine. Public-facing open resolver: a finding and a DDoS amplification risk. |
| **80** | HTTP | Cleartext web. | A site without TLS in 2025 is a finding. Audit the redirect to 443; check HSTS. |
| **443** | HTTPS | TLS-wrapped HTTP. | Normal. Inspect the certificate, the SNI patterns, the JA3/JA4 fingerprint if you have one. |
| **3389** | RDP | Windows remote desktop. | Public-facing 3389 is one of the most attacked ports on the internet. Should be behind a VPN. |
| **5432** | PostgreSQL | Database. | Database directly on the internet is almost always a misconfiguration. Bind to localhost or to a private subnet. |
| **6379** | Redis | In-memory key-value store. | Redis on the internet without `requirepass` set has been mass-compromised since 2015. |
| **27017** | MongoDB | Document database. | MongoDB on the internet without auth has been mass-compromised since 2017 (the "Mongo apocalypse"). |

Two other classes of ports worth knowing:

- **High ports for ephemeral source selection.** When your laptop opens a TCP connection to a server, the OS picks a source port from a high range (Linux: typically 32768-60999). Those high ports appear in every capture as the *client side* of every outbound flow. They are not "open services."
- **Common probe ports.** Any internet-facing host receives unsolicited traffic on 22, 23 (telnet), 80, 443, 445 (SMB), 1433 (MSSQL), 3389, 5900 (VNC), 6379, 9200 (Elasticsearch), 27017. The baseline noise is informative — see the daily SANS Internet Storm Center port reports (<https://isc.sans.edu/>).

Defensive habit: list every port the box has open with `ss -ltnp` and `ss -lunp`. Every open port is *either* a documented service (with an owner) *or* a finding. There is no "I do not know what that one is."

---

## 5. TCP versus UDP

**TCP** is connection-oriented, ordered, reliable, byte-stream. The three-way handshake establishes the connection; sequence numbers and ACKs handle ordering and retransmission; a four-way (or sometimes three-way) close shuts it down.

**UDP** is connectionless, unordered, unreliable, message-based. There is no handshake, no sequence number, no ACK; an application that needs those properties layers them on top. DNS, NTP, DHCP, QUIC (which is HTTP/3's transport), VPNs (`WireGuard`, OpenVPN-UDP), most streaming media, most game traffic — all UDP.

A C6-relevant security difference: UDP is *trivial* to spoof. The source address in a UDP packet is whatever the sender wrote — there is no handshake to prove the source is reachable. This is the substrate of every UDP-amplification DDoS (DNS, NTP, memcached, CharGen) — the attacker sends a small UDP query with the *victim's* address as source; the responder sends a large reply to the victim. Defensive corollary: any UDP service that returns a much larger response than its query (DNS recursion, NTP `monlist`, memcached `stats`) becomes an amplification weapon if reachable from the internet without restriction.

---

## 6. The TCP state machine — what you will see in captures

A TCP connection passes through a defined set of states. The full diagram is in RFC 9293 Figure 5; the security-relevant subset is small:

```
   LISTEN  (server waiting)
      │  SYN received
      ▼
   SYN-RECEIVED
      │  ACK received
      ▼
   ESTABLISHED  (data flows)
      │  FIN sent or received
      ▼
   FIN-WAIT-* / CLOSE-WAIT / LAST-ACK
      │
      ▼
   TIME-WAIT  (60-120s; prevents stale segments)
      │
      ▼
   CLOSED
```

### The three-way handshake

For a connection from client `C` to server `S`:

```
C → S : SYN          (flags=S,   seq=X)
S → C : SYN, ACK     (flags=S.A, seq=Y, ack=X+1)
C → S : ACK          (flags=.A,  seq=X+1, ack=Y+1)
... data flows ...
```

In `tcpdump`, those flag bits appear as `[S]`, `[S.]`, `[.]` — the bracket-flag notation is the dialect to memorise. Capital letters mean the flag is set: `S` for SYN, `F` for FIN, `R` for RST, `P` for PUSH, `.` for ACK. So `[S.]` is "SYN+ACK."

### The half-open and RST cases

A few non-handshake patterns recur:

- **SYN, no SYN-ACK.** The server is not listening on that port, or a firewall has dropped the SYN. In `tcpdump` you see only the client's SYN, retried two or three times, then nothing. This is the silent-drop posture — a stealth signal to an attacker that something is between them and the host.
- **SYN, RST.** The server's kernel is reachable but no service is listening on that port. The kernel sends a RST to refuse the connection. In `tcpdump`: `[S]` from client, `[R.]` from server. This is the *default* behavior when no firewall is dropping the packet; it tells an attacker the host is up.
- **SYN, SYN-ACK, RST.** The classic SYN-scan signature (often called a "half-open scan"). The scanner sends SYN, receives SYN-ACK, never sends the final ACK — instead it sends RST to tear down. The scanner has confirmed the port is open without ever completing the handshake. Both `nmap -sS` and most TCP scanners use this pattern.
- **SYN flood.** Many SYNs from many spoofed sources, never followed by the final ACK. The server allocates state for each half-open connection until the backlog fills. Linux's `tcp_syncookies` is the classical defense — it makes the SYN-ACK encode the connection state in the sequence number, so the server keeps no state until the third packet arrives. Verify on your own box with `sysctl net.ipv4.tcp_syncookies` (should be `1`).

### `TIME-WAIT` and the "why are there so many" question

After a connection closes, the initiating side typically sits in `TIME-WAIT` for 60-120 seconds. The purpose is to absorb stray re-transmitted segments from the closed connection so they do not arrive at a new connection on the same 4-tuple. On a busy server, `ss -t state time-wait | wc -l` showing thousands of entries is normal. Beginners frequently misdiagnose this as a leak; it is not.

---

## 7. DNS — essential infrastructure and exfiltration channel

DNS resolves human-readable names to IP addresses. The query types you will see:

- **A** — IPv4 address for a name.
- **AAAA** — IPv6 address for a name.
- **CNAME** — alias from one name to another.
- **MX** — mail exchanger for a domain.
- **TXT** — arbitrary text (used for SPF, DKIM, DMARC, ACME challenges, and — historically — exfiltration).
- **NS** — name servers responsible for a zone.
- **SOA** — start of authority; the zone's primary record.
- **SRV** — service location.
- **PTR** — reverse: address to name.

A DNS query in `tcpdump`:

```
12:01:33.140 IP 192.168.1.10.51001 > 192.168.1.1.53: 42345+ A? www.example.com. (33)
12:01:33.180 IP 192.168.1.1.53 > 192.168.1.10.51001: 42345 1/0/0 A 93.184.216.34 (49)
```

The query is the small UDP packet to port 53 of the resolver. The response is the slightly larger reply with the answer. The trailing `(33)` and `(49)` are payload lengths in bytes.

### Why DNS is both essential and a defensive nightmare

- **Almost every other protocol depends on DNS.** If DNS fails, the system fails. This makes DNS the single most-targeted infrastructure layer for outages.
- **DNS is on UDP/53 by default.** Easy to spoof, easy to amplify, easy to inject.
- **TXT records can carry arbitrary text.** Encoding 256 bytes of stolen data into a base32-encoded subdomain query — `aGVsbG8gd29ybGQ.exfil.attacker.example` — is a textbook exfiltration technique (MITRE ATT&CK T1071.004). The query *will* be made; your resolver will look it up; the attacker's authoritative server logs it; the data is gone. Iodine, dnscat2, and many real malware families use exactly this pattern.
- **DNS-over-HTTPS (DoH, RFC 8484) and DNS-over-TLS (DoT, RFC 7858)** are recent privacy improvements. They wrap DNS in TLS so it cannot be inspected at the network layer. For defenders this is a trade-off: privacy for users, opacity for security teams. Many enterprise environments block DoH and require all DNS to go to internal resolvers for exactly this reason.

Defensive habits:

- **Log all DNS queries from your network.** A query for `xfaaeaeaeaeaeaeaeae.attacker.example` is not noise. It is evidence.
- **Block egress UDP/53 except to your own resolvers.** A host querying an external resolver directly is bypassing your visibility.
- **Watch for high-entropy subdomain volumes.** The exfil channel makes a lot of unusual queries; legitimate traffic does not.

---

## 8. TLS — what it does and does not protect

TLS (RFC 8446 for version 1.3, RFC 5246 for the still-deployed 1.2) provides:

- **Confidentiality of the body.** The application-layer payload — HTTP request, IMAP commands, anything inside the encrypted record — is unreadable to a passive observer.
- **Integrity of the body.** A modified ciphertext fails authentication; the connection drops.
- **Server authentication.** The certificate proves the server holds a key the CA was willing to sign for that name. Mutual TLS (mTLS) adds client authentication.

TLS does **not** provide:

- **Confidentiality of the destination IP and port.** Every IP packet has them in cleartext. You can always see *who is talking to whom*, even if you cannot read the content.
- **Confidentiality of the SNI by default.** The Server Name Indication extension in the TLS ClientHello includes the hostname in plaintext. An on-path observer learns the hostname even when the body is encrypted. Encrypted Client Hello (ECH) addresses this, but adoption is still partial. As of 2025, expect SNI to be readable in most captures.
- **Concealment of the certificate.** In TLS 1.2 the certificate is in cleartext. In TLS 1.3 it is inside the handshake encryption, but the *presence* and *size* of the cert exchange is still visible.
- **Concealment of timing or size patterns.** Traffic-analysis attacks (recognising a specific website by the bytes-and-timing pattern of its assets) work fine over TLS.
- **Server identity, in the absence of validation.** A client that does not verify the certificate gets no authentication. Curl with `-k`, Python with `verify=False`, every "self-signed dev" workflow — every one of these is a willingness to be MITM'd.

### What this means for you as a defender

- **Cert transparency logs** (the CT logs all CAs are required to publish to, RFC 9162) let you watch which names are being issued certificates. Set up a CT-log monitor for your own domains. Catch typosquats and unauthorized issuance the day they happen. (We do this in Week 7.)
- **TLS fingerprints** (JA3, JA4) characterise the *client* — its ciphersuite list, extensions, EC curves — and identify malware that uses a non-browser TLS stack. A capture with a curl-style fingerprint coming from a host that should only run a browser is informative.
- **The cleartext you can still see** in a TLS connection — IP, port, SNI, cert metadata, timing — is the defender's working evidence in any post-incident review.

---

## 9. Putting it together — reading one line of `tcpdump`

```
12:14:02.418311 IP 192.168.1.42.51334 > 93.184.216.34.443: Flags [S], seq 3729012841, win 64240, options [mss 1460,sackOK,TS val 12345 ecr 0,nop,wscale 7], length 0
```

Reading character by character:

- `12:14:02.418311` — timestamp with microseconds.
- `IP` — layer-3 is IPv4 (you would see `IP6` for IPv6).
- `192.168.1.42.51334` — source: RFC 1918 private IP, ephemeral source port 51334. A device on the LAN.
- `>` — direction marker.
- `93.184.216.34.443` — destination: a public IP, port 443. The remote is a TLS service.
- `Flags [S]` — only SYN is set. This is the opening packet of a three-way handshake.
- `seq 3729012841` — initial sequence number (random by default since RFC 6528).
- `win 64240` — receive window size.
- `options [...]` — TCP options: MSS, SACK permitted, timestamps, window scale.
- `length 0` — no payload (a SYN never carries data — well, technically TCP Fast Open can, but ignore that for now).

In one sentence: a host on the LAN is starting a TLS connection to a public IP. If the next line is a `Flags [S.]` from `93.184.216.34.443` back to `192.168.1.42.51334`, you have observed the first half of the three-way handshake. If instead nothing comes back, the server did not respond — either it is not listening, or a firewall dropped it.

This is what "reading packets" feels like once it is fluent: every field is a question you can answer.

---

## 10. Self-check

Without re-reading:

1. State the three RFC 1918 private IPv4 ranges in CIDR notation.
2. What does `/24` mean? How many usable hosts in a `/24`?
3. For each of these ports, name the canonical service: 22, 53, 80, 443, 3389, 5432, 6379, 27017.
4. Describe the TCP three-way handshake in three lines, naming the flags in each.
5. What is the `tcpdump` flag notation for "SYN+ACK"?
6. Name two things TLS does *not* protect, even when correctly configured.
7. Explain in one sentence why DNS is both essential infrastructure and the most-abused exfiltration channel.
8. A `tcpdump` capture shows a SYN from a client, then a RST from the server. What does this say about the server's state on that port?
9. Why is UDP trivially amplifiable for DDoS, and TCP much less so?

---

## Further reading

- **RFC 9293 — Transmission Control Protocol** (the modern consolidated TCP spec): <https://www.rfc-editor.org/rfc/rfc9293.html>
- **RFC 1035 — Domain Names**: <https://www.rfc-editor.org/rfc/rfc1035>
- **RFC 8446 — TLS 1.3**: <https://www.rfc-editor.org/rfc/rfc8446>
- **IANA Service Name and Transport Protocol Port Number Registry**: <https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml>
- **MITRE ATT&CK — T1071.004 (DNS as C2 / exfil)**: <https://attack.mitre.org/techniques/T1071/004/>

Next: [Lecture 2 — Reading Packets with `tcpdump` and Wireshark](./02-reading-packets-with-tcpdump-and-wireshark.md).
