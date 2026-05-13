# Lecture 2 — Reading Packets with `tcpdump` and Wireshark

> **Outcome:** You can run a useful `tcpdump` capture with a BPF filter; you can open a PCAP in Wireshark and follow a TCP stream; you can identify HTTP, TLS, DNS, and SSH by their first bytes on the wire; and you understand what the PCAP file format is and is not.

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

> **Legal reminder, specific to this lecture.** Capturing traffic on a network you do not own — even passively, even on an "open" Wi-Fi — is illegal in many jurisdictions (in the United States, see 18 U.S.C. § 2511 — the Wiretap Act; the consent of one party is enough on your own traffic, but you are not a party to other people's connections). Every capture in this week is on your own equipment, your own traffic, your own network.

This lecture is hands-on. Have a terminal open. Run the commands as you read them.

## 1. Why packet analysis is a fundamental defensive skill

The wire is the source of truth. Logs can be tampered with by an attacker on the host. Application traces can be incomplete. The packet capture — taken from a network tap, a SPAN port, or the host's own interface — is the closest thing to *evidence* a defender has.

Every blue-team role expects you to be comfortable opening a PCAP and answering basic questions: who talked to whom, when, in what protocol, with what apparent intent. Every incident-response post-mortem at some point includes the words "we then pulled the PCAP and observed..."

This lecture teaches the entry-level fluency. Two tools dominate: `tcpdump` on the terminal, Wireshark in the GUI. They share the same capture-filter dialect (BPF) and the same file format (PCAP / PCAPNG). Learn `tcpdump` for speed and headless servers; learn Wireshark for depth and protocol dissection.

---

## 2. `tcpdump` — the terminal capture tool

`tcpdump` is the canonical packet capture tool on Linux and BSD. It reads packets off an interface, applies a BPF filter, and prints a one-line summary per packet (or writes a PCAP file). It requires root or `CAP_NET_RAW` to open a raw socket.

### The five flags you will use 95% of the time

```bash
sudo tcpdump -i <iface> -nn -vvv -X -w <file.pcap> <filter expression>
```

- `-i <iface>` — interface to listen on. `-i any` to capture from all interfaces (Linux). `tcpdump -D` lists candidates.
- `-n` — do not resolve IPs to names. `-nn` — also do not resolve ports to service names. Add this *always* on a capture box: name resolution generates its own traffic, slows the capture, and pollutes the output.
- `-v`, `-vv`, `-vvv` — verbosity. `-vv` gives you TTL, IP ID, checksum verification, TCP options.
- `-X` — print packet contents as hex *and* ASCII. Useful for cleartext protocols.
- `-w <file>` — write a PCAP file instead of printing. Use this for anything you want to analyze later.
- `-r <file>` — read a PCAP file instead of capturing live.
- `-c <N>` — capture only N packets, then exit. Good for scripted captures.
- `-s <N>` — snaplen (bytes per packet captured). Default in modern `tcpdump` is the full packet (262,144 bytes). Older versions defaulted to 96; if you see a PCAP with truncated payloads, that is why.
- `-G <seconds> -W <count>` — rotate the capture file every `<seconds>`, keep `<count>` files. Standard for long-running captures.

### A first capture

```bash
sudo tcpdump -i any -nn -c 5
```

You will see five packets and then `tcpdump` exits. The output looks like:

```
12:14:02.418311 IP 192.168.1.42.51334 > 93.184.216.34.443: Flags [S], seq 3729012841, win 64240, length 0
12:14:02.480112 IP 93.184.216.34.443 > 192.168.1.42.51334: Flags [S.], seq 1287435019, ack 3729012842, win 65535, length 0
12:14:02.480445 IP 192.168.1.42.51334 > 93.184.216.34.443: Flags [.], ack 1287435020, win 64240, length 0
...
```

That is the three-way handshake from Lecture 1 in the wild. Read each line: source, destination, flags, sequence numbers, payload length.

### Saving a PCAP for later analysis

```bash
sudo tcpdump -i any -nn -w /tmp/lab.pcap -c 200 'tcp port 80 or tcp port 443'
```

This captures 200 packets of HTTP and HTTPS traffic, writes them to `/tmp/lab.pcap`, and exits. Read it back without root:

```bash
tcpdump -nn -r /tmp/lab.pcap | head
```

Or open it in Wireshark.

---

## 3. BPF — the capture filter language

The expression at the end of `tcpdump` is a **Berkeley Packet Filter (BPF)** expression. The kernel compiles it into a tiny program that runs against every packet on the interface, dropping the rejected ones before they reach userland. This is why BPF is fast even on busy interfaces.

BPF works at the *packet* level — IP, TCP/UDP, ICMP headers — not at the application layer. A filter for "HTTP requests with a particular path" is *not* a BPF filter; that is a Wireshark *display* filter (different syntax, applied after capture). Keep the two straight.

### The vocabulary

- **Hosts.** `host 192.168.1.10`, `src host 192.168.1.10`, `dst host 192.168.1.10`.
- **Networks.** `net 192.168.1.0/24`, `src net 10.0.0.0/8`.
- **Ports.** `port 53`, `src port 22`, `dst port 443`, `portrange 1024-65535`.
- **Protocols.** `tcp`, `udp`, `icmp`, `ip`, `ip6`, `arp`.
- **TCP flags.** `tcp[tcpflags] & tcp-syn != 0` matches packets with SYN set. There are mnemonics: `tcp-syn`, `tcp-ack`, `tcp-fin`, `tcp-rst`, `tcp-push`, `tcp-urg`.
- **Combinators.** `and`, `or`, `not`. Parenthesise when mixing.

### Filters you will actually use

```bash
# All DNS traffic
udp port 53

# Everything to or from one host
host 192.168.1.42

# Outbound web traffic from one host
src host 192.168.1.42 and (tcp port 80 or tcp port 443)

# TCP SYNs only (port-scan signature, half of the handshake)
'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'

# Anything except SSH from the box you are on
'not (tcp port 22)'

# IPv6 only
ip6

# Multicast
'(ether multicast or ip multicast or ip6 multicast)'
```

The bit-arithmetic filters can be cryptic; the comment in the man page (`man pcap-filter`) is the canonical reference. Bookmark it.

### One trap to remember

A filter is evaluated *per packet*. A TCP "connection" in BPF terms is *every packet whose source-or-destination matches the 4-tuple* — there is no concept of a flow. If you ask `tcpdump` for `tcp port 443`, you get every packet to or from port 443 — both directions, every flag, every retransmission. Wireshark adds a concept of "TCP stream" on top; BPF does not.

---

## 4. Wireshark — the GUI and the dissector library

`tcpdump` shows you packets. Wireshark *understands* them — its dissectors recognise hundreds of application protocols and present each field by name.

### Layout

When you open a PCAP in Wireshark, you see three panes:

1. **Packet list** (top) — one row per packet, with columns: time, source, destination, protocol, info. Click a row to select.
2. **Packet details** (middle) — the selected packet, decoded layer by layer. Expand each layer to read its fields. This is the pane you read most.
3. **Packet bytes** (bottom) — the raw bytes, hex and ASCII. Click a field in the details pane and the corresponding bytes highlight here.

### Display filters (different from BPF)

Wireshark's display filter syntax is its own language, applied *after* capture. It works at the application-protocol level — you can write `http.request.method == "POST"` or `tls.handshake.extensions_server_name == "github.com"`.

The display filters you will use most this week:

```
http
http.request.method == "POST"
tls
tls.handshake.type == 1            # TLS ClientHello
dns
dns.qry.name contains "exfil"
tcp.flags.syn == 1 and tcp.flags.ack == 0   # bare SYNs
ip.addr == 192.168.1.42
tcp.stream eq 0                    # the first TCP stream in the file
```

### Color coding

Wireshark's default color rules paint TCP RSTs red-on-black, retransmissions yellow, ARPs cyan, and so on. The full list is *View → Coloring Rules*. The colors are signal, not decoration: a packet list lit with red is telling you "look at the RSTs first."

### Follow TCP Stream

Right-click any TCP packet → *Follow → TCP Stream*. Wireshark reconstructs the application-layer bytes both directions and displays them in a window. For an HTTP/1.1 connection, you see the request and response in cleartext. For TLS, you see encrypted bytes — which is itself useful (the *handshake* is decoded; the body is not, unless you have the keys).

### Exporting a single conversation

If a PCAP contains many flows and you want only one, *Statistics → Conversations* lists them by 4-tuple. Right-click a row → *Apply as Filter → Selected* → then *File → Export Specified Packets* writes just that conversation to a new PCAP. This is the workflow for handing a single interesting flow to a colleague.

### `tshark` — Wireshark on the command line

Wireshark ships `tshark`, which exposes the same dissectors as a CLI tool. Useful for batch analysis:

```bash
# Print every HTTP host header from a PCAP
tshark -r /tmp/lab.pcap -Y http -T fields -e http.host

# Count packets per protocol
tshark -r /tmp/lab.pcap -q -z io,phs

# Decode TLS handshake details (SNI)
tshark -r /tmp/lab.pcap -Y tls.handshake.type==1 \
       -T fields -e ip.src -e tls.handshake.extensions_server_name
```

The `-Y` flag takes Wireshark's *display* filter syntax — different from `tcpdump`. The `-T fields -e <field>` formula extracts specific protocol fields.

---

## 5. Reading the three-way handshake in detail

Capture, then read:

```bash
sudo tcpdump -i any -nn -w /tmp/hs.pcap -c 6 'host example.com and tcp port 443'
curl -sS https://example.com/ > /dev/null    # in a second terminal
```

Open `hs.pcap` in Wireshark. You should see:

| # | Source | Destination | Protocol | Info |
|---|--------|-------------|----------|------|
| 1 | 192.168.1.42 | 93.184.216.34 | TCP | 51334 → 443 [SYN] |
| 2 | 93.184.216.34 | 192.168.1.42 | TCP | 443 → 51334 [SYN, ACK] |
| 3 | 192.168.1.42 | 93.184.216.34 | TCP | 51334 → 443 [ACK] |
| 4 | 192.168.1.42 | 93.184.216.34 | TLSv1.3 | Client Hello |
| 5 | 93.184.216.34 | 192.168.1.42 | TLSv1.3 | Server Hello, ... |
| 6 | ... | ... | ... | ... |

Packets 1, 2, 3 are the TCP handshake. Packet 4 is the first application byte the client sends — the TLS ClientHello, which includes the SNI extension. Expand the *Transport Layer Security* layer in the details pane and you will see the hostname in cleartext, even though the rest of the connection will be encrypted.

This is the canonical "read a handshake" exercise. Do it once on your own loopback or LAN; the muscle memory persists.

---

## 6. Identifying common protocols by signature

When a port is non-standard, the dissector still recognises most protocols by their on-the-wire signature. The signatures you should learn to spot:

### HTTP/1.1

Plain ASCII. The first bytes of a request are an HTTP method:

```
GET / HTTP/1.1\r\n
Host: example.com\r\n
\r\n
```

In `tcpdump -X`, the ASCII column on the right shows `GET / HTTP/1.1` immediately after the TCP three-way handshake. Any plaintext you see that looks like a textual protocol header is almost certainly HTTP.

### TLS (ClientHello)

The first byte from the client is `0x16` (TLS record type "Handshake"). The next two bytes are the TLS version (`0x0301` for TLS 1.0 record-layer compatibility — TLS 1.3 still uses this for the legacy header). Then a 2-byte length. Then `0x01` (the handshake message type "ClientHello"). In Wireshark, this is "TLSv1.3" or "TLSv1.2" with "Client Hello" in the Info column.

Two fields in the ClientHello matter to you as a defender:

- **`server_name` extension (SNI).** The hostname the client is connecting to, in cleartext.
- **The cipher-suite list and extension order.** These form the JA3 / JA4 fingerprint — a hash that characterises the client's TLS stack. Browsers, curl, Python `requests`, Go's `net/http` all have different fingerprints.

### DNS

UDP, port 53 (mostly; TCP 53 for zone transfers and large responses). The first bytes are a 2-byte transaction ID, then 2 bytes of flags, then four 2-byte counts (questions, answers, authority, additional). Then the question name in label-prefix encoding: each label is preceded by its length byte. `www.example.com` on the wire is `\x03www\x07example\x03com\x00`.

`tcpdump` decodes DNS by default:

```
12:01:33.140 IP 192.168.1.10.51001 > 192.168.1.1.53: 42345+ A? www.example.com. (33)
```

The `42345+` is the transaction ID and the recursion-desired flag. The `A? www.example.com.` is the question. The trailing `(33)` is the byte count.

### SSH

The first bytes from both client and server are a *banner* in cleartext:

```
SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2
```

The banner exchange happens before any encryption. This is *deliberate* — the protocol version negotiation has to be in cleartext for the key exchange that follows. Defensive corollary: the SSH banner on your server is a fingerprint. Internet-wide scans use it to build vulnerability inventories. (`Shodan` and `Censys` are the canonical examples.) You cannot easily "hide" SSH; you can put it behind a VPN or a port-knocker.

### ICMP echo (ping)

ICMP echo request (type 8) and echo reply (type 0). Useful for liveness checks and the basis of `ping` and (older) `traceroute`. In `tcpdump`: `IP 1.2.3.4 > 5.6.7.8: ICMP echo request, id 12345, seq 1, length 64`.

### ARP

Layer 2; you only see it on the local segment, and only with `-i <ethernet-iface>` (not `-i any`, which on Linux gives you a synthetic "Linux SLL" link layer and may not show ARP). Important because the *entire* trust model of a LAN rests on "I asked who has 192.168.1.1 and someone answered." On an untrusted LAN, ARP spoofing is the basic MITM.

---

## 7. The PCAP file format

The classic PCAP format (libpcap-style) is a tiny header followed by a list of packet records. Each record is a timestamp, an "original length," a "captured length" (which may be less if you set a snaplen), and the bytes themselves. The whole format fits in two paragraphs and is documented at <https://wiki.wireshark.org/Development/LibpcapFileFormat>.

PCAPNG (the modern successor, the default in current Wireshark) is a more structured block format. It supports multiple interfaces per file, per-interface metadata, name resolution sections, comments per packet, and other things the original PCAP could not represent. Backwards compatibility: every tool that reads PCAPNG reads PCAP; the reverse is not always true.

For Week 2's purposes, you should know:

- A PCAP is **the raw bytes off the wire**. Anything in cleartext on the wire is in cleartext in the PCAP. A PCAP from a corporate network is *probably* sensitive — you can read passwords, cookies, tokens, session IDs, internal hostnames. Handle PCAPs with the same care as `/var/log/auth.log`.
- A PCAP has a **fixed magic number** at the start (`0xa1b2c3d4` for libpcap, `0x0a0d0d0a` for PCAPNG). `file <name>.pcap` recognises both.
- PCAP **does not include** anything about the host's view: process names, TLS keys, kernel state. To decrypt a PCAP, you need keys exported separately (`SSLKEYLOGFILE` for browser TLS sessions; Wireshark reads the file and decrypts inline). To map a flow back to a process, you need host-side context (`ss`, `lsof`, eBPF tracing — Week 9 territory).

The PCAP is *evidence*. Treat it as such: hash it (`sha256sum`), keep an original immutable copy, work on copies. The mini-project requires this discipline.

---

## 8. A practical workflow — capture, filter, analyze

The defender's typical sequence:

1. **Decide the scope.** Which interface? Which hosts? Which time window? Be specific. The cheapest mistake in packet analysis is "capture everything for hours" and then have a 40 GB PCAP nobody can open.
2. **Capture deliberately, with a filter.** A narrow BPF expression is your friend. If you do not know in advance what you are looking for, take a *short* unfiltered capture (60 seconds, perhaps), then iterate.
3. **Open in Wireshark.** Apply a display filter. Use *Statistics → Conversations* and *Statistics → Protocol Hierarchy* to get a global picture before drilling in.
4. **Identify each flow.** For each significant conversation, name the protocol, the parties, the rough intent. Anything you cannot identify is a question to research.
5. **Document.** A capture you cannot describe is a capture you have not analyzed. The mini-project's whole point is the *annotation*.

A worked example follows in the mini-project README.

---

## 9. Tooling adjacent to `tcpdump` and Wireshark

You will encounter these names; a paragraph on each:

- **`tshark`** — the CLI form of Wireshark. Same dissectors. Scriptable. Often the right tool for "count X across a 1 GB PCAP."
- **`tcpflow`** — reconstructs TCP flows directly into per-stream files. Good for "show me every HTTP response body in this capture."
- **`ngrep` / `zgrep`** — grep over packet payloads. Crude but fast.
- **`zeek` (formerly Bro)** — a high-level network analysis platform; turns packets into typed logs (connection log, HTTP log, DNS log, x509 log, TLS log). The professional analyst's workhorse, but Week 2 stays on `tcpdump` + Wireshark. Zeek returns in Week 9.
- **`suricata` and `snort`** — IDS engines. Apply signature and rule-based detections to live or recorded traffic. Week 9.
- **`mitmproxy` and Burp Community** — *interactive* proxies for HTTPS interception, useful for TLS-terminated app analysis. Different from packet capture: these terminate the TLS, you see the cleartext, and you act as a willing MITM (between your own browser and the server). Week 4.

---

## 10. Common traps and how to avoid them

- **Capturing on `-i any` and losing layer 2.** On Linux, `tcpdump -i any` uses a synthetic link layer that has no ARP, no Ethernet header. For LAN troubleshooting, capture on a real interface.
- **Forgetting `-n` and seeing reverse-DNS storms.** Without `-n`, `tcpdump` resolves every IP. Each resolution is itself a DNS query in your capture. The output becomes self-referential.
- **A snaplen that truncates payloads.** Modern `tcpdump` defaults to the full packet, but older systems default to 96 bytes. Always check `-s 0` (older notation) or accept the modern default; confirm with the first packet's "captured length" matching its "original length."
- **Display filters where you wanted capture filters.** `tcpdump 'http'` does *not* mean "HTTP packets" — `tcpdump`'s grammar has no `http` keyword. The kernel BPF cannot read the application layer. You filter by port (`tcp port 80`) and let Wireshark dissect.
- **Trusting an attacker-supplied PCAP.** Specially-crafted PCAPs have triggered parser bugs in Wireshark (multiple historical CVEs). Open suspicious PCAPs in a sandbox. (`tshark -r untrusted.pcap` in a disposable VM is the conservative move.)
- **Reading content without the legal right to.** Re-read Section 0 of this lecture. Re-read it again.

---

## 11. Self-check

Without re-reading:

1. Name the difference between a BPF capture filter and a Wireshark display filter. Give one example of each.
2. What command captures 100 packets of DNS traffic on `eth0`, writes to `/tmp/dns.pcap`, and does not resolve names?
3. In Wireshark's display filter syntax, write a filter for "TLS ClientHello packets from any source."
4. What protocol begins every connection with the bytes `SSH-2.0-` in cleartext?
5. What two TLS extensions in the ClientHello are most valuable to a defender, and why?
6. State two things a PCAP file does *not* contain, even though they are relevant to incident response.
7. Why is "`tcpdump 'http'`" not a valid expression?
8. What does the "Follow TCP Stream" feature in Wireshark do?
9. Name a class of attack where the PCAP is the cleanest evidence available to the defender. Why?

---

## Further reading

- **`man pcap-filter`** — the BPF reference. Read it on your own box.
- **Wireshark User's Guide**: <https://www.wireshark.org/docs/wsug_html_chunked/>
- **Wireshark Display Filter Reference**: <https://www.wireshark.org/docs/dfref/>
- **The libpcap file format**: <https://wiki.wireshark.org/Development/LibpcapFileFormat>
- **PCAPNG specification**: <https://github.com/pcapng/pcapng>
- **"Practical Packet Analysis," Chris Sanders** — the standard introductory book; library or used.

Next: [Lecture 3 — Firewalls and Segmentation](./03-firewalls-and-segmentation.md).
