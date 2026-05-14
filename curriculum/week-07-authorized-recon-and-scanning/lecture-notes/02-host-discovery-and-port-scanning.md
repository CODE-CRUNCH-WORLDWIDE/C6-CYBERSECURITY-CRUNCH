# Lecture 2 — Host Discovery and Port Scanning

> *Once the RoE is signed and the scope is clear, the first technical question is: of the IPs in scope, which ones are alive, and on which TCP and UDP ports does each one listen? This lecture answers that question with the smallest possible toolkit — `nmap` for the careful work, `masscan` for the wide work, `naabu` for the modern asynchronous case — and the protocol-level understanding that lets you reason about which packets you are putting on the wire, why, and what they cost.*

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Every command in this lecture is illustrated against 127.0.0.1     │
│  (your loopback), a host-only VM you own, or a placeholder          │
│  198.51.100.x address from the documentation-only block             │
│  (RFC 5737). Do not substitute a real address you are not           │
│  authorised to scan. Do not run any of the example commands         │
│  against any system not covered by an RoE you hold.                 │
└─────────────────────────────────────────────────────────────────────┘
```

This lecture covers:

- The **TCP and UDP protocol primitives** the scanner is exercising, with the relevant RFC pointers.
- **Host discovery** — `nmap -sn`, the ARP / ICMP / TCP-probe layering, when to skip host discovery with `-Pn`.
- **TCP port scanning** — `-sS` versus `-sT` versus `-sA`, what each looks like on the wire, what each costs and signals.
- **UDP port scanning** — `-sU` and why it is slow, unreliable, and necessary anyway.
- **Rate-limit reasoning** — `--max-rate`, `--min-rate`, the timing templates `-T0..-T5`, `--scan-delay`, `--host-timeout`, `--max-retries`, and the *packets-per-second to time* trade.
- **`masscan` and `naabu`** — the fast-scan alternatives, their independent stacks, and the `masscan -> nmap` pipeline.
- **Common failure modes** — packet loss, intermediate firewalls, stateful network gear, the "false negative versus false positive" trade.

---

## 1. The protocol primitives you are exercising

A scanner is a careful generator of network packets. The packets it sends and the responses it parses are all defined in published RFCs you should have read at least once. The short version follows; the canonical references are in § 7.

### 1.1 The TCP three-way handshake (RFC 793 § 3.4, RFC 9293 § 3.5)

When a client wants to open a TCP connection to a server's listening port, the conversation is:

1. **Client → Server: SYN.** A TCP segment with the SYN flag set, no payload, an initial sequence number.
2. **Server → Client: SYN-ACK.** A TCP segment with both SYN and ACK flags, acknowledging the client's sequence number and offering its own.
3. **Client → Server: ACK.** A TCP segment with the ACK flag, acknowledging the server's sequence number. The connection is now established.

If the server's port is **closed**, the server's TCP stack responds to the initial SYN with a **RST** (reset) instead of a SYN-ACK. The presence or absence of a SYN-ACK or RST tells the scanner whether the port is *open* or *closed*; the absence of *either* response (the SYN is silently dropped) tells the scanner the port is *filtered* (by a firewall, by an intermediate device, or by the host's own packet filter).

The three-way handshake is the foundation of the SYN scan (`-sS`) and the connect scan (`-sT`).

### 1.2 The UDP datagram (RFC 768)

UDP has no handshake. A UDP "scan" sends a datagram to a UDP port and waits to see:

- **An application-layer response** (e.g. DNS reply to a DNS query, SNMP response to an SNMP query). The port is *open*.
- **An ICMP Destination Unreachable, code 3 (Port Unreachable)**. The port is *closed* and the host is up.
- **No response at all**. The port is *open|filtered* — the scanner cannot distinguish "an open port whose server happens not to reply to this probe" from "a filtered port whose probe was dropped."

UDP scanning is fundamentally less accurate than TCP scanning because of the response asymmetry. § 4 of this lecture covers what you do about it.

### 1.3 ICMP echo (RFC 792 § Type 8 / Type 0)

ICMP type 8 is an echo request; ICMP type 0 is an echo reply. The `ping` command is a thin wrapper around this exchange. ICMP type 3 is destination unreachable, with various codes including:

- code 1 (host unreachable)
- code 3 (port unreachable — used by UDP scan logic)
- code 13 (communication administratively prohibited — used as a firewall signature)

Host discovery (`-sn`) leans on ICMP echo by default for off-subnet targets and on ARP for on-subnet targets.

### 1.4 ARP (RFC 826)

ARP resolves an IP address to a MAC address on the local subnet. On a local subnet, *every* TCP / UDP / ICMP packet you send to a target is preceded by an ARP exchange. `nmap -sn` on a local subnet uses ARP requests directly as the host-discovery probe; ARP is more reliable than ICMP on a LAN because hosts cannot ignore an ARP request and remain reachable.

### 1.5 Why the protocol layer matters to the scanner operator

Two reasons. First, a flag like `nmap -sS` has a specific meaning at the protocol layer — it sends a SYN and reads either a SYN-ACK or a RST — and reasoning about flags without that grounding produces engineers who run commands they cannot debug. Second, when something goes wrong (no responses, partial responses, weird mid-scan stalls), the diagnosis starts with "what is happening on the wire?" The protocol layer is the *only* layer the scanner is in control of; everything above (the operating system, the application, the firewall) is the *responder's* problem.

---

## 2. Host discovery — finding the live hosts

Before scanning ports, you scan for hosts. A `/24` is 256 addresses; a `/16` is 65,536; a `/8` is 16.7 million. Spending time probing every port on every potential address is wasteful when 90% of the addresses are unallocated.

### 2.1 `nmap -sn` — the ping sweep

```bash
sudo nmap -sn 10.0.2.0/24
```

`-sn` (formerly `-sP`, "ping scan") means: do host discovery, do not do port scanning. On a local subnet (a route the host has in its routing table as `link`), `-sn` sends ARP requests by default. Off-subnet, `-sn` sends a default probe set that includes:

- ICMP echo (type 8)
- ICMP timestamp (type 13)
- TCP SYN to port 443
- TCP ACK to port 80

Any response from any probe marks the host as up. The multi-probe approach handles hosts that filter ICMP but accept TCP, and vice versa.

Output:

```text
Nmap scan report for 10.0.2.15
Host is up (0.00012s latency).
MAC Address: 08:00:27:AB:CD:EF (Oracle VirtualBox virtual NIC)
```

### 2.2 `-Pn` — skip host discovery, assume up

```bash
sudo nmap -Pn -sS 198.51.100.42
```

`-Pn` (formerly `-PN`) means: do not do host discovery; treat every target as up and proceed straight to port scanning. Use `-Pn` when:

- The target is known to filter all host-discovery probes (cloud-hosted hosts often filter ICMP entirely).
- You are scanning a single high-value target and host-discovery is wasted time.
- An RoE explicitly requires you to skip host discovery to reduce probe variety on the wire.

`-Pn` is *the* most common modern setting against internet-facing hosts. It is *not* free: every port scan against every "host" you cannot first confirm is up will run to completion before reporting, often slowing the overall scan if 99% of the address space is unallocated.

### 2.3 The "host-discovery vs. port-scan" decision

A useful heuristic:

| Target shape                                    | Recommended approach                                  |
|-------------------------------------------------|-------------------------------------------------------|
| One known live host                             | `-Pn -sS -p <ports>`                                  |
| A few known live hosts                          | `-Pn -sS -p <ports>` against the list                 |
| A `/24` on a local subnet you control           | `nmap -sn` first to enumerate, then targeted scans    |
| A `/24` off-subnet, cloud-hosted, ICMP filtered | `nmap -Pn -sS -p <small port set>` to find live ones  |
| A large internet range (with RoE)               | `masscan --rate <low>` for sweep, `nmap` to enrich    |

---

## 3. TCP port scanning — the canonical modes

This is the core technical work of the week. The flags below produce different packet patterns on the wire and tell you different things about the target.

### 3.1 TCP SYN scan — `-sS` — the default for root

```bash
sudo nmap -sS -p 1-1000 127.0.0.1
```

`-sS` is the **TCP SYN scan** ("half-open scan"). The scanner sends a SYN; if the response is a SYN-ACK, it marks the port open and sends a RST (rather than completing the handshake) to tear the connection down before the kernel ever sees it. If the response is a RST, the port is closed. If no response arrives, the port is filtered.

The SYN scan is fast because:

- It does not complete the three-way handshake, so it does not generate connection-tracking entries on the target (in most stacks).
- The scanner can fire many probes in parallel without waiting for a full connection lifecycle each time.
- The detection footprint on most application-layer logs is zero — the scanner never establishes a full TCP connection, so the server's `accept(2)` is never called.

`-sS` is the default on Linux when `nmap` runs as root (it requires raw-socket access to forge the SYN and ignore the kernel's automatic RST). On macOS the situation is similar. On Windows it depends on the toolchain.

The "stealth" historically attributed to `-sS` is overstated: every modern IDS / IPS / NDR product fingerprints half-open scans easily. The advantage today is *speed*, not stealth.

### 3.2 TCP connect scan — `-sT` — the unprivileged fallback

```bash
nmap -sT -p 1-1000 127.0.0.1
```

`-sT` is the **TCP connect scan**. Instead of forging raw packets, the scanner calls the operating system's `connect(2)` system call. The kernel performs the full three-way handshake (the application logs see it), and either the connection succeeds (port open), `connect(2)` returns ECONNREFUSED (port closed), or the connection times out (port filtered).

`-sT` is the default when `nmap` runs *without* root. It is slower than `-sS` because the kernel maintains state for every connection attempt. It is also more visible on the target — application logs typically record full connections, not half-open SYNs.

Use `-sT` when:

- You cannot run as root (a managed laptop, a constrained CI environment).
- The target's network state is being measured and you want the scan to look like normal client traffic (an explicit RoE choice).
- You are scanning IPv6 (`-sS` works on IPv6 too in modern `nmap`, but `-sT` is sometimes simpler).

### 3.3 ACK scan — `-sA` — for firewall mapping

```bash
sudo nmap -sA -p 80,443 198.51.100.42
```

`-sA` sends bare ACK packets. A stateful firewall drops the ACK (the firewall has no record of the connection these ACKs would belong to); a stateless firewall, or a host with no firewall, returns a RST. The scan tells you not whether the port is open, but whether the *path* to the port is stateful-firewall-filtered.

`-sA` is rarely the primary scan; it is a diagnostic when other scan modes return unexplained "filtered" results.

### 3.4 FIN / NULL / Xmas scans — `-sF`, `-sN`, `-sX`

These send TCP packets with unusual flag combinations:

- `-sF` (FIN scan): FIN flag only.
- `-sN` (NULL scan): no flags set.
- `-sX` (Xmas scan): FIN, PSH, URG flags set.

Per RFC 793, a closed port should respond with RST to any of these; an open port should not respond at all. In practice, modern stacks (Windows since XP SP2, certain BSDs) behave non-conformantly and return RST regardless. These scans are educational curiosities; they rarely produce useful results against contemporary targets.

### 3.5 Idle scan — `-sI` — the curiosity

`-sI` uses a third-party "zombie" host with a predictable IP-ID counter to scan a target without sending packets from your own IP. The scan is slow, unreliable, easy to detect (the zombie's behaviour stands out), and operationally useless on modern networks where IP-ID randomisation is universal. It exists in the `nmap` toolbox for completeness; you will not run it in this curriculum.

### 3.6 Choosing the port range

`nmap` by default scans the **top 1000** TCP ports (the 1000 most-frequently-found-open ports across `nmap`'s historical scan corpus). The full TCP port space is 65,535 ports. The trade is time-versus-coverage:

| Range                          | Time on a fast subnet | Coverage of *real* services       |
|--------------------------------|-----------------------|-----------------------------------|
| `-F` (fast, top 100)           | seconds               | ~90%                              |
| default (top 1000)             | tens of seconds       | ~95%                              |
| `-p-` (all 65,535)             | minutes to hours      | 100% within the TCP protocol      |
| `-p <list>` (specific)         | fastest               | only what you specify             |

For a recon report, `-p-` against a single high-value host is appropriate; `--top-ports 1000` against a full subnet is appropriate; `-F` against a wide range as a "first sweep" is appropriate.

---

## 4. UDP port scanning — the slow, necessary case

```bash
sudo nmap -sU --top-ports 100 127.0.0.1
```

`-sU` is the UDP scan. It is fundamentally slower and less reliable than TCP scanning for the reasons in § 1.2. Three operational realities:

1. **The default `-sU` rate is slow on purpose.** UDP probes that go unanswered must be retried, and the responder's rate-limit on ICMP unreachable messages (typically 1 per second per source on Linux) bounds the discovery rate. A full-range UDP scan (`-sU -p-`) on a single host can take *days*.

2. **`-sU` benefits enormously from version probes.** With `-sU -sV`, `nmap` sends service-specific UDP payloads (DNS query, SNMP get, NTP request, etc.) that are far more likely to produce a useful response than a blind empty UDP packet. The combination is more accurate but also slower.

3. **`--top-ports 100` for UDP is the operational starting point** for most engagements. The top-100 UDP ports cover DNS, SNMP, NTP, NetBIOS, LDAP, IKE, mDNS, and the handful of other UDP services that account for nearly every UDP finding in practice.

UDP scanning is the second-class citizen of port scanning. You include it in the engagement plan because some critical services are UDP-only; you do not pretend it is as reliable as TCP scanning.

---

## 5. Rate limits and "scanning without melting the network"

This section is the operationally critical one for any engagement against a production network. The default `nmap` settings are tuned for accuracy on a small target; against a large or sensitive target they are wrong, sometimes destructively so. The discipline is to *think* about rate before each engagement and to set the rate explicitly.

### 5.1 The timing templates — `-T0` through `-T5`

`nmap` ships with six pre-tuned timing profiles:

| Template     | Name         | Approximate use case                                          |
|--------------|--------------|---------------------------------------------------------------|
| `-T0`        | Paranoid     | IDS-evasion lab work. 5-minute delay between probes.          |
| `-T1`        | Sneaky       | IDS-evasion lab work. 15-second delay between probes.         |
| `-T2`        | Polite       | Production network, owner concerned about load.               |
| `-T3`        | Normal       | Default. General-purpose, accurate, moderate rate.            |
| `-T4`        | Aggressive   | Fast, modern network, owner OK with the noise.                |
| `-T5`        | Insane       | Lab work only; sacrifices accuracy for speed.                 |

The templates set a bundle of underlying parameters (max retries, parallelism, timeout, scan-delay). For an authorised engagement against a production network, `-T3` or `-T4` is the operationally common setting; `-T0`/`-T1` are for the IDS-evasion educational case (which is rarely the right tool — see § 5.4); `-T5` is rarely correct anywhere.

### 5.2 Explicit rate flags — `--max-rate`, `--min-rate`

```bash
sudo nmap --max-rate 500 -sS -p- 198.51.100.42
```

`--max-rate <pps>` caps the scanner at the stated packets-per-second across the entire scan. This is the **most reliable way to enforce an RoE rate cap**; the timing templates are convenient but imprecise.

`--min-rate <pps>` does the opposite — guarantees a minimum sending rate even if `nmap`'s adaptive logic would otherwise slow down. Use sparingly; this is the flag that produces "I cratered the network" stories.

### 5.3 `--scan-delay` and `--max-retries`

`--scan-delay <time>` enforces a minimum delay between probes from the same source. `100ms` is gentle; `1s` is very gentle and very slow.

`--max-retries <N>` caps how many times `nmap` retries a probe that goes unanswered. The default is 10; in a high-loss environment you might raise it; in a known-good environment you might lower it for speed.

### 5.4 Why "IDS evasion" is usually the wrong frame

Newcomers reach for `-T0` and `-T1` thinking they will "evade detection." Three problems:

1. **Modern detection is signature-and-behaviour-based, not rate-based.** A modern NDR notices the *pattern* of probes (one packet to one port from one source, no follow-up application traffic) regardless of whether the probes arrive at 1pps or 0.001pps.
2. **A long scan is a long signal.** Spreading a scan across hours of `-T0` lets a defender's analytics correlate the probes over time. A short fast scan is sometimes harder to attribute than a long slow one.
3. **The RoE almost always says "do not deliberately evade detection."** Detection-evasion in authorised testing is usually scoped *in* — the customer wants to know whether the SOC catches you — and the right approach is to inform the SOC ahead, not to twist the scanner.

If the engagement scope includes "test the SOC's detection capability," do it deliberately and in a separate phase, not by accident through `-T0`.

### 5.5 `masscan`'s rate parameter and the rate-is-a-weapon problem

```bash
sudo masscan --rate 1000 -p1-65535 198.51.100.0/24
```

`masscan`'s `--rate` flag controls packets-per-second. Defaults are *fast* — the README candidly notes the tool's headline performance number is "the entire IPv4 internet in under six minutes" at 10 million pps. That number is correct, and it is also exactly the rate that will be detected, complained about, and possibly billed for by an upstream ISP within minutes.

Operational rules for `masscan`:

- Always set `--rate` explicitly. Never let it default.
- For a single `/24` against a real target with an RoE, `--rate 1000` is a sensible upper bound.
- Test `--rate` against a known controlled target (your own VM) first to confirm your network can sustain the rate without packet loss.
- Coordinate with the target's network team if the target is on a metered link.

### 5.6 What "did we crash production?" looks like

The failure mode is not glamorous; it is mundane and embarrassing. Typical signs the scan is over-aggressive:

- Round-trip latency to the target spikes during the scan.
- `nmap`'s own "increasing send delays due to N out of M dropped probes since last increase" warnings appear repeatedly.
- The target's owner contact pings you saying "we're seeing increased load on the network — is that you?"
- A specific service on the target becomes unresponsive (often a low-quality load balancer or a misconfigured stateful firewall mid-path).

When any of these appears, **stop**. Pause the scan, talk to the owner contact, find the cause, and adjust the rate before resuming. The cost of pausing for an hour is small. The cost of continuing through a customer's outage is the engagement.

---

## 6. The fast-scan alternatives: `masscan` and `naabu`

### 6.1 `masscan`

`masscan` is Robert Graham's "internet-scale" scanner. Its distinguishing properties:

- **Independent TCP stack.** `masscan` does not use the host's network stack; it crafts its own SYN packets and reads responses directly off the wire. This is what lets it operate at extreme rates without exhausting the host kernel's connection tables.
- **Single-port-at-a-time efficiency.** Architecturally optimised for "scan port 443 across this `/8`," less so for "scan a wide port range against a small target."
- **Output formats compatible with `nmap` pipelines.** `-oX` produces an `nmap`-like XML; the same `xml.etree.ElementTree` parser from Exercise 3 works on `masscan` output.

The canonical `masscan -> nmap` pipeline:

```bash
# Step 1 - wide sweep with masscan, single port, low rate
sudo masscan --rate 1000 -p443 198.51.100.0/24 -oG masscan-443.gnmap

# Step 2 - extract the live hosts from masscan output
awk '/Host:/ {print $2}' masscan-443.gnmap | sort -u > live-hosts.txt

# Step 3 - careful nmap enrichment of just the live hosts
sudo nmap -iL live-hosts.txt -sS -sV -sC -p- -oX nmap-enrichment.xml
```

The pipeline gives you `masscan`'s speed for discovery and `nmap`'s accuracy for enrichment.

### 6.2 `naabu`

`naabu` is ProjectDiscovery's modern asynchronous port scanner. Distinguishing properties:

- **Single-binary, modern Go runtime.** Easy to install; no kernel-modification awkwardness.
- **Native pipeline integration with the rest of ProjectDiscovery's toolchain** (`httpx`, `nuclei`, `subfinder`).
- **Smaller feature set than `nmap`** — no NSE, no OS-fingerprinting, no fancy timing knobs. The tool is deliberately scoped to "find open ports fast and feed them to the next tool."

```bash
naabu -host 198.51.100.42 -p - -rate 1000 -o naabu.txt
```

For most Week 7 work, `naabu` is a convenience for the "I want fast port discovery without `masscan`'s setup overhead" case. It does not replace `nmap` for service detection or NSE work.

### 6.3 Which one to use when

| Situation                                              | Tool                         |
|--------------------------------------------------------|------------------------------|
| One host, careful, full service-detection              | `nmap`                       |
| A `/24`, careful                                       | `nmap`                       |
| A `/16` or larger, with an explicit RoE allowing it    | `masscan` for sweep, `nmap` for enrichment |
| Bug bounty recon on a published large scope            | `naabu` -> `httpx` -> `nuclei` |
| Anything where you doubt the right answer              | `nmap` (the default is rarely wrong) |

The principle: *fast tools find candidates, careful tools enrich them*. The two passes are different jobs.

---

## 7. Common failure modes and how to debug them

Five problems you will see and how to diagnose each.

### 7.1 "All ports show filtered"

Either the target is genuinely filtered (a firewall is dropping your probes), the route to the target is broken, or your scanner is mis-configured. Debug:

```bash
# Is the host reachable at the IP layer at all?
ping -c 4 <target>

# Does an explicit TCP connection succeed on a known service?
nc -vz <target> 80

# Does an unfiltered probe (ACK scan) reveal stateful filtering?
sudo nmap -sA -p 80,443 <target>
```

### 7.2 "Scan stalls partway through"

Symptoms: `nmap` reports an estimated time of 10 minutes, then 20, then 60, then "infinity." Causes:

- The target's upstream network is rate-limiting your traffic. Reduce `--max-rate`.
- A stateful firewall mid-path is filling its state table with half-open SYNs. Reduce parallelism (`--min-parallelism 1 --max-parallelism 10`).
- Your own host is the bottleneck — a laptop on Wi-Fi cannot sustain high pps. Move to wired.

### 7.3 "Different scans report different results"

Run the same scan twice; the second scan reports a different set of open ports. Causes:

- Packet loss between scans means probes are being dropped non-deterministically. Increase `--max-retries` and reduce rate.
- A connection-rate-limit on the target is closing your scanner's probes after N per minute. Reduce rate.
- The target is genuinely changing state between scans (auto-scaling, load-balancer pool rotation). Note this in the report; it is a finding in its own right.

### 7.4 "OS fingerprint says Windows 95"

You ran `-O` on a host that doesn't respond to enough of the OS-fingerprint probes for `nmap` to make an accurate guess. `nmap` defaults to its best match from the available data, which can be very wrong when the data is sparse. § 3.4 of Lecture 3 covers this in more depth; the operational rule is: do not trust an `-O` result with a low "Aggressive OS guesses" confidence number.

### 7.5 "The scan triggers the customer's IDS"

If the RoE says "do not trigger the IDS," reduce rate and probe variety; consider `-sT` instead of `-sS` to look more like normal application traffic. If the RoE says "do trigger the IDS," nothing has gone wrong; document the alert in the report. Either way, communicate with the SOC contact.

---

## 8. A worked example: scanning your own loopback safely

For the practical work this week, every command below is safe on your own loopback. Run them in order:

```bash
# 1. Confirm your toolchain
nmap --version
which masscan
which naabu  # may be absent; optional

# 2. Confirm the loopback responds
ping -c 4 127.0.0.1

# 3. Host discovery only
sudo nmap -sn 127.0.0.1

# 4. Default scan (top 1000 TCP, SYN scan)
sudo nmap -sS 127.0.0.1

# 5. Full-range TCP, rate-capped
sudo nmap -sS --max-rate 5000 -p- 127.0.0.1

# 6. UDP top 100, rate-capped, with version probes
sudo nmap -sU -sV --top-ports 100 --max-rate 100 127.0.0.1

# 7. XML output for Exercise 3 parsing
sudo nmap -sS -sV --top-ports 100 -oX /tmp/loopback.xml 127.0.0.1
```

Read the output for each. The loopback typically shows a handful of locally-listening services (SSH on a developer laptop; DNS if you run a local resolver; the Vagrant or VirtualBox NAT services if you have those running). The exact set tells you about your own machine; *that is the only host you should be running these against right now*.

---

## 9. Closing

Two things to take from this lecture:

1. **The scanner is a packet generator and a response parser.** Every flag corresponds to a specific protocol-layer action; the more clearly you can see the packets, the more clearly you can reason about the result. The Nmap book Chapter 5 is the next thing to read after this lecture; it walks every scan type at the wire level with packet captures.

2. **Rate is a contract, not a default.** Every scan you run against a target you do not own should set `--max-rate` explicitly. Every engagement RoE should record the rate cap. The discipline of "I always set the rate, even on my own loopback" is the one that keeps you out of trouble when you transfer to the customer network.

Read Lecture 3 once you have the protocol layer and the rate discipline internalised.

---

## References

- Nmap Network Scanning, Chapter 5 (Port Scanning Techniques): <https://nmap.org/book/man-port-scanning-techniques.html>.
- Nmap Network Scanning, Chapter 6 (Optimizing Nmap Performance): <https://nmap.org/book/man-performance.html>.
- RFC 793 — Transmission Control Protocol: <https://www.rfc-editor.org/rfc/rfc793>.
- RFC 9293 — Transmission Control Protocol (consolidated): <https://www.rfc-editor.org/rfc/rfc9293>.
- RFC 768 — User Datagram Protocol: <https://www.rfc-editor.org/rfc/rfc768>.
- RFC 792 — Internet Control Message Protocol: <https://www.rfc-editor.org/rfc/rfc792>.
- RFC 826 — Address Resolution Protocol: <https://www.rfc-editor.org/rfc/rfc826>.
- masscan README: <https://github.com/robertdavidgraham/masscan>.
- naabu documentation: <https://docs.projectdiscovery.io/tools/naabu/overview>.
