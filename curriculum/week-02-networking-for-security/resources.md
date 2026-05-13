# Week 2 — Resources

Every resource here is **free** and **publicly accessible**. Most are primary sources — read them in preference to summaries.

## Primary sources — read first

- **RFC 9293 — Transmission Control Protocol (TCP)** (the modern consolidated TCP specification, August 2022, supersedes RFC 793):
  <https://www.rfc-editor.org/rfc/rfc9293.html>
- **RFC 791 — Internet Protocol (IPv4)** (still the normative IPv4 reference):
  <https://www.rfc-editor.org/rfc/rfc791>
- **RFC 8200 — Internet Protocol, Version 6 (IPv6) Specification**:
  <https://www.rfc-editor.org/rfc/rfc8200>
- **RFC 1918 — Address Allocation for Private Internets** (`10/8`, `172.16/12`, `192.168/16`):
  <https://www.rfc-editor.org/rfc/rfc1918>
- **RFC 1035 — Domain Names, Implementation and Specification** (DNS; still the base reference):
  <https://www.rfc-editor.org/rfc/rfc1035>
- **RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3**:
  <https://www.rfc-editor.org/rfc/rfc8446>
- **RFC 9110 — HTTP Semantics** (the modern HTTP reference; supersedes RFC 7230-7235):
  <https://www.rfc-editor.org/rfc/rfc9110.html>
- **IANA Service Name and Transport Protocol Port Number Registry** (the authoritative port list):
  <https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml>

## Tool documentation

- **`tcpdump` manual** — `man 1 tcpdump`; online at <https://www.tcpdump.org/manpages/tcpdump.1.html>.
- **`pcap-filter` manual** (the BPF capture-filter syntax shared by `tcpdump`, Wireshark, `tshark`):
  <https://www.tcpdump.org/manpages/pcap-filter.7.html>
- **Wireshark User's Guide** (free, comprehensive):
  <https://www.wireshark.org/docs/wsug_html_chunked/>
- **Wireshark Display Filter Reference** (display filters are *not* BPF; they are a separate syntax):
  <https://www.wireshark.org/docs/dfref/>
- **`nftables` wiki** (the modern Linux firewall):
  <https://wiki.nftables.org/wiki-nftables/index.php/Main_Page>
- **`iptables` manual** (still in use; understand it for legacy systems):
  <https://ipset.netfilter.org/iptables.man.html>
- **netfilter project home**:
  <https://www.netfilter.org/>

## Free sample PCAPs

These captures are distributed by their authors specifically for learning. Use them; do not reuse anyone else's traffic without permission.

- **Wireshark Sample Captures wiki** (dozens of captures by protocol):
  <https://wiki.wireshark.org/SampleCaptures>
- **Malware-Traffic-Analysis.net** (Brad Duncan; real-world malicious-traffic captures with write-ups; download with care, treat as untrusted):
  <https://www.malware-traffic-analysis.net/>
- **NETRESEC PCAP files** (curated index of public PCAP repositories):
  <https://www.netresec.com/?page=PcapFiles>

## CVEs and advisories worth reading this week

- **CVE-2022-21449 (Psychic Signatures)** — ECDSA signature verification flaw in Java, accepts an all-zero signature. A textbook lesson in why TLS implementation correctness matters even when the protocol is sound.
  <https://nvd.nist.gov/vuln/detail/CVE-2022-21449>
- **CVE-2014-0160 (Heartbleed)** — OpenSSL heartbeat extension read overflow. The bug that taught a generation of defenders to do PCAP analysis on TLS:
  <https://nvd.nist.gov/vuln/detail/CVE-2014-0160>
- **CVE-2008-1447 (Kaminsky DNS cache poisoning)** — the DNS bug that retrofitted source-port randomization across every resolver on the internet:
  <https://nvd.nist.gov/vuln/detail/CVE-2008-1447>

## On DNS as an exfiltration channel

- **MITRE ATT&CK — T1071.004 (Application Layer Protocol: DNS)**:
  <https://attack.mitre.org/techniques/T1071/004/>
- **MITRE ATT&CK — T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol)**:
  <https://attack.mitre.org/techniques/T1048/003/>
- **Iodine** (open-source DNS tunneling tool; read its docs as a defender, do not deploy):
  <https://github.com/yarrick/iodine>

## On TLS — what it protects and what it does not

- **RFC 8446 §1** — the TLS 1.3 design goals, in plain English.
- **The IETF "TLS Encrypted Client Hello" draft** — the still-evolving fix for the fact that SNI is plaintext today:
  <https://datatracker.ietf.org/doc/draft-ietf-tls-esni/>
- **Mozilla TLS guidelines** (the practical "what cipher suites should I allow today"):
  <https://wiki.mozilla.org/Security/Server_Side_TLS>

## On firewalls and segmentation

- **netfilter "How is a packet traversing the netfilter hooks"** — the diagram every Linux firewall author has open:
  <https://en.wikipedia.org/wiki/File:Netfilter-packet-flow.svg>
- **NIST SP 800-41 Rev. 1 — Guidelines on Firewalls and Firewall Policy**:
  <https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final>
- **NIST SP 800-207 — Zero Trust Architecture** (the modern alternative to perimeter-only thinking):
  <https://csrc.nist.gov/publications/detail/sp/800-207/final>

## Books and long-form writing

- **"TCP/IP Illustrated, Volume 1" — W. Richard Stevens** (the classic; second edition with Kevin Fall is still the standard reference).
- **"Practical Packet Analysis" — Chris Sanders** (the Wireshark-focused complement to Stevens).
- **"The Tangled Web" — Michal Zalewski** (chapter 1 covers the web's networking assumptions clearly; the rest is Week 4 territory).

## Tools you will use this week

- `tcpdump` — capture and read packets at the terminal
- `tshark` — Wireshark's command-line companion (same dissectors)
- `wireshark` — the GUI; the dissector library and the protocol view
- `dig` and `nslookup` — DNS query tools
- `ss` — list open sockets (the modern `netstat`)
- `nftables` (`nft`) — the modern Linux firewall
- `iptables` / `ip6tables` — legacy firewall (read-only inspection in many shops today)
- `ufw` — Debian/Ubuntu firewall wrapper
- `firewalld` (`firewall-cmd`) — RHEL/Fedora firewall wrapper
- `nmap` — port scanner (preview; deep dive in Week 7)
- `curl`, `wget` — to generate traffic deliberately during captures
- `mtr`, `traceroute` — path discovery

## Glossary

| Term | One-line definition |
|------|---------------------|
| **CIDR** | Classless Inter-Domain Routing notation, e.g. `192.168.1.0/24` — the `/N` is the prefix length in bits. |
| **RFC 1918** | The private IPv4 ranges (`10/8`, `172.16/12`, `192.168/16`) not routed on the public internet. |
| **SYN / SYN-ACK / ACK** | The three packets of the TCP three-way handshake; flag bits in the TCP header. |
| **TCP state machine** | The set of states a TCP connection passes through (`LISTEN`, `ESTABLISHED`, `TIME-WAIT`, etc.). |
| **BPF** | Berkeley Packet Filter; the kernel-level filtering language `tcpdump` and friends use. |
| **PCAP / PCAPNG** | Packet Capture file formats; PCAPNG is the modern superset, supports multiple interfaces and metadata. |
| **SNI** | Server Name Indication; the TLS extension that names the target host. Plaintext in TLS 1.2 and (by default) TLS 1.3. |
| **MITM** | Man-in-the-middle; an attacker who relays and potentially modifies traffic between two parties. |
| **Default-deny** | The firewall posture where nothing is allowed unless an explicit rule permits it. |
| **Egress filtering** | Outbound filtering — restricting where your hosts can connect *to*, not only what reaches them. |
| **Stateful firewall** | A firewall that tracks connection state, so a return packet is matched against an existing flow. |
| **Network segmentation** | Dividing a network into zones with controlled crossings — VLANs, subnets, host firewalls. |
