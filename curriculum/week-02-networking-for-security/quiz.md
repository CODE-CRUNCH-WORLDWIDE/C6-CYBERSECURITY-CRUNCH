# Week 2 — Quiz

Ten questions. Lectures closed. Aim for 9/10. The questions are written to be unambiguous; if a question seems to allow more than one answer, re-read the lecture.

---

**Q1.** A subnet is written as `192.168.4.0/26`. How many usable host addresses does it contain?

- A) 64
- B) 62
- C) 254
- D) 30

---

**Q2.** Which of the following is **not** an RFC 1918 private IPv4 range?

- A) `10.0.0.0/8`
- B) `172.16.0.0/12`
- C) `192.168.0.0/16`
- D) `169.254.0.0/16`

---

**Q3.** In `tcpdump`, the notation `Flags [S.]` means the packet has which TCP flags set?

- A) SYN only
- B) ACK only
- C) SYN and ACK
- D) PSH and FIN

---

**Q4.** A `tcpdump` capture shows a client sending a SYN, and the server responding with a RST. This means:

- A) The server is unreachable from the client.
- B) The server's kernel is reachable, but no service is listening on that port (and no firewall is silently dropping the SYN).
- C) The connection has been hijacked by an attacker.
- D) The server has rate-limited the client.

---

**Q5.** Which of the following is **not** something TLS 1.3 protects, even when correctly configured?

- A) Confidentiality of the application payload.
- B) Integrity of the application payload.
- C) The destination IP address and TCP port (visible to any on-path observer).
- D) Server authentication (when the client validates the certificate).

---

**Q6.** Which port number is most likely to be an exposed and unauthenticated in-memory key-value store that has been mass-compromised since 2015?

- A) 5432
- B) 6379
- C) 9200
- D) 27017

---

**Q7.** A BPF capture filter and a Wireshark display filter:

- A) Use the same syntax and are interchangeable.
- B) Use different syntaxes; BPF runs in the kernel before capture, display filters run in Wireshark after capture and can match application-protocol fields.
- C) BPF is for IPv4 and Wireshark display filters are for IPv6.
- D) BPF is more powerful than display filters because it can match arbitrary application-protocol fields.

---

**Q8.** A `nftables` chain has `policy drop`. The chain matches the first applicable rule and stops. What does `policy drop` do?

- A) It drops every packet that arrives, regardless of any rules.
- B) It drops every packet that is not explicitly matched by an `accept` rule earlier in the chain.
- C) It drops every packet whose source is in a private range.
- D) It enables the `LOG` target on all rules in the chain.

---

**Q9.** A web server's `nftables` `output` chain has `policy accept` and no explicit rules. The server is compromised. What does this configuration *fail* to prevent?

- A) The attacker reading the database from inside the box.
- B) The attacker `curl`ing an external malware-staging server to pull tooling.
- C) The attacker reading `/etc/shadow`.
- D) The attacker exploiting a kernel CVE.

---

**Q10.** A DNS query for `aGVsbG8gd29ybGQ.exfil.attacker.example` is observed on a network. The most accurate defensive interpretation is:

- A) A typo by a developer.
- B) A normal query for a non-existent subdomain.
- C) A likely DNS-based exfiltration channel: the encoded leftmost label is data being smuggled out via the DNS resolver to an attacker-controlled authoritative server.
- D) A misconfigured DNS resolver returning random subdomains.

---

## Answer key

<details>
<summary>Click to reveal</summary>

1. **B** — A `/26` has 64 addresses; subtract the network and broadcast for **62 usable**. (`/24` is 254, `/27` is 30, `/25` is 126.)
2. **D** — `169.254.0.0/16` is link-local (IPv4 autoconfiguration), not private (RFC 3927). The three RFC 1918 ranges are 10/8, 172.16/12, 192.168/16.
3. **C** — `[S.]` is SYN+ACK in `tcpdump` flag notation. `S` is SYN, the `.` is ACK. (`[S]` alone is SYN-only; `[.]` alone is ACK-only.)
4. **B** — A RST from the server means "the host is alive, the kernel is reachable, but nothing is listening on that port." It is the *default* refused-connection behavior absent a firewall that silently drops.
5. **C** — TLS protects the body, not the routing information. The destination IP and TCP port are in the cleartext IP and TCP headers below TLS. SNI is also cleartext in TLS 1.2 / 1.3 today (ECH is still partially deployed).
6. **B** — 6379 is Redis. Internet-exposed Redis instances without `requirepass` have been mass-compromised since 2015 (initially for cryptominer deployment via `CONFIG SET dir` and `SLAVEOF`).
7. **B** — BPF is a kernel-level capture filter, evaluated per packet at the layer-3/4 headers. Display filters are Wireshark's post-capture filter, with full access to dissected application-protocol fields. They are different languages.
8. **B** — `policy` is the chain's *default* action: it applies only to packets that did not match any rule. So `policy drop` means "drop anything not explicitly accepted by an earlier rule."
9. **B** — Wide-open egress is exactly the configuration that lets a compromised host pull tooling and beacon out. The other options are about host-side controls (MAC, kernel patching, file permissions), not egress filtering.
10. **C** — The leftmost label is base32-style encoded payload. A DNS query for such a name will be resolved by your resolver and reach the attacker's authoritative server, which logs the encoded data. This is MITRE ATT&CK T1071.004; iodine, dnscat2, and many real malware families use exactly this pattern.

</details>

If under 7, re-read the lectures. If 9+, you are ready for the [homework](./homework.md) and the [mini-project](./mini-project/README.md).
