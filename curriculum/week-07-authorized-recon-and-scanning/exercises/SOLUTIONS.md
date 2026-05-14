# Week 7 — Exercise Solutions

> *Solutions and discussion for Exercises 1, 2, and 3. The exact outputs will vary by host, by `nmap` version, and by the configuration of the lab VM, so the answers below are illustrative rather than literal. The reasoning behind each answer is the part that matters.*

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The solutions assume you ran the exercises against authorised      │
│  targets (your own loopback, your own VM). If you ran them          │
│  against anything else, the technical results may match but the     │
│  posture is wrong; stop and reread Lecture 1.                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Exercise 1 — Scan Your Own Host

### Step 3 — Host discovery against loopback

1. **Was the host reported as up?**

   Yes. The loopback interface is always up on a running operating system. `nmap`'s output will read `Host is up`.

2. **What reason did `nmap` log?**

   On loopback you will typically see `Host is up (0.00xxxs latency)` with no explicit reason on the normal output, but the XML output will record a `reason` attribute. Typical values for loopback scans are `conn-refused` (the scan got an immediate response from the local TCP stack) or `syn-ack` if a port was open.

3. **Why is host discovery on loopback trivial?**

   The loopback interface bypasses the normal IP forwarding path; packets to 127.0.0.1 are not actually transmitted on a physical wire and never leave the host. Every host that is running has a loopback interface that responds immediately. Host discovery on loopback is essentially a check that the host is running, which by definition it is if you are running `nmap` on it.

### Step 4 — Default port scan

The default scan is `-sS` against the top 1000 TCP ports. Typical results on a developer laptop:

1. **1000 ports scanned.**
2. The breakdown varies. Common: 998 `closed`, 2 `open` (often SSH on 22, and a development server on 3000, 5000, 8000, or 8080).
3. Without `-sV`, the SERVICE column comes from `nmap`'s static port-to-service-name table (the `nmap-services` file). It is a *guess based on the port number*, not an identification. Port 22 is labelled `ssh` regardless of what is actually listening on port 22.

### Step 5 — Service detection

The `-sV` output enriches each open port with:

1. **Service name** — same as before, but confirmed by probe response.
2. **Product** — the software (`OpenSSH`, `nginx`, `Apache`, `Python SimpleHTTPServer`).
3. **Version** — the version string. For OpenSSH this includes the protocol version.
4. **CPE** — present when `nmap` confidently identifies the product. May be missing for less-common services or for services with banners that do not match the fingerprint database.

The "Service Info" line typically reports the OS based on the banners: `Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel` for a Linux host.

### Step 6 — Default scripts

`-sC` runs the `default` NSE category. On a developer laptop with SSH listening, the most-common added blocks are:

- `ssh-hostkey:` — the host's SSH public keys (RSA, ECDSA, ED25519). The script identifier is literally `ssh-hostkey` in `/usr/share/nmap/scripts/`.
- `ssh-auth-methods:` — the auth methods the SSH server advertises (publickey, password, etc.).

If you run a local web server, you would also see:

- `http-title:` — the page title.
- `http-server-header:` — the `Server:` HTTP header.
- `ssl-cert:` — TLS certificate metadata, if the port runs TLS.

### Step 7 — TCP connect scan

1. **Identical results?** Usually yes for open ports; sometimes subtly different for filtered ports because `connect(2)` and raw-SYN probes hit different kernel paths.

2. **Why might they differ?** The connect scan goes through the full kernel networking stack including any iptables / nftables rules that act on connection state. A SYN scan is raw-socket-based and can in some configurations bypass certain firewall rules (especially OUTPUT-chain rules that only filter ESTABLISHED connections).

3. **Which scan would the loopback service's application see?**

   The connect scan completes the three-way handshake, so the application's `accept(2)` returns and the application sees a connection (which the scanner then immediately closes). The SYN scan never completes the handshake, so the kernel handles the half-open exchange and the application never sees the connection. *Application-layer logs see `-sT` but not `-sS`.* The kernel's connection-tracking subsystem and any network IDS see both.

### Step 8 — UDP scan

1. **100 UDP ports tested** (the top-100 selector).
2. **The most common state is `open|filtered`.** A UDP probe to a port the host does not service-respond to and does not ICMP-port-unreachable for is indistinguishable from a filtered probe; `nmap` reports the ambiguity rather than guessing.
3. **Why `open|filtered` is dominant**: most UDP services do not respond to unstructured packets. A blind UDP probe to port 53 (DNS) is not a DNS query and the DNS server typically does not respond. Without an application-level response, `nmap` cannot distinguish "the service is listening but ignored my non-DNS packet" from "a firewall dropped my packet." `-sU -sV` significantly reduces the ambiguity by sending service-specific probes.

### Step 9 — Rate-limited full scan

1. **Did `-p-` reveal extra ports?** On a typical developer laptop, no — the top-1000 covers essentially everything that listens locally. On a server with an unusual service on a high port (e.g. an admin interface on 49152), `-p-` would find it where the top-1000 missed it.

2. **Time taken?** On loopback at 5000 pps the scan typically completes in 1-3 seconds. Loopback has no real network constraints; the bottleneck is the scanner's own per-packet overhead.

3. **Theoretical minimum.** 65,535 ports ÷ 5000 pps = ~13 seconds. The observed time is often *faster* because `nmap` adapts and bursts when the target is responsive; on loopback the adaptive logic recognises near-zero latency and accelerates beyond the cap when the cap is non-tight.

---

## Exercise 2 — NSE Scripts on a Vulnerable VM

### Step 4 — Service detection

Metasploitable 2's canonical open-port list looks roughly like:

```text
21/tcp    open  ftp         vsftpd 2.3.4
22/tcp    open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp    open  telnet      Linux telnetd
25/tcp    open  smtp        Postfix smtpd
53/tcp    open  domain      ISC BIND 9.4.2
80/tcp    open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp   open  rpcbind     2 (RPC #100000)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp   open  exec        netkit-rsh rexecd
513/tcp   open  login       OpenBSD or Solaris rlogind
514/tcp   open  shell       Netkit rshd
1099/tcp  open  java-rmi    GNU Classpath grmiregistry
1524/tcp  open  bindshell   Metasploitable root shell
2049/tcp  open  nfs         2-4 (RPC #100003)
2121/tcp  open  ftp         ProFTPD 1.3.1
3306/tcp  open  mysql       MySQL 5.0.51a-3ubuntu5
3632/tcp  open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
5432/tcp  open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp  open  vnc         VNC (protocol 3.3)
6000/tcp  open  X11         (access denied)
6667/tcp  open  irc         UnrealIRCd
8009/tcp  open  ajp13       Apache Jserv (Protocol v1.3)
8180/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1
```

End-of-life status, sampled:

- `vsftpd 2.3.4` — EoL plus a backdoor in this specific tarball (CVE-2011-2523).
- `OpenSSH 4.7p1` — EoL; multiple CVEs.
- `Apache 2.2.8` — EoL since 2017.
- `MySQL 5.0` — EoL since 2012.
- `Samba 3.x` — EoL since 2017.

### Step 7 — `vuln and safe`

A representative finding table (yours will vary):

| Port | Service | Version | CVE | CVSS | Confirmed |
|------|---------|---------|-----|------|-----------|
| 21   | vsftpd  | 2.3.4   | CVE-2011-2523 | 10.0 | Yes — version is the backdoored tarball |
| 80   | Apache  | 2.2.8   | CVE-2017-15715 | 8.1 | Likely — version is below the patched 2.2.34 |
| 139  | Samba   | 3.x     | CVE-2017-7494  | 9.8 | Likely — version range covers the vulnerable releases |
| 445  | Samba   | 3.x     | CVE-2017-7494  | 9.8 | Same instance via different port |

The `vuln and safe` selector typically does *not* actively exploit; it cross-references the detected version against known vulnerable version ranges and reports the match. For each finding, you cross-check on NVD by following the CVE link.

### Step 8 — `auth` category

Typical findings:

- `ftp-anon` on port 21 reports anonymous FTP login is permitted.
- `ssh-auth-methods` on port 22 reports `publickey,password,keyboard-interactive` — the SSH server accepts password authentication, which a hardened configuration usually disables.
- `smb-security-mode` on port 445 reports the SMB security mode (typically `user`, with `auth_level: user`, `signing: disabled` on Metasploitable).

### Step 9 — OS fingerprint

`nmap -O` against Metasploitable 2 typically reports:

```text
OS details: Linux 2.6.9 - 2.6.33
```

Inside the VM, `uname -a` returns something like `Linux metasploitable 2.6.24-16-server #1 SMP ...`. The fingerprint range covers the actual kernel; the match is correct but coarse (`-O` reports a range, not the exact version). For most reporting purposes, the range is sufficient.

---

## Exercise 3 — Output parsing with Python

### Running the script

```bash
cd ~/c6-week-07/exercise-01
python3 path/to/exercise-03-output-parsing-with-python.py \
    scan-for-parsing.xml \
    --csv summary.csv \
    --jsonl summary.jsonl \
    --findings
```

Expected output (loopback scan with one or two open ports):

```text
========================================================================
NMAP SCAN SUMMARY
========================================================================
Hosts in report: 1

Host: 127.0.0.1 (localhost)
  Status: up (conn-refused)
  Open ports: 1
    22/tcp  open          ssh - OpenSSH 9.6p1 Ubuntu 3ubuntu13.4
      CPE: cpe:/a:openbsd:openssh:9.6p1
      CPE: cpe:/o:linux:linux_kernel
      [ssh-hostkey] 256 SHA256:abc...= (ECDSA)

Wrote 1 CSV rows to summary.csv
Wrote 1 JSONL records to summary.jsonl

CVE-mentioning NSE script outputs
------------------------------------------------------------------------
(no NSE script outputs mention CVE identifiers)
```

The `--findings` output is more interesting against the Metasploitable XML, where `vuln`-category NSE scripts emit CVE references in their output.

### Common questions

1. **Why is `xml.etree.ElementTree` good enough?**

   The `nmap` XML DTD is well-defined, stable across versions, and small. For the queries we want (enumerate hosts, enumerate ports, extract service info, extract NSE output) the stdlib `ElementTree` is sufficient. Larger XML processing (XPath beyond the simplest selectors, namespaces, validation against the DTD) would push toward `lxml`, but for `nmap` consumption the stdlib is more than adequate.

2. **Why the `defusedxml` note?**

   The stdlib XML parser is documented to be unsafe against several attack classes (billion-laughs, external entities). For untrusted XML you should swap in `defusedxml`. For our case — XML produced by our own `nmap` against our own host — the threat does not exist; we accept the stdlib risk consciously.

3. **Why is the script tolerant of missing fields?**

   Real `nmap` output omits elements when probes do not return data. A `<port>` for a `closed` port has no `<service>` block. A host with no open ports has no `<ports>` block. The script must accept the absence rather than crash; the empty-string default is the right "no information" signal.

4. **Why JSON-Lines instead of one big JSON file?**

   JSON-Lines is *appendable* — you can pipe `nmap` runs into a growing file and a downstream consumer (a SIEM, an analysis script) can `tail -f` it. A single JSON file would require rewriting the whole file on each append. JSON-Lines is also the standard ingest format for Splunk, Elastic, and OpenSearch.

5. **Can I run this against `masscan -oX` output?**

   `masscan` emits a similar but not identical XML format. The script will parse `masscan` output but some fields (the NSE script blocks, the OS-fingerprint section) will be empty because `masscan` does not produce them. For a full pipeline, run `masscan` for the wide sweep and `nmap` for the enrichment, then parse the `nmap` XML.
