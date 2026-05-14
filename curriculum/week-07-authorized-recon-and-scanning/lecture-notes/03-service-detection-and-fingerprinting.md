# Lecture 3 — Service Detection, NSE, and OS Fingerprinting

> *Once you know which TCP and UDP ports are open on a host, the next question is: what is listening behind each port, what version is it, and is that version known-bad? Service detection and the Nmap Scripting Engine (NSE) are the technical answer. The operational answer, which this lecture spends most of its time on, is which scripts to run when, what each costs, and how to write the result up in a way the host owner can act on. The framing rule of the week applies in full: do this only against hosts you own or have signed authorisation to test.*

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Service detection and especially NSE scripts can change target     │
│  state. A `vuln`-category NSE script may verify a finding by        │
│  exercising it; an `intrusive`-category script will trigger         │
│  application-layer alerts; an `exploit`-category script will        │
│  attempt actual exploitation. Run only the categories your RoE      │
│  explicitly authorises. Default and recommended this week:          │
│  `safe` and `default`. Do not run `vuln`, `intrusive`, or           │
│  `exploit` against any host not in your own lab.                    │
└─────────────────────────────────────────────────────────────────────┘
```

This lecture covers:

- **Service version detection** — `-sV`, the version probes, the confidence interval.
- **The Nmap Scripting Engine (NSE)** — what it is, how it loads scripts, the category taxonomy.
- **The NSE categories in operational depth** — `safe`, `default`, `discovery`, `version`, `auth`, `vuln`, `intrusive`, `exploit`, `dos`, `external`. Which to run on which engagement.
- **OS fingerprinting** — `-O`, what `nmap` is fingerprinting, the accuracy and known-failure modes.
- **Output formats** — `-oN`, `-oG`, `-oX`, `-oA`. Picking the right format for downstream parsing.
- **The recon report shape** — what the cover, the scope, the methodology, the findings, and the appendix sections actually contain.

---

## 1. Service version detection — `-sV`

```bash
sudo nmap -sV -p 22,80,443 198.51.100.42
```

`-sV` ("version scan") performs *active service identification*: for each open port, `nmap` sends a sequence of probes designed to elicit a banner, a protocol-specific handshake, or another distinguishing response, and matches the response against a large fingerprint database (`nmap-service-probes`, shipped with `nmap`).

A typical `-sV` output line:

```text
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
```

The structure: **port / protocol / state / service-name / product / version / OS hint / protocol-level metadata**.

### 1.1 What version detection costs

`-sV` is more expensive than a bare port scan because every open port receives multiple probes. The cost is roughly:

- **Time**: each open port adds 1-15 seconds depending on how readily the service identifies itself.
- **Traffic**: a `-sV` against 1000 open ports across 100 hosts sends tens of thousands of additional probes.
- **Log footprint**: every probe is a TCP connection (with `-sV`'s default settings), and most services log every connection. The target's logs will fill noticeably.

These are not reasons not to run `-sV` — service identification is the *point* of recon — but they are reasons to be deliberate about when. On an in-scope engagement, you run `-sV` once per target; you do not run it as a sanity check.

### 1.2 Version-detection intensity — `--version-intensity`

`--version-intensity <0-9>` controls how many probes `nmap` tries against each open port. The default is 7. Lower values are faster but identify fewer services; higher values are exhaustive.

- `--version-intensity 0`: only probes that are highly likely to identify the service.
- `--version-intensity 5`: a balanced middle.
- `--version-intensity 9`: every probe, including the rare ones. Slow.

`--version-light` is an alias for `--version-intensity 2`; `--version-all` is an alias for `--version-intensity 9`. For most engagements, the default is correct.

### 1.3 The CPE field

For every confidently-identified service, `-sV` emits a **Common Platform Enumeration (CPE)** string:

```text
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

For specific products:

```text
22/tcp open  ssh     OpenSSH 9.6p1 (cpe:/a:openbsd:openssh:9.6p1)
```

CPE is the key to downstream vulnerability correlation. The string is structured: `cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>`. Part is `a` (application), `o` (operating system), or `h` (hardware). Lecture 1 of Week 8 picks up the CPE-to-CVE pipeline; for now, capture the CPE in your output and you will use it later.

### 1.4 When version detection is wrong

`-sV` can be wrong in three ways:

1. **Service confidently misidentified.** Rare with default intensity, but happens with custom protocols. Treat any single source of identification as a *probability*, not a fact.
2. **Version banner is forged.** Some services intentionally lie about their version (a configuration option in nginx, in Apache via `ServerTokens`, in OpenSSH via patches). The CPE you record may be inaccurate; cross-check with behavioural fingerprinting where the finding matters.
3. **Service is identified as `tcpwrapped`.** `nmap` saw a connection close immediately after opening; could be a TCP wrapper, a connection-rate-limit, or any of half a dozen other causes. Re-probe with a longer timeout or a single-probe `-sV --version-intensity 0`.

---

## 2. The Nmap Scripting Engine (NSE)

NSE is `nmap`'s extensibility layer: Lua scripts that run during a scan and produce additional findings. Roughly 600 scripts ship with `nmap`; a few hundred more are publicly available. Each script lives in `/usr/share/nmap/scripts/` (Linux) or the equivalent path on macOS / Windows, and is documented at <https://nmap.org/nsedoc/>.

### 2.1 How NSE loads scripts

The two flags that load scripts:

```bash
sudo nmap -sC -p 22,80,443 198.51.100.42
sudo nmap --script <selector> -p 22,80,443 198.51.100.42
```

`-sC` is shorthand for `--script default`. It loads every script in the `default` category — a hand-curated set of scripts that are safe, fast, and useful enough to run on most scans.

`--script <selector>` is the explicit form. The selector can be:

- A **category** — `--script safe`, `--script vuln`, etc.
- A **wildcard** — `--script "http-*"`, `--script "ssl-*"`.
- A **filename** — `--script http-headers`.
- A **boolean expression** — `--script "vuln and safe"`, `--script "default and not http-slowloris"`.

### 2.2 NSE phases

NSE scripts run in one of four phases:

1. **prerule** — before any host is scanned. Used by scripts that broadcast or discover (`broadcast-dhcp-discover`).
2. **hostrule** — per-host, before per-port scripts. Used by scripts that don't need a port (`hostmap-bfk`).
3. **portrule** — per-host, per-port. The most common; service-specific scripts (`http-title`, `ssl-cert`).
4. **postrule** — after all scanning is done. Used for summary or correlation scripts.

You rarely need to think about phases explicitly; categories matter more.

---

## 3. The NSE categories — what each is and when to run it

There are nine NSE categories. Read this section carefully; the operational discipline of "which categories you run on which engagement" is the single most-important judgment call of the week.

### 3.1 `safe`

Scripts that, by the maintainers' judgment, do not crash services, do not generate authentication failures, do not consume substantial bandwidth, and do not exploit vulnerabilities. The `safe` category is the **broad authorised set** for any engagement — if your RoE authorises service detection, it authorises `safe`.

Examples:

- `ssh-hostkey` — fetch the SSH server's host key.
- `ssl-cert` — fetch and parse the TLS certificate.
- `http-title` — fetch and parse the HTTP `<title>`.
- `dns-recursion` — check whether a DNS server allows recursion (a configuration finding, not an exploitation).

### 3.2 `default`

A subset of `safe` plus a few `intrusive` scripts that the `nmap` maintainers consider so valuable they should be on by default. `-sC` runs this category. Most modern engagement runbooks set `-sC` as the baseline; the included scripts are vetted heavily and produce signal-rich output.

### 3.3 `discovery`

Scripts that gather information about a target without changing its state. Things like:

- `dns-brute` — DNS subdomain brute-force.
- `smb-os-discovery` — query SMB for OS information.
- `whois-domain` — WHOIS the target.

`discovery` overlaps significantly with `safe`. Use `discovery` when you want reconnaissance richness; it is rarely controversial in scope.

### 3.4 `version`

Scripts that enhance service-version detection. Loaded automatically when you run `-sV`. You rarely invoke `--script version` directly; the category exists for the framework.

### 3.5 `auth`

Scripts related to authentication mechanisms. They mostly *report* auth configuration (e.g. `ssh-auth-methods` reports which auth methods a server accepts) rather than testing credentials. Most `auth` scripts are `safe`-adjacent.

**Note**: scripts that *attempt* authentication (e.g. `ssh-brute`, `http-brute`) are in the `brute` category, not `auth`, and `brute` is **always RoE-gated**.

### 3.6 `vuln`

Scripts that check for the presence of a known vulnerability. The check may be **safe** (matches a version string to a CVE) or **active** (sends a payload to confirm the bug is present and exploitable). The category mixes both, and the per-script documentation tells you which kind a given script is.

Operational rules for `vuln`:

- Run `vuln` only with explicit RoE authorisation.
- Read the per-script documentation for *active* probes before running.
- Save the full output (`-oA`) so you can correlate which script triggered which finding.
- Be prepared for false positives — `vuln` scripts vary in accuracy.

A typical `vuln`-category invocation:

```bash
sudo nmap --script "vuln and safe" -p 80,443 <metasploitable-vm-ip>
```

The `vuln and safe` selector filters to vulnerability checks that the maintainers also classify as safe — i.e. the version-based checks rather than the active-probe checks.

### 3.7 `intrusive`

Scripts that may crash a service, generate excessive load, or trigger application-level alerts. Run only with explicit RoE authorisation, and even then only where the engagement explicitly asks for intrusive testing.

`intrusive` is *not* a tier of severity above `vuln`; the two categories overlap. A script can be in both categories. Read each script's documentation; do not infer behaviour from category membership alone.

### 3.8 `exploit`

Scripts that attempt actual exploitation of a known vulnerability. These send genuine attack payloads and, if successful, achieve real access. **The C6 curriculum does not authorise running `exploit`-category scripts against any host other than a Metasploitable-style VM you own** — and even there, the value is mostly educational; the same exploitation is more cleanly demonstrated by Metasploit framework modules.

### 3.9 `dos`

Scripts that test for denial-of-service vulnerabilities by *attempting* to denial-of-service the target. **Never run `dos` against any host you do not own and personally do not mind crashing.** The category exists; you do not use it without explicit ownership and explicit purpose.

### 3.10 `external`

Scripts that send traffic to a third-party service (a public WHOIS server, a public DNS resolver, a CVE-database lookup). External scripts are not necessarily dangerous, but the RoE may explicitly prohibit traffic to third parties. Read each script and verify it before running.

### 3.11 Decision matrix

| Engagement profile                              | Recommended category set                  |
|-------------------------------------------------|-------------------------------------------|
| Your own loopback, exploration                  | `default`, `safe`, `discovery`            |
| Authorised consultancy recon engagement         | `default`, `safe` (always); `vuln and safe` (with RoE) |
| Bug bounty recon against in-scope assets        | `default`, `safe`; check program rules for `vuln`/`intrusive` |
| Lab work against Metasploitable                 | All categories permissible (it is your VM and it is vulnerable on purpose) |
| Anything else                                   | Stop and re-read the RoE                  |

---

## 4. OS fingerprinting — `-O`

```bash
sudo nmap -O 198.51.100.42
```

`-O` performs **TCP/IP-stack fingerprinting**. `nmap` sends a series of carefully-crafted probes (with unusual flag combinations, specific IP-ID values, fragmented packets) and observes the responses. The behaviour of the responder's TCP stack — how it handles odd input — is sufficiently distinctive that `nmap` can usually identify the OS family and often the specific OS version, against a database of about 5,000 fingerprints.

### 4.1 What `-O` actually tests

The probes test, among other things:

- The initial sequence number generator's algorithm and entropy.
- The IP-ID counter's algorithm.
- The TCP window size and the window-scale option behaviour.
- Whether the stack sends ICMP responses to fragmented packets.
- The exact contents of TCP options in SYN-ACK responses.

The combination of these signals is, for most stacks, distinctive enough to fingerprint to within a major OS version.

### 4.2 Accuracy expectations

`nmap` reports OS fingerprinting confidence in one of three forms:

- **"Aggressive OS guesses"** — multiple candidate OSes ranked by likelihood, each with a percentage.
- **"OS details"** — a single confident match.
- **"No exact OS matches"** — `nmap` could not confidently identify; the closest matches are listed but not promoted.

A confident match against a modern OS (Linux 5.x, Windows 11, FreeBSD 14) is usually right. A confident match against an unusual stack (an embedded device, a custom appliance) is sometimes spectacularly wrong. The mode of failure is "fingerprint-database doesn't contain this stack; closest known match is wrong by years."

Operational rule: **report OS fingerprint findings with the confidence number, and never escalate a finding on OS fingerprint alone**. If the finding matters, validate with a service-banner cross-check (`ssh-hostkey` often reveals the OS; HTTP `Server:` headers sometimes do).

### 4.3 When `-O` fails

`nmap -O` requires:

- At least one open and one closed port on the target.
- Sufficient round-trip stability (no extreme packet loss).
- Permission to send raw probes (root).

`--osscan-guess` and `--osscan-limit` adjust the failure behaviour: the former asks `nmap` to guess aggressively even when confidence is low; the latter restricts `-O` to hosts where at least one open and one closed port have been found. `--osscan-limit` is the safer default for an engagement.

### 4.4 Banner-based OS hints from `-sV`

`-sV` produces an OS hint at the bottom of its output:

```text
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

This is *banner-derived*, not stack-derived. It is typically less precise than `-O` but more often correct, because services typically advertise their OS truthfully (it would be unusual configuration to lie). For most reports, the `-sV`-derived OS hint is what you cite; `-O` is a secondary confirmation.

---

## 5. Output formats — `-oN`, `-oG`, `-oX`, `-oA`

```bash
sudo nmap -sS -sV -oA /tmp/scan 127.0.0.1
```

`nmap` produces five output formats. The flag controls which:

### 5.1 `-oN` — normal output

```text
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-14 09:00 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000019s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
```

Human-readable. The format you read directly at the terminal. Not great for programmatic parsing — `nmap` versions sometimes change the format subtly.

### 5.2 `-oG` — grepable output

```text
Host: 127.0.0.1 (localhost)  Ports: 22/open/tcp//ssh//OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)/, 80/open/tcp//http//nginx 1.24.0 (Ubuntu)/
```

One line per host. Designed for `grep`, `awk`, and `cut`. Officially deprecated since `nmap` 6, but still supported because so many existing scripts depend on it. *Avoid for new tooling; use XML.*

### 5.3 `-oX` — XML output

```xml
<host starttime="..." endtime="...">
  <status state="up" reason="conn-refused" reason_ttl="0"/>
  <address addr="127.0.0.1" addrtype="ipv4"/>
  <hostnames>
    <hostname name="localhost" type="user"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack" reason_ttl="64"/>
      <service name="ssh" product="OpenSSH" version="9.6p1 Ubuntu 3ubuntu13.4"
               extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux"
               method="probed" conf="10">
        <cpe>cpe:/a:openbsd:openssh:9.6p1</cpe>
        <cpe>cpe:/o:linux:linux_kernel</cpe>
      </service>
    </port>
  </ports>
</host>
```

Structured, programmatically parseable, **the right choice for any tooling**. Stable across `nmap` versions. Exercise 3 of this week walks parsing it with Python's `xml.etree.ElementTree`.

### 5.4 `-oJ` — JSON output

`nmap` 7.90+ includes experimental JSON output via `-oJ`. The schema is reasonable but less battle-tested than XML; tooling that needs to be robust still uses XML. For new scripts, you may prefer JSON for ergonomic reasons; for compatibility, prefer XML.

### 5.5 `-oA` — "all" output

`-oA <basename>` produces `<basename>.nmap` (normal), `<basename>.gnmap` (grepable), and `<basename>.xml` (XML) in a single run. This is the **right default** for any engagement: you get the human-readable view at the terminal *and* the structured artifact for downstream parsing *and* the grepable file for quick `awk` queries, with no extra time cost.

### 5.6 `--reason` and `-v`

`--reason` annotates each port-state with the reason `nmap` reached it (`syn-ack`, `reset`, `no-response`, etc.). Useful for debugging when results seem implausible.

`-v` (verbose) and `-vv` increase the chatter. For engagement runs, `-v` is usually right; `-vv` produces output you cannot easily skim but is useful for debugging.

---

## 6. The recon report — what a finished week-7 deliverable looks like

The technical work produces output files; the *deliverable* is a document the owner can act on. The report shape used by Trail of Bits, NCC Group, and the major consultancies converges on the same six sections.

### 6.1 Cover page

- Engagement title.
- Owner / client legal name.
- Engineer / consultancy name.
- Engagement dates (start and end).
- Document version and date.
- Confidentiality marking ("Confidential — for the eyes of <named recipients> only").

### 6.2 Executive summary

One page, plain English, no jargon. Three or four paragraphs:

- What was tested (in non-technical terms — "the public-facing IP ranges of <product>").
- What was found at a high level — "X services were identified across Y hosts; Z services were running versions with known critical vulnerabilities."
- What the owner should do next — "patch the OpenSSH instances on <hosts> to current; investigate the unsupported version of <product> on <host>; review the firewall configuration in <range> for the unexpected exposed services."
- Confidence in the findings — "this was a recon engagement; vulnerability assessment and exploitation testing were out of scope and were not conducted."

The executive summary is read by directors and officers. Write it for them, not for yourself.

### 6.3 Scope and methodology

- Reference to the signed RoE.
- List of in-scope assets actually tested.
- List of out-of-scope assets explicitly *not* tested.
- Tools used, with versions.
- Time windows when scans were executed.
- Rate caps observed.

This section answers "what did you actually do?" — a question that comes up in every post-engagement audit.

### 6.4 Findings — summary table

A table with one row per finding:

| #  | Severity | Title                                    | Affected hosts          | Status      |
|----|----------|------------------------------------------|-------------------------|-------------|
| 1  | High     | OpenSSH 7.2p2 (5 known CVEs, EoL)        | 203.0.113.10            | Open        |
| 2  | Medium   | Anonymous FTP enabled                    | 203.0.113.42            | Open        |
| 3  | Info     | Server: header reveals nginx version     | 8 hosts                 | Open        |

Severity uses an established taxonomy — typically CVSS-derived, or the Bugcrowd VRT, or the owner's internal severity ladder. Do not invent your own.

### 6.5 Findings — detail

One subsection per finding, each in the five-anchor form adapted from Week 6:

- **Title** and severity.
- **Affected hosts and ports** (precise — IP, port, service version).
- **Description** of the finding — what you observed and why it matters.
- **Reference** — CVE, CWE, vendor advisory.
- **Recommendation** — what the owner should do.
- **Evidence** — the relevant scan output, with command line and timestamp.

### 6.6 Appendix — methodology in depth

- Command lines executed, in order, with timestamps.
- Tool versions.
- Output file references (`scan-2026-05-14T1200Z.xml` etc.).
- Any anomalies encountered (rate-limit hits, mid-scan pauses, contact escalations).

The appendix is the artifact that lets a future auditor verify your work. Write it for someone who will read it in six months without having spoken to you.

---

## 7. A worked example: from `-sV -sC` against your own VM to a one-line finding

A Metasploitable 2 VM, scanned with default service detection and default scripts:

```bash
sudo nmap -sS -sV -sC --top-ports 100 -oA /tmp/meta 10.0.2.15
```

Inside `/tmp/meta.nmap`, you would see entries like:

```text
21/tcp    open  ftp         vsftpd 2.3.4
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
```

The two lines together are a finding: **vsftpd 2.3.4 with anonymous FTP enabled**. The version (2.3.4) has a famous backdoor — CVE-2011-2523, the "smiley face" backdoor — and the anonymous-FTP configuration is independently a finding even when the backdoor is patched. Your detail entry might be:

> **Finding 3 — High — vsftpd 2.3.4 running with anonymous FTP and a known backdoor**
>
> Host 10.0.2.15:21 is running `vsftpd 2.3.4` (CPE `cpe:/a:vsftpd:vsftpd:2.3.4`).
> The version is known to contain a backdoor introduced upstream and disclosed
> as CVE-2011-2523 (NVD score 10.0 critical). The `ftp-anon` NSE script
> confirms anonymous FTP is enabled. The configuration combination — a
> backdoored daemon and an anonymous-login configuration — is severe.
>
> *Reference:* CVE-2011-2523, NVD <https://nvd.nist.gov/vuln/detail/CVE-2011-2523>.
>
> *Recommendation:* Replace the FTP service with `vsftpd` from a maintained
> source, or remove it. If FTP is required, disable anonymous login. If FTP
> is not required, decommission the service.
>
> *Evidence:* `nmap -sS -sV -sC -p 21 10.0.2.15`, output in
> `/tmp/meta.xml`, scan timestamp 2026-05-14T12:00Z.

The output you stamp into your portfolio looks roughly like this. The mini-project this week asks you to produce a full document at this depth on a host you own.

---

## 8. Closing

Two things to take from this lecture:

1. **NSE categories are a contract.** `safe` and `default` are permitted on any in-scope target; `vuln`, `intrusive`, `exploit`, `dos` require explicit per-engagement RoE authorisation, and the prudent default is *do not run them*. The category that gets you in trouble is not `default`; it is the script you ran on a hunch.

2. **The deliverable is the report, not the output file.** A directory full of `.xml` files is not a deliverable; it is the *source data* for a deliverable. The work of Week 7's mini-project is converting that source data into a document the owner can read in twenty minutes and act on for six months.

Read the exercises and the mini-project guide. The framework is now in place for the practical work.

---

## References

- Nmap Network Scanning, Chapter 7 (Service and Version Detection): <https://nmap.org/book/vscan.html>.
- Nmap Network Scanning, Chapter 8 (Remote OS Detection): <https://nmap.org/book/osdetect.html>.
- Nmap Network Scanning, Chapter 9 (Nmap Scripting Engine): <https://nmap.org/book/nse.html>.
- NSE script database (browse by category): <https://nmap.org/nsedoc/>.
- CPE 2.3 specification: <https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe>.
- CVE-2011-2523 (vsftpd 2.3.4 backdoor): <https://nvd.nist.gov/vuln/detail/CVE-2011-2523>.
- Trail of Bits, "Testing Handbook": <https://appsec.guide/>.
