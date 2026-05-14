# Exercise 2 — NSE Scripts on a Vulnerable VM You Own

**Estimated time:** 90 minutes. `nmap` installed. A Metasploitable 2 VM on a host-only network you own.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  This exercise targets a vulnerable-by-design virtual machine       │
│  you provisioned and own, on a host-only network you provisioned    │
│  and own. The VM is intentionally riddled with vulnerabilities;     │
│  scanning it with NSE `vuln` scripts is the entire point.           │
│                                                                     │
│  The VM must be on a host-only or NAT-isolated network. Never       │
│  bridge a vulnerable VM to your LAN. Never expose a vulnerable      │
│  VM to the public internet. The setup section below is              │
│  non-negotiable.                                                    │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

You have an authorised, fully-isolated lab. The target is **Metasploitable 2** (Rapid7's published vulnerable-by-design Linux VM). You will run the canonical sequence — host discovery, port scanning, version detection, default scripts, then targeted NSE script categories — and produce the output that informs Exercise 3 and Challenge 1.

This exercise covers:

- **Network isolation discipline.**
- **NSE category selection** — `default`, `safe`, `vuln and safe`, `auth`.
- **Reading NSE output** and mapping each finding to a CVE.
- **Output capture** for downstream reporting.

---

## Step 0 — Network isolation (15 min, one-time setup)

If you do not yet have Metasploitable on a host-only network, follow these steps. If you already have it set up, **verify the network isolation** before proceeding.

### Option A — VirtualBox

1. Download Metasploitable 2 from the official source: <https://information.rapid7.com/download-metasploitable-2017.html>.
2. In VirtualBox, create a new VM, attach the Metasploitable disk.
3. **In VM settings → Network**: set Adapter 1 to "Host-only Adapter" with the network `vboxnet0` (or whatever your host-only network is named). Disable all other adapters.
4. Boot Metasploitable. Log in as `msfadmin / msfadmin`. Run `ip addr` and record the IP it gets on the host-only network — typically `192.168.56.x` or similar.
5. **Verify isolation**: from inside Metasploitable, run `ping -c 4 8.8.8.8`. The ping should *fail*. If it succeeds, your VM is reaching the internet; reconfigure the network and try again before continuing.

### Option B — Vagrant + Metasploitable 3

Rapid7 maintains Metasploitable 3 via Vagrant. Follow <https://github.com/rapid7/metasploitable3>. The same isolation rule applies: the VM's network must be host-only or fully NAT-isolated; the VM must not be able to ping the internet.

### Option C — Cannot set up Metasploitable right now

If you do not currently have a vulnerable VM, complete this exercise against a small intentionally-vulnerable Docker container you run on your laptop, *bound only to 127.0.0.1*. The OWASP Juice Shop, the DVWA container, or any of the OWASP WebGoat containers work. Replace the `<vuln-vm-ip>` placeholder below with `127.0.0.1` and the appropriate exposed port.

```bash
# Example: DVWA on a Docker container, loopback-only
docker run --rm -d -p 127.0.0.1:8080:80 vulnerables/web-dvwa
# Target becomes 127.0.0.1, port 8080.
```

This fallback is less rich than Metasploitable but is sufficient for the NSE-category coverage this exercise requires.

---

## Step 1 — RoE for this exercise (5 min)

Update `notes/ex2-roe.md` with the in-scope IP for your Metasploitable VM (or the loopback fallback). Specify:

- **In-scope**: the single IP of your vulnerable VM.
- **Out-of-scope**: every other IP.
- **Allowed actions**: SYN scan, version detection, default scripts, `safe`, `vuln and safe`, `auth` NSE categories.
- **Prohibited**: `intrusive`, `exploit`, `dos` categories. (You could run them — it is your VM — but for this exercise the discipline is to gate them behind RoE language. Production engagements never run `dos` on a hunch; build the habit now.)
- **Rate cap**: `--max-rate 1000`.

Save and sign.

---

## Step 2 — Confirm the VM is reachable (5 min)

From your laptop:

```bash
ping -c 4 <vuln-vm-ip>
```

You should see four replies. If not, the VM is off, the network configuration is wrong, or a host firewall is filtering. Fix before continuing.

```bash
mkdir -p ~/c6-week-07/exercise-02
cd ~/c6-week-07/exercise-02
```

---

## Step 3 — Initial port scan (10 min)

```bash
sudo nmap -sS --top-ports 1000 --max-rate 1000 -oA initial-scan <vuln-vm-ip>
```

Read `initial-scan.nmap`. Metasploitable 2 will typically show twenty or more open ports — far more than a real production host. Note the count.

In your notes, list each open port with its `nmap`-inferred service name (no `-sV` yet). The list should look something like:

```text
21/tcp   open  ftp
22/tcp   open  ssh
23/tcp   open  telnet
25/tcp   open  smtp
53/tcp   open  domain
80/tcp   open  http
...
```

---

## Step 4 — Service detection (10 min)

```bash
sudo nmap -sS -sV --top-ports 1000 --max-rate 1000 -oA version-scan <vuln-vm-ip>
```

Read `version-scan.nmap`. For each open port, record the **product**, **version**, and **CPE**. The output for Metasploitable 2 will include several services running ancient versions — that is intentional.

Some entries you will likely see:

- `vsftpd 2.3.4` (a famous CVE-2011-2523 backdoor).
- `OpenSSH 4.7p1 Debian 8ubuntu1` (multiple historical issues, also EoL).
- `Apache httpd 2.2.8` (EoL).
- `MySQL 5.0.51a-3ubuntu5` (EoL).
- `Samba smbd 3.X - 4.X` (multiple historical issues).

Identify, for each service, whether the version is end-of-life. Use the vendor's support page or Wikipedia for the support-status check.

---

## Step 5 — Default scripts (10 min)

```bash
sudo nmap -sS -sV -sC --top-ports 1000 --max-rate 1000 -oA default-script <vuln-vm-ip>
```

Read `default-script.nmap`. Compare to `version-scan.nmap`. Identify each new line that appeared because of `-sC`. Common examples:

- `ftp-anon: Anonymous FTP login allowed (FTP code 230)` — the `ftp-anon` script confirms anonymous FTP.
- `ssh-hostkey: 2048 ... (RSA)` — the SSH server's host keys.
- `http-title: ...` — the HTTP `<title>`.
- `ssl-cert: Subject: ...` — TLS certificate metadata.

In your notes, list each `-sC`-added line and its corresponding NSE script. Cross-reference with <https://nmap.org/nsedoc/>.

---

## Step 6 — The `safe` category in full (10 min)

```bash
sudo nmap -sS -sV --script "safe" --max-rate 1000 -oA safe-scripts <vuln-vm-ip>
```

This will produce significantly more output than `-sC`. Read it. The `safe` category includes everything in `default` plus many more scripts that are safe but not always-useful enough to be on by default.

Identify three new findings or pieces of information that appeared only because you ran the full `safe` category. Record them in your notes.

---

## Step 7 — The `vuln and safe` selector (15 min)

```bash
sudo nmap -sS -sV --script "vuln and safe" --max-rate 1000 -oA vuln-safe <vuln-vm-ip>
```

The `vuln and safe` selector runs only those vulnerability-detection scripts that the `nmap` maintainers classify as safe — i.e. the version-based checks, not the active-probe checks. The output will include CVE references for each finding.

Read `vuln-safe.nmap`. For each finding:

1. Note the **CVE ID**.
2. Look up the CVE on NVD: `https://nvd.nist.gov/vuln/detail/<CVE-ID>`.
3. Record the **CVSS score** and the **affected products**.
4. Confirm whether the version reported by `-sV` matches the "vulnerable" version range on NVD.

In your notes, produce a small table:

| Port | Service | Version | CVE | CVSS | Confirmed vulnerable? |
|------|---------|---------|-----|------|------------------------|
| 21   | vsftpd  | 2.3.4   | CVE-2011-2523 | 10.0 | Yes (backdoor in this version) |
| ...  | ...     | ...     | ... | ... | ... |

---

## Step 8 — The `auth` category (10 min)

```bash
sudo nmap -sS -sV --script "auth" --max-rate 1000 -oA auth-scripts <vuln-vm-ip>
```

The `auth` category reports authentication-related configuration. It does *not* attempt to log in with guessed credentials (those scripts are in `brute`, which this exercise does not run). Read `auth-scripts.nmap` and note:

1. Which services advertise their authentication methods.
2. Whether any service reports an unauthenticated configuration (e.g. anonymous FTP, NULL session on SMB).
3. Any auth-related findings that should be in the report.

---

## Step 9 — OS fingerprinting (5 min)

```bash
sudo nmap -O -oA os-scan <vuln-vm-ip>
```

Read `os-scan.nmap`. Note:

1. The OS family `nmap` reports.
2. The specific OS version.
3. The "Aggressive OS guesses" line, if present, with the per-guess percentages.
4. Whether `nmap` reports the result as confident or as a best-guess.

Cross-check by SSHing to the VM (`ssh msfadmin@<vuln-vm-ip>`, password `msfadmin`) and running `uname -a`. Does `nmap -O` match? If not, by how much?

---

## Step 10 — Notes write-up (10 min)

In `notes/ex2-writeup.md`, ~500 words covering:

- The VM setup: which VM, which network configuration, what isolation steps you verified.
- The findings: at least three specific findings with CVE references, formatted as Lecture 3 § 7 recommends.
- A reflection on NSE category selection: which categories gave the most signal for the time spent, which were overkill.
- A note on what would change about your scan if this VM were a *production* host rather than a vulnerable lab VM — *not* "what would you run" but "what would you stop running and why."

---

## Acceptance

- `notes/ex2-roe.md` exists and lists the lab VM IP.
- `~/c6-week-07/exercise-02/` contains the seven `-oA`-produced file sets.
- The findings table is in `notes/ex2-writeup.md`.
- Three or more findings are listed with CVE references.
- The VM was confirmed isolated from the internet before scanning.

---

## Notes and gotchas

- The first time you run `--script "vuln and safe"`, the output is overwhelming. That is normal for an intentionally-vulnerable VM. Read carefully; the volume is the lab's point.
- A handful of NSE scripts will report errors against Metasploitable's old services — these are usually compatibility issues with the ancient protocol versions, not real failures. Note the errors but do not panic.
- Do not skip Step 0. The single biggest failure mode in this exercise is "I set up Metasploitable but forgot to make the network host-only." Verifying with `ping 8.8.8.8` from inside the VM is the cheap check that catches the expensive mistake.
- The `intrusive` and `exploit` categories *could* be run against the VM, since you own it. The exercise omits them deliberately to build the habit. If you want to explore them, scope a separate session with explicit notes that those categories are running.
