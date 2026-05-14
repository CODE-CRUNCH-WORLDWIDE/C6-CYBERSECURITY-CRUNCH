# Exercise 1 — Scan Your Own Host

**Estimated time:** 60 minutes. `nmap` installed. Linux or macOS. Local-only.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Every command in this exercise targets 127.0.0.1 — your own        │
│  loopback interface — or a virtual machine you provisioned and      │
│  own. Do not substitute any other IP. The loopback is in scope      │
│  for this exercise because you own the host running it.             │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

You are the engineer on rotation. The "engagement" is a recon dry-run on your own laptop. The RoE is the simple one drafted in Lecture 1 § 7. The purpose is to walk every scanner mode from the lectures once, end-to-end, producing both the human-readable output and the structured XML you will use in Exercise 3.

This exercise covers:

- The **RoE-first habit** — you write the document before the first packet.
- **Host discovery** vs. **port scanning** at the smallest possible scale.
- The **canonical scan modes** — `-sn`, `-sS`, `-sT`, `-sU`.
- **Rate-limit discipline** — `--max-rate` even on your own host.
- **Output formats** — `-oN`, `-oG`, `-oX`, `-oA`.

---

## Step 1 — Write the RoE for this exercise (10 min)

Create `notes/ex1-roe.md`. Adapt the skeleton from Lecture 1 § 7:

```markdown
# RoE — Exercise 1

## Parties
- Engineer: <your name>.
- Owner: <your name>.
- Authority: self, by virtue of owning the laptop.

## In-scope
- 127.0.0.1 (loopback on the engineer's laptop).

## Out-of-scope
- Every other IP, including the laptop's LAN address(es) and the
  router. The exercise targets *loopback only*.

## Allowed actions
- TCP SYN scan (`nmap -sS`), TCP connect scan (`nmap -sT`),
  UDP scan (`nmap -sU` top-100), version detection (`-sV`),
  default scripts (`-sC`), safe scripts (`--script safe`).
- Output to file in `~/c6-week-07/exercise-01/`.

## Prohibited
- Any test against any IP other than 127.0.0.1.
- Any NSE category outside `safe` and `default`.
- Any rate above 1000 pps.

## Time window
- One hour of focused work.

## Rate cap
- `--max-rate 1000`.

## Emergency stop
- Engineer's discretion.

## Signed
- Engineer: <name>, <date>.
- Owner: <name>, <date>.
```

The exercise is small; the discipline of writing the document for a small exercise is the same as for a large one.

---

## Step 2 — Confirm the toolchain (5 min)

In a terminal:

```bash
nmap --version
```

You should see version `7.94` or later. If you see something older, update before continuing:

- macOS: `brew install nmap` or `brew upgrade nmap`.
- Debian/Ubuntu: `sudo apt update && sudo apt install nmap`.
- Fedora: `sudo dnf install nmap`.
- Arch: `sudo pacman -S nmap`.

Create the output directory:

```bash
mkdir -p ~/c6-week-07/exercise-01
cd ~/c6-week-07/exercise-01
```

---

## Step 3 — Host discovery against loopback (5 min)

```bash
sudo nmap -sn -oA host-discovery 127.0.0.1
```

Read all three output files (`host-discovery.nmap`, `host-discovery.gnmap`, `host-discovery.xml`). Answer in your notes:

1. Was the host reported as up?
2. How did `nmap` determine that — what reason did it log?
3. Why is host discovery on loopback essentially trivial compared to host discovery on a real subnet?

---

## Step 4 — Default port scan (5 min)

```bash
sudo nmap -sS -oA default-scan 127.0.0.1
```

Read `default-scan.nmap`. Record:

1. How many ports were scanned? (The default is the top 1000 TCP.)
2. How many showed `open`? How many `closed`? How many `filtered`?
3. For each `open` port, what does the SERVICE column show? Is `nmap` guessing the service from the port number alone (no `-sV`), or has it identified the service?

If no ports are open on your loopback, that is fine — many laptops run no listening services. Note the result and continue.

---

## Step 5 — Service detection (10 min)

```bash
sudo nmap -sS -sV -oA version-scan 127.0.0.1
```

Read `version-scan.nmap`. For each open port, record:

1. The service name.
2. The product (e.g. `OpenSSH`, `nginx`).
3. The version string.
4. The CPE, if `nmap` emitted one.

Also note in the bottom of the report:

5. The "Service Info" line — what OS does `-sV` infer from the banners?

---

## Step 6 — Default scripts (10 min)

```bash
sudo nmap -sS -sV -sC -oA full-default 127.0.0.1
```

Compare `full-default.nmap` to `version-scan.nmap`. What did `-sC` add?

If your loopback has open ports, you will typically see additional output blocks like:

- `ssh-hostkey:` listing the SSH server's keys.
- `ssl-cert:` if any port runs TLS.
- `http-title:` for HTTP ports.

For each additional `-sC` output block, identify which NSE script produced it. Cross-reference with <https://nmap.org/nsedoc/> if a script name is unfamiliar.

---

## Step 7 — TCP connect scan (5 min)

```bash
nmap -sT -oA connect-scan 127.0.0.1
```

(Note: no `sudo`. The connect scan is the default when `nmap` runs without root.)

Compare `connect-scan.nmap` to `default-scan.nmap` (the earlier `-sS` output). Answer:

1. Are the results identical?
2. If they differ, why? (Hint: think about the kernel's handling of incoming connections during a connect scan versus a SYN scan.)
3. Which scan would the loopback service's *application* log see?

---

## Step 8 — UDP scan (10 min)

```bash
sudo nmap -sU --top-ports 100 --max-rate 100 -oA udp-scan 127.0.0.1
```

This will take longer than the TCP scans. Read `udp-scan.nmap` once it finishes. Record:

1. How many UDP ports were tested?
2. How many showed `open`? `open|filtered`? `closed`?
3. Why is the most-common state for UDP ports `open|filtered` rather than `open` or `closed`?

---

## Step 9 — Rate-limited full scan (10 min)

```bash
sudo nmap -sS --max-rate 5000 -p- -oA full-tcp 127.0.0.1
```

`-p-` scans all 65,535 TCP ports. `--max-rate 5000` caps the rate at 5000 pps; on loopback this is conservative — the actual scan will likely complete in seconds.

Read `full-tcp.nmap`. Answer:

1. Did `-p-` reveal any ports that the top-1000 default scan missed?
2. How long did the full scan take? (Look for the "Nmap done" line.)
3. At the rate cap of 5000 pps, what is the theoretical minimum time to scan 65,535 ports? Does the observed time match?

---

## Step 10 — XML output for Exercise 3 (5 min)

```bash
sudo nmap -sS -sV -sC --top-ports 100 -oX scan-for-parsing.xml 127.0.0.1
```

This XML file is the input for Exercise 3. Keep it. Optionally, run a second scan against a Metasploitable VM you own to get a richer file:

```bash
# Only if you have a Metasploitable VM on a host-only network you own
sudo nmap -sS -sV -sC --top-ports 100 -oX metasploitable.xml 10.0.2.15
```

If you do not yet have Metasploitable set up, that is fine; Exercise 3 will use the loopback XML as the primary input.

---

## Step 11 — The notes write-up (5 min)

In `notes/ex1-writeup.md`, ~300 words covering:

- What you scanned and what you found.
- Which scan modes returned the most useful information for your loopback.
- Anything surprising — a service listening you did not know about, an unusual response pattern.
- An honest "what would I have done differently?" — the discipline grows from reflection.

---

## Acceptance

- `notes/ex1-roe.md` exists and contains your signed self-RoE.
- `~/c6-week-07/exercise-01/` contains the eight `-oA`-produced file sets.
- `scan-for-parsing.xml` exists and parses as XML (`xmllint --noout scan-for-parsing.xml` returns 0).
- `notes/ex1-writeup.md` exists and is roughly 300 words.

---

## Notes and gotchas

- If `sudo nmap` prompts for a password on macOS, the prompt is normal. The SYN scan needs raw-socket access; that needs root.
- If your loopback shows zero open ports, your laptop is well-configured. Note it in the write-up and continue with the unprivileged `-sT` to confirm you get the same result.
- If you have services bound to `0.0.0.0` rather than `127.0.0.1`, the loopback scan will still see them — but a scan against the laptop's LAN IP would *also* see them. The scope of this exercise is loopback; do not scan the LAN IP unless you separately authorise yourself to do so.
- Some firewalls on enterprise-managed laptops will interfere with loopback scans. If you see entirely unexpected `filtered` results, check whether a managed firewall is intercepting. Note the configuration; the exercise is still complete.
