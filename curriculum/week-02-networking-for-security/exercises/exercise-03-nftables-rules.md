# Exercise 3 — `nftables` Rules

**Time:** ~50 minutes.
**Outcome:** You have written a small `nftables` ruleset on a VM you own that implements default-deny on the `input` chain, allows SSH from a specific source, allows established connections, and logs everything else. You have verified each rule with a test from outside the VM.

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

> **Use a VM you can hard-reset.** The classical mistake in this exercise is locking yourself out of an SSH session by writing a `policy drop` before adding the `accept SSH from my source` rule. Pre-stage the file, load it as one transaction, and have a console session available.

## Problem statement

Build `nftables.conf` for a small server. Load it. Verify each rule with an external test. Document the work in `exercise-03-nftables.md`.

## Setup

A Linux VM you own — Ubuntu 24.04 or Debian 12 are easiest. From the VM's host or another machine on the same LAN you will run tests against the VM. Note the VM's IP (`ip -4 addr`) and your test machine's IP (so you can put the latter in the allow-rule).

```bash
sudo apt install -y nftables
sudo systemctl status nftables    # may be inactive until we enable it
sudo nft list ruleset             # likely empty
```

If you have an existing `ufw` configuration, disable it for this exercise so the rules do not fight:

```bash
sudo systemctl disable --now ufw
```

## Task 1 — Write the ruleset (15 min)

Save the following as `/etc/nftables.conf` on the VM. **Replace `198.51.100.42` with your test-machine's IP** — that is the only host that will be allowed to SSH in.

```nft
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        # 1. Loopback.
        iif "lo" accept

        # 2. Established and related connections (return traffic).
        ct state established,related accept

        # 3. ICMPv4 / ICMPv6 — limited rate.
        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 5/second accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept

        # 4. SSH from a specific source only.
        ip saddr 198.51.100.42 tcp dport 22 ct state new accept

        # 5. Drop invalid packets explicitly.
        ct state invalid drop

        # 6. Log a rate-limited sample of everything else, then drop via policy.
        limit rate 10/minute log prefix "[nft drop input] " level info
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
```

Sanity-check the syntax without loading:

```bash
sudo nft -c -f /etc/nftables.conf && echo OK
```

The `-c` flag is "check only." Do not skip it.

## Task 2 — Load and verify (15 min)

Load the ruleset and inspect:

```bash
sudo nft -f /etc/nftables.conf
sudo nft list ruleset
sudo systemctl enable --now nftables
```

The `enable --now` step persists the configuration across reboots.

From the *test* machine (the one whose IP is allowed):

```bash
# Should succeed:
ssh user@<vm-ip> -o ConnectTimeout=5 echo OK

# Should be silently dropped (no response):
nc -vz <vm-ip> 80 -w 5     # port 80 is not allowed
```

If you have access to a *second* test machine, or you can change your test machine's IP, confirm:

```bash
# From an IP NOT in the allow list — should time out (silently dropped):
nc -vz <vm-ip> 22 -w 5
```

You should observe the `[nft drop input]` log lines on the VM:

```bash
sudo journalctl -kf | grep "nft drop"
```

Each dropped packet adds a line. Browse the LAN's noise and watch what hits.

## Task 3 — Add egress filtering (15 min)

The default `policy accept` on `output` is not a finishing posture. Tighten it:

```nft
    chain output {
        type filter hook output priority filter; policy drop;

        # Loopback.
        oif "lo" accept

        # Established.
        ct state established,related accept

        # DNS (UDP and TCP) to anywhere.
        ct state new tcp dport 53 accept
        ct state new udp dport 53 accept

        # NTP.
        ct state new udp dport 123 accept

        # HTTP / HTTPS to anywhere (apt, web).
        ct state new tcp dport { 80, 443 } accept

        # Outbound SSH (for your own admin work).
        ct state new tcp dport 22 accept

        # ICMP echo and the responses we need to receive.
        ct state new ip protocol icmp icmp type { echo-request } accept
        ct state new ip6 nexthdr icmpv6 icmpv6 type { echo-request, nd-neighbor-solicit } accept

        # Log the drop.
        limit rate 10/minute log prefix "[nft drop output] " level info
    }
```

Reload:

```bash
sudo nft -f /etc/nftables.conf
```

Test that legitimate outbound still works:

```bash
curl -sS https://example.com/ -o /dev/null && echo "https OK"
dig +short example.com
```

Test that an *unusual* outbound is dropped:

```bash
nc -vz -w 5 1.1.1.1 6379       # Redis port — expect a timeout / closed
```

Watch the journal:

```bash
sudo journalctl -kf | grep "nft drop output"
```

You should see the attempted Redis connection logged. Egress filtering is doing its job.

## Acceptance criteria

- [ ] `exercise-03-nftables.md` committed to your Week 2 notes folder.
- [ ] The notes contain the final `nftables.conf` file in full.
- [ ] The notes show the output of `sudo nft list ruleset` after each load.
- [ ] The notes show successful and unsuccessful test results: SSH from the allowed source succeeds; SSH from elsewhere times out; an unauthorised egress is dropped; a legitimate egress works.
- [ ] The notes contain at least one `[nft drop input]` and one `[nft drop output]` log line from `journalctl`.
- [ ] You have not locked yourself out. (Acceptance is implicit: you are still here.)

## Hints

<details>
<summary>If you lose SSH access</summary>

This is the classical mistake. Use your VM's console (the hypervisor's "open console" button — present in QEMU, VirtualBox, Proxmox, vSphere, every cloud console). From the console: `sudo nft flush ruleset`. Then edit `/etc/nftables.conf` and reload.

If you lose console access too (cloud VM with no console), most cloud providers offer an emergency "rescue mode." Use it. Next time, pre-stage rules and load them with `( sleep 60 && nft flush ruleset ) &` in the background, so a mistake auto-recovers after one minute.

</details>

<details>
<summary>If `nftables` is not installed on your distribution</summary>

`sudo apt install nftables` on Debian/Ubuntu. `sudo dnf install nftables` on Fedora. On RHEL/CentOS Stream it is already present.

</details>

<details>
<summary>If you need to find the right interface name</summary>

`ip -4 addr` lists all interfaces. `ip route get 1.1.1.1 | awk '{print $5; exit}'` prints the egress one.

</details>

## Why this matters

Default-deny is the only credible firewall posture for an internet-reachable host. Every junior security engineer is asked, at some point in their first month, to audit or write a host firewall ruleset. Knowing `nftables` from the inside — the chain structure, the state matching, the logging idiom — means you are not guessing.

## Submission

Commit the notes. Make sure `/etc/nftables.conf` is also in the notes (or referenced as a file in the repo). Move on to the challenge.
