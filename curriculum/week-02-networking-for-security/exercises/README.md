# Week 2 — Exercises

Three hands-on drills. Each one takes 40-60 minutes. Do them in order.

1. **[Exercise 1 — Capture your own traffic](exercise-01-capture-your-own-traffic.md)** — first `tcpdump` capture on loopback and on your LAN, opened in Wireshark. (~45 min)
2. **[Exercise 2 — `tcpdump` puzzles](exercise-02-tcpdump-puzzles.md)** — six BPF filter puzzles against captures you produce yourself. **Own-traffic only.** (~50 min)
3. **[Exercise 3 — `nftables` rules](exercise-03-nftables-rules.md)** — build a default-deny `nftables` ruleset on a VM you own and verify it. (~50 min)

## Workflow

- Type, do not paste. The muscle memory matters.
- Capture *your own* traffic. Generate it on purpose: open a browser tab to a known site, run `curl`, run `dig`. You should always be able to point at a packet and say "I caused that, with this command."
- Save every capture. Even the short ones. They become reference data later.
- Do destructive firewall experiments on a VM you can hard-reset. The classic mistake is locking yourself out of a remote box.

## Self-grading

After each exercise, ask yourself: "Could I explain this to a junior engineer in three minutes, with the capture open?" If yes, move on. If no, re-read the relevant lecture before the next one.
