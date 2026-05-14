# Week 7 — Quiz

Ten questions. Lectures closed. Aim for 9/10. The questions are written to be unambiguous; if a question seems to allow more than one answer, re-read the lecture.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Quiz questions about scanning techniques refer to published        │
│  tool documentation, public statutes, and synthesised lab           │
│  scenarios. Answering a quiz question does not authorise you to     │
│  run any scan against any host you do not own.                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

**Q1.** A colleague writes to you on Monday morning: "I have verbal authorisation from the customer's IT director to scan their `/22`. They are out of office until Thursday. The scan window closes Wednesday. Can I start?" What is the correct reply?

- A) Yes — verbal authorisation from someone in IT leadership is sufficient.
- B) No — until you have a signed RoE document that specifies the in-scope assets, time window, rate cap, and emergency-stop contact, the only host you scan is one you own. Wait for the document or shift the window.
- C) Yes, but only at `-T0` (Paranoid) to reduce the risk of detection.
- D) Yes, but only against the most-recently-added systems in their CMDB, since those are the ones that haven't been hardened yet.

---

**Q2.** The DoJ's May 2022 charging-policy update for the Computer Fraud and Abuse Act:

- A) Created a statutory immunity for good-faith security researchers.
- B) Repealed § 1030(a)(2) of the CFAA.
- C) Established a federal prosecutorial policy disfavouring CFAA charges against good-faith security research meeting specified conditions; the policy is not statutory immunity and does not bind state prosecutors or civil plaintiffs.
- D) Extended the CFAA's reach to cover passive port scanning.

---

**Q3.** You are scanning the loopback interface of your own laptop with `sudo nmap -sS 127.0.0.1`. What is happening at the protocol layer when `nmap` reports a port as `open`?

- A) `nmap` completed a full TCP three-way handshake and the kernel handed the connection to the listening application.
- B) `nmap` sent a SYN, received a SYN-ACK in response, marked the port open, and sent a RST to tear down the half-open connection without ever completing the handshake.
- C) `nmap` sent an ICMP echo request and got an echo reply.
- D) `nmap` opened a UDP socket and waited for an application response.

---

**Q4.** A SYN scan (`-sS`) and a connect scan (`-sT`) against the same host typically produce identical results for open ports, but they differ in one important operational dimension. Which?

- A) The SYN scan is faster on every network because it bypasses the kernel networking stack entirely.
- B) The connect scan is more accurate because it uses the operating system's `connect(2)` system call.
- C) The connect scan completes the three-way handshake, so the *application* on the target sees and typically logs a connection; the SYN scan never completes the handshake, so the application does not see it (though the kernel's connection-tracking and any network IDS still do).
- D) The SYN scan is recognised by the target as friendly; the connect scan is recognised as hostile.

---

**Q5.** Your RoE specifies a rate cap of 500 packets per second per source IP. You are about to run `nmap` against a `/24`. Which flag combination most precisely enforces this cap?

- A) `-T0`.
- B) `--scan-delay 100ms`.
- C) `--max-rate 500`.
- D) `--min-rate 500`.

---

**Q6.** You receive an `nmap -sU` output that shows 95 of 100 UDP ports as `open|filtered`, 4 as `closed`, and 1 as `open`. Why is `open|filtered` the dominant state?

- A) The target is running a misconfigured firewall.
- B) UDP has no handshake; an open port that does not respond to a non-service-specific probe is indistinguishable from a filtered port whose probe was dropped. `nmap` reports the ambiguity rather than guessing.
- C) The scanner ran out of network buffers.
- D) The target is honouring an explicit rate-limit on ICMP unreachable responses, which would have indicated closed ports.

---

**Q7.** Which NSE category should never be run against a host without explicit, written RoE language authorising it?

- A) `safe`.
- B) `default`.
- C) `discovery`.
- D) `dos`.

---

**Q8.** You run `masscan --rate 1000000` against a `/24` on the open internet. Why is this almost certainly the wrong rate, regardless of the in-scope authorisation?

- A) `masscan` does not support rates above 100,000 pps.
- B) One million packets per second across a `/24` saturates most realistic uplinks, exhausts the target organisation's perimeter device's session tables, and will be detected and rate-limited (or null-routed) by any competent upstream provider; the scan will fail or cause an incident long before it completes.
- C) The CFAA prohibits scan rates above 10,000 pps.
- D) `masscan` cannot scan a `/24`; it is designed only for `/16` and larger.

---

**Q9.** `nmap -O` reports "Aggressive OS guesses: Linux 2.6.9 - 2.6.33 (90%), Linux 2.6.34 - 3.10 (87%), QNX 6.5 (84%)." How should the recon report describe the OS?

- A) "QNX 6.5" — `-O`'s lowest-confidence guess is the most likely to be unexpected and therefore the most interesting.
- B) "Linux 2.6.9 - 2.6.33 (90% confidence from `-O`, not validated)." Report the highest-confidence guess with its confidence number, label it as `-O`-derived, and validate via `-sV` banner-derived OS hints before escalating any finding that depends on the OS identification.
- C) "Linux 2.6.9 - 2.6.33" as a confident statement; the 90% confidence number is operational, not reportorial.
- D) "Indeterminate" — the three candidates cover too wide a range to report any of them.

---

**Q10.** You are pipeline-ing tools for an authorised wide recon: `masscan` to sweep, `nmap` to enrich. Which order and which output format makes the pipeline robust?

- A) Run `nmap` first for accuracy; run `masscan` afterward only if `nmap` is too slow.
- B) `masscan --rate <cap> -p<single-port> -oG masscan.gnmap <range>`; awk the `Host:` lines into a list; `sudo nmap -iL <list> -sS -sV -sC -p- -oX enrichment.xml`; then parse the XML.
- C) `masscan -p1-65535 -oN masscan.txt <range>`; grep through the text output to find live hosts.
- D) Run both in parallel and merge the outputs manually after both finish.

---

## Answer key

1. **B.** Until the signed RoE is in hand, the only host you scan is one you own. Verbal authorisation is unenforceable, unmemorable, and does not survive an audit. (Lecture 1 § 6.1.)

2. **C.** The 2022 policy update is *prosecutorial guidance*, not statutory immunity. It defines good-faith security research and directs federal prosecutors not to charge such research; state prosecutors and civil plaintiffs are not bound. (Lecture 1 § 1.1.)

3. **B.** A SYN scan is by definition a half-open scan: SYN out, SYN-ACK back, RST out, no full handshake. (Lecture 2 § 3.1; RFC 793 § 3.4.)

4. **C.** The connect scan uses `connect(2)`, which completes the handshake, so the application sees the connection in its accept loop and typically logs it. The SYN scan never completes, so the application is not notified. (Lecture 2 § 3.1, § 3.2.)

5. **C.** `--max-rate <pps>` is the explicit and precise rate cap. `-T<n>` is a bundle of timing parameters but not a hard cap; `--scan-delay` controls inter-probe delay but not aggregate rate; `--min-rate` is the opposite of a cap. (Lecture 2 § 5.2.)

6. **B.** UDP's lack of a handshake means an unresponsive port is indistinguishable from a filtered port. `-sV` reduces the ambiguity with service-specific probes but does not eliminate it. (Lecture 2 § 1.2, § 4.)

7. **D.** `dos` actively attempts denial-of-service. Never run against a host that is not your own lab VM with the explicit purpose of testing DoS. `safe`, `default`, and `discovery` are broadly permissible under a scope that authorises service detection. (Lecture 3 § 3.9.)

8. **B.** Rate is not a personal choice; it is a contract with the network. One million pps against a `/24` is the wrong rate for nearly every real-world authorised engagement. (Lecture 2 § 5.5.)

9. **B.** Report the highest-confidence guess, label it with its confidence and as `-O`-derived, and cross-validate from `-sV` banner-derived OS before any finding depends on it. (Lecture 3 § 4.2.)

10. **B.** Wide tool for the sweep, careful tool for the enrichment. XML output from the enrichment step is the right format for downstream parsing. (Lecture 2 § 6.1.)
