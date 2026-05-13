# Week 1 — Quiz

Ten questions. Lectures closed. Aim for 9/10. The questions are written to be unambiguous; if a question seems to allow more than one answer, re-read the lecture.

---

**Q1.** The CIA triad stands for which three properties?

- A) Confidentiality, Identity, Authentication
- B) Confidentiality, Integrity, Availability
- C) Containment, Integrity, Auditing
- D) Confidentiality, Identity, Authorization

---

**Q2.** Which of the following is a *vulnerability*, not a threat?

- A) A ransomware crew currently active in your industry.
- B) An employee who is about to be laid off.
- C) An unpatched CVE in your reverse proxy.
- D) A regional power outage affecting your data center.

---

**Q3.** In STRIDE, the **R** stands for:

- A) Reflection
- B) Repudiation
- C) Reconnaissance
- D) Replay

---

**Q4.** A file is listed as `-rwsr-xr-x 1 root root  ...  /usr/bin/passwd`. The `s` in the owner-execute slot means:

- A) The file is symbolically linked.
- B) The file has a "shared" attribute and may be edited by group members.
- C) The file is `setuid`; when executed, the process runs with the file owner's effective UID.
- D) The file is in "supervisor" mode and requires sudo to run.

---

**Q5.** A user runs `sudo -l` and sees `(ALL) NOPASSWD: ALL`. Why is this a finding even if the user is "already trusted"?

- A) Because `NOPASSWD` is deprecated and will stop working in sudo 2.0.
- B) Because a compromise of the user's session (stolen cookies, malicious dependency, lost laptop) instantly becomes a compromise of root with no further challenge.
- C) Because `sudo` always logs `NOPASSWD` invocations as suspicious in `/var/log/auth.log`.
- D) Because `NOPASSWD` bypasses SELinux.

---

**Q6.** `CAP_NET_BIND_SERVICE` grants which specific privilege?

- A) The ability to inspect any process's network connections.
- B) The ability to capture raw packets on any interface.
- C) The ability to bind to TCP and UDP ports below 1024.
- D) The ability to modify firewall rules.

---

**Q7.** A web service is compromised. The attacker reads files as the service's user, but cannot read `/etc/shadow` even though the service technically runs as root inside its container. The most likely reason is:

- A) `/etc/shadow` does not exist inside the container.
- B) A MAC layer (SELinux or AppArmor) profile denies the read regardless of UID.
- C) The kernel's "root squash" feature.
- D) The Linux scheduler.

(Both A and B are plausible depending on the system; choose the one Lecture 2 emphasizes.)

---

**Q8.** On a Debian/Ubuntu system, where do `sshd` and `sudo` write authentication events by default?

- A) `/var/log/messages`
- B) `/var/log/auth.log`
- C) `/var/log/secure`
- D) `/etc/audit/audit.log`

---

**Q9.** The four questions of Shostack's threat-modeling framework are:

- A) Who, What, When, Where.
- B) What are we building, What can go wrong, What are we going to do about it, Did we do a good job.
- C) Identify, Protect, Detect, Respond.
- D) Confidentiality, Integrity, Availability, Accountability.

---

**Q10.** A directory is `drwxrwxrwt` (mode 1777). The trailing `t` (sticky bit) on a world-writable directory prevents:

- A) Any user from creating new files in the directory.
- B) Users from `cd`-ing into the directory.
- C) Users from deleting or renaming files they do not own (only the file's owner or root may unlink).
- D) The directory from being listed by `ls`.

---

## Answer key

<details>
<summary>Click to reveal</summary>

1. **B** — Confidentiality, Integrity, Availability. Authentication, authorization, accountability are related but separate properties; see Lecture 1 §2.
2. **C** — A vulnerability is a weakness in your system. A, B, and D are *threats* (potential causes of harm). The discipline of distinguishing the two is in Lecture 1 §3.
3. **B** — Repudiation. The threat is the user denying they performed an action; the mitigation is logging and signed audit trails.
4. **C** — `setuid`. The bit's mechanic — process runs with file owner's effective UID — is the entire reason `passwd` works for unprivileged users and the entire reason every bug in `passwd` is a privilege escalation.
5. **B** — The password requirement is the second factor against a stolen session. `NOPASSWD: ALL` removes it. A is false; C is false; D is false (sudo and SELinux are independent layers).
6. **C** — Bind to ports below 1024. This is exactly the capability you give a web server instead of running it as root.
7. **B** — MAC (SELinux or AppArmor). The point of MAC is that it constrains even root according to the policy.
8. **B** — `/var/log/auth.log` on Debian/Ubuntu. `/var/log/secure` is the RHEL/Fedora equivalent (D is wrong for the default config; auditd is opt-in additional logging).
9. **B** — Shostack's four questions. C is the NIST CSF functions (without "Govern" or "Recover"). D is CIA plus accountability.
10. **C** — Only the file owner (or root) may unlink. This is exactly what protects `/tmp` from one user wiping another user's files.

</details>

If under 7, re-read the lectures. If 9+, you are ready for the [homework](./homework.md).
