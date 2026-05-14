# Week 8 — Quiz

Ten questions. Lectures closed. Aim for 9/10. The questions are written to be unambiguous; if a question seems to allow more than one answer, re-read the lecture.

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  Quiz questions about exploitation techniques refer to published    |
|  OWASP guidance, the lab in this week's mini-project starter, and   |
|  synthesised scenarios. Answering a quiz question does not          |
|  authorise you to send any payload at any host you do not own.      |
+---------------------------------------------------------------------+
```

---

**Q1.** A teammate asks you to run the Lecture 2 SQL injection payload against `https://example-shop.com/lookup?name=alice` because they "suspect it has the bug and want quick confirmation before raising it with the vendor." The site is not in any disclosed bug bounty scope and you do not have written authorisation. What is the correct reply?

- A) Run the payload from a coffee-shop Wi-Fi to avoid attribution.
- B) Run a single benign-shaped payload (`name=alice%27`) — a single apostrophe is too small to be a crime.
- C) Decline. The CFAA / CMA / Directive 2013/40/EU criminalises unauthorised access regardless of payload size or intent. Either the vendor authorises the test in writing or it does not get tested by you. Suggest the teammate use the vendor's published security-disclosure channel.
- D) Run the payload only if the site uses Cloudflare, since Cloudflare would block anything truly damaging.

---

**Q2.** Reflected XSS payload `<script>alert(1)</script>` lands on a page that uses Jinja's default autoescape and *no* `Markup()` wrapper. What does the browser receive in the response body?

- A) `<script>alert(1)</script>` (executes).
- B) `&lt;script&gt;alert(1)&lt;/script&gt;` (rendered as literal text by the browser).
- C) `%3Cscript%3Ealert(1)%3C/script%3E` (URL-encoded).
- D) Nothing — Jinja drops the value.

---

**Q3.** Your patched lab uses `subprocess.run(["convert", filename, "/tmp/out.png"], shell=False)` after validating `filename` with an allow-list. An attacker submits `filename = "test.png\\; id"` (a literal backslash-semicolon). What happens?

- A) The shell parses `\\;` as an escaped semicolon and `id` runs as a second command.
- B) The argv list passes `convert`, `test.png\\; id`, and `/tmp/out.png` as three separate arguments. No shell sees them; `convert` is asked to read a file named `test.png\\; id`, which probably does not exist, so the convert fails. No injection.
- C) Python's `subprocess` always invokes a shell internally.
- D) `convert` interprets the backslash-semicolon as a delimiter and runs `id`.

---

**Q4.** A scanner reports an IDOR at `/profile?id=N`. You log in as user 1 and verify `GET /profile?id=2` returns user 2's data. The patch in your application should:

- A) Encode the `id` parameter so attackers cannot easily change it.
- B) Use a hash of the user id in the URL so the attacker cannot guess valid ids.
- C) Add an ownership check in the view: if the requested id is not the session user's id and the session user is not an admin, return 403.
- D) Move the endpoint behind HTTPS.

---

**Q5.** A Flask application reads `session["token"] = str(random.random())`. Why is this CWE-330 / CWE-338?

- A) The token is too short.
- B) `str()` introduces predictable formatting.
- C) `random.random()` is the Mersenne Twister: it is fast and statistically uniform, but its state can be reconstructed from a handful of consecutive outputs, so future tokens are predictable. The correct API for security-sensitive randomness is `secrets.token_urlsafe()` from the `secrets` module.
- D) The token does not include a timestamp.

---

**Q6.** Python's `pickle.loads()` on attacker-controlled bytes is dangerous because:

- A) The pickle protocol allows the byte stream to encode arbitrary callable-invocation steps (the `__reduce__` mechanism), so unpickling effectively executes attacker-chosen code with the application's privileges.
- B) Pickle decompresses very slowly, leading to a denial of service.
- C) Pickle is incompatible with Python 3.
- D) The pickle byte stream is base64-encoded by default.

---

**Q7.** Server-Side Request Forgery against a misconfigured cloud-hosted web application typically rewards the attacker with:

- A) The web application's source code.
- B) The cloud instance's IAM role temporary credentials, retrieved from the cloud metadata service (e.g. `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` on AWS), which the attacker then uses from outside to assume that role and call the cloud provider's API.
- C) The customer database's schema.
- D) Persistent shell access to the host.

---

**Q8.** A Content Security Policy of `default-src 'self'; script-src 'self'; ...` (no `'unsafe-inline'`) is loaded for a page that, due to a regression, now contains an inline `<script>alert(1)</script>` injected by an XSS bug. What does the browser do?

- A) Executes the script; CSP only applies to externally-loaded resources.
- B) Refuses to execute the inline script, logs a "Refused to execute inline script" violation in the developer console, and (if `report-to` / `report-uri` is configured) sends a violation report to the configured endpoint.
- C) Strips the script tag from the response.
- D) Encodes the `<` and `>` characters in the response.

---

**Q9.** HTTP request smuggling (CL.TE / TE.CL) requires:

- A) A single web server.
- B) Two HTTP processors in series — typically a CDN or reverse proxy in front of an origin server — that disagree on whether to honour `Content-Length` or `Transfer-Encoding` when both are present in a request.
- C) The presence of HTTP/2 on the wire.
- D) A misconfigured TLS terminator.

---

**Q10.** You are designing the patch for `/fetch-image?url=<...>`. A teammate suggests this defence: "look up the URL's hostname, check the resulting IP against an allow-list of public IPs, and refuse to fetch if it resolves to a private IP." Why is this fix not enough?

- A) It does not handle IPv6.
- B) DNS rebinding: the attacker controls a hostname whose first DNS lookup resolves to a benign public IP (passing your check) and whose second DNS lookup (during the actual fetch) resolves to a private internal IP. The defence has a time-of-check / time-of-use gap. The fix is to resolve once, pass the resolved IP to the HTTP fetcher, and set the Host header to the original hostname.
- C) `socket.getaddrinfo` is slow.
- D) The fix needs to be applied at the load balancer, not the application.

---

## Answer key

1. **C.** The CFAA / CMA / Directive 2013/40/EU treats unauthorised access as a crime regardless of payload intent. The single right move is to decline and route the report through the vendor's published channel. (Lecture 1 banner; Lecture 2 banner; Week 7 lecture 1.)

2. **B.** Jinja's default autoescape encodes `<`, `>`, `&`, `"`, `'`. The browser receives `&lt;script&gt;alert(1)&lt;/script&gt;`, which renders as the literal six-character sequence `<script>alert(1)</script>` displayed on the page, not as an executable tag. (Lecture 2 § 2; Lecture 3 § 2; Jinja docs on autoescape.)

3. **B.** With `shell=False` and an argv list, the OS executes `argv[0]` directly and passes `argv[1:]` as arguments without any shell parsing. The semicolon and `id` are characters inside the second argument; the shell never sees them. (Lecture 3 § 3; Python `subprocess` docs Security Considerations.)

4. **C.** The right patch is an ownership check at the start of the view. Encoding the id (A) does not prevent enumeration. Hashing the id (B) is "security through obscurity" — useful as defence-in-depth but not a primary control. HTTPS (D) is unrelated to authorisation. (Lecture 3 § 4.1.)

5. **C.** Mersenne Twister state recoverability is the canonical reason `random` is unsuitable for security. `secrets.token_urlsafe()` reads from the OS CSPRNG and is the right replacement. (Lecture 3 § 6.3; Python `secrets` docs.)

6. **A.** Pickle's `__reduce__` protocol returns a `(callable, args)` tuple that the unpickler invokes. An attacker who controls the bytes can make this any callable, including `os.system`. (Lecture 2 § 9; Python `pickle` docs first paragraph.)

7. **B.** The metadata service is the canonical SSRF target on cloud hosts. The Capital One 2019 breach exfiltrated S3 data this way. (Lecture 2 § 10; Lecture 3 § 8.)

8. **B.** CSP applies to inline scripts as well as external ones. Without `'unsafe-inline'`, the policy refuses inline execution and logs a violation. (Lecture 3 § 9; MDN CSP overview.)

9. **B.** Smuggling is a *disagreement* between two HTTP processors. One processor is necessary but not sufficient; you need a parser disagreement somewhere on the path. (Lecture 3 § 10; Kettle 2019 paper.)

10. **B.** DNS rebinding defeats resolve-then-fetch defences when the resolve happens at the check step and a separate resolve happens at the fetch step. The fix is to resolve once and pass the IP to the fetcher with an explicit Host header. (Lecture 3 § 8; OWASP SSRF Prevention Cheat Sheet.)
