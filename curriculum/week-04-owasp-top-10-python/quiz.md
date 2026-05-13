# Week 4 — Quiz

Ten questions. Lectures closed. Aim for 9/10. The questions are written to be unambiguous; if a question seems to allow more than one answer, re-read the lecture.

---

**Q1.** Which OWASP Top 10 2021 category was promoted to **#1** because of high incidence, high severity, and low detection rates across audited applications?

- A) `A02:2021 Cryptographic Failures`
- B) `A01:2021 Broken Access Control`
- C) `A03:2021 Injection`
- D) `A07:2021 Identification and Authentication Failures`

---

**Q2.** Which of the following is the safest password storage choice for a new Python web application as of the OWASP 2021 / 2025-RC guidance?

- A) `hashlib.md5(password.encode()).hexdigest()`
- B) `hashlib.sha256(password.encode()).hexdigest()`
- C) `argon2.PasswordHasher().hash(password)` (Argon2id)
- D) `bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4))`

---

**Q3.** A Flask route looks like this:

```python
cur.execute(f"SELECT id FROM users WHERE username = '{username}'")
```

Which OWASP category and CWE does it violate, and what is the minimal fix?

- A) `A05 / CWE-16` — set `DEBUG=False`.
- B) `A03 / CWE-89` — use a parameterised query: `cur.execute("SELECT id FROM users WHERE username = ?", (username,))`.
- C) `A02 / CWE-327` — switch to PostgreSQL.
- D) `A07 / CWE-287` — add `@login_required`.

---

**Q4.** A Flask route:

```python
@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    return jsonify(Order.query.get(order_id).to_dict())
```

The bug is best described as:

- A) Cross-site scripting; the response is not HTML-escaped.
- B) SQL injection; the `order_id` is interpolated into the query.
- C) Insecure direct object reference (IDOR) — authentication is checked but not authorisation; user 42 can read user 17's order.
- D) Cryptographic failure; the order details are not encrypted at rest.

---

**Q5.** The 2021 edition folded XML External Entities (XXE, formerly `A04:2017`) into which 2021 category?

- A) `A02:2021 Cryptographic Failures`
- B) `A03:2021 Injection`
- C) `A05:2021 Security Misconfiguration`
- D) `A08:2021 Software and Data Integrity Failures`

---

**Q6.** Which of the following session-ID generation calls is safe for security purposes?

- A) `random.randint(0, 10**12)`
- B) `f"{int(time.time())}-{random.random()}"`
- C) `secrets.token_urlsafe(32)`
- D) `hashlib.md5(str(uuid.uuid1()).encode()).hexdigest()`

---

**Q7.** A Flask route calls `requests.get(user_supplied_url)` with no validation. An attacker submits `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. The vulnerability is:

- A) `A03 Injection` — the URL is concatenated into a query.
- B) `A07 Authentication Failures` — the route does not require login.
- C) `A10 Server-Side Request Forgery (SSRF)` — the server is coerced to fetch a URL it should not, in this case the AWS instance metadata service, leaking IAM credentials.
- D) `A09 Logging Failures` — the fetch is not logged.

---

**Q8.** Which of the following best describes the danger of `pickle.loads(request.get_data())`?

- A) The pickle format is verbose and wastes bandwidth.
- B) Pickle is a code-execution format; loading attacker-controlled bytes is equivalent to running attacker code on the server. The vulnerability is `A08:2021 Software and Data Integrity Failures`, CWE-502 Deserialisation of Untrusted Data.
- C) Pickle is slower than JSON.
- D) Pickle is not compatible with `gunicorn`.

---

**Q9.** A team writes a custom JWT verifier:

```python
header = jwt.get_unverified_header(token)
payload = jwt.decode(token, KEY, algorithms=[header["alg"]])
```

The bug is:

- A) The verifier trusts the *token* to declare its algorithm; a forged token with `alg=none` (or with HS/RS confusion) bypasses signature verification. The fix is to pin the algorithm: `algorithms=["HS256"]`.
- B) `jwt.decode` is deprecated; use `jwt.decode_legacy`.
- C) The key should be passed as a string, not bytes.
- D) The verifier should also accept the algorithm `MD5`.

---

**Q10.** Which of the following logs is most appropriate for a successful login event, per the OWASP Logging Cheat Sheet?

- A) `log.info(f"login {request.form['username']} {request.form['password']}")`
- B) `log.info(f"login successful for {username}")` (string concatenation)
- C) `log.info("auth.login", username=username, source_ip=request.remote_addr, result="success", user_agent=request.user_agent.string)` (structured JSON, with a stable event name, no password)
- D) No log — successful logins are not security-relevant.

---

## Answer key

<details>
<summary>Click to reveal</summary>

1. **B** — `A01:2021 Broken Access Control` was promoted to #1 in the 2021 edition. OWASP's published reasoning: 94% of applications tested had some form of broken access control; the *average* incidence rate was 3.81%; severity-when-found is high. The combination of high incidence and high severity put it at the top.
2. **C** — Argon2id is the OWASP Password Storage Cheat Sheet's recommended default for new systems (2021, reaffirmed in 2025-RC drafts). Bcrypt is acceptable but with caveats (≥72-byte input cap); md5 and sha256 are both wrong for password storage — md5 because it is cryptographically broken, sha256 because it is *fast*, which is the wrong property for password hashing.
3. **B** — `A03:2021 Injection`, CWE-89 SQL Injection. The fix is parameter binding: `cur.execute(sql, params)` with a `?` placeholder. The driver sends SQL and values as separate fields on the wire.
4. **C** — IDOR. `@login_required` is *authentication* (who you are); the route is missing *authorisation* (whether `current_user` owns `order_id`). The fix is to scope the query: `Order.query.filter_by(id=order_id, user_id=current_user.id).first()`.
5. **C** — `A05:2021 Security Misconfiguration`. The reasoning, per OWASP's 2021 introduction: XXE is fundamentally a parser-configuration vulnerability — the parser is willing to resolve external entities when the application has no need.
6. **C** — `secrets.token_urlsafe(32)`. The `secrets` module is backed by `os.urandom` (cryptographic) and produces 256 bits of entropy in URL-safe base64. The others are predictable: `random` is not cryptographic; `time.time()` is observable; `uuid1` includes a MAC address and a timestamp.
7. **C** — SSRF (CWE-918). The attack target `169.254.169.254` is the AWS instance metadata service; on IMDSv1, an unauthenticated request returns IAM credentials. The mitigation stack: URL allow-list, IP-range validation rejecting RFC 1918 + loopback + link-local + reserved, redirect-off, IMDSv2 at the cloud layer, egress firewall at the network layer.
8. **B** — `pickle.loads` is RCE. The pickle stream can construct any Python object including by calling arbitrary callables via `__reduce__`. The rule: never `pickle.loads` data you did not `pickle.dumps` yourself in the same trust boundary. Across a boundary, use JSON with a validated schema, or msgpack, or protobuf.
9. **A** — The "algorithm confusion" class. The verifier accepts whatever algorithm the token declares; a forged token with `alg=none` (no signature required) or `alg=HS256` against an RS256-issued service (the public key, which is *public*, is used as the HMAC secret) bypasses verification. The fix: pin the algorithm on the verifier — `algorithms=["HS256"]` — so any token with a different `alg` header is rejected outright.
10. **C** — Structured JSON, stable event name (`auth.login`), the user identifier, source IP, result, user agent. Never the password (A09 + privacy). String concatenation logs are queryable only with `grep` and are vulnerable to log injection (CWE-117). No-log (D) is `A09` Logging Failures; auth events are the most-read logs in any incident response.

</details>

If under 7, re-read the lectures. If 9+, you are ready for the [homework](./homework.md) and the [mini-project](./mini-project/README.md).
