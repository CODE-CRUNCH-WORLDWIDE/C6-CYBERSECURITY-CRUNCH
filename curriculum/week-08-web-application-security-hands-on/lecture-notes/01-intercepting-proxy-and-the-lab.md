# Lecture 1 — The Intercepting Proxy and the Lab

> *Before you exploit a single bug, you need two things on your workstation: a web application you are allowed to attack, and a tool that lets you see and modify the HTTP traffic going to it. The web application is the vuln_lab Flask app shipped with this week's mini-project starter. The tool is an intercepting HTTP proxy — Burp Suite Community or OWASP ZAP. This lecture is about why the intercepting proxy exists, what it does at the protocol level, how to install and configure it without poisoning your daily browsing, and how the eight vulnerable endpoints of vuln_lab map onto the OWASP Top 10 2021. By the end of this lecture you will have Burp or ZAP intercepting traffic to `127.0.0.1:5000` and you will have run your first curl against the lab.*

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  This lecture's setup steps configure an intercepting proxy on      |
|  your laptop. The proxy will be capable of intercepting and         |
|  modifying any HTTP/HTTPS traffic from a browser you have           |
|  configured to use it. The intended use is the vuln_lab on          |
|  127.0.0.1 - and only that. Do not browse to your bank, your        |
|  email, or any other site you care about while the proxy is on      |
|  and the proxy CA is installed; even though doing so is             |
|  technically legal because it is your own browser, it is a          |
|  privacy-hygiene mistake. Use a dedicated browser profile.          |
+---------------------------------------------------------------------+
```

This lecture covers:

- **What an intercepting proxy is** at the HTTP and TLS layer, and what the proxy CA certificate's job is.
- **Burp Suite Community Edition** versus **OWASP ZAP**: the trade-offs and the case for owning both.
- **Installing and configuring Burp** (with Firefox), including the CA certificate import.
- **Installing and configuring ZAP**, the open-source alternative.
- **The vuln_lab architecture**: the Flask 3.x application, the SQLite database, the mock metadata server, and the eight vulnerable endpoints.
- **A first end-to-end test**: start the lab, configure the proxy, send one request, observe the interception.
- **A short tour of the OWASP Top 10 2021** as they map to the eight endpoints — we cover this only enough to orient you for Lecture 2, which is the exploit walkthrough proper.

---

## 1. The intercepting proxy at the protocol layer

An **HTTP proxy** is a process that sits between a client (a browser, `curl`, your Python script) and a server. Plain HTTP proxies have existed since the 1990s. An **intercepting proxy** adds two capabilities:

1. **TLS interception.** The proxy presents its own TLS certificate to the client and establishes a separate TLS connection to the server. To make this work without the browser throwing a "certificate invalid" error on every request, you install the proxy's **CA certificate** as a trusted root in the browser (or in the operating system's trust store, with caveats below).
2. **Read/write inspection of the in-flight traffic.** The proxy parses every HTTP request and response, displays them in a UI, and lets you pause and modify either before it forwards them on.

The capability is essentially what `mitmproxy` calls **"man-in-the-middle for your own traffic, by your own choice."** Burp and ZAP are the two heavyweight implementations of this idea for the application-security workflow. Both ship a Java GUI, a command-line interface, a scripting API, and an extension system. Both can record, replay, fuzz, and report.

### 1.1 Why not just use `curl` and the browser's dev-tools?

You can, for many things. Modern browsers' developer tools (Chromium DevTools, Firefox's Network panel) show every request and response, including headers and body, and let you "Edit and resend" a request. For about 80% of the work in this week's lab, `curl` and DevTools are sufficient.

The remaining 20% is what justifies the proxy:

- **Repeatable replay** of the *exact* bytes of a request, including any session cookies, CSRF tokens, and quirky body encodings, without re-typing them.
- **Intruder-style fuzzing** of a single request parameter across a wordlist, with the results table and filterable by response length / status / time.
- **Cross-tool history**: every request you have ever sent to the target, indexed by URL, method, status, and length, browsable later.
- **Out-of-band detection** for SSRF-class bugs (Burp Collaborator in Professional; Interactsh and similar in Community).
- **Automated scans** (ZAP's spider and active scan; Burp Pro's scanner; Community's manual workflow).
- **The mental affordance** of always having the last 100 requests one tab away. You will, in practice, work differently with a proxy on than with one off.

### 1.2 The CA certificate, and why it is the most-skipped step

The proxy's TLS interception works by presenting a *forged* server certificate for every host the browser connects to. The forgery is signed by the proxy's own CA. For the browser to accept the forgery without warning, the browser (or the OS) must trust the proxy's CA.

The CA trust is the entire security model of TLS interception. **Anyone who has the proxy's CA private key can man-in-the-middle every HTTPS connection your browser makes** while the trust is installed. The implications:

- **Use a dedicated browser profile** for proxy work. Firefox makes this easy: `firefox --profile-manager` creates a new profile in two clicks. Chromium has a similar profile system. The profile that trusts the proxy CA is the profile you use for the lab and nothing else.
- **Never install the proxy CA into the OS trust store on a machine you also use for personal browsing.** The OS trust store is global; once trusted, the certificate is trusted by every browser, every command-line tool, every program. Stick to per-browser trust.
- **Uninstall or rotate the CA when you are done.** Burp regenerates a new CA on each fresh install; ZAP exposes the CA in Options → Network → Server Certificates and lets you generate a new one. Treat the CA as a session credential, not a permanent install.

For `127.0.0.1:5000` work specifically, the issue is moot because the lab runs over plain HTTP — there is no TLS to intercept, so the CA is not in play. We still install it so that the workflow generalises to HTTPS targets you will hit later. In the lab, the CA's only effect is that when you accidentally browse to `https://example.com` through the proxy, the browser will not warn you. The CA-trust hygiene above is for that case.

---

## 2. Burp Suite Community versus OWASP ZAP

Both tools achieve the same thing. The differences are operational.

### 2.1 Burp Suite Community

**Burp Suite** is PortSwigger's commercial product. The **Community Edition** is free for individual use. The functional differences from Burp Professional are:

- **Intruder is rate-limited** in Community (one request per second on free Intruder runs, no payload position recommendations from the AI features). This is *fine* for the rate caps a responsible RoE imposes anyway, and adequate for the lab.
- **No active scanner.** Community has no automated vulnerability scanner. The manual workflow — Proxy, Repeater, Intruder, Decoder, Comparer — is the entire offering. The scanner is the single largest reason consultancies pay for Burp Pro.
- **No Collaborator client.** Out-of-band detection requires a third-party service (Interactsh from ProjectDiscovery, for instance).
- **No saved sessions.** Community discards state on restart.
- **No extension marketplace.** Community supports extensions but does not get the Pro-only ones.

For learning, for CTFs, and for the work in this lab, Community is sufficient. For client-engagement work, Pro is standard. C6 teaches the workflow on Community; the muscle memory transfers directly to Pro if you upgrade later.

### 2.2 OWASP ZAP

**OWASP ZAP** (formerly "Zed Attack Proxy") is the open-source alternative. ZAP has been an OWASP Flagship project since 2010. Functionally:

- **Active and passive scanners are free.** This is the single largest reason to install ZAP even if you have Burp.
- **Spider and AJAX spider are free.** Both are useful for the lab when you want a "what endpoints exist?" snapshot.
- **The baseline and full scans, in Docker form,** are designed for CI/CD. The packaged scripts (`zap-baseline.py`, `zap-full-scan.py`) are what most modern shops bolt into their pipelines.
- **The API and daemon mode.** ZAP exposes a full HTTP API and can run headlessly (`zap.sh -daemon`); Burp's equivalent (the REST API in Burp Pro) is paid.
- **The Heads Up Display** lets ZAP overlay its findings into the browser without requiring the user to flip to the ZAP GUI. Niche but excellent.

The reason to learn both: Burp's manual workflow is the cleaner experience for a skilled hunter chasing a specific bug, ZAP's automated scanner is the cleaner experience for "what bugs does this app have that I haven't thought to look for." Most working application-security engineers have both installed and reach for one or the other depending on the question.

### 2.3 Which to use this week

Use whichever is easier to install on your laptop. The exercises specify both paths; the mini-project requires you to run at least one **automated** scan with ZAP (because Burp Community has no scanner) and at least one **manual** intercept-and-modify session with either tool. If you can only install one, install ZAP — the lack of an automated scanner in Burp Community is a real gap when you are first learning.

---

## 3. Installing Burp Suite Community (Firefox path)

### 3.1 Install Burp itself

1. Download the Community installer from <https://portswigger.net/burp/communitydownload>. The installer is a JAR-wrapping native installer per platform; both work. The Linux `.sh` installer drops Burp under `/opt/BurpSuiteCommunity/` by default.
2. Run the installer. Accept the defaults.
3. Launch Burp. The first run prompts for a project type (Temporary project is the only option in Community) and the configuration (Burp defaults).
4. You arrive at the Burp dashboard with a default project. The Proxy listener defaults to `127.0.0.1:8080`.

### 3.2 Configure a dedicated Firefox profile

```bash
# macOS or Linux
firefox --profile-manager &
```

In the profile manager, click "Create Profile," name it `burp-only`, and launch it. Close your other Firefox windows so you can tell the two profiles apart by window decoration. (On macOS you may need to use the `-no-remote` flag: `/Applications/Firefox.app/Contents/MacOS/firefox -P burp-only -no-remote &`.)

### 3.3 Configure the Firefox proxy

In the burp-only profile:

1. Open `about:preferences#general`.
2. Scroll to **Network Settings** at the bottom; click **Settings...**.
3. Select **Manual proxy configuration**.
4. **HTTP Proxy**: `127.0.0.1`. **Port**: `8080`.
5. Check **Also use this proxy for HTTPS**.
6. Click **OK**.

### 3.4 Install the Burp CA certificate

1. With Burp running and Firefox configured, browse in Firefox to <http://burpsuite>. Burp serves a small page on its proxy port that hands you the CA.
2. Click "CA Certificate" to download `cacert.der`.
3. In Firefox, open `about:preferences#privacy`. Scroll to **Certificates**; click **View Certificates...**. Click the **Authorities** tab. Click **Import...**. Pick `cacert.der`. Check both **Trust this CA to identify websites** and (if you wish) **Trust this CA to identify email users**.

Verify by browsing to <https://example.com> in the burp-only profile. The site should load. In Burp's Proxy → HTTP history tab, you should see the request to `example.com`. If you see a TLS error, the CA import did not take; redo step 3.4.

### 3.5 Confirm intercept works

In Burp, click Proxy → Intercept and toggle **Intercept is on**. In Firefox (burp-only), browse to <http://example.com>. Burp will pause and show you the request. Click **Forward** to release it. The response will pause too; **Forward** again. The page loads in Firefox. Toggle **Intercept is off** so you can browse without pausing each request, but **HTTP history** continues to record everything.

---

## 4. Installing OWASP ZAP

### 4.1 Install ZAP itself

1. Download the installer from <https://www.zaproxy.org/download/>. Cross-platform; Java application; needs JRE 11+ which most laptops have.
2. Run the installer. On launch you are prompted whether to persist the session ("Yes, and I want to specify the name" / "No, I do not want to persist this session right now"). For lab work, "No, do not persist" keeps things tidy.
3. ZAP's Proxy listener defaults to `127.0.0.1:8080` (the same port Burp uses by default). **Run only one at a time** unless you change the port in one of them.

### 4.2 Configure Firefox to use ZAP

Same procedure as § 3.2 and § 3.3 above, with a profile named `zap-only` if you also have a `burp-only` profile.

### 4.3 Install the ZAP CA

In ZAP, open Tools → Options → Network → Server Certificates. Click **Generate** (if no CA exists yet) and then **Save** to write `owasp_zap_root_ca.cer` to disk. Import that file into Firefox per § 3.4.

### 4.4 Confirm intercept works

In ZAP, Tools → Options → Network → Local Servers/Proxies. Confirm the listener is `127.0.0.1:8080`. Browse from Firefox; entries appear in ZAP's Sites tree. The intercept toggle is the green "play/pause" buttons in the toolbar.

---

## 5. The vuln_lab application: architecture and layout

The lab's source lives in `mini-project/starter/` of this week. The structure:

```text
mini-project/starter/
├── app.py                 # the Flask application, all 8 vulnerable endpoints
├── init_db.py             # creates lab.db, populates users and invoices
├── metadata_server.py     # mock cloud-metadata server for SSRF demo
├── regression_test.py     # the regression script that re-tries every exploit
├── requirements.txt       # Flask, requests (the only deps)
├── templates/
│   ├── base.html          # the layout template
│   ├── index.html         # the public home
│   ├── login.html         # the login form (A07 target)
│   ├── search.html        # the search results (reflected XSS, A03)
│   ├── comments.html      # the comments page (stored XSS, A03)
│   ├── profile.html       # the profile page (IDOR target, A01)
│   ├── admin.html         # the admin page (missing-authz target, A01)
│   ├── import.html        # the import-profile page (pickle, A08)
│   └── fetch.html         # the fetch-image page (SSRF, A10)
└── README.md              # the lab's own README, separate from the week README
```

### 5.1 The application loop

`app.py` is a single Flask 3.x application that wires routes to view functions. The route table:

| Path                          | Method | Bug class                       | OWASP   | CWE      |
|-------------------------------|--------|---------------------------------|---------|----------|
| `/`                           | GET    | (none — public home)            | —       | —        |
| `/login`                      | POST   | No rate limit; plaintext pwd    | A07/A02 | 307/256  |
| `/profile?id=<n>`             | GET    | IDOR (any user's profile)       | A01     | 639      |
| `/admin/users`                | GET    | Missing function-level authz    | A01     | 306      |
| `/search?q=<...>`             | GET    | Reflected XSS                   | A03     | 79       |
| `/comments` (POST)            | POST   | Stored XSS                      | A03     | 79       |
| `/lookup?name=<...>`          | GET    | SQL injection                   | A03     | 89       |
| `/thumbnail?file=<...>`       | GET    | Command injection (`os.system`) | A03     | 78       |
| `/import-profile`             | POST   | Insecure deserialization        | A08     | 502      |
| `/fetch-image?url=<...>`      | GET    | SSRF                            | A10     | 918      |

Eight bug classes in eight endpoints. The endpoint count (eight) was chosen deliberately so each endpoint corresponds to one walkthrough section in Lecture 2 and one exploit step in Exercise 2.

### 5.2 The database

`init_db.py` creates `lab.db` (a SQLite file) with two tables:

- **`users`** — id, username, password (plaintext! that is the A02 bug), email, role.
- **`invoices`** — id, owner_id, amount, description.

The seed data: three users (`alice/password123`, `bob/letmein`, `admin/admin`), each with two invoices. The IDOR exploit reads `bob`'s invoices while logged in as `alice`. The default-credentials exploit logs in as `admin` with `admin`.

### 5.3 The mock metadata server

`metadata_server.py` is a 40-line script that uses `http.server` from the stdlib to serve a tiny page on `127.0.0.1:8080`. The page mimics the AWS Instance Metadata Service endpoint (<http://169.254.169.254/latest/meta-data/iam/security-credentials/>) which, on a real AWS host, returns the host's IAM role credentials and is the canonical SSRF prize.

We do not, of course, hit `169.254.169.254` from the lab. We hit `127.0.0.1:8080`. The mock server returns:

```json
{
    "AccessKeyId": "ASIA-NOT-A-REAL-KEY-LAB-ONLY",
    "SecretAccessKey": "fake-secret-key-for-the-lab-only-do-not-cite",
    "Token": "lab-only-fake-token-do-not-cite"
}
```

The point of the mock is to make the SSRF exploit complete-able offline — no real cloud metadata service involved. The full exercise instructions stress this: the URL of interest in production AWS is `http://169.254.169.254/latest/meta-data/`, but you never, in this lab, send a request anywhere except your own loopback.

### 5.4 The regression test

`regression_test.py` is a Python script that, given a running lab on `127.0.0.1:5000` and a running metadata server on `127.0.0.1:8080`, attempts each of the eight exploits and prints PASS or FAIL for each. Run it against the vulnerable lab: all eight should PASS (the exploits succeed). Run it against your patched lab: all eight should FAIL (the patches work).

The regression script is the verification artifact for the mini-project. You ship the script unchanged; you change `app.py` until the script reports eight FAILs.

---

## 6. First end-to-end run

The complete first run takes about ten minutes.

### 6.1 Create a virtual environment and install Flask

```bash
cd path/to/week-08-web-application-security-hands-on/mini-project/starter/
python3 -m venv .venv
source .venv/bin/activate   # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt` pins Flask and `requests`. Both are pure-Python; the install takes a few seconds.

### 6.2 Initialise the database

```bash
python3 init_db.py
```

The script creates `lab.db` in the starter directory and prints "lab.db created with N users and M invoices."

### 6.3 Run the metadata server (in a second terminal)

```bash
python3 metadata_server.py
```

It binds to `127.0.0.1:8080` and prints "Mock metadata server listening on 127.0.0.1:8080."

### 6.4 Run the lab (in a third terminal)

```bash
python3 app.py
```

Flask prints its usual startup banner and binds to `127.0.0.1:5000`. The lab's `app.py` deliberately sets `app.run(host="127.0.0.1", port=5000, debug=True)` — `debug=True` is the A05 misconfiguration that we exploit and then patch out. **Do not change the bind address from `127.0.0.1`.**

### 6.5 Send a first request with curl

```bash
curl -v http://127.0.0.1:5000/
```

You should see a `200 OK` and the homepage HTML.

### 6.6 Send the same request through the proxy

In the proxy-configured Firefox profile, browse to <http://127.0.0.1:5000/>. The request appears in Burp's Proxy → HTTP history or ZAP's Sites tree. Click into the request to read it; click into the response to read it. This is the workflow you will use for every exploit in Lecture 2 and Exercise 2.

---

## 7. The OWASP Top 10 2021 in the lab (orientation only)

Lecture 2 walks each bug class in detail with payloads. For now, an orienting one-paragraph note on each:

### 7.1 A01 Broken Access Control

The lab's IDOR endpoint is `/profile?id=<n>`. Logged in as `alice` (user id 1), browse to `/profile?id=2` and you see `bob`'s profile. The check the endpoint *should* have made — "is the requested id the same as the logged-in user's id, or is the logged-in user an admin?" — is missing. The lab's missing-function-level-authorization endpoint is `/admin/users`, which a non-admin can hit and which returns the full user list including the plaintext password column. Both bugs are in CWE-862 / CWE-639 / CWE-306 territory.

### 7.2 A02 Cryptographic Failures

The `users.password` column is plaintext. `init_db.py` populates it with the literal strings `password123`, `letmein`, `admin`. The login handler compares the submitted password against this column with `==`. Patching this is half a day's work in any real application; in the lab it is a fifteen-minute fix to `argon2-cffi` plus a migration step. We also generate session tokens with `random.random()` instead of `secrets.token_urlsafe()`; this is CWE-330 / CWE-338, and the fix is two lines.

### 7.3 A03 Injection

Three flavours in the lab:

- **`/lookup?name=<...>`** builds a SQL query by string concatenation. `name=' OR 1=1 --` returns every row.
- **`/search?q=<...>`** echoes the query parameter into the response template using `Markup(q)`, which bypasses Jinja's autoescape. `q=<script>alert(1)</script>` fires.
- **`/thumbnail?file=<...>`** passes the `file` parameter to `os.system("convert " + file + " /tmp/out.png")`. `file=foo; id` runs `id` after the failed convert.

Three different fixes — `sqlite3` placeholders, `escape()` plus removing the `Markup` wrapper, `subprocess.run([list], shell=False)`.

### 7.4 A05 Security Misconfiguration

Flask is started with `debug=True`, which exposes the Werkzeug interactive debugger on any unhandled exception. The debugger is gated by a "pin" but the pin is derived from machine-stable inputs and historically has been brute-forceable. Either way, the lab's `/debug-trigger` endpoint deliberately raises an exception. Browse to it in the debug-enabled lab and the debugger gives you a REPL. The patch is to remove `debug=True`. Other misconfigurations: no security headers, default `admin/admin` credentials, verbose error pages.

### 7.5 A07 Identification and Authentication Failures

No rate limit on `/login`. You can submit `admin/admin`, then `admin/password`, then `admin/123456`, then continue indefinitely. The mini-project includes a small Intruder-style brute-force exercise (capped at 100 attempts, rate-limited by the lab anyway once you patch it). Session tokens generated with `random.random()` (predictable) instead of `secrets.token_urlsafe()`. Password reset via security question, with the question and answer stored in plaintext.

### 7.6 A08 Software and Data Integrity Failures

`/import-profile` accepts a base64-encoded `pickle.loads(...)` payload. The pickle byte stream can encode `__reduce__` returns that execute arbitrary code. The lab's exploit constructs a payload that calls `os.system('id > /tmp/pwned')`. The patch swaps pickle for JSON and validates the JSON schema.

### 7.7 A10 Server-Side Request Forgery

`/fetch-image?url=<...>` calls `requests.get(url)` and proxies the response. The exploit points `url=http://127.0.0.1:8080/latest/meta-data/iam/security-credentials/` and exfiltrates the mock metadata server's fake credentials. The patch is an allow-list of permitted hostnames plus a DNS-rebinding-resistant resolve-then-validate step.

---

## 8. The workflow you will use all week

The standard workflow for each bug:

1. **Read** the OWASP Top 10 entry for the category. Five minutes.
2. **Read** the OWASP Cheat Sheet for the patch. Five minutes.
3. **Read** the lab's vulnerable code for the endpoint. Three minutes.
4. **Exploit** with `curl` first (no proxy needed) so you understand the request shape. Ten minutes.
5. **Re-exploit** with the proxy. Capture the request, replay through Repeater, modify until you understand each input's role. Ten minutes.
6. **Patch** the code. Apply the change in `app.py`. Re-run the lab. Twenty minutes.
7. **Regression**. Re-run the exploit; confirm it now fails. Five minutes.
8. **Document** the finding in your portfolio: command line, payload, before-code, after-code, references. Ten minutes.

Total per bug: about an hour. Eight bugs: about a day's focused work. The mini-project schedule budgets exactly this.

---

## 9. Common setup failures

If you cannot get past the proxy setup or the lab will not start, these are the failures the C6 cohort has seen historically:

1. **Lab fails to start with `address already in use`.** Something else is on `:5000`. Either kill the other process (`lsof -nP -i :5000`) or change the bind port in `app.py` (the regression script reads the port from `LAB_BASE_URL` env var, so this is safe).
2. **Curl returns nothing and the lab terminal shows no request.** You hit the wrong port. The lab is on `:5000`; the proxy is on `:8080`. `curl http://127.0.0.1:5000/` not `127.0.0.1:8080`.
3. **Burp shows the request but the browser shows "connection refused."** The lab is not running, or you hit a different port. Restart the lab.
4. **Firefox warns about an untrusted certificate at `https://`.** You did not import the proxy CA. Re-do § 3.4 or § 4.3.
5. **`pip install -r requirements.txt` fails because `Flask` is already installed system-wide and a version conflict.** Use the venv; that is what venvs exist for.
6. **`init_db.py` fails because `lab.db` already exists.** Delete it: `rm lab.db && python3 init_db.py`.

---

## 10. A note on emojis, screenshots, and write-up style

Your portfolio write-ups for this week should match the C6 register: sober, editorial, no emojis, no breathless exclamation. Screenshots of Burp or ZAP are *encouraged* in the mini-project report — they make the work legible — but treat them as evidence, not decoration. Each screenshot has a one-sentence caption that identifies the request, the timestamp, and the bug class.

The mini-project's grading rubric includes a "professional register" line item. The point is not stylistic conformity for its own sake; it is that the write-up is what you hand a hiring manager, and hiring managers read register the way they read code: any single hint that you do not understand the gravity of what you are demonstrating will cost you the role.

---

## 11. Where this lecture goes

Lecture 2 is the **exploit walkthrough**: bug-by-bug, with the full curl commands, the Burp Repeater steps, and the expected response. By the end of Lecture 2 you will have exploited every endpoint in vuln_lab.

Lecture 3 is the **defence walkthrough**: bug-by-bug, the patches, then the layered Content Security Policy, then the request-smuggling conceptual treatment and the regression-testing workflow. By the end of Lecture 3 you have the patched lab.

Exercise 1 is the *do the setup* exercise from this lecture. Exercise 2 follows Lecture 2. Exercise 3 (the runnable Python script) is the regression-test workflow from Lecture 3. The mini-project is the synthesis.

---

## 12. Required reading for Lecture 2

Before opening Lecture 2:

- **OWASP Top 10 2021 entries** for A01, A03, A07, A08, A10. Read each in full (each entry is two screens of text).
- **PortSwigger Academy "What is SQL injection?" topic page**: <https://portswigger.net/web-security/sql-injection>. Read the topic page (not the labs, yet — those come during the exercises).
- **PortSwigger Academy "What is cross-site scripting?" topic page**: <https://portswigger.net/web-security/cross-site-scripting>. Read.
- **OWASP Cheat Sheet "SQL Injection Prevention"**: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>. Read the "Defense Option 1: Prepared Statements" section, which is the entire fix for the lab.

The total reading is about 60 minutes. Do it before Lecture 2; the lecture assumes the OWASP entries have been read.
