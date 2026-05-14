# Exercise 1 — Stand Up the Lab and Configure the Proxy

**Estimated time:** 60 minutes.

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  This exercise installs an intercepting proxy on your laptop and    |
|  binds a deliberately-vulnerable web application to 127.0.0.1:5000. |
|  The application is intended to be exploited; the proxy is          |
|  intended to mediate that exploitation. Both run only on your own   |
|  loopback. Do not change the bind address. Do not run the proxy    |
|  against any other host. Use a dedicated browser profile and        |
|  uninstall the proxy CA when you are finished for the week.         |
+---------------------------------------------------------------------+
```

The goal of this exercise is the smallest possible end-to-end happy path: by the end you have the lab running, the proxy capturing traffic, and one captured request modified and replayed. The exploitation proper is Exercise 2.

---

## Part 1 — Stand up the lab (15 min)

1. Open a terminal. `cd` to the mini-project starter directory:

    ```bash
    cd path/to/week-08-web-application-security-hands-on/mini-project/starter/
    ```

2. Create and activate a virtual environment:

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate    # on Windows: .venv\Scripts\activate
    ```

3. Install the dependencies:

    ```bash
    pip install -r requirements.txt
    ```

4. Initialise the database:

    ```bash
    python3 init_db.py
    ```

    The script prints "lab.db created with 3 users and 6 invoices." A `lab.db` file appears in the directory.

5. In a second terminal (in the same starter directory, with the venv activated), start the mock metadata server:

    ```bash
    source .venv/bin/activate
    python3 metadata_server.py
    ```

    It prints "Mock metadata server listening on 127.0.0.1:8080." Leave it running.

6. In a third terminal (in the same directory, venv activated), start the lab:

    ```bash
    source .venv/bin/activate
    python3 app.py
    ```

    Flask's startup banner appears. Leave it running.

7. From a fourth terminal (no venv needed for this), confirm the lab responds:

    ```bash
    curl -s http://127.0.0.1:5000/
    ```

    You should see the homepage HTML.

**Checkpoint.** Three processes running: metadata server, lab, and your terminal. The `curl` returned a 200 with HTML.

---

## Part 2 — Choose your proxy (5 min)

You can use either Burp Suite Community or OWASP ZAP. Pick one for this exercise; you will install the other later in the week.

- **Burp Suite Community** — <https://portswigger.net/burp/communitydownload>. Requires a free PortSwigger account.
- **OWASP ZAP** — <https://www.zaproxy.org/download/>. Fully open-source, no account.

If you cannot decide, install ZAP. ZAP has a built-in automated scanner that Burp Community lacks, which makes it the better single tool for the lab.

---

## Part 3 — Configure the proxy and the browser (20 min)

### Path A — Burp Suite Community

1. Launch Burp. Accept the defaults (Temporary project, Burp defaults).
2. Confirm the Proxy listener: Burp → Proxy → Options. The default listener is `127.0.0.1:8080`. The lab itself uses `127.0.0.1:5000`, so the two do not collide.
3. Create a dedicated Firefox profile for proxy work:

    ```bash
    # macOS
    /Applications/Firefox.app/Contents/MacOS/firefox -P
    # Linux
    firefox -P
    # Windows
    firefox.exe -P
    ```

    Create a profile named `burp-only`. Launch it. Close any other Firefox windows.

4. In the burp-only Firefox profile, open `about:preferences#general` → Network Settings → Manual proxy configuration. Set HTTP Proxy to `127.0.0.1`, Port to `8080`. Check "Also use this proxy for HTTPS." Click OK.

5. Install the Burp CA. In the burp-only Firefox, browse to <http://burpsuite>. Click "CA Certificate" to download `cacert.der`.

6. In Firefox `about:preferences#privacy` → Certificates → View Certificates → Authorities → Import. Pick `cacert.der`. Check "Trust this CA to identify websites." Click OK.

7. Verify by browsing to <https://example.com> in the burp-only profile. The site loads without certificate warnings. In Burp → Proxy → HTTP history, you see the `GET /` request.

### Path B — OWASP ZAP

1. Launch ZAP. When prompted, select "No, I do not want to persist this session right now."
2. ZAP's default proxy is `127.0.0.1:8080`. Confirm under Tools → Options → Network → Local Servers/Proxies.
3. Create a Firefox profile named `zap-only` as in Burp Path A step 3.
4. Configure Firefox to use proxy `127.0.0.1:8080` as in Burp Path A step 4.
5. Install the ZAP CA. In ZAP → Tools → Options → Network → Server Certificates, click "Generate" (if no CA exists) and "Save" to write `owasp_zap_root_ca.cer`.
6. Import the cert into Firefox as in Burp Path A step 6.
7. Verify by browsing to <https://example.com> in the zap-only profile. The site loads. ZAP's Sites tree shows the request.

---

## Part 4 — Send a first request through the proxy (10 min)

1. In the proxy-configured Firefox profile, browse to <http://127.0.0.1:5000/>. The lab's homepage loads. The proxy captures the request.

2. **In Burp:** Proxy → HTTP history. Click the `GET /` row. The request and response panes show the full HTTP exchange.

    **In ZAP:** Sites tree → `http://127.0.0.1:5000` → `GET:/`. The request and response panes show the exchange.

3. Right-click the request:

    - **Burp:** "Send to Repeater." Switch to the Repeater tab. The request is editable on the left; click "Send" to fire it and see the response on the right.
    - **ZAP:** "Open/Resend with Request Editor." A modal opens with the request; click "Send" to fire it and see the response.

4. Modify a header in the request. Change `User-Agent: Mozilla/5.0 ...` to `User-Agent: c6-lab`. Re-send. The response is identical (the lab does not care about User-Agent) but you have proved you can intercept, modify, and replay.

---

## Part 5 — Capture and modify mid-flight (10 min)

This is the "intercept" workflow proper.

1. **Burp:** Proxy → Intercept tab → toggle "Intercept is on."
   **ZAP:** click the green "Set break on all requests and responses" button in the toolbar (the icon looks like a hand or break-symbol; the tooltip says "Set Break on all Requests and Responses").

2. In Firefox, browse to <http://127.0.0.1:5000/lookup?name=alice>. The browser hangs — the proxy has paused the request.

3. **Burp:** the request appears in the Intercept tab, editable. Change `name=alice` to `name=bob`. Click "Forward."
   **ZAP:** the request appears in the Break tab, editable. Change `name=alice` to `name=bob`. Click the "Submit and step to next request or response" button.

4. The lab returns Bob's row. The browser displays the page. The proxy continues to the response, also paused; forward it again. The page renders.

5. Toggle "Intercept is off" so future requests pass without pausing. The HTTP history still records everything.

**Checkpoint.** You can pause a request, modify it, and forward it. You can replay any previous request from history. You have the entire proxy workflow under your hands.

---

## Part 6 — Verify the lab's eight endpoints respond (10 min)

A quick smoke test of every endpoint. Run from your fourth terminal, no proxy needed for this part:

```bash
# A03 SQLi target (benign query)
curl -s "http://127.0.0.1:5000/lookup?name=alice" | head -c 200; echo

# A03 reflected XSS target (benign query)
curl -s "http://127.0.0.1:5000/search?q=python" | head -c 200; echo

# A03 stored XSS target (benign post + read)
curl -s -X POST "http://127.0.0.1:5000/comments" -d "body=hello"
curl -s "http://127.0.0.1:5000/comments" | head -c 200; echo

# A03 command injection target (benign filename)
curl -s "http://127.0.0.1:5000/thumbnail?file=test.png"; echo

# A01 IDOR target (requires login first; we just check the redirect for now)
curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:5000/profile?id=1"

# A05 misconfiguration: debug-trigger
curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:5000/debug-trigger"

# A07 auth target
curl -s -X POST "http://127.0.0.1:5000/login" -d "username=alice&password=password123" \
     -o /dev/null -w "%{http_code}\n"

# A08 deserialization target (empty blob; expect failure)
curl -s -X POST "http://127.0.0.1:5000/import-profile" -d "blob=" \
     -o /dev/null -w "%{http_code}\n"

# A10 SSRF target (benign loopback URL)
curl -s "http://127.0.0.1:5000/fetch-image?url=http://127.0.0.1:8080/health"; echo
```

Every endpoint should respond. Errors here mean the lab is not running correctly or the metadata server is not up.

---

## Submission

Commit a `notes/exercise-01.md` containing:

1. Which proxy you installed (Burp Community or ZAP), and why.
2. A screenshot or paste of one captured request from the HTTP history.
3. The output of your smoke-test of the eight endpoints (from Part 6).
4. One sentence on what surprised you about the setup, if anything.

---

## Common failures

- **`pip install -r requirements.txt` fails with "ERROR: Could not find a version that satisfies the requirement Flask==3.x":** your `pip` is too old, or your Python is too old. `python3 --version` should be 3.11+. `pip install --upgrade pip` then retry.
- **`init_db.py` fails with "table users already exists":** you ran it twice. `rm lab.db && python3 init_db.py`.
- **`address already in use` when starting `app.py`:** something else is on port 5000. `lsof -nP -i :5000` to find it; kill it or change `app.py`'s port.
- **Proxy CA installed but HTTPS sites still warn:** you imported into the wrong tab in Firefox. The cert goes under Authorities, not Servers. Re-import.
- **Burp/ZAP shows requests but the browser shows "connection refused":** the proxy is talking to a server that is not running. Confirm `app.py` and `metadata_server.py` are both up.

---

## What you learned

- How to stand up a Flask 3.x app, an `http.server`-based mock metadata server, and a SQLite database from the stdlib in under five minutes.
- How an intercepting proxy works at the protocol layer, and how to configure Firefox to use one without poisoning your daily browsing.
- The Repeater / Request Editor workflow for replaying captured requests with modifications.
- The Intercept workflow for pausing and modifying requests mid-flight.

Exercise 2 takes the same workflow and uses it to exploit each of the eight endpoints in turn.
