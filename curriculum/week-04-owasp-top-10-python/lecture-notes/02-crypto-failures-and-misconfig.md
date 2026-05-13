# Lecture 2 — Cryptographic Failures, Misconfiguration, and Insecure Design

> *Cryptography is the part of the system where almost-right is wrong. Configuration is the part where the defaults are the test you fail by not running. Design is the part where the bug exists before any line of code is written.*

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The vulnerable code in this lecture is for the lab app and your    │
│  own machine only. Do not deploy any of these snippets to a public  │
│  service. Do not run any of the attack payloads against a service   │
│  you do not operate.                                                │
└─────────────────────────────────────────────────────────────────────┘
```

This lecture covers three more of the ten OWASP Top 10 2021 categories:

- **`A02:2021 Cryptographic Failures`** (renamed from `A03:2017 Sensitive Data Exposure`, because the *cause* — bad crypto choices — is the actionable framing).
- **`A05:2021 Security Misconfiguration`** (was `A06:2017`, broadened in 2021 to absorb the former `A04:2017 XML External Entities` category).
- **`A04:2021 Insecure Design`** (new in 2021; an explicit category for *the bug that is the architecture*, distinct from *the bug that is the code*).

The order in the lecture mirrors how the categories actually surface in code review: you find the crypto failure in the line of code, the misconfiguration in the deployment, and the insecure design only after you have lifted your eyes from both and asked the harder question.

---

## 1. `A02:2021 Cryptographic Failures`

### 1.1 What OWASP says

*"The first thing is to determine the protection needs of data in transit and at rest. For example, passwords, credit card numbers, health records, personal information, and business secrets require extra protection, particularly if that data falls under privacy laws, e.g., EU's General Data Protection Regulation (GDPR), or regulations, e.g., financial data protection such as PCI Data Security Standard (PCI DSS). For all such data ... encrypt all sensitive data at rest. Encrypt all data in transit with secure protocols such as TLS with forward secrecy (FS) ciphers, cipher prioritisation by the server, and secure parameters."* (Top 10 2021, `A02:2021`, condensed.)

CWE families:

- **CWE-327** Use of a Broken or Risky Cryptographic Algorithm
- **CWE-329** Generation of Predictable IV with CBC Mode
- **CWE-330** Use of Insufficiently Random Values
- **CWE-331** Insufficient Entropy
- **CWE-310** Cryptographic Issues (parent)
- **CWE-319** Cleartext Transmission of Sensitive Information

The list is short and the failure modes are well-catalogued. The Python developer's job, *in almost all cases*, is to **not write any cryptography** — to use a library that ships safe defaults, and to pick the named construction that fits the use case.

### 1.2 The decision tree

For the application engineer, the questions are:

1. *Am I storing a password?* — Use **Argon2id** (`argon2-cffi`). This is the only password case. Covered in Lecture 1.
2. *Am I encrypting a small piece of data for myself, with a key only I hold?* — Use **`cryptography.fernet.Fernet`**. AES-128-CBC with HMAC-SHA256, plus a versioned token format. The "I am encrypting a session token / a CSRF token / a small secret" case.
3. *Am I encrypting data that someone else will decrypt with a different key?* — Use **`cryptography.hazmat`'s `AES-GCM`** with a per-message random 96-bit nonce. Or, if you need a higher-level construction with a stable nonce-handling story, **`PyNaCl`**'s `SecretBox` (XSalsa20-Poly1305).
4. *Am I encrypting data for a recipient whose public key I have?* — Use **`cryptography`'s `X25519`** key exchange to derive a shared key, then `AES-GCM`. Or **`PyNaCl`**'s `Box`.
5. *Am I signing data for verification by a known-public-key recipient?* — Use **`cryptography`'s `Ed25519`** for signing. JWTs are signed; prefer **`Authlib`** or **`PyJWT`** with `EdDSA` or `ES256`; avoid `HS256` for cross-service tokens, avoid `none`, and reject `alg=none` explicitly on the verifier side.
6. *Am I generating a token / nonce / API key?* — Use **`secrets.token_urlsafe(32)`** (256 bits of entropy, URL-safe base64). Never `random.random`, never `time.time`-derived.

There are exactly two libraries you should default to:

- **`cryptography`** (the PyCA library; `pip install cryptography`). Active, audited, the obvious default for new code.
- **`PyNaCl`** (Python binding for libsodium; `pip install pynacl`). Also active, also audited, narrower surface, harder to misuse.

Avoid: **`pycrypto`** (unmaintained since 2014, replaced by `pycryptodome`); **`pycryptodome`** is usable but ships modes (ECB, CBC without authentication, raw RSA-OAEP) that invite misuse — prefer `cryptography` for new code; **any blog post that builds AES yourself**.

### 1.3 The textbook A02 — `md5` for passwords

Covered in Lecture 1 §3.2; the canonical A02 failure is using a fast cryptographic hash for password storage. Even if `md5` is replaced with `sha256`, `sha256` is *also* the wrong answer — fast hashes are exactly what an attacker with a leaked database wants. Argon2id is slow on purpose.

### 1.4 ECB mode, or the "Tux penguin" failure

**Vulnerable (`ecb_bad.py`):**

```python
from Crypto.Cipher import AES  # pycryptodome

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    # ECB: each 16-byte block is encrypted independently. Identical plaintext
    # blocks produce identical ciphertext blocks. The Tux penguin remains visible.
    cipher = AES.new(key, AES.MODE_ECB)
    # Padding (PKCS#7) omitted for brevity; the mode itself is the bug.
    return cipher.encrypt(plaintext)
```

ECB mode is correct *only* when the plaintext is a single 16-byte block of random data — i.e. essentially never in application code. The visible failure mode is the famous "ECB Tux" image; the practical failure mode in web apps is that ciphertext leaks structure of the plaintext.

**Fixed (`aesgcm_good.py`):**

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    # AES-GCM: AEAD construction; per-message random 96-bit nonce; authenticated.
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    # Caller stores nonce + ct together. Convention: prepend nonce.
    return nonce + ct

def decrypt(key: bytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, associated_data)
```

Three properties of AES-GCM that matter:

1. **AEAD** (Authenticated Encryption with Associated Data). The decrypt call raises if the ciphertext or the associated-data has been tampered with. Without authentication, a CBC ciphertext is silently corruptible (padding-oracle attacks; bit-flipping).
2. **Per-message random nonce.** Reusing a nonce with the same key is catastrophic in GCM — the attacker recovers the key. The `os.urandom(12)` call is not optional.
3. **Associated data.** A field that is *authenticated but not encrypted*. Use for context (user ID, message version) to bind the ciphertext to its intended use.

### 1.5 The Fernet shortcut

For "I just want to encrypt a small piece of data with a key only I hold":

```python
from cryptography.fernet import Fernet

key = Fernet.generate_key()      # 32 random bytes, URL-safe base64-encoded
f = Fernet(key)
token = f.encrypt(b"secret data")  # versioned, timestamped, authenticated
plaintext = f.decrypt(token)        # raises InvalidToken on tamper or expiry
```

Fernet is AES-128-CBC + HMAC-SHA256 + version byte + timestamp, with a well-defined token format. It is the "do not think about modes" default. Use it for anything from CSRF tokens to encrypted session cookies to small secrets at rest.

For key rotation, `MultiFernet([new_key, old_key])` decrypts with either and encrypts with the first.

### 1.6 TLS — what to verify, what not to disable

Almost all application-level TLS failures are *certificate verification disabled* under a deadline.

**Vulnerable (`tls_bad.py`):**

```python
import requests
# Disables certificate verification entirely. Every man-in-the-middle is now valid.
r = requests.get("https://api.example.com/data", verify=False)
```

**Fixed:**

```python
import requests
# Default behaviour: verify against the system CA bundle.
r = requests.get("https://api.example.com/data")

# If the server uses a private CA, point at its bundle:
r = requests.get("https://internal.example/", verify="/etc/ssl/internal-ca.pem")
```

`verify=False` is correct *only* in unit tests with a self-signed certificate generated for the test, and even then a fixed test CA is better. Never in production.

The deeper TLS rules:

- **TLS 1.2 or 1.3 only.** Disable 1.0 and 1.1 at the server. (Browsers no longer offer them.)
- **Modern ciphersuites** with **forward secrecy** (ECDHE-anything). Mozilla's "Intermediate" or "Modern" presets are the configuration target: <https://ssl-config.mozilla.org/>.
- **HSTS** at the reverse proxy: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`. After the first visit, browsers refuse plain-HTTP fallback.
- **Certificate Transparency** monitoring (e.g. crt.sh, Cert Spotter) for your own domains. Detects rogue certificate issuance against your name.

### 1.7 JWT — the recurring crypto failure

JWTs are signed bearer tokens; the signature is the entire security boundary. The recurring failures:

- **`alg=none`.** A JWT with `{"alg": "none"}` and no signature *is a valid JWT* by some buggy verifier implementations. Always assert `alg` matches an expected value on the verifier side.
- **`HS256` / `RS256` confusion.** A library that accepts whichever algorithm the token specifies will, given an `HS256` token signed with the *public key* of an `RS256` keypair (because the public key is publicly known), accept the forged token. Always pin the algorithm at verification.
- **Long-lived tokens without revocation.** A JWT with a 30-day `exp` and no server-side revocation is a credential you cannot un-mint when leaked. Pair with a short-TTL access token (5-15 minutes) and a server-tracked refresh token.

**Fixed (`jwt_good.py`), with `PyJWT`:**

```python
import jwt
from datetime import datetime, timedelta, timezone

SECRET = b"..."  # for HS256; for RS256/EdDSA, a public/private key pair

def issue(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
        "iss": "https://auth.example.com",
        "aud": "api.example.com",
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")

def verify(token: str) -> dict:
    # Pin algorithm. Pin issuer. Pin audience. Verify expiry.
    return jwt.decode(
        token, SECRET,
        algorithms=["HS256"],
        issuer="https://auth.example.com",
        audience="api.example.com",
        options={"require": ["exp", "iat", "sub", "iss", "aud"]},
    )
```

Note `algorithms=["HS256"]` is a *list of acceptable algorithms*, not "the algorithm to use." `PyJWT` will reject any token whose header `alg` is not in the list — closing the `alg=none` and HS/RS confusion classes in one go.

### 1.8 Detection

- **`bandit -r .`** flags `verify=False`, weak hashes, ECB mode, `random` for security purposes.
- **`semgrep --config p/owasp-top-ten`** ships rules for many of these patterns.
- **TLS configuration scanners**: `testssl.sh`, `sslyze`, Mozilla Observatory — automated, free, run them in CI against staging.

---

## 2. `A05:2021 Security Misconfiguration`

### 2.1 What OWASP says

*"The application might be vulnerable if the application is: missing appropriate security hardening across any part of the application stack, or improperly configured permissions on cloud services. Unnecessary features are enabled or installed (e.g., unnecessary ports, services, pages, accounts, or privileges). Default accounts and their passwords are still enabled and unchanged. Error handling reveals stack traces or other overly informative error messages to users. The latest security features are disabled or not configured securely. The security settings in the application servers, application frameworks, libraries, databases, etc., are not set to secure values."* (Top 10 2021, `A05:2021`, condensed.)

OWASP folded the former `A04:2017 XML External Entities (XXE)` into `A05:2021 Security Misconfiguration` in 2021, because XXE *is* a parser misconfiguration — the XML parser is willing to resolve external entities when the application has no need for it to.

CWE families:

- **CWE-16** Configuration
- **CWE-260** Password in Configuration File
- **CWE-611** Improper Restriction of XML External Entity Reference
- **CWE-1004** Sensitive Cookie Without 'HttpOnly' Flag
- **CWE-1275** Sensitive Cookie with Improper SameSite Attribute

### 2.2 `DEBUG = True` in production

The simplest A05 — and shipped weekly.

**Vulnerable (`config_bad.py`):**

```python
# settings.py
DEBUG = True
ALLOWED_HOSTS = ["*"]
SECRET_KEY = "django-insecure-DO-NOT-USE"
```

`DEBUG = True` in Django renders an interactive traceback on any error, including the local variables at each frame. Local variables include database connection strings, secret keys, and user input. `ALLOWED_HOSTS = ["*"]` accepts any `Host` header, enabling cache-poisoning and password-reset host-header attacks.

**Fixed:**

```python
# settings.py
import os

DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = os.environ["DJANGO_ALLOWED_HOSTS"].split(",")
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
```

Plus, separately, *fail closed*: if the environment variables are not set, the app refuses to start. Do not provide a "safe default" for `SECRET_KEY` in production; a missing key should be a `KeyError` at import.

### 2.3 Security headers

The right set of HTTP response headers makes large classes of attack ineffective even when the underlying bug exists. The baseline (Flask + `flask-talisman`, or Django + `django-csp` + `SECURE_*` settings):

```python
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(
    app,
    content_security_policy={
        "default-src": "'self'",
        "img-src": ["'self'", "data:"],
        "style-src": ["'self'", "'unsafe-inline'"],  # tighten if you can
        "script-src": ["'self'"],
        "object-src": "'none'",
        "frame-ancestors": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'",
    },
    strict_transport_security=True,
    strict_transport_security_max_age=63072000,  # 2 years
    strict_transport_security_include_subdomains=True,
    strict_transport_security_preload=True,
    session_cookie_secure=True,
    session_cookie_http_only=True,
    session_cookie_samesite="Lax",
    referrer_policy="strict-origin-when-cross-origin",
)
```

What each header buys you:

- **CSP** — bounds the damage of XSS. A reflected XSS injects `<script>` but the browser refuses to execute it because the CSP allows scripts only from `'self'`.
- **HSTS** — closes the plain-HTTP downgrade window. After the first visit, the browser refuses HTTP.
- **`X-Content-Type-Options: nosniff`** (Talisman ships this) — closes MIME-confusion XSS.
- **`X-Frame-Options` / `frame-ancestors`** — closes clickjacking.
- **`Referrer-Policy`** — limits cross-origin Referer leakage.
- **Cookie flags** (`Secure`, `HttpOnly`, `SameSite`) — restrict where the session cookie may go.

Test your headers with the **Mozilla Observatory** (<https://observatory.mozilla.org/>) — free, useful, and the grade is a credible audit signal.

### 2.4 CORS — the easy thing to get wrong

CORS is the browser's same-origin-bypass mechanism. Misconfigured, it gives any origin the ability to read authenticated responses from your API.

**Vulnerable (`cors_bad.py`):**

```python
from flask import Flask, make_response

app = Flask(__name__)

@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp
```

The spec forbids `Allow-Origin: *` with `Allow-Credentials: true`; some servers honour it anyway and the result is full cross-origin authenticated reads.

**Fixed:**

```python
from flask_cors import CORS

app = Flask(__name__)
CORS(
    app,
    origins=["https://app.example.com"],
    supports_credentials=True,
    max_age=600,
)
```

Default to a tight allow-list of origins. If you genuinely need wildcard CORS, you do not need credentials with it.

### 2.5 The XXE residue

XXE survives from 2017 as a sub-class of A05. The vulnerable Python pattern uses `lxml` or the stdlib `xml.*` modules on attacker-controlled input.

**Vulnerable (`xxe_bad.py`):**

```python
from lxml import etree

def parse(xml_bytes: bytes):
    # Default lxml parser resolves external entities.
    return etree.fromstring(xml_bytes)
```

An attacker submits:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r>&x;</r>
```

— and the parsed tree contains `/etc/passwd`.

**Fixed:**

```python
from defusedxml.lxml import fromstring

def parse(xml_bytes: bytes):
    # defusedxml disables entity expansion and external-DTD loading.
    return fromstring(xml_bytes)
```

`defusedxml` ships drop-in modules for `xml.etree`, `xml.sax`, `xml.dom`, `xml.dom.minidom`, `xmlrpc.server`, `xmlrpc.client`, and `lxml`. Use them by default for any XML you do not 100% control. If you 100% control the XML, you probably do not need XML.

### 2.6 Cloud and host misconfiguration

The cloud-shaped A05 — the cases that produce the biggest headlines:

- **Public S3 / GCS / Azure-Blob buckets.** Default-deny is right; default-allow is what ships the leak. Enable bucket-level "block all public access" and require an explicit per-bucket exception.
- **Default credentials.** Postgres `postgres` / `postgres`. MongoDB without auth. Redis without `requirepass`. Elasticsearch on `0.0.0.0`. Each of these has produced multi-million-record leaks. The fix is a baseline scanner (`prowler` for AWS, `scout-suite` cross-cloud) in your deployment pipeline.
- **IAM roles too broad.** `*:*` on a Lambda's role is shippable; auditable only if you read the role.
- **The metadata service.** `169.254.169.254` is accessible from any process on the instance; combined with SSRF (Lecture 3, `A10`), it leaks credentials. The mitigation is **IMDSv2** on AWS (required-token, hop-limit-1).

### 2.7 Detection

- **Mozilla Observatory** for header grading.
- **`gixy`** for nginx-config linting: <https://github.com/yandex/gixy>.
- **`prowler`** for AWS: <https://github.com/prowler-cloud/prowler>.
- **Snyk Cloud, Steampipe, Cloud Custodian** for broader cloud config posture.
- **Periodic "what's exposed?"** scans of your own perimeter — `nmap -sV` from outside, or `shodan` searches for your IP space.

---

## 3. `A04:2021 Insecure Design`

### 3.1 What OWASP says

*"Insecure design is a broad category representing different weaknesses, expressed as 'missing or ineffective control design.' Insecure design is not the source of all the other Top 10 risk categories. There is a difference between insecure design and insecure implementation. We differentiate between design flaws and implementation defects for a reason, they have different root causes and remediation."* (Top 10 2021, `A04:2021`.)

A04 was new in 2021. The category names the case where *the architecture is wrong*, not the code. A perfectly implemented password-reset flow that emails a non-expiring link to a non-rate-limited address is securely *coded* and insecurely *designed*.

CWE families:

- **CWE-209** Generation of Error Message Containing Sensitive Information
- **CWE-256** Plaintext Storage of a Password (design choice)
- **CWE-501** Trust Boundary Violation
- **CWE-522** Insufficiently Protected Credentials
- **CWE-840** Business Logic Errors

### 3.2 Examples of design failures

**Password reset by email "magic link," no expiry, no rate limit.** Designed-in failure. The fix is a design fix — short-TTL token, single use, rate-limited, audited.

**"Remember me" cookie that never rotates and never expires.** A pure design choice. Implementation is fine; the design is "a permanent credential lives in browser local storage forever."

**Multi-tenant database without row-level security.** Every query has to remember to add `WHERE tenant_id = ?` and the day a developer forgets, one tenant reads another's data. The design fix is **row-level security at the database layer** (PostgreSQL RLS policies) so that even a forgetful query cannot cross tenants.

**Public file storage where filenames are guessable.** "Hide" via a 40-character random filename — the design fix is *authorisation on the file URL*, not obscurity in the name. (Many products ship the obscurity and then re-learn the lesson.)

**Authentication by knowledge questions.** "What was your first pet's name?" — every modern attacker can look this up. The design fix is to remove the question, not to add more.

**Account recovery via support phone call.** SIM-swap and social-engineering bypass the support agent. Design fix: lock recovery behind out-of-band verification with a high friction floor.

### 3.3 Threat-modelling into the SDLC

The structural answer to A04 is the structural answer of Week 3: threat-model *before* you code. OWASP's framing in the `A04:2021` page is explicit: "Establish and use a secure development lifecycle with AppSec professionals to help evaluate and design security and privacy-related controls."

In practice, for a small team:

1. **Every new feature gets one paragraph** in the design doc titled "What can go wrong?"
2. **Every new feature gets one paragraph** titled "What is the abuse case?"
3. **PR template asks** "If this feature were misused, what is the worst outcome?" The dev fills it in; the reviewer reads it.

These are cheap. They are also frequently skipped, and the bugs from skipping them are the A04 bugs.

### 3.4 The "Did we do a good job?" check

Week 3's fourth Shostack question lives in A04. If a finding in your STRIDE pass cannot be traced to a specific line of vulnerable code, but is real anyway — that finding is A04. Examples:

- "An attacker registers many accounts and uses them to spam the comment system." There is no specific *vulnerability* line; the abuse case is the *absence of a rate limit on registration combined with the absence of cost-to-create on the account*. The fix is a design fix.
- "An attacker who knows a user's email can lock them out of their account by repeatedly entering wrong passwords until lockout." The lockout is *correctly implemented*; the design assumes lockout is purely defensive when it is also offensive against the user. Fix: per-IP back-off rather than per-account lockout; CAPTCHA gate.

### 3.5 The 2025 RC

The 2025 release candidate keeps `A04 Insecure Design` and is expected to strengthen the language around **business-logic abuse** as a sub-class. Track the OWASP page.

---

## 4. Summary

Three more categories. Three classes of fix:

| Category | Vulnerable pattern | Fix |
|---|---|---|
| `A02 Cryptographic Failures` | `md5(pw)`, ECB, `verify=False`, `alg=none` JWT, `random` for secrets | Argon2id for passwords; AES-GCM or Fernet for data; default-verify TLS; pinned-algorithm JWT; `secrets` for tokens |
| `A05 Security Misconfiguration` | `DEBUG=True`, no security headers, `CORS: *` with credentials, XXE-permissive parsers, public buckets, IMDSv1 | Env-based config; Talisman / django-csp; tight CORS allow-list; defusedxml; bucket policies; IMDSv2 |
| `A04 Insecure Design` | Designed-in abuse — non-expiring magic links, recovery by knowledge questions, tenant data with no RLS, "remember me" forever | Threat-model before coding; abuse-case paragraph per feature; row-level security at the DB; tight-TTL recovery flows |

Lecture 3 covers the remaining four categories: A06 (Vulnerable Components), A09 (Logging Failures), A10 (SSRF), A08 (Software and Data Integrity).

---

*Read on to [Lecture 3 — The Rest: Vulnerable Components, Logging, SSRF, Integrity](./03-the-rest-vulnerable-components-logging-ssrf.md).*
