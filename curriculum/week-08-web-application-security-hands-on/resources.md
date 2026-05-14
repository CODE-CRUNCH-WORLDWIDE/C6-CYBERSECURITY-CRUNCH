# Week 8 — Resources

Every resource here is **free** and, where possible, a primary source. This is the *hands-on* week; the reading list is shorter than Week 7's and the doing-list is longer. Read the primary materials on each bug class before you exploit it, and re-read the matching OWASP Cheat Sheet before you patch it. The secondary commentary is supplementary only.

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  The tools and payloads referenced below are run only against:      |
|  - the vuln_lab Flask application bundled with this week's          |
|    mini-project starter directory, bound to 127.0.0.1.              |
|                                                                     |
|  Reading about a payload is legal everywhere. Sending a payload     |
|  to a host you are not authorised to touch is a crime in nearly     |
|  every jurisdiction. The reading list below assumes you know the    |
|  difference.                                                        |
+---------------------------------------------------------------------+
```

---

## Primary — the OWASP Top 10 2021 (the spine of the week)

The OWASP Top 10 2021 is the canonical awareness list and the spine that the lab application's eight endpoints are organised around. Every exercise this week maps to one or more of these.

- **OWASP Top 10 2021 (the list and the explanatory pages):** <https://owasp.org/Top10/> — index page.
- **A01 Broken Access Control:** <https://owasp.org/Top10/A01_2021-Broken_Access_Control/> — the most-prevalent category in 2021's data. IDOR and missing function-level authorization are the two flavours we exploit.
- **A02 Cryptographic Failures:** <https://owasp.org/Top10/A02_2021-Cryptographic_Failures/> — renamed from "Sensitive Data Exposure" in the 2017 list. Plaintext passwords and weak randomness for session tokens are the two flavours we exploit.
- **A03 Injection:** <https://owasp.org/Top10/A03_2021-Injection/> — folds XSS into the Injection category for the 2021 revision. SQLi, XSS (reflected and stored), and command injection are the flavours we exploit.
- **A04 Insecure Design:** <https://owasp.org/Top10/A04_2021-Insecure_Design/> — new category in 2021. We touch this conceptually when discussing the password-reset-via-security-question pattern.
- **A05 Security Misconfiguration:** <https://owasp.org/Top10/A05_2021-Security_Misconfiguration/> — Flask `debug=True`, verbose error pages, default credentials.
- **A06 Vulnerable and Outdated Components:** <https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/> — discussed in the lecture, not exploited in the lab (the lab pins Flask and ships current packages; the discussion belongs in Week 11 supply-chain).
- **A07 Identification and Authentication Failures:** <https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/> — no rate limit on login, predictable tokens, weak reset flow.
- **A08 Software and Data Integrity Failures:** <https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/> — insecure deserialization via `pickle.loads`.
- **A09 Security Logging and Monitoring Failures:** <https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/> — the lab logs nothing useful to start with; the patched version adds structured logging.
- **A10 Server-Side Request Forgery:** <https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/> — new top-level category in 2021. The mock metadata server in the starter exists to demonstrate this.

---

## Primary — PortSwigger Web Security Academy (the lab catalogue)

PortSwigger's Web Security Academy is free, the labs are graded automatically, and the topic coverage matches the OWASP Top 10 almost one-to-one. Every category we touch this week has at least one matching academy lab. Do at least one academy lab per category before you exploit the same category against vuln_lab; the academy lab is the controlled introduction, vuln_lab is the put-it-together exercise.

- **Academy index:** <https://portswigger.net/web-security/all-topics> — the topic tree.
- **All labs list:** <https://portswigger.net/web-security/all-labs> — the labs grouped by topic.
- **SQL Injection:** <https://portswigger.net/web-security/sql-injection> — and the labs under <https://portswigger.net/web-security/sql-injection/lab>.
- **Cross-Site Scripting (XSS):** <https://portswigger.net/web-security/cross-site-scripting> — reflected, stored, DOM-based; labs at <https://portswigger.net/web-security/cross-site-scripting/lab>.
- **Access Control Vulnerabilities (including IDOR):** <https://portswigger.net/web-security/access-control> — and the labs at <https://portswigger.net/web-security/access-control/lab>.
- **Server-Side Request Forgery (SSRF):** <https://portswigger.net/web-security/ssrf> — with the labs at <https://portswigger.net/web-security/ssrf/lab>.
- **Authentication Vulnerabilities:** <https://portswigger.net/web-security/authentication> — labs at <https://portswigger.net/web-security/authentication/lab>.
- **Insecure Deserialization:** <https://portswigger.net/web-security/deserialization> — labs at <https://portswigger.net/web-security/deserialization/lab>.
- **HTTP Request Smuggling:** <https://portswigger.net/web-security/request-smuggling> — labs at <https://portswigger.net/web-security/request-smuggling/lab>. (Smuggling is conceptual-only in vuln_lab; the academy labs are the right place to actually pull it off.)
- **CORS misconfiguration:** <https://portswigger.net/web-security/cors> — labs at <https://portswigger.net/web-security/cors/lab>. (Out of scope for the lab; useful prerequisite for Week 9.)
- **Information Disclosure:** <https://portswigger.net/web-security/information-disclosure> — labs at <https://portswigger.net/web-security/information-disclosure/lab>. (Relevant to A05 Security Misconfiguration.)
- **OS Command Injection:** <https://portswigger.net/web-security/os-command-injection> — labs at <https://portswigger.net/web-security/os-command-injection/lab>.

---

## Primary — the OWASP Cheat Sheet Series (the patch guides)

When you patch a bug, the OWASP Cheat Sheet for that class is the highest-density, lowest-cost guide to the right fix. Every patch in `exercises/SOLUTIONS.md` cites the matching cheat sheet.

- **Cheat Sheet index:** <https://cheatsheetseries.owasp.org/> — the table of contents.
- **SQL Injection Prevention:** <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> — parameterized queries, stored procedures, escaping rules, whitelist input validation.
- **Cross Site Scripting Prevention:** <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> — context-aware output encoding, the "Output Encoding Rules" table.
- **DOM-based XSS Prevention:** <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>.
- **Content Security Policy:** <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html> — the canonical CSP guidance.
- **Server-Side Request Forgery Prevention:** <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>.
- **Authentication:** <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>.
- **Authorization:** <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>.
- **Session Management:** <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>.
- **Password Storage:** <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html> — Argon2id, bcrypt, scrypt, PBKDF2; what passes muster in 2026.
- **Deserialization:** <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>.
- **HTTP Security Response Headers:** <https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html>.
- **REST Security:** <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>.
- **Logging:** <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>.
- **Input Validation:** <https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html>.

---

## Primary — the OWASP Web Security Testing Guide (WSTG)

WSTG is the methodology document that pairs with the Top 10 awareness list. Week 7 cited Chapter 2 (Information Gathering); this week we cite the testing chapters.

- **WSTG v4.2 root:** <https://owasp.org/www-project-web-security-testing-guide/v42/> — the whole guide.
- **WSTG Chapter 4 — Web Application Security Testing:** <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/> — the index of testing categories.
- **WSTG § 4.5 Authorization Testing:** <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/> — IDOR, function-level authorization.
- **WSTG § 4.6 Session Management Testing:** <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/>.
- **WSTG § 4.7 Input Validation Testing:** <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/> — SQLi, XSS, command injection, SSRF.

---

## Primary — CWE and CVE

Every finding in the report cites a CWE and at least one CVE.

- **CWE root:** <https://cwe.mitre.org/> — the Common Weakness Enumeration.
- **CWE Top 25 Most Dangerous Software Weaknesses (2024):** <https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html> — the latest list; the 2025 list will replace it when published.
- **CWE-1003 — "Weaknesses for Simplified Mapping of Published Vulnerabilities":** <https://cwe.mitre.org/data/definitions/1003.html> — the canonical view CVE numbering authorities use to map CVEs to a CWE.
- **Selected CWE entries relevant to this week:**
  - **CWE-22** Path Traversal: <https://cwe.mitre.org/data/definitions/22.html>.
  - **CWE-77** Command Injection: <https://cwe.mitre.org/data/definitions/77.html>.
  - **CWE-78** OS Command Injection: <https://cwe.mitre.org/data/definitions/78.html>.
  - **CWE-79** Cross-site Scripting: <https://cwe.mitre.org/data/definitions/79.html>.
  - **CWE-89** SQL Injection: <https://cwe.mitre.org/data/definitions/89.html>.
  - **CWE-200** Information Exposure: <https://cwe.mitre.org/data/definitions/200.html>.
  - **CWE-256** Plaintext Storage of a Password: <https://cwe.mitre.org/data/definitions/256.html>.
  - **CWE-287** Improper Authentication: <https://cwe.mitre.org/data/definitions/287.html>.
  - **CWE-306** Missing Authentication for Critical Function: <https://cwe.mitre.org/data/definitions/306.html>.
  - **CWE-307** Improper Restriction of Excessive Authentication Attempts: <https://cwe.mitre.org/data/definitions/307.html>.
  - **CWE-330** Use of Insufficiently Random Values: <https://cwe.mitre.org/data/definitions/330.html>.
  - **CWE-338** Use of Cryptographically Weak Pseudo-Random Number Generator: <https://cwe.mitre.org/data/definitions/338.html>.
  - **CWE-352** Cross-Site Request Forgery (CSRF): <https://cwe.mitre.org/data/definitions/352.html>.
  - **CWE-434** Unrestricted Upload of File with Dangerous Type: <https://cwe.mitre.org/data/definitions/434.html>.
  - **CWE-502** Deserialization of Untrusted Data: <https://cwe.mitre.org/data/definitions/502.html>.
  - **CWE-639** Authorization Bypass Through User-Controlled Key (IDOR): <https://cwe.mitre.org/data/definitions/639.html>.
  - **CWE-918** Server-Side Request Forgery (SSRF): <https://cwe.mitre.org/data/definitions/918.html>.

- **CVE Program:** <https://www.cve.org/> — the canonical CVE registry.
- **NIST NVD:** <https://nvd.nist.gov/> — the National Vulnerability Database; CVE plus CVSS plus CPE mapping.

### Real-world CVEs that match each bug class in the lab (cite at least one per finding in the report)

- **SQLi:** **CVE-2017-9805** (Apache Struts 2 REST plugin, XStream deserialization that yields SQLi-equivalent RCE); **CVE-2019-7256** (Linear eMerge SQL injection). Browse NVD for "SQL injection" in any recent year and pick from hundreds.
- **XSS (stored):** **CVE-2023-2825** (GitLab path traversal that chains to stored XSS); **CVE-2023-29489** (cPanel reflected XSS).
- **IDOR:** **CVE-2021-22192** (GitLab IDOR allowing access to private snippets); **CVE-2022-31876** (Microweber CMS IDOR).
- **SSRF:** **CVE-2021-26855** (Microsoft Exchange "ProxyLogon" — SSRF as the first link in the chain); **CVE-2019-8451** (Atlassian Jira SSRF).
- **Insecure Deserialization:** **CVE-2017-5638** (Apache Struts 2 OGNL injection / deserialization, the Equifax-breach CVE); **CVE-2017-9805** (Struts REST plugin XStream).
- **Command Injection:** **CVE-2014-6271** (Shellshock); **CVE-2021-41773** (Apache HTTP Server path traversal + RCE on `mod_cgi`-enabled servers).
- **Authentication Failures (predictable tokens):** **CVE-2008-0166** (Debian OpenSSL PRNG seed disaster — every key generated on Debian for two years was predictable).

The lab's exploit walk-throughs cite the closest real-world analogue for each finding; the report you ship as the mini-project should cite at least one real CVE per finding.

---

## Primary — Burp Suite and OWASP ZAP

The two intercepting proxies that bracket every web-app engagement.

### Burp Suite Community

- **Burp Suite Community download:** <https://portswigger.net/burp/communitydownload>.
- **Burp Suite documentation root:** <https://portswigger.net/burp/documentation> — the official docs.
- **"Getting started with Burp Suite Community Edition":** <https://portswigger.net/burp/documentation/desktop/getting-started>.
- **Installing the Burp CA certificate:** <https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate> — the one step learners most often skip and then complain Burp does not work on HTTPS sites.
- **Burp Proxy:** <https://portswigger.net/burp/documentation/desktop/tools/proxy>.
- **Burp Repeater:** <https://portswigger.net/burp/documentation/desktop/tools/repeater>.
- **Burp Intruder (Community Edition is rate-limited; that is fine for the lab):** <https://portswigger.net/burp/documentation/desktop/tools/intruder>.
- **Burp Comparer and Decoder:** <https://portswigger.net/burp/documentation/desktop/tools/comparer> and <https://portswigger.net/burp/documentation/desktop/tools/decoder>.

### OWASP ZAP

- **ZAP download:** <https://www.zaproxy.org/download/>.
- **ZAP documentation root:** <https://www.zaproxy.org/docs/>.
- **"Getting started" walkthrough:** <https://www.zaproxy.org/docs/desktop/start/>.
- **ZAP Baseline Scan (the CI-friendly mode):** <https://www.zaproxy.org/docs/docker/baseline-scan/>.
- **ZAP Full Scan:** <https://www.zaproxy.org/docs/docker/full-scan/>.
- **ZAP API:** <https://www.zaproxy.org/docs/api/>.
- **ZAP daemon mode (`-cmd`, `-daemon`):** <https://www.zaproxy.org/docs/desktop/cmdline/>.

---

## Primary — Mozilla Developer Network (HTTP and CSP reference)

MDN is the canonical reference for HTTP semantics and security headers. It is free, well-maintained, and primary.

- **MDN HTTP root:** <https://developer.mozilla.org/en-US/docs/Web/HTTP>.
- **HTTP request methods:** <https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods>.
- **HTTP status codes:** <https://developer.mozilla.org/en-US/docs/Web/HTTP/Status>.
- **HTTP headers index:** <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers>.
- **Content Security Policy (CSP) overview:** <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>.
- **CSP header reference:** <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy>.
- **`script-src` directive:** <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src>.
- **`Strict-Transport-Security`:** <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security>.
- **`X-Content-Type-Options`:** <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options>.
- **`X-Frame-Options`:** <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options>.
- **`Referrer-Policy`:** <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy>.
- **`Set-Cookie` and the cookie attributes (`HttpOnly`, `Secure`, `SameSite`):** <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>.

---

## Primary — request smuggling research

Smuggling is conceptual-only in this week's lab but is one of the most important modern web-app classes. The canonical research is free.

- **James Kettle, *HTTP Desync Attacks: Request Smuggling Reborn* (2019 PortSwigger / USENIX):** <https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn>.
- **James Kettle, *HTTP/2: The Sequel is Always Worse* (2021):** <https://portswigger.net/research/http2>.
- **PortSwigger's request smuggling academy topic:** <https://portswigger.net/web-security/request-smuggling>.
- **OWASP HTTP request smuggling primer:** <https://owasp.org/www-community/attacks/HTTP_Response_Splitting>.

---

## Primary — Flask security guidance

The lab runs on Flask 3.x. Flask publishes a short, primary, security guide.

- **Flask documentation:** <https://flask.palletsprojects.com/en/stable/>.
- **Flask security considerations:** <https://flask.palletsprojects.com/en/stable/web-security/>.
- **Flask sessions:** <https://flask.palletsprojects.com/en/stable/quickstart/#sessions> — and the deeper *securecookie* internals at <https://flask.palletsprojects.com/en/stable/api/#sessions>.
- **Jinja autoescaping:** <https://jinja.palletsprojects.com/en/stable/api/#autoescaping> — the default in Flask templates and the thing that prevents XSS *if you do not bypass it with `Markup` or `|safe`*.
- **Werkzeug debugger pin protection:** <https://werkzeug.palletsprojects.com/en/stable/debug/> — read the security note about why `debug=True` is not for production.

---

## Primary — Python security and stdlib references

- **Python `subprocess` (the safe replacement for `os.system`):** <https://docs.python.org/3/library/subprocess.html> — pay attention to the "Security Considerations" section.
- **Python `sqlite3` (the parameterized-query API):** <https://docs.python.org/3/library/sqlite3.html> — see "How to use placeholders to bind values in SQL queries."
- **Python `secrets` (the right module for tokens):** <https://docs.python.org/3/library/secrets.html> — replaces `random` for security-sensitive randomness.
- **Python `pickle` (the documentation that says, in the second sentence, "do not unpickle data received from an untrusted or unauthenticated source"):** <https://docs.python.org/3/library/pickle.html>.
- **Python `hashlib` and `hmac`:** <https://docs.python.org/3/library/hashlib.html> and <https://docs.python.org/3/library/hmac.html>.
- **Python `urllib.parse` (for SSRF allow-list parsing):** <https://docs.python.org/3/library/urllib.parse.html>.

---

## Primary — CISA, NIST, and government guidance

- **CISA Known Exploited Vulnerabilities (KEV) catalogue:** <https://www.cisa.gov/known-exploited-vulnerabilities-catalog> — CVEs CISA knows are actively exploited; every CVE you cite in the report should be checked against KEV.
- **NIST SP 800-218 — Secure Software Development Framework (SSDF):** <https://csrc.nist.gov/publications/detail/sp/800-218/final>.
- **NIST SP 800-95 — Guide to Secure Web Services:** <https://csrc.nist.gov/publications/detail/sp/800-95/final>.

---

## Primary — legal frame (the same statutes from Week 7, restated)

Read the Week 7 legal-frame primary sources if you have not already. The statutes below are unchanged from Week 7 — they govern Week 8 in exactly the same way.

- **18 U.S.C. § 1030 — Computer Fraud and Abuse Act:** <https://www.law.cornell.edu/uscode/text/18/1030>.
- **Computer Misuse Act 1990 (UK):** <https://www.legislation.gov.uk/ukpga/1990/18/contents>.
- **Directive 2013/40/EU:** <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32013L0040>.
- **DoJ May 2022 charging-policy update:** <https://www.justice.gov/opa/pr/department-justice-announces-new-policy-charging-cases-under-computer-fraud-and-abuse-act>.

Sending an `' OR 1=1 --` payload to a host you do not own is a CFAA / CMA / 2013/40/EU violation. Sending it to vuln_lab on `127.0.0.1` is the exercise.

---

## Secondary — practitioner notebooks and writeups

These are useful supplements but should be read *after* the primary references above, not before.

- **HackTricks (Carlos Polop):** <https://book.hacktricks.xyz/> — the *Pentesting Web* section covers every category we touch.
- **PayloadsAllTheThings (swisskyrepo):** <https://github.com/swisskyrepo/PayloadsAllTheThings> — payload index by vulnerability class. Bookmark.
- **SecLists (Daniel Miessler):** <https://github.com/danielmiessler/SecLists> — wordlists for authentication brute-forcing, fuzzing, and discovery.
- **Common Payloads (PortSwigger):** payloads referenced inside the Web Security Academy material. The academy lab solutions are the canonical "right" payloads for each lab.

---

## Supporting — references for the report and the regression script

- **Python `pytest`:** <https://docs.pytest.org/> — for the optional pytest version of `regression_test.py`.
- **`requests` library:** <https://requests.readthedocs.io/en/latest/> — used in the regression script.
- **`http.server` from the stdlib:** <https://docs.python.org/3/library/http.server.html> — what the lab's mock metadata server is built on.
- **`argparse`:** <https://docs.python.org/3/library/argparse.html> — for the regression script's CLI.
- **`logging`:** <https://docs.python.org/3/library/logging.html> — for the patched lab's structured logs.

---

## How to choose what to read this week

You cannot read every linked resource in the seven days of Week 8. The recommended budget is:

1. **The OWASP Top 10 2021 entry for each of A01, A02, A03, A05, A07, A08, A10.** Read in full. Total: roughly 90 minutes.
2. **One PortSwigger Web Security Academy lab in each of the SQL Injection, XSS, IDOR, SSRF, and Deserialization topics.** The labs are graded; do the easiest in each topic, then come back to the harder ones during the stretch hours. Budget per lab: 30-60 minutes.
3. **The matching OWASP Cheat Sheet for each bug class.** Read in full as you patch each class. Total: 60-90 minutes.
4. **MDN's Content Security Policy overview and `Content-Security-Policy` header reference.** Read in full before writing the CSP in Challenge 1. Total: 30 minutes.
5. **Burp's "Getting Started" and "Installing the CA certificate" pages,** and ZAP's "Getting Started" walkthrough. Read both before Exercise 1. Total: 30 minutes.
6. **One James Kettle smuggling paper** (the 2019 USENIX version is the canonical entry point). Read in full for context; smuggling is on the quiz. Total: 60-90 minutes.
7. **Skim the rest** as you need them during the exercises and mini-project.

Total reading budget: roughly 8-10 hours, spread across Mon-Wed. The exercises and the mini-project consume the remainder of the week.
