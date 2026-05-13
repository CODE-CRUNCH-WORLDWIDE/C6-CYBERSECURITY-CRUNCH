# Week 4 — Resources

Every resource here is **free** and, where possible, a primary source. The OWASP Top 10 is itself a free, GPL-friendly, community-maintained document; you should treat it as the first reading on every category.

## Primary — the OWASP Top 10 itself

- **OWASP Top 10 2021** (the current published edition at the time of writing): <https://owasp.org/Top10/>
  Each category has its own page with the canonical definition, CWE mappings, example attack scenarios, prevention guidance, and references. Read the page for any category *before* the lecture that covers it.
- **OWASP Top 10 2025** (release candidate / data call in progress at the time of writing): <https://owasp.org/www-project-top-ten/>
  The methodology page (data call, CWE-weighted incidence, community survey for two "forward-looking" categories) is essential reading for understanding *how* the list is built. Track the project page for the final 2025 release.
- **OWASP Top 10 — methodology** (the documented process for selecting and ordering the categories): <https://owasp.org/Top10/A00_2021-Introduction/>
  The 2021 introduction explains why the list is data-driven, what the survey covers, and how categories are merged or split between editions.

## OWASP supporting projects

- **OWASP Application Security Verification Standard (ASVS)** v4.0.3 — the line-itemised checklist of controls a secure application should meet, organised by Level 1 / 2 / 3: <https://owasp.org/www-project-application-security-verification-standard/>
  Use ASVS Level 1 as the closing audit checklist after the Top 10 walkthrough. ASVS section numbers are stable enough to cite in audit reports.
- **OWASP Cheat Sheet Series** — short, dense, practitioner-facing references per topic. The most useful pages for Week 4:
  - <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
- **OWASP Juice Shop** (deliberately vulnerable Node.js shopping app — useful as a comparator to the Python lab; you can run challenges through the same Top 10 lens): <https://owasp.org/www-project-juice-shop/>
- **OWASP WebGoat** (the Java equivalent, with explicit lessons mapped to Top 10 categories): <https://owasp.org/www-project-webgoat/>
- **OWASP ZAP** (free dynamic application security testing proxy; useful for the mini-project as an automated cross-check): <https://www.zaproxy.org/>

## CWE and MITRE

- **MITRE CWE Top 25 (most recent year)** — the weakness-class counterpart to the OWASP Top 10. Every OWASP category maps to one or more CWE IDs: <https://cwe.mitre.org/top25/>
- **MITRE CWE** main site — searchable by CWE-ID: <https://cwe.mitre.org/>
  Key CWEs cited this week:
  - CWE-89 SQL Injection
  - CWE-78 OS Command Injection
  - CWE-79 Cross-Site Scripting
  - CWE-22 Path Traversal
  - CWE-918 Server-Side Request Forgery
  - CWE-502 Deserialization of Untrusted Data
  - CWE-285 Improper Authorisation
  - CWE-287 Improper Authentication
  - CWE-256 Plaintext Storage of a Password
  - CWE-327 Use of a Broken or Risky Cryptographic Algorithm
  - CWE-732 Incorrect Permission Assignment for Critical Resource
  - CWE-1395 Vulnerable Third-Party Component
  - CWE-117 Improper Output Neutralisation for Logs
  - CWE-778 Insufficient Logging
- **MITRE ATT&CK Enterprise** — the techniques most commonly mapped to web vulnerabilities: <https://attack.mitre.org/>
  Key technique IDs cited this week:
  - `T1190` Exploit Public-Facing Application
  - `T1110.004` Brute Force: Credential Stuffing
  - `T1078` Valid Accounts
  - `T1552.001` Unsecured Credentials: Credentials in Files
  - `T1499` Endpoint Denial of Service
  - `T1505.003` Server Software Component: Web Shell

## Python tooling

- **`bandit`** — Python AST-level lint for security smells. Run with `bandit -r .` on any Python project. Source / docs: <https://bandit.readthedocs.io/>
- **`semgrep`** — pattern-matching static analysis with a large free rule registry; the OWASP Top 10 ruleset is `p/owasp-top-ten`. Run `semgrep --config p/owasp-top-ten`. Docs: <https://semgrep.dev/docs/>
- **`pip-audit`** — Python supply-chain vulnerability scanner from PyPA, backed by the OSV database. Run `pip-audit -r requirements.txt`. Source: <https://github.com/pypa/pip-audit>
- **`safety`** — alternative supply-chain scanner; free CLI with a community-curated DB. <https://github.com/pyupio/safety>
- **`cryptography`** — the recommended Python cryptography library; `Fernet`, `AES-GCM`, `X25519` and friends. **Use this, not PyCryptodome, not custom code.** <https://cryptography.io/>
- **`argon2-cffi`** — Argon2id password hashing, the OWASP-recommended default for password storage as of 2021 and reaffirmed in 2025. <https://argon2-cffi.readthedocs.io/>
- **`defusedxml`** — XML parsing without XXE, billion-laughs, or external-DTD attacks. Drop-in for `xml.etree`, `lxml`, etc. <https://github.com/tiran/defusedxml>
- **`PyYAML`** — *use `yaml.safe_load`, never `yaml.load` on untrusted input*. Docs: <https://pyyaml.org/wiki/PyYAMLDocumentation>
- **`requests`**, **`httpx`**, **`urllib3`** — the HTTP client landscape; relevant to A10 (SSRF). Each has different defaults around redirect-following and proxy honouring; check before deploying.
- **`Authlib`** — well-maintained OAuth/OIDC/JWT library for Python; reference implementation for A07 fixes that involve OAuth or OpenID Connect. <https://authlib.org/>
- **`flask-talisman`** — automatic security headers for Flask (CSP, HSTS, etc.); relevant to A05. <https://github.com/GoogleCloudPlatform/flask-talisman>
- **`django-csp`** — the equivalent for Django. <https://django-csp.readthedocs.io/>

## Standards and identity

- **NIST SP 800-63B *Digital Identity Guidelines*** §5 (Authenticator and Verifier Requirements). The reference for password rules, MFA, and authenticator lifetimes. AAL1/AAL2/AAL3 are the levels you should know by ID: <https://pages.nist.gov/800-63-3/sp800-63b.html>
- **NIST SP 800-53 Rev. 5** — federal control catalogue; the controls overlap heavily with ASVS. Cite when the audience is regulated: <https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final>
- **PCI DSS v4.0** — if your service ever touches payment cards, this is the floor. Free with registration at <https://www.pcisecuritystandards.org/>.

## Supply-chain and integrity

- **OSV (Open Source Vulnerabilities) database** — Google-led, schema-defined vulnerability database; backs `pip-audit`: <https://osv.dev/>
- **GitHub Advisory Database** — the source for Dependabot alerts: <https://github.com/advisories>
- **Sigstore / `cosign`** — keyless signing for software artifacts, including Python packages (PEP 740 and follow-ups). Track here: <https://www.sigstore.dev/>
- **The XZ Utils backdoor (CVE-2024-3094)** — the supply-chain incident that shifted the conversation in 2024. Andres Freund's disclosure post: <https://www.openwall.com/lists/oss-security/2024/03/29/4>. Read it; it is the canonical primary source.

## Logging and detection

- **OWASP Logging Cheat Sheet** (the practitioner's quick reference for what to log and what *not* to log): <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
- **Elastic Common Schema (ECS)** — the de-facto field schema for structured security logs: <https://www.elastic.co/guide/en/ecs/current/index.html>
- **The OWASP AppSensor project** — a model for application-layer intrusion detection. Useful as a thinking tool even if you do not adopt it as a framework: <https://owasp.org/www-project-appsensor/>

## Books

- **Bryan Sullivan and Vincent Liu, *Web Application Security: A Beginner's Guide*** (McGraw-Hill, 2011). Dated in the specifics, still the cleanest beginner walkthrough of the *categories* of web vulnerability. Library copy.
- **Dafydd Stuttard and Marcus Pinto, *The Web Application Hacker's Handbook* (2nd ed.)*** (Wiley, 2011). The other foundational text; written by the PortSwigger founders. Library copy.
- **Andrew Hoffman, *Web Application Security: Exploitation and Countermeasures for Modern Web Applications*** (O'Reilly, 2020, 2024 2nd ed.). The most up-to-date single-author book; covers the modern SPA / API surface that the older books predate. Library copy.

## Glossary

| Term | One-line definition |
|------|---------------------|
| **OWASP** | Open Worldwide Application Security Project — the foundation that produces the Top 10, ASVS, the Cheat Sheets, ZAP, Juice Shop, and most of the free practitioner literature for web security. |
| **Top 10** | OWASP's data-driven list of the ten most critical web-application security risks, updated every three to four years. |
| **CWE** | Common Weakness Enumeration — MITRE's catalogue of software weakness *classes* (the underlying mistakes, not the specific vulnerabilities). |
| **CVE** | Common Vulnerabilities and Exposures — a specific *instance* of a weakness in a specific product/version (e.g. CVE-2024-3094). |
| **ASVS** | Application Security Verification Standard — OWASP's line-itemised control catalogue; the closing checklist after the Top 10. |
| **CSP** | Content Security Policy — the HTTP header that constrains what a browser may load / execute on your page. |
| **HSTS** | HTTP Strict Transport Security — the header that tells browsers to refuse plain-HTTP fallback to your domain. |
| **IDOR** | Insecure Direct Object Reference — the A01 sub-class where the server trusts the client to send only IDs it is authorised to access. |
| **SSRF** | Server-Side Request Forgery — the A10 vulnerability where the server fetches a URL the attacker controls. |
| **SSTI** | Server-Side Template Injection — the sub-class of A03 specific to template engines like Jinja2. |
| **XXE** | XML External Entities — the 2017-era category; in 2021 folded into A05 (Security Misconfiguration). |
| **JWT** | JSON Web Token — a signed (and optionally encrypted) token used for session and API authentication; a recurring source of A02 and A07 bugs. |
| **Argon2id** | The password-hashing algorithm OWASP recommends for new systems as of 2021 (Password Storage Cheat Sheet). |
| **IMDS** | Instance Metadata Service — the `169.254.169.254` endpoint on AWS, Azure, and GCP; the canonical SSRF target. |
| **IMDSv2** | The session-based, hop-limited version of IMDS that mitigates SSRF on AWS; enable on every EC2 instance. |
| **Sigstore** | Keyless artifact signing infrastructure; the modern answer to "is this package the one the maintainer published?" |
