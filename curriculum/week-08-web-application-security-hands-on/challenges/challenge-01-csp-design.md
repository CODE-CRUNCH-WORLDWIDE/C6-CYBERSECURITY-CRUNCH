# Challenge 1 — Design a Content Security Policy From Scratch

**Estimated time:** 90 minutes.

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  This challenge involves editing the vuln_lab application and       |
|  measuring its behaviour with a CSP header in place. All work is    |
|  on your own laptop, against the lab on 127.0.0.1:5000. The CSP     |
|  you design is for the lab; you may reuse it (with care, and with   |
|  appropriate revisions for the production environment) on systems   |
|  you own.                                                           |
+---------------------------------------------------------------------+
```

Lecture 3 § 9 walked one Content Security Policy and pointed at the canonical references. This challenge asks you to design a CSP for the patched vuln_lab from scratch — reasoning about each directive, justifying each choice, and validating that the policy fires correctly on every endpoint.

The deliverable is one document, `csp-design.md`, and one updated `app.py` with the new policy installed.

---

## What you ship

1. `csp-design.md`, a 1500-2500 word design document.
2. The updated `app.py` with the new policy installed in the `set_security_headers` after-request hook.
3. A "CSP report" — the output of `curl -sI http://127.0.0.1:5000/` after the patch, showing the CSP header in full.
4. A "violation log" — the browser console output when the original Lecture 2 XSS payloads are sent against the patched lab. The expected behaviour is that each payload triggers a CSP violation, the browser refuses to execute the script, and the console logs a message naming the directive that blocked it.

---

## Required sections in `csp-design.md`

### § 1 — The application's actual content sources (200-300 words)

Inventory every resource the patched vuln_lab loads. For each:

- The resource type (script, stylesheet, image, font, font, iframe, etc.).
- The origin it loads from (same-origin, a specific CDN, a data URI, etc.).
- Whether it is server-rendered (the templates control it) or client-rendered (JavaScript loads it later).

The lab is small — the inventory is two screens of text — but the discipline of *listing every resource before writing the policy* is what produces a CSP that does not break the application.

Hint: open each page in Firefox's developer tools → Network tab. Every loaded resource is listed.

### § 2 — Directive-by-directive justification (400-600 words)

For each directive in your policy — `default-src`, `script-src`, `style-src`, `img-src`, `connect-src`, `font-src`, `object-src`, `frame-src`, `frame-ancestors`, `base-uri`, `form-action`, `report-uri` / `report-to` — explain in 2-4 sentences:

- What the directive controls (cite the MDN reference inline).
- The value you chose.
- The reason the value is what it is for *this application*.
- What an attacker who could inject HTML into a page would gain if you left this directive open.

Directives you do not include are themselves a design choice; explain at least three you considered and rejected, with reasoning.

### § 3 — Inline scripts and styles (200-400 words)

The patched lab has no inline `<script>` blocks and no inline `<style>` blocks in its templates. Confirm this is true (`grep -r "<script" mini-project/starter/templates/` should return only `<script src="...">` tags, never inline-content `<script>` blocks).

Decide: does your policy include `'unsafe-inline'`? The answer should be no. If you find yourself wanting to include `'unsafe-inline'`, the better fix is to refactor the application to put the inline content in an external file or to use a `nonce-<random>` source expression.

Write 200-400 words on:

- Why `'unsafe-inline'` is a near-defeat of `script-src`.
- The `'nonce-<random>'` source expression and how it works (the server generates a fresh random nonce per response, injects it into the policy header and into each `<script>` tag that should be allowed; the browser only executes inline scripts whose `nonce` attribute matches; an attacker who injects a `<script>` without the nonce cannot execute).
- The `'sha256-<hash>'` / `'sha384-<hash>'` source expressions and when they are useful (whitelist a specific known-good inline script by its hash).
- The case for replacing inline scripts with external files unconditionally.

### § 4 — Reporting (100-200 words)

The CSP can include a reporting endpoint. When the browser blocks a resource, it sends a structured report to the endpoint. The legacy mechanism is `report-uri <endpoint>`; the modern replacement is `report-to <group-name>` paired with a `Reporting-Endpoints` response header.

Pick one. Implement it (the lab can have a `/csp-report` endpoint that logs the report to a file). Show, in the document, one captured report from the violation log section below. Discuss how you would route reports in production: at low volume, log to a file; at higher volume, ship to a SIEM; at very high volume, sample.

### § 5 — Validation against the Lecture 2 payloads (200-400 words)

For each of the XSS payloads from Exercise 2 (reflected and stored), run the payload against the *patched* lab with the new CSP installed, observe the browser console, and record what happens.

Expected: the autoescape patch from Lecture 3 means the payload is encoded and never reaches the browser as a `<script>` tag. CSP is a *backstop*: if a future template regression reintroduces `|safe`, CSP catches the resulting XSS. For the *purpose of testing CSP itself*, temporarily revert the autoescape patch — change the template back to `{{ q | safe }}` — and re-run the XSS payload. The browser receives the `<script>` tag this time; CSP blocks the execution; the browser logs the violation. Capture the violation message.

Re-apply the autoescape patch after the CSP test. The shipped lab has both defences.

Show the violation log entry for each payload type.

### § 6 — Deployment considerations (200-300 words)

Discuss the difference between *report-only* CSP (the `Content-Security-Policy-Report-Only` header) and *enforced* CSP (the `Content-Security-Policy` header). Real production deployments often run report-only for several weeks before enforcing, to discover violations from legitimate content the team forgot.

Discuss the difference between development and production policies. The lab's policy works for the lab; a production CSP for a similar application would also include directives for any CDN you serve assets from, for analytics endpoints, for the OAuth provider's login flow, and so on. List three real-world adjustments you would make.

---

## Acceptance criteria

- `csp-design.md` exists and contains all six sections.
- Section word counts are within 25% of the targets in each section heading.
- Every directive cites the MDN reference inline.
- Section 5 includes the actual browser-console violation messages from the patched lab (paste the text, not a screenshot).
- The updated `app.py` has the policy installed and `curl -sI` shows it.
- The Lecture 2 XSS payloads, against the patched lab with both autoescape and CSP, are blocked: the autoescape encodes them, and the CSP would block them if the encoding ever regressed.

---

## Stretch

- **Run `Mozilla Observatory` against the lab.** Observatory (<https://observatory.mozilla.org/>) is a free tool that grades your security-header configuration. It cannot reach `127.0.0.1` from the public internet — but if you have a personal VPS to deploy a copy of the lab to, run Observatory against it and add the report to the deliverable. (Reminder: only deploy to a VPS you own and only for the purpose of running the audit; do not expose the lab to the internet for any other reason.)
- **Build the `Reporting-Endpoints` modern reporting flow** end-to-end: the lab emits the header, the browser sends the report to `/csp-report`, the endpoint validates and stores the report, and a small companion script (`tools/show_reports.py`) summarises the report log.
- **Compare your CSP to GitHub's, Mozilla's, and Cloudflare's.** All three publish their CSPs (or, more accurately, you can read theirs off any page's response headers with `curl -sI`). Note what they include that you do not, and why each major site needs the directives it does.
- **Read the OWASP CSP Cheat Sheet end-to-end** and re-evaluate your policy against every section's recommendations. Add a "review against OWASP cheat sheet" subsection to § 6.

---

## Common failures

- **The policy breaks the application.** If a legitimate stylesheet or image stops loading after the policy is installed, your policy is too tight. The fix is to add the missing source explicitly; do *not* fall back to `*` for any directive.
- **`'unsafe-inline'` creeps in.** A common reason: the legitimate need for a small inline script (an analytics tag, a feature flag) leads to "just allow inline." Resist. The right answer is nonces or external files.
- **The CSP is dropped on some routes.** Flask's `@app.after_request` runs for every response *only* if no earlier hook short-circuits. Make sure your hook is the last one and that no early-return paths in views bypass it.
- **The violation log is empty.** The CSP is in report-only mode, or the browser does not have console violations enabled. Check the response header is `Content-Security-Policy` (not `-Report-Only`); check the browser console filter level.

---

## What the C6 instructor will look at

When this challenge is graded for portfolio inclusion, the reviewer will look at:

1. **§ 1 inventory.** Did you actually list every resource? If you missed obvious ones (the static CSS the lab serves, the favicon), the rest of the policy is suspect.
2. **§ 2 reasoning.** Is each directive's value justified, or did you copy the lab's default? The latter is fine for learning, not fine for the portfolio. Make at least one defensible deviation.
3. **§ 5 evidence.** The violation log is the proof-of-work. If it is missing or vague, the work has not been done.
4. **The shipped policy in `app.py`.** Does it match what § 2 describes? Disagreement between the document and the code is the single biggest disqualifier.

---

## A note on emojis and tone

The deliverable is for the portfolio. Editorial tone, no emojis, MDN and OWASP citations inline. The audience is a hiring manager skimming for *did this person understand CSP, and can they reason about it under deviation pressure*. They are not skimming for a tutorial recap; they are skimming for evidence of understanding.

If you find yourself recapping what CSP *is*, cut that section. The reader knows. The deliverable is *your* design, not a tutorial.
