# OWASP Sentinel Pro — Burp Suite Extension

Real-time, passive OWASP Top 10 (2021) detection for Burp Suite, built on the
**Montoya API** (Java). As you browse a target through Burp's Proxy, Sentinel
analyses every request/response, classifies issues by OWASP category, **de-dupes
by endpoint + issue**, and gives you **attack payloads**, **context-aware test
cases**, and one-click **Send to Repeater / Intruder**.

> ⚠️ **Authorised testing only.** This tool flags *candidate* issues with passive
> heuristics — it does not exploit anything. Always confirm manually and only test
> systems you have permission to test.

---

## What it covers

**Full OWASP Top 10 (2021):**

| Category | Examples detected |
|---|---|
| A01 Broken Access Control | IDOR/BOLA (id in param or path), admin/internal paths, CSRF (no token), Open Redirect |
| A02 Cryptographic Failures | Credentials/tokens over cleartext HTTP, weak cookie flags (HttpOnly/Secure/SameSite) |
| A03 Injection | SQL/NoSQL, Reflected XSS (echo-detected), OS command, Path traversal/LFI, XXE, LDAP |
| A04 Insecure Design | State-changing actions delivered over GET |
| A05 Security Misconfiguration | Missing security headers, permissive/credentialed CORS, verbose error/stack-trace leaks |
| A06 Vulnerable & Outdated Components | Server / X-Powered-By version banners |
| A07 Identification & Auth Failures | Login/registration/reset/MFA/SSO endpoints |
| A08 Software & Data Integrity | Insecure deserialization (Java/.NET/PHP markers), JWT alg issues |
| A09 Logging & Monitoring | Client-controllable debug/verbose switches |
| A10 SSRF | URL-bearing parameters (with cloud-metadata payloads) |

**Dedicated advanced modules (explicitly called out in the UI):**

- **JWT** — finds tokens in `Authorization`, cookies, params, and responses;
  decodes the header, reads `alg`, and suggests alg-specific attacks (alg:none,
  HS/RS confusion, weak-secret cracking, `kid`/`jku`/`jwk` header abuse, claim tampering).
- **OAuth 2.0 / OIDC** — detects the flow from `response_type` / `grant_type` /
  `client_id` / `redirect_uri` / token & authorize endpoints, notices **missing
  `state`** and **missing PKCE**, and tailors the test checklist accordingly
  (redirect_uri manipulation, code reuse/injection, CSRF, scope escalation, mix-up).
- **SAML 2.0** — flags `SAMLRequest` / `SAMLResponse` and suggests XML Signature
  Wrapping (XSW), signature exclusion/downgrade, assertion replay, audience confusion, XXE.

Every finding carries: **severity** (colour-coded), **confidence**, **evidence**,
**remediation**, a **payload set**, and **manual test cases**.

---

## Build

You need **JDK 17+**. Pick either path:

### Option A — standalone script (no Gradle)
```bash
# Git Bash / WSL
bash build.sh
```
```powershell
# Windows PowerShell
./build.ps1
```
Both download the Montoya API jar on first run and produce
`dist/owasp-sentinel-1.0.0.jar`.

### Option B — Gradle / IDE
Open the folder in IntelliJ (or run `gradle jar`). Output:
`build/libs/owasp-sentinel-1.0.0.jar`.

> Montoya is a `compileOnly` dependency — Burp provides it at runtime, so the jar
> is intentionally tiny and bundles no third-party code.

---

## Install in Burp

1. **Extensions → Installed → Add**
2. Extension type: **Java**
3. Select `dist/owasp-sentinel-1.0.0.jar`
4. A new **"OWASP Sentinel"** tab appears.

Works in Burp **Community or Professional** (Montoya 2023.12+, i.e. Burp 2023.10+).

---

## Scope control

By default Sentinel scans **all** proxied traffic. To restrict it to your target:

1. In the **Scope:** bar, enter one or more hosts / URLs, comma- or
   space-separated — e.g. `example.com, app.example.com/api`.
2. Tick the options you want and click **Apply scope**:
   - **Subdomains** — `example.com` also matches `*.example.com` (on by default).
   - **Use Burp scope** — additionally honour Burp's own Target → Scope.
   - **Include SSO/IdP** — *(on by default)* even when a request leaves your
     target and redirects to a known identity provider
     (`login.microsoftonline.com`, `*.b2clogin.com`, Google, Okta, Auth0, Ping,
     OneLogin, Salesforce, GitHub, …), Sentinel still inspects it — but in
     **SSO-only mode**, running just the JWT / OAuth 2.0 / SAML modules so you
     get the SSO findings without noise about the provider's own website.

The status bar shows the active scope. A blank scope + "Use Burp scope" off means
"scan everything". **Manual right-click scans always run in full, ignoring scope.**

## Use

1. Make sure the **`● Live (capturing)`** toggle is on, then browse the target
   through Burp's Proxy. Findings stream into the table in real time.
2. **Filter** by OWASP category or severity, or **search** any text.
3. Click a finding to see:
   - **Overview** — evidence + remediation
   - **Suggested Payloads** — copy/paste ready (replace `OOB_HOST` with your Collaborator)
   - **Test Cases** — the manual steps for that issue
   - **Request / Response** — the exact traffic, in native Burp editors
4. **Send to Repeater** / **Send to Intruder** to start testing; **Copy payloads**
   to grab the list; **Export HTML/MD** for a report.
5. Want to scan items you already captured (or while paused)? Right-click any
   request anywhere in Burp → **"Scan with OWASP Sentinel"** (multi-select supported).

## Triage & noise suppression

Each finding has a **Status** column you control from the **Triage** bar:

- **Confirm** — mark a verified true positive (shown bold red).
- **False positive** / **Ignore** — mark as noise.
- **Reset status** — back to *New*.
- **Suppress issue type** — removes every finding of that *category + issue* and
  **drops all future ones** (e.g. tired of "Missing security headers" on every
  page? Suppress it once). Persisted, so it stays suppressed across restarts.

Filter the table by **Status**, or tick **Hide FP/Ignored** to declutter while
you work. Verdicts and suppressions are saved with the project (below).

## Persistence (project-scoped)

Findings, triage verdicts, scope settings and suppression rules are saved into
Burp's **project file** (`persistence().extensionData()`), so:

- Reopen an **existing project** → its findings/verdicts/scope come back.
- Open a **different project** → you see that project's data.
- Start a **new project** → the table is empty.

The full request/response is stored per finding, so **Send to Repeater** and the
request/response viewers keep working after a reload. Saves are debounced in the
background and flushed when the extension unloads / Burp closes.

> Caveat: Burp **Community** uses temporary, non-saved projects, so cross-restart
> persistence needs Burp **Pro** with a saved project file. Use **Export HTML/MD**
> as a portable backup in Community.

### De-duplication
The same endpoint + same issue collapses into **one row**; the **Hits** column
counts how many times it recurred. "Endpoint" is normalised to
`METHOD host:port path` (query stripped), so `/item?id=1` and `/item?id=2` are one
SQLi/IDOR finding, not hundreds.

---

## Tuning

Detection dictionaries (parameter names, paths) live in
`detect/DetectionEngine.java`; payloads in `payload/PayloadLibrary.java`; the
OAuth/SAML/JWT checklists in `payload/TestCaseLibrary.java`. Add your own and
rebuild.

## Roadmap (future-proofing ideas)

Already shipped beyond the Top-10 core: **scope control**, **SSO/IdP auto-scope**,
**secret/credential leak detection** (AWS/Google/GitHub/Slack/Stripe/private keys/
leaked JWTs), context-aware OAuth/JWT/SAML playbooks, **project-scoped persistence**,
and **triage + issue-type suppression**. High-value next steps:

- **Raise native Burp issues** — push findings into Burp's Issues panel via the
  Montoya `siteMap()`/audit-issue API so they appear in Burp's own reports.
- **Collaborator integration** — auto-mint a live OOB host (`api.collaborator()`)
  and inject it into SSRF/XXE/blind payloads, then poll for hits.
- **Per-host suppression** — extend the current issue-type suppression to host-scoped.
- **Custom rules via JSON** — let users add param/path/header signatures and
  payloads without recompiling.
- **Protocol breadth** — GraphQL introspection & injection, WebSocket monitoring,
  gRPC, and richer JSON/API body parsing.
- **Export formats** — SARIF and CSV in addition to HTML/Markdown.
- **Tech fingerprint → CVE** — map disclosed `Server`/`X-Powered-By` versions to
  known CVEs.
- **AI-assisted triage** — summarise a finding and tailor payloads with the
  Claude API (`claude-opus-4-8`).

## License

[MIT](LICENSE) © 2026 r04i7. Use only against systems you are authorised to test.

## Notes & limits
- Analysis is **passive** (it reads traffic, never modifies or replays it).
- Heuristics favour **coverage**; expect some tentative/speculative findings —
  triage with the Confidence column.
- Large response bodies are capped at 200 KB for reflection checks to stay fast.
