package com.owaspsentinel.payload;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Step-by-step manual test cases per issue type. Each entry follows a
 * "<b>Title</b> — Goal / How / Look for / Impact" shape so it reads as a mini
 * playbook, not just a hint. The OAuth/JWT helpers are context-aware: they adapt
 * the checklist to the exact grant type / algorithm observed in traffic.
 */
public final class TestCaseLibrary {

    private TestCaseLibrary() {}

    // ====================================================================
    //  OAuth 2.0 / OIDC
    // ====================================================================

    /**
     * @param responseType e.g. "code", "token", "id_token" (may be null)
     * @param grantType    e.g. "authorization_code", "client_credentials" (may be null)
     * @param hasState     whether a state parameter was present
     * @param hasPkce      whether code_challenge/PKCE was present
     */
    public static List<String> oauth(String responseType, String grantType,
                                     boolean hasState, boolean hasPkce) {
        List<String> t = new ArrayList<>();

        t.add("redirect_uri takeover — Goal: steal the authorization code/token. How: change redirect_uri to a host "
                + "you control, then escalate through parser tricks: add a path/query, use //evil, /%2f%2fevil, "
                + "backslashes, redirect_uri=https://target@evil, and a target-domain open redirect as the landing "
                + "page. Look for: the ?code= / #access_token= landing on your host (also check Referer & browser "
                + "history). Impact: full account takeover.");
        t.add("redirect_uri matching weakness — Goal: bypass allow-listing. How: test prefix matching "
                + "(https://target.com.evil.com), suffix matching, sub-path (https://target.com/../evil), and case/encoding. "
                + "Look for: any non-exact match the server still accepts.");

        if (!hasState) {
            t.add("Login CSRF (NO state seen) — Goal: graft the attacker's identity onto the victim, or vice-versa. "
                    + "How: capture a valid authorization callback for the ATTACKER's account and replay/serve it to a "
                    + "logged-in victim (no state means the callback isn't bound to the victim's session). Look for: the "
                    + "victim's session silently linked to the attacker's IdP account. Impact: account hijack / data theft.");
        } else {
            t.add("state binding — Goal: confirm CSRF protection is real. How: omit state, reuse an old state, and swap "
                    + "another user's state. Look for: the flow completing despite a missing/invalid/foreign state. "
                    + "Impact: if any of these work, the 'state' is decorative and login CSRF is live.");
        }

        if ("code".equalsIgnoreCase(responseType) || "authorization_code".equalsIgnoreCase(grantType)) {
            t.add("Authorization-code abuse — Goal: replay/steal a code. How: submit the same code twice (codes must "
                    + "be single-use), test code lifetime (should be ~30-60s), and try code substitution across clients "
                    + "(redeem client A's code at client B's token endpoint). Look for: a second redemption succeeding, "
                    + "long-lived codes, or cross-client acceptance. Impact: token theft / impersonation.");
            t.add("Code/token injection — Goal: inject attacker-issued artefacts into the victim's session. How: feed a "
                    + "code or token minted for YOUR account into the victim's callback/token exchange. Look for: the "
                    + "victim's app accepting your code. Impact: session confusion / account linking attacks.");
            if (!hasPkce) {
                t.add("PKCE missing — Goal: intercept the code on a public client. How: this code flow carries no "
                        + "code_challenge; capture the code (mobile/SPA redirect, referrer, logs) and redeem it yourself. "
                        + "Look for: successful redemption without a code_verifier. Impact: authorization-code interception. "
                        + "Fix: enforce PKCE (S256) for all clients.");
            } else {
                t.add("PKCE downgrade — Goal: defeat PKCE. How: drop code_challenge entirely, or set "
                        + "code_challenge_method=plain and supply the verifier in clear. Look for: the server still issuing "
                        + "tokens. Impact: PKCE becomes a no-op.");
            }
        }

        if ("token".equalsIgnoreCase(responseType) || "id_token".equalsIgnoreCase(responseType)) {
            t.add("Implicit-flow leakage — Goal: harvest tokens from the URL fragment. How: response_type=token/id_token "
                    + "puts tokens in the #fragment; check Referer headers, browser history, proxy/CDN logs, and "
                    + "open-redirect chaining. Look for: tokens reachable off-host. Impact: token theft. Fix: migrate to "
                    + "code + PKCE.");
        }
        if ("id_token".equalsIgnoreCase(responseType) || responseType == null && grantType != null) {
            t.add("OIDC id_token validation — Goal: forge identity. How: tamper the id_token (alg:none, wrong aud, wrong "
                    + "iss, missing/old nonce, swapped sub/email). Look for: the relying party accepting it. Impact: "
                    + "authentication bypass / impersonation. (See the dedicated JWT module for signature attacks.)");
        }
        if ("client_credentials".equalsIgnoreCase(grantType)) {
            t.add("client_credentials hardening — Goal: find over-privilege/secret leak. How: request extra/admin scopes, "
                    + "and check whether the client secret ever reaches the browser/mobile bundle. Look for: granted "
                    + "scopes beyond need, or an exposed secret. Impact: privilege escalation.");
        }

        t.add("Scope escalation — Goal: get more access than authorised. How: add admin/extra scopes to the auth & token "
                + "requests. Look for: the issued token carrying scopes you shouldn't have. Impact: privilege escalation.");
        t.add("IdP mix-up / confusion — Goal: redirect the code to the wrong IdP. How: where multiple IdPs are supported, "
                + "swap issuer/authorization/token endpoints between requests. Look for: the client accepting a token/code "
                + "from a different issuer than it started with. Impact: account takeover.");
        t.add("Token endpoint hardening — Goal: weaken client auth & rotation. How: test missing client authentication, "
                + "refresh-token reuse after rotation, and whether revocation actually invalidates tokens. Look for: "
                + "accepted unauthenticated/rotated/revoked tokens.");
        return t;
    }

    // ====================================================================
    //  SAML
    // ====================================================================

    public static List<String> saml(boolean isResponse) {
        List<String> t = new ArrayList<>();
        t.add(isResponse
                ? "Context — this is a SAMLResponse (IdP→SP): the SP trusts a signed assertion, so focus on forging/"
                        + "wrapping the assertion so the SP authenticates you as someone else."
                : "Context — this is a SAMLRequest (SP→IdP): focus on RelayState abuse and request tampering; the "
                        + "high-value forgery target is the Response on the way back.");
        t.add("XML Signature Wrapping (XSW1–8) — Goal: change the assertion while keeping a valid signature. How: add a "
                + "second forged Assertion/Response and relocate the signed element (wrap it in an unsigned parent, move it "
                + "to a decoy, abuse Id references) so the signature validates over the original but the SP processes YOUR "
                + "assertion. Tooling: SAML Raider. Look for: login as the forged NameID despite a 'valid' signature. "
                + "Impact: full authentication bypass.");
        t.add("Signature exclusion — Goal: get an unsigned assertion accepted. How: strip <ds:Signature> entirely (and "
                + "test removing it from Response vs Assertion separately). Look for: the SP still logging you in. Impact: "
                + "trivial auth bypass.");
        t.add("Signature algorithm downgrade — Goal: weaken verification. How: change SignatureMethod to a weak/empty "
                + "algorithm, or re-sign with your own key/cert and see if the SP trusts an unknown issuer. Look for: "
                + "acceptance of attacker-signed assertions.");
        t.add("Assertion replay — Goal: reuse a captured login. How: resend a previously valid assertion. Look for: no "
                + "enforcement of NotOnOrAfter, OneTimeUse, or InResponseTo. Impact: session replay.");
        t.add("Audience/Recipient/Destination confusion — Goal: cross-SP token reuse. How: alter <Audience>, Recipient, "
                + "and Destination to another service provider. Look for: an assertion minted for SP-A accepted by SP-B.");
        t.add("XXE in SAML XML — Goal: file read / SSRF via the parser. How: the message is usually base64 (+ DEFLATE for "
                + "redirect binding); decode, inject an external entity, re-encode. Look for: entity resolution / OOB hit. "
                + "Impact: local file disclosure or SSRF.");
        t.add("NameID canonicalization/comment injection — Goal: map to another user. How: inject XML comments "
                + "(admin<!---->@evil.com) or canonicalization quirks into NameID so signature validation and user mapping "
                + "disagree. Look for: logging in as the 'admin' portion. Impact: account takeover.");
        t.add("RelayState abuse — Goal: open redirect / XSS. How: set RelayState to an external URL or a script payload. "
                + "Look for: an unvalidated redirect or reflected XSS after SSO. Impact: phishing / token theft.");
        return t;
    }

    // ====================================================================
    //  JWT
    // ====================================================================

    /** @param alg the observed "alg" header value (e.g. "HS256", "RS256", "none"). */
    public static List<String> jwt(String alg) {
        String a = alg == null ? "" : alg.toLowerCase();
        List<String> t = new ArrayList<>();
        t.add("alg:none — Goal: forge an unsigned token. How: set the header alg to none/None/nOnE/NONE and delete the "
                + "signature (keep the trailing dot). Tamper claims (role=admin, sub=victim). Look for: the API accepting "
                + "the token. Impact: authentication bypass. Tooling: jwt_tool, Burp 'JSON Web Tokens' ext.");
        if (a.startsWith("hs")) {
            t.add("Weak HMAC secret — Goal: recover the signing key. How: crack offline with hashcat -m 16500 (or jwt_tool) "
                    + "against rockyou/secret-keys wordlists. Look for: a cracked secret. Then: re-sign arbitrary claims "
                    + "(role=admin). Impact: full token forgery.");
            t.add("Claim tampering — Goal: privilege/identity change. How: with the (cracked or guessed) key, flip "
                    + "role/scope/sub/tenant; also test the token with NO signature change to confirm the server truly "
                    + "verifies it. Look for: elevated access.");
        } else if (a.startsWith("rs") || a.startsWith("es") || a.startsWith("ps")) {
            t.add("Algorithm confusion (RS256→HS256) — Goal: forge with the public key. How: take the server's PUBLIC key "
                    + "(from /.well-known/jwks.json, a TLS cert, or recovered from two tokens), switch the header alg to "
                    + "HS256, and HMAC-sign the token using that public key as the secret. If the server calls a single "
                    + "verify() with the public key, it may accept your forgery. Look for: acceptance. Impact: full forgery.");
            t.add("Public-key recovery — Goal: get the key for the confusion attack. How: if JWKS isn't published, recover "
                    + "the RSA public key from two captured tokens (jwt_tool / rsa_sign2n). Look for: a usable n,e.");
        }
        t.add("kid header injection — Goal: control which key verifies. How: set kid to a path traversal "
                + "(../../dev/null then sign with empty key), an SQLi string, or point it at a predictable/attacker key. "
                + "Look for: verification against a key you control. Impact: forgery.");
        t.add("jku / x5u header — Goal: supply your own verification key. How: repoint jku/x5u to an attacker-hosted JWKS/"
                + "cert (test SSRF allow-list bypasses). Look for: the server fetching and trusting your key. Impact: forgery.");
        t.add("jwk header embedding — Goal: self-provide the key (CVE-2018-0114 class). How: embed a self-signed public key "
                + "in the token's jwk header and sign with the matching private key. Look for: acceptance.");
        t.add("Claim & lifetime checks — Goal: find missing validation. How: remove exp, send an expired token, change "
                + "aud/iss, and decode-only tamper (no re-sign) to confirm the signature is actually checked. Look for: "
                + "any acceptance. Impact: bypass / replay.");
        t.add("Cross-service / cross-tenant replay — Goal: reuse a token where it shouldn't work. How: present the token "
                + "to another audience, tenant, or environment. Look for: acceptance outside its intended scope.");
        return t;
    }

    // ====================================================================
    //  Per-category generic checklists
    // ====================================================================

    public static List<String> accessControl() {
        return Arrays.asList(
                "Horizontal IDOR/BOLA — Goal: read/modify another user's object. How: keep YOUR session but change the "
                        + "object id (decrement/increment, swap a known id/UUID, try id[]=a&id[]=b). Look for: another "
                        + "user's data in the response or a successful write. Impact: data breach / tampering.",
                "Vertical privilege escalation — Goal: reach admin functions as a low-priv user. How: force-browse admin/"
                        + "internal endpoints, and replay an admin action with your own session. Look for: 200 + the "
                        + "privileged action succeeding. Impact: full compromise.",
                "Role/flag tampering — Goal: elevate via client-trusted fields. How: flip role=admin / isAdmin=true / "
                        + "account_type in body, JWT, or cookie. Look for: elevated behaviour. Impact: privilege escalation.",
                "Method & verb tampering — Goal: bypass verb-based rules. How: swap GET/POST/PUT/DELETE, try HEAD, and "
                        + "X-HTTP-Method-Override. Look for: an action allowed under a different verb.",
                "Access-rule bypass by encoding — Goal: dodge path-based auth. How: /admin vs /Admin vs /admin/. vs "
                        + "/%2e/admin vs //admin. Look for: the gate failing open.");
    }

    public static List<String> misconfig() {
        return Arrays.asList(
                "Missing security headers — Goal: enable client-side attacks. How: check for absent CSP, HSTS, "
                        + "X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy. Look for: gaps. "
                        + "Impact: clickjacking, MIME sniffing, weaker XSS containment.",
                "CORS probe — Goal: read authenticated data cross-origin. How: send Origin: https://evil.example and watch "
                        + "the response. Look for: Access-Control-Allow-Origin reflecting your origin WITH "
                        + "Allow-Credentials: true. Impact: cross-origin account-data theft.",
                "Verbose errors / debug surfaces — Goal: leak internals or find an oracle. How: trigger 500s, hit /debug, "
                        + "/actuator, /.env, default creds. Look for: stack traces, framework versions, secrets. Impact: "
                        + "recon + injection oracles.",
                "Cookie flags — Goal: weaken session protection. How: inspect Set-Cookie for Secure, HttpOnly, SameSite. "
                        + "Look for: a session/auth cookie missing any of these. Impact: theft (XSS/MITM) or CSRF.");
    }

    public static List<String> auth() {
        return Arrays.asList(
                "Credential attacks — Goal: break weak login. How: test rate-limiting/lockout with repeated attempts, "
                        + "and try credential stuffing with known breached pairs. Look for: no throttling/lockout. Impact: "
                        + "account takeover at scale.",
                "Session fixation — Goal: hijack via a pre-set session. How: note the session id before login; log in; "
                        + "check if it rotates. Look for: the same id surviving authentication. Impact: hijack.",
                "Password reset weaknesses — Goal: take over via reset. How: test Host-header poisoning on the reset link, "
                        + "token predictability/expiry/reuse, and user enumeration in responses/timing. Look for: a reset "
                        + "link pointed at your host or a guessable token. Impact: account takeover.",
                "MFA bypass — Goal: skip the second factor. How: tamper the 'mfa_passed' response/flag, brute-force the "
                        + "OTP (no rate-limit), reuse/guess backup codes, or check if direct post-login endpoints skip MFA. "
                        + "Look for: access without a valid second factor.");
    }

    // ---- injection family (referenced from the engine) -------------------

    public static List<String> sqli() {
        return Arrays.asList(
                "Boolean/error probe — Goal: confirm injectable. How: send a lone quote, then true vs false pairs "
                        + "(' OR '1'='1 vs ' AND '1'='2). Look for: errors, or content differing between true/false. "
                        + "Impact: data exfiltration.",
                "UNION extraction — Goal: pull data. How: find column count with ORDER BY n, then UNION SELECT to dump "
                        + "version()/users. Look for: injected values appearing in the response.",
                "Blind (time/boolean) — Goal: extract without output. How: use SLEEP/pg_sleep/WAITFOR and binary search "
                        + "on conditions; or boolean-diff. Look for: response-time deltas. Tooling: sqlmap to confirm.",
                "NoSQL variant — Goal: auth bypass on document stores. How: send {\"$gt\":\"\"} / {\"$ne\":null} in JSON "
                        + "params. Look for: bypassed filters / returned records.");
    }

    public static List<String> xss() {
        return Arrays.asList(
                "Find the reflection context — Goal: know how to break out. How: submit a unique marker and locate it in "
                        + "the response: HTML body, attribute, <script> block, or URL. Look for: which of < > \" ' / "
                        + "survive un-encoded.",
                "Break out & execute — Goal: run JS. How: pick the matching vector ( \"><script>… for attributes, "
                        + "'-alert(1)-' inside JS, javascript: in href). Confirm with a harmless alert(document.domain).",
                "Filter evasion — Goal: defeat blocklists/WAF. How: event handlers (onerror/onload), SVG/MathML, "
                        + "case/encoding, nested/broken tags. Look for: any vector that fires.",
                "Assess impact — Goal: prove severity. How: read document.cookie (if no HttpOnly), perform an action via "
                        + "fetch with the victim's session, or pivot to stored XSS. Impact: session/account takeover.");
    }

    public static List<String> ssrf() {
        return Arrays.asList(
                "Internal reach — Goal: prove the server fetches your URL. How: point the param at http://127.0.0.1/ and "
                        + "common internal ports. Look for: differing responses/timing vs an external host.",
                "Cloud metadata — Goal: steal credentials. How: target 169.254.169.254 (AWS), metadata.google.internal "
                        + "(GCP), and the Azure IMDS endpoint. Look for: instance/IAM data. Impact: cloud account compromise.",
                "Blind confirmation — Goal: detect no-output SSRF. How: use a Collaborator/OOB host and watch for DNS/HTTP "
                        + "callbacks. Look for: an interaction from the target's egress IP.",
                "Filter bypass — Goal: defeat allow/deny lists. How: IP obfuscation (decimal/octal/IPv6), "
                        + "http://evil@127.0.0.1, #/@ tricks, redirects to internal, and gopher/dict/file schemes. "
                        + "Look for: a blocked target becoming reachable.");
    }

    public static List<String> idor() {
        return Arrays.asList(
                "Enumerate references — Goal: access others' objects. How: decrement/increment numeric ids; for UUIDs, "
                        + "try known/leaked ones. Look for: another user's data. Impact: mass data exposure.",
                "Keep your session, change the id — Goal: prove missing authorization (not just auth). How: replace only "
                        + "the object id while authenticated as yourself. Look for: success despite not owning the object.",
                "Method/parameter pollution — Goal: bypass checks. How: id[]=yours&id[]=theirs, JSON arrays, or duplicate "
                        + "params. Look for: the server resolving to the second value.",
                "Write-side IDOR — Goal: tamper, not just read. How: repeat on POST/PUT/DELETE/PATCH. Look for: modifying "
                        + "or deleting another user's resource.");
    }

    public static List<String> commandInjection() {
        return Arrays.asList(
                "Inline metacharacters — Goal: run a command. How: append ;id |id `id` $(id) and OS variants. Look for: "
                        + "command output in the response.",
                "Blind/time-based — Goal: confirm without output. How: inject sleep/ping delays and a Collaborator DNS/HTTP "
                        + "callback ($(curl OOB) / nslookup OOB). Look for: delay or OOB hit. Impact: RCE.",
                "Argument & filter bypass — Goal: defeat sanitisation. How: newline (%0a) injection, ${IFS} for spaces, "
                        + "quotes/concatenation. Look for: execution despite filtering.");
    }

    public static List<String> pathTraversal() {
        return Arrays.asList(
                "Directory walk — Goal: read arbitrary files. How: ../../../../etc/passwd and ..\\..\\windows\\win.ini, "
                        + "with encodings (%2e, double-encode, ....// ) and a null byte. Look for: file contents in the "
                        + "response.",
                "LFI→RCE pivot — Goal: escalate to code exec. How: PHP wrappers (php://filter, data://), log poisoning, or "
                        + "session files. Look for: source disclosure or executed payload.",
                "Path normalisation bypass — Goal: defeat sanitisers. How: mixed slashes, over-long traversal, absolute "
                        + "paths, and UNC. Look for: the filter failing.");
    }

    public static List<String> xxe() {
        return Arrays.asList(
                "In-band file read — Goal: read local files. How: declare an external entity (file:///etc/passwd) and echo "
                        + "it in an element. Look for: file content reflected. Impact: disclosure.",
                "Out-of-band (blind) — Goal: exfiltrate without output. How: use a parameter entity that fetches an "
                        + "attacker DTD and posts data back. Look for: a Collaborator/OOB hit.",
                "SSRF & DoS via XXE — Goal: extend impact. How: point an entity at internal URLs/metadata; (carefully) test "
                        + "billion-laughs only in a lab. Look for: internal reach.");
    }

    public static List<String> openRedirect() {
        return Arrays.asList(
                "External redirect — Goal: send users off-site. How: set the redirect param to https://evil.example, then "
                        + "//evil, /\\evil, https:evil, target@evil, %2f%2fevil. Look for: a 3xx Location (or JS redirect) to "
                        + "your host. Impact: phishing.",
                "Chain into SSO/OAuth — Goal: steal tokens. How: use the open redirect as the OAuth redirect_uri landing or "
                        + "SAML RelayState. Look for: codes/tokens forwarded to your host. Impact: account takeover.");
    }

    public static List<String> deserialization() {
        return Arrays.asList(
                "Identify the format — Goal: pick the right gadget. How: confirm Java (rO0AB / AC ED 00 05), .NET "
                        + "(AAEAAAD/////), PHP (O:n:\"..\"), or Python pickle. Look for: the magic bytes in params/body.",
                "Gadget execution — Goal: RCE. How: build a chain with ysoserial / ysoserial.net / phpggc matching the "
                        + "libraries on the classpath. Look for: command output or behaviour change.",
                "Blind confirmation — Goal: safe proof. How: use a DNS/HTTP OOB gadget (e.g. URLDNS) before any RCE chain. "
                        + "Look for: a Collaborator callback. Impact: full server compromise.");
    }

    public static List<String> secret() {
        return Arrays.asList(
                "Validate the secret — Goal: confirm it's live, not a placeholder. How: (within scope/authorisation) test "
                        + "the key against its provider's read-only API. Look for: a 200/identity response. Impact depends on "
                        + "the key's privileges.",
                "Trace the exposure — Goal: find the root cause & blast radius. How: check whether it's in JS bundles, API "
                        + "responses, source maps, or comments; search history/other endpoints for the same value.",
                "Report & rotate — Goal: contain. How: recommend immediate revocation/rotation and moving the secret "
                        + "server-side / into a vault. Do NOT use the key beyond minimal proof.");
    }
}
