package com.owaspsentinel.detect;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.owaspsentinel.model.Confidence;
import com.owaspsentinel.model.Finding;
import com.owaspsentinel.model.OwaspCategory;
import com.owaspsentinel.model.Severity;
import com.owaspsentinel.payload.PayloadLibrary;
import com.owaspsentinel.payload.TestCaseLibrary;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The passive analysis brain. For each piece of proxy traffic it runs every
 * OWASP Top-10 detector plus the JWT / OAuth / SAML modules, de-duplicates by
 * endpoint+issue, and returns only what is new (existing findings just get their
 * hit-counter bumped). All public methods are thread-safe — Burp calls us from
 * its own proxy threads.
 */
public final class DetectionEngine {

    /** new = first time this endpoint+issue was seen; repeated = a known one re-hit. */
    public static final class Result {
        public final List<Finding> created = new ArrayList<>();
        public final List<Finding> repeated = new ArrayList<>();
        public boolean isEmpty() { return created.isEmpty() && repeated.isEmpty(); }
    }

    private final Map<String, Finding> store = new ConcurrentHashMap<>();

    /** category+subtype keys the user has chosen to suppress as noise. */
    private final Set<String> suppressedTypes = ConcurrentHashMap.newKeySet();

    // --- heuristic dictionaries -------------------------------------------

    private static final Set<String> SQLI_PARAMS = setOf(
            "id", "uid", "user", "username", "user_id", "userid", "search", "q", "query",
            "filter", "sort", "order", "orderby", "name", "email", "category", "cat", "year",
            "page", "lang", "keyword", "s", "term", "where", "column", "table", "fields",
            "select", "from", "group", "limit", "offset", "product", "item", "ref", "code");

    private static final Set<String> XSS_PARAMS = setOf(
            "q", "s", "search", "query", "keyword", "name", "message", "msg", "comment",
            "title", "subject", "text", "content", "body", "feedback", "redirect_url",
            "returnurl", "callback", "lang", "page", "tab", "view", "ref", "utm_source");

    private static final Set<String> CMD_PARAMS = setOf(
            "cmd", "exec", "command", "run", "ping", "host", "ip", "dns", "domain", "system",
            "shell", "exe", "code", "do", "action", "func", "feature", "option", "tool");

    private static final Set<String> LFI_PARAMS = setOf(
            "file", "path", "dir", "folder", "page", "document", "doc", "template", "include",
            "load", "read", "download", "filename", "name", "view", "content", "item", "show",
            "site", "locate", "pg", "style", "lang", "module", "conf", "config");

    private static final Set<String> SSRF_PARAMS = setOf(
            "url", "uri", "link", "next", "dest", "destination", "target", "callback", "webhook",
            "host", "domain", "feed", "site", "html", "continue", "return", "returnurl", "image",
            "img", "load", "fetch", "proxy", "open", "out", "view", "to", "data", "reference",
            "page", "remote", "endpoint", "server", "port", "path", "src", "source", "forward");

    private static final Set<String> REDIRECT_PARAMS = setOf(
            "redirect", "redir", "url", "next", "return", "returnurl", "return_url", "goto",
            "dest", "destination", "continue", "forward", "out", "to", "checkout_url",
            "redirect_uri", "redirect_url", "back", "callback", "rurl", "target");

    private static final Set<String> IDOR_PARAMS = setOf(
            "id", "uid", "user_id", "userid", "account", "account_id", "acct", "doc", "document_id",
            "order", "order_id", "invoice", "invoice_id", "file", "file_id", "pid", "num", "no",
            "key", "ref", "uuid", "guid", "object", "record", "row", "ticket", "msg_id", "group_id");

    private static final Set<String> AUTH_PATH_TOKENS = setOf(
            "login", "signin", "sign-in", "authenticate", "auth", "session", "register", "signup",
            "sign-up", "password", "reset", "forgot", "mfa", "otp", "verify", "2fa", "sso",
            "logout", "credential", "account/recover");

    private static final Set<String> SECURITY_HEADERS = setOf(
            "content-security-policy", "strict-transport-security", "x-frame-options",
            "x-content-type-options", "referrer-policy");

    // --- precompiled patterns ---------------------------------------------

    private static final Pattern JWT = Pattern.compile(
            "eyJ[A-Za-z0-9_-]{5,}\\.eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*");
    private static final Pattern ALG = Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern NUMERIC_SEG = Pattern.compile("/\\d{2,}(/|$)");
    private static final Pattern UUID_SEG = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern STACKTRACE = Pattern.compile(
            "(?i)(Exception in thread|at [a-z0-9_.]+\\([A-Za-z0-9_]+\\.java:\\d+\\)|Traceback \\(most recent call last\\)"
                    + "|Warning: [a-z_]+\\(\\)|Fatal error:|SQLSTATE\\[|ORA-\\d{4,}|You have an error in your SQL syntax"
                    + "|System\\.[A-Za-z.]+Exception|org\\.springframework|java\\.lang\\.[A-Za-z]+Exception)");
    private static final Pattern PHP_SERIALIZED = Pattern.compile("(^|[=&])O:\\d+:\"");

    // High-signal secret patterns scanned in request + response bodies.
    private static final String[] SECRET_NAMES = {
            "AWS access key", "Google API key", "GitHub token", "Slack token",
            "Stripe secret key", "Private key block", "Google OAuth client secret",
            "JWT in body"
    };
    private static final Pattern[] SECRET_REGEX = {
            Pattern.compile("A(?:KIA|SIA)[0-9A-Z]{16}"),
            Pattern.compile("AIza[0-9A-Za-z_\\-]{35}"),
            Pattern.compile("gh[pousr]_[0-9A-Za-z]{36}"),
            Pattern.compile("xox[baprs]-[0-9A-Za-z-]{10,48}"),
            Pattern.compile("sk_live_[0-9A-Za-z]{16,}"),
            Pattern.compile("-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
            Pattern.compile("GOCSPX-[0-9A-Za-z_\\-]{20,}"),
            JWT
    };

    // ----------------------------------------------------------------------

    /** Full analysis (every detector). Used by manual right-click scans. */
    public Result analyze(HttpRequestResponse rr) {
        return analyze(rr, false);
    }

    /**
     * @param ssoOnly when true (an out-of-target-scope identity provider), only
     *                the JWT / OAuth / SAML modules run, so login redirects are
     *                still covered without noise about the IdP's own site.
     */
    public Result analyze(HttpRequestResponse rr, boolean ssoOnly) {
        Result result = new Result();
        if (rr == null || rr.request() == null) {
            return result;
        }
        Ctx c = new Ctx(rr);

        if (ssoOnly) {
            detectJwt(c, result);
            detectOAuth(c, result);
            detectSaml(c, result);
            return result;
        }

        detectInjection(c, result);
        detectXss(c, result);
        detectCommandInjection(c, result);
        detectPathTraversal(c, result);
        detectXxe(c, result);
        detectSsrf(c, result);
        detectAccessControl(c, result);
        detectOpenRedirect(c, result);
        detectAuth(c, result);
        detectJwt(c, result);
        detectOAuth(c, result);
        detectSaml(c, result);
        detectCrypto(c, result);
        detectMisconfig(c, result);
        detectVulnComponents(c, result);
        detectIntegrity(c, result);
        detectSecrets(c, result);
        detectLogging(c, result);
        detectInsecureDesign(c, result);

        return result;
    }

    public List<Finding> all() {
        return new ArrayList<>(store.values());
    }

    public void clear() {
        store.clear();
    }

    /** Re-seed the dedup store from persisted findings so repeats merge correctly. */
    public void restore(Finding f) {
        if (f != null) store.putIfAbsent(f.dedupKey(), f);
    }

    /** Suppress an entire issue type and remove any current matching findings. */
    public List<Finding> suppressType(String typeKey) {
        List<Finding> removed = new ArrayList<>();
        if (typeKey == null) return removed;
        suppressedTypes.add(typeKey);
        for (Finding f : new ArrayList<>(store.values())) {
            if (typeKey.equals(f.typeKey())) {
                removed.add(f);
                store.remove(f.dedupKey());
            }
        }
        return removed;
    }

    public void addSuppressedType(String typeKey) {
        if (typeKey != null && !typeKey.isEmpty()) suppressedTypes.add(typeKey);
    }

    public Set<String> suppressedTypes() {
        return new HashSet<>(suppressedTypes);
    }

    // --- detectors --------------------------------------------------------

    private void detectInjection(Ctx c, Result r) {
        for (ParsedHttpParameter p : c.params) {
            if (SQLI_PARAMS.contains(p.name().toLowerCase(Locale.ROOT))) {
                add(c, r, Finding.of(OwaspCategory.A03, "SQL / NoSQL Injection point")
                        .severity(Severity.HIGH).confidence(Confidence.TENTATIVE)
                        .location(p.name())
                        .evidence("Parameter '" + p.name() + "' (" + p.type() + ") looks query-backed.")
                        .payloads(PayloadLibrary.SQLI)
                        .testCases(TestCaseLibrary.sqli()));
            }
        }
    }

    private void detectXss(Ctx c, Result r) {
        boolean html = c.contentType.contains("html");
        for (ParsedHttpParameter p : c.params) {
            String v = p.value();
            String name = p.name().toLowerCase(Locale.ROOT);
            boolean reflected = html && v != null && v.length() >= 3 && !isNumeric(v)
                    && c.responseBody.contains(v);
            if (reflected) {
                add(c, r, Finding.of(OwaspCategory.A03, "Reflected XSS (input echoed in HTML)")
                        .severity(Severity.HIGH).confidence(Confidence.FIRM)
                        .location(p.name())
                        .evidence("Value of '" + p.name() + "' is reflected unencoded in the HTML response.")
                        .payloads(PayloadLibrary.XSS)
                        .testCases(TestCaseLibrary.xss()));
            } else if (html && XSS_PARAMS.contains(name)) {
                add(c, r, Finding.of(OwaspCategory.A03, "Potential XSS sink")
                        .severity(Severity.MEDIUM).confidence(Confidence.SPECULATIVE)
                        .location(p.name())
                        .evidence("User-influenced parameter '" + p.name() + "' on an HTML page.")
                        .payloads(PayloadLibrary.XSS));
            }
        }
    }

    private void detectCommandInjection(Ctx c, Result r) {
        for (ParsedHttpParameter p : c.params) {
            if (CMD_PARAMS.contains(p.name().toLowerCase(Locale.ROOT))) {
                add(c, r, Finding.of(OwaspCategory.A03, "OS Command Injection point")
                        .severity(Severity.HIGH).confidence(Confidence.SPECULATIVE)
                        .location(p.name())
                        .evidence("Parameter '" + p.name() + "' may reach a shell/system call.")
                        .payloads(PayloadLibrary.COMMAND_INJECTION)
                        .testCases(TestCaseLibrary.commandInjection()));
            }
        }
    }

    private void detectPathTraversal(Ctx c, Result r) {
        for (ParsedHttpParameter p : c.params) {
            if (LFI_PARAMS.contains(p.name().toLowerCase(Locale.ROOT))) {
                add(c, r, Finding.of(OwaspCategory.A03, "Path Traversal / LFI point")
                        .severity(Severity.HIGH).confidence(Confidence.SPECULATIVE)
                        .location(p.name())
                        .evidence("Parameter '" + p.name() + "' may map to a file path.")
                        .payloads(PayloadLibrary.PATH_TRAVERSAL)
                        .testCases(TestCaseLibrary.pathTraversal()));
            }
        }
    }

    private void detectXxe(Ctx c, Result r) {
        boolean xml = c.contentType.contains("xml") || c.requestBody.trim().startsWith("<?xml")
                || c.requestBody.contains("<!DOCTYPE");
        if (xml && !c.requestBody.isEmpty()) {
            add(c, r, Finding.of(OwaspCategory.A03, "XML input (XXE candidate)")
                    .severity(Severity.HIGH).confidence(Confidence.TENTATIVE)
                    .location("request body (XML)")
                    .evidence("Endpoint consumes XML — test external entity processing.")
                    .payloads(PayloadLibrary.XXE)
                    .testCases(TestCaseLibrary.xxe()));
        }
    }

    private void detectSsrf(Ctx c, Result r) {
        for (ParsedHttpParameter p : c.params) {
            String name = p.name().toLowerCase(Locale.ROOT);
            String val = p.value() == null ? "" : p.value().toLowerCase(Locale.ROOT);
            boolean looksUrl = val.startsWith("http") || val.contains("://") || val.contains("%3a%2f%2f");
            if (SSRF_PARAMS.contains(name) && (looksUrl || name.contains("url") || name.contains("uri"))) {
                add(c, r, Finding.of(OwaspCategory.A10, "SSRF candidate (URL-bearing parameter)")
                        .severity(Severity.HIGH).confidence(looksUrl ? Confidence.TENTATIVE : Confidence.SPECULATIVE)
                        .location(p.name())
                        .evidence("Parameter '" + p.name() + "' carries/expects a URL the server may fetch.")
                        .payloads(PayloadLibrary.SSRF)
                        .testCases(TestCaseLibrary.ssrf()));
            }
        }
    }

    private void detectAccessControl(Ctx c, Result r) {
        // IDOR: numeric/UUID id parameters, or numeric/UUID path segments.
        for (ParsedHttpParameter p : c.params) {
            String name = p.name().toLowerCase(Locale.ROOT);
            if (IDOR_PARAMS.contains(name) && p.value() != null
                    && (isNumeric(p.value()) || UUID_SEG.matcher(p.value()).matches())) {
                add(c, r, Finding.of(OwaspCategory.A01, "IDOR / BOLA candidate")
                        .severity(Severity.HIGH).confidence(Confidence.TENTATIVE)
                        .location(p.name())
                        .evidence("Direct object reference in '" + p.name() + "' = " + truncate(p.value(), 40))
                        .payloads(PayloadLibrary.IDOR)
                        .testCases(TestCaseLibrary.idor()));
            }
        }
        if (NUMERIC_SEG.matcher(c.path).find() || UUID_SEG.matcher(c.path).find()) {
            add(c, r, Finding.of(OwaspCategory.A01, "IDOR candidate (id in URL path)")
                    .severity(Severity.MEDIUM).confidence(Confidence.SPECULATIVE)
                    .location("URL path")
                    .evidence("Path embeds an object id: " + c.path)
                    .payloads(PayloadLibrary.IDOR)
                    .testCases(TestCaseLibrary.idor()));
        }
        // Force-browsing to sensitive areas.
        String lp = c.path.toLowerCase(Locale.ROOT);
        if (lp.contains("/admin") || lp.contains("/internal") || lp.contains("/manage")
                || lp.contains("/actuator") || lp.contains("/console") || lp.contains("/debug")) {
            add(c, r, Finding.of(OwaspCategory.A01, "Sensitive / admin endpoint")
                    .severity(Severity.MEDIUM).confidence(Confidence.TENTATIVE)
                    .location("URL path")
                    .evidence("Administrative-looking path: " + c.path)
                    .testCases(TestCaseLibrary.accessControl()));
        }
        // CSRF: state-changing request, cookie auth, no anti-CSRF token, weak SameSite.
        if (isStateChanging(c) && c.hasCookieAuth && !c.hasCsrfToken) {
            add(c, r, Finding.of(OwaspCategory.A01, "Potential CSRF (no anti-CSRF token)")
                    .severity(Severity.MEDIUM).confidence(Confidence.SPECULATIVE)
                    .location("request")
                    .evidence(c.method + " with cookie auth and no CSRF token / no strong SameSite seen.")
                    .testCases(Arrays.asList(
                            "Build a cross-site auto-submitting form/fetch and confirm the action executes.",
                            "Check SameSite on the auth cookie and whether a token is required & validated.")));
        }
    }

    private void detectOpenRedirect(Ctx c, Result r) {
        String location = headerValue(c.responseHeaders, "location");
        for (ParsedHttpParameter p : c.params) {
            if (!REDIRECT_PARAMS.contains(p.name().toLowerCase(Locale.ROOT))) continue;
            boolean reflectedInLocation = location != null && p.value() != null
                    && !p.value().isEmpty() && location.contains(p.value());
            Confidence conf = reflectedInLocation ? Confidence.FIRM : Confidence.SPECULATIVE;
            Severity sev = reflectedInLocation ? Severity.MEDIUM : Severity.LOW;
            add(c, r, Finding.of(OwaspCategory.A01, "Open Redirect candidate")
                    .severity(sev).confidence(conf)
                    .location(p.name())
                    .evidence(reflectedInLocation
                            ? "Parameter '" + p.name() + "' is reflected into the Location header."
                            : "Redirect-style parameter '" + p.name() + "'.")
                    .payloads(PayloadLibrary.OPEN_REDIRECT)
                    .testCases(TestCaseLibrary.openRedirect()));
        }
    }

    private void detectAuth(Ctx c, Result r) {
        String lp = c.path.toLowerCase(Locale.ROOT);
        for (String tok : AUTH_PATH_TOKENS) {
            if (lp.contains(tok)) {
                add(c, r, Finding.of(OwaspCategory.A07, "Authentication endpoint")
                        .severity(Severity.MEDIUM).confidence(Confidence.TENTATIVE)
                        .location("URL path")
                        .evidence("Auth-related path ('" + tok + "'): " + c.path)
                        .testCases(TestCaseLibrary.auth()));
                break;
            }
        }
    }

    private void detectJwt(Ctx c, Result r) {
        Set<String> seen = new HashSet<>();
        for (String hay : c.jwtHaystacks()) {
            Matcher m = JWT.matcher(hay);
            while (m.find()) {
                String token = m.group();
                if (!seen.add(token)) continue;
                String alg = jwtAlg(token);
                Severity sev = Severity.MEDIUM;
                String note = "JWT detected (alg=" + (alg == null ? "?" : alg) + ").";
                if (alg != null && alg.equalsIgnoreCase("none")) {
                    sev = Severity.HIGH;
                    note = "JWT uses alg=none — unsigned token accepted?";
                }
                add(c, r, Finding.of(OwaspCategory.JWT, "JWT in use (alg=" + (alg == null ? "?" : alg) + ")")
                        .severity(sev).confidence(Confidence.FIRM)
                        .location("token: " + truncate(token, 28) + "…")
                        .evidence(note)
                        .payloads(PayloadLibrary.JWT_SECRETS)
                        .testCases(TestCaseLibrary.jwt(alg)));
            }
        }
    }

    private void detectOAuth(Ctx c, Result r) {
        String responseType = c.paramVal("response_type");
        String grantType = c.paramVal("grant_type");
        boolean hasClientId = c.hasParam("client_id");
        boolean hasRedirect = c.hasParam("redirect_uri");
        boolean hasCode = c.hasParam("code");
        boolean isTokenEndpoint = c.path.toLowerCase(Locale.ROOT).matches(".*/(oauth2?|connect)/(token|authorize).*")
                || c.path.toLowerCase(Locale.ROOT).endsWith("/token")
                || c.path.toLowerCase(Locale.ROOT).contains("/authorize");

        boolean isOAuth = responseType != null || grantType != null || isTokenEndpoint
                || (hasClientId && (hasRedirect || hasCode));
        if (!isOAuth) return;

        boolean hasState = c.hasParam("state");
        boolean hasPkce = c.hasParam("code_challenge") || c.hasParam("code_verifier");

        String flow = grantType != null ? "grant_type=" + grantType
                : responseType != null ? "response_type=" + responseType
                : isTokenEndpoint ? "token/authorize endpoint" : "client_id flow";

        Severity sev = (!hasState || (!hasPkce && "code".equalsIgnoreCase(responseType)))
                ? Severity.HIGH : Severity.MEDIUM;

        add(c, r, Finding.of(OwaspCategory.OAUTH, "OAuth 2.0 flow (" + flow + ")")
                .severity(sev).confidence(Confidence.FIRM)
                .location(hasRedirect ? "redirect_uri" : "OAuth params")
                .evidence("OAuth detected — " + flow
                        + (hasState ? "" : ", NO state")
                        + (hasPkce ? ", PKCE present" : ", no PKCE"))
                .testCases(TestCaseLibrary.oauth(responseType, grantType, hasState, hasPkce)));
    }

    private void detectSaml(Ctx c, Result r) {
        boolean resp = c.hasParam("SAMLResponse");
        boolean req = c.hasParam("SAMLRequest");
        if (!resp && !req) return;
        add(c, r, Finding.of(OwaspCategory.SAML, resp ? "SAMLResponse (assertion)" : "SAMLRequest")
                .severity(Severity.HIGH).confidence(Confidence.FIRM)
                .location(resp ? "SAMLResponse" : "SAMLRequest")
                .evidence("SAML SSO message observed — high-value signature/assertion attack surface.")
                .testCases(TestCaseLibrary.saml(resp)));
    }

    private void detectCrypto(Ctx c, Result r) {
        // Sensitive material over cleartext HTTP.
        if (!c.secure) {
            boolean sensitive = c.hasParam("password") || c.hasParam("pass") || c.hasParam("pwd")
                    || c.hasParam("token") || c.hasParam("secret") || c.hasParam("apikey")
                    || c.hasParam("api_key") || headerValue(c.requestHeaders, "authorization") != null
                    || headerValue(c.requestHeaders, "cookie") != null;
            if (sensitive) {
                add(c, r, Finding.of(OwaspCategory.A02, "Sensitive data over cleartext HTTP")
                        .severity(Severity.HIGH).confidence(Confidence.FIRM)
                        .location("transport")
                        .evidence("Credentials/tokens/session sent over plain HTTP (no TLS).")
                        .testCases(Arrays.asList(
                                "Confirm the same endpoint is reachable only over HTTPS; check HSTS.",
                                "Look for credential/token capture opportunity on the network path.")));
            }
        }
        // Weak cookie flags.
        for (String sc : headerValues(c.responseHeaders, "set-cookie")) {
            String low = sc.toLowerCase(Locale.ROOT);
            List<String> missing = new ArrayList<>();
            if (!low.contains("httponly")) missing.add("HttpOnly");
            if (!low.contains("secure")) missing.add("Secure");
            if (!low.contains("samesite")) missing.add("SameSite");
            if (!missing.isEmpty()) {
                String cookieName = sc.contains("=") ? sc.substring(0, sc.indexOf('=')).trim() : "cookie";
                add(c, r, Finding.of(OwaspCategory.A02, "Weak cookie flags")
                        .severity(Severity.LOW).confidence(Confidence.FIRM)
                        .location(cookieName)
                        .evidence("Set-Cookie '" + cookieName + "' missing: " + String.join(", ", missing))
                        .testCases(Arrays.asList(
                                "If a session/auth cookie, escalate: missing HttpOnly -> XSS theft; missing Secure -> MITM.",
                                "Missing SameSite enables CSRF — chain with a state-changing request.")));
            }
        }
    }

    private void detectMisconfig(Ctx c, Result r) {
        boolean htmlDoc = c.contentType.contains("html") && c.statusCode >= 200 && c.statusCode < 300;
        if (htmlDoc) {
            List<String> missing = new ArrayList<>();
            for (String h : SECURITY_HEADERS) {
                if (headerValue(c.responseHeaders, h) == null) missing.add(h);
            }
            if (!missing.isEmpty()) {
                add(c, r, Finding.of(OwaspCategory.A05, "Missing security headers")
                        .severity(Severity.LOW).confidence(Confidence.FIRM)
                        .location("response headers")
                        .evidence("Missing: " + String.join(", ", missing))
                        .testCases(TestCaseLibrary.misconfig()));
            }
        }
        // CORS misconfiguration.
        String acao = headerValue(c.responseHeaders, "access-control-allow-origin");
        String acac = headerValue(c.responseHeaders, "access-control-allow-credentials");
        String origin = headerValue(c.requestHeaders, "origin");
        if (acao != null) {
            boolean reflected = origin != null && acao.equalsIgnoreCase(origin);
            boolean wildcardCreds = "*".equals(acao) && "true".equalsIgnoreCase(acac == null ? "" : acac);
            if (reflected || wildcardCreds || (reflected && "true".equalsIgnoreCase(acac == null ? "" : acac))) {
                add(c, r, Finding.of(OwaspCategory.A05, "Permissive CORS policy")
                        .severity(reflected && "true".equalsIgnoreCase(acac == null ? "" : acac)
                                ? Severity.HIGH : Severity.MEDIUM)
                        .confidence(Confidence.FIRM)
                        .location("Access-Control-Allow-Origin")
                        .evidence("ACAO=" + acao + (acac != null ? ", ACAC=" + acac : "")
                                + (reflected ? " (reflects Origin)" : ""))
                        .testCases(Arrays.asList(
                                "Send Origin: https://evil and confirm it is reflected with credentials:true.",
                                "If credentialed, read authenticated responses cross-origin (account takeover impact).")));
            }
        }
        // Verbose errors / stack traces.
        if (STACKTRACE.matcher(c.responseBody).find()) {
            add(c, r, Finding.of(OwaspCategory.A05, "Verbose error / stack trace leak")
                    .severity(Severity.MEDIUM).confidence(Confidence.FIRM)
                    .location("response body")
                    .evidence("Server returned a stack trace / detailed error (info leak, possible injection oracle).")
                    .testCases(Arrays.asList(
                            "Mine the trace for tech stack, file paths, and SQL — pivot to injection.",
                            "Recommend generic error pages and server-side logging only.")));
        }
    }

    private void detectVulnComponents(Ctx c, Result r) {
        String server = headerValue(c.responseHeaders, "server");
        String powered = headerValue(c.responseHeaders, "x-powered-by");
        if ((server != null && server.matches(".*\\d.*")) || powered != null) {
            String banner = (server != null ? "Server: " + server : "")
                    + (powered != null ? (server != null ? "; " : "") + "X-Powered-By: " + powered : "");
            add(c, r, Finding.of(OwaspCategory.A06, "Version banner disclosed")
                    .severity(Severity.LOW).confidence(Confidence.FIRM)
                    .location("response headers")
                    .evidence(banner)
                    .testCases(Arrays.asList(
                            "Map the disclosed version to known CVEs (search NVD / exploit-db).",
                            "Recommend suppressing version banners.")));
        }
    }

    private void detectIntegrity(Ctx c, Result r) {
        String hay = c.requestBody + " " + c.allParamValues;
        String reason = null;
        if (hay.contains("rO0AB")) reason = "Java serialized object (rO0AB...) in request.";
        else if (hay.contains("AAEAAAD/////")) reason = ".NET BinaryFormatter blob in request.";
        else if (PHP_SERIALIZED.matcher(hay).find()) reason = "PHP serialized object (O:n:\"...\") in request.";
        if (reason != null) {
            add(c, r, Finding.of(OwaspCategory.A08, "Insecure deserialization candidate")
                    .severity(Severity.HIGH).confidence(Confidence.TENTATIVE)
                    .location("request body / parameter")
                    .evidence(reason)
                    .testCases(TestCaseLibrary.deserialization()));
        }
    }

    private void detectSecrets(Ctx c, Result r) {
        String hay = c.responseBody + "\n" + c.requestBody;
        if (hay.isEmpty()) return;
        for (int i = 0; i < SECRET_REGEX.length; i++) {
            // JWTs are handled richly by detectJwt; here we only flag JWTs sitting
            // in a *response body* (a token leak), not ones in the request.
            if (SECRET_REGEX[i] == JWT && !c.responseBody.contains("eyJ")) continue;
            Matcher m = SECRET_REGEX[i].matcher(hay);
            if (m.find()) {
                add(c, r, Finding.of(OwaspCategory.A02, "Exposed secret: " + SECRET_NAMES[i])
                        .severity(Severity.HIGH).confidence(Confidence.FIRM)
                        .location(SECRET_NAMES[i])
                        .evidence("Matched " + SECRET_NAMES[i] + " pattern (" + truncate(m.group(), 10)
                                + "…) in traffic — verify and rotate.")
                        .testCases(TestCaseLibrary.secret()));
            }
        }
    }

    private void detectLogging(Ctx c, Result r) {
        if (c.hasParam("debug") || c.hasParam("test") || c.hasParam("verbose")
                || headerValue(c.responseHeaders, "x-debug") != null) {
            add(c, r, Finding.of(OwaspCategory.A09, "Debug/diagnostic flag exposed")
                    .severity(Severity.LOW).confidence(Confidence.SPECULATIVE)
                    .location("debug parameter/header")
                    .evidence("Client-controllable debug/verbose switch present.")
                    .testCases(Arrays.asList(
                            "Toggle debug=true and look for extra data, stack traces, or behaviour change.",
                            "Confirm security-relevant events are logged server-side and not exposed to clients.")));
        }
    }

    private void detectInsecureDesign(Ctx c, Result r) {
        // State-changing action delivered via GET = design smell (CSRF-by-GET, replay).
        String lp = c.path.toLowerCase(Locale.ROOT) + " " + c.allParamValues.toLowerCase(Locale.ROOT);
        boolean mutatingWord = lp.contains("delete") || lp.contains("remove") || lp.contains("transfer")
                || lp.contains("update") || lp.contains("approve") || lp.contains("grant")
                || lp.contains("disable") || lp.contains("reset");
        if ("GET".equalsIgnoreCase(c.method) && mutatingWord) {
            add(c, r, Finding.of(OwaspCategory.A04, "State-changing action over GET")
                    .severity(Severity.MEDIUM).confidence(Confidence.SPECULATIVE)
                    .location("URL")
                    .evidence("GET appears to perform a mutating action: " + c.path)
                    .testCases(Arrays.asList(
                            "Confirm the GET actually changes state; if so it is trivially CSRF-able & cacheable.",
                            "Recommend POST + anti-CSRF token + re-auth for sensitive actions.")));
        }
    }

    // --- dedup core -------------------------------------------------------

    private void add(Ctx c, Result r, Finding.Builder b) {
        Finding f = b.endpoint(c.method, c.host, c.port, c.secure, c.url, c.path)
                .requestResponse(c.rr)
                .build();
        if (suppressedTypes.contains(f.typeKey())) {
            return; // user marked this whole issue type as noise
        }
        Finding existing = store.putIfAbsent(f.dedupKey(), f);
        if (existing == null) {
            r.created.add(f);
        } else {
            existing.hits.incrementAndGet();
            if (!r.repeated.contains(existing)) r.repeated.add(existing);
        }
    }

    // --- per-message parsed context ---------------------------------------

    private static final class Ctx {
        final HttpRequestResponse rr;
        final HttpRequest req;
        final HttpResponse resp;
        final String method, host, url, path, contentType;
        final int port, statusCode;
        final boolean secure;
        final List<ParsedHttpParameter> params;
        final List<burp.api.montoya.http.message.HttpHeader> requestHeaders;
        final List<burp.api.montoya.http.message.HttpHeader> responseHeaders;
        final String requestBody, responseBody, allParamValues;
        final boolean hasCookieAuth, hasCsrfToken;

        Ctx(HttpRequestResponse rr) {
            this.rr = rr;
            this.req = rr.request();
            this.resp = rr.response();
            this.method = safe(req.method());
            this.host = req.httpService() != null ? req.httpService().host() : "";
            this.port = req.httpService() != null ? req.httpService().port() : 0;
            this.secure = req.httpService() != null && req.httpService().secure();
            this.url = safe(req.url());
            String p = safe(req.path());
            int q = p.indexOf('?');
            this.path = q >= 0 ? p.substring(0, q) : p;
            this.params = req.parameters();
            this.requestHeaders = req.headers();
            this.responseHeaders = resp != null ? resp.headers() : java.util.Collections.emptyList();
            this.requestBody = safe(req.bodyToString());
            this.responseBody = resp != null ? capped(resp.bodyToString()) : "";
            this.statusCode = resp != null ? resp.statusCode() : 0;
            this.contentType = headerValueStatic(responseHeaders, "content-type");

            StringBuilder vals = new StringBuilder();
            for (ParsedHttpParameter pp : params) {
                if (pp.value() != null) vals.append(pp.value()).append(' ');
            }
            this.allParamValues = vals.toString();
            this.hasCookieAuth = headerValueStatic(requestHeaders, "cookie") != null;
            this.hasCsrfToken = hasCsrf();
        }

        boolean hasCsrf() {
            for (burp.api.montoya.http.message.HttpHeader h : requestHeaders) {
                String n = h.name().toLowerCase(Locale.ROOT);
                if (n.contains("csrf") || n.equals("x-xsrf-token") || n.equals("x-requested-with")) return true;
            }
            for (ParsedHttpParameter p : params) {
                String n = p.name().toLowerCase(Locale.ROOT);
                if (n.contains("csrf") || n.contains("xsrf") || n.equals("_token") || n.equals("authenticity_token"))
                    return true;
            }
            return false;
        }

        boolean hasParam(String name) {
            for (ParsedHttpParameter p : params) {
                if (p.name().equalsIgnoreCase(name)) return true;
            }
            return false;
        }

        String paramVal(String name) {
            for (ParsedHttpParameter p : params) {
                if (p.name().equalsIgnoreCase(name)) return p.value();
            }
            return null;
        }

        /** Places a JWT might live: Authorization header, cookies, params, response body. */
        List<String> jwtHaystacks() {
            List<String> hs = new ArrayList<>();
            String auth = headerValueStatic(requestHeaders, "authorization");
            if (auth != null) hs.add(auth);
            String cookie = headerValueStatic(requestHeaders, "cookie");
            if (cookie != null) hs.add(cookie);
            for (ParsedHttpParameter p : params) {
                if (p.value() != null) hs.add(p.value());
            }
            String setCookie = headerValueStatic(responseHeaders, "set-cookie");
            if (setCookie != null) hs.add(setCookie);
            if (responseBody.contains("eyJ")) hs.add(responseBody);
            return hs;
        }
    }

    // --- small helpers ----------------------------------------------------

    private static String jwtAlg(String token) {
        try {
            String headerB64 = token.split("\\.")[0];
            byte[] decoded = Base64.getUrlDecoder().decode(pad(headerB64));
            String header = new String(decoded, StandardCharsets.UTF_8);
            Matcher m = ALG.matcher(header);
            return m.find() ? m.group(1) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String pad(String b64) {
        int mod = b64.length() % 4;
        if (mod == 0) return b64;
        StringBuilder sb = new StringBuilder(b64);
        for (int i = 0; i < 4 - mod; i++) sb.append('=');
        return sb.toString();
    }

    private static boolean isStateChanging(Ctx c) {
        String m = c.method.toUpperCase(Locale.ROOT);
        return m.equals("POST") || m.equals("PUT") || m.equals("DELETE") || m.equals("PATCH");
    }

    private static boolean isNumeric(String s) {
        if (s == null || s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) return false;
        }
        return true;
    }

    private static String headerValue(List<burp.api.montoya.http.message.HttpHeader> headers, String name) {
        return headerValueStatic(headers, name);
    }

    private static String headerValueStatic(List<burp.api.montoya.http.message.HttpHeader> headers, String name) {
        if (headers == null) return null;
        for (burp.api.montoya.http.message.HttpHeader h : headers) {
            if (h.name().equalsIgnoreCase(name)) return h.value();
        }
        return null;
    }

    private static List<String> headerValues(List<burp.api.montoya.http.message.HttpHeader> headers, String name) {
        List<String> out = new ArrayList<>();
        if (headers == null) return out;
        for (burp.api.montoya.http.message.HttpHeader h : headers) {
            if (h.name().equalsIgnoreCase(name)) out.add(h.value());
        }
        return out;
    }

    private static String safe(String s) { return s == null ? "" : s; }

    private static String capped(String s) {
        if (s == null) return "";
        return s.length() > 200_000 ? s.substring(0, 200_000) : s;
    }

    private static String truncate(String s, int n) {
        if (s == null) return "";
        return s.length() <= n ? s : s.substring(0, n);
    }

    private static Set<String> setOf(String... items) {
        return new HashSet<>(Arrays.asList(items));
    }
}
