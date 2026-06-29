package com.owaspsentinel;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Decides whether (and how deeply) a piece of live proxy traffic should be
 * analysed. Three outcomes:
 *
 * <ul>
 *   <li>{@code FULL}  — host is in the user's target scope (or no scope is set):
 *       run every detector.</li>
 *   <li>{@code SSO}   — host is out of target scope but is a known Identity
 *       Provider (Microsoft/Google/Okta/…): run only the JWT/OAuth/SAML modules,
 *       so login redirects are still covered without flooding the table with
 *       findings about the IdP's own site.</li>
 *   <li>{@code OUT}   — skip entirely.</li>
 * </ul>
 *
 * Manual right-click scans bypass this and always run FULL — if you explicitly
 * asked to scan something, scope shouldn't second-guess you.
 */
public final class ScopeManager {

    public enum Decision { FULL, SSO, OUT }

    /** Built-in SSO / IdP host suffixes, matched against the request host. */
    private static final List<String> IDP_SUFFIXES = Arrays.asList(
            // Microsoft / Azure AD / Entra ID / ADFS / B2C
            "login.microsoftonline.com", "login.microsoftonline.us", "login.partner.microsoftonline.cn",
            "login.microsoft.com", "login.live.com", "login.windows.net", "sts.windows.net",
            "microsoftonline.com", "b2clogin.com", "account.activedirectory.windowsazure.com",
            "msftauth.net", "microsoft.com",
            // Google
            "accounts.google.com", "oauth2.googleapis.com", "googleapis.com",
            // Okta / Auth0 / Ping / OneLogin / ForgeRock
            "okta.com", "oktapreview.com", "okta-emea.com", "auth0.com",
            "onelogin.com", "pingidentity.com", "pingone.com", "forgerock.io",
            // Others
            "login.salesforce.com", "appleid.apple.com", "id.atlassian.com",
            "amazoncognito.com", "signin.aws.amazon.com", "duosecurity.com",
            "login.yahoo.com", "facebook.com", "github.com", "gitlab.com");

    private final MontoyaApi api;

    private volatile List<Entry> userEntries = new ArrayList<>();
    private volatile boolean useBurpScope = false;
    private volatile boolean includeIdps = true;     // default ON, as requested
    private volatile boolean matchSubdomains = true;

    public ScopeManager(MontoyaApi api) {
        this.api = api;
    }

    // --- configuration ----------------------------------------------------

    /** Accepts a comma/space/newline-separated list of hosts or URLs. */
    public void setScopeText(String raw) {
        List<Entry> parsed = new ArrayList<>();
        if (raw != null) {
            for (String tok : raw.split("[\\s,;]+")) {
                Entry e = Entry.parse(tok);
                if (e != null) parsed.add(e);
            }
        }
        this.userEntries = parsed;
    }

    public void setUseBurpScope(boolean v) { this.useBurpScope = v; }
    public void setIncludeIdps(boolean v) { this.includeIdps = v; }
    public void setMatchSubdomains(boolean v) { this.matchSubdomains = v; }

    public boolean hasUserScope() { return !userEntries.isEmpty(); }

    // --- decision ---------------------------------------------------------

    public Decision decide(HttpRequest req) {
        if (req == null || req.httpService() == null) return Decision.OUT;
        String host = req.httpService().host().toLowerCase(Locale.ROOT);
        String url = safe(req.url());
        String path = pathOf(req);

        boolean noScopeConfigured = userEntries.isEmpty() && !useBurpScope;
        if (noScopeConfigured) {
            return Decision.FULL; // nothing configured yet -> scan everything
        }
        if (matchesUser(host, path) || (useBurpScope && api.scope().isInScope(url))) {
            return Decision.FULL;
        }
        if (includeIdps && isIdp(host)) {
            return Decision.SSO; // login redirect to a known IdP
        }
        return Decision.OUT;
    }

    public boolean isIdp(String host) {
        if (host == null) return false;
        String h = host.toLowerCase(Locale.ROOT);
        for (String s : IDP_SUFFIXES) {
            if (h.equals(s) || h.endsWith("." + s)) return true;
        }
        return false;
    }

    public String summary() {
        if (userEntries.isEmpty() && !useBurpScope) {
            return "No scope set — scanning ALL proxied traffic. Enter target host(s) to restrict.";
        }
        StringBuilder sb = new StringBuilder("In scope: ");
        if (!userEntries.isEmpty()) {
            List<String> names = new ArrayList<>();
            for (Entry e : userEntries) names.add(e.toString());
            sb.append(String.join(", ", names));
        }
        if (useBurpScope) sb.append(userEntries.isEmpty() ? "" : " + ").append("Burp Suite scope");
        sb.append(matchSubdomains ? " (incl. subdomains)" : "");
        sb.append(includeIdps ? " | SSO/IdP domains auto-included" : " | SSO auto-include OFF");
        return sb.toString();
    }

    // --- matching ---------------------------------------------------------

    private boolean matchesUser(String host, String path) {
        for (Entry e : userEntries) {
            boolean hostOk = host.equals(e.host) || (matchSubdomains && host.endsWith("." + e.host));
            boolean pathOk = e.path.isEmpty() || e.path.equals("/") || path.startsWith(e.path);
            if (hostOk && pathOk) return true;
        }
        return false;
    }

    private static String pathOf(HttpRequest req) {
        String p = safe(req.path());
        int q = p.indexOf('?');
        return q >= 0 ? p.substring(0, q) : p;
    }

    private static String safe(String s) { return s == null ? "" : s; }

    /** A normalised scope entry: host (no scheme/port) + optional path prefix. */
    private static final class Entry {
        final String host;
        final String path;

        private Entry(String host, String path) {
            this.host = host;
            this.path = path;
        }

        static Entry parse(String token) {
            if (token == null) return null;
            String t = token.trim().toLowerCase(Locale.ROOT);
            if (t.isEmpty()) return null;
            int scheme = t.indexOf("://");
            if (scheme >= 0) t = t.substring(scheme + 3);
            if (t.startsWith("*.")) t = t.substring(2); // wildcard -> rely on subdomain match
            String host = t;
            String path = "";
            int slash = t.indexOf('/');
            if (slash >= 0) {
                host = t.substring(0, slash);
                path = t.substring(slash);
            }
            int colon = host.indexOf(':'); // drop any :port
            if (colon >= 0) host = host.substring(0, colon);
            if (host.isEmpty()) return null;
            return new Entry(host, path);
        }

        @Override
        public String toString() {
            return host + (path.isEmpty() ? "" : path);
        }
    }
}
