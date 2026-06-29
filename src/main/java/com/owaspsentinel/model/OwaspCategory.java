package com.owaspsentinel.model;

/**
 * OWASP Top 10 (2021) categories, plus three cross-cutting "modules" the user
 * asked to call out explicitly (JWT, OAuth 2.0, SAML). The modules still map to
 * a real Top-10 bucket via {@link #parent}, but get their own row group so they
 * are easy to find in the UI.
 */
public enum OwaspCategory {

    A01("A01:2021", "Broken Access Control",
            "Enforce access control server-side; deny by default; reject client-supplied IDs."),
    A02("A02:2021", "Cryptographic Failures",
            "Force TLS everywhere; mark cookies Secure/HttpOnly; never expose secrets/PII in transit or responses."),
    A03("A03:2021", "Injection",
            "Use parameterised queries, context-aware output encoding, and strict input validation."),
    A04("A04:2021", "Insecure Design",
            "Add threat-modelling, rate limits, and secure design patterns for the affected flow."),
    A05("A05:2021", "Security Misconfiguration",
            "Harden headers (CSP/HSTS/X-Frame-Options), disable verbose errors, lock down CORS."),
    A06("A06:2021", "Vulnerable & Outdated Components",
            "Remove version banners; inventory and patch server/framework components."),
    A07("A07:2021", "Identification & Authentication Failures",
            "Strengthen auth: MFA, session fixation defence, secure token handling, lockout."),
    A08("A08:2021", "Software & Data Integrity Failures",
            "Verify signatures/integrity; avoid insecure deserialization; pin update sources."),
    A09("A09:2021", "Security Logging & Monitoring Failures",
            "Log security events server-side; never leak internal logging/debug to clients."),
    A10("A10:2021", "Server-Side Request Forgery (SSRF)",
            "Allow-list outbound destinations; block internal ranges/metadata; validate URLs."),

    // Cross-cutting modules (explicitly requested).
    JWT("MOD-JWT", "JSON Web Token (JWT)", A08,
            "Pin a strong algorithm server-side; reject 'none'; validate signature, kid, exp, aud, iss."),
    OAUTH("MOD-OAUTH", "OAuth 2.0 / OIDC", A07,
            "Enforce state/PKCE, exact redirect_uri matching, short-lived single-use codes."),
    SAML("MOD-SAML", "SAML 2.0 SSO", A07,
            "Validate signatures over the whole assertion; defend against XSW; check audience/recipient.");

    public final String id;
    public final String title;
    public final OwaspCategory parent; // null for the real Top-10 buckets
    public final String remediation;

    OwaspCategory(String id, String title, String remediation) {
        this(id, title, null, remediation);
    }

    OwaspCategory(String id, String title, OwaspCategory parent, String remediation) {
        this.id = id;
        this.title = title;
        this.parent = parent;
        this.remediation = remediation;
    }

    /** e.g. "A03:2021 - Injection" */
    public String label() {
        return id + " - " + title;
    }
}
