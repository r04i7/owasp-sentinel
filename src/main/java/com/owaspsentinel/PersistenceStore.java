package com.owaspsentinel;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import com.owaspsentinel.model.Confidence;
import com.owaspsentinel.model.Finding;
import com.owaspsentinel.model.OwaspCategory;
import com.owaspsentinel.model.Severity;
import com.owaspsentinel.model.Status;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Saves and restores findings, triage verdicts, scope settings and suppression
 * rules in Burp's <b>project-data</b> store ({@code persistence().extensionData()}).
 *
 * Because that store lives inside the Burp <i>project file</i>, persistence is
 * naturally project-scoped: reopen an old project and its findings come back;
 * open a different project and you see that project's data; start a brand-new
 * project and the table is empty. (Note: Burp Community uses temporary,
 * non-saved projects, so cross-restart persistence needs Burp Pro saved projects.)
 *
 * The full {@link burp.api.montoya.http.message.HttpRequestResponse} is stored
 * per finding, so "Send to Repeater" and the request/response viewers keep
 * working after a reload.
 */
public final class PersistenceStore {

    private static final String SEP = ""; // joins list items inside one string

    private final MontoyaApi api;

    public PersistenceStore(MontoyaApi api) {
        this.api = api;
    }

    /** Everything restored from the project file in one shot. */
    public static final class Loaded {
        public final List<Finding> findings = new ArrayList<>();
        public final Set<String> suppressedTypes = new HashSet<>();
        public String scopeText = "";
        public boolean useBurpScope = false;
        public boolean includeIdps = true;
        public boolean matchSubdomains = true;
    }

    // --- save -------------------------------------------------------------

    public synchronized void save(List<Finding> findings, String scopeText, boolean useBurpScope,
                                  boolean includeIdps, boolean matchSubdomains, Set<String> suppressed) {
        PersistedObject root = api.persistence().extensionData();

        root.setInteger("count", findings.size());
        for (int i = 0; i < findings.size(); i++) {
            root.setChildObject("f" + i, toChild(findings.get(i)));
        }

        root.setString("scope.text", scopeText == null ? "" : scopeText);
        root.setBoolean("scope.useBurp", useBurpScope);
        root.setBoolean("scope.idp", includeIdps);
        root.setBoolean("scope.sub", matchSubdomains);
        root.setString("suppressed", String.join(SEP, suppressed));
    }

    private PersistedObject toChild(Finding f) {
        PersistedObject c = PersistedObject.persistedObject();
        c.setString("category", f.category.name());
        c.setString("subtype", f.subtype);
        c.setString("severity", f.severity.name());
        c.setString("confidence", f.confidence.name());
        c.setString("status", f.getStatus().name());
        c.setInteger("hits", f.hits.get());
        c.setString("location", f.location);
        c.setString("evidence", f.evidence);
        c.setString("remediation", f.remediation);
        c.setString("method", f.method);
        c.setString("host", f.host);
        c.setInteger("port", f.port);
        c.setBoolean("secure", f.secure);
        c.setString("url", f.url);
        c.setString("path", f.path);
        c.setString("payloads", String.join(SEP, f.payloads));
        c.setString("testcases", String.join(SEP, f.testCases));
        if (f.requestResponse != null) {
            c.setHttpRequestResponse("rr", f.requestResponse);
        }
        return c;
    }

    // --- load -------------------------------------------------------------

    public synchronized Loaded load() {
        Loaded out = new Loaded();
        PersistedObject root = api.persistence().extensionData();

        Integer count = root.getInteger("count");
        int n = count == null ? 0 : count;
        for (int i = 0; i < n; i++) {
            PersistedObject c = root.getChildObject("f" + i);
            if (c == null) continue;
            try {
                out.findings.add(fromChild(c));
            } catch (Exception ex) {
                api.logging().logToError("OWASP Sentinel: skipped a corrupt persisted finding: " + ex);
            }
        }

        out.scopeText = orEmpty(root.getString("scope.text"));
        out.useBurpScope = orFalse(root.getBoolean("scope.useBurp"));
        out.includeIdps = root.getBoolean("scope.idp") == null ? true : root.getBoolean("scope.idp");
        out.matchSubdomains = root.getBoolean("scope.sub") == null ? true : root.getBoolean("scope.sub");

        String suppressed = root.getString("suppressed");
        if (suppressed != null && !suppressed.isEmpty()) {
            out.suppressedTypes.addAll(Arrays.asList(suppressed.split(SEP)));
        }
        return out;
    }

    private Finding fromChild(PersistedObject c) {
        OwaspCategory category = OwaspCategory.valueOf(c.getString("category"));
        Integer hits = c.getInteger("hits");
        Integer port = c.getInteger("port");
        return Finding.of(category, orEmpty(c.getString("subtype")))
                .severity(Severity.valueOf(c.getString("severity")))
                .confidence(Confidence.valueOf(c.getString("confidence")))
                .status(Status.valueOf(c.getString("status")))
                .hits(hits == null ? 1 : hits)
                .location(orEmpty(c.getString("location")))
                .evidence(orEmpty(c.getString("evidence")))
                .remediation(orEmpty(c.getString("remediation")))
                .endpoint(orEmpty(c.getString("method")), orEmpty(c.getString("host")),
                        port == null ? 0 : port, orFalse(c.getBoolean("secure")),
                        orEmpty(c.getString("url")), orEmpty(c.getString("path")))
                .payloads(split(c.getString("payloads")))
                .testCases(split(c.getString("testcases")))
                .requestResponse(c.getHttpRequestResponse("rr"))
                .build();
    }

    // --- helpers ----------------------------------------------------------

    private static List<String> split(String joined) {
        if (joined == null || joined.isEmpty()) return new ArrayList<>();
        return new ArrayList<>(Arrays.asList(joined.split(SEP)));
    }

    private static String orEmpty(String s) { return s == null ? "" : s; }
    private static boolean orFalse(Boolean b) { return b != null && b; }
}
