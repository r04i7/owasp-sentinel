package com.owaspsentinel.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * One detected issue against a specific endpoint. Findings are de-duplicated by
 * {@link #dedupKey()} (category + subtype + method + host + path + location), so
 * the same endpoint hit repeatedly produces a single row whose {@link #hits}
 * counter increments. Built via the fluent {@link Builder}.
 */
public final class Finding {

    public final OwaspCategory category;
    public final String subtype;       // e.g. "Reflected XSS", "SQL Injection point"
    public final Severity severity;
    public final Confidence confidence;

    public final String method;
    public final String host;
    public final int port;
    public final boolean secure;
    public final String url;
    public final String path;          // path without query, for dedup + display
    public final String location;      // affected parameter / header / cookie name

    public final String evidence;      // short "why this fired" note
    public final List<String> payloads;
    public final List<String> testCases;
    public final String remediation;

    /** The traffic that triggered the finding — used for Repeater / editors. */
    public final HttpRequestResponse requestResponse;

    /** Times this exact endpoint+issue has been seen (1 on first detection). */
    public final AtomicInteger hits;

    /** Triage verdict — mutable, persisted. */
    private volatile Status status;

    private Finding(Builder b) {
        this.category = b.category;
        this.subtype = b.subtype;
        this.severity = b.severity;
        this.confidence = b.confidence;
        this.method = b.method;
        this.host = b.host;
        this.port = b.port;
        this.secure = b.secure;
        this.url = b.url;
        this.path = b.path;
        this.location = b.location == null ? "" : b.location;
        this.evidence = b.evidence == null ? "" : b.evidence;
        this.payloads = Collections.unmodifiableList(new ArrayList<>(b.payloads));
        this.testCases = Collections.unmodifiableList(new ArrayList<>(b.testCases));
        this.remediation = b.remediation != null ? b.remediation : b.category.remediation;
        this.requestResponse = b.requestResponse;
        this.hits = new AtomicInteger(b.hits);
        this.status = b.status;
    }

    public String dedupKey() {
        return category.id + "|" + subtype + "|" + method + "|" + host + ":" + port
                + "|" + path + "|" + location.toLowerCase();
    }

    /** Identifies the issue *type* (category + subtype), for type-level suppression. */
    public String typeKey() {
        return category.name() + "" + subtype;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public static Builder of(OwaspCategory category, String subtype) {
        return new Builder(category, subtype);
    }

    public static final class Builder {
        private final OwaspCategory category;
        private final String subtype;
        private Severity severity = Severity.MEDIUM;
        private Confidence confidence = Confidence.TENTATIVE;
        private String method = "GET";
        private String host = "";
        private int port = 0;
        private boolean secure;
        private String url = "";
        private String path = "";
        private String location;
        private String evidence;
        private final List<String> payloads = new ArrayList<>();
        private final List<String> testCases = new ArrayList<>();
        private String remediation;
        private HttpRequestResponse requestResponse;
        private int hits = 1;
        private Status status = Status.NEW;

        private Builder(OwaspCategory category, String subtype) {
            this.category = category;
            this.subtype = subtype;
        }

        public Builder severity(Severity s) { this.severity = s; return this; }
        public Builder confidence(Confidence c) { this.confidence = c; return this; }
        public Builder location(String l) { this.location = l; return this; }
        public Builder evidence(String e) { this.evidence = e; return this; }
        public Builder remediation(String r) { this.remediation = r; return this; }
        public Builder requestResponse(HttpRequestResponse rr) { this.requestResponse = rr; return this; }
        public Builder hits(int h) { this.hits = h; return this; }
        public Builder status(Status s) { this.status = s; return this; }

        public Builder payloads(List<String> p) {
            if (p != null) this.payloads.addAll(p);
            return this;
        }

        public Builder testCases(List<String> t) {
            if (t != null) this.testCases.addAll(t);
            return this;
        }

        /** Copies the endpoint coordinates straight off the request info. */
        public Builder endpoint(String method, String host, int port, boolean secure,
                                String url, String path) {
            this.method = method;
            this.host = host;
            this.port = port;
            this.secure = secure;
            this.url = url;
            this.path = path;
            return this;
        }

        public Finding build() {
            return new Finding(this);
        }
    }
}
