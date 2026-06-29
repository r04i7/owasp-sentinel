package com.owaspsentinel.report;

import com.owaspsentinel.model.Finding;

import java.util.List;

/** Renders the current findings to a self-contained HTML or Markdown report. */
public final class ReportExporter {

    private ReportExporter() {}

    public static String toHtml(List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!doctype html><html><head><meta charset='utf-8'>")
                .append("<title>OWASP Sentinel Report</title><style>")
                .append("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1a1a1a}")
                .append("h1{margin-bottom:4px}.sub{color:#666;margin-bottom:20px}")
                .append(".f{border:1px solid #ddd;border-radius:8px;padding:14px 16px;margin:14px 0}")
                .append(".cat{font-weight:600}.sev{display:inline-block;padding:2px 8px;border-radius:10px;")
                .append("color:#fff;font-size:12px;margin-left:6px}")
                .append(".u{color:#0a58ca;word-break:break-all}.k{color:#555}")
                .append("pre{background:#f6f8fa;padding:10px;border-radius:6px;overflow:auto;font-size:12px}")
                .append("ul{margin:6px 0}</style></head><body>");
        sb.append("<h1>OWASP Sentinel Pro — Findings</h1>");
        sb.append("<div class='sub'>").append(findings.size())
                .append(" issue(s). Passive heuristics — verify manually before reporting.</div>");

        for (Finding f : findings) {
            sb.append("<div class='f'>");
            sb.append("<div class='cat'>").append(esc(f.category.label())).append(" — ")
                    .append(esc(f.subtype))
                    .append("<span class='sev' style='background:")
                    .append(toHex(f.severity.color)).append("'>").append(f.severity)
                    .append("</span> <span class='k'>").append(f.confidence)
                    .append(" · seen ").append(f.hits.get()).append("×</span></div>");
            sb.append("<div><span class='k'>Endpoint:</span> ").append(esc(f.method)).append(' ')
                    .append("<span class='u'>").append(esc(f.url)).append("</span></div>");
            if (!f.location.isEmpty()) {
                sb.append("<div><span class='k'>Location:</span> ").append(esc(f.location)).append("</div>");
            }
            if (!f.evidence.isEmpty()) {
                sb.append("<div><span class='k'>Evidence:</span> ").append(esc(f.evidence)).append("</div>");
            }
            sb.append("<div><span class='k'>Remediation:</span> ").append(esc(f.remediation)).append("</div>");
            appendList(sb, "Suggested payloads", f.payloads);
            appendList(sb, "Test cases", f.testCases);
            sb.append("</div>");
        }
        sb.append("</body></html>");
        return sb.toString();
    }

    public static String toMarkdown(List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("# OWASP Sentinel Pro — Findings\n\n")
                .append(findings.size()).append(" issue(s). Passive heuristics — verify before reporting.\n\n");
        for (Finding f : findings) {
            sb.append("## ").append(f.category.label()).append(" — ").append(f.subtype).append('\n');
            sb.append("- **Severity:** ").append(f.severity).append(" | **Confidence:** ")
                    .append(f.confidence).append(" | **Seen:** ").append(f.hits.get()).append("×\n");
            sb.append("- **Endpoint:** `").append(f.method).append(' ').append(f.url).append("`\n");
            if (!f.location.isEmpty()) sb.append("- **Location:** ").append(f.location).append('\n');
            if (!f.evidence.isEmpty()) sb.append("- **Evidence:** ").append(f.evidence).append('\n');
            sb.append("- **Remediation:** ").append(f.remediation).append('\n');
            if (!f.payloads.isEmpty()) {
                sb.append("\n**Suggested payloads:**\n```\n");
                for (String p : f.payloads) sb.append(p).append('\n');
                sb.append("```\n");
            }
            if (!f.testCases.isEmpty()) {
                sb.append("\n**Test cases:**\n");
                for (String t : f.testCases) sb.append("- ").append(t).append('\n');
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    private static void appendList(StringBuilder sb, String title, List<String> items) {
        if (items == null || items.isEmpty()) return;
        sb.append("<div class='k'>").append(title).append(":</div><ul>");
        for (String i : items) sb.append("<li><code>").append(esc(i)).append("</code></li>");
        sb.append("</ul>");
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String toHex(java.awt.Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }
}
