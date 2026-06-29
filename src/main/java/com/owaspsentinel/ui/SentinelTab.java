package com.owaspsentinel.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.owaspsentinel.PersistenceStore;
import com.owaspsentinel.ScopeManager;
import com.owaspsentinel.detect.DetectionEngine;
import com.owaspsentinel.model.Finding;
import com.owaspsentinel.model.OwaspCategory;
import com.owaspsentinel.model.Severity;
import com.owaspsentinel.model.Status;
import com.owaspsentinel.report.ReportExporter;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * The "OWASP Sentinel" suite tab. Top: action bar + filters. Centre: a live,
 * filterable findings table over an embedded request/response + detail view.
 * All UI mutation happens on the Swing thread; {@link #process} is safe to call
 * from Burp's proxy threads.
 */
public final class SentinelTab {

    private final MontoyaApi api;
    private final DetectionEngine engine = new DetectionEngine();
    private final ScopeManager scope;
    private final PersistenceStore store;

    private final JPanel root = new JPanel(new BorderLayout());
    private final FindingsTableModel model = new FindingsTableModel();
    private final JTable table = new JTable(model);
    private final TableRowSorter<FindingsTableModel> sorter = new TableRowSorter<>(model);

    private final JToggleButton liveToggle = new JToggleButton("● Live (capturing)", true);
    private final JTextField scopeField = new JTextField(26);
    private final JCheckBox burpScopeBox = new JCheckBox("Use Burp scope");
    private final JCheckBox idpBox = new JCheckBox("Include SSO/IdP", true);
    private final JCheckBox subBox = new JCheckBox("Subdomains", true);
    private final JComboBox<String> categoryFilter = new JComboBox<>();
    private final JComboBox<String> severityFilter = new JComboBox<>();
    private final JComboBox<String> statusFilter = new JComboBox<>();
    private final JCheckBox hideNoiseBox = new JCheckBox("Hide FP/Ignored");
    private final JTextField searchField = new JTextField(16);
    private final JLabel countLabel = new JLabel();

    // Debounced background saver so rapid proxy traffic doesn't thrash the project file.
    private final ScheduledExecutorService saver = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "owasp-sentinel-saver");
        t.setDaemon(true);
        return t;
    });
    private ScheduledFuture<?> pendingSave;
    private volatile boolean loading = false;
    private final JLabel statusLabel = new JLabel(" Ready. Browse through Burp's Proxy and findings will appear live.");

    private final JTextArea overviewArea = new JTextArea();
    private final JTextArea payloadArea = new JTextArea();
    private final JTextArea testCaseArea = new JTextArea();
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    public SentinelTab(MontoyaApi api) {
        this.api = api;
        this.scope = new ScopeManager(api);
        this.store = new PersistenceStore(api);
        this.requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        buildUi();
        loadFromProject();
        // Flush to the project file when the extension is unloaded / Burp closes.
        api.extension().registerUnloadingHandler(this::onUnload);
    }

    private void onUnload() {
        flushNow();
        saver.shutdown();
    }

    public JComponent getUiComponent() {
        return root;
    }

    public boolean isLive() {
        return liveToggle.isSelected();
    }

    /**
     * Runs the detection engine over one message and folds the result into the
     * table. Safe to call off the Swing thread (Burp proxy threads do).
     *
     * @param respectPause when true (live proxy traffic), honours the pause
     *                     toggle and the scope filter. Manual right-click scans
     *                     pass false and are always analysed in full.
     */
    public void process(HttpRequestResponse rr, boolean respectPause) {
        boolean ssoOnly = false;
        if (respectPause) {
            if (!isLive()) {
                return;
            }
            ScopeManager.Decision d = scope.decide(rr.request());
            if (d == ScopeManager.Decision.OUT) {
                return;
            }
            ssoOnly = (d == ScopeManager.Decision.SSO);
        }
        DetectionEngine.Result res = engine.analyze(rr, ssoOnly);
        if (res.isEmpty()) {
            return;
        }
        SwingUtilities.invokeLater(() -> applyResult(res));
    }

    private void applyResult(DetectionEngine.Result res) {
        for (Finding f : res.created) {
            model.add(f);
        }
        for (Finding f : res.repeated) {
            model.refresh(f);
        }
        updateCount();
        if (!res.created.isEmpty()) {
            statusLabel.setText(" +" + res.created.size() + " new finding(s). Total: "
                    + model.getRowCount());
        }
        scheduleSave();
    }

    // --- UI construction --------------------------------------------------

    private void buildUi() {
        JPanel top = new JPanel(new java.awt.GridLayout(0, 1));
        top.add(buildActionBar());
        top.add(buildTriageBar());
        top.add(buildScopeBar());
        top.add(buildFilterBar());

        configureTable();
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Findings (real-time, de-duplicated by endpoint + issue)"));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, buildDetailPane());
        split.setResizeWeight(0.45);

        root.add(top, BorderLayout.NORTH);
        root.add(split, BorderLayout.CENTER);
        root.add(statusLabel, BorderLayout.SOUTH);
        updateCount();
    }

    private JComponent buildActionBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

        liveToggle.addActionListener(e -> {
            liveToggle.setText(liveToggle.isSelected() ? "● Live (capturing)" : "❚❚ Paused");
            statusLabel.setText(liveToggle.isSelected() ? " Capturing resumed." : " Capture paused.");
        });

        JButton repeater = new JButton("Send to Repeater");
        repeater.addActionListener(e -> sendToRepeater());

        JButton intruder = new JButton("Send to Intruder");
        intruder.addActionListener(e -> sendToIntruder());

        JButton copyPayloads = new JButton("Copy payloads");
        copyPayloads.addActionListener(e -> copyPayloads());

        JButton copyEndpoint = new JButton("Copy endpoint");
        copyEndpoint.addActionListener(e -> {
            Finding f = selected();
            if (f != null) copyToClipboard(f.method + " " + f.url);
        });

        JButton exportHtml = new JButton("Export HTML");
        exportHtml.addActionListener(e -> export(true));

        JButton exportMd = new JButton("Export MD");
        exportMd.addActionListener(e -> export(false));

        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> {
            engine.clear();
            model.clear();
            overviewArea.setText("");
            payloadArea.setText("");
            testCaseArea.setText("");
            updateCount();
            scheduleSave();
            statusLabel.setText(" Cleared (issue-type suppressions kept).");
        });

        bar.add(liveToggle);
        bar.add(repeater);
        bar.add(intruder);
        bar.add(copyPayloads);
        bar.add(copyEndpoint);
        bar.add(exportHtml);
        bar.add(exportMd);
        bar.add(clear);
        return bar;
    }

    private JComponent buildScopeBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        scopeField.setToolTipText("Comma/space-separated target host(s) or URL(s), "
                + "e.g.  example.com, app.example.com/api  — leave empty to scan everything.");

        Runnable apply = () -> {
            scope.setScopeText(scopeField.getText());
            scope.setUseBurpScope(burpScopeBox.isSelected());
            scope.setIncludeIdps(idpBox.isSelected());
            scope.setMatchSubdomains(subBox.isSelected());
            scheduleSave();
            statusLabel.setText(" " + scope.summary());
        };
        JButton applyBtn = new JButton("Apply scope");
        applyBtn.addActionListener(e -> apply.run());
        scopeField.addActionListener(e -> apply.run());
        burpScopeBox.addActionListener(e -> apply.run());
        idpBox.addActionListener(e -> apply.run());
        subBox.addActionListener(e -> apply.run());

        bar.add(new JLabel("Scope:"));
        bar.add(scopeField);
        bar.add(subBox);
        bar.add(burpScopeBox);
        bar.add(idpBox);
        bar.add(applyBtn);
        return bar;
    }

    private JComponent buildTriageBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        JButton confirm = new JButton("Confirm");
        confirm.setToolTipText("Mark the selected finding as a verified true positive.");
        confirm.addActionListener(e -> setStatusOnSelected(Status.CONFIRMED));

        JButton fp = new JButton("False positive");
        fp.addActionListener(e -> setStatusOnSelected(Status.FALSE_POSITIVE));

        JButton ignore = new JButton("Ignore");
        ignore.addActionListener(e -> setStatusOnSelected(Status.IGNORED));

        JButton reset = new JButton("Reset status");
        reset.addActionListener(e -> setStatusOnSelected(Status.NEW));

        JButton suppress = new JButton("Suppress issue type");
        suppress.setToolTipText("Remove all findings of this category+issue and drop future ones (persisted).");
        suppress.addActionListener(e -> suppressSelectedType());

        bar.add(new JLabel("Triage:"));
        bar.add(confirm);
        bar.add(fp);
        bar.add(ignore);
        bar.add(reset);
        bar.add(new JLabel("   "));
        bar.add(suppress);
        return bar;
    }

    private JComponent buildFilterBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        categoryFilter.addItem("All categories");
        for (OwaspCategory c : OwaspCategory.values()) {
            categoryFilter.addItem(c.label());
        }
        categoryFilter.addActionListener(e -> updateRowFilter());

        severityFilter.addItem("All severities");
        for (Severity s : Severity.values()) {
            severityFilter.addItem(s.name());
        }
        severityFilter.addActionListener(e -> updateRowFilter());

        statusFilter.addItem("All statuses");
        for (Status s : Status.values()) {
            statusFilter.addItem(s.label);
        }
        statusFilter.addActionListener(e -> updateRowFilter());
        hideNoiseBox.addActionListener(e -> updateRowFilter());

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { updateRowFilter(); }
            public void removeUpdate(DocumentEvent e) { updateRowFilter(); }
            public void changedUpdate(DocumentEvent e) { updateRowFilter(); }
        });

        bar.add(new JLabel("Filter:"));
        bar.add(categoryFilter);
        bar.add(severityFilter);
        bar.add(statusFilter);
        bar.add(hideNoiseBox);
        bar.add(new JLabel("Search:"));
        bar.add(searchField);
        bar.add(countLabel);
        return bar;
    }

    private void configureTable() {
        table.setRowHeight(22);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateColumnsFromModel(true);
        table.getColumnModel().getColumn(1).setCellRenderer(new SeverityRenderer());
        table.getColumnModel().getColumn(3).setCellRenderer(new StatusRenderer());

        // Sensible default widths.
        int[] widths = {34, 66, 70, 92, 200, 200, 56, 320, 120, 40};
        for (int i = 0; i < widths.length && i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        // Sort by severity rank by default (highest first) using the severity column.
        sorter.setComparator(1, (a, b) ->
                Integer.compare(Severity.valueOf((String) b).rank, Severity.valueOf((String) a).rank));

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showSelected();
        });
    }

    private JComponent buildDetailPane() {
        JTabbedPane tabs = new JTabbedPane();

        overviewArea.setEditable(false);
        overviewArea.setLineWrap(true);
        overviewArea.setWrapStyleWord(true);
        overviewArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        tabs.addTab("Overview", new JScrollPane(overviewArea));

        payloadArea.setEditable(false);
        payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        tabs.addTab("Suggested Payloads", new JScrollPane(payloadArea));

        testCaseArea.setEditable(false);
        testCaseArea.setLineWrap(true);
        testCaseArea.setWrapStyleWord(true);
        testCaseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        tabs.addTab("Test Cases", new JScrollPane(testCaseArea));

        tabs.addTab("Request", requestEditor.uiComponent());
        tabs.addTab("Response", responseEditor.uiComponent());
        return tabs;
    }

    // --- selection / detail rendering -------------------------------------

    private Finding selected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return null;
        return model.at(table.convertRowIndexToModel(viewRow));
    }

    private void showSelected() {
        Finding f = selected();
        if (f == null) return;

        StringBuilder o = new StringBuilder();
        o.append("CATEGORY    : ").append(f.category.label()).append('\n');
        o.append("ISSUE       : ").append(f.subtype).append('\n');
        o.append("SEVERITY    : ").append(f.severity).append("   CONFIDENCE: ").append(f.confidence).append('\n');
        o.append("SEEN        : ").append(f.hits.get()).append(" time(s)\n");
        o.append("ENDPOINT    : ").append(f.method).append(' ').append(f.url).append('\n');
        if (!f.location.isEmpty()) o.append("LOCATION    : ").append(f.location).append('\n');
        if (!f.evidence.isEmpty()) o.append("EVIDENCE    : ").append(f.evidence).append('\n');
        o.append('\n').append("REMEDIATION\n-----------\n").append(f.remediation).append('\n');
        overviewArea.setText(o.toString());
        overviewArea.setCaretPosition(0);

        StringBuilder p = new StringBuilder();
        if (f.payloads.isEmpty()) {
            p.append("No payloads bundled for this finding type — see Test Cases tab.");
        } else {
            p.append("# Copy/paste into Repeater or Intruder. Replace OOB_HOST with your Collaborator.\n\n");
            for (String s : f.payloads) p.append(s).append('\n');
        }
        payloadArea.setText(p.toString());
        payloadArea.setCaretPosition(0);

        StringBuilder t = new StringBuilder();
        if (f.testCases.isEmpty()) {
            t.append("No specific test cases — apply the standard methodology for ").append(f.category.title);
        } else {
            int i = 1;
            for (String s : f.testCases) t.append(i++).append(". ").append(s).append("\n\n");
        }
        testCaseArea.setText(t.toString());
        testCaseArea.setCaretPosition(0);

        if (f.requestResponse != null && f.requestResponse.request() != null) {
            requestEditor.setRequest(f.requestResponse.request());
        }
        if (f.requestResponse != null && f.requestResponse.response() != null) {
            responseEditor.setResponse(f.requestResponse.response());
        }
    }

    // --- actions ----------------------------------------------------------

    private void sendToRepeater() {
        Finding f = selected();
        if (f == null || f.requestResponse == null) {
            statusLabel.setText(" Select a finding first.");
            return;
        }
        String caption = f.category.id + " " + f.subtype;
        if (caption.length() > 40) caption = caption.substring(0, 40);
        api.repeater().sendToRepeater(f.requestResponse.request(), caption);
        statusLabel.setText(" Sent to Repeater: " + caption);
    }

    private void sendToIntruder() {
        Finding f = selected();
        if (f == null || f.requestResponse == null) {
            statusLabel.setText(" Select a finding first.");
            return;
        }
        api.intruder().sendToIntruder(f.requestResponse.request());
        statusLabel.setText(" Sent to Intruder. Mark the '" + f.location + "' position and load the payloads tab.");
    }

    private void copyPayloads() {
        Finding f = selected();
        if (f == null || f.payloads.isEmpty()) {
            statusLabel.setText(" No payloads to copy for this finding.");
            return;
        }
        copyToClipboard(String.join("\n", f.payloads));
        statusLabel.setText(" Copied " + f.payloads.size() + " payload(s) to clipboard.");
    }

    private void export(boolean html) {
        List<Finding> data = model.snapshot();
        if (data.isEmpty()) {
            statusLabel.setText(" Nothing to export yet.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File(html ? "owasp-sentinel-report.html"
                : "owasp-sentinel-report.md"));
        if (chooser.showSaveDialog(root) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        String content = html ? ReportExporter.toHtml(data) : ReportExporter.toMarkdown(data);
        try (FileWriter w = new FileWriter(chooser.getSelectedFile(), StandardCharsets.UTF_8)) {
            w.write(content);
            statusLabel.setText(" Report saved: " + chooser.getSelectedFile().getAbsolutePath());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(root, "Export failed: " + ex.getMessage());
        }
    }

    // --- triage -----------------------------------------------------------

    private void setStatusOnSelected(Status s) {
        Finding f = selected();
        if (f == null) {
            statusLabel.setText(" Select a finding first.");
            return;
        }
        f.setStatus(s);
        model.refresh(f);
        updateRowFilter(); // re-apply in case "Hide FP/Ignored" is on
        scheduleSave();
        statusLabel.setText(" Marked \"" + f.subtype + "\" as " + s.label + ".");
    }

    private void suppressSelectedType() {
        Finding f = selected();
        if (f == null) {
            statusLabel.setText(" Select a finding first.");
            return;
        }
        String label = f.category.id + " " + f.subtype;
        List<Finding> removed = engine.suppressType(f.typeKey());
        for (Finding r : removed) {
            model.remove(r);
        }
        updateCount();
        scheduleSave();
        statusLabel.setText(" Suppressed issue type: " + label + " — removed " + removed.size()
                + " row(s); future matches will be dropped.");
    }

    // --- persistence ------------------------------------------------------

    private void loadFromProject() {
        loading = true;
        try {
            PersistenceStore.Loaded data = store.load();

            scopeField.setText(data.scopeText);
            burpScopeBox.setSelected(data.useBurpScope);
            idpBox.setSelected(data.includeIdps);
            subBox.setSelected(data.matchSubdomains);
            scope.setScopeText(data.scopeText);
            scope.setUseBurpScope(data.useBurpScope);
            scope.setIncludeIdps(data.includeIdps);
            scope.setMatchSubdomains(data.matchSubdomains);

            for (String typeKey : data.suppressedTypes) {
                engine.addSuppressedType(typeKey);
            }
            for (Finding f : data.findings) {
                engine.restore(f);
                model.add(f);
            }
            updateCount();
            statusLabel.setText(data.findings.isEmpty()
                    ? " " + scope.summary()
                    : " Restored " + data.findings.size() + " finding(s) from this project. " + scope.summary());
        } catch (Exception ex) {
            api.logging().logToError("OWASP Sentinel: project load failed: " + ex);
        } finally {
            loading = false;
        }
    }

    /** Debounced save — coalesces bursts of proxy findings into one write. */
    private void scheduleSave() {
        if (loading) {
            return;
        }
        if (pendingSave != null) {
            pendingSave.cancel(false);
        }
        pendingSave = saver.schedule(this::flushNow, 1500, TimeUnit.MILLISECONDS);
    }

    private void flushNow() {
        try {
            store.save(model.snapshot(), scopeField.getText(), burpScopeBox.isSelected(),
                    idpBox.isSelected(), subBox.isSelected(), engine.suppressedTypes());
        } catch (Exception ex) {
            api.logging().logToError("OWASP Sentinel: project save failed: " + ex);
        }
    }

    // --- filtering --------------------------------------------------------

    private void updateRowFilter() {
        final String cat = (String) categoryFilter.getSelectedItem();
        final String sev = (String) severityFilter.getSelectedItem();
        final String stat = (String) statusFilter.getSelectedItem();
        final boolean hideNoise = hideNoiseBox.isSelected();
        final String text = searchField.getText().trim().toLowerCase();

        List<RowFilter<FindingsTableModel, Integer>> filters = new ArrayList<>();
        if (cat != null && !cat.startsWith("All")) {
            filters.add(RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(cat) + "$", 4));
        }
        if (sev != null && !sev.startsWith("All")) {
            filters.add(RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(sev) + "$", 1));
        }
        if (stat != null && !stat.startsWith("All")) {
            filters.add(RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(stat) + "$", 3));
        }
        if (hideNoise) {
            filters.add(new RowFilter<FindingsTableModel, Integer>() {
                @Override
                public boolean include(Entry<? extends FindingsTableModel, ? extends Integer> entry) {
                    String s = String.valueOf(entry.getValue(3));
                    return !s.equals(Status.FALSE_POSITIVE.label) && !s.equals(Status.IGNORED.label);
                }
            });
        }
        if (!text.isEmpty()) {
            filters.add(new RowFilter<FindingsTableModel, Integer>() {
                @Override
                public boolean include(Entry<? extends FindingsTableModel, ? extends Integer> entry) {
                    for (int i = 0; i < entry.getValueCount(); i++) {
                        Object v = entry.getValue(i);
                        if (v != null && v.toString().toLowerCase().contains(text)) return true;
                    }
                    return false;
                }
            });
        }
        sorter.setRowFilter(filters.isEmpty() ? null : RowFilter.andFilter(filters));
        updateCount();
    }

    private void updateCount() {
        countLabel.setText("   Findings: " + model.getRowCount() + " (shown " + table.getRowCount() + ")");
    }

    // --- misc -------------------------------------------------------------

    private void copyToClipboard(String s) {
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(s == null ? "" : s), null);
    }

    /** Colours the severity cell by severity. */
    private static final class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean selected,
                                                       boolean focus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, selected, focus, row, col);
            try {
                Severity s = Severity.valueOf(String.valueOf(value));
                if (!selected) c.setForeground(s.color);
                c.setFont(c.getFont().deriveFont(s.rank >= Severity.HIGH.rank ? Font.BOLD : Font.PLAIN));
            } catch (Exception ignored) {
                if (!selected) c.setForeground(Color.DARK_GRAY);
            }
            return c;
        }
    }

    /** Colours the triage-status cell. */
    private static final class StatusRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean selected,
                                                       boolean focus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, selected, focus, row, col);
            Status s = statusForLabel(String.valueOf(value));
            if (s != null) {
                if (!selected) c.setForeground(s.color);
                c.setFont(c.getFont().deriveFont(s == Status.CONFIRMED ? Font.BOLD : Font.PLAIN));
            }
            return c;
        }
    }

    private static Status statusForLabel(String label) {
        for (Status s : Status.values()) {
            if (s.label.equals(label)) return s;
        }
        return null;
    }
}
