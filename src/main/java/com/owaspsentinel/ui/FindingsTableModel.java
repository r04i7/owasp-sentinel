package com.owaspsentinel.ui;

import com.owaspsentinel.model.Finding;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Backing model for the findings table. Holds the live list of {@link Finding}s
 * (insertion order); sorting/filtering is layered on top by a TableRowSorter in
 * the tab, so this stays a plain ordered list.
 */
public final class FindingsTableModel extends AbstractTableModel {

    private final String[] cols = {
            "#", "Severity", "Conf", "Status", "OWASP Category", "Issue", "Method", "Endpoint", "Location", "Hits"
    };

    private final List<Finding> rows = new ArrayList<>();

    // add/remove/clear/snapshot are synchronized so the background saver thread
    // can take a consistent snapshot while the EDT mutates the list.

    public synchronized void add(Finding f) {
        rows.add(f);
        int i = rows.size() - 1;
        fireTableRowsInserted(i, i);
    }

    public synchronized void remove(Finding f) {
        int i = rows.indexOf(f);
        if (i >= 0) {
            rows.remove(i);
            fireTableRowsDeleted(i, i);
        }
    }

    /** Called when a known finding's hit-count changed, so the row repaints. */
    public void refresh(Finding f) {
        int i = rows.indexOf(f);
        if (i >= 0) fireTableRowsUpdated(i, i);
    }

    public synchronized void clear() {
        int n = rows.size();
        rows.clear();
        if (n > 0) fireTableRowsDeleted(0, n - 1);
    }

    public Finding at(int modelRow) {
        return modelRow >= 0 && modelRow < rows.size() ? rows.get(modelRow) : null;
    }

    public synchronized List<Finding> snapshot() {
        return new ArrayList<>(rows);
    }

    @Override public int getRowCount() { return rows.size(); }
    @Override public int getColumnCount() { return cols.length; }
    @Override public String getColumnName(int c) { return cols[c]; }

    @Override
    public Class<?> getColumnClass(int c) {
        return (c == 0 || c == 9) ? Integer.class : String.class;
    }

    @Override
    public Object getValueAt(int r, int c) {
        Finding f = rows.get(r);
        switch (c) {
            case 0:  return r + 1;
            case 1:  return f.severity.name();
            case 2:  return f.confidence.name();
            case 3:  return f.getStatus().label;
            case 4:  return f.category.label();
            case 5:  return f.subtype;
            case 6:  return f.method;
            case 7:  return f.url;
            case 8:  return f.location;
            case 9:  return f.hits.get();
            default: return "";
        }
    }
}
