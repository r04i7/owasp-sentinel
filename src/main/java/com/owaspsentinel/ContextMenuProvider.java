package com.owaspsentinel;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.owaspsentinel.ui.SentinelTab;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * Adds "Scan with OWASP Sentinel" to Burp's right-click menu, so you can pull
 * already-captured items (Proxy history, Repeater, Logger, etc.) into the
 * scanner on demand — even while live capture is paused.
 */
public final class ContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final SentinelTab tab;

    public ContextMenuProvider(MontoyaApi api, SentinelTab tab) {
        this.api = api;
        this.tab = tab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        final List<HttpRequestResponse> targets = collect(event);
        if (targets.isEmpty()) {
            return null;
        }

        JMenuItem item = new JMenuItem("Scan with OWASP Sentinel (" + targets.size() + ")");
        item.addActionListener(e -> new Thread(() -> {
            for (HttpRequestResponse rr : targets) {
                try {
                    tab.process(rr, false); // manual scan ignores the pause toggle
                } catch (Exception ex) {
                    api.logging().logToError("OWASP Sentinel manual scan failed: " + ex);
                }
            }
        }, "owasp-sentinel-manual").start());

        List<Component> items = new ArrayList<>();
        items.add(item);
        return items;
    }

    private List<HttpRequestResponse> collect(ContextMenuEvent event) {
        List<HttpRequestResponse> out = new ArrayList<>();
        if (event.messageEditorRequestResponse().isPresent()) {
            out.add(event.messageEditorRequestResponse().get().requestResponse());
        }
        out.addAll(event.selectedRequestResponses());
        return out;
    }
}
