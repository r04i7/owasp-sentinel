package com.owaspsentinel;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.owaspsentinel.ui.SentinelTab;

/**
 * Entry point. Burp instantiates this class (declared in
 * META-INF/services/burp.api.montoya.BurpExtension) and calls initialize().
 *
 * Wires three things together:
 *   1. the "OWASP Sentinel" suite tab (the UI + detection engine),
 *   2. a passive Proxy response handler that feeds live traffic to the engine,
 *   3. a right-click menu item for scanning already-captured requests.
 */
public final class OwaspSentinelExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("OWASP Sentinel Pro");

        SentinelTab tab = new SentinelTab(api);
        api.userInterface().registerSuiteTab("OWASP Sentinel", tab.getUiComponent());
        api.proxy().registerResponseHandler(new ProxyMonitor(api, tab));
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuProvider(api, tab));

        api.logging().logToOutput(
                "OWASP Sentinel Pro loaded. Browse via the Burp Proxy and findings will populate the "
                        + "'OWASP Sentinel' tab in real time. Right-click any request -> "
                        + "'Scan with OWASP Sentinel' to scan it on demand.");
    }
}
