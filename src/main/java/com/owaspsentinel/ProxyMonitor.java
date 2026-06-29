package com.owaspsentinel;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import com.owaspsentinel.ui.SentinelTab;

/**
 * Hooks Burp's Proxy. We analyse on {@code handleResponseReceived} because at
 * that point both the request and its response are available, giving detectors
 * the full picture. We never modify traffic — this is passive — so both handler
 * methods simply continue with the message unchanged.
 */
public final class ProxyMonitor implements ProxyResponseHandler {

    private final MontoyaApi api;
    private final SentinelTab tab;

    public ProxyMonitor(MontoyaApi api, SentinelTab tab) {
        this.api = api;
        this.tab = tab;
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        try {
            HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(
                    interceptedResponse.initiatingRequest(), interceptedResponse);
            tab.process(rr, true);
        } catch (Exception ex) {
            api.logging().logToError("OWASP Sentinel proxy analysis failed: " + ex);
        }
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
}
