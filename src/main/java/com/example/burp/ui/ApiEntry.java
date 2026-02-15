package com.example.burp.ui;

import burp.IHttpRequestResponse;

public class ApiEntry {
    private final String url;
    private final IHttpRequestResponse requestResponse;

    public ApiEntry(String url, IHttpRequestResponse requestResponse) {
        this.url = url;
        this.requestResponse = requestResponse;
    }

    public String getUrl() {
        return url;
    }

    public IHttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    @Override
    public String toString() {
        return url;
    }
}
