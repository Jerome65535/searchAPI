package com.example.burp.core;

import burp.IHttpRequestResponse;

public class ResultItem {
    private final String module;
    private final String title;
    private final String url;
    private final String detail;
    private final String time;
    private final IHttpRequestResponse requestResponse;

    public ResultItem(String module, String title, String url, String detail, String time, IHttpRequestResponse requestResponse) {
        this.module = module;
        this.title = title;
        this.url = url;
        this.detail = detail;
        this.time = time;
        this.requestResponse = requestResponse;
    }

    public String getModule() {
        return module;
    }

    public String getTitle() {
        return title;
    }

    public String getUrl() {
        return url;
    }

    public String getDetail() {
        return detail;
    }

    public String getTime() {
        return time;
    }

    public IHttpRequestResponse getRequestResponse() {
        return requestResponse;
    }
}
