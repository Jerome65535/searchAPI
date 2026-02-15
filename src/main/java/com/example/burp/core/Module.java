package com.example.burp.core;

import burp.IHttpRequestResponse;

import javax.swing.JPanel;

public interface Module {
    String getName();

    JPanel getPanel();

    void processResponse(int toolFlag, IHttpRequestResponse messageInfo);

    void processManual(IHttpRequestResponse messageInfo);
}
