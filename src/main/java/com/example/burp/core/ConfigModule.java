package com.example.burp.core;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.BoxLayout;
import java.awt.BorderLayout;
import java.awt.FlowLayout;

public class ConfigModule implements Module {
    private final IBurpExtenderCallbacks callbacks;
    private final JPanel panel;
    private final JCheckBox enabledCheck;
    private final JCheckBox proxyCheck;
    private final JCheckBox repeaterCheck;
    private final JCheckBox apiCheck;
    private final JCheckBox jsCheck;
    private final JCheckBox htmlCheck;
    private final JCheckBox imageCheck;
    private final JCheckBox otherCheck;

    public ConfigModule(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.panel = new JPanel(new BorderLayout());
        this.enabledCheck = new JCheckBox("Enable Plugin");
        this.proxyCheck = new JCheckBox("Monitor Proxy");
        this.repeaterCheck = new JCheckBox("Monitor Repeater");
        this.apiCheck = new JCheckBox("Scan API");
        this.jsCheck = new JCheckBox("Scan JS");
        this.htmlCheck = new JCheckBox("Scan HTML");
        this.imageCheck = new JCheckBox("Scan Images");
        this.otherCheck = new JCheckBox("Scan Other Resources");
        initDefaults();
        initUi();
        bindListeners();
    }

    @Override
    public String getName() {
        return "Config";
    }

    @Override
    public JPanel getPanel() {
        return panel;
    }

    @Override
    public void processResponse(int toolFlag, IHttpRequestResponse messageInfo) {
    }

    @Override
    public void processManual(IHttpRequestResponse messageInfo) {
    }

    public boolean isEnabled() {
        return enabledCheck.isSelected();
    }

    public boolean monitorProxy() {
        return proxyCheck.isSelected();
    }

    public boolean monitorRepeater() {
        return repeaterCheck.isSelected();
    }

    public boolean scanApi() {
        return apiCheck.isSelected();
    }

    public boolean scanJs() {
        return jsCheck.isSelected();
    }

    public boolean scanHtml() {
        return htmlCheck.isSelected();
    }

    public boolean scanImage() {
        return imageCheck.isSelected();
    }

    public boolean scanOther() {
        return otherCheck.isSelected();
    }

    private void initDefaults() {
        enabledCheck.setSelected(loadBoolean("cfg_enabled", false));
        proxyCheck.setSelected(loadBoolean("cfg_monitor_proxy", true));
        repeaterCheck.setSelected(loadBoolean("cfg_monitor_repeater", false));
        apiCheck.setSelected(loadBoolean("cfg_scan_api", true));
        jsCheck.setSelected(loadBoolean("cfg_scan_js", false));
        htmlCheck.setSelected(loadBoolean("cfg_scan_html", false));
        imageCheck.setSelected(loadBoolean("cfg_scan_image", false));
        otherCheck.setSelected(loadBoolean("cfg_scan_other", false));
    }

    private void initUi() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row1.add(enabledCheck);
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row2.add(new JLabel("Monitor Tools:"));
        row2.add(proxyCheck);
        row2.add(repeaterCheck);
        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row3.add(new JLabel("Passive Targets:"));
        row3.add(apiCheck);
        row3.add(jsCheck);
        row3.add(htmlCheck);
        row3.add(imageCheck);
        row3.add(otherCheck);
        content.add(row1);
        content.add(row2);
        content.add(row3);
        panel.add(content, BorderLayout.NORTH);
    }

    private void bindListeners() {
        JCheckBox[] checkboxes = {enabledCheck, proxyCheck, repeaterCheck, apiCheck, jsCheck, htmlCheck, imageCheck, otherCheck};
        for (JCheckBox checkbox : checkboxes) {
            checkbox.addActionListener(e -> saveConfig());
        }
    }

    private void saveConfig() {
        saveBoolean("cfg_enabled", enabledCheck.isSelected());
        saveBoolean("cfg_monitor_proxy", proxyCheck.isSelected());
        saveBoolean("cfg_monitor_repeater", repeaterCheck.isSelected());
        saveBoolean("cfg_scan_api", apiCheck.isSelected());
        saveBoolean("cfg_scan_js", jsCheck.isSelected());
        saveBoolean("cfg_scan_html", htmlCheck.isSelected());
        saveBoolean("cfg_scan_image", imageCheck.isSelected());
        saveBoolean("cfg_scan_other", otherCheck.isSelected());
    }

    private boolean loadBoolean(String key, boolean defaultValue) {
        String value = callbacks.loadExtensionSetting(key);
        if (value == null) {
            return defaultValue;
        }
        return "true".equalsIgnoreCase(value);
    }

    private void saveBoolean(String key, boolean value) {
        callbacks.saveExtensionSetting(key, Boolean.toString(value));
    }
}
