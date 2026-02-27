package com.example.burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import burp.ITab;
import com.example.burp.core.AiAnalysisModule;
import com.example.burp.core.ApiScanModule;
import com.example.burp.core.ConfigModule;
import com.example.burp.core.Module;
import com.example.burp.core.ModuleManager;
import com.example.burp.core.SensitiveInfoModule;
import com.example.burp.core.UnauthorizedScanModule;

import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {
    private static final String EXTENSION_NAME = "SearchAPI";
    private static final String VERSION = "1.0.0";
    private static final String DEVELOPER = "Jerome";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private ModuleManager moduleManager;
    private JTabbedPane tabs;
    private JPanel mainPanel;
    private ConfigModule configModule;
    private ApiScanModule apiScanModule;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.printOutput("========================================");
        callbacks.printOutput("Extension: " + EXTENSION_NAME);
        callbacks.printOutput("Version: " + VERSION);
        callbacks.printOutput("Developer: " + DEVELOPER);
        callbacks.printOutput("========================================");
        this.moduleManager = new ModuleManager();
        this.tabs = new JTabbedPane();
        initModules();
        this.mainPanel = new JPanel();
        this.mainPanel.setLayout(new java.awt.BorderLayout());
        this.mainPanel.add(tabs, java.awt.BorderLayout.CENTER);
        callbacks.addSuiteTab(this);
        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(this);
    }

    private void initModules() {
        configModule = new ConfigModule(callbacks);
        Module sensitive = new SensitiveInfoModule(callbacks, helpers);
        apiScanModule = new ApiScanModule(callbacks, helpers);
        Module unauthorized = new UnauthorizedScanModule(callbacks, helpers);
        Module ai = new AiAnalysisModule(callbacks, helpers);
        moduleManager.addModule(configModule);
        moduleManager.addModule(sensitive);
        moduleManager.addModule(apiScanModule);
        moduleManager.addModule(unauthorized);
        moduleManager.addModule(ai);
        for (Module module : moduleManager.getModules()) {
            tabs.addTab(module.getName(), module.getPanel());
        }
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) {
            if (configModule != null) {
                if (!configModule.isEnabled()) return;
                if (!isToolEnabled(toolFlag)) return;
            }
            if (apiScanModule != null && (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == 1024)) {
                apiScanModule.processResponse(toolFlag, messageInfo);
            }
            if (configModule != null && configModule.isEnabled() && shouldScanTarget(messageInfo)) {
                for (Module module : moduleManager.getModules()) {
                    if (module instanceof ConfigModule || module == apiScanModule) continue;
                    try {
                        module.processResponse(toolFlag, messageInfo);
                    } catch (Exception ignored) {}
                }
            }
        }
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<JMenuItem>();
        if (invocation.getToolFlag() != IBurpExtenderCallbacks.TOOL_PROXY
                && invocation.getToolFlag() != IBurpExtenderCallbacks.TOOL_REPEATER) {
            return items;
        }
        IHttpRequestResponse[] selected = invocation.getSelectedMessages();
        if (selected == null || selected.length == 0) {
            return items;
        }
        for (Module module : moduleManager.getModules()) {
            if (module instanceof ConfigModule) {
                continue;
            }
            JMenuItem item = new JMenuItem("Send to " + module.getName());
            item.addActionListener(e -> {
                for (IHttpRequestResponse msg : selected) {
                    moduleManager.processManual(module, msg);
                }
            });
            items.add(item);
        }
        return items;
    }

    private boolean isToolEnabled(int toolFlag) {
        boolean proxyEnabled = configModule.monitorProxy();
        boolean repeaterEnabled = configModule.monitorRepeater();
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == 1024) {
            return proxyEnabled;
        }
        if (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) {
            return repeaterEnabled;
        }
        return false;
    }

    private boolean shouldScanTarget(IHttpRequestResponse messageInfo) {
        if (messageInfo == null || messageInfo.getResponse() == null) {
            return false;
        }
        IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
        String contentType = responseInfo.getStatedMimeType();
        if (contentType == null) {
            contentType = "";
        }
        String lowerContentType = contentType.toLowerCase();
        String path = helpers.analyzeRequest(messageInfo).getUrl().getPath().toLowerCase();

        boolean isJs = lowerContentType.contains("script") || path.endsWith(".js");
        boolean isHtml = lowerContentType.contains("html") || path.endsWith(".html") || path.endsWith(".htm");
        boolean isImage = lowerContentType.contains("image") || isImageExtension(path);
        boolean isCss = lowerContentType.contains("css") || path.endsWith(".css");
        boolean isFont = isFontExtension(path);
        boolean isApi = !isJs && !isHtml && !isImage && !isCss && !isFont;
        boolean isOther = !isApi && !isJs && !isHtml && !isImage;

        return (configModule.scanApi() && isApi)
                || (configModule.scanJs() && isJs)
                || (configModule.scanHtml() && isHtml)
                || (configModule.scanImage() && isImage)
                || (configModule.scanOther() && isOther);
    }

    private boolean isImageExtension(String path) {
        return path.endsWith(".png") || path.endsWith(".jpg") || path.endsWith(".jpeg")
                || path.endsWith(".gif") || path.endsWith(".svg") || path.endsWith(".ico")
                || path.endsWith(".webp") || path.endsWith(".bmp");
    }

    private boolean isFontExtension(String path) {
        return path.endsWith(".woff") || path.endsWith(".woff2")
                || path.endsWith(".ttf") || path.endsWith(".otf") || path.endsWith(".eot");
    }
}
