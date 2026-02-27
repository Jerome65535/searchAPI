package com.example.burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.example.burp.util.ClipboardUtils;
import com.example.burp.util.UrlUtils;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import java.awt.BorderLayout;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ApiScanTreePanel extends JPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final JTree tree;
    private final DefaultTreeModel treeModel;
    private final DefaultMutableTreeNode root;
    private final Map<String, DefaultMutableTreeNode> domainToNode = new HashMap<String, DefaultMutableTreeNode>();
    private final Map<String, Set<String>> domainUrls = new HashMap<String, Set<String>>();

    private com.example.burp.core.ApiScanModule apiScanModule;
    private JTextField urlInput;

    public ApiScanTreePanel(IBurpExtenderCallbacks callbacks) {
        super(new BorderLayout());
        this.callbacks = callbacks;
        this.root = new DefaultMutableTreeNode("API");
        this.treeModel = new DefaultTreeModel(root);
        this.tree = new JTree(treeModel);
        this.tree.setRootVisible(true);
        this.tree.setShowsRootHandles(true);
        this.tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        this.tree.setCellRenderer(new ApiScanTreeCellRenderer());
        this.tree.setComponentPopupMenu(createContextMenu());
        add(new JScrollPane(tree), BorderLayout.CENTER);
        add(buildToolbar(), BorderLayout.NORTH);
    }

    public void setApiScanModule(com.example.burp.core.ApiScanModule module) {
        this.apiScanModule = module;
    }

    private JToolBar buildToolbar() {
        JToolBar bar = new JToolBar();
        bar.setFloatable(false);
        bar.add(new JLabel("目标 URL: "));
        urlInput = new JTextField("https://open.jshbank.com/portal/#/homepage", 42);
        bar.add(urlInput);
        JButton fetchScanBtn = new JButton("请求分析");
        fetchScanBtn.addActionListener(e -> {
            if (apiScanModule == null) return;
            String url = urlInput.getText();
            if (url != null) url = url.trim();
            if (url == null || url.isEmpty()) return;
            final String targetUrl = url;
            fetchScanBtn.setEnabled(false);
            new Thread(() -> {
                try {
                    apiScanModule.fetchAndScan(targetUrl);
                } finally {
                    SwingUtilities.invokeLater(() -> fetchScanBtn.setEnabled(true));
                }
            }).start();
        });
        bar.add(fetchScanBtn);
        bar.addSeparator();
        bar.add(new JLabel("按域名分组，点击展开查看 API 列表"));
        return bar;
    }

    private JPopupMenu createContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        JMenuItem copyAllUrls = new JMenuItem("Copy All URLs under domain");
        JMenuItem toRepeater = new JMenuItem("Send to Repeater");
        JMenuItem toIntruder = new JMenuItem("Send to Intruder");
        copyUrl.addActionListener(e -> copySelectedUrl());
        copyAllUrls.addActionListener(e -> copyAllUrlsUnderSelected());
        toRepeater.addActionListener(e -> sendSelectedToRepeater());
        toIntruder.addActionListener(e -> sendSelectedToIntruder());
        menu.add(copyUrl);
        menu.add(copyAllUrls);
        menu.addSeparator();
        menu.add(toRepeater);
        menu.add(toIntruder);
        return menu;
    }

    private void copySelectedUrl() {
        Object node = getSelectedUserObject();
        if (node instanceof ApiEntry) {
            ClipboardUtils.copyToClipboard(((ApiEntry) node).getUrl());
        } else if (node instanceof String && !"API".equals(node)) {
            ClipboardUtils.copyToClipboard((String) node);
        }
    }

    private void copyAllUrlsUnderSelected() {
        TreePath path = tree.getSelectionPath();
        if (path == null) {
            return;
        }
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        StringBuilder sb = new StringBuilder();
        collectUrls(node, sb);
        if (sb.length() > 0) {
            ClipboardUtils.copyToClipboard(sb.toString());
        }
    }

    private void collectUrls(DefaultMutableTreeNode node, StringBuilder sb) {
        Object obj = node.getUserObject();
        if (obj instanceof ApiEntry) {
            sb.append(((ApiEntry) obj).getUrl()).append("\n");
        }
        for (Enumeration<?> e = node.children(); e.hasMoreElements(); ) {
            collectUrls((DefaultMutableTreeNode) e.nextElement(), sb);
        }
    }

    private void sendSelectedToRepeater() {
        IHttpRequestResponse rr = getSelectedRequestResponse();
        if (rr == null) {
            return;
        }
        callbacks.sendToRepeater(rr.getHttpService().getHost(),
                rr.getHttpService().getPort(),
                rr.getHttpService().getProtocol().equalsIgnoreCase("https"),
                rr.getRequest(),
                "API Scan");
    }

    private void sendSelectedToIntruder() {
        IHttpRequestResponse rr = getSelectedRequestResponse();
        if (rr == null) {
            return;
        }
        callbacks.sendToIntruder(rr.getHttpService().getHost(),
                rr.getHttpService().getPort(),
                rr.getHttpService().getProtocol().equalsIgnoreCase("https"),
                rr.getRequest());
    }

    private IHttpRequestResponse getSelectedRequestResponse() {
        Object node = getSelectedUserObject();
        if (node instanceof ApiEntry) {
            return ((ApiEntry) node).getRequestResponse();
        }
        return null;
    }

    private Object getSelectedUserObject() {
        TreePath path = tree.getSelectionPath();
        if (path == null) {
            return null;
        }
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        return node.getUserObject();
    }

    public void addApi(String fullUrl, IHttpRequestResponse requestResponse) {
        if (fullUrl == null || fullUrl.isEmpty()) {
            return;
        }
        String origin = UrlUtils.extractOrigin(fullUrl);
        if (origin == null) {
            return;
        }
        Set<String> urls = domainUrls.get(origin);
        if (urls != null && urls.contains(fullUrl)) {
            return;
        }
        DefaultMutableTreeNode domainNode = domainToNode.get(origin);
        if (domainNode == null) {
            domainNode = new DefaultMutableTreeNode(origin);
            domainToNode.put(origin, domainNode);
            domainUrls.put(origin, new HashSet<String>());
            treeModel.insertNodeInto(domainNode, root, root.getChildCount());
        }
        domainUrls.get(origin).add(fullUrl);
        ApiEntry entry = new ApiEntry(fullUrl, requestResponse);
        DefaultMutableTreeNode leaf = new DefaultMutableTreeNode(entry);
        treeModel.insertNodeInto(leaf, domainNode, domainNode.getChildCount());
    }

    public void addApis(java.util.Set<String> urls, IHttpRequestResponse requestResponse) {
        if (urls == null || urls.isEmpty()) {
            return;
        }
        for (String url : urls) {
            addApi(url, requestResponse);
        }
    }
}
