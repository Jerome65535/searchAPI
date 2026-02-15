package com.example.burp.ui;

import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.Component;

public class ApiScanTreeCellRenderer extends DefaultTreeCellRenderer {
    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {
        super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);
        if (value instanceof DefaultMutableTreeNode) {
            Object userObject = ((DefaultMutableTreeNode) value).getUserObject();
            if (userObject instanceof ApiEntry) {
                setText(((ApiEntry) userObject).getUrl());
            } else if (userObject instanceof String) {
                String s = (String) userObject;
                if ("API".equals(s)) {
                    setText("API");
                } else {
                    DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
                    int count = node.getChildCount();
                    setText(s + " (" + count + ")");
                }
            }
        }
        return this;
    }
}
