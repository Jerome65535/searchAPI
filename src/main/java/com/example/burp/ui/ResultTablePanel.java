package com.example.burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.example.burp.core.ResultItem;
import com.example.burp.util.ClipboardUtils;

import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JToolBar;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ResultTablePanel extends JPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final ResultTableModel model;
    private final JTable table;
    private final JPopupMenu contextMenu;

    public ResultTablePanel(IBurpExtenderCallbacks callbacks, ResultTableModel model) {
        super(new BorderLayout());
        this.callbacks = callbacks;
        this.model = model;
        this.table = new JTable(model);
        this.table.setRowSorter(new TableRowSorter<ResultTableModel>(model));
        this.contextMenu = createContextMenu();
        add(new JScrollPane(table), BorderLayout.CENTER);
        add(buildToolbar(), BorderLayout.NORTH);
        table.setComponentPopupMenu(contextMenu);
    }

    public JTable getTable() {
        return table;
    }

    private JToolBar buildToolbar() {
        JToolBar toolBar = new JToolBar();
        toolBar.setFloatable(false);
        toolBar.add(new JLabel("Results (right-click for actions)"));
        return toolBar;
    }

    private JPopupMenu createContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("Copy");
        JMenuItem copyUrlItem = new JMenuItem("Copy URL");
        JMenuItem exportItem = new JMenuItem("Export CSV");
        JMenuItem toRepeaterItem = new JMenuItem("Send to Repeater");
        JMenuItem toIntruderItem = new JMenuItem("Send to Intruder");
        JMenuItem toComparerItem = new JMenuItem("Send to Comparer");
        copyItem.addActionListener(this::copySelectedRows);
        copyUrlItem.addActionListener(this::copySelectedUrls);
        exportItem.addActionListener(this::exportCsv);
        toRepeaterItem.addActionListener(this::sendSelectedToRepeater);
        toIntruderItem.addActionListener(this::sendSelectedToIntruder);
        toComparerItem.addActionListener(this::sendSelectedToComparer);
        menu.add(copyItem);
        menu.add(copyUrlItem);
        menu.addSeparator();
        menu.add(exportItem);
        menu.addSeparator();
        menu.add(toRepeaterItem);
        menu.add(toIntruderItem);
        menu.add(toComparerItem);
        return menu;
    }

    private void copySelectedRows(ActionEvent e) {
        List<ResultItem> items = getSelectedItems();
        if (items.isEmpty()) {
            items = model.getItemsSnapshot();
        }
        StringBuilder sb = new StringBuilder();
        for (ResultItem item : items) {
            sb.append(item.getTime()).append("\t")
                    .append(item.getModule()).append("\t")
                    .append(item.getTitle()).append("\t")
                    .append(item.getUrl()).append("\t")
                    .append(item.getDetail()).append("\n");
        }
        ClipboardUtils.copyToClipboard(sb.toString());
    }

    private void copySelectedUrls(ActionEvent e) {
        List<ResultItem> items = getSelectedItems();
        if (items.isEmpty()) {
            items = model.getItemsSnapshot();
        }
        StringBuilder sb = new StringBuilder();
        for (ResultItem item : items) {
            sb.append(item.getUrl()).append("\n");
        }
        ClipboardUtils.copyToClipboard(sb.toString());
    }

    private void exportCsv(ActionEvent e) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export CSV");
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        List<ResultItem> items = model.getItemsSnapshot();
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
            writer.write("Time,Module,Title,URL,Detail\n");
            for (ResultItem item : items) {
                writer.write(csv(item.getTime()));
                writer.write(",");
                writer.write(csv(item.getModule()));
                writer.write(",");
                writer.write(csv(item.getTitle()));
                writer.write(",");
                writer.write(csv(item.getUrl()));
                writer.write(",");
                writer.write(csv(item.getDetail()));
                writer.write("\n");
            }
        } catch (Exception ex) {
            callbacks.printError(ex.getMessage());
        }
    }

    private String csv(String value) {
        if (value == null) {
            return "";
        }
        String escaped = value.replace("\"", "\"\"");
        return "\"" + escaped + "\"";
    }

    private void sendSelectedToRepeater(ActionEvent e) {
        ResultItem item = getFirstSelectedItem();
        if (item == null || item.getRequestResponse() == null) {
            return;
        }
        IHttpRequestResponse rr = item.getRequestResponse();
        callbacks.sendToRepeater(rr.getHttpService().getHost(),
                rr.getHttpService().getPort(),
                rr.getHttpService().getProtocol().equalsIgnoreCase("https"),
                rr.getRequest(),
                "BurpTemplate");
    }

    private void sendSelectedToIntruder(ActionEvent e) {
        ResultItem item = getFirstSelectedItem();
        if (item == null || item.getRequestResponse() == null) {
            return;
        }
        callbacks.sendToIntruder(item.getRequestResponse().getHttpService().getHost(),
                item.getRequestResponse().getHttpService().getPort(),
                item.getRequestResponse().getHttpService().getProtocol().equalsIgnoreCase("https"),
                item.getRequestResponse().getRequest());
    }

    private void sendSelectedToComparer(ActionEvent e) {
        ResultItem item = getFirstSelectedItem();
        if (item == null || item.getRequestResponse() == null) {
            return;
        }
        callbacks.sendToComparer(item.getRequestResponse().getRequest());
    }

    private List<ResultItem> getSelectedItems() {
        int[] rows = table.getSelectedRows();
        List<ResultItem> selected = new ArrayList<ResultItem>();
        for (int row : rows) {
            int modelRow = table.convertRowIndexToModel(row);
            ResultItem item = model.getItem(modelRow);
            if (item != null) {
                selected.add(item);
            }
        }
        return selected;
    }

    private ResultItem getFirstSelectedItem() {
        int row = table.getSelectedRow();
        if (row < 0) {
            return null;
        }
        int modelRow = table.convertRowIndexToModel(row);
        return model.getItem(modelRow);
    }
}
