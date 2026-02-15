package com.example.burp.ui;

import com.example.burp.core.ResultItem;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ResultTableModel extends AbstractTableModel {
    private final List<ResultItem> items = Collections.synchronizedList(new ArrayList<ResultItem>());
    private final String[] columns = new String[]{"Time", "Module", "Title", "URL", "Detail"};

    @Override
    public int getRowCount() {
        return items.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public String getColumnName(int column) {
        return columns[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ResultItem item = items.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return item.getTime();
            case 1:
                return item.getModule();
            case 2:
                return item.getTitle();
            case 3:
                return item.getUrl();
            case 4:
                return item.getDetail();
            default:
                return "";
        }
    }

    public void addItem(ResultItem item) {
        int row = items.size();
        items.add(item);
        fireTableRowsInserted(row, row);
    }

    public ResultItem getItem(int row) {
        if (row < 0 || row >= items.size()) {
            return null;
        }
        return items.get(row);
    }

    public List<ResultItem> getItemsSnapshot() {
        synchronized (items) {
            return new ArrayList<ResultItem>(items);
        }
    }
}
