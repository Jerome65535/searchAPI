package com.example.burp.util;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

public final class ClipboardUtils {

    private ClipboardUtils() {
    }

    public static void copyToClipboard(String text) {
        if (text == null) {
            return;
        }
        StringSelection selection = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }
}
