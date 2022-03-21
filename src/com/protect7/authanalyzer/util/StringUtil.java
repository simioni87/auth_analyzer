package com.protect7.authanalyzer.util;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.List;

public class StringUtil {
    public static String trimUriParams(String uri) {
        if (null == uri || 0 >= uri.length() || 0 >= uri.indexOf('?')) {
            return uri;
        }

        return uri.substring(0, uri.charAt('?'));
    }

    public static String list2String(List<String> stringList) {
        if (null == stringList || 0 >= stringList.size()) {
            return "";
        }

        String result = "";
        for (String s : stringList) {
            result += s + "\n";
        }
        result = result.substring(0, result.length() - 2);
        return result;
    }

    public static void copyString2Clipboard(String text) {
        if (null == text || 0 >= text.length()) {
            return;
        }

        StringSelection stringSelection = new StringSelection(text);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
    }
}
