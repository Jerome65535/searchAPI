package com.example.burp.util;

import java.net.URL;

public final class UrlUtils {

    private UrlUtils() {
    }

    public static String extractOrigin(URL url) {
        if (url == null) {
            return null;
        }
        String host = url.getHost();
        if (host == null) {
            return null;
        }
        String protocol = url.getProtocol();
        int port = url.getPort();
        if (port <= 0) {
            port = "https".equalsIgnoreCase(protocol) ? 443 : 80;
        }
        int defaultPort = "https".equalsIgnoreCase(protocol) ? 443 : 80;
        String origin = protocol + "://" + host;
        if (port != defaultPort) {
            origin += ":" + port;
        }
        return origin;
    }

    public static String extractOrigin(String urlString) {
        if (urlString == null || urlString.isEmpty()) {
            return null;
        }
        try {
            return extractOrigin(new URL(urlString));
        } catch (Exception e) {
            return null;
        }
    }
}
