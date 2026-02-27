package com.example.burp.core;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IResponseInfo;
import com.example.burp.ui.ApiScanTreePanel;
import com.example.burp.util.UrlUtils;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApiScanModule implements Module {
    private static final int MAX_BODY_LENGTH = 2 * 1024 * 1024;
    private static final int MAX_PATH_LENGTH = 400;

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final ApiScanTreePanel resultPanel;
    private final JPanel panel;

    private final Set<String> scannedOrigins = ConcurrentHashMap.newKeySet();

    private static final Pattern QUOTED_ABSOLUTE_PATH = Pattern.compile(
            "(?:\"|')(/(?!\\s*[/\\*])[a-zA-Z0-9_\\-/:.?=&]*)(?:\"|')"
    );

    private static final Pattern QUOTED_RELATIVE_PATH = Pattern.compile(
            "(?:\"|')([a-zA-Z0-9_\\-]+/[a-zA-Z0-9_\\-/.?=&]+)(?:\"|')"
    );

    private static final Pattern QUOTED_RELATIVE_PATH_TRAILING = Pattern.compile(
            "(?:\"|')([a-zA-Z0-9_\\-]+/)(?:\"|')"
    );

    private static final Pattern JS_PATH_KEY = Pattern.compile(
            "(?i)path\\s*:\\s*[\"']([^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern JS_URL_KEY = Pattern.compile(
            "(?i)(?:url|baseUrl|baseURL|apiUrl|apiBase|BASE_URL|API_URL)\\s*[:=]\\s*[\"']([^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern JS_TO_KEY = Pattern.compile(
            "(?i)\\bto\\s*:\\s*[\"']([^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern QUOTED_RELATIVE_DOT = Pattern.compile(
            "(?:\"|')((?:\\.\\./|\\./)[^\"\'><,;| *()%$^\\\\\\[\\]]*)(?:\"|')"
    );

    private static final Pattern HTML_ATTR = Pattern.compile(
            "(?i)(?:href|src|action|data-src|data-url|data-api)\\s*=\\s*[\"']([^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern QUOTED_ABSOLUTE_URL = Pattern.compile(
            "(?:\"|')((?:https?|wss?)://[^\"'/\\s]+)(?:\"|')"
    );

    private static final String[] BUILTIN_ABSOLUTE_PATHS = {
            "/1q1", "/ocq", "/whu", "/dist/", "/apiIndex/apiMarkIndex", "/docIndex", "/fileDownIndex",
            "/newsDetail/", "/manIndex", "/agreement", "/news", "/support", "/registerIndex", "/getPwdBack",
            "/supportIndex", "/supportQuestion", "/apiIndex", "/loginIndex", "/manIndex/myAppltal",
            "/manIndex/myAppltal/addMyAppl", "/homePage", "/manIndex/myAppl", "/sandBoxNav", "/newsDetail/:id",
            "/sandbox", "/sandindex/sandEnvi", "/sandindex/sandAcct", "/sandindex/sandTools", "/sourceCenter",
            "/searchResult", "/manIndex/coProtocol", "/manIndex/developer", "/manIndex/sandEnv", "/manIndex/interAccess",
            "/supportResult", "/manIndex/myAppltal/myApplEnv", "/manIndex/myAppltal/myApplFun", "/manIndex/myAppltal/myApplInfo",
            "/manIndex/myAppltal/myApplOnline", "/getPwdBackHeader", "/sandBox", "/homepage"
    };
    private static final String[] BUILTIN_RELATIVE_PATHS = {
            "ifs/listInterface", "ifs/viewInterface", "notice/listNotice?pageNum=", "upload/certPic", "dev/getDevEntPerInfo",
            "dev/updateDeveloperInfo", "dev/updateRealInfo", "ifs/listModule", "dev/ReOpenDevApp", "dev/CloseDevApp",
            "dev/deleteDevApp", "dev/ViewDevApp", "support/addFaq", "support/getFAQList?pageNum=", "support/getFAQInfo",
            "support/faqList?pageNum=1&pageSize=6", "dev/ListDevApp?pageNum=", "vaild/validEmail", "vaild/sendEmail",
            "notice/queryNoticeInfo?noticeId=", "upload/queryphoto", "ifs/listModuleWithInterface", "dev/AddDevApp",
            "env/listGatewayEnv", "ifs/listUserInterface", "env/addKeyInfo", "dev/ModifyDevApp", "vaild/sendPhone",
            "vaild/validPhone", "dev/updateAuditDev", "dev/ModifyAuthLinkList", "dev/ListAuditDev?pageNum=",
            "support/faqList?pageNum=0&pageSize=2000", "upload/uploadAppLogo", "ifs/listApiPacket", "dev/ModifyDevAppPublicKey",
            "dev/getDevAppCert", "dev/addDevAppCert", "dev/editDevAppCert", "dev/ModifyDevAppNotifyUrl", "env/getKeyInfo?devId=",
            "env/addSm2KeyInfo", "mock/generateReqWithSign", "mock/", "support/faqList?pageNum=", "gw/listAppInterface",
            "gw/listFlowStat?pageNum=", "version/"
    };

    private static final String[] EXCLUDE_SUBSTRINGS = {
            "node_modules", "jquery", "google-analytics", "gpt.js", "googletagmanager",
            "text/html", "application/json", "application/javascript", "image/"
    };

    private static final Pattern STATIC_EXT = Pattern.compile(
            "\\.(jpg|jpeg|png|gif|bmp|webp|svg|ico|mp3|mp4|m4a|wav|woff2?|ttf|eot|otf|css|less|scss|js|jsx|ts|tsx)(?:[?#]|$)",
            Pattern.CASE_INSENSITIVE
    );

    private static final int MAX_SCRIPTS_TO_FETCH = 40;

    public ApiScanModule(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.resultPanel = new ApiScanTreePanel(callbacks);
        this.panel = resultPanel;
        this.resultPanel.setApiScanModule(this);
    }

    @Override
    public String getName() {
        return "API Scan";
    }

    @Override
    public JPanel getPanel() {
        return panel;
    }

    @Override
    public void processResponse(int toolFlag, IHttpRequestResponse messageInfo) {
        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY && toolFlag != 1024) {
            return;
        }
        if (messageInfo == null || messageInfo.getRequest() == null) {
            return;
        }
        String origin = originFromRequest(messageInfo);
        if (origin == null || scannedOrigins.contains(origin)) {
            return;
        }
        scanMessage(messageInfo);
        scannedOrigins.add(origin);
    }

    @Override
    public void processManual(IHttpRequestResponse messageInfo) {
        String origin = originFromRequest(messageInfo);
        if (origin != null) {
            scannedOrigins.remove(origin);
        }
        scanMessage(messageInfo);
    }

    private String originFromRequest(IHttpRequestResponse messageInfo) {
        if (messageInfo == null || messageInfo.getRequest() == null) {
            return null;
        }
        try {
            URL u = helpers.analyzeRequest(messageInfo.getRequest()).getUrl();
            return UrlUtils.extractOrigin(u);
        } catch (Exception e) {
            return null;
        }
    }

    public void fetchAndScan(String urlString) {
        if (urlString == null || (urlString = urlString.trim()).isEmpty()) {
            return;
        }
        try {
            URL mainUrl = new URL(urlString);
            String path = mainUrl.getPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            URL requestUrl = new URL(mainUrl.getProtocol(), mainUrl.getHost(), mainUrl.getPort(), path);
            int port = mainUrl.getPort();
            if (port <= 0) {
                port = "https".equalsIgnoreCase(mainUrl.getProtocol()) ? 443 : 80;
            }
            IHttpService service = helpers.buildHttpService(mainUrl.getHost(), port, mainUrl.getProtocol());
            Set<String> allUrls = new LinkedHashSet<String>();

            byte[] req = helpers.buildHttpRequest(requestUrl);
            IHttpRequestResponse mainResp = callbacks.makeHttpRequest(service, req);
            if (mainResp != null && mainResp.getResponse() != null) {
                allUrls.addAll(extractUrlsFromResponse(mainResp, service, mainUrl, requestUrl));
            }
            if (allUrls.isEmpty()) {
                allUrls.addAll(buildBuiltinUrlsForTarget(mainUrl, port));
            }
            final Set<String> copy = new LinkedHashSet<String>(allUrls);
            final IHttpRequestResponse msg = mainResp;
            SwingUtilities.invokeLater(() -> resultPanel.addApis(copy, msg));
        } catch (Exception e) {
            callbacks.printError("API Scan fetchAndScan error: " + e.getMessage());
        }
    }

    private Set<String> extractUrlsFromResponse(IHttpRequestResponse mainResp, IHttpService service, URL mainUrl, URL requestUrl) {
        Set<String> allUrls = new LinkedHashSet<String>();
        IResponseInfo mainInfo = helpers.analyzeResponse(mainResp.getResponse());
        int bodyOffset = mainInfo.getBodyOffset();
        int len = Math.min(mainResp.getResponse().length - bodyOffset, MAX_BODY_LENGTH);
        if (len <= 0) {
            return allUrls;
        }
        byte[] bodyBytes = new byte[len];
        System.arraycopy(mainResp.getResponse(), bodyOffset, bodyBytes, 0, len);
        String htmlBody = helpers.bytesToString(bodyBytes);
        if (htmlBody == null || htmlBody.isEmpty()) {
            return allUrls;
        }
        URL docUrl = helpers.analyzeRequest(mainResp.getRequest()).getUrl();
        allUrls.addAll(extractPathsFromJsHtml(htmlBody, docUrl, true));
        List<String> scriptUrls = parseScriptSrcUrls(htmlBody, requestUrl);
        int fetched = 0;
        for (String scriptUrlStr : scriptUrls) {
            if (fetched >= MAX_SCRIPTS_TO_FETCH) {
                break;
            }
            try {
                URL scriptUrl = new URL(scriptUrlStr);
                if (!scriptUrl.getHost().equalsIgnoreCase(mainUrl.getHost())) {
                    continue;
                }
                byte[] sReq = helpers.buildHttpRequest(scriptUrl);
                IHttpRequestResponse sResp = callbacks.makeHttpRequest(service, sReq);
                if (sResp == null || sResp.getResponse() == null) {
                    continue;
                }
                IResponseInfo sInfo = helpers.analyzeResponse(sResp.getResponse());
                int sOffset = sInfo.getBodyOffset();
                int sLen = Math.min(sResp.getResponse().length - sOffset, MAX_BODY_LENGTH);
                if (sLen <= 0) {
                    continue;
                }
                String jsBody = helpers.bytesToString(Arrays.copyOfRange(sResp.getResponse(), sOffset, sOffset + sLen));
                if (jsBody != null && !jsBody.isEmpty()) {
                    URL scriptDocUrl = helpers.analyzeRequest(sResp.getRequest()).getUrl();
                    allUrls.addAll(extractPathsFromJsHtml(jsBody, scriptDocUrl, false));
                    fetched++;
                }
            } catch (Exception ignored) {
            }
        }
        return allUrls;
    }

    private Set<String> buildBuiltinUrlsForTarget(URL mainUrl, int port) {
        Set<String> urls = new LinkedHashSet<String>();
        try {
            boolean defaultPort = ("https".equalsIgnoreCase(mainUrl.getProtocol()) && port == 443)
                    || ("http".equalsIgnoreCase(mainUrl.getProtocol()) && port == 80);
            String baseStr = mainUrl.getProtocol() + "://" + mainUrl.getHost() + (defaultPort ? "" : ":" + port);
            String pathPrefix = mainUrl.getPath();
            if (pathPrefix == null || pathPrefix.isEmpty()) {
                pathPrefix = "/";
            } else if (!pathPrefix.endsWith("/")) {
                pathPrefix = pathPrefix + "/";
            }
            URL baseUrl = new URL(baseStr + pathPrefix);
            urls.addAll(buildBuiltinFullUrls(baseUrl));
        } catch (Exception ignored) {
        }
        return urls;
    }

    private static Set<String> buildBuiltinFullUrls(URL base) {
        Set<String> out = new LinkedHashSet<String>();
        try {
            URI baseUri = base.toURI();
            for (String p : BUILTIN_ABSOLUTE_PATHS) {
                URI resolved = baseUri.resolve(p);
                out.add(resolved.toURL().toString());
            }
            for (String p : BUILTIN_RELATIVE_PATHS) {
                URI resolved = baseUri.resolve(p);
                out.add(resolved.toURL().toString());
            }
        } catch (Exception ignored) { }
        return out;
    }

    private List<String> parseScriptSrcUrls(String html, URL base) {
        List<String> list = new ArrayList<String>();
        Pattern p = Pattern.compile("<script[^>]+src\\s*=\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(html);
        while (m.find()) {
            String src = m.group(1).trim();
            if (src.isEmpty() || src.startsWith("data:") || src.startsWith("javascript:")) continue;
            try {
                URL resolved = base.toURI().resolve(src).toURL();
                list.add(resolved.toString());
            } catch (Exception ignored) { }
        }
        return list;
    }

    private void scanMessage(IHttpRequestResponse messageInfo) {
        if (messageInfo == null || messageInfo.getResponse() == null) {
            return;
        }
        IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
        String contentType = responseInfo.getStatedMimeType();
        if (contentType == null) {
            contentType = "";
        }
        String ct = contentType.toLowerCase();
        boolean isScript = ct.contains("script");
        boolean isHtml = ct.contains("html");
        boolean isJson = ct.contains("json");
        boolean isXml = ct.contains("xml");

        if (!isScript && !isHtml && !isJson && !isXml && messageInfo.getRequest() != null) {
            String path = getRequestPath(messageInfo);
            if (path != null) {
                String p = path.toLowerCase();
                if (p.endsWith(".js") || p.endsWith(".mjs")) {
                    isScript = true;
                } else if (p.endsWith(".html") || p.endsWith(".htm") || p.equals("/") || p.endsWith("/")) {
                    isHtml = true;
                }
            }
        }
        if (!isScript && !isHtml && !isJson && !isXml) {
            return;
        }

        int bodyOffset = responseInfo.getBodyOffset();
        byte[] response = messageInfo.getResponse();
        int length = Math.min(response.length - bodyOffset, MAX_BODY_LENGTH);
        if (length <= 0) {
            return;
        }
        byte[] bodyBytes = new byte[length];
        System.arraycopy(response, bodyOffset, bodyBytes, 0, length);
        String body = helpers.bytesToString(bodyBytes);
        if (body == null || body.isEmpty()) {
            return;
        }

        URL documentUrl = helpers.analyzeRequest(messageInfo).getUrl();
        Set<String> fullUrls = extractPathsFromJsHtml(body, documentUrl, isHtml);
        if (fullUrls.isEmpty()) {
            fullUrls.addAll(buildBuiltinUrlsForDocument(documentUrl));
        }
        if (fullUrls.isEmpty()) {
            return;
        }

        final Set<String> copy = new LinkedHashSet<String>(fullUrls);
        final IHttpRequestResponse msg = messageInfo;
        SwingUtilities.invokeLater(() -> resultPanel.addApis(copy, msg));
    }

    private String getRequestPath(IHttpRequestResponse messageInfo) {
        try {
            URL u = helpers.analyzeRequest(messageInfo.getRequest()).getUrl();
            return u != null ? u.getPath() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private Set<String> buildBuiltinUrlsForDocument(URL documentUrl) {
        Set<String> urls = new LinkedHashSet<String>();
        try {
            String baseStr = documentUrl.getProtocol() + "://" + documentUrl.getHost();
            int port = documentUrl.getPort();
            boolean defaultPort = ("https".equalsIgnoreCase(documentUrl.getProtocol()) && port == 443)
                    || ("http".equalsIgnoreCase(documentUrl.getProtocol()) && port == 80);
            if (!defaultPort && port > 0) {
                baseStr += ":" + port;
            }
            String pathPrefix = documentUrl.getPath();
            if (pathPrefix == null || pathPrefix.isEmpty()) {
                pathPrefix = "/";
            } else if (!pathPrefix.endsWith("/")) {
                pathPrefix = pathPrefix + "/";
            }
            URL baseUrl = new URL(baseStr + pathPrefix);
            urls.addAll(buildBuiltinFullUrls(baseUrl));
        } catch (Exception ignored) {
        }
        return urls;
    }

    private Set<String> extractPathsFromJsHtml(String body, URL documentUrl, boolean isHtml) {
        Set<String> out = new LinkedHashSet<String>();

        Matcher m = QUOTED_ABSOLUTE_PATH.matcher(body);
        while (m.find()) {
            String path = trimQuotes(m.group(1));
            if (path == null || path.isEmpty() || path.contains("://")) continue;
            if (path.length() > MAX_PATH_LENGTH) continue;
            if (shouldExclude(path) || isStaticAsset(path)) continue;
            addResolved(path, documentUrl, out);
        }

        Matcher rel = QUOTED_RELATIVE_PATH.matcher(body);
        while (rel.find()) {
            String path = trimQuotes(rel.group(1));
            if (path == null || path.isEmpty()) continue;
            if (path.startsWith("/") || path.contains("://")) continue;
            if (path.length() > MAX_PATH_LENGTH) continue;
            if (looksLikeMimeOrStatic(path)) continue;
            if (shouldExclude(path) || isStaticAsset(path)) continue;
            addResolved(path, documentUrl, out);
        }

        Matcher relTrail = QUOTED_RELATIVE_PATH_TRAILING.matcher(body);
        while (relTrail.find()) {
            String path = trimQuotes(relTrail.group(1));
            if (path == null || path.length() < 2) continue;
            if (path.startsWith("/") || path.contains("://")) continue;
            if (shouldExclude(path) || isStaticAsset(path)) continue;
            addResolved(path, documentUrl, out);
        }

        Matcher pathKey = JS_PATH_KEY.matcher(body);
        while (pathKey.find()) {
            String path = pathKey.group(1).trim();
            if (path.isEmpty()) continue;
            if (path.length() > MAX_PATH_LENGTH) continue;
            if (shouldExclude(path) || isStaticAsset(path)) continue;
            addResolved(path, documentUrl, out);
        }

        Matcher urlKey = JS_URL_KEY.matcher(body);
        while (urlKey.find()) {
            String path = urlKey.group(1).trim();
            if (path.isEmpty()) continue;
            if (path.length() > MAX_PATH_LENGTH) continue;
            if (path.startsWith("javascript:") || path.startsWith("mailto:")) continue;
            if (path.contains("://") && !isLikelyRealUrl(path)) continue;
            if (looksLikeMimeOrStatic(path)) continue;
            if (shouldExclude(path) || isStaticAsset(path)) continue;
            addResolved(path, documentUrl, out);
        }

        Matcher toKey = JS_TO_KEY.matcher(body);
        while (toKey.find()) {
            String path = toKey.group(1).trim();
            if (path.isEmpty() || path.contains("://")) continue;
            if (path.length() > MAX_PATH_LENGTH) continue;
            if (shouldExclude(path) || isStaticAsset(path)) continue;
            addResolved(path, documentUrl, out);
        }

        Matcher dotRel = QUOTED_RELATIVE_DOT.matcher(body);
        while (dotRel.find()) {
            String path = trimQuotes(dotRel.group(1));
            if (path == null || path.isEmpty()) continue;
            if (path.length() > MAX_PATH_LENGTH) continue;
            if (shouldExclude(path) || isStaticAsset(path)) continue;
            addResolved(path, documentUrl, out);
        }

        if (isHtml) {
            Matcher attr = HTML_ATTR.matcher(body);
            while (attr.find()) {
                String path = attr.group(1).trim();
                if (path.isEmpty() || "#".equals(path) || path.startsWith("javascript:")) continue;
                if (path.length() > MAX_PATH_LENGTH) continue;
                if (path.contains("://") && !isLikelyRealUrl(path)) continue;
                if (shouldExclude(path) || isStaticAsset(path)) continue;
                addResolved(path, documentUrl, out);
            }
        }

        Matcher absUrl = QUOTED_ABSOLUTE_URL.matcher(body);
        while (absUrl.find()) {
            String raw = trimQuotes(absUrl.group(1));
            if (raw == null || raw.isEmpty()) continue;
            if (!isLikelyRealUrl(raw)) continue;
            try {
                if (pathLooksLikeTokenOrBase64(new URL(raw).getPath())) continue;
            } catch (Exception ignored) { continue; }
            if (shouldExclude(raw) || isStaticAsset(raw)) continue;
            out.add(raw);
        }

        return out;
    }

    private void addResolved(String pathOrUrl, URL base, Set<String> out) {
        String full = resolveToFullUrl(pathOrUrl, base);
        if (full == null) return;
        try {
            if (pathLooksLikeTokenOrBase64(new URL(full).getPath())) return;
            out.add(full);
        } catch (Exception ignored) { }
    }

    private String trimQuotes(String s) {
        if (s == null) return null;
        s = s.trim();
        if (s.length() >= 2) {
            char a = s.charAt(0), b = s.charAt(s.length() - 1);
            if ((a == '"' && b == '"') || (a == '\'' && b == '\'')) {
                s = s.substring(1, s.length() - 1).trim();
            }
        }
        s = s.replace("\\\"", "\"").replace("\\\'", "'");
        return s.trim();
    }

    private boolean isLikelyRealUrl(String s) {
        if (s == null || s.length() > 512) return false;
        if (!s.startsWith("http://") && !s.startsWith("https://") && !s.startsWith("ws://") && !s.startsWith("wss://"))
            return false;
        try {
            URL u = new URL(s);
            String host = u.getHost();
            if (host == null || host.isEmpty()) return false;
            if (host.length() > 253) return false;
            if (host.contains("=") || host.matches("[A-Za-z0-9+/=]{40,}")) return false;
            int dot = host.lastIndexOf('.');
            if (dot < 0) return false;
            String tld = host.substring(dot + 1);
            if (!tld.matches("[a-zA-Z]{2,6}")) return false;
            if (pathLooksLikeTokenOrBase64(u.getPath())) return false;
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean pathLooksLikeTokenOrBase64(String path) {
        if (path == null || path.isEmpty()) return false;
        int q = path.indexOf('?');
        int h = path.indexOf('#');
        String p = q >= 0 ? path.substring(0, q) : path;
        p = h >= 0 ? p.substring(0, h) : p;
        for (String seg : p.split("/")) {
            if (seg.isEmpty()) continue;
            if (seg.endsWith("=") && seg.length() >= 10) return true;
            if (seg.length() > 32 && seg.matches("[A-Za-z0-9+/=_-]+")) return true;
        }
        return false;
    }

    private boolean looksLikeMimeOrStatic(String path) {
        String lower = path.toLowerCase();
        if (lower.startsWith("text/") || lower.startsWith("application/") || lower.startsWith("image/")) return true;
        return isStaticAsset(path);
    }

    private boolean shouldExclude(String s) {
        if (s == null) return true;
        String lower = s.toLowerCase();
        for (String x : EXCLUDE_SUBSTRINGS) {
            if (lower.contains(x)) return true;
        }
        return false;
    }

    private boolean isStaticAsset(String s) {
        if (s == null) return true;
        int q = s.indexOf('?');
        int h = s.indexOf('#');
        String path = q >= 0 ? s.substring(0, q) : s;
        path = h >= 0 ? path.substring(0, h) : path;
        return STATIC_EXT.matcher(path).find();
    }

    private String resolveToFullUrl(String pathOrUrl, URL base) {
        if (pathOrUrl == null || pathOrUrl.isEmpty()) return null;
        String s = pathOrUrl.trim();
        try {
            if (s.startsWith("http://") || s.startsWith("https://") || s.startsWith("ws://") || s.startsWith("wss://")) {
                if (!isLikelyRealUrl(s)) return null;
                return s;
            }
            if (s.startsWith("//")) {
                if (!isLikelyRealUrl(base.getProtocol() + ":" + s)) return null;
                return base.getProtocol() + ":" + s;
            }
            URI baseUri = base.toURI();
            URI resolved = baseUri.resolve(s);
            return resolved.toURL().toString();
        } catch (Exception e) {
            return null;
        }
    }
}
