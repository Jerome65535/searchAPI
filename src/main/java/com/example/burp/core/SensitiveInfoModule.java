package com.example.burp.core;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.example.burp.ui.ResultTableModel;
import com.example.burp.ui.ResultTablePanel;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SensitiveInfoModule implements Module {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final ResultTableModel model;
    private final ResultTablePanel resultPanel;
    private final JPanel panel;
    private final JTextArea rulesArea;
    private final List<RegexRule> rules = new ArrayList<RegexRule>();
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public SensitiveInfoModule(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.model = new ResultTableModel();
        this.resultPanel = new ResultTablePanel(callbacks, model);
        this.rulesArea = new JTextArea(6, 80);
        this.panel = new JPanel(new BorderLayout());
        initDefaultRules();
        initUi();
    }

    @Override
    public String getName() {
        return "Sensitive Info";
    }

    @Override
    public JPanel getPanel() {
        return panel;
    }

    @Override
    public void processResponse(int toolFlag, IHttpRequestResponse messageInfo) {
        scanMessage(messageInfo);
    }

    @Override
    public void processManual(IHttpRequestResponse messageInfo) {
        scanMessage(messageInfo);
    }

    private void initUi() {
        JPanel top = new JPanel(new BorderLayout());
        JPanel actions = new JPanel();
        JButton applyBtn = new JButton("Apply Rules");
        JButton importBtn = new JButton("Import Rules");
        applyBtn.addActionListener(e -> loadRulesFromText());
        importBtn.addActionListener(e -> importRules());
        actions.add(applyBtn);
        actions.add(importBtn);
        top.add(new JLabel("Rules (name=regex per line)"), BorderLayout.NORTH);
        top.add(new JScrollPane(rulesArea), BorderLayout.CENTER);
        top.add(actions, BorderLayout.SOUTH);
        panel.add(top, BorderLayout.NORTH);
        panel.add(resultPanel, BorderLayout.CENTER);
    }

    private void initDefaultRules() {
        rulesArea.setText(
                "手机号=\\b1[3-9]\\d{9}\\b\n" +
                "身份证号=\\b[1-9]\\d{5}(?:19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{3}[\\dXx]\\b\n" +
                "邮箱=\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b\n" +
                "银行卡号=\\b(?:62|4\\d|5[1-5]|3[47]|6011|35)\\d{13,18}\\b\n" +
                "护照号=\\b[EeGgDdSsPpHh]\\d{8}\\b\n" +
                "统一社会信用代码=\\b[0-9]{2}[0-9]{6}[0-9A-Z]{10}\\b\n" +
                "IPv4地址=\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b\n" +
                "IPv4端口=\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d):\\d{1,5}\\b\n" +
                "内网IP=\\b(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b\n" +
                "IPv6地址=(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})\n" +

                "密码泄露=(?i)(password|passwd|pwd|passphrase|secret|credential)[\\s]*[:=]\\s*[\"']?[^\\s\"']{4,}[\"']?\n" +
                "Token泄露=(?i)(token|access_token|refresh_token|auth_token|session_token|api_token)[\\s]*[:=]\\s*[\"']?[^\\s\"']{8,}[\"']?\n" +
                "APIKey泄露=(?i)(apikey|api_key|api-key|access_key|secret_key|app_key|client_secret|client_id)[\\s]*[:=]\\s*[\"']?[^\\s\"']{8,}[\"']?\n" +
                "硬编码密码=(?i)(?:password|passwd|pwd|pass)\\s*[:=]\\s*[\"'][^\"']{4,}[\"']\n" +
                "硬编码Token=(?i)(?:token|secret|api_key|apikey|credential)\\s*[:=]\\s*[\"'][^\"']{8,}[\"']\n" +
                "BearerToken=(?i)bearer\\s+[a-z0-9\\-._~+/]+=*\n" +
                "BasicAuth=(?i)basic\\s+[A-Za-z0-9+/]{10,}={0,2}\n" +
                "JWT=eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9._-]{10,}\\.[A-Za-z0-9._-]{10,}\n" +

                "AWS AccessKeyId=(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\n" +
                "AWS MWS Key=amzn\\.mws\\.[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\n" +
                "AWS SecretKey=(?i)(aws_secret_access_key|aws_secret|secret_access_key)\\s*[:=]\\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?\n" +

                "阿里云AccessKey=\\bLTAI[a-zA-Z0-9]{12,20}\\b\n" +
                "阿里云AccessSecret=(?i)(accesskeysecret|access_key_secret|alicloud_secret)\\s*[:=]\\s*[\"']?[A-Za-z0-9]{30}[\"']?\n" +
                "阿里云STS=(?i)SecurityToken\\s*[:=]\\s*[\"']?[A-Za-z0-9+/=]{100,}[\"']?\n" +
                "腾讯云SecretId=\\bAKID[a-zA-Z0-9]{13,20}\\b\n" +
                "腾讯云SecretKey=(?i)(secretkey|tencent_secret|secret_key)\\s*[:=]\\s*[\"']?[A-Za-z0-9]{32}[\"']?\n" +
                "华为云AccessKey=(?i)(huawei_ak|hw_access_key)\\s*[:=]\\s*[\"']?[A-Z0-9]{20}[\"']?\n" +
                "百度云AccessKey=(?i)(baidu_ak|bce_access_key)\\s*[:=]\\s*[\"']?[a-f0-9]{32}[\"']?\n" +
                "京东云AccessKey=\\bJDCLOUD[a-zA-Z0-9]{20,30}\\b\n" +
                "金山云AccessKey=\\bAKLT[a-zA-Z0-9]{16,24}\\b\n" +
                "青云AccessKey=\\bQYACL[a-zA-Z0-9]{20,30}\\b\n" +
                "火山引擎AccessKey=\\bAKLT[a-zA-Z0-9]{40,50}\\b\n" +
                "UCloud公钥=(?i)(ucloud_public_key|ucloud_api_key)\\s*[:=]\\s*[\"']?[A-Za-z0-9]{40,}[\"']?\n" +

                "Google API Key=\\bAIza[A-Za-z0-9_-]{35}\\b\n" +
                "Google OAuth=\\b\\d+-[A-Za-z0-9_]{32}\\.apps\\.googleusercontent\\.com\\b\n" +
                "GCP ServiceAccount=(?i)\"type\"\\s*:\\s*\"service_account\"\n" +
                "Google ServiceAccount=\\b[A-Za-z0-9._-]+@[A-Za-z0-9._-]+\\.iam\\.gserviceaccount\\.com\\b\n" +
                "Firebase URL=\\bhttps://[a-z0-9-]+\\.firebaseio\\.com\\b\n" +

                "Azure Storage连接=DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}\n" +
                "Azure ClientSecret=(?i)(azure|aad|ad)[_-]?(client[_-]?secret|secret)\\s*[:=]\\s*[\"']?[A-Za-z0-9~._-]{34,}[\"']?\n" +
                "Azure SAS Token=\\bsig=[A-Za-z0-9%+/=]{43,}%3D\n" +
                "Azure Connection=(?i)(DefaultEndpointsProtocol|AccountKey|SharedAccessSignature)=[^\\s\"';]+\n" +

                "GitHub Personal Token=\\bghp_[A-Za-z0-9]{36}\\b\n" +
                "GitHub OAuth Token=\\bgho_[A-Za-z0-9]{36}\\b\n" +
                "GitHub User-Server=\\bghu_[A-Za-z0-9]{36}\\b\n" +
                "GitHub App Token=\\bghs_[A-Za-z0-9]{36}\\b\n" +
                "GitHub App Refresh=\\bghr_[A-Za-z0-9]{36}\\b\n" +
                "GitHub PAT精细化=\\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\\b\n" +

                "GitLab Token=\\bglpat-[A-Za-z0-9\\-=]{20,}\\b\n" +
                "GitLab Pipeline Token=\\bglptt-[A-Za-z0-9]{20}\\b\n" +
                "GitLab Runner Token=\\bGR1348941[A-Za-z0-9\\-_]{20}\\b\n" +
                "GitLab Feed Token=\\bglft-[A-Za-z0-9\\-]{20}\\b\n" +

                "Bitbucket Token=\\bATBB[A-Za-z0-9]{24}\\b\n" +
                "Bitbucket App密码=(?i)bitbucket_app_password\\s*[:=]\\s*[\"']?[A-Za-z0-9]{20,}[\"']?\n" +

                "Jenkins API Token=(?i)jenkins[_-]?(?:api[_-]?)?token\\s*[:=]\\s*[\"']?[a-f0-9]{32,}[\"']?\n" +
                "CircleCI Token=(?i)circle[_-]?(?:ci[_-]?)?token\\s*[:=]\\s*[\"']?[A-Za-z0-9]{40}[\"']?\n" +
                "Travis CI Token=(?i)travis[_-]?token\\s*[:=]\\s*[\"']?[A-Za-z0-9]{22}[\"']?\n" +
                "Buildkite Token=\\bbkua_[a-zA-Z0-9]{40}\\b\n" +
                "Drone CI Token=(?i)drone[_-]?token\\s*[:=]\\s*[\"']?[A-Za-z0-9]{32,}[\"']?\n" +
                "GitHub Actions Secret=(?i)secrets\\.[A-Z_]{2,}\\b\n" +
                "JFrog Key=\\bAKCp[A-Za-z0-9]{70,}\\b\n" +
                "SonarQube Token=\\bsqu_[a-f0-9]{40}\\b\n" +
                "SonarQube旧Token=\\bsqp_[a-f0-9]{40}\\b\n" +

                "Slack Token=\\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\\b\n" +
                "Slack App Token=\\bxapp-[0-9]+-[A-Z0-9]+-[0-9]+-[a-f0-9]+\\b\n" +
                "Slack Webhook=https://hooks\\.slack\\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24}\n" +
                "Slack Config Token=\\bxoxe\\.xox[bp]-[0-9]+-[A-Za-z0-9]+\\b\n" +

                "Discord Token=\\b[NM][A-Za-z0-9]{23}\\.[A-Za-z0-9]{6}\\.[A-Za-z0-9-_]{27,}\\b\n" +
                "Discord Webhook=https://discord(?:app)?\\.com/api/webhooks/\\d+/[A-Za-z0-9_-]+\n" +

                "Telegram Bot Token=\\b\\d{8,10}:[A-Za-z0-9_-]{35}\\b\n" +

                "钉钉机器人Webhook=https://oapi\\.dingtalk\\.com/robot/send\\?access_token=[a-f0-9]{64}\n" +
                "飞书机器人Webhook=https://open\\.(?:feishu|larksuite)\\.com/open-apis/bot/v2/hook/[a-f0-9-]{36}\n" +
                "企业微信机器人=https://qyapi\\.weixin\\.qq\\.com/cgi-bin/webhook/send\\?key=[a-f0-9-]{36}\n" +
                "钉钉AccessToken=(?i)dingtalk[_-]?(?:access[_-]?)?token\\s*[:=]\\s*[\"']?[a-f0-9]{64}[\"']?\n" +

                "Stripe Live Key=\\bsk_live_[0-9a-zA-Z]{24,99}\\b\n" +
                "Stripe Publishable=\\bpk_live_[0-9a-zA-Z]{24,99}\\b\n" +
                "Stripe Restricted=\\brk_live_[0-9a-zA-Z]{24,99}\\b\n" +
                "Stripe Webhook=\\bwhsec_[0-9a-zA-Z]{32,}\\b\n" +
                "Square Access Token=\\bsq0atp-[A-Za-z0-9_-]{22}\\b\n" +
                "Square OAuth=\\bsq0csp-[A-Za-z0-9_-]{43}\\b\n" +
                "Shopify Access Token=\\bshpat_[a-fA-F0-9]{32}\\b\n" +
                "Shopify Shared Secret=\\bshpss_[a-fA-F0-9]{32}\\b\n" +
                "Shopify Custom App=\\bshpca_[a-fA-F0-9]{32}\\b\n" +
                "Shopify Private App=\\bshppa_[a-fA-F0-9]{32}\\b\n" +

                "Twilio Account SID=\\bAC[a-f0-9]{32}\\b\n" +
                "Twilio API Key=\\bSK[a-f0-9]{32}\\b\n" +
                "SendGrid Key=\\bSG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}\\b\n" +
                "Mailgun Key=\\bkey-[a-f0-9]{32}\\b\n" +
                "Mailchimp Key=\\b[a-f0-9]{32}-us[0-9]{1,2}\\b\n" +
                "Postmark Token=(?i)X-Postmark-Server-Token\\s*:\\s*[a-f0-9-]{36}\n" +

                "OpenAI Key旧版=\\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\\b\n" +
                "OpenAI Project Key=\\bsk-proj-[A-Za-z0-9_-]{48,}\\b\n" +
                "OpenAI Org Key=\\bsk-org-[A-Za-z0-9_-]{48,}\\b\n" +
                "Anthropic Key=\\bsk-ant-[A-Za-z0-9_-]{80,}\\b\n" +
                "HuggingFace Token=\\bhf_[A-Za-z0-9]{34,}\\b\n" +
                "Replicate Token=\\br8_[A-Za-z0-9]{22,}\\b\n" +
                "Cohere Key=(?i)(cohere[_-]?api[_-]?key|co[_-]api[_-]key)\\s*[:=]\\s*[\"']?[A-Za-z0-9]{40}[\"']?\n" +
                "智谱AI Key=\\b[a-f0-9]{32}\\.[a-zA-Z0-9]{16}\\b\n" +
                "通义千问Key=\\bsk-[a-f0-9]{32}\\b\n" +
                "DeepSeek Key=\\bsk-[a-f0-9]{32,48}\\b\n" +
                "硅基流动Key=\\bsk-[a-zA-Z0-9]{48,}\\b\n" +
                "百川AI Key=(?i)(baichuan[_-]?api[_-]?key)\\s*[:=]\\s*[\"']?[A-Za-z0-9]{32,}[\"']?\n" +
                "月之暗面Key=(?i)(moonshot[_-]?api[_-]?key)\\s*[:=]\\s*[\"']?sk-[A-Za-z0-9]{40,}[\"']?\n" +
                "零一万物Key=(?i)(yi[_-]?api[_-]?key)\\s*[:=]\\s*[\"']?[A-Za-z0-9]{32,}[\"']?\n" +
                "讯飞星火Key=(?i)(spark[_-]?api[_-]?(?:key|secret))\\s*[:=]\\s*[\"']?[A-Za-z0-9]{32}[\"']?\n" +
                "MiniMax Key=(?i)(minimax[_-]?api[_-]?key)\\s*[:=]\\s*[\"']?[A-Za-z0-9]{32,}[\"']?\n" +
                "Stability AI Key=\\bsk-[A-Za-z0-9]{48}\\b\n" +
                "Mistral AI Key=(?i)(mistral[_-]?api[_-]?key)\\s*[:=]\\s*[\"']?[A-Za-z0-9]{32}[\"']?\n" +
                "Google Gemini Key=(?i)(gemini[_-]?api[_-]?key|google[_-]?ai[_-]?key)\\s*[:=]\\s*[\"']?AIza[A-Za-z0-9_-]{35}[\"']?\n" +

                "JDBC连接=(?i)jdbc:(mysql|postgresql|sqlserver|oracle|mariadb|clickhouse|h2|sqlite|db2|sybase|dm)://[^\\s\"']+\n" +
                "MongoDB连接=(?i)mongodb(\\+srv)?://[^\\s\"']+\n" +
                "Redis连接=(?i)rediss?://[^\\s\"']+\n" +
                "MySQL连接=(?i)mysql://[^\\s\"']+\n" +
                "PostgreSQL连接=(?i)postgres(ql)?://[^\\s\"']+\n" +
                "ClickHouse连接=(?i)clickhouse://[^\\s\"']+\n" +
                "Elasticsearch连接=(?i)https?://[^\\s\"']*(?:@)[^\\s\"']*(?:9200|9300)[^\\s\"']*\n" +
                "AMQP连接=(?i)amqps?://[^\\s\"']+\n" +
                "LDAP连接=(?i)ldaps?://[^\\s\"']+\n" +
                "Memcached连接=(?i)memcached://[^\\s\"']+\n" +
                "InfluxDB连接=(?i)influxdb://[^\\s\"']+\n" +
                "Cassandra连接=(?i)cassandra://[^\\s\"']+\n" +
                "FTP连接=(?i)ftps?://[^\\s\"']+\n" +
                "SSH连接=(?i)ssh://[^\\s\"']+\n" +
                "达梦连接=(?i)jdbc:dm://[^\\s\"']+\n" +
                "人大金仓连接=(?i)jdbc:kingbase[^\\s\"']+\n" +
                "南大通用连接=(?i)jdbc:gbase[^\\s\"']+\n" +

                "RSA私钥=-----BEGIN RSA PRIVATE KEY-----\n" +
                "EC私钥=-----BEGIN EC PRIVATE KEY-----\n" +
                "DSA私钥=-----BEGIN DSA PRIVATE KEY-----\n" +
                "OPENSSH私钥=-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                "PGP私钥=-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "PKCS8私钥=-----BEGIN PRIVATE KEY-----\n" +
                "PKCS8加密私钥=-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
                "证书=-----BEGIN CERTIFICATE-----\n" +
                "SSH公钥=ssh-(?:rsa|dss|ed25519|ecdsa)\\s+[A-Za-z0-9+/]+=*\n" +

                "Authorization头=(?i)Authorization\\s*:\\s*(?:Basic|Bearer|Token|Digest|AWS4-HMAC-SHA256)\\s+[A-Za-z0-9+/=._-]{10,}\n" +
                "X-API-Key头=(?i)X-API-Key\\s*:\\s*[^\\r\\n]{8,}\n" +
                "X-Auth-Token头=(?i)X-Auth-Token\\s*:\\s*[^\\r\\n]{8,}\n" +
                "Server信息泄露=(?i)(?:X-Powered-By|Server|X-AspNet-Version|X-AspNetMvc-Version)\\s*:\\s*[^\\r\\n]+\n" +
                "X-Debug-Token=(?i)X-Debug-Token\\s*:\\s*[^\\r\\n]+\n" +

                "微信AppID=\\bwx[a-f0-9]{16}\\b\n" +
                "微信AppSecret=(?i)(appsecret|wechat[_-]?secret)\\s*[:=]\\s*[\"']?[a-f0-9]{32}[\"']?\n" +
                "支付宝AppID=\\b20\\d{14}\\b\n" +
                "支付宝私钥=(?i)(alipay[_-]?private[_-]?key|app_private_key)\\s*[:=]\\s*[\"']?MII[A-Za-z0-9+/=]{100,}[\"']?\n" +

                "Sentry DSN=https://[a-f0-9]{32}@[a-z0-9]+\\.ingest\\.sentry\\.io/\\d+\n" +
                "Datadog API Key=(?i)(dd[_-]?api[_-]?key|datadog[_-]?api[_-]?key)\\s*[:=]\\s*[\"']?[a-f0-9]{32}[\"']?\n" +
                "Datadog App Key=(?i)(dd[_-]?app[_-]?key|datadog[_-]?app[_-]?key)\\s*[:=]\\s*[\"']?[a-f0-9]{40}[\"']?\n" +
                "New Relic Key=\\bNRAK-[A-Z0-9]{27}\\b\n" +
                "New Relic Insights=\\bNRIQ-[A-Za-z0-9_-]{32}\\b\n" +
                "New Relic Browser=\\bNRJS-[a-f0-9]{19}\\b\n" +
                "Grafana Token=\\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\\b\n" +
                "Grafana Cloud Token=\\bglc_[A-Za-z0-9]{44,}\\b\n" +
                "PagerDuty Key=(?i)(pagerduty[_-]?(?:api[_-]?)?key|pd[_-]?api[_-]?key)\\s*[:=]\\s*[\"']?[A-Za-z0-9+/=]{20,}[\"']?\n" +
                "Dynatrace Token=\\bdt0c01\\.[A-Z0-9]{24}\\.[A-Za-z0-9]{64}\\b\n" +
                "Elastic APM Token=(?i)(elastic[_-]?apm[_-]?secret[_-]?token)\\s*[:=]\\s*[\"']?[A-Za-z0-9]{20,}[\"']?\n" +

                "NPM Token=\\bnpm_[A-Za-z0-9]{36}\\b\n" +
                "PyPI Token=\\bpypi-[A-Za-z0-9_-]{70,}\\b\n" +
                "NuGet API Key=\\boy2[a-z0-9]{43}\\b\n" +
                "RubyGems Token=\\brubygems_[a-f0-9]{48}\\b\n" +

                "Vault Token=\\bs\\.[A-Za-z0-9]{24}\\b\n" +
                "Vault Unseal Key=(?i)(unseal_key|vault_unseal)\\s*[:=]\\s*[\"']?[A-Za-z0-9+/=]{44}[\"']?\n" +
                "Consul Token=(?i)(consul[_-]?(?:http[_-]?)?token)\\s*[:=]\\s*[\"']?[a-f0-9-]{36}[\"']?\n" +
                "Terraform Cloud=\\b[A-Za-z0-9]{14}\\.atlasv1\\.[A-Za-z0-9]{67}\\b\n" +
                "Pulumi Token=\\bpul-[a-f0-9]{40}\\b\n" +
                "Doppler Token=\\bdp\\.st\\.[a-zA-Z0-9]{43}\\b\n" +

                "Notion Token=\\bsecret_[A-Za-z0-9]{43}\\b\n" +
                "Notion Integration=\\bntn_[A-Za-z0-9]{50,}\\b\n" +
                "Asana Token=\\b[0-9]/[A-Za-z0-9]{32}:[A-Za-z0-9]{16}\\b\n" +
                "Linear API Key=\\blin_api_[A-Za-z0-9]{40}\\b\n" +
                "Airtable PAT=\\bpat[A-Za-z0-9]{14}\\.[a-f0-9]{64}\\b\n" +
                "Figma Token=\\bfigd_[A-Za-z0-9_-]{40,}\\b\n" +
                "Contentful Token=\\bCFPAT-[A-Za-z0-9_-]{43}\\b\n" +
                "Lark/飞书Token=(?i)(lark[_-]?app[_-]?secret|feishu[_-]?app[_-]?secret)\\s*[:=]\\s*[\"']?[A-Za-z0-9]{32,}[\"']?\n" +

                "DigitalOcean Token=\\bdop_v1_[a-f0-9]{64}\\b\n" +
                "DigitalOcean PAT=\\bdoo_v1_[a-f0-9]{64}\\b\n" +
                "DigitalOcean Refresh=\\bdor_v1_[a-f0-9]{64}\\b\n" +
                "Heroku API Key=(?i)(heroku[_-]?api[_-]?key)\\s*[:=]\\s*[\"']?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}[\"']?\n" +
                "Cloudflare API Token=(?i)(cf[_-]?api[_-]?token|cloudflare[_-]?api[_-]?token)\\s*[:=]\\s*[\"']?[A-Za-z0-9_-]{40}[\"']?\n" +
                "Cloudflare Global Key=(?i)(cf[_-]?(?:api[_-]?)?key|cloudflare[_-]?global[_-]?key)\\s*[:=]\\s*[\"']?[a-f0-9]{37}[\"']?\n" +
                "Vercel Token=(?i)(vercel[_-]?token|vc[_-]?token)\\s*[:=]\\s*[\"']?[A-Za-z0-9]{24,}[\"']?\n" +
                "Netlify Token=(?i)(netlify[_-]?(?:auth[_-]?)?token)\\s*[:=]\\s*[\"']?[A-Za-z0-9_-]{40,}[\"']?\n" +
                "Fastly API Key=(?i)(fastly[_-]?api[_-]?key)\\s*[:=]\\s*[\"']?[A-Za-z0-9_-]{32}[\"']?\n" +
                "Render API Key=\\brnd_[A-Za-z0-9]{32,}\\b\n" +
                "Fly.io Token=\\bFlyV1\\s+fm[12]_[A-Za-z0-9_-]{43}\\b\n" +

                "JWT Secret=(?i)(jwt_secret|jwt_secret_key|jwt[_-]key|jwtkey|jwt_signing)\\s*[:=]\\s*[\"']?[^\\s\"']{8,}[\"']?\n" +
                "Session Secret=(?i)(session_secret|session[_-]key|cookie[_-]secret|signing[_-]secret)\\s*[:=]\\s*[\"']?[^\\s\"']{8,}[\"']?\n" +
                "App Secret=(?i)(app_secret|app_secret_key|appsecret)\\s*[:=]\\s*[\"']?[^\\s\"']{8,}[\"']?\n" +
                "Encryption Key=(?i)(encrypt_key|encryption_key|aes_key|des_key|cipher_key|crypto_key)\\s*[:=]\\s*[\"']?[^\\s\"']{8,}[\"']?\n" +
                "Private Key Config=(?i)(private_key|privatekey)\\s*[:=]\\s*[\"']?[^\\s\"']{20,}[\"']?\n" +
                "Auth Key=(?i)(auth_key|authkey|authorization_key)\\s*[:=]\\s*[\"']?[^\\s\"']{8,}[\"']?\n" +
                "Admin密码=(?i)(admin_password|admin_pwd|adminpass)\\s*[:=]\\s*[\"']?[^\\s\"']{4,}[\"']?\n" +
                "Root密码=(?i)(root_password|root_pwd|rootpass)\\s*[:=]\\s*[\"']?[^\\s\"']{4,}[\"']?\n" +
                "DB密码=(?i)(db_password|database_password|dbpass|db_pwd)\\s*[:=]\\s*[\"']?[^\\s\"']{4,}[\"']?\n" +
                "Redis密码=(?i)(redis_password|redis_pwd|redispass|redis_auth)\\s*[:=]\\s*[\"']?[^\\s\"']{4,}[\"']?\n" +
                "Mongo密码=(?i)(mongo_password|mongodb_password|mongopass|mongo_pwd)\\s*[:=]\\s*[\"']?[^\\s\"']{4,}[\"']?\n" +
                "SMTP密码=(?i)(smtp_password|smtp_pwd|mail_password|email_password)\\s*[:=]\\s*[\"']?[^\\s\"']{4,}[\"']?\n" +
                "LDAP密码=(?i)(ldap_password|ldap_pwd|ldappass|bind_password)\\s*[:=]\\s*[\"']?[^\\s\"']{4,}[\"']?\n" +
                "OAuth Secret=(?i)(oauth_secret|oauth_client_secret|oauth_token)\\s*[:=]\\s*[\"']?[^\\s\"']{8,}[\"']?\n" +
                "SAML Key=(?i)(saml_key|saml_secret|saml_certificate)\\s*[:=]\\s*[\"']?[^\\s\"']{20,}[\"']?\n" +
                "SSO Token=(?i)(sso_token|sso_secret|sso_key)\\s*[:=]\\s*[\"']?[^\\s\"']{8,}[\"']?\n" +

                "SQL注入=(?i)(select\\s+.*\\s+from|union\\s+(?:all\\s+)?select|insert\\s+into|delete\\s+from|drop\\s+table|exec\\s+|execute\\s+|xp_cmdshell|sp_executesql|load_file|into\\s+outfile|into\\s+dumpfile)\n" +
                "XPath注入=(?i)(xpath|/\\*\\[|\\]\\[|contains\\s*\\(|text\\s*\\()\n" +
                "LDAP注入=(?i)(\\(\\|\\(|\\(\\&\\(|\\(\\!\\(|\\=\\*\\)|\\(cn=|\\(dn=|\\(uid=|\\(objectclass=)\n" +
                "命令注入=(?i)(\\||\\$\\(|\\$\\{|system\\s*\\(|exec\\s*\\(|shell_exec|passthru|popen|Runtime\\.exec|ProcessBuilder|subprocess\\.)\n" +
                "路径穿越=(?i)(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e/|\\.\\.%2f|%2e%2e%5c|%252e%252e)\n" +
                "XXE=(?i)(<!ENTITY|<!DOCTYPE.*\\[|SYSTEM\\s+\"|PUBLIC\\s+\")\n" +
                "SSRF参数=(?i)(url=|uri=|dest=|redirect=|next=|target=|rurl=|domain=|callback=|return_url=|goto=|feed=|host=|site=|html=|data=|reference=|ref=|load=|sourceUrl=)\n" +
                "开放重定向=(?i)(redirect\\s*=|location\\s*[:=]|next\\s*=|url\\s*=|return_to\\s*=|goto\\s*=|continue\\s*=|dest\\s*=|destination\\s*=|returnUrl\\s*=|forward\\s*=)\n" +
                "CORS配置=(?i)(access-control-allow-origin\\s*:\\s*\\*|access-control-allow-credentials\\s*:\\s*true)\n" +
                "CRLF注入=(?i)(%0d%0a|\\r\\n|\\\\r\\\\n)\n" +
                "反序列化=(?i)(ObjectInputStream|readObject|unserialize|deserialize|pickle\\.loads?|yaml\\.unsafe_load|eval\\s*\\(|Function\\s*\\()\n" +
                "模板注入=(?i)(\\{\\{[^}]*\\}\\}.*\\{\\{|<%[^%]*%>.*<%|\\$\\{[^}]*\\}.*\\$\\{|#\\{[^}]*\\}.*#\\{)\n" +

                "敏感路径=(?i)(/etc/passwd|/etc/shadow|/etc/hosts|/proc/self|c:\\\\windows|c:/windows|/var/log|/proc/version|/proc/net/arp|/proc/net/tcp)\n" +

                "备份文件=(?i)(\\.bak|\\.backup|\\.old|\\.copy|\\.orig|\\.save|\\.swp|\\.swo|\\.tmp|\\.temp|~$|\\.sql\\.gz|\\.sql\\.bak|\\.tar\\.bak)\n" +
                "压缩包=(?i)(\\.zip|\\.tar|\\.tar\\.gz|\\.tgz|\\.rar|\\.7z|\\.gz|\\.war|\\.jar|\\.ear)\n" +
                "日志文件=(?i)(\\.log|error_log|access_log|debug\\.log|error\\.log|application\\.log|catalina\\.out)\n" +
                "配置文件=(?i)(\\.conf|\\.config|\\.ini|\\.yaml|\\.yml|\\.json|\\.xml|\\.properties|\\.toml|\\.env)\n" +
                "源码泄露=(?i)(/\\.git/|/\\.svn/|/\\.hg/|/\\.bzr|/CVS/|\\.DS_Store|Thumbs\\.db|\\._)\n" +
                "IDE配置=(?i)(\\.idea/|\\.vscode/|\\.project|\\.classpath|\\.settings/|workspace\\.xml)\n" +
                "Docker配置=(?i)(Dockerfile|docker-compose\\.ya?ml|\\.dockerignore|docker-entrypoint)\n" +
                "K8s配置=(?i)(\\.kube/config|k8s|deployment\\.ya?ml|pod\\.ya?ml|service\\.ya?ml|configmap\\.ya?ml|secret\\.ya?ml)\n" +
                "CI/CD配置=(?i)(\\.gitlab-ci\\.yml|\\.github/workflows|Jenkinsfile|\\.circleci|\\.travis\\.yml|bitbucket-pipelines|azure-pipelines)\n" +
                "Terraform文件=(?i)(\\.tf|\\.tfvars|\\.tfstate)\n" +

                "API文档泄露=(?i)(swagger-ui|openapi|api-docs|graphiql|playground|altair|knife4j|rapidoc)\n" +
                "调试信息=(?i)(debug\\s*(?:info|output|mode)|phpinfo|var_dump|print_r|console\\.(?:log|debug|trace|error)\\s*\\(|stacktrace|stack_trace)\n" +
                "Java异常堆栈=(?i)(Exception\\s+in\\s+thread|at\\s+[a-zA-Z0-9$.]+\\([A-Za-z0-9]+\\.java:\\d+\\)|java\\.lang\\.[A-Z]\\w+Exception)\n" +
                "Python异常堆栈=(?i)(Traceback\\s+\\(most\\s+recent|File\\s+\"[^\"]+\",\\s+line\\s+\\d+|raise\\s+\\w+Error)\n" +
                "数据库错误=(?i)(mysql_error|pg_error|ora-\\d{5}|SQL\\s*syntax.*near|You\\s+have\\s+an\\s+error\\s+in\\s+your\\s+SQL|SQLSTATE\\[|PDOException|Warning.*mysql_|Unclosed\\s+quotation|MariaDB\\s+server)\n" +
                "PHP错误=(?i)(PHP\\s+(?:Fatal|Parse|Warning|Notice)\\s+error|Call\\s+to\\s+undefined\\s+function|Allowed\\s+memory\\s+size)\n" +
                "Debug开关=(?i)(debug|debug_mode|debug_enabled|development_mode)\\s*[:=]\\s*(?:true|1|yes|on|enabled)\n" +
                "版本信息头=(?i)(x-powered-by|server-version|product-version)\\s*:\\s*[^\\r\\n]+\n" +
                "Bcrypt哈希=\\$2[aby]?\\$\\d{1,2}\\$[./A-Za-z0-9]{53}\n" +

                "Web框架=(?i)(?:X-Powered-By|Server)\\s*:\\s*(?:Express|Kestrel|Jetty|Undertow|Netty|Tomcat|Nginx|Apache|IIS|Werkzeug|Gunicorn|uvicorn|Puma|Unicorn|WEBrick|Cowboy)\n" +
                "Java框架=(?i)(springframework|springboot|spring-boot|struts2?|mybatis|hibernate|shiro|dubbo|fastjson|jackson|log4j|druid|ruoyi|jeecg|bladex)\n" +
                "PHP框架=(?i)(thinkphp|laravel|symfony|codeigniter|yii|drupal|wordpress|joomla|typecho|discuz|phpcms|dedecms|empirecms)\n" +
                "Python框架=(?i)(django|flask|fastapi|tornado|sanic|aiohttp|bottle|pyramid|web2py|streamlit|gradio)\n" +
                "Go框架=(?i)(gin-gonic|beego|echo|fiber|iris|revel|chi|gorilla/mux)\n" +
                "系统识别=(?i)\\b(oa|erp|crm|hrm|ehr|mes|wms|srm|plm|bi|bpm|his|hss|cms|lms|scm|mdm|iot|scada)\\b\n" +

                "Generic API Key=(?i)(?:key|api|token|secret|client|passwd|password|auth|access)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=>?|:{1,3}=|\\|\\|:)(?:'|\"|\\s|=){0,5}([0-9a-z\\-_.=]{10,150})\n" +
                "Password in URL=[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]\n" +
                "Google OAuth Access=ya29\\.[0-9A-Za-z\\-_]+\n" +
                "Facebook Access Token=EAACEdEose0cBA[0-9A-Za-z]+\n" +
                "PayPal Braintree=access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}\n" +
                "AWS AppSync Key=da2-[a-z0-9]{26}\n" +
                "Twitter OAuth=(?i)twitter.*['\"][0-9a-zA-Z]{35,44}['\"]\n" +
                "Picatic API=sk_live_[0-9a-z]{32}\n" +

                "Vercel Env=(?i)(vercel|vc)[_-]?(?:api[_-]?)?(?:key|token)\\s*[:=]\\s*[\"']?[A-Za-z0-9_]{24,}[\"']?\n" +
                "Railway Token=(?i)railway[_-]?token\\s*[:=]\\s*[\"']?[A-Za-z0-9_-]{30,}[\"']?\n" +
                "Supabase Key=eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9._-]{10,}\n" +
                "Supabase Anon=(?i)supabase[_-]?(?:anon|service)[_-]?key\\s*[:=]\\s*[\"']?eyJ[\"']?\n" +
                "PlanetScale Password=(?i)pscale[_-]?(?:password|token)\\s*[:=]\\s*[\"']?[A-Za-z0-9_-]{20,}[\"']?\n" +
                "Neon DB=(?i)neon[_-]?(?:database|connection)[_-]?(?:url|string)\\s*[:=]\\s*[\"']?postgres[^\"]+[\"']?\n" +
                "Upstash Redis=(?i)upstash[_-]?(?:redis|rest)[_-]?(?:url|token)\\s*[:=]\\s*[\"']?[^\"']{20,}[\"']?\n" +
                "Ably Key=(?i)ably[_-]?(?:api[_-]?)?key\\s*[:=]\\s*[\"']?[A-Za-z0-9._-]{20,}[\"']?\n" +
                "LaunchDarkly=(?i)sdk[_-]?key\\s*[:=]\\s*[\"']?[a-f0-9-]{36}[\"']?\n" +
                "LogTail Source=(?i)(logtail|betterstack)[_-]?(?:source[_-]?)?token\\s*[:=]\\s*[\"']?[A-Za-z0-9]{30,}[\"']?\n" +

                "七牛云AK=(?i)(qiniu|kodo)[_-]?(?:access[_-]?)?key\\s*[:=]\\s*[\"']?[A-Za-z0-9]{20,}[\"']?\n" +
                "七牛SK=(?i)(qiniu|kodo)[_-]?secret[_-]?key\\s*[:=]\\s*[\"']?[A-Za-z0-9]{30,}[\"']?\n" +
                "又拍云=(?i)(upyun|b0)[_-]?(?:bucket|operator|password)\\s*[:=]\\s*[\"']?[^\"']{8,}[\"']?\n" +
                "环信=(?i)(easemob|huanxin)[_-]?(?:appkey|client_id|client_secret)\\s*[:=]\\s*[\"']?[^\"']{8,}[\"']?\n" +
                "融云=(?i)rongcloud[_-]?(?:app_key|app_secret)\\s*[:=]\\s*[\"']?[^\"']{8,}[\"']?\n" +
                "声网Agora=(?i)agora[_-]?(?:app_id|app_certificate)\\s*[:=]\\s*[\"']?[A-Za-z0-9]{32,}[\"']?\n" +
                "极光推送=(?i)(jpush|jiguang)[_-]?(?:app_key|master_secret)\\s*[:=]\\s*[\"']?[A-Za-z0-9]{20,}[\"']?\n" +
                "个推=(?i)getui[_-]?(?:appid|appkey|appsecret)\\s*[:=]\\s*[\"']?[^\"']{8,}[\"']?\n" +

                "暴露路径/etc/passwd=(?i)[\"']/etc/passwd[\"']\n" +
                "暴露路径.env=(?i)[\"']\\.env[\"']\n" +
                "暴露路径git=(?i)[\"']\\.git/[^\"']*[\"']\n" +
                "暴露路径WEB-INF=(?i)[\"']WEB-INF/[^\"']*[\"']\n" +
                "硬编码域名=(?i)(?:api|admin|backend|internal)\\.(?:example\\.com|test\\.com|local|localhost)[^\\s\"']*\n"
        );
        loadRulesFromText();
    }

    private void loadRulesFromText() {
        rules.clear();
        String[] lines = rulesArea.getText().split("\\r?\\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || !trimmed.contains("=")) {
                continue;
            }
            int idx = trimmed.indexOf('=');
            String name = trimmed.substring(0, idx).trim();
            String regex = trimmed.substring(idx + 1).trim();
            if (name.isEmpty() || regex.isEmpty()) {
                continue;
            }
            try {
                Pattern pattern = Pattern.compile(regex);
                rules.add(new RegexRule(name, pattern));
            } catch (Exception ex) {
                callbacks.printError("Invalid regex: " + regex);
            }
        }
    }

    private void importRules() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Rules");
        int result = chooser.showOpenDialog(panel);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            StringBuilder sb = new StringBuilder(rulesArea.getText());
            if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '\n') {
                sb.append("\n");
            }
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            rulesArea.setText(sb.toString());
            loadRulesFromText();
        } catch (Exception ex) {
            callbacks.printError(ex.getMessage());
        }
    }

    private void scanMessage(IHttpRequestResponse messageInfo) {
        if (messageInfo == null) {
            return;
        }
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        StringBuilder combined = new StringBuilder();
        combined.append(String.join("\n", requestInfo.getHeaders())).append("\n");
        byte[] request = messageInfo.getRequest();
        int reqBodyOffset = requestInfo.getBodyOffset();
        if (request != null && reqBodyOffset >= 0 && reqBodyOffset < request.length) {
            int reqLength = Math.min(request.length - reqBodyOffset, 200000);
            if (reqLength > 0) {
                byte[] reqBodyBytes = new byte[reqLength];
                System.arraycopy(request, reqBodyOffset, reqBodyBytes, 0, reqLength);
                String reqBody = helpers.bytesToString(reqBodyBytes);
                if (reqBody != null && !reqBody.isEmpty()) {
                    combined.append(reqBody).append("\n");
                }
            }
        }
        if (messageInfo.getResponse() != null) {
            IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
            combined.append(String.join("\n", responseInfo.getHeaders())).append("\n");
            int bodyOffset = responseInfo.getBodyOffset();
            byte[] response = messageInfo.getResponse();
            if (bodyOffset >= 0 && bodyOffset < response.length) {
                int length = Math.min(response.length - bodyOffset, 500000);
                if (length > 0) {
                    byte[] bodyBytes = new byte[length];
                    System.arraycopy(response, bodyOffset, bodyBytes, 0, length);
                    String body = helpers.bytesToString(bodyBytes);
                    if (body != null && !body.isEmpty()) {
                        combined.append(body);
                    }
                }
            }
        }
        String content = combined.toString();
        if (content.isEmpty()) {
            return;
        }
        String url = requestInfo.getUrl().toString();
        String time = timeFormat.format(new Date());
        for (RegexRule rule : rules) {
            Matcher matcher = rule.pattern.matcher(content);
            while (matcher.find()) {
                String match = matcher.group();
                if (isPlaceholderOrExample(match)) {
                    continue;
                }
                ResultItem item = new ResultItem(getName(), rule.name, url, match, time, messageInfo);
                SwingUtilities.invokeLater(() -> model.addItem(item));
            }
        }
    }

    private boolean isPlaceholderOrExample(String match) {
        if (match == null || match.length() < 3) {
            return false;
        }
        String lower = match.toLowerCase();
        if (lower.contains("your_") || lower.contains("your-") || lower.contains("replace_me")
                || lower.contains("example.com") || lower.contains("test.com") || lower.contains("xxx")
                || lower.contains("sample") || lower.contains("placeholder") || lower.contains("dummy")
                || lower.matches(".*<[a-z]+>.*") || lower.contains("changeme") || lower.contains("insert_")) {
            return true;
        }
        return false;
    }

    private static class RegexRule {
        private final String name;
        private final Pattern pattern;

        private RegexRule(String name, Pattern pattern) {
            this.name = name;
            this.pattern = pattern;
        }
    }
}
