package com.example.burp.core;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

public class UnauthorizedScanModule implements Module {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final ResultTableModel model;
    private final ResultTablePanel resultPanel;
    private final JPanel panel;
    private final JTextArea pathsArea;
    private final JTextArea hitPatternArea;
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Set<String> checkedTargets = new HashSet<String>();
    private List<String> paths = new ArrayList<String>();
    private Pattern hitPattern;

    public UnauthorizedScanModule(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.model = new ResultTableModel();
        this.resultPanel = new ResultTablePanel(callbacks, model);
        this.pathsArea = new JTextArea(8, 80);
        this.hitPatternArea = new JTextArea(2, 80);
        this.panel = new JPanel(new BorderLayout());
        initDefaultConfig();
        initUi();
    }

    @Override
    public String getName() {
        return "Unauthorized Scan";
    }

    @Override
    public JPanel getPanel() {
        return panel;
    }

    @Override
    public void processResponse(int toolFlag, IHttpRequestResponse messageInfo) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
            scheduleChecks(messageInfo);
        }
    }

    @Override
    public void processManual(IHttpRequestResponse messageInfo) {
        scheduleChecks(messageInfo);
    }

    private void initUi() {
        JPanel top = new JPanel(new BorderLayout());
        JPanel pathsPanel = new JPanel(new BorderLayout());
        pathsPanel.add(new JLabel("Paths to check (one per line):"), BorderLayout.NORTH);
        pathsPanel.add(new JScrollPane(pathsArea), BorderLayout.CENTER);
        JPanel patternPanel = new JPanel(new BorderLayout());
        patternPanel.add(new JLabel("Hit pattern (regex for response body match):"), BorderLayout.NORTH);
        patternPanel.add(new JScrollPane(hitPatternArea), BorderLayout.CENTER);
        JPanel actions = new JPanel();
        JButton applyBtn = new JButton("Apply Config");
        JButton importBtn = new JButton("Import Config");
        applyBtn.addActionListener(e -> loadConfigFromText());
        importBtn.addActionListener(e -> importConfig());
        actions.add(applyBtn);
        actions.add(importBtn);
        top.add(pathsPanel, BorderLayout.NORTH);
        top.add(patternPanel, BorderLayout.CENTER);
        top.add(actions, BorderLayout.SOUTH);
        panel.add(top, BorderLayout.NORTH);
        panel.add(resultPanel, BorderLayout.CENTER);
    }

    private void initDefaultConfig() {
        String defaultHitPattern = "(?i)(swagger|openapi|actuator|api.?docs|doc\\.html|knife4j|rapidoc|druid|solr|jenkins|sonarqube|argocd|phpinfo|git|svn|config|env|heapdump|mappings|configprops|trace|graphql|graphiql|playground|jolokia|nexus|artifactory|harbor|registry|v2/_catalog|elasticsearch|opensearch|kibana|prometheus|grafana|victoriametrics|alertmanager|jaeger|metrics|loggers|logfile|swagger-ui|openapi\\.json|nacos|apollo|sentinel|consul|etcd|xxl-job|elastic-job|powerjob|rocketmq|kafka|kafka-ui|zipkin|skywalking|seata|dubbo|h2-console|tomcat manager|rabbitmq|activemq|pulsar|dashboard|admin|login|health|threaddump|gateway|portainer|rancher|kubernetes|phpmyadmin|adminer|pgadmin|mongo-express|redis|minio|gitea|gogs|gitlab|wordpress|wp-json|django|flower|sidekiq|resque|bull-board|debug/pprof|debug/vars|server-status|server-info|nginx.status|stub_status|meta-data|metadata|computeMetadata|WEB-INF|phpMyAdmin|well-known|security\\.txt|robots\\.txt|sitemap|crossdomain|terraform|backup|dump|webshell|shell|cmd|eval|httptrace|auditevents|sessions|conditions|flyway|liquibase|quartz|sbom|chaosmonkey|apidocs|api-spec|redoc|scalar|stoplight|telescope|_debugbar|superset|metabase|redash|airflow|mlflow|kubeflow|ruoyi|jeecg|renren|blade|eladmin|cockpit|webmin|cpanel|zabbix|_framework|blazor|serverless|vercel|netlify|amplify)";
        try (InputStream is = getClass().getResourceAsStream("/unauthorized_paths_enhanced.txt")) {
            if (is != null) {
                StringBuilder sb = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                }
                pathsArea.setText(sb.toString());
                hitPatternArea.setText(defaultHitPattern);
                loadConfigFromText();
                return;
            }
        } catch (Exception e) {
            callbacks.printError("Load resource paths: " + e.getMessage());
        }
        pathsArea.setText(
                "/swagger-ui/\n" +
                "/swagger-ui.html\n" +
                "/swagger-ui/index.html\n" +
                "/swagger\n" +
                "/swagger.json\n" +
                "/swagger.yaml\n" +
                "/swagger.yml\n" +
                "/swagger/index.html\n" +
                "/swagger/ui/index.html\n" +
                "/swagger/swagger-ui.html\n" +
                "/v2/api-docs\n" +
                "/v2/api-docs?group=default\n" +
                "/v3/api-docs\n" +
                "/v3/api-docs/swagger-config\n" +
                "/api-docs\n" +
                "/api-docs.json\n" +
                "/api-docs.yaml\n" +
                "/api-docs/index.html\n" +
                "/api/swagger.json\n" +
                "/api/swagger.yaml\n" +
                "/api/swagger-ui.html\n" +
                "/api/swagger-ui/\n" +
                "/api/v1/swagger.json\n" +
                "/api/v2/swagger.json\n" +
                "/api/v3/swagger.json\n" +
                "/api-docs/swagger.json\n" +
                "/swagger/v1/swagger.json\n" +
                "/swagger/v2/swagger.json\n" +
                "/swagger/v3/swagger.json\n" +
                "/openapi.json\n" +
                "/openapi.yaml\n" +
                "/openapi.yml\n" +
                "/openapi/v3/api-docs\n" +
                "/swagger-resources\n" +
                "/swagger-resources/configuration/ui\n" +
                "/swagger-resources/configuration/security\n" +
                "/configuration/ui\n" +
                "/webjars/swagger-ui/\n" +
                "/webjars/swagger-ui/index.html\n" +
                "/doc.html\n" +
                "/knife4j/doc.html\n" +
                "/knife4j\n" +
                "/knife4j/api-docs\n" +
                "/redoc\n" +
                "/redoc/index.html\n" +
                "/docs\n" +
                "/docs/\n" +
                "/docs/api\n" +
                "/api-doc\n" +
                "/api-documentation\n" +
                "/rapidoc\n" +
                "/rapidoc/index.html\n" +
                "/scalar\n" +
                "/stoplight\n" +
                "/elements\n" +
                "/graphql\n" +
                "/graphiql\n" +
                "/graphiql.html\n" +
                "/graphql/playground\n" +
                "/graphql/console\n" +
                "/graphql/schema\n" +
                "/graphql/schema.json\n" +
                "/graphql/schema.graphql\n" +
                "/altair\n" +
                "/voyager\n" +
                "/playground\n" +
                "/api/graphql\n" +
                "/api/playground\n" +
                "/api/schema\n" +
                "/api/schema.json\n" +
                "/api/schema.graphql\n" +

                "/actuator\n" +
                "/actuator/\n" +
                "/actuator/health\n" +
                "/actuator/health/liveness\n" +
                "/actuator/health/readiness\n" +
                "/actuator/env\n" +
                "/actuator/env.json\n" +
                "/actuator/env/{property}\n" +
                "/actuator/info\n" +
                "/actuator/info.json\n" +
                "/actuator/metrics\n" +
                "/actuator/metrics/{metric}\n" +
                "/actuator/prometheus\n" +
                "/actuator/heapdump\n" +
                "/actuator/threaddump\n" +
                "/actuator/mappings\n" +
                "/actuator/configprops\n" +
                "/actuator/trace\n" +
                "/actuator/httptrace\n" +
                "/actuator/loggers\n" +
                "/actuator/loggers/{logger}\n" +
                "/actuator/logfile\n" +
                "/actuator/caches\n" +
                "/actuator/caches/{cache}\n" +
                "/actuator/scheduledtasks\n" +
                "/actuator/beans\n" +
                "/actuator/conditions\n" +
                "/actuator/auditevents\n" +
                "/actuator/flyway\n" +
                "/actuator/liquibase\n" +
                "/actuator/sessions\n" +
                "/actuator/sessions/{sessionId}\n" +
                "/actuator/shutdown\n" +
                "/actuator/startup\n" +
                "/actuator/quartz\n" +
                "/actuator/quartz/jobs\n" +
                "/actuator/quartz/triggers\n" +
                "/actuator/sbom\n" +
                "/actuator/sbom/application\n" +
                "/actuator/jolokia\n" +
                "/actuator/jolokia/list\n" +
                "/actuator/jolokia/read\n" +
                "/actuator/gateway/routes\n" +
                "/actuator/gateway/routes/{id}\n" +
                "/actuator/gateway/globalfilters\n" +
                "/actuator/gateway/routefilters\n" +
                "/actuator/gateway/refresh\n" +
                "/actuator/chaosmonkey\n" +
                "/actuator/chaosmonkey/status\n" +
                "/actuator/chaosmonkey/assaults\n" +
                "/actuator/chaosmonkey/watchers\n" +
                "/actuator/refresh\n" +
                "/actuator/features\n" +
                "/actuator/integrationgraph\n" +
                "/actuator/serviceregistry\n" +
                "/actuator/busrefresh\n" +
                "/actuator/busenv\n" +
                "/env\n" +
                "/health\n" +
                "/info\n" +
                "/trace\n" +
                "/dump\n" +
                "/beans\n" +
                "/mappings\n" +
                "/autoconfig\n" +
                "/configprops\n" +
                "/metrics\n" +
                "/heapdump\n" +
                "/threaddump\n" +
                "/loggers\n" +
                "/auditevents\n" +
                "/shutdown\n" +
                "/restart\n" +
                "/pause\n" +
                "/resume\n" +
                "/refresh\n" +

                "/druid\n" +
                "/druid/index.html\n" +
                "/druid/login.html\n" +
                "/druid/datasource.html\n" +
                "/druid/sql.html\n" +
                "/druid/wall.html\n" +
                "/druid/webapp.html\n" +
                "/druid/weburi.html\n" +
                "/druid/websession.html\n" +
                "/druid/api/stat\n" +

                "/jenkins\n" +
                "/jenkins/script\n" +
                "/jenkins/scriptText\n" +
                "/jenkins/credentials\n" +
                "/jenkins/people\n" +
                "/jenkins/api/json\n" +
                "/jenkins/manage\n" +
                "/jenkins/configureSecurity\n" +
                "/jenkins/systemInfo\n" +
                "/sonarqube\n" +
                "/sonarqube/api/system/status\n" +
                "/sonar\n" +
                "/sonar/api/system/status\n" +
                "/sonar/api/components/search\n" +
                "/argocd\n" +
                "/argocd/api/v1/applications\n" +
                "/argocd/api/v1/clusters\n" +

                "/nacos\n" +
                "/nacos/\n" +
                "/nacos/#/login\n" +
                "/nacos/v1/ns/operator/metrics\n" +
                "/nacos/v1/cs/configs?dataId=&group=&appName=&config_tags=&pageNo=1&pageSize=10&tenant=&search=accurate\n" +
                "/nacos/v1/auth/users?pageNo=1&pageSize=9\n" +
                "/nacos/v1/ns/instance/list?serviceName=\n" +
                "/apollo\n" +
                "/apollo/#/config\n" +
                "/apollo-admin\n" +
                "/apollo-portal\n" +
                "/sentinel\n" +
                "/sentinel/#/dashboard\n" +
                "/sentinel/api/flow/rules\n" +
                "/consul\n" +
                "/consul/v1/kv/?recurse\n" +
                "/v1/agent/self\n" +
                "/v1/catalog/services\n" +
                "/v1/kv/?recurse\n" +
                "/etcd\n" +
                "/v2/keys\n" +
                "/v3/kv/range\n" +

                "/xxl-job-admin\n" +
                "/xxl-job-admin/login\n" +
                "/xxl-job-admin/jobinfo\n" +
                "/xxl-job-admin/api\n" +
                "/job/admin\n" +
                "/elastic-job-console\n" +
                "/powerjob\n" +
                "/schedulerx\n" +

                "/kafka\n" +
                "/kafka-manager\n" +
                "/kafka/consumer\n" +
                "/kafka-ui\n" +
                "/kafka-ui/api/clusters\n" +
                "/redpanda-console\n" +
                "/rocketmq-console\n" +
                "/rocketmq\n" +
                "/rocketmq/#/dashboard\n" +
                "/rocketmq-dashboard\n" +
                "/rabbitmq\n" +
                "/api/overview\n" +
                "/api/queues\n" +
                "/api/exchanges\n" +
                "/activemq\n" +
                "/activemq/admin\n" +
                "/pulsar-manager\n" +
                "/pulsar/admin/v2/tenants\n" +

                "/zipkin\n" +
                "/zipkin/api/v2/services\n" +
                "/skywalking\n" +
                "/skywalking/graphql\n" +
                "/jaeger\n" +
                "/jaeger/search\n" +
                "/jaeger/api/traces\n" +

                "/seata\n" +
                "/seata/v1/registry\n" +
                "/dubbo\n" +
                "/dubbop\n" +

                "/nexus\n" +
                "/nexus/service/rest/v1/status\n" +
                "/nexus/#welcome\n" +
                "/nexus/service/rest/v1/search\n" +
                "/artifactory\n" +
                "/artifactory/webapp\n" +
                "/artifactory/api/system/ping\n" +
                "/harbor\n" +
                "/harbor/sign-in\n" +
                "/harbor/api/v2.0/projects\n" +
                "/registry\n" +
                "/v2/_catalog\n" +
                "/v2/\n" +

                "/elasticsearch\n" +
                "/_cat/indices\n" +
                "/_cat/health\n" +
                "/_cat/nodes\n" +
                "/_cluster/health\n" +
                "/_cluster/settings\n" +
                "/_nodes\n" +
                "/_nodes/stats\n" +
                "/_search\n" +
                "/_all/_search\n" +
                "/_mapping\n" +
                "/_aliases\n" +
                "/_template\n" +
                "/_ingest/pipeline\n" +
                "/kibana\n" +
                "/kibana/app/kibana\n" +
                "/kibana/api/status\n" +
                "/opensearch\n" +
                "/_plugins/_security\n" +
                "/_opendistro/_security/api/roles\n" +
                "/solr\n" +
                "/solr/admin\n" +
                "/solr/#/\n" +
                "/solr/admin/info/system\n" +
                "/solr/admin/cores\n" +

                "/metrics\n" +
                "/metrics/health\n" +
                "/prometheus\n" +
                "/prometheus/targets\n" +
                "/prometheus/graph\n" +
                "/prometheus/api/v1/targets\n" +
                "/prometheus/api/v1/query?query=up\n" +
                "/grafana\n" +
                "/grafana/login\n" +
                "/grafana/api/dashboards/home\n" +
                "/grafana/api/org\n" +
                "/grafana/api/search\n" +
                "/victoriametrics\n" +
                "/alertmanager\n" +
                "/alertmanager/api/v2/alerts\n" +

                "/portainer\n" +
                "/portainer/api/status\n" +
                "/portainer/api/endpoints\n" +
                "/rancher\n" +
                "/rancher/v3\n" +
                "/rancher/v3/settings\n" +
                "/kubernetes-dashboard\n" +
                "/k8s/api/v1/namespaces\n" +
                "/api/v1/pods\n" +
                "/api/v1/services\n" +
                "/api/v1/namespaces\n" +
                "/api/v1/nodes\n" +

                "/h2-console\n" +
                "/h2-console/login.jsp\n" +
                "/phpmyadmin\n" +
                "/phpMyAdmin\n" +
                "/pma\n" +
                "/mysql\n" +
                "/adminer\n" +
                "/adminer.php\n" +
                "/pgadmin\n" +
                "/pgadmin4\n" +
                "/mongo-express\n" +
                "/redis-commander\n" +
                "/redis-insight\n" +
                "/memadmin\n" +

                "/minio\n" +
                "/minio/login\n" +
                "/minio/health/live\n" +
                "/minio/health/ready\n" +

                "/gitea\n" +
                "/gitea/api/v1\n" +
                "/gogs\n" +
                "/gogs/api/v1\n" +
                "/gitlab\n" +
                "/gitlab/explore\n" +

                "/admin\n" +
                "/admin/\n" +
                "/admin/login\n" +
                "/admin/console\n" +
                "/admin/dashboard\n" +
                "/administrator\n" +
                "/administrator/index.php\n" +
                "/dashboard\n" +
                "/manage\n" +
                "/management\n" +
                "/console\n" +
                "/system\n" +
                "/monitor\n" +
                "/backstage\n" +
                "/backend\n" +
                "/panel\n" +
                "/control\n" +
                "/webmaster\n" +

                "/wp-admin/\n" +
                "/wp-login.php\n" +
                "/wp-config.php.bak\n" +
                "/wp-json/wp/v2/users\n" +
                "/wp-json/\n" +
                "/xmlrpc.php\n" +
                "/wp-content/debug.log\n" +

                "/phpinfo.php\n" +
                "/info.php\n" +
                "/pi.php\n" +
                "/php_info.php\n" +
                "/test.php\n" +

                "/django-admin/\n" +
                "/admin/login/?next=/admin/\n" +
                "/flower\n" +
                "/flower/api/tasks\n" +
                "/celery\n" +

                "/debug/pprof/\n" +
                "/debug/pprof/goroutine\n" +
                "/debug/pprof/heap\n" +
                "/debug/pprof/threadcreate\n" +
                "/debug/pprof/block\n" +
                "/debug/pprof/mutex\n" +
                "/debug/pprof/cmdline\n" +
                "/debug/pprof/profile\n" +
                "/debug/pprof/symbol\n" +
                "/debug/pprof/trace\n" +
                "/debug/vars\n" +
                "/debug/requests\n" +
                "/debug/events\n" +

                "/rails/info/routes\n" +
                "/rails/info/properties\n" +
                "/sidekiq\n" +
                "/sidekiq/queues\n" +
                "/sidekiq/busy\n" +
                "/resque\n" +
                "/resque/overview\n" +

                "/bull-board\n" +
                "/bull-board/api/queues\n" +
                "/express-admin\n" +

                "/jolokia\n" +
                "/jolokia/list\n" +
                "/jolokia/read/java.lang:type=Runtime\n" +
                "/manager/html\n" +
                "/host-manager/html\n" +
                "/manager/status\n" +

                "/server-status\n" +
                "/server-info\n" +
                "/.htaccess\n" +
                "/nginx-status\n" +
                "/stub_status\n" +
                "/nginx_status\n" +
                "/apm-server-status\n" +

                "/latest/meta-data/\n" +
                "/metadata/v1/\n" +
                "/computeMetadata/v1/\n" +

                "/.git/config\n" +
                "/.git/index\n" +
                "/.git/HEAD\n" +
                "/.gitignore\n" +
                "/.svn/entries\n" +
                "/.svn/wc.db\n" +
                "/.hg\n" +
                "/.hg/hgrc\n" +
                "/.env\n" +
                "/.env.local\n" +
                "/.env.prod\n" +
                "/.env.production\n" +
                "/.env.development\n" +
                "/.env.staging\n" +
                "/.env.test\n" +
                "/.env.backup\n" +
                "/config.php.bak\n" +
                "/config.yml\n" +
                "/config.yaml\n" +
                "/config.json\n" +
                "/config.js\n" +
                "/application.yml\n" +
                "/application.yaml\n" +
                "/application.properties\n" +
                "/application-dev.yml\n" +
                "/application-prod.yml\n" +
                "/application-test.yml\n" +
                "/bootstrap.yml\n" +
                "/bootstrap.yaml\n" +
                "/web.config\n" +
                "/web.config.bak\n" +
                "/appsettings.json\n" +
                "/appsettings.Development.json\n" +
                "/appsettings.Production.json\n" +
                "/WEB-INF/web.xml\n" +
                "/WEB-INF/applicationContext.xml\n" +
                "/settings.json\n" +
                "/settings.py\n" +
                "/database.yml\n" +
                "/credentials.yml\n" +
                "/secrets.yml\n" +

                "/robots.txt\n" +
                "/sitemap.xml\n" +
                "/crossdomain.xml\n" +
                "/clientaccesspolicy.xml\n" +
                "/security.txt\n" +
                "/.well-known/security.txt\n" +
                "/.well-known/openid-configuration\n" +
                "/.well-known/jwks.json\n" +
                "/.well-known/assetlinks.json\n" +
                "/.well-known/apple-app-site-association\n" +

                "/.terraform/\n" +
                "/terraform.tfstate\n" +
                "/terraform.tfvars\n" +

                "/backup.sql\n" +
                "/backup.zip\n" +
                "/dump.sql\n" +
                "/database.sql\n" +
                "/db.sql\n" +
                "/data.sql\n" +
                "/site.tar.gz\n" +
                "/www.zip\n" +
                "/wwwroot.zip\n" +
                "/web.zip\n"
        );
        hitPatternArea.setText("(?i)(swagger|openapi|actuator|api.?docs|doc\\.html|knife4j|rapidoc|druid|solr|jenkins|sonarqube|argocd|phpinfo|git|svn|config|env|heapdump|mappings|configprops|trace|graphql|graphiql|playground|jolokia|nexus|artifactory|harbor|registry|v2/_catalog|elasticsearch|opensearch|kibana|prometheus|grafana|victoriametrics|alertmanager|jaeger|metrics|loggers|logfile|swagger-ui|openapi\\.json|nacos|apollo|sentinel|consul|etcd|xxl-job|elastic-job|powerjob|rocketmq|kafka|kafka-ui|zipkin|skywalking|seata|dubbo|h2-console|tomcat manager|rabbitmq|activemq|pulsar|dashboard|admin|login|health|threaddump|gateway|portainer|rancher|kubernetes|phpmyadmin|adminer|pgadmin|mongo-express|redis|minio|gitea|gogs|gitlab|wordpress|wp-json|django|flower|sidekiq|resque|bull-board|debug/pprof|debug/vars|server-status|server-info|nginx.status|stub_status|meta-data|metadata|computeMetadata|WEB-INF|phpMyAdmin|well-known|security\\.txt|robots\\.txt|sitemap|crossdomain|terraform|backup|dump|webshell|shell|cmd|eval|httptrace|auditevents|sessions|conditions|flyway|liquibase|quartz|sbom|chaosmonkey|apidocs|api-spec|redoc|scalar|stoplight|telescope|_debugbar|superset|metabase|redash|airflow|mlflow|kubeflow|ruoyi|jeecg|renren|blade|eladmin|cockpit|webmin|cpanel|zabbix|_framework|blazor|serverless|vercel|netlify|amplify)");
        loadConfigFromText();
    }

    private void loadConfigFromText() {
        paths.clear();
        String[] lines = pathsArea.getText().split("\\r?\\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            paths.add(trimmed);
        }
        String patternText = hitPatternArea.getText().trim();
        if (!patternText.isEmpty()) {
            try {
                hitPattern = Pattern.compile(patternText);
            } catch (Exception ex) {
                callbacks.printError("Invalid hit pattern: " + patternText);
                hitPattern = Pattern.compile("(?i)(swagger|openapi|actuator|api docs)");
            }
        }
    }

    private void importConfig() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Config");
        int result = chooser.showOpenDialog(panel);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            StringBuilder pathsBuilder = new StringBuilder();
            StringBuilder patternBuilder = new StringBuilder();
            String line;
            boolean inPaths = true;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("#PATTERN:")) {
                    inPaths = false;
                    patternBuilder.append(line.substring(9));
                    continue;
                }
                if (inPaths) {
                    if (pathsBuilder.length() > 0) {
                        pathsBuilder.append("\n");
                    }
                    pathsBuilder.append(line);
                } else {
                    patternBuilder.append(line);
                }
            }
            pathsArea.setText(pathsBuilder.toString());
            hitPatternArea.setText(patternBuilder.toString());
            loadConfigFromText();
        } catch (Exception ex) {
            callbacks.printError(ex.getMessage());
        }
    }

    private void scheduleChecks(IHttpRequestResponse messageInfo) {
        if (messageInfo == null) {
            return;
        }
        URL baseUrl = helpers.analyzeRequest(messageInfo).getUrl();
        List<String> headers = helpers.analyzeRequest(messageInfo).getHeaders();
        List<String> basePaths = buildBasePaths(baseUrl.getPath());
        for (String basePath : basePaths) {
            scheduleTarget(baseUrl, basePath, headers);
            for (String path : paths) {
                String combined = combinePaths(basePath, path);
                scheduleTarget(baseUrl, combined, headers);
            }
        }
    }

    private void scheduleTarget(URL baseUrl, String path, List<String> headers) {
        String baseKey = baseUrl.getProtocol() + "://" + baseUrl.getHost() + ":" + baseUrl.getPort();
        String key = baseKey + path;
        if (checkedTargets.contains(key)) {
            return;
        }
        checkedTargets.add(key);
        List<String> headersCopy = new ArrayList<String>(headers);
        executor.submit(() -> checkPath(baseUrl, path, headersCopy));
    }

    private List<String> buildBasePaths(String path) {
        List<String> result = new ArrayList<String>();
        if (path == null || path.isEmpty()) {
            result.add("/");
            return result;
        }
        String normalized = path.startsWith("/") ? path : "/" + path;
        String[] parts = normalized.split("/");
        List<String> segments = new ArrayList<String>();
        for (String part : parts) {
            if (!part.isEmpty()) {
                segments.add(part);
            }
        }
        if (segments.isEmpty()) {
            result.add("/");
            return result;
        }
        Set<String> unique = new HashSet<String>();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < segments.size(); i++) {
            sb.append("/").append(segments.get(i));
            String item = sb.toString();
            unique.add(item);
            if (i < segments.size() - 1) {
                unique.add(item + "/");
            }
        }
        unique.add("/");
        result.addAll(unique);
        return result;
    }

    private String combinePaths(String basePath, String subPath) {
        if (basePath == null || basePath.isEmpty() || "/".equals(basePath)) {
            return subPath;
        }
        String left = basePath.endsWith("/") ? basePath : basePath + "/";
        String right = subPath.startsWith("/") ? subPath.substring(1) : subPath;
        return left + right;
    }

    private void checkPath(URL baseUrl, String path, List<String> originalHeaders) {
        try {
            URI baseUri = new URI(baseUrl.getProtocol(), null, baseUrl.getHost(), baseUrl.getPort(), null, null, null);
            URL target = baseUri.resolve(path).toURL();
            
            // Check 1: Unauthorized (remove auth headers)
            doCheck(baseUrl, target, originalHeaders, false);
            
            // Check 2: Authorized (keep auth headers)
            doCheck(baseUrl, target, originalHeaders, true);
            
        } catch (Exception ex) {
            callbacks.printError(ex.getMessage());
        }
    }

    private void doCheck(URL baseUrl, URL targetUrl, List<String> originalHeaders, boolean withAuth) {
        try {
            List<String> newHeaders = new ArrayList<String>();
            for (String header : originalHeaders) {
                String lower = header.toLowerCase();
                if (!withAuth && isAuthHeader(header)) {
                    continue;
                }
                // Remove content headers as we force GET
                if (lower.startsWith("content-length:") || lower.startsWith("content-type:")) {
                    continue;
                }
                newHeaders.add(header);
            }
            
            if (!newHeaders.isEmpty()) {
                String firstLine = newHeaders.get(0);
                String[] parts = firstLine.split("\\s+");
                if (parts.length >= 3) {
                    String newPath = targetUrl.getFile();
                    if (newPath.isEmpty()) {
                        newPath = "/";
                    }
                    // Force GET method for path scanning
                    newHeaders.set(0, "GET " + newPath + " " + parts[2]);
                }
            }
            
            byte[] request = helpers.buildHttpMessage(newHeaders, null);
            IHttpRequestResponse resp = callbacks.makeHttpRequest(helpers.buildHttpService(
                    baseUrl.getHost(), baseUrl.getPort(), baseUrl.getProtocol()), request);
            
            if (resp == null || resp.getResponse() == null) {
                return;
            }
            
            IResponseInfo responseInfo = helpers.analyzeResponse(resp.getResponse());
            int statusCode = responseInfo.getStatusCode();
            if (isIgnoredStatusCode(statusCode)) {
                return;
            }
            if (statusCode != 200) {
                return;
            }
            
            int bodyOffset = responseInfo.getBodyOffset();
            byte[] bodyBytes = new byte[Math.max(0, resp.getResponse().length - bodyOffset)];
            System.arraycopy(resp.getResponse(), bodyOffset, bodyBytes, 0, bodyBytes.length);
            String body = helpers.bytesToString(bodyBytes);
            if (body == null) {
                return;
            }
            
            if (hitPattern != null && !hitPattern.matcher(body).find()) {
                return;
            }
            
            String time = timeFormat.format(new Date());
            String title = withAuth ? "Authorized Access (200)" : "Unauthorized Access (200)";
            ResultItem item = new ResultItem(getName(), title, targetUrl.toString(), "status=200", time, resp);
            SwingUtilities.invokeLater(() -> model.addItem(item));
            
        } catch (Exception e) {
            callbacks.printError("Check failed: " + e.getMessage());
        }
    }

    private boolean isAuthHeader(String header) {
        String lower = header.toLowerCase();
        return lower.startsWith("cookie:") || 
               lower.startsWith("authorization:") || 
               lower.startsWith("token:") ||
               lower.startsWith("x-auth-token:") ||
               lower.startsWith("x-access-token:") ||
               lower.startsWith("access-token:");
    }

    private boolean isIgnoredStatusCode(int statusCode) {
        return statusCode == 404 || statusCode == 502 || statusCode == 503 || statusCode == 504;
    }
}
