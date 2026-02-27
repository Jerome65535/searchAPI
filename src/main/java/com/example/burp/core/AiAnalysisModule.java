package com.example.burp.core;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.example.burp.ui.ResultTableModel;
import com.example.burp.ui.ResultTablePanel;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.TitledBorder;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AiAnalysisModule implements Module {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final ResultTableModel model;
    private final ResultTablePanel resultPanel;
    private final JPanel panel;
    private final JTextArea templateArea;
    private final JTextArea resultArea;
    private String promptTemplate;
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private JComboBox<String> providerCombo;
    private JTextField apiUrlField;
    private JTextField apiKeyField;
    private JTextField modelField;
    private JTextField maxTokensField;
    private JTextField temperatureField;

    private static final String[] PROVIDERS = {
            "OpenAI",
            "Claude (Anthropic)",
            "智谱AI (GLM)",
            "通义千问 (Qwen)",
            "DeepSeek",
            "硅基流动 (SiliconFlow)",
            "Ollama (Local)"
    };

    private static final Map<String, String> DEFAULT_URLS = new HashMap<String, String>();
    private static final Map<String, String> DEFAULT_MODELS = new HashMap<String, String>();

    static {
        DEFAULT_URLS.put("OpenAI", "https://api.openai.com/v1/chat/completions");
        DEFAULT_URLS.put("Claude (Anthropic)", "https://api.anthropic.com/v1/messages");
        DEFAULT_URLS.put("智谱AI (GLM)", "https://open.bigmodel.cn/api/paas/v4/chat/completions");
        DEFAULT_URLS.put("通义千问 (Qwen)", "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation");
        DEFAULT_URLS.put("DeepSeek", "https://api.deepseek.com/v1/chat/completions");
        DEFAULT_URLS.put("硅基流动 (SiliconFlow)", "https://api.siliconflow.cn/v1/chat/completions");
        DEFAULT_URLS.put("Ollama (Local)", "http://localhost:11434/api/chat");

        DEFAULT_MODELS.put("OpenAI", "gpt-4o");
        DEFAULT_MODELS.put("Claude (Anthropic)", "claude-3-5-sonnet-20241022");
        DEFAULT_MODELS.put("智谱AI (GLM)", "glm-4");
        DEFAULT_MODELS.put("通义千问 (Qwen)", "qwen-turbo");
        DEFAULT_MODELS.put("DeepSeek", "deepseek-chat");
        DEFAULT_MODELS.put("硅基流动 (SiliconFlow)", "Qwen/Qwen2.5-7B-Instruct");
        DEFAULT_MODELS.put("Ollama (Local)", "llama3");
    }

    public AiAnalysisModule(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.model = new ResultTableModel();
        this.resultPanel = new ResultTablePanel(callbacks, model);
        this.templateArea = new JTextArea(8, 80);
        this.resultArea = new JTextArea(10, 80);
        this.resultArea.setEditable(false);
        this.panel = new JPanel(new BorderLayout());
        initDefaultTemplate();
        initUi();
    }

    @Override
    public String getName() {
        return "AI Analysis";
    }

    @Override
    public JPanel getPanel() {
        return panel;
    }

    @Override
    public void processResponse(int toolFlag, IHttpRequestResponse messageInfo) {
    }

    @Override
    public void processManual(IHttpRequestResponse messageInfo) {
        String prompt = buildPrompt(messageInfo);
        if (prompt == null || prompt.isEmpty()) {
            return;
        }
        String url = helpers.analyzeRequest(messageInfo).getUrl().toString();
        String time = timeFormat.format(new Date());
        ResultItem item = new ResultItem(getName(), "Prompt", url, prompt, time, messageInfo);
        SwingUtilities.invokeLater(() -> model.addItem(item));
    }

    private void initUi() {
        JPanel configPanel = createConfigPanel();
        JPanel templatePanel = createTemplatePanel();
        JPanel analysisPanel = createAnalysisPanel();

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(configPanel, BorderLayout.NORTH);
        topPanel.add(templatePanel, BorderLayout.CENTER);
        topPanel.add(analysisPanel, BorderLayout.SOUTH);

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(resultPanel, BorderLayout.CENTER);
    }

    private JPanel createConfigPanel() {
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(new TitledBorder("AI Provider Configuration"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 3, 3, 3);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0;
        configPanel.add(new JLabel("Provider:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1;
        providerCombo = new JComboBox<String>(PROVIDERS);
        providerCombo.addActionListener(e -> updateProviderDefaults());
        configPanel.add(providerCombo, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0;
        configPanel.add(new JLabel("API URL:"), gbc);

        gbc.gridx = 3;
        gbc.weightx = 2;
        apiUrlField = new JTextField(40);
        configPanel.add(apiUrlField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0;
        configPanel.add(new JLabel("API Key:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1;
        apiKeyField = new JPasswordField(30);
        configPanel.add(apiKeyField, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0;
        configPanel.add(new JLabel("Model:"), gbc);

        gbc.gridx = 3;
        gbc.weightx = 2;
        modelField = new JTextField(30);
        configPanel.add(modelField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0;
        configPanel.add(new JLabel("Max Tokens:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1;
        maxTokensField = new JTextField("4096", 10);
        configPanel.add(maxTokensField, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0;
        configPanel.add(new JLabel("Temperature:"), gbc);

        gbc.gridx = 3;
        gbc.weightx = 2;
        temperatureField = new JTextField("0.7", 10);
        configPanel.add(temperatureField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 4;
        gbc.weightx = 1;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton testBtn = new JButton("Test Connection");
        testBtn.addActionListener(e -> testConnection());
        JButton saveBtn = new JButton("Save Config");
        saveBtn.addActionListener(e -> saveConfig());
        JButton loadBtn = new JButton("Load Config");
        loadBtn.addActionListener(e -> loadConfig());
        buttonPanel.add(testBtn);
        buttonPanel.add(saveBtn);
        buttonPanel.add(loadBtn);
        configPanel.add(buttonPanel, gbc);

        updateProviderDefaults();
        return configPanel;
    }

    private JPanel createTemplatePanel() {
        JPanel templatePanel = new JPanel(new BorderLayout());
        templatePanel.setBorder(new TitledBorder("Prompt Template"));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton applyBtn = new JButton("Apply Template");
        applyBtn.addActionListener(e -> promptTemplate = templateArea.getText());
        JButton resetBtn = new JButton("Reset Default");
        resetBtn.addActionListener(e -> {
            initDefaultTemplate();
            templateArea.setText(promptTemplate);
        });
        actions.add(applyBtn);
        actions.add(resetBtn);
        templatePanel.add(actions, BorderLayout.NORTH);
        templatePanel.add(new JScrollPane(templateArea), BorderLayout.CENTER);
        return templatePanel;
    }

    private JPanel createAnalysisPanel() {
        JPanel analysisPanel = new JPanel(new BorderLayout());
        analysisPanel.setBorder(new TitledBorder("AI Analysis Result"));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton analyzeBtn = new JButton("Analyze Selected");
        analyzeBtn.addActionListener(e -> analyzeSelected());
        JButton clearBtn = new JButton("Clear Result");
        clearBtn.addActionListener(e -> resultArea.setText(""));
        actions.add(analyzeBtn);
        actions.add(clearBtn);
        analysisPanel.add(actions, BorderLayout.NORTH);
        analysisPanel.add(new JScrollPane(resultArea), BorderLayout.CENTER);
        return analysisPanel;
    }

    private void updateProviderDefaults() {
        String provider = (String) providerCombo.getSelectedItem();
        if (provider != null) {
            apiUrlField.setText(DEFAULT_URLS.get(provider));
            modelField.setText(DEFAULT_MODELS.get(provider));
        }
    }

    private void testConnection() {
        executor.submit(() -> {
            try {
                String testPrompt = "Hello, this is a test message. Please respond with 'Connection successful.'";
                String response = callAiApi(testPrompt);
                SwingUtilities.invokeLater(() -> {
                    if (response != null && !response.isEmpty()) {
                        JOptionPane.showMessageDialog(panel, "Connection successful!\nResponse: " + response.substring(0, Math.min(200, response.length())), "Test Result", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(panel, "Connection failed: Empty response", "Test Result", JOptionPane.ERROR_MESSAGE);
                    }
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(panel, "Connection failed: " + e.getMessage(), "Test Result", JOptionPane.ERROR_MESSAGE));
            }
        });
    }

    private void saveConfig() {
        callbacks.saveExtensionSetting("ai_provider", (String) providerCombo.getSelectedItem());
        callbacks.saveExtensionSetting("ai_api_url", apiUrlField.getText());
        callbacks.saveExtensionSetting("ai_api_key", apiKeyField.getText());
        callbacks.saveExtensionSetting("ai_model", modelField.getText());
        callbacks.saveExtensionSetting("ai_max_tokens", maxTokensField.getText());
        callbacks.saveExtensionSetting("ai_temperature", temperatureField.getText());
        callbacks.saveExtensionSetting("ai_prompt_template", templateArea.getText());
        JOptionPane.showMessageDialog(panel, "Configuration saved!", "Save", JOptionPane.INFORMATION_MESSAGE);
    }

    private void loadConfig() {
        String savedUrl = callbacks.loadExtensionSetting("ai_api_url");
        if (savedUrl == null) {
            JOptionPane.showMessageDialog(panel, "No saved configuration found.", "Load", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String savedProvider = callbacks.loadExtensionSetting("ai_provider");
        if (savedProvider != null) {
            providerCombo.setSelectedItem(savedProvider);
        }
        apiUrlField.setText(savedUrl);
        setFieldIfNotNull(apiKeyField, callbacks.loadExtensionSetting("ai_api_key"));
        setFieldIfNotNull(modelField, callbacks.loadExtensionSetting("ai_model"));
        setFieldIfNotNull(maxTokensField, callbacks.loadExtensionSetting("ai_max_tokens"));
        setFieldIfNotNull(temperatureField, callbacks.loadExtensionSetting("ai_temperature"));
        String template = callbacks.loadExtensionSetting("ai_prompt_template");
        if (template != null) {
            templateArea.setText(template);
            promptTemplate = template;
        }
        JOptionPane.showMessageDialog(panel, "Configuration loaded!", "Load", JOptionPane.INFORMATION_MESSAGE);
    }

    private void setFieldIfNotNull(JTextField field, String value) {
        if (value != null) {
            field.setText(value);
        }
    }

    private void analyzeSelected() {
        int[] selectedRows = resultPanel.getTable().getSelectedRows();
        if (selectedRows.length == 0) {
            JOptionPane.showMessageDialog(panel, "Please select at least one result to analyze.", "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int modelRow = resultPanel.getTable().convertRowIndexToModel(selectedRows[0]);
        ResultItem item = model.getItem(modelRow);
        if (item == null) {
            return;
        }
        String prompt = item.getDetail();
        resultArea.setText("Analyzing... Please wait...");
        executor.submit(() -> {
            try {
                String response = callAiApi(prompt);
                SwingUtilities.invokeLater(() -> {
                    if (response != null) {
                        resultArea.setText(response);
                    } else {
                        resultArea.setText("Analysis failed: Empty response from AI");
                    }
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> resultArea.setText("Analysis failed: " + e.getMessage()));
            }
        });
    }

    private String callAiApi(String prompt) throws Exception {
        String provider = (String) providerCombo.getSelectedItem();
        String apiUrl = apiUrlField.getText().trim();
        String apiKey = apiKeyField.getText().trim();
        String model = modelField.getText().trim();
        int maxTokens = parseIntOrDefault(maxTokensField.getText().trim(), 4096);
        double temperature = parseDoubleOrDefault(temperatureField.getText().trim(), 0.7);

        if (apiUrl.isEmpty()) {
            throw new Exception("API URL is required");
        }

        URL url = new URL(apiUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(60000);

        String requestBody = buildRequestBody(provider, model, prompt, maxTokens, temperature, apiKey, conn);

        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = requestBody.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            String errorResponse = readStream(conn.getErrorStream());
            throw new Exception("API returned " + responseCode + ": " + errorResponse);
        }

        String response = readStream(conn.getInputStream());
        conn.disconnect();

        return parseResponse(response, provider);
    }

    private int parseIntOrDefault(String value, int defaultValue) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private double parseDoubleOrDefault(String value, double defaultValue) {
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private String buildRequestBody(String provider, String model, String prompt, int maxTokens, double temperature, String apiKey, HttpURLConnection conn) {
        if ("Claude (Anthropic)".equals(provider)) {
            conn.setRequestProperty("x-api-key", apiKey);
            conn.setRequestProperty("anthropic-version", "2023-06-01");
            return buildClaudeRequest(model, prompt, maxTokens);
        } else if ("Ollama (Local)".equals(provider)) {
            return buildOllamaRequest(model, prompt);
        } else if ("通义千问 (Qwen)".equals(provider)) {
            conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            return buildQwenRequest(model, prompt, maxTokens, temperature);
        } else {
            conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            return buildOpenAICompatibleRequest(model, prompt, maxTokens, temperature);
        }
    }

    private String readStream(java.io.InputStream stream) throws Exception {
        if (stream == null) {
            return "";
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        reader.close();
        return sb.toString();
    }

    private String buildOpenAICompatibleRequest(String model, String prompt, int maxTokens, double temperature) {
        String escapedPrompt = escapeJson(prompt);
        return "{\"model\":\"" + model + "\",\"messages\":[{\"role\":\"user\",\"content\":\"" + escapedPrompt + "\"}],\"max_tokens\":" + maxTokens + ",\"temperature\":" + temperature + "}";
    }

    private String buildClaudeRequest(String model, String prompt, int maxTokens) {
        String escapedPrompt = escapeJson(prompt);
        return "{\"model\":\"" + model + "\",\"max_tokens\":" + maxTokens + ",\"messages\":[{\"role\":\"user\",\"content\":\"" + escapedPrompt + "\"}]}";
    }

    private String buildOllamaRequest(String model, String prompt) {
        String escapedPrompt = escapeJson(prompt);
        return "{\"model\":\"" + model + "\",\"messages\":[{\"role\":\"user\",\"content\":\"" + escapedPrompt + "\"}],\"stream\":false}";
    }

    private String buildQwenRequest(String model, String prompt, int maxTokens, double temperature) {
        String escapedPrompt = escapeJson(prompt);
        return "{\"model\":\"" + model + "\",\"input\":{\"messages\":[{\"role\":\"user\",\"content\":\"" + escapedPrompt + "\"}]},\"parameters\":{\"max_tokens\":" + maxTokens + ",\"temperature\":" + temperature + "}}";
    }

    private String escapeJson(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String parseResponse(String jsonResponse, String provider) {
        try {
            String searchKey;
            if ("Claude (Anthropic)".equals(provider)) {
                searchKey = "\"text\":\"";
            } else {
                searchKey = "\"content\":\"";
            }
            int contentStart = jsonResponse.indexOf(searchKey);
            if (contentStart == -1) {
                return jsonResponse;
            }
            contentStart += searchKey.length();
            int contentEnd = jsonResponse.indexOf("\"", contentStart);
            if (!"Claude (Anthropic)".equals(provider) && !"通义千问 (Qwen)".equals(provider)) {
                while (contentEnd != -1 && jsonResponse.charAt(contentEnd - 1) == '\\') {
                    contentEnd = jsonResponse.indexOf("\"", contentEnd + 1);
                }
            }
            if (contentEnd != -1) {
                return unescapeJson(jsonResponse.substring(contentStart, contentEnd));
            }
            return jsonResponse;
        } catch (Exception e) {
            return jsonResponse;
        }
    }

    private String unescapeJson(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
    }

    private void initDefaultTemplate() {
        promptTemplate = "You are a security analysis assistant. Please analyze the following HTTP request and response for potential security vulnerabilities, and provide risk assessment and verification suggestions:\n" +
                "\n" +
                "URL: {{url}}\n" +
                "Method: {{method}}\n" +
                "Request Headers:\n{{req_headers}}\n" +
                "Request Body:\n{{req_body}}\n" +
                "Response Status: {{status}}\n" +
                "Response Headers:\n{{resp_headers}}\n" +
                "Response Body:\n{{resp_body}}\n" +
                "\n" +
                "Please analyze:\n" +
                "1. Potential security vulnerabilities (SQL injection, XSS, SSRF, IDOR, etc.)\n" +
                "2. Sensitive information disclosure\n" +
                "3. Authentication and authorization issues\n" +
                "4. Security header configuration\n" +
                "5. Specific verification steps and PoC suggestions";
        templateArea.setText(promptTemplate);
    }

    private String buildPrompt(IHttpRequestResponse messageInfo) {
        if (messageInfo == null) {
            return null;
        }
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        IResponseInfo responseInfo = messageInfo.getResponse() == null ? null : helpers.analyzeResponse(messageInfo.getResponse());
        String url = requestInfo.getUrl().toString();
        String method = requestInfo.getMethod();
        String reqHeaders = String.join("\n", requestInfo.getHeaders());
        String reqBody = "";
        byte[] req = messageInfo.getRequest();
        int reqBodyOffset = requestInfo.getBodyOffset();
        if (req != null && reqBodyOffset >= 0 && reqBodyOffset < req.length) {
            byte[] bodyBytes = new byte[req.length - reqBodyOffset];
            System.arraycopy(req, reqBodyOffset, bodyBytes, 0, bodyBytes.length);
            reqBody = helpers.bytesToString(bodyBytes);
        }
        String status = responseInfo != null ? String.valueOf(responseInfo.getStatusCode()) : "no response";
        String respHeaders = responseInfo != null ? String.join("\n", responseInfo.getHeaders()) : "";
        String respBody = "";
        if (messageInfo.getResponse() != null && responseInfo != null) {
            int bodyOffset = responseInfo.getBodyOffset();
            byte[] resp = messageInfo.getResponse();
            if (bodyOffset >= 0 && bodyOffset < resp.length) {
                byte[] bodyBytes = new byte[resp.length - bodyOffset];
                System.arraycopy(resp, bodyOffset, bodyBytes, 0, bodyBytes.length);
                respBody = helpers.bytesToString(bodyBytes);
            }
        }
        String prompt = promptTemplate;
        prompt = prompt.replace("{{url}}", url);
        prompt = prompt.replace("{{method}}", method);
        prompt = prompt.replace("{{req_headers}}", reqHeaders);
        prompt = prompt.replace("{{req_body}}", reqBody);
        prompt = prompt.replace("{{status}}", status);
        prompt = prompt.replace("{{resp_headers}}", respHeaders);
        prompt = prompt.replace("{{resp_body}}", respBody);
        return prompt;
    }
}
