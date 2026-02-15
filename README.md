# SearchAPI Burp 插件

SearchAPI 是一款面向 Burp Suite 的扩展，提供敏感信息收集、API 扫描、未授权访问检测与 AI 安全分析，支持被动/主动扫描与右键单条数据手动扫描。支持 Java 8 / 11 / 21，可打包多版本 JAR 便于在不同环境加载。

## 功能概览

- **敏感信息收集**：基于内置正则规则扫描请求/响应头与请求/响应体，识别姓名、手机号、身份证、邮箱、密钥、JWT、数据库连接、域名、IP、IP:Port、系统特征等；支持规则自定义与导入
- **API 扫描**：从网站 JS/HTML 中主动/被动提取 API 路径，支持按域名分组展示、目标去重、手动触发重新扫描
- **未授权检测**：对常见 Swagger/Actuator/管理端点进行被动扫描，并对当前 URL 路径进行递归覆盖
- **AI 分析**：支持 OpenAI/Claude/智谱/千问/DeepSeek/硅基流动/Ollama 等自定义 API 配置，对单条数据包进行安全分析
- **结果管理**：表格右键支持复制、复制 URL、导出 CSV、发送到 Repeater/Intruder/Comparer
- **手动扫描**：在 Proxy/Repeater 选中数据右键可选择模块单独扫描

## 使用方式

### 1. 在 Burp 中加载插件

1. 使用下方构建命令生成 JAR
2. Burp -> Extender -> Extensions -> Add
3. Extension type 选择 **Java**
4. 选择生成的 `searchAPI-1.0.0-java8.jar` / `searchAPI-1.0.0-java11.jar` / `searchAPI-1.0.0-java21.jar`

加载成功后，Burp 输出中会显示开发者与版本信息。

### 2. 配置模块（Config）

默认关闭插件与扫描开关，建议先到 **Config** 选项卡进行设置：

- **Enable Plugin**：启用插件
- **Monitor Proxy / Repeater**：选择被动监听来源
- **Scan API / JS / HTML / Images / Other**：选择被动扫描的资源类型

默认状态：不启用插件、监听 Proxy、仅扫描 API。

### 3. API 扫描使用

API 扫描模块支持三种触发方式：

#### 3.1 主动请求分析
- 在 **API Scan** 标签页的工具栏中输入目标 URL（如 `https://example.com`）
- 点击「请求分析」按钮
- 插件会主动请求目标页面及同源 JS 文件，从中提取 API 路径
- 结果按域名分组展示为树形结构

#### 3.2 被动扫描
- 当 Proxy 中有目标站点的流量经过时，API Scan 会自动检测
- 对同一目标（origin）只自动扫描一次，避免重复
- 从 HTML/JS 响应中提取绝对路径（如 `/api/user`）和相对路径（如 `user/list`）

#### 3.3 手动扫描
- 在 Proxy 历史中选中目标请求
- 右键选择「Send to API Scan」
- 会重新扫描该目标，不受自动扫描去重限制

#### 3.4 结果展示
- 按域名（origin）分组展示
- 每个域名下显示提取到的 API URL 列表
- 右键支持复制 URL、发送到 Repeater/Intruder

### 4. 被动扫描逻辑

被动扫描来自 Burp Proxy/Repeater 响应。未授权模块会对当前 URL 路径进行递归覆盖，例如：

- 原始 URL：`https://www.test.com/bb/cc`
- 递归覆盖：`/bb/cc`、`/bb/`、`/`

每个递归路径会与未授权规则中的默认路径进行组合扫描。

### 5. 手动扫描

在 Proxy 或 Repeater 中选中某条数据，右键菜单选择：

- **Send to Sensitive Info**
- **Send to API Scan**
- **Send to Unauthorized Scan**
- **Send to AI Analysis**

即可将该条数据发送到对应模块进行单独扫描。

### 6. AI 分析配置

在 **AI Analysis** 模块中配置：

- Provider（OpenAI/Claude/智谱/千问/DeepSeek/硅基流动/Ollama）
- API URL
- API Key
- Model、Max Tokens、Temperature
- Prompt 模板

选择结果后点击分析即可输出 AI 风险分析。

## 构建

```bash
mvn -Pjava8 -DskipTests package
mvn -Pjava11 -DskipTests package
mvn -Pjava21 -DskipTests package
```

生成文件：

- `target/searchAPI-1.0.0-java8.jar`
- `target/searchAPI-1.0.0-java11.jar`
- `target/searchAPI-1.0.0-java21.jar`

## 前置要求与兼容性

- **JDK**：8、11 或 21（按需选择对应 JAR）
- **Burp Suite**：建议使用当前最新版本

## 许可证

本项目使用 [MIT License](LICENSE)。

## 贡献指南

请查看 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 模块说明

### Sensitive Info

- 对请求/响应头与请求/响应体统一扫描
- 内置规则可编辑、可导入

### API Scan

- 从 JS/HTML 中主动/被动提取 API 路径
- 支持绝对路径（`/api/user`）和相对路径（`user/list`）
- 按域名分组展示，支持目标去重
- 三种触发方式：主动请求、被动扫描、手动触发
- 内置常见 API 路径列表，确保有结果可展示

### Unauthorized Scan

- 内置 Swagger/Actuator/管理端点路径
- 支持规则自定义与导入
- 递归路径覆盖

### AI Analysis

- 多 Provider 支持
- 自定义 Prompt
- 对单条数据包进行安全分析
