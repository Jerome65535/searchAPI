# 贡献指南

感谢你对 SearchAPI 的贡献兴趣。为了保持代码质量和一致性，请遵循以下流程。

## 环境要求

- JDK 8/11/21（至少一个版本）
- Maven 3.6+
- Burp Suite

## 开发流程

1. Fork 并创建分支：`feature/xxx` 或 `fix/xxx`
2. 保持变更聚焦，避免无关修改
3. 确保代码风格一致、无新增警告
4. 构建验证通过：

```bash
mvn -Pjava8 -DskipTests package
mvn -Pjava11 -DskipTests package
mvn -Pjava21 -DskipTests package
```

## 提交规范

- 提交信息建议：`type: summary`
- 类型示例：`feat` / `fix` / `refactor` / `docs` / `chore`

## 功能验收建议

- 在 Burp 中加载构建产物
- 确认 Config 开关生效
- Proxy/Repeater 右键发送到模块可用
- 各模块有结果输出且可导出
