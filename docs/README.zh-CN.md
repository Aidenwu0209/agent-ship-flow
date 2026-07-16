# 文档导航

[English](README.md) | 简体中文

请选择最符合目标的短指南。核心 CLI 与 Agent 无关；Codex 适配器是可选组件。

| 读者目标 | English | 中文 |
| --- | --- | --- |
| 使用任意兼容 Agent 交付仓库 | [Quick start](quickstart.md) | [快速入门](quickstart-zh.md) |
| 使用 JSON 协议集成 Agent | [Integration guide](agent-integration.md) | [集成说明](agent-integration.md) |
| 安装 Codex 适配器 | [Codex adapter quick start](ship-flow-quickstart.md) | [Codex 适配器快速入门](ship-flow-quickstart-zh.md) |
| 安全地参与贡献 | [Contributing](../CONTRIBUTING.md) | [贡献指南](../CONTRIBUTING.md) |
| 报告漏洞 | [Security policy](../SECURITY.md) | [安全策略](../SECURITY.md) |

第一次运行时，先确认检测到的 manifest，再审阅、暂存并提交
`.ship/manifest.toml`，然后才能启动运行。确认后的 manifest 会返回人工
`commit_manifest` 操作，不会被自动提交。
