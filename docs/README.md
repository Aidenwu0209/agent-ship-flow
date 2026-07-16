# Documentation

English | [简体中文](README.zh-CN.md)

Choose the shortest guide that matches your goal. The core CLI is
agent-neutral; the Codex adapter is optional.

| Reader goal | English | Chinese |
| --- | --- | --- |
| Ship a repository with any compatible agent | [Quick start](quickstart.md) | [快速入门](quickstart-zh.md) |
| Integrate an agent with the JSON protocol | [Integration guide](agent-integration.md) | [集成说明](agent-integration.md) |
| Install the Codex adapter | [Codex adapter quick start](ship-flow-quickstart.md) | [Codex 适配器快速入门](ship-flow-quickstart-zh.md) |
| Contribute safely | [Contributing](../CONTRIBUTING.md) | [贡献指南](../CONTRIBUTING.md) |
| Report a vulnerability | [Security policy](../SECURITY.md) | [安全策略](../SECURITY.md) |

For a first run, confirm the detected manifest, then review, add, and commit
`.ship/manifest.toml` before starting the run. The accepted manifest returns a
human `commit_manifest` action; it is not committed automatically.
