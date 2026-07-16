# Agent Ship Flow 中文快速入门（Codex 适配器）

> Agent Ship Flow 的核心 CLI 和 JSON 协议可被任何能执行本地命令的 Agent
> 使用；本文介绍随仓库提供的 Codex 适配器。其他 Agent 请先阅读
> [通用集成说明](agent-integration.md)。

## 1. 它会帮你做什么

Ship Flow 是“Codex 控制层 + 确定性本地引擎”。Codex 负责理解需求、独立审查和解释；引擎负责 Git 隔离、状态转换、证据校验和外部操作回执。因此你不需要记住流程，只需要回答当前那一个人类问题。

## 2. 安装

需要 Python 3.11+ 和 Git。在 Agent Ship Flow 源码仓库根目录运行：

```bash
python3 scripts/install-codex-skill.py
```

请先确认 `python3 --version` 为 3.11 或更高；若系统提供多个 Python，使用符合版本要求的解释器执行同一条命令。

验收：

```bash
~/.codex/tools/ship-flow/bin/ship --help
```

如果安装中断，不要手动删除事务日志。修复磁盘空间或权限后重新运行同一条安装命令，安装器会校验并恢复已知事务。

## 3. 第一次 ship

在目标 Git 仓库的 Codex 任务里说：

```text
使用 $ship-flow 帮我完成“登录失败后显示可操作的错误提示”，完成开发、独立 Review 和 Verification，停在正式上线确认前。
```

Codex 先检测 `.ship/manifest.toml`。首次使用时它会请你确认：

- 基础分支和远程名称；
- 需要执行的 lint / unit / integration / e2e / build 命令；
- 是否需要发布，以及精确的目标；
- deploy 后如何断言“运行的就是本次候选版本”；
- 回滚命令和是否可能影响数据。

请不要因为“以前这条命令成功过”就确认未检查的 deploy 配置。

## 4. 继续中断的运行

告诉 Codex 仓库路径和 `run-id`：

```text
使用 $ship-flow 继续 run-login-001，仓库是 /absolute/repo。
```

控制层每一轮的第一条流程命令都必须是：

```bash
~/.codex/tools/ship-flow/bin/ship status --repo /absolute/repo --run-id run-login-001 --json
```

这会校验工作树、commit/tree、manifest、Review、Verification 和外部回执，而不是相信聊天里上次的描述。

## 5. Codex 会问哪些问题

它每次只问当前第一个缺失决定：

1. 检测到的项目命令是否正确；
2. 需求验收标准或实施计划是否确认；
3. 上线时的精确目标、当前证据与失效时间是否确认；
4. 外部写入中断后，证据能否断言“已应用”或“未应用”；
5. 可能影响数据的回滚是否批准；
6. 最终证据是否满足预期，是否清理工具所有的 worktree。

Review 或 Verification 失败时，Codex 自动回到 Developer；不会问你“是否忽略失败”。

## 6. `UNKNOWN` 不是失败，也不是成功

如果 deploy 在发出后掉线，引擎无法仅凭进程退出码确定外部系统是否收到。它会保留 `UNKNOWN` 回执并：

- 有可靠 probe 时用 probe 只读确认；
- 没有可靠 probe 时要求人工提供“已应用 / 未应用”的明确裁定和回执摘要。

在完成这一步前，请不要手动重跑 deploy。

## 7. 卸载

```bash
python3 scripts/install-codex-skill.py --uninstall
```

卸载器只删除中央安装状态能证明为 Ship Flow 所有、且内容摘要仍匹配的两个目录。如果你手动改过安装目录，它会拒绝删除并请你先备份或确认。

## 8. 重要边界

Skill 不会自动获得凭据，也不会绕过 Codex 的权限确认。“请直接完成”不等于“允许推送、合并或生产上线”。每个外部目标的批准都绑定当前证据并有失效时间。
