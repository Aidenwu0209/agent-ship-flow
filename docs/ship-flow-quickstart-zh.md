# Agent Ship Flow 中文快速入门（Codex 适配器）

[English](ship-flow-quickstart.md)

> 核心 CLI 和 JSON 协议可被任何能执行本地命令的 Agent 使用。其他控制层请阅读
> [Agent 集成指南](agent-integration.md)。

## 1. 安装 Codex 适配器

在本仓库根目录中，确保 Python 3.11+ 和 Git 可用：

```bash
python3 scripts/install-codex-skill.py
~/.codex/tools/ship-flow/bin/ship --help
```

如果安装中断，修复磁盘空间或权限后重新运行同一安装器。不要删除事务日志；恢复过程会验证
已知的分阶段与已安装目录。

## 2. 从自主模式开始

新运行默认为 `autonomous`。一次性告诉 Codex 完整初始边界，包括你愿意授权的发布目标和回滚版本：

```text
使用 $ship-flow 实现“登录失败时显示可操作的错误提示”，独立 Review 和 Verification 通过后将这一精确候选版本发布到 production，验证健康状态，并安全清理引擎所有 worktree。上一发布版本是 v1。
```

初始目标和授权合约是权限边界。Codex 不询问就执行每个返回的自动操作，包括计划/发布/
回滚的合约授权，以及符合条件的清理。进度更新是陈述，不是请求许可。

自主 `init` 返回自动 `commit_manifest`。Codex 必须在 `start` 前提交这份精确的生成策略，
但不会再询问一次。合约绑定模式、仓库/worktree、目标、分支、manifest 摘要、发布目标、
上一版本、generation、创建时间和状态 revision。状态公开 `authorization.mode`、`source`、
`generation` 和 `digest`；关卡回执使用 `scope-contract:<contract-digest>`。

## 3. 从持久状态恢复

对于已有运行，告诉 Codex 仓库路径和 `run-id`。每一轮都从以下命令开始：

```bash
~/.codex/tools/ship-flow/bin/ship status --repo /absolute/repo --run-id run-login-001 --json
```

Codex 遵循完整 `next_action`，然后再读状态。独立 Plan Critic、Reviewer 和 Verifier 上下文仍然强制。
代码、manifest 材料、目标或合约 generation 变化后，旧证据不可继续使用。

## 4. 只批准已记录的范围扩展

如果当前合约仅包含账户导出，你又要求部署仪表盘，Codex 先报告已完成的范围内进度，并记录原始与
拟议边界：

```bash
~/.codex/tools/ship-flow/bin/ship request-scope-change --repo /absolute/repo --run-id run-login-001 --expected-revision 12 --reason feature_expansion --summary "add deployment dashboard" --goal "ship account export and a deployment dashboard" --manifest-sha256 <sha256> --release-target production --json
```

只有返回的 `approve_scope_change` 才会变成常规人工问题。你批准精确提案后，Codex 执行：

```bash
~/.codex/tools/ship-flow/bin/ship resolve-scope-change --repo /absolute/repo --run-id run-login-001 --expected-revision 13 --decision approve --actor human-owner --json
```

新合约 generation 会返回计划阶段，不复用原任务的旧证据。Codex 不得用“仪表盘要哪些功能”这类临时问题
代替范围变更记录。

## 5. 需要显式审计关卡时使用 strict

当计划、发布、回滚和清理都必须停下等待人工批准时，明确要求 strict 模式：

```text
使用 $ship-flow 的 --mode strict 交付“更新需审计的计费规则”。
```

strict 初始化还保留检测 manifest 确认。没有合约的旧运行会自动使用 strict 兼容行为，并报告
`authorization.source=legacy_default`。

## 6. 安全处理 `UNKNOWN` 和清理

手动 `UNKNOWN` 外部结果是安全阻塞，不是许可问题。Codex 保留回执并陈述缺失事实；使用可靠的只读
probe 或引擎裁定路径，不得重放外部写入。

自动清理只能在路径、所有权、合并/已批准条件与证据检查通过后，删除引擎所有的干净 worktree。
脏、外来或不安全资源会被拒绝。适配器不会自动获得凭据，也不会绕过 Codex 平台自身的权限确认。

## 7. 卸载

```bash
python3 scripts/install-codex-skill.py --uninstall
```

卸载器只删除记录内容仍匹配的 Ship Flow 所有目录；会拒绝已修改或被替换的安装路径。
