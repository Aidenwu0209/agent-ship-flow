# Agent Ship Flow 中文快速入门

[English](quickstart.md)

这份指南适用于任何能执行本地 argv 命令、保存仓库绝对路径与 `run-id`、解析
JSON，并展示一次范围变更决策的 Agent。新运行默认使用范围授权的 `autonomous`
模式。

## 1. 安装 CLI

Agent Ship Flow 需要 Python 3.11+、Git 和一个已存在的 Git 仓库：

```bash
git clone https://github.com/Aidenwu0209/agent-ship-flow.git
cd agent-ship-flow
python3 -m pip install -e .
ship --help
```

开发本项目时改用 `python3 -m pip install -e ".[dev]"`。

## 2. 初始化默认自主策略

```bash
ship init --repo /absolute/path/to/target-repo --json
```

自主初始化会写入检测到的 manifest，并返回自动 `commit_manifest`。控制层不询问就执行它。
如果你直接使用 CLI，请检查并跨越同一个 Git 提交边界：

```bash
git add .ship/manifest.toml
git commit -m "chore: configure ship flow"
```

manifest 仍定义基础分支、验证命令、发布目标、健康检查和回滚操作。启动运行前必须提交它；
autonomous 只是去掉第二次对话，不是去掉该边界。

## 3. 启动并检查授权合约

```bash
ship start \
  --repo /absolute/path/to/target-repo \
  --run-id run-login-error-001 \
  --goal "登录失败时显示可操作的错误提示" \
  --release-target production \
  --previous-release v1 \
  --json
```

不可变合约 generation 绑定：

- 执行模式；
- 标准化仓库与引擎所有 worktree；
- 精确用户目标与分支；
- manifest SHA-256，包含验证、发布、健康检查和回滚材料；
- 发布目标与上一发布版本；
- 合约 generation、创建时间与绑定的状态 revision。

响应会公开 `authorization.mode`、`source`、`generation` 和 `digest`。请原样保留返回的
`run-id` 与不透明值。

## 4. 每一轮都以状态驱动

```bash
ship status \
  --repo /absolute/path/to/target-repo \
  --run-id run-login-error-001 \
  --json
```

使用 `state`、`evidence_status`、`authorization`、可选 `scope_change` 和完整
`next_action`：

- 使用当前 revision 与 ID 执行每个 `automatic` 操作，然后再读状态；
- autonomous 模式下只就 `approve_scope_change` 询问；
- 进度是陈述，不是请求许可；
- 手动 `UNKNOWN` 结果是安全阻塞，不得重放外部写入。

独立 Plan Review、Code Review、Verification、发布健康证据、回滚验证和旧证据拒绝
在两种模式中都仍然强制。

## 5. 执行扩展前先记录

假设当前目标仅包含账户导出，用户又要求部署仪表盘。先保留两个边界并申请扩展：

```bash
ship request-scope-change \
  --repo /absolute/path/to/target-repo \
  --run-id run-login-error-001 \
  --expected-revision 12 \
  --reason feature_expansion \
  --summary "add deployment dashboard" \
  --goal "ship account export and a deployment dashboard" \
  --manifest-sha256 <sha256> \
  --release-target production \
  --json
```

返回 `approve_scope_change` 时，展示原始边界、精确提案和批准后果。批准命令为：

```bash
ship resolve-scope-change --repo /absolute/path/to/target-repo --run-id run-login-error-001 --expected-revision 13 --decision approve --actor human-owner --json
```

批准会创建下一个合约 generation 并返回计划阶段；拒绝保留当前 generation。

## 6. 需要时选择严格模式

strict 模式保留检测 manifest 确认，以及计划、发布、回滚和清理批准：

```bash
ship start --repo /absolute/path/to/target-repo --run-id run-audit-001 --goal "交付需审计的变更" --mode strict --json
```

授权合约出现之前创建的运行也会报告 `authorization.source=legacy_default`，并遵循同样的
strict 行为。

## 7. 清理仍受边界约束

自主清理只能在路径、所有权、合并/已批准条件和证据检查全部通过后，删除引擎所有的
干净 worktree。两种模式都会拒绝脏、外来或不安全资源。

Codex 用户请继续阅读 [Codex 适配器快速入门](ship-flow-quickstart-zh.md)。适配器作者请阅读
[JSON 协议指南](agent-integration.md)。
