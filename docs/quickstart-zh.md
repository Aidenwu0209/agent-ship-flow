# Agent Ship Flow 中文快速入门

[English](quickstart.md)

这是一份面向所有 Agent 的 CLI 入门，不依赖 Codex、Claude、Cursor 或任何
模型 API。只要你的 Agent 能执行本地 argv 命令、保存仓库绝对路径与 `run-id`、
解析 JSON，并把需要人确认的问题展示给用户，就能使用它。

## 1. 安装核心引擎

需要 Python 3.11+、Git，以及一个已经存在的目标 Git 仓库。

```bash
git clone https://github.com/Aidenwu0209/agent-ship-flow.git
cd agent-ship-flow
python3 -m pip install -e .
ship --help
```

如果你正在开发此项目，安装开发依赖：

```bash
python3 -m pip install -e ".[dev]"
```

## 2. 让 Agent 初始化一次交付任务

Agent 先检测目标仓库的流程配置：

```bash
ship init --repo /absolute/path/to/target-repo --json
```

它会返回检测到的基础分支、测试命令、发布目标、健康检查和回滚策略。Agent
必须向用户展示这些内容；在用户明确确认前，不能继续。

确认后，Agent 使用同一仓库路径接受检测结果：

```bash
ship init --repo /absolute/path/to/target-repo --accept-detected --json
```

接受后，返回的 `commit_manifest` 人工操作表示 Agent 必须停下，让用户审阅
`.ship/manifest.toml`。这份 manifest 是经过审阅的项目策略；请在启动运行前暂存并
提交它：

```bash
git add .ship/manifest.toml
git commit -m "chore: configure ship flow"
```

当确认的策略启用干净基础工作树保护时，`ship start` 要求基础工作树干净。请先完成
或明确处理其他工作树改动，再继续。

随后创建一次有明确目标的运行：

```bash
ship start \
  --repo /absolute/path/to/target-repo \
  --run-id run-login-error-001 \
  --goal "登录失败时显示可操作的错误提示" \
  --json
```

## 3. 每一轮都从状态恢复

无论 Agent 是否换模型、重启或丢失上下文，都先读取持久状态：

```bash
ship status \
  --repo /absolute/path/to/target-repo \
  --run-id run-login-error-001 \
  --json
```

只以返回 JSON 中的 `state`、`evidence_status` 和完整 `next_action` 为准：

- `next_action` 是自动操作时，使用返回的 ID 与当前 revision 执行该操作，再读一次状态；
- `next_action` 是 human 或 manual 时，只向用户询问第一个缺失决定，然后停止；
- 不手写 `.ship` 中的状态、证据、批准、回执或 worktree 所有权记录；
- 不以聊天记录、分支名或 `git status` 代替引擎状态。

## 4. 不会被自动越过的关卡

计划、独立 Plan Review、开发、独立 Code Review、确定性 Verification、上线
批准、健康检查、回滚与清理都是状态机的一部分。代码或配置发生变化会使旧的
Review/Verification 证据失效；外部操作结果为 `UNKNOWN` 时，系统只会 probe
或要求人工裁定，不会盲目重试。

对于 Codex，仓库还提供可选 Skill 适配器；安装与使用方法见
[Codex adapter quick start](ship-flow-quickstart-zh.md)。
