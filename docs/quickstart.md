# Agent Ship Flow quick start

English | [简体中文](quickstart-zh.md)

This guide works with any agent that can execute local argv commands, retain an
absolute repository path and `run-id`, parse JSON, and show human decisions.

## 1. Install the CLI

Agent Ship Flow requires Python 3.11+, Git, and an existing Git repository to
ship. Install the CLI from a checkout of this repository:

```bash
git clone https://github.com/Aidenwu0209/agent-ship-flow.git
cd agent-ship-flow
python3 -m pip install -e .
ship --help
```

Use `python3 -m pip install -e ".[dev]"` instead when developing this project.

## 2. Detect the repository policy

Ask the agent to inspect the target repository. It must show the detected base
branch, commands, release target, health check, and rollback policy before a
human confirms them.

```bash
ship init --repo /absolute/path/to/target-repo --json
```

## 3. Confirm the detected policy

Only after that human confirmation, accept the detected policy:

```bash
ship init --repo /absolute/path/to/target-repo --accept-detected --json
```

The accepted result returns the human `commit_manifest` action. Review
`.ship/manifest.toml` as project policy; do not let the agent commit it for you.

## 4. Review and version the manifest

Add and commit the reviewed manifest in the target repository:

```bash
git add .ship/manifest.toml
git commit -m "chore: configure ship flow"
```

`ship start` requires a clean base when the confirmed policy enables that
protection. Finish or deliberately resolve any other working-tree changes
before starting the run.

## 5. Start the run

Create a run only after the manifest commit:

```bash
ship start \
  --repo /absolute/path/to/target-repo \
  --run-id run-login-error-001 \
  --goal "Show an actionable error when login fails" \
  --json
```

The engine creates an isolated worktree and returns the next action. Keep the
returned `run-id`; do not replace it with a new value.

## 6. Resume every later turn from status

Begin every later agent turn with the durable state, even after a restart or
lost context:

```bash
ship status \
  --repo /absolute/path/to/target-repo \
  --run-id run-login-error-001 \
  --json
```

Follow the returned `state`, `evidence_status`, and complete `next_action`.
When the action is human or manual, ask only that first question and stop.

For Codex, install the optional adapter with the [Codex adapter quick
start](ship-flow-quickstart.md). Adapter authors should use the [JSON protocol
guide](agent-integration.md).
