# Agent Ship Flow quick start for Codex

English | [简体中文](ship-flow-quickstart-zh.md)

> The core CLI and JSON protocol work with any local-command agent. If you do
> not use Codex, follow the [agent integration guide](agent-integration.md).

## 1. Install the Codex adapter

From the Agent Ship Flow source repository, with Python 3.11+ and Git
available, run:

```bash
python3 scripts/install-codex-skill.py
```

Confirm the installation:

```bash
~/.codex/tools/ship-flow/bin/ship --help
```

If installation is interrupted, do not delete its transaction log by hand.
Correct the disk-space or permission issue and run the same installer again so
it can validate and recover the known transaction.

## 2. Start the first task

In a Codex task for the target Git repository, ask:

```text
Use $ship-flow to implement “Show an actionable error when login fails”, complete development, independent Review, and Verification, then stop before formal release approval.
```

The adapter detects `.ship/manifest.toml` and asks one question at a time about
the base branch, commands, release target, health check, and rollback policy.
After you confirm the detected policy, it accepts the manifest and returns the
human `commit_manifest` action. Review, add, and commit that first manifest
before `ship start`; the adapter must not commit it automatically.

## 3. Answer one human gate at a time

The controller presents only the first missing decision. It never treats “go
ahead” as permission to fabricate a release approval, and it does not bypass a
failed Review or Verification. Release approval remains bound to the current
target and evidence; cleanup is also a human gate.

For an existing run, provide its repository path and `run-id`. Every later turn
starts from durable state:

```bash
~/.codex/tools/ship-flow/bin/ship status --repo /absolute/repo --run-id run-login-001 --json
```

## 4. Handle `UNKNOWN` outcomes safely

An interrupted external operation can be `UNKNOWN`: neither success nor
failure. Preserve its receipt. Use a reliable read-only probe when available,
or make the engine's requested human adjudication; never rerun the external
write blindly.

## 5. Uninstall

```bash
python3 scripts/install-codex-skill.py --uninstall
```

The uninstaller removes only Ship Flow-owned directories whose recorded
contents still match. If you changed an installation directory, it refuses to
delete it until you back it up or explicitly resolve the mismatch.
