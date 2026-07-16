# Agent Ship Flow quick start

English | [简体中文](quickstart-zh.md)

This guide works with any agent that can execute local argv commands, retain an
absolute repository path and `run-id`, parse JSON, and present one scope-change
decision. New runs use scope-authorized `autonomous` mode by default.

## 1. Install the CLI

Agent Ship Flow requires Python 3.11+, Git, and an existing Git repository:

```bash
git clone https://github.com/Aidenwu0209/agent-ship-flow.git
cd agent-ship-flow
python3 -m pip install -e .
ship --help
```

Use `python3 -m pip install -e ".[dev]"` when developing this project.

## 2. Initialize the default autonomous policy

```bash
ship init --repo /absolute/path/to/target-repo --json
```

Autonomous initialization writes the detected manifest and returns automatic
`commit_manifest`. A controller executes that action without asking. When using
the CLI directly, inspect and cross the same Git commit boundary yourself:

```bash
git add .ship/manifest.toml
git commit -m "chore: configure ship flow"
```

The manifest still defines the base branch, verification commands, release
target, health check, and rollback operations. It must be committed before the
run starts; autonomous mode removes a second conversation, not this boundary.

## 3. Start and inspect the authorization contract

```bash
ship start \
  --repo /absolute/path/to/target-repo \
  --run-id run-login-error-001 \
  --goal "Show an actionable error when login fails" \
  --release-target production \
  --previous-release v1 \
  --json
```

The immutable contract generation binds:

- execution mode;
- canonical repository and engine-owned worktree;
- exact user goal and branch;
- manifest SHA-256, including verification, release, health, and rollback
  material;
- release target and previous release; and
- contract generation, creation time, and bound state revision.

The response exposes `authorization.mode`, `source`, `generation`, and `digest`.
Preserve the returned `run-id` and opaque values exactly.

## 4. Drive every turn from status

```bash
ship status \
  --repo /absolute/path/to/target-repo \
  --run-id run-login-error-001 \
  --json
```

Use `state`, `evidence_status`, `authorization`, optional `scope_change`, and the
complete `next_action`:

- execute every `automatic` action with its current revision and IDs, then read
  status again;
- in autonomous mode, ask only for `approve_scope_change`;
- report progress as a statement, never as a permission request; and
- treat a manual `UNKNOWN` result as a safety block and never replay the write.

Independent Plan Review, Code Review, Verification, release health evidence,
rollback verification, and stale-evidence rejection remain mandatory.

## 5. Record an expansion before doing it

Suppose the current goal covers account export and the user adds a deployment
dashboard. Preserve both boundaries and request the expansion first:

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

When the returned action is `approve_scope_change`, show the original boundary,
the exact proposal, and the consequence. After approval:

```bash
ship resolve-scope-change --repo /absolute/path/to/target-repo --run-id run-login-error-001 --expected-revision 13 --decision approve --actor human-owner --json
```

Approval creates the next contract generation and returns to planning; rejection
keeps the current generation.

## 6. Select strict mode when required

Strict mode retains detected-manifest confirmation plus plan, release, rollback,
and cleanup approvals:

```bash
ship start --repo /absolute/path/to/target-repo --run-id run-audit-001 --goal "Ship the audited change" --mode strict --json
```

Runs created before authorization contracts also report
`authorization.source=legacy_default` and follow this strict behavior.

## 7. Cleanup remains bounded

Autonomous cleanup can remove only the engine-owned, clean worktree after path,
ownership, merge/approved-condition, and evidence checks pass. Dirty, foreign,
or unsafe resources are refused in both modes.

For Codex, continue with the [Codex adapter quick start](ship-flow-quickstart.md).
Adapter authors should use the [JSON protocol guide](agent-integration.md).
