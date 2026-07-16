# Agent Ship Flow quick start for Codex

English | [简体中文](ship-flow-quickstart-zh.md)

> The core CLI and JSON protocol work with any local-command agent. Other
> controllers should follow the [agent integration guide](agent-integration.md).

## 1. Install the Codex adapter

From this repository, with Python 3.11+ and Git available:

```bash
python3 scripts/install-codex-skill.py
~/.codex/tools/ship-flow/bin/ship --help
```

If installation is interrupted, fix the disk-space or permission issue and run
the same installer again. Do not delete its transaction log; recovery validates
the known staged and installed trees.

## 2. Start in autonomous mode

New runs default to `autonomous`. Give Codex the complete initial boundary,
including any release target and rollback version you intend to authorize:

```text
Use $ship-flow to implement “Show an actionable error when login fails”, independently review and verify it, release this exact candidate to production if all evidence passes, verify health, and safely clean up the engine-owned worktree. The previous release is v1.
```

The initial goal and authorization contract are the permission boundary. Codex
executes every returned automatic action without asking, including contract
authorization for plan/release/rollback and eligible cleanup. Progress updates
are statements.

Autonomous `init` returns automatic `commit_manifest`. Codex must commit that
exact generated policy before `start`, but does not ask for a second approval.
The contract binds mode, repository/worktree, goal, branch, manifest digest,
release target, previous release, generation, creation time, and state revision.
Status exposes `authorization.mode`, `source`, `generation`, and `digest`; gate
receipts use
`scope-contract:<contract-digest>`.

## 3. Resume from durable status

For an existing run, give Codex its repository path and `run-id`. Every turn
starts with:

```bash
~/.codex/tools/ship-flow/bin/ship status --repo /absolute/repo --run-id run-login-001 --json
```

Codex follows the complete `next_action`, then reads status again. Independent
Plan Critic, Reviewer, and Verifier contexts remain required. Changed code,
manifest material, target, or contract generation makes old evidence unusable.

## 4. Approve only a recorded scope expansion

If the current contract covers account export and you ask for a deployment
dashboard, Codex first reports completed in-contract progress and records the
original and proposed boundaries:

```bash
~/.codex/tools/ship-flow/bin/ship request-scope-change --repo /absolute/repo --run-id run-login-001 --expected-revision 12 --reason feature_expansion --summary "add deployment dashboard" --goal "ship account export and a deployment dashboard" --manifest-sha256 <sha256> --release-target production --json
```

Only the returned `approve_scope_change` action becomes an ordinary question.
After you approve the exact proposal, Codex runs:

```bash
~/.codex/tools/ship-flow/bin/ship resolve-scope-change --repo /absolute/repo --run-id run-login-001 --expected-revision 13 --decision approve --actor human-owner --json
```

The new contract generation returns to planning, so prior evidence is not reused
for the expanded task. Codex must not replace this record with an ad-hoc question
about dashboard details.

## 5. Use strict mode for explicit audit gates

Ask for strict mode when plan, release, rollback, and cleanup must each stop for
human approval:

```text
Use $ship-flow in --mode strict to ship “Update the audited billing rule”.
```

Strict initialization also preserves detected-manifest confirmation. Existing
runs with no contract use strict compatibility automatically and report
`authorization.source=legacy_default`.

## 6. Handle `UNKNOWN` and cleanup safely

A manual `UNKNOWN` external result is a safety block, not a permission prompt.
Codex preserves its receipt and states the missing fact; it uses a reliable
read-only probe or the engine's adjudication path and never replays the write.

Automatic cleanup removes only an engine-owned, clean worktree after path,
ownership, merge/approved-condition, and evidence checks pass. Dirty, foreign,
or unsafe resources are refused. The adapter never gains credentials or bypasses
Codex's own platform permissions.

## 7. Uninstall

```bash
python3 scripts/install-codex-skill.py --uninstall
```

The uninstaller removes only Ship Flow-owned directories whose recorded content
still matches. It refuses modified or replaced installation paths.
