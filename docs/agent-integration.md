# Integrating Agent Ship Flow with Any Agent

Agent Ship Flow is split into a deterministic CLI engine and optional
conversational controllers. The CLI and JSON schema are the portability
boundary.

## Minimum capability

An integrating agent must execute local argv commands without a shell, retain
an absolute repository path and `run-id`, parse JSON, preserve opaque values,
and present the exact scope-change decision. No model API or hosted service is
required by the core.

## Authorization contract

The initial goal plus current authorization contract are the permission
boundary. New runs default to `autonomous`; `--mode strict` preserves explicit
plan, release, rollback, and cleanup gates. Runs with no contract use strict
compatibility and report `authorization.source=legacy_default`.

Each contract generation binds mode, canonical repository, engine-owned
worktree, goal, branch, manifest SHA-256 (verification, release, health-check,
and rollback material), release target, previous release, generation, creation
time, and state revision. JSON exposes `authorization.mode`, `source`,
`generation`, and `digest`. Contract-authorized gate receipts use
`scope-contract:<contract-digest>`.

## Initialize and start

For the default autonomous path:

```text
ship init --repo <repo> --json
```

The result writes the detected manifest and returns automatic
`commit_manifest`. Execute that action without asking, but preserve the existing
Git commit boundary for `.ship/manifest.toml`. Start only from the committed,
clean policy:

```text
ship start --repo <repo> --run-id <run-id> --goal <goal> --release-target <target> --previous-release <release> --json
```

Omit release values only when they are outside the requested workflow. In
strict initialization, use `init --mode strict`; surface
`confirm_detected_manifest`, then use `--accept-detected` only after that
decision.

## Turn protocol

Every later turn begins with:

```text
ship status --repo <repo> --run-id <run-id> --json
```

Read the complete `state`, `reason`, `evidence_status`, `authorization`, optional
`scope_change`, and `next_action` objects.

- In autonomous mode, execute every `automatic` action with the returned IDs
  and current `--expected-revision`; do not ask permission first.
- Ask an ordinary question only for `approve_scope_change`. Present the
  current/original boundary, exact proposal, and consequence.
- Report progress as statements.
- A `manual` `UNKNOWN` state is a safety block. Preserve its receipt, report the
  missing fact, and never replay the external write.
- In strict or legacy mode, surface the existing human gates one at a time.

Read status again after every mutation. Never generate replacement IDs, infer a
phase from chat/Git, or edit `.ship` state directly.

## Automatic authorization commands

Map policy actions exactly:

```text
authorize_plan     -> ship authorize --gate plan --repo <repo> --run-id <run-id> --expected-revision <revision> --json
authorize_release  -> ship authorize --gate release --repo <repo> --run-id <run-id> --expected-revision <revision> --json
authorize_rollback -> ship authorize --gate rollback --repo <repo> --run-id <run-id> --expected-revision <revision> --json
```

Do not add an actor to `authorize`. The engine derives the current contract
actor and validates evidence, target, failed-release context, and generation.

## Scope-change protocol

Before adding an objective, changing a target/resource, or altering accepted
manifest material, create a durable request:

```text
ship request-scope-change --repo <repo> --run-id <run-id> --expected-revision <revision> --reason <reason> --summary <summary> --goal <proposed-goal> --manifest-sha256 <sha256> --json
```

Include proposed release/previous-release values when applicable. The only
ordinary autonomous human action is then resolved with:

```text
ship resolve-scope-change --repo <repo> --run-id <run-id> --expected-revision <revision> --decision approve --actor <actor> --json
```

Approval appends a contract generation and returns to `PLANNING`; rejection
keeps the current generation. Neither decision reuses old evidence for a changed
subject.

## Evidence, roles, and cleanup

Autonomy never merges Planner/Plan Critic, Developer/Reviewer, or
Reviewer/Verifier. Current Review, Verification, health, rollback, immutable
receipt, and stale-evidence checks remain mandatory.

Automatic cleanup calls the same preflight as strict cleanup and may remove only
an engine-owned, clean worktree whose path, ownership, merge/approved condition,
and evidence checks pass. Refuse dirty, foreign, or unsafe resources.

## Existing adapter

`skills/ship-flow/` is the Codex adapter. Other hosts can implement equivalent
thin controllers from this contract; they do not need to import Codex-specific
code.
