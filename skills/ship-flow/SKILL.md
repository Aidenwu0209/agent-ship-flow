---
name: "ship-flow"
description: "Use when a user wants Codex to implement, continue, review, verify, release, deploy, or inspect status through a maintainable end-to-end Git shipping workflow."
---

# Ship Flow

## Core contract

The initial user goal and current authorization contract are the permission
boundary. New runs default to `autonomous`; runs started with `--mode strict`
retain explicit plan, release, rollback, and cleanup gates. A legacy run with no
contract is always `strict`.

The contract binds the mode, repository and owned worktree, goal, branch,
manifest SHA-256 (including verification/release/health/rollback operations),
release target, previous release, generation, creation time, and state revision.
Status exposes `authorization.mode`, `source`, `generation`, and `digest`.
Contract gate
receipts use actor `scope-contract:<contract-digest>`.

## Engine and durable state

Run only `${CODEX_HOME:-$HOME/.codex}/tools/ship-flow/bin/ship` with an argv
array. Treat JSON as authoritative; never edit `.ship` state, evidence,
approvals, receipts, or ownership records.

For an existing run, the first workflow command in every turn is:

```text
<ship> status --repo <repo> --run-id <run-id> --json
```

For a new autonomous run, call `init`, execute its automatic `commit_manifest`
action, then call `start` with the exact goal and any declared release target or
previous release. Use `--mode strict` only when explicit audit approvals are
required.

## Controller loop

1. Read the complete `state`, `reason`, `evidence_status`, `authorization`,
   optional `scope_change`, and `next_action` objects.
2. In `autonomous` mode, execute every returned `automatic` action without
   asking, using its exact IDs and current `--expected-revision`. Progress
   updates are statements, not permission requests.
3. Ask an ordinary human question only when `next_action.action` is
   `approve_scope_change`. State the current/original contract boundary, the
   exact proposed boundary, and the consequence of approval. Do no expanded
   work before the decision.
4. A `manual` `UNKNOWN` external effect is a safety block, not an approval.
   Preserve its receipt, state the missing fact, and never replay the write.
5. In `strict` mode, follow the existing human gates in the command map. After
   every action, read status again.

Use [workflow.md](references/workflow.md) for exact commands and
[roles.md](references/roles.md) for actor boundaries.

## Evidence and cleanup boundaries

- Planner/Plan Critic, Developer/Reviewer, and Reviewer/Verifier remain
  separate; a Verifier records evidence and never repairs code.
- Changed candidate, manifest, command, target, or contract generation makes
  old evidence unusable. Current Review, Verification, health, and rollback
  evidence remain mandatory in both modes.
- A deploy health check must assert the exact released candidate or version.
  Generic service health evidence is insufficient.
- Autonomous release and rollback use the current contract, not guessed consent.
- Automatic cleanup may remove only an engine-owned, clean worktree after all
  path, ownership, merge/condition, and evidence preflights pass. Dirty,
  foreign, or unsafe resources are refused.

## Scope-change response

```text
当前：<phase>（证据：<current/stale/missing 摘要>）
已完成：<in-contract progress>
原始边界：<current contract goal and material>
拟议扩展：<exact proposed goal and material>
需要你确认：是否批准这一范围变更？
```

## Common mistakes

- Ask an ad-hoc feature-detail question instead of recording a scope change.
- Turn a progress update into a permission gate.
- Treat an `UNKNOWN` safety block as a retry signal.
