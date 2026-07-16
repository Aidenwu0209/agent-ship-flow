---
name: "ship-flow"
description: "Use when a user wants Codex to implement, continue, review, verify, release, deploy, or inspect status through a maintainable end-to-end Git shipping workflow."
---

# Ship Flow

Use the installed Ship Flow engine as the authority for every workflow state and
next action. The controller makes the workflow understandable for a beginner;
it does not replace the engine's gates with prose or judgment.

## Engine

Run the engine only through:

```text
${CODEX_HOME:-$HOME/.codex}/tools/ship-flow/bin/ship
```

Pass arguments as an argv array, never through a shell-built command. Treat the
JSON response as authoritative. Do not edit `.ship` state, evidence, approvals,
operation receipts, or ownership records by hand.

## Start every turn from durable state

For an existing run, the first workflow command in every turn must be:

```text
${CODEX_HOME:-$HOME/.codex}/tools/ship-flow/bin/ship status --repo <repo> --run-id <run-id> --json
```

Do this even when the user says where the run stopped. Never infer the phase
from conversation history, Git alone, a previous Review, or a previous command
result. If the repository or run ID is missing and cannot be identified without
guessing, ask only for that first missing value and stop.

For a new run, call `ship init --repo <repo> --json`. When it returns
`confirm_detected_manifest`, summarize the detected commands, release target,
health check, and rollback policy, ask the user to confirm or correct them, and
stop. Use `--accept-detected` only after that explicit confirmation. Then call
`ship start` with the confirmed goal.

## Controller loop

1. Read `state.revision`, `state.phase`, `reason`, `evidence_status`, and the
   complete `next_action` object from JSON.
2. If `next_action.kind` is `human` or `manual`, ask exactly the first missing
   decision or fact. Explain the consequence in plain Chinese. Do not perform a
   different action in the same turn.
3. If it is automatic, perform exactly that action with the returned identifiers
   and current `--expected-revision`. Do not invent or reuse an approval ID,
   cycle ID, target, failed release ID, previous release, subject, or revision.
4. Immediately run `status --json` again. Report the new phase, evidence, and
   next action. Continue automatically only when the user explicitly asked to
   carry the flow forward and the next action is still automatic and reversible.
5. On a conflict, recovery error, `UNKNOWN` external effect, or changed subject,
   stop. Preserve all evidence and present the engine's first required manual
   adjudication. Never blindly replay an external write.

Use the command mapping in [workflow.md](references/workflow.md). Use the role
boundaries in [roles.md](references/roles.md).

## Gates that must never be bypassed

- Planner and Plan Critic must be distinct contexts. A plan approval applies
  only to the reviewed plan subject.
- Developer and Reviewer must be distinct contexts. Any candidate/tree/manifest/
  command change makes later Review or Verification evidence stale as reported
  by the engine.
- Verifier runs confirmed commands and records evidence; it never repairs code.
  A failure returns control to Development and requires a fresh Review.
- A release requires current Review and Verification evidence plus a current,
  target-bound, expiring human approval. Do not turn a user's vague "go ahead"
  into a fabricated approval record.
- Never deploy when a deploy operation lacks a confirmed health check that
  asserts the released candidate/version.
- Rollback uses its own approval and immutable context bound to the failed
  release and previous release. Never substitute a guessed release ID.
- Cleanup is a human gate and may remove only engine-owned, clean resources
  under the approved condition.
- Never push, merge, release, deploy, rollback, delete a worktree, or resolve an
  `UNKNOWN` effect unless the current engine state explicitly authorizes that
  exact action.

## Beginner-facing response

Keep the response short and concrete:

```text
当前：<phase>（证据：<current/stale/missing 摘要>）
已完成：<one action, or none>
需要你确认：<the first human/manual question, if any>
下一步：<engine next_action>
```

Never claim success merely because a command was started. Cite the evidence or
receipt path returned by the engine when a gate or external operation completes.
