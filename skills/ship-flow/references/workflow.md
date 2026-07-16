# Workflow command map

Always take command arguments from the latest JSON state. `<ship>` means
`${CODEX_HOME:-$HOME/.codex}/tools/ship-flow/bin/ship`.

| Engine action | Controller action |
| --- | --- |
| `confirm_detected_manifest` | Show detected manifest and ask one confirmation; after approval call `init --accept-detected` |
| `set_plan` | Produce a plan file, then call `set-plan` with the current revision |
| `review_plan` | Start a distinct Plan Critic context, then call `record-plan-review` |
| `approve_plan` | Ask the human to approve the current reviewed plan; call `approve --gate plan` only after confirmation |
| `develop` | Work in the returned owned worktree; call `development-ready` only with the approved paths |
| `review_code` | Start a distinct Reviewer context for the exact current subject, then call `record-review` |
| `verify` | Start a distinct Verifier context and call `verify`; never repair in that context |
| `approve_release` | Show target, evidence subject and expiry; ask the human, then call `approve --gate release` |
| `release` | Call `release` with the exact returned target/approval/cycle context, then read status again |
| `reconcile_operation` | Present immutable UNKNOWN receipt evidence and request explicit adjudication; never rerun the write |
| `approve_rollback` | Show failed release and previous release; ask the human, then call `approve --gate rollback` |
| `rollback` | Call `rollback` with the exact returned approval and immutable rollback context |
| `record_sync` | Record the current code/docs/rules/project-knowledge sync report |
| `approve_cleanup` | Show owned resources and condition, ask the human, then call `cleanup --approve` |

Common form:

```text
<ship> <command> --repo <repo> --run-id <run-id> --expected-revision <revision> --json ...
```

`status` and `resume` are read/reconcile operations and do not take an expected
revision. Prefer `status` at the start of a turn. `resume` returns one safe next
action, but does not authorize the controller to skip its human/manual kind.

If the engine reports stale evidence, follow the returned earlier phase. Keep
old evidence as history. Never overwrite it, relabel it for a new commit, or
create an out-of-band exception.
