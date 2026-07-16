# Workflow command map

Always take arguments from the latest JSON state. `<ship>` means
`${CODEX_HOME:-$HOME/.codex}/tools/ship-flow/bin/ship`.

## Policy routing

New runs default to `autonomous`. Execute every returned automatic action and
read status again. The only ordinary human action is `approve_scope_change`.
A manual `UNKNOWN` result remains blocked and is never replayed. `strict` and
legacy runs preserve the original approval sequence.

| Engine action | Exact controller command or response |
| --- | --- |
| `commit_manifest` | Review the generated manifest, commit that exact file at the Git boundary, then continue; do not ask in autonomous mode |
| `set_plan` | Produce a plan file, then call `set-plan` with the current revision |
| `review_plan` | Start a distinct Plan Critic context, then call `record-plan-review` |
| `authorize_plan` | `<ship> authorize --gate plan --repo <repo> --run-id <run-id> --expected-revision <revision> --json` |
| `develop` | Work only in the returned owned worktree; call `development-ready` with approved paths |
| `review_code` | Start a distinct Reviewer context for the exact current subject, then call `record-review` |
| `verify` | Start a distinct Verifier context and call `verify`; never repair in that context |
| `authorize_release` | `<ship> authorize --gate release --repo <repo> --run-id <run-id> --expected-revision <revision> --json` |
| `release` | Call `release` with the exact returned approval/target/cycle context, then read status |
| `authorize_rollback` | `<ship> authorize --gate rollback --repo <repo> --run-id <run-id> --expected-revision <revision> --json` |
| `rollback` | Call `rollback` with the exact returned approval and immutable failed-release context |
| `record_sync` | Record the current code/docs/rules/project-knowledge sync report |
| `cleanup` | Call `<ship> cleanup --repo <repo> --run-id <run-id> --expected-revision <revision> --json`; unchanged safety preflight may refuse it |
| `request_scope_change` | `<ship> request-scope-change --repo <repo> --run-id <run-id> --expected-revision <revision> --reason <reason> --summary <summary> --goal <proposed-goal> --manifest-sha256 <sha256> --json` |
| `approve_scope_change` | `<ship> resolve-scope-change --repo <repo> --run-id <run-id> --expected-revision <revision> --decision approve --actor <actor> --json` |
| `manual_reconciliation` | Present the immutable `UNKNOWN` receipt and missing fact as a safety block; never rerun the write |

Use `request-scope-change` before semantic expansion. Include
`--release-target` and `--previous-release` when either proposed value is part
of the new boundary. Approval or rejection returns to `PLANNING`; approval
creates a new contract generation, so Review and Verification restart for the
expanded subject. Use `--decision reject` to retain the current generation.

## Strict and legacy gates

In `strict` mode, `confirm_detected_manifest`, `approve_plan`,
`approve_release`, `approve_rollback`, and `approve_cleanup` remain human
actions. After the exact decision, use `approve --gate plan|release|rollback`
with its required actor/context, or `cleanup --approve`. A run without an
authorization contract reports `authorization.source=legacy_default` and uses
the same strict sequence.

`status` and `resume` are read/reconcile operations and do not take an expected
revision. Prefer `status` at the start of a turn. Never overwrite stale
evidence, invent an ID/revision/target, ask permission for an automatic action,
or convert a manual safety block into a generic confirmation.
