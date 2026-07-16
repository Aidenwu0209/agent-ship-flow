# Scope-Authorized Autonomy Design

**Status:** Approved
**Date:** 2026-07-16

## Goal

Make Ship Flow ask a person only when continuing would expand the user's
original authorization. Normal work inside that authorization—including
planning, implementation, independent review, verification, merge, release,
rollback, and safe engine-owned cleanup—must run without artificial approval
stops.

The default mode is `autonomous`. A `strict` mode preserves the existing
approval-heavy workflow for projects that require explicit audit gates.

## Problem

The current state machine treats plan approval, release approval, rollback
approval, and cleanup approval as unconditional human phases. The installed
skill then stops whenever the engine reports one of those phases. This makes a
clear request unnecessarily conversational even when every subsequent action
is already implied by that request.

Evidence independence is valuable and remains mandatory. Human confirmation is
not the evidence: independent review, verification, operation receipts, and
health checks continue to provide it.

## Product Decision

Ship Flow uses two execution policies, selected before a run begins and stored
with the run:

| Policy | Default | Human interaction |
| --- | --- | --- |
| `autonomous` | Yes | Ask only for a requested expansion of the recorded authorization. Exceptional unsafe states block with evidence; they do not create routine confirmation prompts. |
| `strict` | No | Preserve the current plan, release, rollback, and cleanup approval gates, in addition to scope-expansion requests. |

The initial authorization is not inferred from an action's risk label. It is a
durable contract made from the repository, the user's stated goal, the accepted
manifest, and the run-owned resources. An action is permitted when it stays
inside that contract and its ordinary evidence requirements are current.

## Authorization Contract

Each run receives an immutable, versioned authorization-contract record. The
record is stored in the run's private state directory rather than folded into
`RunState`, so existing state records remain readable and the contract can keep
its own append-only history.

Each generation records:

- execution policy (`autonomous` or `strict`);
- canonical repository path and run-owned worktree identity;
- user goal text;
- accepted manifest digest, including verification, release, health-check, and
  rollback operations;
- the baseline branch/ref and declared external target material;
- contract generation, creation time, and the state revision that bound it.

The initial manifest is part of the starting contract in autonomous mode. It is
reported in status output and must still cross the existing Git commit boundary
before a run starts, but it does not require a second conversational approval.
Strict initialization retains the explicit detected-manifest confirmation.

Changing a verification command, release target, rollback operation, health
check, owned resource, repository, or branch/ref after the contract is bound is
a hard scope change. The engine compares the current material with the contract
before external operations and safe cleanup. Semantic expansion that cannot be
derived from files (for example, adding a new feature direction) is raised by
the controller through the same scope-change command; the skill forbids it from
silently proceeding.

## Scope-Change Protocol

A new `AWAITING_SCOPE_APPROVAL` state and a `scope-change` request record
replace routine human gates in autonomous mode. A request contains the original
contract generation, a concise reason, an exact proposed expansion, and the
state revision that produced it.

The only ordinary human next action in autonomous mode is
`approve_scope_change`. Its response presents the original boundary, the
proposed boundary, and the consequence of acceptance. Approval appends a new
contract generation and returns the run to `PLANNING`; this forces fresh plan
review and prevents old evidence from being reused for the expanded task.
Rejection returns the run to the pre-change plan without applying the request.

The CLI will expose a single explicit request command for controller-detected
semantic expansion. The engine will create equivalent requests automatically
for hard boundary mismatches. Approval records bind to the request digest and
revision, so a stale approval cannot authorize a different expansion.

## State-Machine Behavior

The existing evidence phases remain. Only the routing after current evidence
changes by policy.

| Current evidence boundary | `autonomous` transition | `strict` transition |
| --- | --- | --- |
| plan critic passes | `PLAN_REVIEW -> DEVELOPING` | `PLAN_REVIEW -> AWAITING_PLAN_APPROVAL -> DEVELOPING` |
| verification passes | `VERIFYING -> RELEASING` | `VERIFYING -> AWAITING_RELEASE_APPROVAL -> RELEASING` |
| post-release health fails with an in-contract rollback | `POST_RELEASE_VERIFYING -> ROLLING_BACK` | `POST_RELEASE_VERIFYING -> ROLLBACK_PENDING -> ROLLING_BACK` |
| project sync is current and owned worktree is clean | `SYNCING -> COMPLETED` after safe cleanup | `SYNCING -> AWAITING_CLEANUP_APPROVAL -> COMPLETED` |

For both modes, a scope-change request routes to
`AWAITING_SCOPE_APPROVAL -> PLANNING` after approval. A dirty or unowned
resource is not deleted automatically. An `UNKNOWN` external effect remains
`BLOCKED` and must never be replayed; status reports the immutable receipt and
the missing fact rather than asking a generic confirmation question.

Release and rollback records in autonomous mode must bind the exact candidate,
target, contract generation, and manifest digest. They retain the same current
review, verification, operation-receipt, and health-check requirements as
strict mode. The sole difference is the authorization source: current contract
instead of a one-off human gate.

## CLI and Status Contract

- New runs default to `autonomous`; callers can select `strict` before the run
  is initialized and started.
- Existing runs without a policy record behave as `strict` for compatibility.
- `status --json` includes the execution policy, current authorization-contract
  digest/generation, and a `scope_change` object when one is pending.
- In autonomous mode, `next_action.kind` is `human` only for
  `approve_scope_change`. Routine release, rollback, and cleanup actions remain
  `automatic` once evidence and contract checks pass.
- A blocked unknown external operation remains `manual`, never `human`; it is a
  safety stop, not an approval request.

## Skill and Documentation Behavior

The Ship Flow skill will describe the authorization contract first. Its
controller loop may automatically carry an autonomous run through any
in-contract action, including external operations that the user explicitly
authorized by starting the run. It must issue a scope-change request before
adding objectives, changing targets, widening resources, weakening checks, or
changing the accepted manifest material.

Progress updates state what is happening and what evidence changed. They do not
ask for permission. The beginner-facing template asks for a decision only when
there is a pending scope change or an exceptional blocked state that has no safe
automatic continuation.

README and quick-start documentation will show both modes, make autonomous mode
the normal path, and give one concrete scope-change example.

## Compatibility and Migration

The state schema remains readable. Per-run policy and contract records are
additive. A missing policy record means `strict`, preserving the behavior and
approval receipts of already-created runs. New evidence records include an
authorization-source discriminator (`contract` or `human_approval`) so recovery
can validate either path without weakening subject, target, or revision checks.

The old approval commands remain available for strict runs. They reject use in
autonomous mode unless the run is currently handling a scope-change request.

## Testing Strategy

Unit tests will cover policy parsing, immutable contract generations, contract
digest comparison, authorization-source validation, and legal state
transitions.

Integration tests will prove all of the following:

1. a default autonomous run reaches completion without plan, release, rollback,
   or cleanup prompts while review and verification evidence remain current;
2. strict runs retain the current approval sequence and old approval receipts;
3. a changed manifest target or controller-requested semantic expansion produces
   exactly one `approve_scope_change` action and invalidates prior evidence;
4. a contract-bound release or rollback cannot reuse a stale contract generation
   or target;
5. `UNKNOWN` external effects stay blocked and are never replayed;
6. unowned or dirty cleanup is refused in both policies.

Documentation and skill transcript tests will assert that routine status text
does not contain confirmation language and that a genuine expansion does.

## Non-Goals

- Inferring feature scope from natural language without a controller declaration.
- Allowing automatic deletion of user-owned or dirty resources.
- Retrying an external operation whose outcome cannot be established.
- Removing independent plan criticism, code review, verification, release
  health checks, rollback verification, or immutable evidence.
