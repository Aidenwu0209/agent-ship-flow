# Role boundaries

Ship Flow separates judgment from implementation so that evidence is genuinely
independent. A person may make a gate decision, while the engine owns its durable
record and validates the evidence subject.

| Role | May do | Must not do |
| --- | --- | --- |
| Planner | Clarify the goal, risks, acceptance criteria, migration and rollback plan | Approve its own plan |
| Plan Critic | Review the plan subject and record findings with exact locations | Implement the plan or reuse the Planner identity |
| Developer | Work only in the owned worktree and create the candidate | Record independent code Review or Verification as itself |
| Reviewer | Inspect the exact current subject; report correctness, security and migration findings | Edit the candidate or pass a different commit/tree |
| Verifier | Run the confirmed deterministic commands in order and preserve redacted evidence | Repair failures or silently change commands |
| Human approver | Confirm plan, exact release target, rollback context, or cleanup condition | Convert stale/missing evidence into a pass |

Every engine-issued handoff is one-time and subject-bound. Use a fresh context
and actor identity for each independent role. If a role discovers a required
change, return to the engine-directed earlier phase; do not patch from Reviewer
or Verifier context.

Findings must be actionable and include category, severity, message, and exact
location. A `pass` means zero unresolved critical, important, or migration-safety
findings for that exact subject, not merely "looks good".
