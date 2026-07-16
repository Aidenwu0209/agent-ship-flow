# Role boundaries

Ship Flow separates authorization, judgment, implementation, and evidence.
Autonomous mode changes the source of routine gate authorization; it does not
merge roles or weaken evidence.

| Role | May do | Must not do |
| --- | --- | --- |
| Planner | Clarify the in-contract goal, risks, acceptance criteria, migration, and rollback plan | Approve its own plan or silently widen the contract |
| Plan Critic | Review the exact plan subject and record actionable findings | Implement the plan or reuse the Planner identity |
| Developer | Work only in the owned worktree and create the candidate | Record independent Code Review or Verification as itself |
| Reviewer | Inspect the exact current subject; report correctness, security, and migration findings | Edit the candidate or pass a different commit/tree |
| Verifier | Run confirmed deterministic commands and preserve redacted evidence | Repair failures or silently change commands |
| Scope approver | Compare the original/current contract with the exact proposed expansion and approve or reject that request | Replace missing evidence, approve a different request, or make a stale approval current |
| Strict approver | In `strict` or legacy mode, decide the current plan, release target, rollback context, or cleanup condition | Treat vague consent as a durable approval or bypass stale evidence |

Contract authorization is an engine record, not an independent human role. In
autonomous mode the engine records routine gate actor
`scope-contract:<contract-digest>` only after checking the current contract and
evidence. In strict mode it records the explicit human approval instead.

Every engine-issued handoff is one-time and subject-bound. Use a fresh context
and actor identity for each independent role. If a role discovers a required
change, return to the engine-directed earlier phase. A semantic expansion must
become a durable scope-change request before planning or implementation.

Findings include category, severity, message, and exact location. A `pass`
means zero unresolved critical, important, or migration-safety findings for
that exact subject. A manual `UNKNOWN` operation remains a safety block; no
role may replay it or relabel uncertainty as approval.
