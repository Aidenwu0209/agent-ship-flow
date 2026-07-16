# Agent Contributor Guide

This file is written for any coding Agent, not one provider.

1. For an existing Ship Flow run, execute `ship status --repo <repo> --run-id
   <run-id> --json` before deciding what to do.
2. Treat JSON `next_action` as authoritative. Do not infer phase from chat
   history, a branch name, or an old test result.
3. Ask only the first missing human or manual decision. Never invent a
   revision, approval ID, cycle ID, target, release ID, or health assertion.
4. Keep Planner, Plan Critic, Developer, Reviewer, and Verifier independent.
   A Verifier records evidence and never repairs code.
5. Never replay an `UNKNOWN` external write. Preserve evidence and use the
   engine's probe or manual adjudication path.
6. Do not push, merge, release, deploy, rollback, or delete worktrees unless
   the current engine state authorizes that exact action and the user has
   supplied the required human approval.

Read [docs/agent-integration.md](docs/agent-integration.md) for the complete
portable integration contract.
