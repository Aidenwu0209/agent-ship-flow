# Integrating Agent Ship Flow with Any Agent

Agent Ship Flow is intentionally split into a deterministic CLI engine and
optional conversational adapters. The CLI is the portability boundary.

## Minimum capability

An integrating Agent needs to be able to:

1. execute a local argv command without invoking a shell;
2. retain or ask for an absolute repository path and a `run-id`;
3. parse JSON responses; and
4. show a user the first required human decision.

No model API, framework, or hosted service is required by the core.

## Turn protocol

For a new request:

```text
ship init --repo <repo> --json
ship start --repo <repo> --run-id <run-id> --expected-revision <revision> ... --json
```

For every later turn of an existing run:

```text
ship status --repo <repo> --run-id <run-id> --json
```

Read `state`, `evidence_status`, and the entire `next_action` object. If the
action is automatic, execute only that action with the returned IDs and current
revision, then call `status` again. If it is human or manual, ask exactly that
question and stop.

## Adapter rules

- Never write `.ship` state, evidence, approvals, receipts, or ownership
  records directly.
- Do not make raw Git status a substitute for engine status.
- Preserve opaque IDs verbatim. Do not generate replacements.
- Keep external-effect approval, health checking, unknown-outcome handling,
  and cleanup in the engine's state machine.
- Convert engine output into the host Agent's UX, but do not weaken its gate.

## Existing adapters

`skills/ship-flow/` is the Codex adapter. Other hosts can implement equivalent
thin adapters by following this document and `AGENTS.md`; they do not need to
import Codex-specific code.
