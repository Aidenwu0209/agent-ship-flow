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

## Confirm and version the manifest

For a new repository, run `ship init --repo <repo> --json` and surface its
`confirm_detected_manifest` decision to the human. After the human confirms the
detected policy, run `ship init --repo <repo> --accept-detected --json`. A new
manifest returns the human JSON action `commit_manifest` with its path.

Surface `commit_manifest` to the human and stop for the human Git action. The
integration must not commit the file automatically. The human reviews the
project policy, then adds and commits the manifest:

```text
git add .ship/manifest.toml
git commit -m "chore: configure ship flow"
```

Resume with `ship start` only after the repository is clean. When the confirmed
manifest requires a clean base, the engine refuses to create a run from a dirty
base checkout.

## Turn protocol

For a new request, confirm and commit the manifest as described above, then
start the run with its goal:

```text
ship start --repo <repo> --run-id <run-id> --goal <goal> --json
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
