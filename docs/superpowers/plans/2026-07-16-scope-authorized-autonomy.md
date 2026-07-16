# Scope-Authorized Autonomy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make new Ship Flow CLI runs autonomous by default, preserve strict mode for existing/high-audit runs, and ask a human only for durable scope expansion.

**Architecture:** Add a private append-only authorization store beside each run's state WAL. Keep existing approval phases as recovery-safe internal checkpoints, but derive automatic gate receipts from the current contract in autonomous mode. Add one scope-change state and request/resolve protocol; retain all review, verification, external-operation, health-check, and cleanup safety evidence.

**Tech Stack:** Python 3.11+, standard library, `unittest`, existing Ship Flow state/evidence modules, Ruff.

## Global Constraints

- New CLI runs default to `autonomous`; `--mode strict` preserves the existing interactive approval sequence.
- Existing runs without an authorization contract behave as `strict`.
- Autonomous mode emits a human next action only for `approve_scope_change`; an `UNKNOWN` external effect remains a manual safety block and is never replayed automatically.
- Plan criticism, code review, verification, release health checks, rollback verification, immutable receipts, actor separation, and stale-evidence rejection remain mandatory.
- Contract-authorized gate receipts use the actor `scope-contract:<contract-digest>`; human approval receipt schemas remain backward compatible.
- Automatic cleanup may remove only the engine-owned clean worktree under the existing cleanup preflight.
- No runtime dependency may be added; Python 3.11 and 3.12 remain supported.
- Every production behavior change follows red-green-refactor and is committed with its focused tests.

---

### Task 1: Durable authorization contracts and scope-change state

**Files:**
- Create: `src/ship_flow/authorization.py`
- Modify: `src/ship_flow/model.py`
- Modify: `src/ship_flow/store.py`
- Create: `tests/unit/test_authorization.py`
- Modify: `tests/unit/test_store.py`

**Interfaces:**
- Consumes: `StateStore`, `FileLock`, `_atomic_write_private_json`, `_read_bounded_private_file`, `_remove_private_file`, `manifest_digest`.
- Produces: `ExecutionMode`, `AuthorizationContract`, `ScopeChangeRequest`, `ScopeChangeResolution`, `AuthorizationStore.create_initial()`, `AuthorizationStore.current()`, `AuthorizationStore.mode()`, `AuthorizationStore.request_change()`, and `AuthorizationStore.resolve_change()`.

- [ ] **Step 1: Write failing model and persistence tests**

Add tests that construct a private `StateStore`, create a run, and assert this public contract:

```python
contract = AuthorizationStore(store).create_initial(
    mode=ExecutionMode.AUTONOMOUS,
    goal="ship the requested repository change",
    repository=repo.resolve(),
    worktree=worktree.resolve(),
    branch="feat/example",
    manifest_sha256="a" * 64,
    release_target="production",
    previous_release="v1",
    state_revision=state.revision,
)
self.assertEqual(contract.generation, 1)
self.assertEqual(AuthorizationStore(store).current(), contract)
self.assertEqual(AuthorizationStore(store).mode(), ExecutionMode.AUTONOMOUS)
self.assertRegex(contract.digest(), r"^[0-9a-f]{64}$")
```

Also assert that a missing authorization directory returns `None` from
`current()` and `ExecutionMode.STRICT` from `mode()`, an existing initial
contract is idempotent only for identical input, immutable contract files are
mode `0600`, and a symlinked authorization path is rejected.

- [ ] **Step 2: Run the new tests and verify RED**

Run:

```bash
/tmp/agent-ship-flow-scope-authority-venv/bin/python -m unittest tests.unit.test_authorization -v
```

Expected: import failure for `ship_flow.authorization`.

- [ ] **Step 3: Add the authorization data model and private store**

Implement these exact top-level types in `authorization.py`:

```python
class ExecutionMode(str, Enum):
    AUTONOMOUS = "autonomous"
    STRICT = "strict"


@dataclass(frozen=True)
class AuthorizationContract:
    run_id: str
    generation: int
    mode: ExecutionMode
    goal: str
    repository: str
    worktree: str
    branch: str
    manifest_sha256: str
    release_target: str | None
    previous_release: str | None
    state_revision: int
    created_at: str
    schema_version: int = 1


@dataclass(frozen=True)
class ScopeChangeRequest:
    request_id: str
    run_id: str
    contract_digest: str
    contract_generation: int
    reason: str
    summary: str
    proposed_goal: str
    proposed_manifest_sha256: str
    proposed_release_target: str | None
    proposed_previous_release: str | None
    requested_at: str
    gate_revision: int
    schema_version: int = 1


@dataclass(frozen=True)
class ScopeChangeResolution:
    resolution_id: str
    request_id: str
    run_id: str
    decision: str
    actor: str
    previous_contract_digest: str
    resulting_contract_digest: str
    resolved_at: str
    gate_revision: int
    schema_version: int = 1
```

`AuthorizationContract` must implement `to_dict(self) -> dict[str, object]`,
`from_dict(cls, value: Mapping[str, object]) -> AuthorizationContract`, and
`digest(self) -> str`. `ScopeChangeRequest` and `ScopeChangeResolution` must
implement the corresponding `to_dict`, `from_dict`, and `digest` methods.

`AuthorizationStore` must expose these complete signatures:

- `__init__(self, store: StateStore) -> None`
- `create_initial(self, *, mode: ExecutionMode, goal: str, repository: Path, worktree: Path, branch: str, manifest_sha256: str, release_target: str | None, previous_release: str | None, state_revision: int) -> AuthorizationContract`
- `current(self) -> AuthorizationContract | None`
- `mode(self) -> ExecutionMode`
- `pending(self) -> ScopeChangeRequest | None`
- `latest_resolution(self) -> ScopeChangeResolution | None`
- `request_change(self, *, reason: str, summary: str, proposed_goal: str, proposed_manifest_sha256: str, proposed_release_target: str | None, proposed_previous_release: str | None, expected_revision: int) -> ScopeChangeRequest`
- `resolve_change(self, *, decision: str, actor: str, expected_revision: int) -> AuthorizationContract`

Use canonical JSON and SHA-256. Store immutable generations at
`authorization/contracts/0001-<digest>.json`, a replaceable `current.json`
pointer containing the exact generation and digest, and one replaceable
`pending-scope-change.json`. Every approve/reject decision writes an immutable
`authorization/resolutions/<request-id>-<resolution-id>.json` binding the
request, actor, decision, previous contract, resulting contract, and gate
revision before the pending pointer is removed. Use the existing private-file
helpers and a run-local `authorization.lock`.

- [ ] **Step 4: Add and test the scope-change phase**

Add `Phase.AWAITING_SCOPE_APPROVAL`. Permit normal transitions from all active
pre-release/release-gate/sync-gate phases into it, and permit only
`AWAITING_SCOPE_APPROVAL -> PLANNING`. Add matching conservative reconciliation
edges for interrupted scope request/approval publication.

Tests must prove:

```python
request = authorizations.request_change(
    reason="manifest_drift",
    summary="verification command changed",
    proposed_goal=contract.goal,
    proposed_manifest_sha256="b" * 64,
    proposed_release_target=contract.release_target,
    proposed_previous_release=contract.previous_release,
    expected_revision=state.revision,
)
self.assertEqual(store.load().phase, Phase.AWAITING_SCOPE_APPROVAL)
self.assertEqual(authorizations.pending(), request)

expanded = authorizations.resolve_change(
    decision="approve",
    actor="human-owner",
    expected_revision=store.load().revision,
)
self.assertEqual(expanded.generation, 2)
self.assertEqual(store.load().phase, Phase.PLANNING)
self.assertIsNone(authorizations.pending())
self.assertEqual(authorizations.latest_resolution().decision, "approve")
self.assertEqual(authorizations.latest_resolution().actor, "human-owner")
```

For `decision="reject"`, retain generation 1, return it, clear the pending
request, and transition to `PLANNING`. Reject stale revisions, changed request
digests, multiple pending requests, invalid SHA-256 values, and empty reasons.

- [ ] **Step 5: Verify Task 1 and commit**

Run:

```bash
/tmp/agent-ship-flow-scope-authority-venv/bin/python -m unittest tests.unit.test_authorization tests.unit.test_store -v
```

Expected: all selected tests pass.

Commit:

```bash
git add src/ship_flow/authorization.py src/ship_flow/model.py src/ship_flow/store.py tests/unit/test_authorization.py tests/unit/test_store.py
git commit -m "feat: add durable authorization contracts"
```

---

### Task 2: CLI mode selection, status, and scope-change protocol

**Files:**
- Modify: `src/ship_flow/cli.py`
- Modify: `src/ship_flow/reconcile.py`
- Modify: `tests/integration/test_cli.py`
- Modify: `tests/integration/test_reconcile.py`

**Interfaces:**
- Consumes: Task 1's `AuthorizationStore` and authorization data classes.
- Produces: `ship init --mode`, `ship start --mode`, `ship request-scope-change`, `ship resolve-scope-change`, authorization metadata in status, and policy-aware `next_action` JSON.

- [ ] **Step 1: Write failing CLI tests for default and strict modes**

Extend the CLI fixture so a default start asserts:

```python
self.assertEqual(started["authorization"]["mode"], "autonomous")
self.assertEqual(started["authorization"]["generation"], 1)
self.assertRegex(started["authorization"]["digest"], r"^[0-9a-f]{64}$")
```

Add a strict start with `--mode strict` and assert the same payload reports
`strict`. Add a direct-library legacy run with no contract and assert status
reports strict compatibility.

- [ ] **Step 2: Run focused CLI tests and verify RED**

Run:

```bash
/tmp/agent-ship-flow-scope-authority-venv/bin/python -m unittest tests.integration.test_cli.BeginnerCliFlowTests tests.integration.test_reconcile.NextActionTests -v
```

Expected: parser rejects `--mode` or the authorization payload is missing.

- [ ] **Step 3: Add mode-aware init/start and status payloads**

Add parser choices `("autonomous", "strict")` to `init` and `start`, defaulting
to autonomous. Add `start` options `--release-target` and
`--previous-release`. After `_workflow_start`, create the initial contract from
the current manifest, resolved repository/worktree paths, selected branch, goal,
and state revision. Repeated identical `start` calls must recover the same
contract.

For `init`, autonomous mode writes the detected manifest immediately and emits:

```json
{"kind":"automatic","action":"commit_manifest"}
```

Strict mode keeps `confirm_detected_manifest` until `--accept-detected` is
provided. The manifest commit boundary remains unchanged.

Add to every run payload:

```python
"authorization": {
    "mode": contract.mode.value if contract else "strict",
    "source": "contract" if contract else "legacy_default",
    "generation": contract.generation if contract else None,
    "digest": contract.digest() if contract else None,
}
```

- [ ] **Step 4: Write failing scope-request CLI tests**

From an autonomous `DEVELOPING` run, invoke:

```text
ship request-scope-change --reason feature_expansion
  --summary "add deployment dashboard"
  --goal "ship the feature and deployment dashboard"
  --manifest-sha256 <current sha>
  --release-target production
```

Assert the state becomes `AWAITING_SCOPE_APPROVAL` and the exact next action is:

```json
{"phase":"AWAITING_SCOPE_APPROVAL","kind":"human","action":"approve_scope_change","request_id":"<sha256>"}
```

Resolve with `ship resolve-scope-change --decision approve --actor human-owner`
and assert generation 2 plus `PLANNING`. Add a rejection case that retains
generation 1.

- [ ] **Step 5: Implement the two scope-change handlers and policy-aware action**

Add `_handle_request_scope_change`, `_handle_resolve_scope_change`, parser
definitions with required expected revisions, and a `_policy_aware_next_action`
wrapper. `AWAITING_SCOPE_APPROVAL` is the only phase that returns a human action
for an autonomous contract. `BLOCKED` remains `manual_reconciliation`.

When the current manifest digest differs from the contract, status returns an
automatic `request_scope_change` action containing reason `manifest_drift`, the
current contract digest, and the proposed manifest digest. It does not mutate
state or silently accept the drift.

- [ ] **Step 6: Verify Task 2 and commit**

Run:

```bash
/tmp/agent-ship-flow-scope-authority-venv/bin/python -m unittest tests.integration.test_cli tests.integration.test_reconcile -v
```

Expected: all CLI and reconciliation tests pass.

Commit:

```bash
git add src/ship_flow/cli.py src/ship_flow/reconcile.py tests/integration/test_cli.py tests/integration/test_reconcile.py
git commit -m "feat: expose autonomous and strict modes"
```

---

### Task 3: Automatic contract authorization for existing durable gates

**Files:**
- Modify: `src/ship_flow/cli.py`
- Modify: `src/ship_flow/reconcile.py`
- Modify: `src/ship_flow/release.py`
- Modify: `src/ship_flow/workflow.py`
- Modify: `tests/integration/test_cli.py`
- Modify: `tests/integration/test_release.py`
- Modify: `tests/integration/test_workflow.py`

**Interfaces:**
- Consumes: Task 2's policy-aware action and contract fields.
- Produces: `ship authorize --gate plan|release|rollback`, contract-bound approval receipts, automatic safe cleanup, and recovery-safe autonomous next actions.

- [ ] **Step 1: Write failing automatic-plan authorization test**

After a passing plan critic report in a default autonomous CLI run, assert
status emits:

```json
{"phase":"AWAITING_PLAN_APPROVAL","kind":"automatic","action":"authorize_plan","authorization_source":"contract"}
```

Run `ship authorize --gate plan` with the returned revision. Assert it reaches
`DEVELOPING`, its approval evidence stores
`approver_actor="scope-contract:<current-contract-digest>"`, and no `--actor`
argument exists on the authorize command.

- [ ] **Step 2: Implement the automatic authorize command for plan and release**

Add `authorize` as a mutation command with `--gate` choices
`plan`, `release`, and `rollback`. It rejects strict or missing-contract runs.
For plan, call `record_plan_approval()` using the derived contract actor.

For release, require `contract.release_target`, call
`ReleaseEngine.record_approval()` with the contract actor and the existing
15-minute expiry, then return `authorization_source="contract"`, approval ID,
target, and automatic `release` next action. The resulting immutable receipt is
already bound to subject, target, operation digests, gate revision, and actor;
the contract digest in the actor completes the authorization binding without a
receipt schema migration.

- [ ] **Step 3: Write and implement automatic rollback authorization**

Add a read-only `ReleaseEngine.inspect_failed_release_context()` returning an
`ExternalCycleContext` for the sealed failed release cycle while state is
`ROLLBACK_PENDING`. The context must include the release approval ID and target;
it must not create or repair evidence.

When `authorize --gate rollback` runs, require contract target and
`previous_release`, obtain the sealed failed release context, and record the
rollback approval with:

```python
engine.record_approval(
    gate="rollback",
    target=contract.release_target,
    approver_actor=f"scope-contract:{contract.digest()}",
    expires_at=_utc_after(),
    failed_release_id=failed_context.approval_id,
    previous_release=contract.previous_release,
)
```

Tests must reject a mismatched target, missing previous release, stale contract
generation, and an unsealed/missing failed cycle. A healthy release never emits
rollback authorization.

- [ ] **Step 4: Make autonomous cleanup automatic without weakening preflight**

For `AWAITING_CLEANUP_APPROVAL`, policy-aware status emits automatic `cleanup`.
Allow `_handle_cleanup` without `--approve` only when the current contract is
autonomous. Continue to call the unchanged ownership, clean-worktree, merge,
path, and approved-condition checks in `cleanup_run`; strict mode still requires
`--approve`.

Tests must show an autonomous clean engine-owned worktree is removed, while a
dirty worktree, unmerged candidate without its explicit condition, or foreign
path remains refused.

- [ ] **Step 5: Verify Task 3 and commit**

Run:

```bash
/tmp/agent-ship-flow-scope-authority-venv/bin/python -m unittest tests.integration.test_cli tests.integration.test_release tests.integration.test_workflow -v
```

Expected: all selected tests pass.

Commit:

```bash
git add src/ship_flow/cli.py src/ship_flow/reconcile.py src/ship_flow/release.py src/ship_flow/workflow.py tests/integration/test_cli.py tests/integration/test_release.py tests/integration/test_workflow.py
git commit -m "feat: authorize in-scope gates automatically"
```

---

### Task 4: End-to-end policy behavior and recovery coverage

**Files:**
- Modify: `tests/integration/test_cli.py`
- Modify: `tests/integration/test_reconcile.py`
- Modify: `tests/integration/test_release.py`
- Modify: `tests/skill/pressure-scenarios.md`
- Create: `tests/skill/transcripts/with_skill/SF-08-scope-expansion.json`
- Create: `tests/skill/transcripts/baseline/SF-08-scope-expansion.json`

**Interfaces:**
- Consumes: Tasks 1-3 complete CLI and engine behavior.
- Produces: acceptance-level proof for autonomous continuity, strict compatibility, scope expansion, and unknown-effect safety.

- [ ] **Step 1: Add the autonomous no-prompt acceptance flow**

Build one CLI integration test that starts in default mode and drives plan
review, `authorize plan`, development, code review, verification, `authorize
release` when configured, release, sync, and automatic cleanup. Collect every
returned `next_action` and assert no item has `kind="human"`.

The same test must assert independent actor names remain distinct and that
review, verification, release, sync, and cleanup evidence paths exist at their
respective boundaries.

- [ ] **Step 2: Add strict compatibility acceptance coverage**

Run the same pre-release path with `--mode strict`. Assert the exact human
actions remain `approve_plan`, `approve_release`, and `approve_cleanup`. Also
load a run created directly through `start_run()` with no contract and assert it
uses the strict path.

- [ ] **Step 3: Add expansion and UNKNOWN recovery pressure scenarios**

Add `SF-08` demonstrating that a controller reports progress for in-contract
work, calls `request-scope-change` before adding a deployment dashboard, and
asks exactly one scope question. The with-skill transcript must preserve the
original and proposed boundaries; the baseline transcript demonstrates the
undesired silent expansion.

Retain the existing `SF-07` UNKNOWN rule and add an assertion that autonomous
mode still returns a manual reconciliation action and never invokes release or
rollback a second time.

- [ ] **Step 4: Run acceptance tests and commit**

Run:

```bash
/tmp/agent-ship-flow-scope-authority-venv/bin/python -m unittest tests.integration.test_cli tests.integration.test_reconcile tests.integration.test_release -v
```

Expected: all selected tests pass.

Commit:

```bash
git add tests/integration/test_cli.py tests/integration/test_reconcile.py tests/integration/test_release.py tests/skill/pressure-scenarios.md tests/skill/transcripts/baseline/SF-08-scope-expansion.json tests/skill/transcripts/with_skill/SF-08-scope-expansion.json
git commit -m "test: cover scope-authorized autonomy"
```

---

### Task 5: Skill and user documentation

> **Implementation note (2026-07-16):** Task 5's controller, bilingual
> documentation, installer eight-scenario support, authentic SF-08 RED
> transcript, and original fresh pressure validation are complete. Commit
> `3014a98c08fe02554e549ce9583f5712532a178b` bound the then-current Skill tree
> to its exact receipt. This reviewer follow-up restores an explicit
> deploy-health safeguard and preserves the 5+5 SF-08 micro-test samples, so the
> prior receipt is now historical. Do not modify canonical SF-01..08
> transcripts or regenerate the receipt in this fix; fresh validation for the
> updated Skill belongs to the Task 6 whole-branch gate.

**Files:**
- Modify: `skills/ship-flow/SKILL.md`
- Modify: `skills/ship-flow/references/workflow.md`
- Modify: `skills/ship-flow/references/roles.md`
- Modify: `README.md`
- Modify: `README.zh-CN.md`
- Modify: `docs/quickstart.md`
- Modify: `docs/quickstart-zh.md`
- Modify: `docs/ship-flow-quickstart.md`
- Modify: `docs/ship-flow-quickstart-zh.md`
- Modify: `docs/agent-integration.md`
- Modify: `docs/superpowers/specs/2026-07-16-scope-authorized-autonomy-design.md`
- Modify: `docs/superpowers/plans/2026-07-16-scope-authorized-autonomy.md`
- Modify: `tests/unit/test_installer.py`

**Interfaces:**
- Consumes: final CLI names and JSON fields from Tasks 1-4.
- Produces: installed controller behavior and bilingual usage instructions matching the executable contract.

- [ ] **Step 1: Write failing installer/skill assertions**

Add assertions that installed skill content includes `autonomous`, `strict`,
`approve_scope_change`, and `scope-contract`, and that it no longer states that
release or cleanup is always a human gate. Assert the workflow reference maps
`authorize_plan`, `authorize_release`, `authorize_rollback`, `request_scope_change`,
and `approve_scope_change` to exact CLI commands.

- [ ] **Step 2: Run the installer tests and verify RED**

Run:

```bash
/tmp/agent-ship-flow-scope-authority-venv/bin/python -m unittest tests.unit.test_installer -v
```

Expected: new autonomy wording assertions fail.

- [ ] **Step 3: Rewrite controller and role guidance**

Make the skill's controller rule explicit:

```text
The initial user goal and current authorization contract are the permission
boundary. In autonomous mode, execute every returned automatic action without
asking. Ask only when next_action.action is approve_scope_change. Progress
updates are statements, not permission requests. A manual UNKNOWN state is a
safety block and must never be replayed.
```

Keep strict mode's existing gates and all role-separation rules. Update the
beginner response so `需要你确认` appears only for a scope expansion.

- [ ] **Step 4: Update bilingual README and quick starts**

Show autonomous mode first, one `--mode strict` example, the contract fields,
one scope-change example, automatic cleanup limits, and legacy strict behavior.
English and Chinese pages must carry the same guarantees and commands.

- [ ] **Step 5: Verify documentation, format, and commit**

Run:

```bash
/tmp/agent-ship-flow-scope-authority-venv/bin/python -m unittest tests.unit.test_installer -v
/tmp/agent-ship-flow-repo-entry-venv/bin/ruff format --check src/ship_flow tests scripts/install_codex_skill.py scripts/install-codex-skill.py
/tmp/agent-ship-flow-repo-entry-venv/bin/ruff check src/ship_flow tests scripts/install_codex_skill.py scripts/install-codex-skill.py
git diff --check
```

Expected: installer tests and both Ruff checks pass with no whitespace errors.

Commit:

```bash
git add skills/ship-flow README.md README.zh-CN.md docs tests/unit/test_installer.py
git commit -m "docs: explain scope-authorized autonomy"
```

---

### Task 6: Whole-branch verification and GitHub branch publication

**Files:**
- Verify all changed files; create no production file solely for this task.

**Interfaces:**
- Consumes: completed Tasks 1-5.
- Produces: a reviewed, fully tested `feat/scope-authority` remote branch.

- [ ] **Step 1: Run the complete local validation surface**

Run:

```bash
/tmp/agent-ship-flow-scope-authority-venv/bin/python -m unittest discover -s tests/unit -q
/tmp/agent-ship-flow-scope-authority-venv/bin/python -m unittest discover -s tests/integration -q
/tmp/agent-ship-flow-repo-entry-venv/bin/ruff format --check src/ship_flow tests scripts/install_codex_skill.py scripts/install-codex-skill.py
/tmp/agent-ship-flow-repo-entry-venv/bin/ruff check src/ship_flow tests scripts/install_codex_skill.py scripts/install-codex-skill.py
git diff origin/main...HEAD --check
```

Expected: zero test failures, zero Ruff errors, and zero whitespace errors.

- [ ] **Step 2: Perform independent whole-branch review**

Review `origin/main...HEAD` for authorization bypasses, stale-evidence reuse,
unsafe cleanup, receipt compatibility, recovery gaps, documentation mismatch,
and untested user-visible actions. Resolve every Critical or Important finding
and rerun its covering tests.

- [ ] **Step 3: Push the completed branch and verify its remote identity**

Run:

```bash
git push origin feat/scope-authority
git rev-parse HEAD
git ls-remote origin refs/heads/feat/scope-authority
```

Expected: local HEAD equals the remote branch SHA. Do not merge to `main` and do
not create a pull request unless the user separately requests either action.
