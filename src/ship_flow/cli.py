from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .authorization import (
    AuthorizationContract,
    AuthorizationStore,
    ExecutionMode,
)
from .gitops import (
    CandidateSafetyError,
    CleanupRefusedError,
    GitOperationError,
    GitRepository,
    WorktreeOwnership,
    commit_candidate,
)
from .manifest import (
    Manifest,
    detect_manifest,
    load_manifest,
    manifest_digest,
    write_manifest,
)
from .model import LEGAL_TRANSITIONS, Phase, RunState
from .reconcile import (
    EvidenceInventory,
    EvidenceStatus,
    ReconciledRun,
    ReconciliationError,
    ReconciliationRecoveryError,
    Reconciler,
    _load_safe_manifest,
    next_action,
    record_plan_approval,
)
from .release import (
    OperationAdjudication,
    OperationRecord,
    PendingOperationDecision,
    ReleaseEngine,
    ReleaseError,
    ReleaseRecoveryError,
)
from .review import (
    ReviewError,
    ReviewRecoveryError,
    ReviewRole,
    issue_handoff,
    record_code_review,
    record_plan_review,
    resume_review_publication,
)
from .store import (
    InvalidTransitionError,
    StateCorruptionError,
    StateNotFoundError,
    StateStore,
    StateStoreError,
    StaleRevisionError,
)
from .subject import EvidenceSubject
from .sync import SyncError, SyncRecoveryError, SyncReportDraft, record_sync_report
from .verify import (
    VerificationError,
    VerificationRecoveryError,
    Verifier,
)
from .workflow import (
    WorkflowError,
    WorkflowRecoveryError,
    _observe_subject_locked,
    cleanup_run,
    discover_repository,
    load_run,
    observe_subject,
    run_directory,
    set_plan,
    start_run,
)


@dataclass(frozen=True)
class CliFailure(RuntimeError):
    code: str
    message: str
    exit_code: int

    def __str__(self) -> str:
        return self.message


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliFailure("usage_error", "命令参数不完整或无效。", 2)


def _utc_after(minutes: int = 15) -> str:
    return (
        (datetime.now(timezone.utc) + timedelta(minutes=minutes))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _state_payload(state: RunState) -> dict[str, object]:
    return {
        "run_id": state.run_id,
        "phase": state.phase.value,
        "revision": state.revision,
        "updated_at": state.updated_at,
    }


def _next_action_payload(run: RunState | ReconciledRun) -> dict[str, str]:
    action = next_action(run)
    return {
        "phase": action.phase.value,
        "kind": action.kind,
        "action": action.action,
    }


def _inventory_payload(inventory: EvidenceInventory) -> dict[str, str]:
    return {
        "plan_approval": inventory.plan_approval.value,
        "code_review": inventory.code_review.value,
        "verification": inventory.verification.value,
        "release_or_external": inventory.release_or_external.value,
        "sync": inventory.sync.value,
    }


def _approval_aware_next_action(run: ReconciledRun) -> dict[str, str]:
    action = _next_action_payload(run)
    gate_actions = {
        Phase.AWAITING_RELEASE_APPROVAL: ("approve_release", "release", "release"),
        Phase.ROLLBACK_PENDING: ("approve_rollback", "rollback", "rollback"),
    }
    if run.ownership is None or run.manifest is None or run.subject is None:
        if run.state.phase in {
            Phase.AWAITING_RELEASE_APPROVAL,
            Phase.RELEASING,
            Phase.POST_RELEASE_VERIFYING,
            Phase.ROLLBACK_PENDING,
            Phase.ROLLING_BACK,
            Phase.ROLLBACK_VERIFYING,
        }:
            raise ReleaseRecoveryError("current external context is incomplete")
        return action
    engine = _release_engine(run, run.ownership)
    gate_action = gate_actions.get(run.state.phase)
    if gate_action is not None:
        context = engine.inspect_active_external_context(phase=run.state.phase)
        if context is not None:
            recovered = {
                "phase": run.state.phase.value,
                "kind": "automatic",
                "action": gate_action[2],
                "cycle_id": context.cycle_id,
                "approval_id": context.approval_id,
                "target": context.target,
            }
            if context.mode == "rollback":
                assert context.failed_release_id is not None
                assert context.previous_release is not None
                recovered.update(
                    {
                        "failed_release_id": context.failed_release_id,
                        "previous_release": context.previous_release,
                    }
                )
            return recovered
        approval = engine.inspect_current_unconsumed_approval(gate=gate_action[1])
        if approval is None:
            return {
                "phase": run.state.phase.value,
                "kind": "human",
                "action": gate_action[0],
            }
        recovered = {
            "phase": run.state.phase.value,
            "kind": "automatic",
            "action": gate_action[2],
            "approval_id": approval.approval_id,
            "target": approval.target,
        }
        if approval.gate == "rollback":
            assert approval.failed_release_id is not None
            assert approval.previous_release is not None
            recovered.update(
                {
                    "failed_release_id": approval.failed_release_id,
                    "previous_release": approval.previous_release,
                }
            )
        return recovered
    external_actions = {
        Phase.RELEASING: "release",
        Phase.POST_RELEASE_VERIFYING: "release",
        Phase.ROLLING_BACK: "rollback",
        Phase.ROLLBACK_VERIFYING: "rollback",
    }
    command = external_actions.get(run.state.phase)
    if command is None:
        return action
    context = engine.inspect_active_external_context(phase=run.state.phase)
    if context is None:
        raise ReleaseRecoveryError("active external context is missing")
    recovered = {
        "phase": run.state.phase.value,
        "kind": "automatic",
        "action": command,
        "cycle_id": context.cycle_id,
        "approval_id": context.approval_id,
        "target": context.target,
    }
    if context.mode == "rollback":
        assert context.failed_release_id is not None
        assert context.previous_release is not None
        recovered.update(
            {
                "failed_release_id": context.failed_release_id,
                "previous_release": context.previous_release,
            }
        )
    return recovered


def _authorization_payload(
    contract: AuthorizationContract | None,
) -> dict[str, object]:
    return {
        "mode": contract.mode.value if contract else "strict",
        "source": "contract" if contract else "legacy_default",
        "generation": contract.generation if contract else None,
        "digest": contract.digest() if contract else None,
    }


def _current_authorization(store: StateStore) -> AuthorizationContract | None:
    path = store.run_directory / "authorization"
    if not os.path.lexists(path):
        return None
    return AuthorizationStore(store).current()


def _policy_aware_state_action(
    store: StateStore,
    state: RunState,
) -> dict[str, object]:
    if type(store) is not StateStore:
        return _next_action_payload(state)
    authorizations = AuthorizationStore(store)
    return _policy_aware_next_action(
        state,
        authorizations=authorizations,
        contract=_current_authorization(store),
    )


def _policy_aware_pending_release_action(
    repository: GitRepository,
    run_id: str,
    store: StateStore,
    state: RunState,
) -> dict[str, object]:
    authorizations = AuthorizationStore(store)
    contract = _current_authorization(store)
    if contract is not None and contract.mode is ExecutionMode.AUTONOMOUS:
        run = Reconciler(repository).reconcile(run_id)
        return _policy_aware_next_action(
            run,
            authorizations=authorizations,
            contract=contract,
            recover_approval=True,
        )
    return _policy_aware_next_action(
        state,
        authorizations=authorizations,
        contract=contract,
    )


def _policy_aware_next_action(
    run: RunState | ReconciledRun,
    *,
    authorizations: AuthorizationStore,
    contract: AuthorizationContract | None,
    recover_approval: bool = False,
) -> dict[str, object]:
    action: dict[str, object] = (
        _approval_aware_next_action(run)
        if recover_approval and isinstance(run, ReconciledRun)
        else _next_action_payload(run)
    )
    state = run.state if isinstance(run, ReconciledRun) else run
    if state.phase is Phase.AWAITING_SCOPE_APPROVAL:
        pending = authorizations.pending()
        if pending is None:
            raise StateCorruptionError("scope approval is missing its request")
        return {
            "phase": state.phase.value,
            "kind": "human",
            "action": "approve_scope_change",
            "request_id": pending.request_id,
        }
    if contract is None:
        return action
    if state.phase is Phase.BLOCKED:
        return action
    manifest = run.manifest if isinstance(run, ReconciledRun) else None
    if (
        manifest is not None
        and manifest_digest(manifest) != contract.manifest_sha256
        and Phase.AWAITING_SCOPE_APPROVAL in LEGAL_TRANSITIONS[state.phase]
    ):
        return {
            "phase": state.phase.value,
            "kind": "automatic",
            "action": "request_scope_change",
            "reason": "manifest_drift",
            "contract_digest": contract.digest(),
            "proposed_manifest_sha256": manifest_digest(manifest),
        }
    if contract.mode is ExecutionMode.STRICT:
        return action
    automatic_gates = {
        "approve_plan": "authorize_plan",
        "approve_release": "authorize_release",
        "approve_rollback": "authorize_rollback",
        "approve_cleanup": "cleanup",
    }
    automatic = automatic_gates.get(str(action.get("action")))
    if action.get("kind") == "human" and automatic is not None:
        return {
            "phase": state.phase.value,
            "kind": "automatic",
            "action": automatic,
            "authorization_source": "contract",
        }
    return action


def _run_payload(
    run: ReconciledRun,
    *,
    store: StateStore | None = None,
    recover_approval: bool = False,
) -> dict[str, object]:
    if store is None and isinstance(run.ownership, WorktreeOwnership):
        store = StateStore(run.ownership.record_path.parent)
    authorizations = AuthorizationStore(store) if store is not None else None
    contract = _current_authorization(store) if store is not None else None
    payload: dict[str, object] = {
        "state": _state_payload(run.state),
        "reason": run.reason,
        "next_action": (
            _policy_aware_next_action(
                run,
                authorizations=authorizations,
                contract=contract,
                recover_approval=recover_approval,
            )
            if authorizations is not None
            else (
                _approval_aware_next_action(run)
                if recover_approval
                else _next_action_payload(run)
            )
        ),
        "evidence_status": _inventory_payload(run.evidence),
        "authorization": _authorization_payload(contract),
    }
    if authorizations is not None and contract is not None:
        pending = authorizations.pending()
        if pending is not None:
            payload["scope_change"] = pending.to_dict()
    if run.ownership is not None:
        payload["worktree"] = str(run.ownership.worktree_path)
        payload["branch"] = run.ownership.branch
    if run.subject is not None:
        payload["subject"] = {
            "digest": run.subject.digest(),
            "candidate_oid": run.subject.candidate_oid,
            "tree_oid": run.subject.tree_oid,
        }
    return payload


def _success(command: str, **payload: object) -> dict[str, object]:
    return {"ok": True, "command": command, **payload}


def _repository(path: str) -> GitRepository:
    return discover_repository(path)


def _run_directory(repository: GitRepository, run_id: str) -> Path:
    return run_directory(repository, run_id)


def _load_run(
    repository: GitRepository, run_id: str
) -> tuple[WorktreeOwnership, StateStore]:
    run = load_run(repository, run_id)
    return run.ownership, run.store


def _standard_variables(
    ownership: WorktreeOwnership, manifest: Manifest
) -> dict[str, str]:
    return {
        "repo": str(ownership.primary_checkout),
        "worktree": str(ownership.worktree_path),
        "branch": ownership.branch,
        "base_branch": manifest.base_branch,
        "remote": manifest.remote,
    }


def _require_expected_revision(
    store: StateStore,
    expected_revision: int,
) -> RunState:
    state = store.load()
    if state.revision != expected_revision:
        raise CliFailure("stale_revision", "状态已变化，请先重新查看状态。", 4)
    return state


def _require_phase(state: RunState, allowed: Sequence[Phase]) -> None:
    if state.phase not in allowed:
        raise CliFailure("phase_conflict", "当前状态不允许执行这个动作。", 4)


def _preflight(
    repository: GitRepository,
    run_id: str,
    expected_revision: int,
    allowed: Sequence[Phase],
) -> tuple[ReconciledRun, WorktreeOwnership, StateStore]:
    ownership, store = _load_run(repository, run_id)
    _require_expected_revision(store, expected_revision)
    run = Reconciler(repository).reconcile(run_id)
    if run.state.revision != expected_revision:
        raise CliFailure("stale_revision", "状态已自动校正，请重新确认下一步。", 4)
    _require_phase(run.state, allowed)
    if run.ownership is None:
        raise CliFailure("evidence_missing", "运行工作区证据缺失。", 6)
    return run, ownership, store


def _subject_for(run: ReconciledRun) -> EvidenceSubject:
    if run.subject is None:
        raise CliFailure("evidence_missing", "当前证据指纹尚未生成。", 6)
    return run.subject


def _workflow_start(
    repository: GitRepository,
    *,
    run_id: str,
    branch: str,
    worktree_path: Path,
) -> tuple[WorktreeOwnership, StateStore, RunState]:
    run = start_run(
        repository,
        run_id=run_id,
        branch=branch,
        worktree_path=worktree_path,
    )
    return run.ownership, run.store, run.state


def _workflow_set_plan(
    repository: GitRepository,
    run_id: str,
    contents: bytes,
    *,
    expected_revision: int,
) -> tuple[RunState, EvidenceSubject]:
    run = set_plan(
        repository,
        run_id,
        contents.decode("utf-8"),
        expected_revision=expected_revision,
    )
    if run.subject is None:
        raise CliFailure("evidence_invalid", "计划证据生成失败。", 6)
    return run.state, run.subject


def _findings(raw: str) -> tuple[dict[str, str], ...]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CliFailure("invalid_input", "Review 发现项不是有效 JSON。", 5) from error
    if not isinstance(payload, list) or any(
        not isinstance(item, dict) for item in payload
    ):
        raise CliFailure("invalid_input", "Review 发现项必须是 JSON 数组。", 5)
    if any(
        any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in item.items()
        )
        for item in payload
    ):
        raise CliFailure("invalid_input", "Review 发现项字段必须是字符串。", 5)
    return tuple(dict(item) for item in payload)


def _operation_payload(
    record: OperationRecord,
    *,
    adjudicated_applied: bool = False,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "mode": record.mode,
        "index": record.index,
        "attempt": record.attempt,
        "status": record.status.value,
        "target": record.target,
        "command_sha256": record.command_sha256,
        "cycle_id": record.cycle_id,
    }
    if adjudicated_applied and record.status.value == "UNKNOWN":
        payload["logical_status"] = "adjudicated_applied"
    return payload


def _release_engine(run: ReconciledRun, ownership: WorktreeOwnership) -> ReleaseEngine:
    if run.manifest is None:
        raise CliFailure("evidence_missing", "已确认的流程配置缺失。", 6)
    return ReleaseEngine(
        repo=ownership.worktree_path,
        run_directory=ownership.record_path.parent,
        manifest=run.manifest,
        current_subject=_subject_for(run),
        variables=_standard_variables(ownership, run.manifest),
    )


def _live_release_context(
    repository: GitRepository,
    run_id: str,
) -> tuple[ReleaseEngine, StateStore, RunState]:
    workflow_run = load_run(repository, run_id)
    manifest = load_manifest(
        workflow_run.ownership.worktree_path / ".ship" / "manifest.toml"
    )
    subject = observe_subject(repository, run_id)
    engine = ReleaseEngine(
        repo=workflow_run.ownership.worktree_path,
        run_directory=workflow_run.run_directory,
        manifest=manifest,
        current_subject=subject,
        variables=_standard_variables(workflow_run.ownership, manifest),
    )
    return engine, workflow_run.store, workflow_run.state


def _decision_payload(decision: PendingOperationDecision) -> dict[str, object]:
    return {
        "run_id": decision.run_id,
        "cycle_id": decision.cycle_id,
        "mode": decision.mode,
        "index": decision.index,
        "attempt": decision.attempt,
        "operation_name": decision.operation_name,
        "target": decision.target,
        "argv": list(decision.argv),
        "reason": decision.reason,
        "unknown_receipt_sha256": decision.unknown_receipt_sha256,
        "operation_start_marker_id": decision.operation_start_marker_id,
        "blocked_revision": decision.blocked_revision,
        "confirmation_token": decision.confirmation_token,
    }


def _adjudication_payload(adjudication: OperationAdjudication) -> dict[str, object]:
    return {
        "adjudication_id": adjudication.adjudication_id,
        "mode": adjudication.mode,
        "index": adjudication.index,
        "attempt": adjudication.attempt,
        "target": adjudication.target,
        "command_sha256": adjudication.command_sha256,
        "unknown_receipt_sha256": adjudication.unknown_receipt_sha256,
        "actor": adjudication.actor,
        "outcome": adjudication.outcome,
        "reason": adjudication.reason,
        "recorded_at": adjudication.recorded_at,
    }


def _handle_init(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    path = repository.primary_checkout / ".ship" / "manifest.toml"
    if path.parent.is_symlink() or path.is_symlink():
        raise CliFailure("invalid_input", "流程配置路径不能是符号链接。", 5)
    detected = detect_manifest(repository.primary_checkout)
    if path.exists():
        confirmed = load_manifest(path)
        return _success(
            "init",
            accepted=True,
            created=False,
            project_type="existing",
            evidence={"manifest": str(path)},
            manifest_sha256=manifest_digest(confirmed),
        )
    mode = ExecutionMode(args.mode)
    if mode is ExecutionMode.STRICT and not args.accept_detected:
        return _success(
            "init",
            accepted=False,
            created=False,
            next_action={
                "kind": "human",
                "action": "confirm_detected_manifest",
            },
            detected={
                "project_name": detected.project_name,
                "base_branch": detected.base_branch,
                "release_required": detected.release_required,
            },
        )
    write_manifest(path, detected)
    return _success(
        "init",
        accepted=True,
        created=True,
        next_action={
            "kind": "automatic" if mode is ExecutionMode.AUTONOMOUS else "human",
            "action": "commit_manifest",
            "manifest": str(path),
        },
        evidence={"manifest": str(path)},
        manifest_sha256=manifest_digest(detected),
    )


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (slug or "change")[:32]


def _handle_start(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    run_id = args.run_id or f"run-{secrets.token_hex(6)}"
    short = re.sub(r"[^A-Za-z0-9]", "", run_id)[-8:] or secrets.token_hex(4)
    branch = args.branch or f"ship/{_safe_slug(args.goal)}-{short.lower()}"
    if args.worktree:
        worktree = Path(args.worktree).expanduser().absolute()
    else:
        worktree_root = repository.primary_checkout.parent / ".ship-worktrees"
        if os.path.lexists(worktree_root):
            if worktree_root.is_symlink() or not worktree_root.is_dir():
                raise CliFailure(
                    "invalid_input",
                    "默认 worktree 根目录不是安全的真实目录。",
                    5,
                )
        else:
            worktree_root.mkdir(mode=0o700)
        worktree = worktree_root / f"{repository.primary_checkout.name}-{short.lower()}"
    ownership, store, state = _workflow_start(
        repository,
        run_id=run_id,
        branch=branch,
        worktree_path=worktree,
    )
    manifest = _load_safe_manifest(ownership.worktree_path)
    authorizations = AuthorizationStore(store)
    existing_contract = _current_authorization(store)
    if existing_contract is not None and existing_contract.generation != 1:
        raise CliFailure(
            "phase_conflict",
            "运行授权已扩展，不能作为初始启动重试。",
            4,
        )
    initial_state_revision = (
        existing_contract.state_revision
        if existing_contract is not None
        else state.revision
    )
    contract = authorizations.create_initial(
        mode=ExecutionMode(args.mode),
        goal=args.goal,
        repository=repository.primary_checkout.resolve(),
        worktree=ownership.worktree_path.resolve(),
        branch=ownership.branch,
        manifest_sha256=manifest_digest(manifest),
        release_target=args.release_target,
        previous_release=args.previous_release,
        state_revision=initial_state_revision,
    )
    return _success(
        "start",
        state=_state_payload(state),
        worktree=str(ownership.worktree_path),
        branch=ownership.branch,
        next_action=_policy_aware_next_action(
            state,
            authorizations=authorizations,
            contract=contract,
        ),
        authorization={
            "mode": contract.mode.value,
            "source": "contract",
            "generation": contract.generation,
            "digest": contract.digest(),
        },
        evidence={
            "state": str(store.state_path),
            "events": str(store.events_path),
            "ownership": str(ownership.record_path),
        },
    )


def _handle_status(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    store = (
        StateStore(_run_directory(repository, args.run_id))
        if isinstance(repository, GitRepository)
        else None
    )
    contract = _current_authorization(store) if store is not None else None
    if contract is not None and store is not None:
        state = store.load()
        try:
            manifest = _load_safe_manifest(Path(contract.worktree))
        except ReconciliationRecoveryError:
            manifest = None
        if (
            manifest is not None
            and manifest_digest(manifest) != contract.manifest_sha256
            and Phase.AWAITING_SCOPE_APPROVAL in LEGAL_TRANSITIONS[state.phase]
        ):
            stale = EvidenceInventory(
                plan_approval=EvidenceStatus.STALE,
                code_review=EvidenceStatus.STALE,
                verification=EvidenceStatus.STALE,
                release_or_external=EvidenceStatus.STALE,
                sync=EvidenceStatus.STALE,
            )
            drift = ReconciledRun(
                state=state,
                ownership=None,
                manifest=manifest,
                subject=None,
                plan_approval=None,
                dirty=None,
                reason="manifest-drift-requires-scope-change",
                evidence=stale,
            )
            payload = _run_payload(drift, store=store, recover_approval=False)
            payload["worktree"] = contract.worktree
            payload["branch"] = contract.branch
            return _success("status", **payload)
    run = Reconciler(repository).reconcile(args.run_id)
    return _success(
        "status",
        **_run_payload(run, store=store, recover_approval=True),
    )


def _handle_request_scope_change(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    ownership, store = _load_run(repository, args.run_id)
    _require_expected_revision(store, args.expected_revision)
    authorizations = AuthorizationStore(store)
    request = authorizations.request_change(
        reason=args.reason,
        summary=args.summary,
        proposed_goal=args.goal,
        proposed_manifest_sha256=args.manifest_sha256,
        proposed_release_target=args.release_target,
        proposed_previous_release=args.previous_release,
        expected_revision=args.expected_revision,
    )
    state = store.load()
    contract = authorizations.current()
    if contract is None:
        raise StateCorruptionError("scope change lost its authorization contract")
    return _success(
        "request-scope-change",
        state=_state_payload(state),
        worktree=str(ownership.worktree_path),
        branch=ownership.branch,
        authorization=_authorization_payload(contract),
        scope_change=request.to_dict(),
        next_action=_policy_aware_next_action(
            state,
            authorizations=authorizations,
            contract=contract,
        ),
    )


def _handle_resolve_scope_change(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    ownership, store = _load_run(repository, args.run_id)
    _require_expected_revision(store, args.expected_revision)
    authorizations = AuthorizationStore(store)
    contract = authorizations.resolve_change(
        decision=args.decision,
        actor=args.actor,
        expected_revision=args.expected_revision,
    )
    state = store.load()
    resolution = authorizations.latest_resolution()
    if resolution is None:
        raise StateCorruptionError("scope resolution evidence is missing")
    return _success(
        "resolve-scope-change",
        state=_state_payload(state),
        worktree=str(ownership.worktree_path),
        branch=ownership.branch,
        authorization=_authorization_payload(contract),
        scope_change_resolution=resolution.to_dict(),
        next_action=_policy_aware_next_action(
            state,
            authorizations=authorizations,
            contract=contract,
        ),
    )


def _handle_set_plan(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    source = Path(args.file).expanduser()
    try:
        contents = source.read_bytes()
    except OSError as error:
        raise CliFailure("invalid_input", "无法读取计划文件。", 5) from error
    if not contents or len(contents) > 1024 * 1024:
        raise CliFailure("invalid_input", "计划文件必须为 1 MiB 以内的非空文件。", 5)
    try:
        contents.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CliFailure("invalid_input", "计划文件必须使用 UTF-8。", 5) from error
    state, subject = _workflow_set_plan(
        repository,
        args.run_id,
        contents,
        expected_revision=args.expected_revision,
    )
    run_directory = _run_directory(repository, args.run_id)
    store = StateStore(run_directory)
    return _success(
        "set-plan",
        state=_state_payload(state),
        next_action=_policy_aware_state_action(store, state),
        subject={"digest": subject.digest()},
        evidence={"plan": str(run_directory / "plan.md")},
    )


def _record_review_command(
    args: argparse.Namespace, *, review_type: str
) -> dict[str, object]:
    repository = _repository(args.repo)
    expected = Phase.PLAN_REVIEW if review_type == "plan" else Phase.CODE_REVIEW
    run, _, store = _preflight(
        repository,
        args.run_id,
        args.expected_revision,
        (expected,),
    )
    subject = _subject_for(run)
    if args.source_actor == args.reviewer:
        raise CliFailure("role_conflict", "Review 必须由不同的角色完成。", 4)
    findings = _findings(args.findings_json)
    role = ReviewRole.PLAN_CRITIC if review_type == "plan" else ReviewRole.REVIEWER
    nonce = issue_handoff(
        store,
        subject=subject,
        source_actor=args.source_actor,
        role=role,
    )
    recorder: Callable[..., object] = (
        record_plan_review if review_type == "plan" else record_code_review
    )
    recorder(
        store,
        current_subject=subject,
        reviewer_actor=args.reviewer,
        handoff_nonce=nonce,
        verdict=args.verdict,
        findings=findings,
    )
    state = store.load()
    command = "record-plan-review" if review_type == "plan" else "record-review"
    return _success(
        command,
        state=_state_payload(state),
        next_action=_policy_aware_state_action(store, state),
        verdict=args.verdict,
        evidence={
            "review": str(
                store.run_directory / "reviews" / f"{review_type}-review.json"
            )
        },
    )


def _handle_approve(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    if args.gate == "plan":
        run, _, store = _preflight(
            repository,
            args.run_id,
            args.expected_revision,
            (Phase.AWAITING_PLAN_APPROVAL,),
        )
        record = record_plan_approval(
            store,
            current_subject=_subject_for(run),
            approver_actor=args.actor,
        )
        state = store.load()
        return _success(
            "approve",
            gate="plan",
            approval_id=record.approval_id,
            state=_state_payload(state),
            next_action=_policy_aware_state_action(store, state),
            evidence={
                "approval": str(
                    store.run_directory
                    / "approvals"
                    / "plan"
                    / f"{record.approval_id}.json"
                )
            },
        )
    allowed = (
        (Phase.AWAITING_RELEASE_APPROVAL,)
        if args.gate == "release"
        else (Phase.ROLLBACK_PENDING, Phase.AWAITING_RELEASE_APPROVAL)
    )
    run, ownership, store = _preflight(
        repository,
        args.run_id,
        args.expected_revision,
        allowed,
    )
    if not args.target:
        raise CliFailure("invalid_input", "该审批必须指定目标。", 5)
    engine = _release_engine(run, ownership)
    record = engine.record_approval(
        gate=args.gate,
        target=args.target,
        approver_actor=args.actor,
        expires_at=args.expires_at or _utc_after(),
        failed_release_id=args.failed_release_id,
        previous_release=args.previous_release,
        allow_default_expiry_recovery=args.expires_at is None,
    )
    state = store.load()
    approval = {
        "gate": record.gate,
        "approval_id": record.approval_id,
        "target": record.target,
    }
    if record.gate == "rollback":
        approval.update(
            {
                "failed_release_id": record.failed_release_id,
                "previous_release": record.previous_release,
            }
        )
    if args.gate == "release":
        next_action = {
            "phase": state.phase.value,
            "kind": "automatic",
            "action": "release",
            "approval_id": record.approval_id,
            "target": record.target,
        }
    elif state.phase is Phase.ROLLBACK_PENDING:
        next_action = {
            "phase": state.phase.value,
            "kind": "automatic",
            "action": "rollback",
            "approval_id": record.approval_id,
            "target": record.target,
        }
    else:
        next_action = _policy_aware_pending_release_action(
            repository,
            args.run_id,
            store,
            state,
        )
    return _success(
        "approve",
        gate=args.gate,
        approval_id=record.approval_id,
        target=record.target,
        approval=approval,
        state=_state_payload(state),
        next_action=next_action,
        evidence={
            "approval": str(
                store.run_directory / "approvals" / f"{record.approval_id}.json"
            )
        },
    )


def _handle_development_ready(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    _, ownership, store = _preflight(
        repository,
        args.run_id,
        args.expected_revision,
        (Phase.DEVELOPING,),
    )
    identity = commit_candidate(
        ownership,
        message=args.message,
        approved_paths=tuple(args.approved_path),
    )
    run = Reconciler(repository).reconcile(args.run_id)
    if run.state.phase is not Phase.CODE_REVIEW:
        raise CliFailure("evidence_invalid", "候选提交尚未进入独立 Review。", 6)
    return _success(
        "development-ready",
        **_run_payload(run),
        candidate={"commit_oid": identity.commit_oid, "tree_oid": identity.tree_oid},
        evidence={"ownership": str(ownership.record_path)},
    )


def _handle_verify(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    run, ownership, store = _preflight(
        repository,
        args.run_id,
        args.expected_revision,
        (Phase.VERIFYING,),
    )
    subject = _subject_for(run)
    if run.manifest is None:
        raise CliFailure("evidence_missing", "已确认的流程配置缺失。", 6)
    if args.source_actor == args.verifier:
        raise CliFailure("role_conflict", "Verification 必须由不同的角色完成。", 4)
    nonce = issue_handoff(
        store,
        subject=subject,
        source_actor=args.source_actor,
        role=ReviewRole.VERIFIER,
    )
    sensitive_values: list[str] = []
    for name in args.sensitive_value_env:
        value = os.environ.get(name)
        if value:
            sensitive_values.append(value)
    report = Verifier(
        repo=ownership.worktree_path,
        run_directory=store.run_directory,
        manifest=run.manifest,
        current_subject=subject,
        variables=_standard_variables(ownership, run.manifest),
    ).verify(
        args.run_id,
        verifier_actor=args.verifier,
        handoff_nonce=nonce,
        sensitive_values=tuple(sensitive_values),
    )
    state = store.load()
    return _success(
        "verify",
        state=_state_payload(state),
        next_action=_policy_aware_state_action(store, state),
        evidence={
            "verification": str(
                store.run_directory
                / "verifications"
                / f"verification-{report.round:04d}.json"
            ),
            "logs": str(store.run_directory / "logs"),
        },
    )


def _handle_release(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    if args.approval_id is None:
        _, gate_store = _load_run(repository, args.run_id)
        gate_state = _require_expected_revision(
            gate_store,
            args.expected_revision,
        )
        if gate_state.phase is Phase.AWAITING_RELEASE_APPROVAL:
            raise CliFailure(
                "approval_required",
                "请先单独记录正式发布审批，再提交 approval-id。",
                4,
            )
    run, ownership, store = _preflight(
        repository,
        args.run_id,
        args.expected_revision,
        (
            Phase.AWAITING_RELEASE_APPROVAL,
            Phase.RELEASING,
            Phase.POST_RELEASE_VERIFYING,
            Phase.SYNCING,
        ),
    )
    engine = _release_engine(run, ownership)
    approval_id = args.approval_id
    resumed = False
    if approval_id is None:
        records = engine.resume_external_cycle(target=args.target)
        resumed = True
    else:
        records = engine.release(
            target=args.target,
            approval_id=approval_id,
            rollback_approval_id=args.rollback_approval_id,
            previous_release=args.previous_release,
        )
    state = store.load()
    return _success(
        "release",
        approval_id=approval_id,
        resumed=resumed,
        state=_state_payload(state),
        next_action=_policy_aware_state_action(store, state),
        operations=[
            _operation_payload(record, adjudicated_applied=resumed)
            for record in records
        ],
        evidence={"release": str(store.run_directory / "release-cycles")},
    )


def _handle_reconcile_operation(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    engine, store, state = _live_release_context(repository, args.run_id)
    if args.outcome is None:
        if state.phase is not Phase.BLOCKED or state.revision != args.expected_revision:
            raise CliFailure("phase_conflict", "当前没有待人工判断的未知动作。", 4)
        decision = engine.inspect_unknown_operation(target=args.target)
        return _success(
            "reconcile-operation",
            state=_state_payload(state),
            next_action={
                "phase": state.phase.value,
                "kind": "human",
                "action": "confirm_external_operation_outcome",
            },
            decision=_decision_payload(decision),
            evidence={"release": str(store.run_directory / "release-cycles")},
        )
    if not args.unknown_receipt_sha256 or not args.confirmation_token or not args.actor:
        raise CliFailure(
            "confirmation_required",
            "请原样回传未知回执、确认令牌和判断人。",
            4,
        )
    valid_retry_state = (
        state.phase is Phase.BLOCKED and state.revision == args.expected_revision
    ) or (
        state.phase in {Phase.RELEASING, Phase.ROLLING_BACK}
        and state.revision == args.expected_revision + 1
    )
    if not valid_retry_state:
        raise CliFailure("stale_revision", "未知动作状态已变化，请重新查看。", 4)
    adjudication = engine.record_operation_outcome(
        target=args.target,
        unknown_receipt_sha256=args.unknown_receipt_sha256,
        confirmation_token=args.confirmation_token,
        expected_revision=args.expected_revision,
        actor=args.actor,
        outcome=args.outcome,
    )
    state = store.load()
    return _success(
        "reconcile-operation",
        state=_state_payload(state),
        next_action=_policy_aware_state_action(store, state),
        adjudication=_adjudication_payload(adjudication),
        evidence={"release": str(store.run_directory / "release-cycles")},
    )


def _handle_rollback(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    if args.approval_id is None:
        _, gate_store = _load_run(repository, args.run_id)
        gate_state = _require_expected_revision(
            gate_store,
            args.expected_revision,
        )
        if gate_state.phase is Phase.ROLLBACK_PENDING:
            raise CliFailure(
                "approval_required",
                "请先单独记录回滚审批，再提交 approval-id。",
                4,
            )
    run, ownership, store = _preflight(
        repository,
        args.run_id,
        args.expected_revision,
        (Phase.ROLLBACK_PENDING, Phase.ROLLING_BACK, Phase.ROLLBACK_VERIFYING),
    )
    engine = _release_engine(run, ownership)
    if run.state.phase is Phase.ROLLBACK_VERIFYING:
        if not args.previous_release:
            raise CliFailure(
                "invalid_input",
                "回滚验证必须指定回滚前版本。",
                5,
            )
        healthy = engine.verify_rollback(
            target=args.target,
            previous_release=args.previous_release,
        )
        state = store.load()
        return _success(
            "rollback",
            verified=True,
            healthy=healthy,
            state=_state_payload(state),
            next_action=_policy_aware_state_action(store, state),
            operations=[],
            evidence={"release": str(store.run_directory / "release-cycles")},
        )
    approval_id = args.approval_id
    resumed = False
    if approval_id is None:
        records = engine.resume_external_cycle(target=args.target)
        resumed = True
    else:
        records = engine.rollback(
            target=args.target,
            approval_id=approval_id,
            failed_release_id=args.failed_release_id,
            previous_release=args.previous_release,
        )
    state = store.load()
    return _success(
        "rollback",
        approval_id=approval_id,
        resumed=resumed,
        state=_state_payload(state),
        next_action=_policy_aware_state_action(store, state),
        operations=[
            _operation_payload(record, adjudicated_applied=resumed)
            for record in records
        ],
        evidence={"release": str(store.run_directory / "release-cycles")},
    )


def _handle_record_sync(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    run, ownership, store = _preflight(
        repository,
        args.run_id,
        args.expected_revision,
        (Phase.SYNCING,),
    )
    try:
        if args.report_json is not None:
            raw = json.loads(args.report_json)
        else:
            raw = json.loads(Path(args.report).expanduser().read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CliFailure("invalid_input", "同步报告不是有效 JSON。", 5) from error
    draft = SyncReportDraft.from_dict(raw)
    subject = _subject_for(run)

    def current_subject() -> EvidenceSubject:
        return _observe_subject_locked(repository, args.run_id)

    report = record_sync_report(
        store,
        draft,
        subject,
        worktree=ownership.worktree_path,
        current_subject=current_subject,
    )
    state = store.load()
    return _success(
        "record-sync",
        state=_state_payload(state),
        next_action=_policy_aware_state_action(store, state),
        subject={"digest": report.subject_digest},
        evidence={"sync": str(store.run_directory / "sync-report.json")},
    )


def _handle_cleanup(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    run, ownership, store = _preflight(
        repository,
        args.run_id,
        args.expected_revision,
        (Phase.AWAITING_CLEANUP_APPROVAL,),
    )
    if not args.approve:
        raise CliFailure("confirmation_required", "清理需要人工确认。", 4)
    completed = cleanup_run(
        repository,
        args.run_id,
        expected_revision=args.expected_revision,
        approved=True,
        merged_into=args.merged_into,
        approved_conditions=tuple(args.approved_condition),
    )
    return _success(
        "cleanup",
        state=_state_payload(completed.state),
        next_action=_policy_aware_state_action(store, completed.state),
        removed_worktree=str(ownership.worktree_path),
        evidence={"events": str(store.events_path)},
    )


def _handle_resume(args: argparse.Namespace) -> dict[str, object]:
    repository = _repository(args.repo)
    run = Reconciler(repository).reconcile(args.run_id)
    status_store = (
        StateStore(_run_directory(repository, args.run_id))
        if isinstance(repository, GitRepository)
        else None
    )
    review_reasons = {
        "plan-review-publication-recoverable",
        "code-review-publication-recoverable",
    }
    recovered: dict[str, object] | None = None
    if run.reason in review_reasons:
        if run.ownership is None or run.subject is None:
            raise CliFailure("evidence_missing", "可恢复 Review 的运行证据缺失。", 6)
        store = StateStore(run.ownership.record_path.parent)
        report = resume_review_publication(
            store,
            current_subject=run.subject,
        )
        recovered = {
            "kind": "review_publication",
            "review_type": report.review_type,
            "verdict": report.verdict,
            "evidence": str(
                store.run_directory / "reviews" / f"{report.review_type}-review.json"
            ),
        }
    elif run.reason == "verification-publication-recoverable":
        if run.ownership is None or run.subject is None or run.manifest is None:
            raise CliFailure(
                "evidence_missing",
                "可恢复 Verification 的运行证据缺失。",
                6,
            )
        report = Verifier(
            repo=run.ownership.worktree_path,
            run_directory=run.ownership.record_path.parent,
            manifest=run.manifest,
            current_subject=run.subject,
            variables=_standard_variables(run.ownership, run.manifest),
        ).resume_publication()
        recovered = {
            "kind": "verification_publication",
            "round": report.round,
            "verdict": report.verdict,
            "evidence": str(
                run.ownership.record_path.parent
                / "verifications"
                / f"verification-{report.round:04d}.json"
            ),
        }
    if recovered is None:
        return _success(
            "resume",
            **_run_payload(run, store=status_store, recover_approval=True),
        )
    current = Reconciler(repository).reconcile(args.run_id)
    return _success(
        "resume",
        recovered=recovered,
        **_run_payload(current, store=status_store, recover_approval=True),
    )


Handler = Callable[[argparse.Namespace], dict[str, object]]


def _common(subparser: argparse.ArgumentParser, *, run: bool = True) -> None:
    subparser.add_argument("--repo", default=".")
    if run:
        subparser.add_argument("--run-id", required=True)
    subparser.add_argument("--json", action="store_true", dest="json_output")


def _mutation(subparser: argparse.ArgumentParser) -> None:
    _common(subparser)
    subparser.add_argument("--expected-revision", type=int, required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="ship", description="可恢复、可审查的软件交付流程")
    parser.add_argument("--json", action="store_true", dest="global_json_output")
    commands = parser.add_subparsers(
        dest="command", required=True, parser_class=_Parser
    )

    command = commands.add_parser("init")
    _common(command, run=False)
    command.add_argument(
        "--mode",
        choices=("autonomous", "strict"),
        default="autonomous",
    )
    command.add_argument("--accept-detected", action="store_true")
    command.set_defaults(handler=_handle_init)

    command = commands.add_parser("start")
    _common(command, run=False)
    command.add_argument("--run-id")
    command.add_argument("--goal", required=True)
    command.add_argument("--branch")
    command.add_argument("--worktree")
    command.add_argument(
        "--mode",
        choices=("autonomous", "strict"),
        default="autonomous",
    )
    command.add_argument("--release-target")
    command.add_argument("--previous-release")
    command.set_defaults(handler=_handle_start)

    command = commands.add_parser("status")
    _common(command)
    command.set_defaults(handler=_handle_status)

    command = commands.add_parser("request-scope-change")
    _mutation(command)
    command.add_argument("--reason", required=True)
    command.add_argument("--summary", required=True)
    command.add_argument("--goal", required=True)
    command.add_argument("--manifest-sha256", required=True)
    command.add_argument("--release-target")
    command.add_argument("--previous-release")
    command.set_defaults(handler=_handle_request_scope_change)

    command = commands.add_parser("resolve-scope-change")
    _mutation(command)
    command.add_argument(
        "--decision",
        choices=("approve", "reject"),
        required=True,
    )
    command.add_argument("--actor", required=True)
    command.set_defaults(handler=_handle_resolve_scope_change)

    command = commands.add_parser("set-plan")
    _mutation(command)
    command.add_argument("--file", required=True)
    command.set_defaults(handler=_handle_set_plan)

    command = commands.add_parser("record-plan-review")
    _mutation(command)
    command.add_argument("--source-actor", required=True)
    command.add_argument("--reviewer", required=True)
    command.add_argument(
        "--verdict", choices=("pass", "changes_requested"), required=True
    )
    command.add_argument("--findings-json", default="[]")
    command.set_defaults(
        handler=lambda args: _record_review_command(args, review_type="plan")
    )

    command = commands.add_parser("approve")
    _mutation(command)
    command.add_argument(
        "--gate", choices=("plan", "release", "rollback"), required=True
    )
    command.add_argument("--actor", required=True)
    command.add_argument("--target")
    command.add_argument("--expires-at")
    command.add_argument("--failed-release-id")
    command.add_argument("--previous-release")
    command.set_defaults(handler=_handle_approve)

    command = commands.add_parser("development-ready")
    _mutation(command)
    command.add_argument("--message", required=True)
    command.add_argument("--approved-path", action="append", required=True)
    command.set_defaults(handler=_handle_development_ready)

    command = commands.add_parser("record-review")
    _mutation(command)
    command.add_argument("--source-actor", required=True)
    command.add_argument("--reviewer", required=True)
    command.add_argument(
        "--verdict", choices=("pass", "changes_requested"), required=True
    )
    command.add_argument("--findings-json", default="[]")
    command.set_defaults(
        handler=lambda args: _record_review_command(args, review_type="code")
    )

    command = commands.add_parser("verify")
    _mutation(command)
    command.add_argument("--source-actor", required=True)
    command.add_argument("--verifier", required=True)
    command.add_argument("--sensitive-value-env", action="append", default=[])
    command.set_defaults(handler=_handle_verify)

    command = commands.add_parser("release")
    _mutation(command)
    command.add_argument("--target", required=True)
    command.add_argument("--approval-id")
    command.add_argument("--rollback-approval-id")
    command.add_argument("--previous-release")
    command.set_defaults(handler=_handle_release)

    command = commands.add_parser("reconcile-operation")
    _mutation(command)
    command.add_argument("--target", required=True)
    command.add_argument("--outcome", choices=("applied", "not_applied"))
    command.add_argument("--unknown-receipt-sha256")
    command.add_argument("--confirmation-token")
    command.add_argument("--actor")
    command.set_defaults(handler=_handle_reconcile_operation)

    command = commands.add_parser("rollback")
    _mutation(command)
    command.add_argument("--target", required=True)
    command.add_argument("--approval-id")
    command.add_argument("--failed-release-id")
    command.add_argument("--previous-release")
    command.set_defaults(handler=_handle_rollback)

    command = commands.add_parser("record-sync")
    _mutation(command)
    source = command.add_mutually_exclusive_group(required=True)
    source.add_argument("--report")
    source.add_argument("--report-json")
    command.set_defaults(handler=_handle_record_sync)

    command = commands.add_parser("cleanup")
    _mutation(command)
    command.add_argument("--approve", action="store_true")
    command.add_argument("--merged-into", default="HEAD")
    command.add_argument("--approved-condition", action="append", default=[])
    command.set_defaults(handler=_handle_cleanup)

    command = commands.add_parser("resume")
    _common(command)
    command.set_defaults(handler=_handle_resume)
    return parser


def _failure_for(error: BaseException) -> CliFailure:
    if isinstance(error, CliFailure):
        return error
    if isinstance(error, StaleRevisionError):
        return CliFailure("stale_revision", "状态已变化，请先重新查看状态。", 4)
    if isinstance(error, InvalidTransitionError):
        return CliFailure("phase_conflict", "当前状态不允许执行这个动作。", 4)
    if isinstance(error, StateNotFoundError):
        return CliFailure("run_not_found", "找不到这个运行记录。", 3)
    if isinstance(error, CandidateSafetyError):
        return CliFailure(
            "candidate_needs_confirmation", "候选提交包含需要确认的文件。", 4
        )
    if isinstance(error, CleanupRefusedError):
        return CliFailure("cleanup_refused", "工作区尚不满足安全清理条件。", 4)
    if isinstance(
        error,
        (
            ReconciliationRecoveryError,
            ReviewRecoveryError,
            VerificationRecoveryError,
            ReleaseRecoveryError,
            SyncRecoveryError,
            WorkflowRecoveryError,
            StateCorruptionError,
        ),
    ):
        return CliFailure("evidence_invalid", "证据缺失、过期或无法安全恢复。", 6)
    if isinstance(
        error,
        (
            ReviewError,
            VerificationError,
            ReleaseError,
            SyncError,
            ReconciliationError,
            WorkflowError,
        ),
    ):
        return CliFailure("workflow_rejected", "流程安全检查未通过。", 6)
    if isinstance(error, GitOperationError):
        return CliFailure("git_error", "Git 工作区操作失败。", 7)
    if isinstance(error, StateStoreError):
        return CliFailure("state_error", "运行状态无法安全更新。", 7)
    if isinstance(error, (ValueError, TypeError, OSError)):
        return CliFailure("invalid_input", "输入或本地配置无效。", 5)
    return CliFailure("internal_error", "发生未预期错误，状态未被视为成功。", 70)


def _emit(payload: Mapping[str, object], *, json_output: bool) -> None:
    if json_output:
        print(
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return
    if payload.get("ok") is True:
        state = payload.get("state")
        if isinstance(state, Mapping):
            print(f"已完成：{payload.get('command')}（{state.get('phase')}）")
        else:
            print(f"已完成：{payload.get('command')}")
    else:
        error = payload.get("error")
        message = error.get("message") if isinstance(error, Mapping) else "操作失败。"
        print(message)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    wants_json = "--json" in arguments
    try:
        args = build_parser().parse_args(arguments)
        handler: Handler = args.handler
        payload = handler(args)
        _emit(
            payload,
            json_output=bool(
                getattr(args, "json_output", False)
                or getattr(args, "global_json_output", False)
            ),
        )
        return 0
    except SystemExit:
        raise
    except Exception as error:
        failure = _failure_for(error)
        _emit(
            {
                "ok": False,
                "command": _command_name(arguments),
                "error": {"code": failure.code, "message": failure.message},
            },
            json_output=wants_json,
        )
        return failure.exit_code


def _command_name(arguments: Sequence[str]) -> str:
    for argument in arguments:
        if not argument.startswith("-"):
            return argument
    return "unknown"
