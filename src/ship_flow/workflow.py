"""Crash-safe orchestration for the high-level ship workflow.

This module deliberately composes the narrower domain primitives instead of
reimplementing their ownership, state-WAL, or live-evidence validation rules.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence, TypeVar

from .gitops import (
    CleanupRefusedError,
    GitRepository,
    OwnershipError,
    ResourceCollisionError,
    WorktreeOwnership,
    _cleanup_receipt_path,
    _load_run_worktree_locked,
    _ownership_payload,
    _preflight_owned_worktree_cleanup_locked,
    _registered_worktree_details,
    cleanup_owned_worktree,
    create_run_worktree,
    load_run_worktree,
)
from .model import Phase, RunState
from .reconcile import (
    _load_safe_manifest,
    _observe_live_run,
    _open_run_directory,
    _run_directory_is_current,
)
from .store import (
    FileLock,
    PrivateRootAnchor,
    StateAlreadyExistsError,
    StateCorruptionError,
    StateEvent,
    StateNotFoundError,
    StateStore,
    _atomic_write_private_bytes,
    _atomic_write_private_json,
    _read_bounded_private_file,
    _remove_private_file,
    _private_entry_exists_at,
    _utc_now,
)
from .subject import EvidenceSubject


_RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_OBJECT_ID_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_MAX_PLAN_BYTES = 1_048_576
_MAX_OPERATION_BYTES = 1_048_576
_ENGINE_VERSION = "0.1.0"
_EVIDENCE_SCHEMA_VERSION = 1


class WorkflowError(RuntimeError):
    """Base error for high-level workflow orchestration."""


class WorkflowRecoveryError(WorkflowError):
    """A pending workflow transaction cannot be safely recovered."""


@dataclass(frozen=True)
class WorkflowRun:
    """A validated snapshot of one workflow run."""

    repository: GitRepository
    ownership: WorktreeOwnership
    store: StateStore
    state: RunState
    run_directory: Path
    subject: EvidenceSubject | None


def _validate_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or _RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise ValueError("run_id contains unsafe characters")
    return run_id


def discover_repository(start: GitRepository | Path | str) -> GitRepository:
    """Discover and normalize a non-bare repository and its primary checkout."""

    if isinstance(start, GitRepository):
        discovered = GitRepository.discover(start.primary_checkout)
        if discovered != start:
            raise WorkflowRecoveryError("repository identity changed after discovery")
        return discovered
    return GitRepository.discover(start)


def run_directory(
    repository: GitRepository | Path | str,
    run_id: str,
) -> Path:
    """Return the private run directory without accepting path traversal."""

    repo = discover_repository(repository)
    return _run_directory(repo, _validate_run_id(run_id))


def _run_directory(repository: GitRepository, run_id: str) -> Path:
    return repository.git_common_directory / "ship-flow" / "runs" / run_id


def _canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _same_ownership(
    observed: WorktreeOwnership,
    expected: WorktreeOwnership,
) -> bool:
    return _ownership_payload(observed) == _ownership_payload(expected) and (
        observed.record_path == expected.record_path
    )


def _validate_requested_ownership(
    ownership: WorktreeOwnership,
    *,
    branch: str,
    worktree_path: Path,
) -> None:
    if ownership.branch != branch or ownership.worktree_path != worktree_path:
        raise WorkflowRecoveryError(
            "existing run ownership does not match the requested branch and worktree"
        )


def _open_current_run_directory(repository: GitRepository, run_id: str) -> int:
    descriptor = _open_run_directory(repository, run_id)
    if not _run_directory_is_current(descriptor, _run_directory(repository, run_id)):
        os.close(descriptor)
        raise WorkflowRecoveryError("run directory changed while being opened")
    return descriptor


def _require_run_directory_current(descriptor: int, directory: Path) -> None:
    if not _run_directory_is_current(descriptor, directory):
        raise WorkflowRecoveryError("run directory identity changed during workflow")


def _create_state_anchored(store: StateStore, run_id: str) -> RunState:
    """Create the initial WAL using only the store's already anchored run FD."""

    with store._locked_run_directory() as run_fd:
        if _private_entry_exists_at(
            run_fd,
            store.state_path.name,
        ) or _private_entry_exists_at(run_fd, store.events_path.name):
            raise StateAlreadyExistsError(f"run state already exists: {run_id}")
        now = _utc_now()
        state = RunState(
            run_id=run_id,
            phase=Phase.INITIALIZED,
            revision=0,
            created_at=now,
            updated_at=now,
        )
        event = StateEvent(
            event_type="run.created",
            run_id=run_id,
            sequence=0,
            revision=0,
            previous_phase=None,
            phase=Phase.INITIALIZED,
            occurred_at=now,
            state=state,
            previous_event_sha256=None,
            operation_start=None,
            operation_adjudication=None,
            reconciliation_reason=None,
        )
        store._append_event(event, truncate_to=0, run_descriptor=run_fd)
        store._write_snapshot(state, run_descriptor=run_fd)
        return state


def _load_state_anchored(
    store: StateStore,
    descriptor: int,
) -> RunState:
    anchor = PrivateRootAnchor(store.run_directory, descriptor)
    with store.anchored(anchor):
        return store.load()


def _require_matching_state(state: RunState, run_id: str) -> None:
    if state.run_id != run_id:
        raise WorkflowRecoveryError("run state belongs to another workflow")


def load_run(
    repository: GitRepository | Path | str,
    run_id: str,
) -> WorkflowRun:
    """Load ownership and state through one stable repository boundary."""

    repo = discover_repository(repository)
    safe_run_id = _validate_run_id(run_id)
    with FileLock.repository(repo.git_common_directory):
        ownership = _load_run_worktree_locked(repo, safe_run_id)
        descriptor = _open_current_run_directory(repo, safe_run_id)
        try:
            store = StateStore(_run_directory(repo, safe_run_id))
            state = _load_state_anchored(store, descriptor)
            _require_matching_state(state, safe_run_id)
            _require_run_directory_current(descriptor, store.run_directory)
        finally:
            os.close(descriptor)
    return WorkflowRun(repo, ownership, store, state, store.run_directory, None)


def _observe_subject_locked(
    repository: GitRepository,
    run_id: str,
) -> EvidenceSubject:
    ownership = _load_run_worktree_locked(repository, run_id)
    descriptor = _open_current_run_directory(repository, run_id)
    try:
        store = StateStore(_run_directory(repository, run_id))
        anchor = PrivateRootAnchor(store.run_directory, descriptor)
        with store.anchored(anchor):
            state = store.load()
            _require_matching_state(state, run_id)
            observation = _observe_live_run(
                ownership,
                run_descriptor=descriptor,
                engine_version=_ENGINE_VERSION,
                evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            )
            _require_run_directory_current(descriptor, store.run_directory)
        return observation.subject
    finally:
        os.close(descriptor)


def observe_subject(
    repository: GitRepository | Path | str,
    run_id: str,
) -> EvidenceSubject:
    """Observe the live evidence subject for a validated run."""

    repo = discover_repository(repository)
    safe_run_id = _validate_run_id(run_id)
    with FileLock.repository(repo.git_common_directory):
        return _observe_subject_locked(repo, safe_run_id)


def _load_or_create_ownership(
    repository: GitRepository,
    *,
    run_id: str,
    branch: str,
    worktree_path: Path,
) -> WorktreeOwnership:
    directory = _run_directory(repository, run_id)
    manifest = _load_safe_manifest(repository.primary_checkout)
    if os.path.lexists(directory):
        try:
            ownership = load_run_worktree(repository, run_id)
        except OwnershipError:
            pass
        else:
            _validate_requested_ownership(
                ownership,
                branch=branch,
                worktree_path=worktree_path,
            )
            return ownership

    try:
        ownership = create_run_worktree(
            repository,
            run_id=run_id,
            branch=branch,
            worktree_path=worktree_path,
            base_ref=manifest.base_branch,
            require_clean_base=manifest.require_clean_base,
        )
    except ResourceCollisionError as collision:
        try:
            ownership = load_run_worktree(repository, run_id)
        except OwnershipError:
            raise WorkflowRecoveryError(
                "run creation collided with resources not owned by this run"
            ) from collision
        _validate_requested_ownership(
            ownership,
            branch=branch,
            worktree_path=worktree_path,
        )
    return ownership


def start_run(
    repository: GitRepository | Path | str,
    *,
    run_id: str,
    branch: str,
    worktree_path: Path | str,
) -> WorkflowRun:
    """Create or recover a run worktree and initialize its durable state."""

    repo = discover_repository(repository)
    safe_run_id = _validate_run_id(run_id)
    if not isinstance(branch, str) or not branch:
        raise ValueError("branch must be a non-empty string")
    canonical_worktree = (
        Path(worktree_path).expanduser().absolute().resolve(strict=False)
    )
    ownership = _load_or_create_ownership(
        repo,
        run_id=safe_run_id,
        branch=branch,
        worktree_path=canonical_worktree,
    )

    with FileLock.repository(repo.git_common_directory):
        ownership = _load_run_worktree_locked(repo, safe_run_id)
        _validate_requested_ownership(
            ownership,
            branch=branch,
            worktree_path=canonical_worktree,
        )
        descriptor = _open_current_run_directory(repo, safe_run_id)
        try:
            directory = _run_directory(repo, safe_run_id)
            store = StateStore(directory)
            with FileLock.at(
                descriptor,
                "workflow.lock",
                display_path=directory / "workflow.lock",
            ) as workflow_lock:
                with store.anchored(workflow_lock.trusted_parent):
                    try:
                        state = store.load()
                    except StateNotFoundError:
                        try:
                            state = _create_state_anchored(store, safe_run_id)
                        except StateAlreadyExistsError:
                            state = store.load()
                    _require_matching_state(state, safe_run_id)
                    _require_run_directory_current(descriptor, directory)
                    if state.phase is Phase.INITIALIZED:
                        state = store.transition(
                            Phase.PLANNING,
                            expected_revision=state.revision,
                        )
                    _require_run_directory_current(descriptor, directory)
            _require_run_directory_current(descriptor, directory)
        finally:
            os.close(descriptor)
    return WorkflowRun(repo, ownership, store, state, store.run_directory, None)


_PLAN_OPERATION_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "expected_revision",
        "target_phase",
        "plan_sha256",
        "plan_size",
        "previous_plan_sha256",
        "stage",
    }
)
_PLAN_STAGES = frozenset({"prepared", "plan-written", "state-transitioned"})


def _validate_plan_operation(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict) or set(payload) != _PLAN_OPERATION_KEYS:
        raise WorkflowRecoveryError("pending plan operation schema is invalid")
    previous_digest = payload.get("previous_plan_sha256")
    if (
        payload.get("schema_version") != 1
        or not isinstance(payload.get("run_id"), str)
        or _RUN_ID_PATTERN.fullmatch(str(payload["run_id"])) is None
        or type(payload.get("expected_revision")) is not int
        or int(payload["expected_revision"]) < 0
        or payload.get("target_phase") != Phase.PLAN_REVIEW.value
        or not isinstance(payload.get("plan_sha256"), str)
        or _SHA256_PATTERN.fullmatch(str(payload["plan_sha256"])) is None
        or type(payload.get("plan_size")) is not int
        or not 0 < int(payload["plan_size"]) <= _MAX_PLAN_BYTES
        or (
            previous_digest is not None
            and (
                not isinstance(previous_digest, str)
                or _SHA256_PATTERN.fullmatch(previous_digest) is None
            )
        )
        or payload.get("stage") not in _PLAN_STAGES
    ):
        raise WorkflowRecoveryError("pending plan operation is invalid")
    return dict(payload)


T = TypeVar("T", bound=dict[str, object])


def _read_canonical_operation(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
    label: str,
    validator: Callable[[object], T],
) -> T | None:
    try:
        raw = _read_bounded_private_file(
            path,
            trusted_root=trusted_root,
            label=label,
            max_bytes=_MAX_OPERATION_BYTES,
        )
    except StateNotFoundError:
        return None
    except StateCorruptionError as error:
        raise WorkflowRecoveryError(f"{label} cannot be read safely") from error
    try:
        payload = json.loads(raw.decode("utf-8"))
        canonical = _canonical_json_bytes(payload) + b"\n"
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise WorkflowRecoveryError(f"{label} is not canonical JSON") from error
    if raw != canonical:
        raise WorkflowRecoveryError(f"{label} is not canonical JSON")
    return validator(payload)


def _read_plan(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> bytes | None:
    try:
        return _read_bounded_private_file(
            path,
            trusted_root=trusted_root,
            label="run plan",
            max_bytes=_MAX_PLAN_BYTES,
        )
    except StateNotFoundError:
        return None
    except StateCorruptionError as error:
        raise WorkflowRecoveryError("run plan cannot be read safely") from error


def _optional_digest(payload: bytes | None) -> str | None:
    return None if payload is None else _sha256(payload)


def _require_exact_plan(
    path: Path,
    expected: bytes,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> None:
    observed = _read_plan(path, trusted_root=trusted_root)
    if (
        observed is None
        or len(observed) != len(expected)
        or _sha256(observed) != _sha256(expected)
        or observed != expected
    ):
        raise WorkflowRecoveryError(
            "run plan changed before the PLAN_REVIEW transition"
        )


def _plan_request_matches(
    operation: dict[str, object],
    *,
    run_id: str,
    expected_revision: int,
    plan_bytes: bytes,
) -> bool:
    return (
        operation["run_id"] == run_id
        and operation["expected_revision"] == expected_revision
        and operation["plan_sha256"] == _sha256(plan_bytes)
        and operation["plan_size"] == len(plan_bytes)
    )


def _write_plan_operation(
    path: Path,
    operation: dict[str, object],
    *,
    trusted_root: Path | PrivateRootAnchor,
    stage: str,
) -> dict[str, object]:
    updated = {**operation, "stage": stage}
    validated = _validate_plan_operation(updated)
    _atomic_write_private_json(path, validated, trusted_root=trusted_root)
    return validated


def _compensate_invalid_plan_review(
    store: StateStore,
    operation_path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
    descriptor: int,
    directory: Path,
    source_revision: int,
) -> RunState:
    """Fail closed after PLAN_REVIEW was reached with untrusted plan bytes."""

    state = store.load()
    if state.phase is Phase.PLAN_REVIEW and state.revision == source_revision + 1:
        _require_run_directory_current(descriptor, directory)
        state = store.reconcile_transition(
            Phase.PLANNING,
            expected_revision=state.revision,
            reason="plan-publication-evidence-drift",
        )
        _require_run_directory_current(descriptor, directory)
    elif not (state.phase is Phase.PLANNING and state.revision == source_revision + 2):
        raise WorkflowRecoveryError("invalid plan review cannot be safely reconciled")

    _remove_private_file(
        operation_path,
        trusted_root=trusted_root,
        missing_ok=True,
    )
    return state


def set_plan(
    repository: GitRepository | Path | str,
    run_id: str,
    text: str,
    *,
    expected_revision: int,
) -> WorkflowRun:
    """Publish an exact plan and advance PLANNING to PLAN_REVIEW atomically."""

    if not isinstance(text, str) or not text.strip():
        raise ValueError("plan text must be non-empty")
    plan_bytes = text.encode("utf-8")
    if len(plan_bytes) > _MAX_PLAN_BYTES:
        raise ValueError("plan text exceeds the 1 MiB limit")
    if type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("expected_revision must be a non-negative integer")
    repo = discover_repository(repository)
    safe_run_id = _validate_run_id(run_id)
    directory = _run_directory(repo, safe_run_id)

    with FileLock.repository(repo.git_common_directory):
        ownership = _load_run_worktree_locked(repo, safe_run_id)
        descriptor = _open_current_run_directory(repo, safe_run_id)
        try:
            store = StateStore(directory)
            with FileLock.at(
                descriptor,
                "workflow.lock",
                display_path=directory / "workflow.lock",
            ) as workflow_lock:
                with store.anchored(workflow_lock.trusted_parent):
                    trusted_root = store.trusted_root
                    operation_path = directory / "set-plan-operation.json"
                    plan_path = directory / "plan.md"
                    operation = _read_canonical_operation(
                        operation_path,
                        trusted_root=trusted_root,
                        label="pending plan operation",
                        validator=_validate_plan_operation,
                    )
                    state = store.load()
                    _require_matching_state(state, safe_run_id)
                    try:
                        current_plan = _read_plan(
                            plan_path,
                            trusted_root=trusted_root,
                        )
                    except WorkflowRecoveryError as error:
                        if operation is not None and (
                            (
                                state.phase is Phase.PLAN_REVIEW
                                and state.revision == expected_revision + 1
                            )
                            or (
                                state.phase is Phase.PLANNING
                                and state.revision == expected_revision + 2
                            )
                        ):
                            _compensate_invalid_plan_review(
                                store,
                                operation_path,
                                trusted_root=trusted_root,
                                descriptor=descriptor,
                                directory=directory,
                                source_revision=expected_revision,
                            )
                        raise WorkflowRecoveryError(
                            "run plan is unsafe; publication was reconciled"
                        ) from error

                    if operation is None:
                        if (
                            state.phase is Phase.PLAN_REVIEW
                            and state.revision == expected_revision + 1
                            and current_plan == plan_bytes
                        ):
                            subject = _observe_live_run(
                                ownership,
                                run_descriptor=descriptor,
                                engine_version=_ENGINE_VERSION,
                                evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
                            ).subject
                            _require_run_directory_current(descriptor, directory)
                            return WorkflowRun(
                                repo,
                                ownership,
                                store,
                                state,
                                directory,
                                subject,
                            )
                        if (
                            state.phase is not Phase.PLANNING
                            or state.revision != expected_revision
                        ):
                            raise WorkflowRecoveryError(
                                "plan publication source state no longer matches"
                            )
                        operation = {
                            "schema_version": 1,
                            "run_id": safe_run_id,
                            "expected_revision": expected_revision,
                            "target_phase": Phase.PLAN_REVIEW.value,
                            "plan_sha256": _sha256(plan_bytes),
                            "plan_size": len(plan_bytes),
                            "previous_plan_sha256": _optional_digest(current_plan),
                            "stage": "prepared",
                        }
                        operation = _write_plan_operation(
                            operation_path,
                            operation,
                            trusted_root=trusted_root,
                            stage="prepared",
                        )
                    elif not _plan_request_matches(
                        operation,
                        run_id=safe_run_id,
                        expected_revision=expected_revision,
                        plan_bytes=plan_bytes,
                    ):
                        raise WorkflowRecoveryError(
                            "retry does not match the pending plan publication"
                        )

                    if operation is not None and (
                        (
                            state.phase is Phase.PLAN_REVIEW
                            and state.revision == expected_revision + 1
                            and current_plan != plan_bytes
                        )
                        or (
                            state.phase is Phase.PLANNING
                            and state.revision == expected_revision + 2
                        )
                    ):
                        _compensate_invalid_plan_review(
                            store,
                            operation_path,
                            trusted_root=trusted_root,
                            descriptor=descriptor,
                            directory=directory,
                            source_revision=expected_revision,
                        )
                        raise WorkflowRecoveryError(
                            "plan evidence drifted after PLAN_REVIEW; "
                            "publication was reconciled to PLANNING"
                        )

                    current_plan_digest = _optional_digest(current_plan)
                    if current_plan_digest == operation["plan_sha256"]:
                        pass
                    elif current_plan_digest == operation["previous_plan_sha256"]:
                        _atomic_write_private_bytes(
                            plan_path,
                            plan_bytes,
                            trusted_root=trusted_root,
                        )
                    else:
                        raise WorkflowRecoveryError(
                            "run plan changed outside the pending publication"
                        )
                    if operation["stage"] == "prepared":
                        operation = _write_plan_operation(
                            operation_path,
                            operation,
                            trusted_root=trusted_root,
                            stage="plan-written",
                        )

                    state = store.load()
                    _require_exact_plan(
                        plan_path,
                        plan_bytes,
                        trusted_root=trusted_root,
                    )
                    _require_run_directory_current(descriptor, directory)
                    if (
                        state.phase is Phase.PLANNING
                        and state.revision == expected_revision
                    ):
                        state = store.transition(
                            Phase.PLAN_REVIEW,
                            expected_revision=expected_revision,
                        )
                    elif not (
                        state.phase is Phase.PLAN_REVIEW
                        and state.revision == expected_revision + 1
                    ):
                        raise WorkflowRecoveryError(
                            "plan publication state changed during recovery"
                        )
                    _require_run_directory_current(descriptor, directory)
                    if operation["stage"] != "state-transitioned":
                        _write_plan_operation(
                            operation_path,
                            operation,
                            trusted_root=trusted_root,
                            stage="state-transitioned",
                        )
                    try:
                        _require_exact_plan(
                            plan_path,
                            plan_bytes,
                            trusted_root=trusted_root,
                        )
                    except WorkflowRecoveryError as error:
                        _compensate_invalid_plan_review(
                            store,
                            operation_path,
                            trusted_root=trusted_root,
                            descriptor=descriptor,
                            directory=directory,
                            source_revision=expected_revision,
                        )
                        raise WorkflowRecoveryError(
                            "plan evidence drifted after PLAN_REVIEW; "
                            "publication was reconciled to PLANNING"
                        ) from error
                    _remove_private_file(
                        operation_path,
                        trusted_root=trusted_root,
                    )
                    subject = _observe_live_run(
                        ownership,
                        run_descriptor=descriptor,
                        engine_version=_ENGINE_VERSION,
                        evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
                    ).subject
                    _require_run_directory_current(descriptor, directory)
            _require_run_directory_current(descriptor, directory)
        finally:
            os.close(descriptor)
    return WorkflowRun(repo, ownership, store, state, directory, subject)


_CLEANUP_OPERATION_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "expected_revision",
        "target_phase",
        "approved",
        "approved_conditions",
        "merged_into",
        "target_oid",
        "ownership_record_sha256",
        "ownership",
        "stage",
    }
)
_CLEANUP_STAGES = frozenset({"prepared", "state-transitioned", "completed"})
_OWNERSHIP_KEYS = frozenset(
    {
        "run_id",
        "primary_checkout",
        "git_common_directory",
        "worktree_path",
        "branch",
        "base_oid",
        "last_known_oid",
        "git_backlink",
    }
)


def _validate_cleanup_operation(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict) or set(payload) != _CLEANUP_OPERATION_KEYS:
        raise WorkflowRecoveryError("cleanup workflow operation schema is invalid")
    ownership = payload.get("ownership")
    conditions = payload.get("approved_conditions")
    if (
        payload.get("schema_version") != 1
        or not isinstance(payload.get("run_id"), str)
        or _RUN_ID_PATTERN.fullmatch(str(payload["run_id"])) is None
        or type(payload.get("expected_revision")) is not int
        or int(payload["expected_revision"]) < 0
        or payload.get("target_phase") != Phase.COMPLETED.value
        or payload.get("approved") is not True
        or not isinstance(conditions, list)
        or any(not isinstance(item, str) for item in conditions)
        or conditions != sorted(set(conditions))
        or any(item != "unmerged" for item in conditions)
        or not isinstance(payload.get("merged_into"), str)
        or not str(payload["merged_into"]).strip()
        or not isinstance(payload.get("target_oid"), str)
        or _OBJECT_ID_PATTERN.fullmatch(str(payload["target_oid"])) is None
        or not isinstance(payload.get("ownership_record_sha256"), str)
        or _SHA256_PATTERN.fullmatch(str(payload["ownership_record_sha256"])) is None
        or not isinstance(ownership, dict)
        or set(ownership) != _OWNERSHIP_KEYS
        or payload.get("stage") not in _CLEANUP_STAGES
    ):
        raise WorkflowRecoveryError("cleanup workflow operation is invalid")
    for key, value in ownership.items():
        if not isinstance(value, str) or not value:
            raise WorkflowRecoveryError("cleanup ownership snapshot is invalid")
        if key in {"base_oid", "last_known_oid"} and (
            _OBJECT_ID_PATTERN.fullmatch(value) is None
        ):
            raise WorkflowRecoveryError("cleanup ownership snapshot is invalid")
    if ownership["run_id"] != payload["run_id"]:
        raise WorkflowRecoveryError("cleanup ownership belongs to another run")
    return dict(payload)


def _ownership_from_cleanup_operation(
    repository: GitRepository,
    operation: dict[str, object],
) -> WorktreeOwnership:
    payload = operation["ownership"]
    assert isinstance(payload, dict)
    ownership = WorktreeOwnership(
        run_id=str(payload["run_id"]),
        primary_checkout=Path(str(payload["primary_checkout"])),
        git_common_directory=Path(str(payload["git_common_directory"])),
        worktree_path=Path(str(payload["worktree_path"])),
        branch=str(payload["branch"]),
        base_oid=str(payload["base_oid"]),
        last_known_oid=str(payload["last_known_oid"]),
        git_backlink=Path(str(payload["git_backlink"])),
        record_path=_run_directory(repository, str(payload["run_id"]))
        / "worktree.json",
    )
    if (
        ownership.primary_checkout != repository.primary_checkout
        or ownership.git_common_directory != repository.git_common_directory
    ):
        raise WorkflowRecoveryError("cleanup ownership repository identity changed")
    return ownership


def _cleanup_request_matches(
    operation: dict[str, object],
    *,
    run_id: str,
    expected_revision: int,
    approved_conditions: tuple[str, ...],
    merged_into: str,
) -> bool:
    return (
        operation["run_id"] == run_id
        and operation["expected_revision"] == expected_revision
        and operation["approved_conditions"] == list(approved_conditions)
        and operation["merged_into"] == merged_into
        and operation["approved"] is True
    )


def _write_cleanup_operation(
    path: Path,
    operation: dict[str, object],
    *,
    trusted_root: Path | PrivateRootAnchor,
    stage: str,
) -> dict[str, object]:
    updated = {**operation, "stage": stage}
    validated = _validate_cleanup_operation(updated)
    _atomic_write_private_json(path, validated, trusted_root=trusted_root)
    return validated


def _require_cleanup_preflight_binding(
    repository: GitRepository,
    ownership: WorktreeOwnership,
    operation: dict[str, object],
) -> None:
    try:
        preflight = _preflight_owned_worktree_cleanup_locked(
            ownership,
            repository,
            approved_conditions=frozenset(
                str(item) for item in operation["approved_conditions"]
            ),
            merged_into=str(operation["target_oid"]),
        )
    except Exception as error:
        raise WorkflowRecoveryError(
            "cleanup preflight no longer validates the prepared ownership"
        ) from error
    if (
        preflight.target_oid != operation["target_oid"]
        or preflight.ownership_record_sha256 != operation["ownership_record_sha256"]
        or list(preflight.approved_conditions) != operation["approved_conditions"]
    ):
        raise WorkflowRecoveryError(
            "cleanup ownership or target changed after preflight"
        )


def _prepare_cleanup(
    repository: GitRepository,
    *,
    run_id: str,
    expected_revision: int,
    approved_conditions: tuple[str, ...],
    merged_into: str,
) -> tuple[WorktreeOwnership, StateStore, RunState, bool, str]:
    directory = _run_directory(repository, run_id)
    operation_path = directory / "cleanup-workflow-operation.json"
    completion_path = directory / "cleanup-workflow-completed.json"
    with FileLock.repository(repository.git_common_directory):
        descriptor = _open_current_run_directory(repository, run_id)
        try:
            store = StateStore(directory)
            with FileLock.at(
                descriptor,
                "workflow.lock",
                display_path=directory / "workflow.lock",
            ) as workflow_lock:
                with store.anchored(workflow_lock.trusted_parent):
                    trusted_root = store.trusted_root
                    operation = _read_canonical_operation(
                        operation_path,
                        trusted_root=trusted_root,
                        label="cleanup workflow operation",
                        validator=_validate_cleanup_operation,
                    )
                    completion = _read_canonical_operation(
                        completion_path,
                        trusted_root=trusted_root,
                        label="cleanup workflow completion",
                        validator=_validate_cleanup_operation,
                    )
                    if operation is not None and completion is not None:
                        operation_completed = {**operation, "stage": "completed"}
                        if completion != operation_completed:
                            raise WorkflowRecoveryError(
                                "cleanup operation conflicts with its completion receipt"
                            )
                    selected = operation or completion
                    if selected is not None and not _cleanup_request_matches(
                        selected,
                        run_id=run_id,
                        expected_revision=expected_revision,
                        approved_conditions=approved_conditions,
                        merged_into=merged_into,
                    ):
                        raise WorkflowRecoveryError(
                            "retry does not match the pending cleanup operation"
                        )

                    state = store.load()
                    _require_matching_state(state, run_id)
                    _require_run_directory_current(descriptor, directory)
                    if operation is None and completion is not None:
                        if not (
                            state.phase is Phase.COMPLETED
                            and state.revision == expected_revision + 1
                        ):
                            raise WorkflowRecoveryError(
                                "cleanup completion state no longer matches"
                            )
                        _require_run_directory_current(descriptor, directory)
                        return (
                            _ownership_from_cleanup_operation(
                                repository,
                                completion,
                            ),
                            store,
                            state,
                            True,
                            str(completion["target_oid"]),
                        )

                    if operation is None:
                        if not (
                            state.phase is Phase.AWAITING_CLEANUP_APPROVAL
                            and state.revision == expected_revision
                        ):
                            raise WorkflowRecoveryError(
                                "cleanup source state no longer matches"
                            )
                        ownership = _load_run_worktree_locked(repository, run_id)
                        preflight = _preflight_owned_worktree_cleanup_locked(
                            ownership,
                            repository,
                            approved_conditions=frozenset(approved_conditions),
                            merged_into=merged_into,
                        )
                        operation = {
                            "schema_version": 1,
                            "run_id": run_id,
                            "expected_revision": expected_revision,
                            "target_phase": Phase.COMPLETED.value,
                            "approved": True,
                            "approved_conditions": list(approved_conditions),
                            "merged_into": merged_into,
                            "target_oid": preflight.target_oid,
                            "ownership_record_sha256": (
                                preflight.ownership_record_sha256
                            ),
                            "ownership": _ownership_payload(ownership),
                            "stage": "prepared",
                        }
                        operation = _write_cleanup_operation(
                            operation_path,
                            operation,
                            trusted_root=trusted_root,
                            stage="prepared",
                        )
                    else:
                        ownership = _ownership_from_cleanup_operation(
                            repository,
                            operation,
                        )

                    if (
                        state.phase is Phase.AWAITING_CLEANUP_APPROVAL
                        and state.revision == expected_revision
                    ):
                        _require_cleanup_preflight_binding(
                            repository,
                            ownership,
                            operation,
                        )
                        _require_run_directory_current(descriptor, directory)
                        state = store.transition(
                            Phase.COMPLETED,
                            expected_revision=expected_revision,
                        )
                    elif not (
                        state.phase is Phase.COMPLETED
                        and state.revision == expected_revision + 1
                    ):
                        raise WorkflowRecoveryError(
                            "cleanup state changed during recovery"
                        )
                    _require_run_directory_current(descriptor, directory)
                    if operation["stage"] != "state-transitioned":
                        _write_cleanup_operation(
                            operation_path,
                            operation,
                            trusted_root=trusted_root,
                            stage="state-transitioned",
                        )
                    _require_run_directory_current(descriptor, directory)
                    return (
                        ownership,
                        store,
                        state,
                        False,
                        str(operation["target_oid"]),
                    )
        finally:
            os.close(descriptor)


def _finish_owned_cleanup(
    repository: GitRepository,
    ownership: WorktreeOwnership,
    *,
    approved_conditions: tuple[str, ...],
    merged_into: str,
) -> None:
    try:
        current = load_run_worktree(repository, ownership.run_id)
    except OwnershipError as load_error:
        with FileLock.repository(repository.git_common_directory):
            record_exists = os.path.lexists(ownership.record_path)
            receipt_exists = os.path.lexists(_cleanup_receipt_path(ownership))
            registered = _registered_worktree_details(
                repository,
                ownership.worktree_path,
            )
            backlink_exists = os.path.lexists(ownership.git_backlink)
        if record_exists:
            raise WorkflowRecoveryError(
                "cleanup ownership record cannot be validated"
            ) from load_error
        if not receipt_exists:
            if registered is not None or backlink_exists:
                raise WorkflowRecoveryError(
                    "missing cleanup evidence still has a registered worktree"
                ) from load_error
            return
    else:
        if not _same_ownership(current, ownership):
            raise WorkflowRecoveryError(
                "cleanup ownership changed after the state transition"
            )
    cleanup_owned_worktree(
        ownership,
        approved=True,
        approved_conditions=approved_conditions,
        merged_into=merged_into,
    )


def _finalize_cleanup(
    repository: GitRepository,
    *,
    run_id: str,
    expected_revision: int,
    approved_conditions: tuple[str, ...],
    merged_into: str,
) -> tuple[WorktreeOwnership, StateStore, RunState]:
    directory = _run_directory(repository, run_id)
    operation_path = directory / "cleanup-workflow-operation.json"
    completion_path = directory / "cleanup-workflow-completed.json"
    with FileLock.repository(repository.git_common_directory):
        descriptor = _open_current_run_directory(repository, run_id)
        try:
            store = StateStore(directory)
            with FileLock.at(
                descriptor,
                "workflow.lock",
                display_path=directory / "workflow.lock",
            ) as workflow_lock:
                with store.anchored(workflow_lock.trusted_parent):
                    trusted_root = store.trusted_root
                    operation = _read_canonical_operation(
                        operation_path,
                        trusted_root=trusted_root,
                        label="cleanup workflow operation",
                        validator=_validate_cleanup_operation,
                    )
                    completion = _read_canonical_operation(
                        completion_path,
                        trusted_root=trusted_root,
                        label="cleanup workflow completion",
                        validator=_validate_cleanup_operation,
                    )
                    selected = operation or completion
                    if selected is None or not _cleanup_request_matches(
                        selected,
                        run_id=run_id,
                        expected_revision=expected_revision,
                        approved_conditions=approved_conditions,
                        merged_into=merged_into,
                    ):
                        raise WorkflowRecoveryError(
                            "cleanup operation disappeared before finalization"
                        )
                    ownership = _ownership_from_cleanup_operation(
                        repository,
                        selected,
                    )
                    if os.path.lexists(ownership.record_path) or os.path.lexists(
                        _cleanup_receipt_path(ownership)
                    ):
                        raise WorkflowRecoveryError(
                            "owned cleanup has not durably completed"
                        )
                    state = store.load()
                    if not (
                        state.phase is Phase.COMPLETED
                        and state.revision == expected_revision + 1
                    ):
                        raise WorkflowRecoveryError(
                            "cleanup final state no longer matches"
                        )
                    _require_run_directory_current(descriptor, directory)
                    completed = {**selected, "stage": "completed"}
                    completed = _validate_cleanup_operation(completed)
                    if completion is not None and completion != completed:
                        raise WorkflowRecoveryError(
                            "cleanup completion receipt conflicts with this request"
                        )
                    if completion is None:
                        _atomic_write_private_json(
                            completion_path,
                            completed,
                            trusted_root=trusted_root,
                        )
                    if operation is not None:
                        _remove_private_file(
                            operation_path,
                            trusted_root=trusted_root,
                        )
                    _require_run_directory_current(descriptor, directory)
                    return ownership, store, state
        finally:
            os.close(descriptor)


def cleanup_run(
    repository: GitRepository | Path | str,
    run_id: str,
    *,
    expected_revision: int,
    approved: bool,
    merged_into: str = "HEAD",
    approved_conditions: Sequence[str] = (),
) -> WorkflowRun:
    """Complete state and safely remove only the worktree owned by this run."""

    if type(approved) is not bool:
        raise TypeError("approved must be a boolean")
    if not approved:
        raise CleanupRefusedError(("approval",))
    if type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("expected_revision must be a non-negative integer")
    if not isinstance(merged_into, str) or not merged_into.strip():
        raise ValueError("merged_into must be a non-empty string")
    if isinstance(approved_conditions, (str, bytes)):
        raise TypeError("approved_conditions must be a sequence of condition names")
    conditions = tuple(sorted(set(approved_conditions)))
    if any(not isinstance(item, str) for item in conditions):
        raise TypeError("approved_conditions must contain strings")
    unknown = set(conditions) - {"unmerged"}
    if unknown:
        raise ValueError(
            "unknown cleanup approval conditions: " + ", ".join(sorted(unknown))
        )

    repo = discover_repository(repository)
    safe_run_id = _validate_run_id(run_id)
    ownership, store, state, completed, target_oid = _prepare_cleanup(
        repo,
        run_id=safe_run_id,
        expected_revision=expected_revision,
        approved_conditions=conditions,
        merged_into=merged_into,
    )
    if not completed:
        _finish_owned_cleanup(
            repo,
            ownership,
            approved_conditions=conditions,
            merged_into=target_oid,
        )
        ownership, store, state = _finalize_cleanup(
            repo,
            run_id=safe_run_id,
            expected_revision=expected_revision,
            approved_conditions=conditions,
            merged_into=merged_into,
        )
    return WorkflowRun(
        repo,
        ownership,
        store,
        state,
        _run_directory(repo, safe_run_id),
        None,
    )


__all__ = [
    "WorkflowError",
    "WorkflowRecoveryError",
    "WorkflowRun",
    "cleanup_run",
    "discover_repository",
    "load_run",
    "observe_subject",
    "run_directory",
    "set_plan",
    "start_run",
]
