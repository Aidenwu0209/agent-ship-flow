from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Mapping

from .authorization import AuthorizationStore
from .gitops import (
    GitRepository,
    WorktreeOwnership,
    _load_run_worktree_locked,
)
from .manifest import Manifest, load_manifest, manifest_digest
from .model import Phase, RunState
from .release import (
    ExternalEvidenceMissingError,
    ExternalEvidenceUnknownError,
    ReleaseRecoveryError,
    validate_external_operation_evidence,
)
from .review import (
    ReviewEvidenceMissingError,
    ReviewEvidenceStaleError,
    ReviewRecoveryError,
    validate_completed_review_publication,
    validate_passing_code_review,
    validate_recoverable_review_publication,
)
from .store import (
    FileLock,
    LockUnavailableError,
    PrivateRootAnchor,
    StateStore,
    _atomic_write_private_json,
    _remove_private_file as _remove_private_file_at,
)
from .subject import EvidenceSubject
from .sync import SyncRecoveryError, _load_current_sync_report_locked
from .verify import (
    VerificationEvidenceMissingError,
    VerificationEvidenceStaleError,
    VerificationRecoveryError,
    validate_passing_verification,
    validate_recoverable_verification_publication,
    verification_commands_digest,
)


class ReconciliationError(RuntimeError):
    pass


class ReconciliationRecoveryError(ReconciliationError):
    pass


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(payload: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def _read_private_canonical_json(
    path: Path,
    *,
    root: Path | PrivateRootAnchor,
    label: str,
    max_bytes: int = 1_048_576,
) -> tuple[dict[str, object], bytes]:
    try:
        directory_descriptor = _open_existing_private_directory(
            path.parent,
            root=root,
        )
    except OSError as error:
        raise ReconciliationRecoveryError(f"{label} cannot be opened safely") from error
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    except OSError as error:
        os.close(directory_descriptor)
        raise ReconciliationRecoveryError(f"{label} cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ReconciliationRecoveryError(f"{label} is not a regular private file")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65_536, max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise ReconciliationRecoveryError(f"{label} is too large")
        raw = b"".join(chunks)
        current = os.stat(
            path.name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
            raise ReconciliationRecoveryError(f"{label} changed while loading")
    except ReconciliationRecoveryError:
        raise
    except OSError as error:
        raise ReconciliationRecoveryError(f"{label} cannot be inspected") from error
    finally:
        os.close(descriptor)
        os.close(directory_descriptor)
    try:
        payload = json.loads(raw.decode("utf-8"))
        canonical = _canonical_json_bytes(payload)
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise ReconciliationRecoveryError(f"{label} is corrupt") from error
    if not isinstance(payload, dict) or raw != canonical + b"\n":
        raise ReconciliationRecoveryError(f"{label} is not canonical JSON")
    return payload, raw


def _private_relative_parts(
    path: Path,
    *,
    root: Path | PrivateRootAnchor,
) -> tuple[str, ...]:
    path = Path(os.path.abspath(path))
    root = Path(
        os.path.abspath(root.path if isinstance(root, PrivateRootAnchor) else root)
    )
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ReconciliationRecoveryError(
            "private evidence path escapes the run"
        ) from error
    if any(
        not component
        or component in {".", ".."}
        or "/" in component
        or "\\" in component
        for component in relative.parts
    ):
        raise ReconciliationRecoveryError(
            "private evidence path has an unsafe component"
        )
    return relative.parts


def _open_existing_private_directory(
    path: Path,
    *,
    root: Path | PrivateRootAnchor,
) -> int:
    relative_parts = _private_relative_parts(path, root=root)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if isinstance(root, PrivateRootAnchor):
        descriptor = os.dup(root.descriptor)
    else:
        try:
            descriptor = os.open(root, flags)
        except OSError as error:
            raise ReconciliationRecoveryError(
                "run evidence root cannot be opened safely"
            ) from error
    try:
        root_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise ReconciliationRecoveryError(
                "run evidence root is not a private directory"
            )
        for component in relative_parts:
            child = os.open(component, flags, dir_fd=descriptor)
            metadata = os.fstat(child)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                os.close(child)
                raise ReconciliationRecoveryError(
                    "private evidence directory is unsafe"
                )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _private_path_exists(
    path: Path,
    *,
    root: Path | PrivateRootAnchor,
) -> bool:
    try:
        descriptor = _open_existing_private_directory(path.parent, root=root)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ReconciliationRecoveryError(
            "private evidence parent cannot be opened safely"
        ) from error
    try:
        try:
            metadata = os.stat(
                path.name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(metadata.st_mode):
            raise ReconciliationRecoveryError(
                "private evidence path is a symbolic link"
            )
        return True
    except OSError as error:
        raise ReconciliationRecoveryError(
            "private evidence path cannot be inspected"
        ) from error
    finally:
        os.close(descriptor)


def _private_directory_names(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> tuple[str, ...]:
    try:
        descriptor = _open_existing_private_directory(path, root=trusted_root)
    except OSError as error:
        raise ReconciliationRecoveryError(
            "private evidence directory cannot be opened safely"
        ) from error
    try:
        return tuple(sorted(os.listdir(descriptor)))
    except OSError as error:
        raise ReconciliationRecoveryError(
            "private evidence directory cannot be listed"
        ) from error
    finally:
        os.close(descriptor)


def _write_private_json(
    path: Path,
    payload: dict[str, object],
    *,
    trusted_root: Path | PrivateRootAnchor,
    immutable: bool,
) -> None:
    _atomic_write_private_json(
        path,
        payload,
        trusted_root=trusted_root,
        immutable=immutable,
    )


def _remove_private_file(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> None:
    _remove_private_file_at(path, trusted_root=trusted_root)


@dataclass(frozen=True)
class PlanApprovalRecord:
    approval_id: str
    run_id: str
    plan_sha256: str
    manifest_sha256: str
    plan_review_sha256: str
    approver_actor: str
    gate_revision: int
    issued_at: str
    schema_version: int = 1

    def __post_init__(self) -> None:
        if (
            not isinstance(self.approval_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.approval_id) is None
            or not isinstance(self.run_id, str)
            or not self.run_id
            or not isinstance(self.approver_actor, str)
            or not self.approver_actor
            or type(self.gate_revision) is not int
            or self.gate_revision < 0
            or self.schema_version != 1
        ):
            raise ValueError("plan approval identity is invalid")
        for digest in (
            self.plan_sha256,
            self.manifest_sha256,
            self.plan_review_sha256,
        ):
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise ValueError("plan approval digest is invalid")
        if not isinstance(self.issued_at, str) or not self.issued_at.endswith("Z"):
            raise ValueError("plan approval timestamp is invalid")
        try:
            parsed = datetime.fromisoformat(self.issued_at[:-1] + "+00:00")
        except ValueError as error:
            raise ValueError("plan approval timestamp is invalid") from error
        if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise ValueError("plan approval timestamp is invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "approval_id": self.approval_id,
            "run_id": self.run_id,
            "plan_sha256": self.plan_sha256,
            "manifest_sha256": self.manifest_sha256,
            "plan_review_sha256": self.plan_review_sha256,
            "approver_actor": self.approver_actor,
            "gate_revision": self.gate_revision,
            "issued_at": self.issued_at,
        }


def _plan_approval_from_payload(payload: object) -> PlanApprovalRecord:
    expected = {
        "schema_version",
        "approval_id",
        "run_id",
        "plan_sha256",
        "manifest_sha256",
        "plan_review_sha256",
        "approver_actor",
        "gate_revision",
        "issued_at",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ReconciliationRecoveryError("plan approval schema is invalid")
    try:
        record = PlanApprovalRecord(**payload)
    except (TypeError, ValueError) as error:
        raise ReconciliationRecoveryError("plan approval is invalid") from error
    stable = record.to_dict()
    stable.pop("approval_id")
    if _digest(stable) != record.approval_id:
        raise ReconciliationRecoveryError("plan approval digest is invalid")
    return record


def _passing_plan_review(
    store: StateStore,
    subject: EvidenceSubject,
) -> tuple[dict[str, object], str]:
    path = store.run_directory / "reviews" / "plan-review.json"
    report, raw = _read_private_canonical_json(
        path,
        root=store.trusted_root,
        label="plan review",
    )
    expected = {
        "schema_version",
        "review_type",
        "run_id",
        "reviewer_actor",
        "role",
        "subject",
        "subject_digest",
        "verdict",
        "findings",
        "recorded_at",
        "handoff_nonce_sha256",
        "plan_sha256",
    }
    if (
        set(report) != expected
        or report.get("schema_version") != 1
        or report.get("review_type") != "plan"
        or report.get("run_id") != subject.run_id
        or report.get("role") != "plan_critic"
        or report.get("verdict") != "pass"
        or report.get("subject") != subject.to_dict()
        or report.get("subject_digest") != subject.digest()
        or report.get("plan_sha256") != subject.plan_sha256
        or not isinstance(report.get("reviewer_actor"), str)
        or not report["reviewer_actor"]
    ):
        raise ReconciliationError("a current passing plan review is required")
    handoff_digest = report.get("handoff_nonce_sha256")
    if (
        not isinstance(handoff_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", handoff_digest) is None
    ):
        raise ReconciliationRecoveryError("plan review handoff identity is invalid")
    handoff, _ = _read_private_canonical_json(
        store.run_directory / "handoffs" / f"{handoff_digest}.json",
        root=store.trusted_root,
        label="plan review handoff",
    )
    handoff_keys = {
        "schema_version",
        "run_id",
        "role",
        "source_actor",
        "subject",
        "subject_digest",
        "nonce_sha256",
        "issued_at",
        "consumed_at",
        "consumed_by",
    }
    if (
        set(handoff) != handoff_keys
        or handoff.get("schema_version") != 1
        or handoff.get("run_id") != subject.run_id
        or handoff.get("role") != "plan_critic"
        or handoff.get("nonce_sha256") != handoff_digest
        or handoff.get("subject") != subject.to_dict()
        or handoff.get("subject_digest") != subject.digest()
        or handoff.get("consumed_by") != report["reviewer_actor"]
        or handoff.get("consumed_at") != report.get("recorded_at")
        or handoff.get("source_actor") == report["reviewer_actor"]
        or not isinstance(handoff.get("source_actor"), str)
        or not handoff["source_actor"]
    ):
        raise ReconciliationRecoveryError("plan review handoff is stale or invalid")
    validate_completed_review_publication(
        store,
        report,
        review_type="plan",
    )
    return report, hashlib.sha256(raw).hexdigest()


def _load_plan_approval_file(
    path: Path,
    *,
    root: Path | PrivateRootAnchor,
) -> PlanApprovalRecord:
    payload, _ = _read_private_canonical_json(
        path,
        root=root,
        label="plan approval",
    )
    record = _plan_approval_from_payload(payload)
    if path.name != f"{record.approval_id}.json":
        raise ReconciliationRecoveryError("plan approval filename is invalid")
    return record


_PLAN_APPROVAL_OPERATION_KEYS = {
    "schema_version",
    "stage",
    "request",
    "request_digest",
    "record",
    "record_digest",
    "approval_path",
    "expected_revision",
    "target_phase",
}
_PLAN_APPROVAL_OPERATION_STAGES = {
    "prepared": 0,
    "approval-sealed": 1,
    "state-transitioned": 2,
}


def _plan_approval_operation_path(store: StateStore) -> Path:
    return store.run_directory / "plan-approval-operation.json"


def _load_plan_approval_operation(
    store: StateStore,
) -> dict[str, object] | None:
    path = _plan_approval_operation_path(store)
    if not _private_path_exists(path, root=store.trusted_root):
        return None
    payload, _ = _read_private_canonical_json(
        path,
        root=store.trusted_root,
        label="plan approval operation",
    )
    if (
        set(payload) != _PLAN_APPROVAL_OPERATION_KEYS
        or payload.get("schema_version") != 1
        or payload.get("stage") not in _PLAN_APPROVAL_OPERATION_STAGES
        or not isinstance(payload.get("request"), dict)
        or not isinstance(payload.get("record"), dict)
        or payload.get("request_digest") != _digest(payload["request"])
        or payload.get("record_digest") != _digest(payload["record"])
        or type(payload.get("expected_revision")) is not int
        or payload.get("target_phase") != Phase.DEVELOPING.value
        or not isinstance(payload.get("approval_path"), str)
    ):
        raise ReconciliationRecoveryError(
            "plan approval publication receipt is invalid"
        )
    record = _plan_approval_from_payload(payload["record"])
    expected_path = (
        store.run_directory / "approvals" / "plan" / f"{record.approval_id}.json"
    )
    if payload["approval_path"] != str(expected_path):
        raise ReconciliationRecoveryError("plan approval publication path is invalid")
    return payload


def _write_plan_approval_operation_stage(
    store: StateStore,
    operation: dict[str, object],
    *,
    stage: str,
) -> dict[str, object]:
    changed = dict(operation)
    changed["stage"] = stage
    _write_private_json(
        _plan_approval_operation_path(store),
        changed,
        trusted_root=store.trusted_root,
        immutable=False,
    )
    return changed


def _latest_plan_gate_revision(store: StateStore) -> int:
    gates = [
        event
        for event in store.events()
        if event.event_type == "phase.transitioned"
        and event.previous_phase is Phase.PLAN_REVIEW
        and event.phase is Phase.AWAITING_PLAN_APPROVAL
    ]
    if not gates:
        raise ReconciliationRecoveryError(
            "plan approval gate is not bound to the state WAL"
        )
    return gates[-1].revision


def _plan_approval_request(
    *,
    run_id: str,
    subject: EvidenceSubject,
    plan_review_sha256: str,
    approver_actor: str,
    gate_revision: int,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "plan_sha256": subject.plan_sha256,
        "manifest_sha256": subject.manifest_sha256,
        "plan_review_sha256": plan_review_sha256,
        "approver_actor": approver_actor,
        "gate_revision": gate_revision,
    }


_PLAN_APPROVAL_REQUEST_KEYS = {
    "schema_version",
    "run_id",
    "plan_sha256",
    "manifest_sha256",
    "plan_review_sha256",
    "approver_actor",
    "gate_revision",
}


def _recover_pending_plan_approval_for_reconciliation(
    store: StateStore,
    *,
    current_subject: EvidenceSubject,
) -> PlanApprovalRecord | None:
    """Finish a self-contained plan-approval publication without user input."""

    operation = _load_plan_approval_operation(store)
    if operation is None:
        return None
    request = operation.get("request")
    if not isinstance(request, dict) or set(request) != _PLAN_APPROVAL_REQUEST_KEYS:
        raise ReconciliationRecoveryError("pending plan approval request is invalid")
    approver_actor = request.get("approver_actor")
    gate_revision = request.get("gate_revision")
    if (
        request.get("schema_version") != 1
        or request.get("run_id") != current_subject.run_id
        or request.get("plan_sha256") != current_subject.plan_sha256
        or request.get("manifest_sha256") != current_subject.manifest_sha256
        or not isinstance(approver_actor, str)
        or not approver_actor
        or type(gate_revision) is not int
        or gate_revision != _latest_plan_gate_revision(store)
    ):
        raise ReconciliationRecoveryError(
            "pending plan approval request is stale or invalid"
        )
    expected_request = _plan_approval_request(
        run_id=current_subject.run_id,
        subject=current_subject,
        plan_review_sha256=str(request.get("plan_review_sha256")),
        approver_actor=approver_actor,
        gate_revision=gate_revision,
    )
    if expected_request != request:
        raise ReconciliationRecoveryError(
            "pending plan approval request is stale or invalid"
        )
    return _recover_plan_approval_publication(
        store,
        operation=operation,
        request=request,
        current_subject=current_subject,
    )


def _record_matches_request(
    record: PlanApprovalRecord,
    request: dict[str, object],
) -> bool:
    return (
        all(
            getattr(record, key) == value
            for key, value in request.items()
            if key != "schema_version"
        )
        and record.schema_version == request["schema_version"]
    )


def _matching_plan_approvals(
    store: StateStore,
    request: dict[str, object],
) -> tuple[PlanApprovalRecord, ...]:
    directory = store.run_directory / "approvals" / "plan"
    if not _private_path_exists(directory, root=store.trusted_root):
        return ()
    names = _private_directory_names(
        directory,
        trusted_root=store.trusted_root,
    )
    if any(re.fullmatch(r"[0-9a-f]{64}\.json", name) is None for name in names):
        raise ReconciliationRecoveryError("plan approval directory has unknown files")
    records = tuple(
        _load_plan_approval_file(directory / name, root=store.trusted_root)
        for name in names
    )
    return tuple(
        record for record in records if _record_matches_request(record, request)
    )


def _recover_plan_approval_publication(
    store: StateStore,
    *,
    operation: dict[str, object],
    request: dict[str, object],
    current_subject: EvidenceSubject,
) -> PlanApprovalRecord:
    if operation["request"] != request:
        raise ReconciliationRecoveryError(
            "pending plan approval belongs to a different request"
        )
    _, current_review_sha256 = _passing_plan_review(store, current_subject)
    if current_review_sha256 != request["plan_review_sha256"]:
        raise ReconciliationRecoveryError(
            "pending plan approval review evidence changed"
        )
    record = _plan_approval_from_payload(operation["record"])
    if not _record_matches_request(record, request):
        raise ReconciliationRecoveryError(
            "pending plan approval record differs from its request"
        )
    approval_path = Path(str(operation["approval_path"]))
    stage = str(operation["stage"])
    if _private_path_exists(approval_path, root=store.trusted_root):
        sealed = _load_plan_approval_file(
            approval_path,
            root=store.trusted_root,
        )
        if sealed != record:
            raise ReconciliationRecoveryError(
                "plan approval differs from its immutable seal"
            )
    elif stage == "prepared":
        try:
            _write_private_json(
                approval_path,
                record.to_dict(),
                trusted_root=store.trusted_root,
                immutable=True,
            )
        except Exception as error:
            raise ReconciliationRecoveryError(
                "plan approval could not be sealed"
            ) from error
    else:
        raise ReconciliationRecoveryError("sealed plan approval is missing")
    if (
        _PLAN_APPROVAL_OPERATION_STAGES[stage]
        < _PLAN_APPROVAL_OPERATION_STAGES["approval-sealed"]
    ):
        operation = _write_plan_approval_operation_stage(
            store,
            operation,
            stage="approval-sealed",
        )

    state = store.load()
    expected_revision = int(operation["expected_revision"])
    source_state = (
        state.phase is Phase.AWAITING_PLAN_APPROVAL
        and state.revision == expected_revision
    )
    target_state = (
        state.phase is Phase.DEVELOPING and state.revision == expected_revision + 1
    )
    if source_state:
        store.transition(Phase.DEVELOPING, expected_revision=expected_revision)
    elif not target_state:
        raise ReconciliationRecoveryError(
            "plan approval state differs from its publication receipt"
        )
    if (
        _PLAN_APPROVAL_OPERATION_STAGES[str(operation["stage"])]
        < _PLAN_APPROVAL_OPERATION_STAGES["state-transitioned"]
    ):
        _write_plan_approval_operation_stage(
            store,
            operation,
            stage="state-transitioned",
        )
    _remove_private_file(
        _plan_approval_operation_path(store),
        trusted_root=store.trusted_root,
    )
    return record


def record_plan_approval(
    store: StateStore,
    *,
    current_subject: EvidenceSubject,
    approver_actor: str,
) -> PlanApprovalRecord:
    if not isinstance(approver_actor, str) or not approver_actor.strip():
        raise ReconciliationError("plan approver actor must be a non-empty string")
    lock = FileLock(
        store.run_directory / "plan-approval.lock",
        private_root=store.run_directory,
    )
    with lock as acquired_lock, store.anchored(acquired_lock.trusted_parent):
        state = store.load()
        if state.run_id != current_subject.run_id:
            raise ReconciliationError("plan approval belongs to another run")
        gate_revision = _latest_plan_gate_revision(store)
        if (
            state.phase is Phase.AWAITING_PLAN_APPROVAL
            and state.revision != gate_revision
        ):
            raise ReconciliationRecoveryError(
                "plan approval gate revision differs from current state"
            )
        if state.phase not in {Phase.AWAITING_PLAN_APPROVAL, Phase.DEVELOPING}:
            raise ReconciliationError(
                "plan approval requires its approval gate or recovered target state"
            )
        _, plan_review_sha256 = _passing_plan_review(store, current_subject)
        request = _plan_approval_request(
            run_id=state.run_id,
            subject=current_subject,
            plan_review_sha256=plan_review_sha256,
            approver_actor=approver_actor.strip(),
            gate_revision=gate_revision,
        )
        pending = _load_plan_approval_operation(store)
        if pending is not None:
            return _recover_plan_approval_publication(
                store,
                operation=pending,
                request=request,
                current_subject=current_subject,
            )
        matching = _matching_plan_approvals(store, request)
        if state.phase is Phase.DEVELOPING:
            if len(matching) != 1:
                raise ReconciliationRecoveryError(
                    "completed plan approval seal set is invalid"
                )
            return matching[0]
        if matching:
            raise ReconciliationRecoveryError(
                "orphan plan approval seal requires manual reconciliation"
            )
        provisional: dict[str, object] = {
            "schema_version": 1,
            "run_id": state.run_id,
            "plan_sha256": current_subject.plan_sha256,
            "manifest_sha256": current_subject.manifest_sha256,
            "plan_review_sha256": plan_review_sha256,
            "approver_actor": approver_actor.strip(),
            "gate_revision": state.revision,
            "issued_at": _utc_now(),
        }
        record = PlanApprovalRecord(
            approval_id=_digest(provisional),
            **provisional,
        )
        approval_path = (
            store.run_directory / "approvals" / "plan" / f"{record.approval_id}.json"
        )
        operation: dict[str, object] = {
            "schema_version": 1,
            "stage": "prepared",
            "request": request,
            "request_digest": _digest(request),
            "record": record.to_dict(),
            "record_digest": _digest(record.to_dict()),
            "approval_path": str(approval_path),
            "expected_revision": state.revision,
            "target_phase": Phase.DEVELOPING.value,
        }
        _write_plan_approval_operation_stage(
            store,
            operation,
            stage="prepared",
        )
        return _recover_plan_approval_publication(
            store,
            operation=operation,
            request=request,
            current_subject=current_subject,
        )


def _read_private_bytes(path: Path, *, label: str) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ReconciliationRecoveryError(f"{label} cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ReconciliationRecoveryError(f"{label} is not a regular private file")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65_536, 1_048_577 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > 1_048_576:
                raise ReconciliationRecoveryError(f"{label} is too large")
        current = os.stat(path, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
            raise ReconciliationRecoveryError(f"{label} changed while loading")
        return b"".join(chunks)
    except ReconciliationRecoveryError:
        raise
    except OSError as error:
        raise ReconciliationRecoveryError(f"{label} cannot be inspected") from error
    finally:
        os.close(descriptor)


def _git_read(repo: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ("git", *arguments),
            cwd=repo,
            check=False,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        raise ReconciliationRecoveryError(
            "run Git evidence cannot be inspected"
        ) from error
    if completed.returncode != 0:
        raise ReconciliationRecoveryError("run Git evidence cannot be inspected")
    return completed.stdout.removesuffix("\n")


def _plan_review_digest_for_approval(
    store: StateStore,
    *,
    run_id: str,
) -> tuple[EvidenceSubject, str]:
    path = store.run_directory / "reviews" / "plan-review.json"
    payload, _ = _read_private_canonical_json(
        path,
        root=store.trusted_root,
        label="plan review",
    )
    subject_payload = payload.get("subject")
    try:
        if not isinstance(subject_payload, dict):
            raise TypeError
        review_subject = EvidenceSubject(**subject_payload)
    except (TypeError, ValueError) as error:
        raise ReconciliationRecoveryError("plan review subject is invalid") from error
    if review_subject.run_id != run_id:
        raise ReconciliationRecoveryError("plan review belongs to another run")
    _, digest = _passing_plan_review(store, review_subject)
    return review_subject, digest


@dataclass(frozen=True)
class _LiveObservation:
    ownership: WorktreeOwnership
    manifest: Manifest
    variables: Mapping[str, str]
    subject: EvidenceSubject
    dirty: bool
    base_drift: bool


@dataclass(frozen=True)
class _PlanEvidenceInspection:
    status: EvidenceStatus
    approval: PlanApprovalRecord | None
    review_subject: EvidenceSubject | None
    reason: str


def _open_run_directory(
    repository: GitRepository,
    run_id: str,
) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(repository.git_common_directory, flags)
        for component in ("ship-flow", "runs", run_id):
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise ReconciliationRecoveryError(
            "run state directory cannot be opened safely"
        ) from error


def _run_directory_is_current(descriptor: int, path: Path) -> bool:
    try:
        opened = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISDIR(opened.st_mode)
        and stat.S_ISDIR(current.st_mode)
        and not stat.S_ISLNK(current.st_mode)
        and (opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino)
    )


_RUNTIME_EVIDENCE_DIRECTORIES = frozenset(
    {
        "approvals",
        "handoffs",
        "logs",
        "release-cycles",
        "review-publications",
        "reviews",
        "sync-publications",
        "verification-executions",
        "verification-publications",
        "verifications",
    }
)


def _runtime_evidence_ancestors_are_safe(run_descriptor: int) -> bool:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        names = set(os.listdir(run_descriptor))
        for name in names & _RUNTIME_EVIDENCE_DIRECTORIES:
            metadata = os.stat(
                name,
                dir_fd=run_descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                return False
            descriptor = os.open(name, flags, dir_fd=run_descriptor)
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISDIR(opened.st_mode) or (
                    opened.st_dev,
                    opened.st_ino,
                ) != (metadata.st_dev, metadata.st_ino):
                    return False
            finally:
                os.close(descriptor)
        return True
    except OSError:
        return False


def _read_private_bytes_at(
    directory_descriptor: int,
    name: str,
    *,
    label: str,
) -> bytes:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ReconciliationRecoveryError(f"{label} has an unsafe name")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    except OSError as error:
        raise ReconciliationRecoveryError(f"{label} cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > 1_048_576
        ):
            raise ReconciliationRecoveryError(f"{label} is not a bounded private file")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65_536, 1_048_577 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > 1_048_576:
                raise ReconciliationRecoveryError(f"{label} is too large")
        current = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
            raise ReconciliationRecoveryError(f"{label} changed while loading")
        return b"".join(chunks)
    except ReconciliationRecoveryError:
        raise
    except OSError as error:
        raise ReconciliationRecoveryError(f"{label} cannot be inspected") from error
    finally:
        os.close(descriptor)


def _load_safe_manifest(worktree: Path) -> Manifest:
    ship_path = worktree / ".ship"
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    ship_descriptor = -1
    manifest_descriptor = -1
    try:
        ship_descriptor = os.open(ship_path, directory_flags)
        ship_metadata = os.fstat(ship_descriptor)
        manifest_descriptor = os.open(
            "manifest.toml",
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=ship_descriptor,
        )
        manifest_metadata = os.fstat(manifest_descriptor)
        if not stat.S_ISREG(manifest_metadata.st_mode):
            raise ReconciliationRecoveryError(
                "confirmed manifest is not a regular file"
            )
        descriptor_path = Path(f"/dev/fd/{manifest_descriptor}")
        try:
            manifest = load_manifest(descriptor_path)
        except (OSError, ValueError) as error:
            raise ReconciliationRecoveryError(
                "confirmed manifest cannot be normalized"
            ) from error
        current_ship = os.stat(ship_path, follow_symlinks=False)
        current_manifest = os.stat(
            "manifest.toml",
            dir_fd=ship_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(current_ship.st_mode)
            or (ship_metadata.st_dev, ship_metadata.st_ino)
            != (current_ship.st_dev, current_ship.st_ino)
            or (manifest_metadata.st_dev, manifest_metadata.st_ino)
            != (current_manifest.st_dev, current_manifest.st_ino)
        ):
            raise ReconciliationRecoveryError(
                "confirmed manifest changed while loading"
            )
        return manifest
    except ReconciliationRecoveryError:
        raise
    except OSError as error:
        raise ReconciliationRecoveryError(
            "confirmed manifest is missing or unsafe"
        ) from error
    finally:
        if manifest_descriptor >= 0:
            os.close(manifest_descriptor)
        if ship_descriptor >= 0:
            os.close(ship_descriptor)


def _observe_live_run(
    ownership: WorktreeOwnership,
    *,
    run_descriptor: int,
    engine_version: str,
    evidence_schema_version: int,
) -> _LiveObservation:
    plan_bytes = _read_private_bytes_at(
        run_descriptor,
        "plan.md",
        label="run plan",
    )
    manifest = _load_safe_manifest(ownership.worktree_path)
    variables: Mapping[str, str] = {
        "repo": str(ownership.primary_checkout),
        "worktree": str(ownership.worktree_path),
        "branch": ownership.branch,
        "base_branch": manifest.base_branch,
        "remote": manifest.remote,
    }
    candidate_oid = _git_read(
        ownership.worktree_path,
        "rev-parse",
        "--verify",
        "HEAD^{commit}",
    )
    tree_oid = _git_read(
        ownership.worktree_path,
        "rev-parse",
        "--verify",
        "HEAD^{tree}",
    )
    dirty = bool(
        _git_read(
            ownership.worktree_path,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        )
    )
    live_base_oid = _git_read(
        ownership.worktree_path,
        "rev-parse",
        "--verify",
        f"refs/heads/{manifest.base_branch}^{{commit}}",
    )
    subject = EvidenceSubject(
        run_id=ownership.run_id,
        base_oid=ownership.base_oid,
        candidate_oid=candidate_oid,
        tree_oid=tree_oid,
        plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
        manifest_sha256=manifest_digest(manifest),
        commands_sha256=verification_commands_digest(manifest, variables),
        engine_version=engine_version,
        schema_version=evidence_schema_version,
    )
    return _LiveObservation(
        ownership=ownership,
        manifest=manifest,
        variables=variables,
        subject=subject,
        dirty=dirty,
        base_drift=live_base_oid != ownership.base_oid,
    )


def _approval_transition_events(store: StateStore) -> tuple[object, ...]:
    return tuple(
        event
        for event in store.events()
        if event.event_type == "phase.transitioned"
        and event.previous_phase is Phase.AWAITING_PLAN_APPROVAL
        and event.phase is Phase.DEVELOPING
    )


def _inspect_plan_evidence(
    store: StateStore,
    *,
    state: RunState,
    current_subject: EvidenceSubject,
) -> _PlanEvidenceInspection:
    plan_review_path = store.run_directory / "reviews" / "plan-review.json"
    try:
        review_subject, review_sha256 = _plan_review_digest_for_approval(
            store,
            run_id=state.run_id,
        )
    except ReconciliationRecoveryError:
        try:
            review_exists = _private_path_exists(
                plan_review_path,
                root=store.trusted_root,
            )
        except ReconciliationRecoveryError:
            review_exists = True
        status = EvidenceStatus.INVALID if review_exists else EvidenceStatus.MISSING
        return _PlanEvidenceInspection(
            status=status,
            approval=None,
            review_subject=None,
            reason=f"plan-review-evidence-{status.value}",
        )
    if (
        current_subject.plan_sha256 != review_subject.plan_sha256
        or current_subject.manifest_sha256 != review_subject.manifest_sha256
    ):
        return _PlanEvidenceInspection(
            status=EvidenceStatus.STALE,
            approval=None,
            review_subject=review_subject,
            reason="plan-or-manifest-drift",
        )
    gate_events = tuple(
        event
        for event in store.events()
        if event.event_type == "phase.transitioned"
        and event.previous_phase is Phase.PLAN_REVIEW
        and event.phase is Phase.AWAITING_PLAN_APPROVAL
    )
    if not gate_events:
        return _PlanEvidenceInspection(
            status=EvidenceStatus.INVALID,
            approval=None,
            review_subject=review_subject,
            reason="plan-approval-gate-missing",
        )
    gate_revision = gate_events[-1].revision
    approval_events = _approval_transition_events(store)
    current_approval_events = tuple(
        event for event in approval_events if event.revision == gate_revision + 1
    )
    if len(current_approval_events) > 1:
        return _PlanEvidenceInspection(
            status=EvidenceStatus.INVALID,
            approval=None,
            review_subject=review_subject,
            reason="plan-approval-transition-invalid",
        )
    try:
        publication_incomplete = _private_path_exists(
            _plan_approval_operation_path(store),
            root=store.trusted_root,
        )
    except ReconciliationRecoveryError:
        publication_incomplete = True
    if publication_incomplete:
        return _PlanEvidenceInspection(
            status=EvidenceStatus.INVALID,
            approval=None,
            review_subject=review_subject,
            reason="plan-approval-publication-incomplete",
        )
    directory = store.run_directory / "approvals" / "plan"
    try:
        directory_exists = _private_path_exists(
            directory,
            root=store.trusted_root,
        )
    except ReconciliationRecoveryError:
        return _PlanEvidenceInspection(
            status=EvidenceStatus.INVALID,
            approval=None,
            review_subject=review_subject,
            reason="plan-approval-evidence-invalid",
        )
    if not directory_exists:
        awaiting = (
            state.phase is Phase.AWAITING_PLAN_APPROVAL and not current_approval_events
        )
        return _PlanEvidenceInspection(
            status=EvidenceStatus.MISSING,
            approval=None,
            review_subject=review_subject,
            reason=(
                "awaiting-plan-approval"
                if awaiting
                else "plan-approval-evidence-missing"
            ),
        )
    try:
        names = _private_directory_names(
            directory,
            trusted_root=store.trusted_root,
        )
        if any(re.fullmatch(r"[0-9a-f]{64}\.json", name) is None for name in names):
            raise ReconciliationRecoveryError(
                "plan approval directory has unknown evidence"
            )
        records = tuple(
            _load_plan_approval_file(
                directory / name,
                root=store.trusted_root,
            )
            for name in names
        )
    except (OSError, ReconciliationRecoveryError):
        return _PlanEvidenceInspection(
            status=EvidenceStatus.INVALID,
            approval=None,
            review_subject=review_subject,
            reason="plan-approval-evidence-invalid",
        )
    if state.phase is Phase.AWAITING_PLAN_APPROVAL and not current_approval_events:
        current_orphans = tuple(
            record
            for record in records
            if record.run_id == state.run_id
            and record.plan_sha256 == current_subject.plan_sha256
            and record.manifest_sha256 == current_subject.manifest_sha256
            and record.plan_review_sha256 == review_sha256
            and record.gate_revision == gate_revision
        )
        if current_orphans:
            return _PlanEvidenceInspection(
                status=EvidenceStatus.INVALID,
                approval=None,
                review_subject=review_subject,
                reason="orphan-plan-approval-evidence",
            )
        return _PlanEvidenceInspection(
            status=EvidenceStatus.MISSING,
            approval=None,
            review_subject=review_subject,
            reason="awaiting-plan-approval",
        )
    if not current_approval_events:
        return _PlanEvidenceInspection(
            status=EvidenceStatus.INVALID,
            approval=None,
            review_subject=review_subject,
            reason="plan-approval-wal-missing",
        )
    if not records:
        return _PlanEvidenceInspection(
            status=EvidenceStatus.MISSING,
            approval=None,
            review_subject=review_subject,
            reason="plan-approval-evidence-missing",
        )
    matching = tuple(
        record
        for record in records
        if record.run_id == state.run_id
        and record.plan_sha256 == current_subject.plan_sha256
        and record.manifest_sha256 == current_subject.manifest_sha256
        and record.plan_review_sha256 == review_sha256
        and record.gate_revision == gate_revision
    )
    if len(matching) != 1:
        return _PlanEvidenceInspection(
            status=EvidenceStatus.INVALID,
            approval=None,
            review_subject=review_subject,
            reason="plan-approval-evidence-invalid",
        )
    return _PlanEvidenceInspection(
        status=EvidenceStatus.CURRENT,
        approval=matching[0],
        review_subject=review_subject,
        reason="plan-approval-is-current",
    )


class EvidenceStatus(str, Enum):
    CURRENT = "current"
    RECOVERABLE = "recoverable"
    STALE = "stale"
    MISSING = "missing"
    INVALID = "invalid"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class EvidenceInventory:
    plan_approval: EvidenceStatus
    code_review: EvidenceStatus
    verification: EvidenceStatus
    release_or_external: EvidenceStatus
    sync: EvidenceStatus

    @classmethod
    def not_applicable(cls) -> EvidenceInventory:
        return cls(
            plan_approval=EvidenceStatus.NOT_APPLICABLE,
            code_review=EvidenceStatus.NOT_APPLICABLE,
            verification=EvidenceStatus.NOT_APPLICABLE,
            release_or_external=EvidenceStatus.NOT_APPLICABLE,
            sync=EvidenceStatus.NOT_APPLICABLE,
        )


@dataclass(frozen=True)
class ReconciledRun:
    state: RunState
    ownership: WorktreeOwnership | None
    manifest: Manifest | None
    subject: EvidenceSubject | None
    plan_approval: PlanApprovalRecord | None
    dirty: bool | None
    reason: str
    evidence: EvidenceInventory


@dataclass(frozen=True)
class NextAction:
    phase: Phase
    kind: str
    action: str


_NEXT_ACTIONS: Mapping[Phase, tuple[str, str]] = {
    Phase.INITIALIZED: ("automatic", "initialize_plan"),
    Phase.PLANNING: ("automatic", "prepare_plan"),
    Phase.PLAN_REVIEW: ("automatic", "review_plan"),
    Phase.AWAITING_PLAN_APPROVAL: ("human", "approve_plan"),
    Phase.AWAITING_SCOPE_APPROVAL: ("human", "approve_scope_change"),
    Phase.DEVELOPING: ("automatic", "develop"),
    Phase.CODE_REVIEW: ("automatic", "review_code"),
    Phase.VERIFYING: ("automatic", "verify"),
    Phase.AWAITING_RELEASE_APPROVAL: ("human", "approve_release"),
    Phase.RELEASING: ("automatic", "resume_release"),
    Phase.POST_RELEASE_VERIFYING: ("automatic", "verify_release"),
    Phase.ROLLBACK_PENDING: ("human", "approve_rollback"),
    Phase.ROLLING_BACK: ("automatic", "resume_rollback"),
    Phase.ROLLBACK_VERIFYING: ("automatic", "verify_rollback"),
    Phase.ROLLED_BACK: ("terminal", "none"),
    Phase.SYNCING: ("automatic", "sync_project"),
    Phase.AWAITING_CLEANUP_APPROVAL: ("human", "approve_cleanup"),
    Phase.COMPLETED: ("terminal", "none"),
    Phase.BLOCKED: ("manual", "manual_reconciliation"),
    Phase.CANCELLED: ("terminal", "none"),
}


class Reconciler:
    def __init__(
        self,
        repository: GitRepository | Path | str,
        *,
        engine_version: str = "0.1.0",
        evidence_schema_version: int = 1,
    ) -> None:
        self.repository = (
            repository
            if isinstance(repository, GitRepository)
            else GitRepository.discover(repository)
        )
        if not isinstance(engine_version, str) or not engine_version.strip():
            raise ValueError("engine_version must be a non-empty string")
        if type(evidence_schema_version) is not int or evidence_schema_version < 1:
            raise ValueError("evidence_schema_version must be positive")
        self.engine_version = engine_version
        self.evidence_schema_version = evidence_schema_version

    def reconcile(self, run_id: str) -> ReconciledRun:
        if (
            not isinstance(run_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id) is None
        ):
            raise ValueError("run_id contains unsafe characters")
        run_directory = (
            self.repository.git_common_directory / "ship-flow" / "runs" / run_id
        )
        run_descriptor = _open_run_directory(self.repository, run_id)
        store = StateStore(run_directory)
        run_anchor = ExitStack()
        try:
            run_anchor.enter_context(
                store.anchored(PrivateRootAnchor(run_directory, run_descriptor))
            )
        except BaseException:
            os.close(run_descriptor)
            raise

        def state_only_result(state: RunState, reason: str) -> ReconciledRun:
            return ReconciledRun(
                state=state,
                ownership=None,
                manifest=None,
                subject=None,
                plan_approval=None,
                dirty=None,
                reason=reason,
                evidence=EvidenceInventory.not_applicable(),
            )

        def completed_sync_result(
            state: RunState,
            *,
            status: EvidenceStatus,
            reason: str,
            subject: EvidenceSubject | None = None,
        ) -> ReconciledRun:
            return ReconciledRun(
                state=state,
                ownership=None,
                manifest=None,
                subject=subject,
                plan_approval=None,
                dirty=None,
                reason=reason,
                evidence=EvidenceInventory(
                    plan_approval=EvidenceStatus.NOT_APPLICABLE,
                    code_review=EvidenceStatus.NOT_APPLICABLE,
                    verification=EvidenceStatus.NOT_APPLICABLE,
                    release_or_external=EvidenceStatus.NOT_APPLICABLE,
                    sync=status,
                ),
            )

        pre_evidence_phases = {
            Phase.INITIALIZED,
            Phase.PLANNING,
            Phase.AWAITING_SCOPE_APPROVAL,
        }
        terminal_phases = {
            Phase.BLOCKED,
            Phase.CANCELLED,
        }
        successful_terminal_phases = {Phase.COMPLETED, Phase.ROLLED_BACK}
        external_phases = {
            Phase.RELEASING,
            Phase.POST_RELEASE_VERIFYING,
            Phase.ROLLBACK_PENDING,
            Phase.ROLLING_BACK,
            Phase.ROLLBACK_VERIFYING,
            Phase.ROLLED_BACK,
        }
        code_required_phases = {
            Phase.VERIFYING,
            Phase.AWAITING_RELEASE_APPROVAL,
            *external_phases,
            Phase.SYNCING,
            Phase.AWAITING_CLEANUP_APPROVAL,
            Phase.COMPLETED,
        }
        verification_required_phases = {
            Phase.AWAITING_RELEASE_APPROVAL,
            *external_phases,
            Phase.SYNCING,
            Phase.AWAITING_CLEANUP_APPROVAL,
            Phase.COMPLETED,
        }

        def complete(
            *,
            source_state: RunState,
            target: Phase,
            reason: str,
            observation: _LiveObservation,
            plan_approval: PlanApprovalRecord | None,
            inventory: EvidenceInventory,
        ) -> ReconciledRun:
            changed = source_state
            if (
                target is not source_state.phase
                and source_state.phase not in successful_terminal_phases
            ):
                changed = store.reconcile_transition(
                    target,
                    expected_revision=source_state.revision,
                    reason=reason,
                )
            return ReconciledRun(
                state=changed,
                ownership=observation.ownership,
                manifest=observation.manifest,
                subject=observation.subject,
                plan_approval=plan_approval,
                dirty=observation.dirty,
                reason=reason,
                evidence=inventory,
            )

        def block_without_observation(
            state: RunState,
            *,
            reason: str,
        ) -> ReconciledRun:
            changed = state
            if state.phase not in {Phase.BLOCKED, *successful_terminal_phases}:
                changed = store.reconcile_transition(
                    Phase.BLOCKED,
                    expected_revision=state.revision,
                    reason=reason,
                )
            invalid = EvidenceInventory(
                plan_approval=EvidenceStatus.INVALID,
                code_review=EvidenceStatus.NOT_APPLICABLE,
                verification=EvidenceStatus.NOT_APPLICABLE,
                release_or_external=EvidenceStatus.NOT_APPLICABLE,
                sync=EvidenceStatus.NOT_APPLICABLE,
            )
            return ReconciledRun(
                state=changed,
                ownership=None,
                manifest=None,
                subject=None,
                plan_approval=None,
                dirty=None,
                reason=reason,
                evidence=invalid,
            )

        try:
            initial_state = store.load()
            if initial_state.run_id != run_id:
                raise ReconciliationRecoveryError("run state belongs to another run")
            if not _run_directory_is_current(run_descriptor, run_directory):
                raise ReconciliationRecoveryError(
                    "run state directory changed while loading"
                )
            AuthorizationStore(store).recover_pending_transition()
            initial_state = store.load()
            if initial_state.run_id != run_id:
                raise ReconciliationRecoveryError("run state belongs to another run")
            if not _run_directory_is_current(run_descriptor, run_directory):
                raise ReconciliationRecoveryError(
                    "run state directory changed while loading"
                )
            if initial_state.phase in pre_evidence_phases:
                return state_only_result(initial_state, "state-is-current")
            if initial_state.phase in terminal_phases:
                persisted_reason = None
                if initial_state.phase is Phase.BLOCKED:
                    latest_event = store.events()[-1]
                    if (
                        latest_event.event_type == "phase.reconciled"
                        and latest_event.phase is Phase.BLOCKED
                    ):
                        persisted_reason = latest_event.reconciliation_reason
                return state_only_result(
                    initial_state,
                    (
                        persisted_reason or "run-is-blocked"
                        if initial_state.phase is Phase.BLOCKED
                        else "run-is-terminal"
                    ),
                )

            with ExitStack() as publication_locks:
                try:
                    publication_locks.enter_context(
                        FileLock.repository(self.repository.git_common_directory)
                    )
                    for lock_name in (
                        "release-publication.lock",
                        "approval-publication.lock",
                        "plan-approval.lock",
                        "review-publication.lock",
                        "verification.lock",
                        "sync-publication.lock",
                    ):
                        publication_locks.enter_context(
                            FileLock.at(
                                run_descriptor,
                                lock_name,
                                display_path=run_directory / lock_name,
                            )
                        )
                except LockUnavailableError:
                    return state_only_result(
                        initial_state,
                        "publication-in-progress",
                    )
                for _attempt in range(3):
                    state = store.load()
                    if state.run_id != run_id:
                        raise ReconciliationRecoveryError(
                            "run state belongs to another run"
                        )
                    if state.phase in pre_evidence_phases:
                        return state_only_result(state, "state-is-current")
                    if state.phase in terminal_phases:
                        persisted_reason = None
                        if state.phase is Phase.BLOCKED:
                            latest_event = store.events()[-1]
                            if (
                                latest_event.event_type == "phase.reconciled"
                                and latest_event.phase is Phase.BLOCKED
                            ):
                                persisted_reason = latest_event.reconciliation_reason
                        return state_only_result(
                            state,
                            (
                                persisted_reason or "run-is-blocked"
                                if state.phase is Phase.BLOCKED
                                else "run-is-terminal"
                            ),
                        )
                    if state.phase is Phase.COMPLETED:

                        def deleted_worktree_subject() -> EvidenceSubject:
                            raise ReconciliationRecoveryError(
                                "completed audit must not consult the deleted worktree"
                            )

                        try:
                            completed_report = _load_current_sync_report_locked(
                                store,
                                None,
                                worktree=run_directory / ".deleted-worktree",
                                current_subject=deleted_worktree_subject,
                                allow_completed=True,
                            )
                        except (RuntimeError, SyncRecoveryError):
                            return completed_sync_result(
                                state,
                                status=EvidenceStatus.INVALID,
                                reason="sync-evidence-invalid",
                            )
                        return completed_sync_result(
                            state,
                            status=EvidenceStatus.CURRENT,
                            reason="terminal-evidence-is-current",
                            subject=completed_report.subject,
                        )
                    try:
                        ownership = _load_run_worktree_locked(
                            self.repository,
                            run_id,
                        )
                        if ownership.record_path.parent != store.run_directory:
                            raise ReconciliationRecoveryError(
                                "run ownership and state directories differ"
                            )
                        observation = _observe_live_run(
                            ownership,
                            run_descriptor=run_descriptor,
                            engine_version=self.engine_version,
                            evidence_schema_version=self.evidence_schema_version,
                        )
                    except Exception:
                        return block_without_observation(
                            state,
                            reason="live-evidence-invalid",
                        )
                    if not _runtime_evidence_ancestors_are_safe(run_descriptor):
                        return block_without_observation(
                            state,
                            reason="runtime-evidence-ancestor-unsafe",
                        )

                    try:
                        recovered_plan_approval = (
                            _recover_pending_plan_approval_for_reconciliation(
                                store,
                                current_subject=observation.subject,
                            )
                        )
                    except ReconciliationRecoveryError:
                        return block_without_observation(
                            state,
                            reason="plan-approval-publication-invalid",
                        )
                    if recovered_plan_approval is not None:
                        continue

                    plan = (
                        _PlanEvidenceInspection(
                            status=EvidenceStatus.NOT_APPLICABLE,
                            approval=None,
                            review_subject=None,
                            reason="awaiting-plan-review",
                        )
                        if state.phase is Phase.PLAN_REVIEW
                        else _inspect_plan_evidence(
                            store,
                            state=state,
                            current_subject=observation.subject,
                        )
                    )
                    try:
                        pending_review_type = validate_recoverable_review_publication(
                            store,
                            observation.subject,
                        )
                    except ReviewEvidenceMissingError:
                        pending_review_type = None
                    except ReviewRecoveryError:
                        return block_without_observation(
                            state,
                            reason="review-publication-invalid",
                        )
                    if pending_review_type is not None:
                        pending_inventory = EvidenceInventory(
                            plan_approval=(
                                EvidenceStatus.RECOVERABLE
                                if pending_review_type == "plan"
                                else plan.status
                            ),
                            code_review=(
                                EvidenceStatus.RECOVERABLE
                                if pending_review_type == "code"
                                else EvidenceStatus.NOT_APPLICABLE
                            ),
                            verification=EvidenceStatus.NOT_APPLICABLE,
                            release_or_external=EvidenceStatus.NOT_APPLICABLE,
                            sync=EvidenceStatus.NOT_APPLICABLE,
                        )
                        return complete(
                            source_state=state,
                            target=state.phase,
                            reason=(
                                f"{pending_review_type}-review-publication-recoverable"
                            ),
                            observation=observation,
                            plan_approval=plan.approval,
                            inventory=pending_inventory,
                        )
                    try:
                        pending_verification = (
                            validate_recoverable_verification_publication(
                                store,
                                manifest=observation.manifest,
                                current_subject=observation.subject,
                                variables=observation.variables,
                            )
                        )
                    except VerificationEvidenceMissingError:
                        pending_verification = None
                    except VerificationRecoveryError:
                        return block_without_observation(
                            state,
                            reason="verification-publication-invalid",
                        )
                    if pending_verification is not None:
                        return complete(
                            source_state=state,
                            target=state.phase,
                            reason="verification-publication-recoverable",
                            observation=observation,
                            plan_approval=plan.approval,
                            inventory=EvidenceInventory(
                                plan_approval=plan.status,
                                code_review=EvidenceStatus.CURRENT,
                                verification=EvidenceStatus.RECOVERABLE,
                                release_or_external=(EvidenceStatus.NOT_APPLICABLE),
                                sync=EvidenceStatus.NOT_APPLICABLE,
                            ),
                        )
                    code_status = (
                        EvidenceStatus.MISSING
                        if state.phase is Phase.CODE_REVIEW
                        else EvidenceStatus.NOT_APPLICABLE
                    )
                    verification_status = (
                        EvidenceStatus.MISSING
                        if state.phase is Phase.VERIFYING
                        else EvidenceStatus.NOT_APPLICABLE
                    )
                    release_status = EvidenceStatus.NOT_APPLICABLE
                    sync_status = (
                        EvidenceStatus.MISSING
                        if state.phase in {Phase.SYNCING, Phase.COMPLETED}
                        else EvidenceStatus.NOT_APPLICABLE
                    )

                    def inventory() -> EvidenceInventory:
                        return EvidenceInventory(
                            plan_approval=plan.status,
                            code_review=code_status,
                            verification=verification_status,
                            release_or_external=release_status,
                            sync=sync_status,
                        )

                    target = state.phase
                    reason = "state-is-current"
                    if observation.base_drift:
                        target = Phase.BLOCKED
                        reason = "base-branch-drift-start-new-run"
                    elif plan.status is EvidenceStatus.STALE:
                        target = (
                            Phase.BLOCKED
                            if state.phase in external_phases
                            else Phase.PLANNING
                        )
                        reason = (
                            "external-phase-plan-or-manifest-drift"
                            if target is Phase.BLOCKED
                            else plan.reason
                        )
                    elif plan.status in {
                        EvidenceStatus.MISSING,
                        EvidenceStatus.INVALID,
                    }:
                        awaiting_plan = (
                            state.phase is Phase.AWAITING_PLAN_APPROVAL
                            and plan.reason == "awaiting-plan-approval"
                        )
                        if awaiting_plan:
                            reason = plan.reason
                        else:
                            target = Phase.BLOCKED
                            reason = plan.reason

                    external_inspection = None
                    if target is state.phase and state.phase is not Phase.PLAN_REVIEW:
                        try:
                            external_inspection = validate_external_operation_evidence(
                                repo=ownership.worktree_path,
                                run_directory=store.run_directory,
                                manifest=observation.manifest,
                                current_subject=observation.subject,
                                variables=observation.variables,
                                phase=state.phase,
                            )
                        except ExternalEvidenceMissingError:
                            release_status = EvidenceStatus.MISSING
                            target = Phase.BLOCKED
                            reason = "external-operation-evidence-missing"
                        except ExternalEvidenceUnknownError:
                            release_status = EvidenceStatus.INVALID
                            target = Phase.BLOCKED
                            reason = "external-operation-unknown"
                        except ReleaseRecoveryError:
                            release_status = EvidenceStatus.INVALID
                            target = Phase.BLOCKED
                            reason = "external-operation-evidence-invalid"

                    if target is state.phase and external_inspection is not None:
                        if external_inspection.recoverable:
                            release_status = EvidenceStatus.RECOVERABLE
                            reason = (
                                "external-cycle-publication-recoverable"
                                if state.phase
                                in {
                                    Phase.AWAITING_RELEASE_APPROVAL,
                                    Phase.ROLLBACK_PENDING,
                                }
                                else "external-health-publication-recoverable"
                            )
                        elif external_inspection.in_flight and (
                            state.phase not in external_phases
                        ):
                            release_status = EvidenceStatus.INVALID
                            target = Phase.BLOCKED
                            reason = "external-operation-in-flight-outside-release"
                        elif state.phase in external_phases:
                            if external_inspection.records or (
                                external_inspection.active_cycle
                                and state.phase in {Phase.RELEASING, Phase.ROLLING_BACK}
                            ):
                                release_status = EvidenceStatus.CURRENT
                            else:
                                release_status = EvidenceStatus.MISSING
                                target = Phase.BLOCKED
                                reason = "external-operation-evidence-missing"
                        elif state.phase is Phase.AWAITING_RELEASE_APPROVAL:
                            release_status = (
                                EvidenceStatus.MISSING
                                if observation.manifest.release_required
                                else EvidenceStatus.NOT_APPLICABLE
                            )
                        elif state.phase in {
                            Phase.SYNCING,
                            Phase.AWAITING_CLEANUP_APPROVAL,
                            Phase.COMPLETED,
                        }:
                            if observation.manifest.release_required:
                                if external_inspection.records:
                                    release_status = EvidenceStatus.CURRENT
                                else:
                                    release_status = EvidenceStatus.MISSING
                                    target = Phase.BLOCKED
                                    reason = "external-operation-evidence-missing"

                    if target is state.phase and state.phase is Phase.CODE_REVIEW:
                        try:
                            validate_passing_code_review(
                                store,
                                observation.subject,
                            )
                        except ReviewEvidenceMissingError:
                            code_status = EvidenceStatus.MISSING
                        except ReviewEvidenceStaleError:
                            code_status = EvidenceStatus.STALE
                        except ReviewRecoveryError:
                            code_status = EvidenceStatus.INVALID
                            target = Phase.BLOCKED
                            reason = "code-review-evidence-invalid"
                        else:
                            code_status = EvidenceStatus.CURRENT

                    if target is state.phase and state.phase in code_required_phases:
                        try:
                            validate_passing_code_review(
                                store,
                                observation.subject,
                            )
                        except ReviewEvidenceStaleError:
                            code_status = EvidenceStatus.STALE
                            target = (
                                Phase.BLOCKED
                                if state.phase in external_phases
                                else Phase.CODE_REVIEW
                            )
                            reason = (
                                "external-phase-code-review-stale"
                                if target is Phase.BLOCKED
                                else "candidate-needs-current-code-review"
                            )
                        except ReviewEvidenceMissingError:
                            code_status = EvidenceStatus.MISSING
                            target = Phase.BLOCKED
                            reason = "code-review-evidence-missing"
                        except ReviewRecoveryError:
                            code_status = EvidenceStatus.INVALID
                            target = Phase.BLOCKED
                            reason = "code-review-evidence-invalid"
                        else:
                            code_status = EvidenceStatus.CURRENT

                    if target is state.phase and state.phase is Phase.VERIFYING:
                        try:
                            validate_passing_verification(
                                store,
                                manifest=observation.manifest,
                                current_subject=observation.subject,
                                variables=observation.variables,
                            )
                        except VerificationEvidenceMissingError:
                            verification_status = EvidenceStatus.MISSING
                        except VerificationEvidenceStaleError:
                            verification_status = EvidenceStatus.STALE
                        except VerificationRecoveryError:
                            verification_status = EvidenceStatus.INVALID
                            target = Phase.BLOCKED
                            reason = "verification-evidence-invalid"
                        else:
                            verification_status = EvidenceStatus.CURRENT

                    if (
                        target is state.phase
                        and state.phase in verification_required_phases
                    ):
                        try:
                            validate_passing_verification(
                                store,
                                manifest=observation.manifest,
                                current_subject=observation.subject,
                                variables=observation.variables,
                            )
                        except VerificationEvidenceStaleError:
                            verification_status = EvidenceStatus.STALE
                            target = (
                                Phase.BLOCKED
                                if state.phase in external_phases
                                else Phase.CODE_REVIEW
                            )
                            reason = (
                                "external-phase-verification-stale"
                                if target is Phase.BLOCKED
                                else "candidate-needs-current-code-review"
                            )
                        except VerificationEvidenceMissingError:
                            verification_status = EvidenceStatus.MISSING
                            target = Phase.BLOCKED
                            reason = "verification-evidence-missing"
                        except VerificationRecoveryError:
                            verification_status = EvidenceStatus.INVALID
                            target = Phase.BLOCKED
                            reason = "verification-evidence-invalid"
                        else:
                            verification_status = EvidenceStatus.CURRENT

                    if target is state.phase and observation.dirty:
                        if state.phase in successful_terminal_phases:
                            target = Phase.BLOCKED
                            reason = "terminal-worktree-drift"
                        elif state.phase is Phase.PLAN_REVIEW:
                            reason = "plan-review-worktree-dirty"
                        elif state.phase is Phase.AWAITING_PLAN_APPROVAL:
                            reason = "awaiting-plan-approval-worktree-dirty"
                        elif state.phase in external_phases or (
                            external_inspection is not None
                            and external_inspection.in_flight
                        ):
                            target = Phase.BLOCKED
                            reason = "worktree-drift-after-external-operation"
                        else:
                            target = Phase.DEVELOPING
                            reason = "worktree-is-dirty"
                    elif (
                        target is state.phase
                        and state.phase is Phase.DEVELOPING
                        and observation.subject.candidate_oid
                        != observation.subject.base_oid
                    ):
                        target = Phase.CODE_REVIEW
                        reason = "clean-engine-candidate-needs-review"
                    elif (
                        target is state.phase
                        and state.phase is Phase.AWAITING_RELEASE_APPROVAL
                        and verification_status is EvidenceStatus.CURRENT
                        and not observation.manifest.release_required
                    ):
                        target = Phase.SYNCING
                        reason = "release-not-required"

                    if target is state.phase and state.phase in {
                        Phase.AWAITING_CLEANUP_APPROVAL,
                        Phase.COMPLETED,
                    }:

                        def current_sync_subject() -> EvidenceSubject:
                            current_ownership = _load_run_worktree_locked(
                                self.repository,
                                run_id,
                            )
                            if (
                                current_ownership.record_path.parent
                                != store.run_directory
                            ):
                                raise ReconciliationRecoveryError(
                                    "run ownership and state directories differ"
                                )
                            return _observe_live_run(
                                current_ownership,
                                run_descriptor=run_descriptor,
                                engine_version=self.engine_version,
                                evidence_schema_version=(self.evidence_schema_version),
                            ).subject

                        try:
                            _load_current_sync_report_locked(
                                store,
                                observation.subject,
                                worktree=ownership.worktree_path,
                                current_subject=current_sync_subject,
                            )
                        except (RuntimeError, SyncRecoveryError):
                            sync_status = EvidenceStatus.INVALID
                            target = Phase.BLOCKED
                            reason = "sync-evidence-invalid"
                        else:
                            sync_status = EvidenceStatus.CURRENT

                    if (
                        target is state.phase
                        and state.phase in successful_terminal_phases
                    ):
                        reason = "terminal-evidence-is-current"

                    if not _run_directory_is_current(
                        run_descriptor,
                        run_directory,
                    ) or not _runtime_evidence_ancestors_are_safe(run_descriptor):
                        return block_without_observation(
                            state,
                            reason="run-directory-changed-during-reconciliation",
                        )
                    try:
                        confirmed_ownership = _load_run_worktree_locked(
                            self.repository,
                            run_id,
                        )
                        confirmed_observation = _observe_live_run(
                            confirmed_ownership,
                            run_descriptor=run_descriptor,
                            engine_version=self.engine_version,
                            evidence_schema_version=self.evidence_schema_version,
                        )
                    except Exception:
                        return block_without_observation(
                            state,
                            reason="live-evidence-changed-during-reconciliation",
                        )
                    latest_state = store.load()
                    if latest_state != state or confirmed_observation != observation:
                        continue
                    return complete(
                        source_state=state,
                        target=target,
                        reason=reason,
                        observation=observation,
                        plan_approval=plan.approval,
                        inventory=inventory(),
                    )

                state = store.load()
                return block_without_observation(
                    state,
                    reason="evidence-kept-changing-during-reconciliation",
                )
        finally:
            run_anchor.close()
            os.close(run_descriptor)


def next_action(run: RunState | ReconciledRun) -> NextAction:
    if isinstance(run, ReconciledRun):
        state = run.state
    elif isinstance(run, RunState):
        state = run
    else:
        raise TypeError("next_action requires a RunState or ReconciledRun")
    if (
        isinstance(run, ReconciledRun)
        and run.reason == "base-branch-drift-start-new-run"
    ):
        return NextAction(
            phase=state.phase,
            kind="manual",
            action="start_new_run_from_latest_base",
        )
    if isinstance(run, ReconciledRun) and run.reason in {
        "plan-review-publication-recoverable",
        "code-review-publication-recoverable",
    }:
        review_type = run.reason.removesuffix("-review-publication-recoverable")
        return NextAction(
            phase=state.phase,
            kind="automatic",
            action=f"resume_{review_type}_review_publication",
        )
    if (
        isinstance(run, ReconciledRun)
        and run.reason == "verification-publication-recoverable"
    ):
        return NextAction(
            phase=state.phase,
            kind="automatic",
            action="resume_verification_publication",
        )
    if (
        isinstance(run, ReconciledRun)
        and run.reason == "external-health-publication-recoverable"
    ):
        action = (
            "resume_rollback_health_publication"
            if state.phase is Phase.ROLLBACK_VERIFYING
            else "resume_release_health_publication"
        )
        return NextAction(
            phase=state.phase,
            kind="automatic",
            action=action,
        )
    if (
        isinstance(run, ReconciledRun)
        and run.reason == "external-cycle-publication-recoverable"
    ):
        action = (
            "resume_rollback_publication"
            if state.phase is Phase.ROLLBACK_PENDING
            else "resume_release_publication"
        )
        return NextAction(
            phase=state.phase,
            kind="automatic",
            action=action,
        )
    if isinstance(run, ReconciledRun) and state.phase in {
        Phase.COMPLETED,
        Phase.ROLLED_BACK,
    }:
        statuses = {
            run.evidence.plan_approval,
            run.evidence.code_review,
            run.evidence.verification,
            run.evidence.release_or_external,
            run.evidence.sync,
        }
        if statuses & {
            EvidenceStatus.MISSING,
            EvidenceStatus.STALE,
            EvidenceStatus.INVALID,
        }:
            return NextAction(
                phase=state.phase,
                kind="manual",
                action="manual_reconciliation",
            )
    kind, action = _NEXT_ACTIONS[state.phase]
    return NextAction(phase=state.phase, kind=kind, action=action)
