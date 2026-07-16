from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

from .manifest import CommandSpec, Manifest, OperationSpec, manifest_digest
from .model import OperationStatus, Phase
from .review import _write_canonical_json
from .runner import CommandResult, CommandRunner, _resolved_argv
from .store import (
    FileLock,
    PrivateRootAnchor,
    StateNotFoundError,
    StateStore,
    _private_directory_names,
    _read_bounded_private_file,
)
from .subject import EvidenceSubject
from .verify import (
    _command_digest,
    _report_from_payload,
    _validate_log_evidence,
    _write_immutable_json,
    verification_commands_digest,
)


class ReleaseError(RuntimeError):
    pass


class ReleaseRecoveryError(ReleaseError):
    pass


class ExternalEvidenceMissingError(ReleaseRecoveryError):
    pass


class ExternalEvidenceUnknownError(ReleaseRecoveryError):
    pass


@dataclass(frozen=True)
class ExternalEvidenceInspection:
    records: tuple[OperationRecord, ...]
    in_flight: tuple[OperationRecord, ...]
    active_cycle: bool
    recoverable: bool = False


@dataclass(frozen=True)
class ExternalCycleContext:
    cycle_id: str
    mode: str
    approval_id: str
    target: str
    failed_release_id: str | None
    previous_release: str | None

    def __post_init__(self) -> None:
        if (
            re.fullmatch(r"[0-9a-f]{64}", self.cycle_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", self.approval_id) is None
            or self.mode not in {"release", "rollback"}
            or not isinstance(self.target, str)
            or not self.target
        ):
            raise ValueError("external cycle context identity is invalid")
        if self.mode == "release":
            if self.failed_release_id is not None or self.previous_release is not None:
                raise ValueError("release context cannot contain rollback fields")
        elif (
            not isinstance(self.failed_release_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.failed_release_id) is None
            or not isinstance(self.previous_release, str)
            or not self.previous_release
        ):
            raise ValueError("rollback external context is invalid")


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    run_id: str
    gate: str
    gate_phase: str
    gate_revision: int
    approver_actor: str
    subject: EvidenceSubject
    target: str
    operation_digests: tuple[str, ...]
    failed_release_id: str | None
    previous_release: str | None
    issued_at: str
    expires_at: str
    consumed_at: str | None = None
    consumed_by: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        if (
            not isinstance(self.approval_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.approval_id) is None
        ):
            raise ValueError("approval_id must be a lowercase SHA-256")
        if (
            not isinstance(self.run_id, str)
            or not self.run_id
            or not isinstance(self.gate, str)
            or self.gate not in {"release", "rollback"}
        ):
            raise ValueError("approval identity is invalid")
        if (
            type(self.gate_revision) is not int
            or self.gate_revision < 0
            or (
                self.gate == "release"
                and self.gate_phase != Phase.AWAITING_RELEASE_APPROVAL.value
            )
            or (
                self.gate == "rollback"
                and self.gate_phase
                not in {
                    Phase.AWAITING_RELEASE_APPROVAL.value,
                    Phase.ROLLBACK_PENDING.value,
                }
            )
        ):
            raise ValueError("approval gate generation is invalid")
        if (
            not isinstance(self.approver_actor, str)
            or not self.approver_actor
            or not isinstance(self.target, str)
            or not self.target
        ):
            raise ValueError("approval actor and target must be non-empty")
        if type(self.subject) is not EvidenceSubject:
            raise ValueError("approval subject is invalid")
        if (
            type(self.operation_digests) is not tuple
            or not self.operation_digests
            or any(
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                for digest in self.operation_digests
            )
        ):
            raise ValueError("approval operation digests are invalid")
        if self.gate == "release":
            if self.failed_release_id is not None or self.previous_release is not None:
                raise ValueError("release approval cannot contain rollback context")
        elif (
            not isinstance(self.failed_release_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.failed_release_id) is None
            or not isinstance(self.previous_release, str)
            or not self.previous_release.strip()
        ):
            raise ValueError("rollback approval context is invalid")
        _parse_utc(self.issued_at, "issued_at")
        _parse_utc(self.expires_at, "expires_at")
        if (self.consumed_at is None) != (self.consumed_by is None):
            raise ValueError("approval consumption is incomplete")
        if self.consumed_at is not None:
            _parse_utc(self.consumed_at, "consumed_at")
            if not isinstance(self.consumed_by, str) or not self.consumed_by:
                raise ValueError("approval consumer is invalid")
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("approval schema version is invalid")


@dataclass(frozen=True)
class OperationRecord:
    run_id: str
    cycle_id: str
    mode: str
    index: int
    attempt: int
    status: OperationStatus
    subject: EvidenceSubject
    target: str
    argv: tuple[str, ...]
    probe_argv: tuple[str, ...]
    command_sha256: str
    probe_sha256: str | None
    approval_id: str
    idempotency: str
    idempotency_key: str
    failed_release_id: str | None
    previous_release: str | None
    previous_receipt_sha256: str | None
    prepared_at: str
    started_at: str | None = None
    finished_at: str | None = None
    result: dict[str, object] | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        if (
            not isinstance(self.run_id, str)
            or not self.run_id
            or not isinstance(self.mode, str)
            or self.mode not in {"release", "rollback"}
        ):
            raise ValueError("operation identity is invalid")
        if (
            not isinstance(self.cycle_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.cycle_id) is None
        ):
            raise ValueError("operation cycle identity is invalid")
        if type(self.index) is not int or self.index < 1:
            raise ValueError("operation index is invalid")
        if type(self.attempt) is not int or self.attempt < 1:
            raise ValueError("operation attempt is invalid")
        if type(self.status) is not OperationStatus:
            raise ValueError("operation status is invalid")
        if (
            type(self.subject) is not EvidenceSubject
            or not isinstance(self.target, str)
            or not self.target
        ):
            raise ValueError("operation subject or target is invalid")
        if (
            type(self.argv) is not tuple
            or type(self.probe_argv) is not tuple
            or not self.argv
            or any(not isinstance(token, str) or not token for token in self.argv)
            or any(not isinstance(token, str) or not token for token in self.probe_argv)
        ):
            raise ValueError("operation argv is invalid")
        for digest in (self.command_sha256, self.approval_id, self.idempotency_key):
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise ValueError("operation digest is invalid")
        if self.probe_sha256 is not None and (
            not isinstance(self.probe_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.probe_sha256) is None
        ):
            raise ValueError("operation probe digest is invalid")
        if self.previous_receipt_sha256 is not None and (
            not isinstance(self.previous_receipt_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.previous_receipt_sha256) is None
        ):
            raise ValueError("previous operation receipt digest is invalid")
        if not isinstance(self.idempotency, str) or self.idempotency not in {
            "safe",
            "probe",
            "manual_reconcile",
        }:
            raise ValueError("operation idempotency is invalid")
        if self.mode == "release":
            if self.failed_release_id is not None or self.previous_release is not None:
                raise ValueError("release operation cannot contain rollback context")
        elif (
            not isinstance(self.failed_release_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.failed_release_id) is None
            or not isinstance(self.previous_release, str)
            or not self.previous_release.strip()
        ):
            raise ValueError("rollback operation context is invalid")
        _parse_utc(self.prepared_at, "prepared_at")
        if self.status is OperationStatus.PREPARED:
            if (self.attempt == 1) != (self.previous_receipt_sha256 is None):
                raise ValueError("prepared operation receipt chain is invalid")
            if any(
                value is not None
                for value in (self.started_at, self.finished_at, self.result)
            ):
                raise ValueError("prepared operation has terminal fields")
        elif self.status is OperationStatus.RUNNING:
            if (
                self.previous_receipt_sha256 is None
                or self.started_at is None
                or any(value is not None for value in (self.finished_at, self.result))
            ):
                raise ValueError("running operation fields are invalid")
            _parse_utc(self.started_at, "started_at")
        else:
            if (
                self.previous_receipt_sha256 is None
                or self.started_at is None
                or self.finished_at is None
                or not isinstance(self.result, dict)
            ):
                raise ValueError("terminal operation fields are invalid")
            _parse_utc(self.started_at, "started_at")
            _parse_utc(self.finished_at, "finished_at")
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("operation schema version is invalid")


@dataclass(frozen=True)
class PendingOperationDecision:
    run_id: str
    cycle_id: str
    mode: str
    index: int
    attempt: int
    operation_name: str
    target: str
    argv: tuple[str, ...]
    reason: str
    unknown_receipt_sha256: str
    operation_start_marker_id: str
    blocked_revision: int
    confirmation_token: str

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not self.run_id:
            raise ValueError("pending operation run identity is invalid")
        if (
            not isinstance(self.cycle_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.cycle_id) is None
            or self.mode not in {"release", "rollback"}
            or type(self.index) is not int
            or self.index < 1
            or type(self.attempt) is not int
            or self.attempt < 1
        ):
            raise ValueError("pending operation identity is invalid")
        if (
            not isinstance(self.operation_name, str)
            or not self.operation_name
            or not isinstance(self.target, str)
            or not self.target
            or type(self.argv) is not tuple
            or not self.argv
            or any(not isinstance(token, str) or not token for token in self.argv)
            or not isinstance(self.reason, str)
            or not self.reason
        ):
            raise ValueError("pending operation details are invalid")
        for digest in (
            self.unknown_receipt_sha256,
            self.operation_start_marker_id,
            self.confirmation_token,
        ):
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise ValueError("pending operation digest is invalid")
        if type(self.blocked_revision) is not int or self.blocked_revision < 0:
            raise ValueError("pending operation blocked revision is invalid")


@dataclass(frozen=True)
class OperationAdjudication:
    adjudication_id: str
    run_id: str
    cycle_id: str
    mode: str
    index: int
    attempt: int
    subject: EvidenceSubject
    target: str
    argv: tuple[str, ...]
    command_sha256: str
    idempotency_key: str
    unknown_receipt_sha256: str
    operation_start_marker_id: str
    blocked_revision: int
    confirmation_token: str
    actor: str
    outcome: str
    reason: str
    recorded_at: str
    schema_version: int = 1

    def __post_init__(self) -> None:
        for digest in (
            self.adjudication_id,
            self.cycle_id,
            self.command_sha256,
            self.idempotency_key,
            self.unknown_receipt_sha256,
            self.operation_start_marker_id,
            self.confirmation_token,
        ):
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise ValueError("operation adjudication digest is invalid")
        if (
            not isinstance(self.run_id, str)
            or not self.run_id
            or self.mode not in {"release", "rollback"}
            or type(self.index) is not int
            or self.index < 1
            or type(self.attempt) is not int
            or self.attempt < 1
            or type(self.subject) is not EvidenceSubject
        ):
            raise ValueError("operation adjudication identity is invalid")
        if (
            not isinstance(self.target, str)
            or not self.target
            or type(self.argv) is not tuple
            or not self.argv
            or any(not isinstance(token, str) or not token for token in self.argv)
            or not isinstance(self.actor, str)
            or not self.actor
            or self.outcome not in {"applied", "not_applied"}
            or not isinstance(self.reason, str)
            or not self.reason
        ):
            raise ValueError("operation adjudication details are invalid")
        if type(self.blocked_revision) is not int or self.blocked_revision < 0:
            raise ValueError("operation adjudication blocked revision is invalid")
        _parse_utc(self.recorded_at, "recorded_at")
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("operation adjudication schema version is invalid")


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _parse_utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(f"{field} must be a UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{field} must be a UTC timestamp")
    return parsed


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


def _read_bounded_private_bytes(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
    label: str,
    max_bytes: int = 4 * 1024 * 1024,
) -> bytes:
    try:
        return _read_bounded_private_file(
            path,
            trusted_root=trusted_root,
            label=label,
            max_bytes=max_bytes,
        )
    except OSError as error:
        raise ReleaseRecoveryError(f"{label} cannot be opened safely") from error
    except RuntimeError as error:
        raise ReleaseRecoveryError(f"{label} cannot be read safely") from error


def _approval_stable_payload(record: ApprovalRecord) -> dict[str, object]:
    return {
        "schema_version": record.schema_version,
        "run_id": record.run_id,
        "gate": record.gate,
        "gate_phase": record.gate_phase,
        "gate_revision": record.gate_revision,
        "approver_actor": record.approver_actor,
        "subject": record.subject.to_dict(),
        "target": record.target,
        "operation_digests": list(record.operation_digests),
        "failed_release_id": record.failed_release_id,
        "previous_release": record.previous_release,
        "issued_at": record.issued_at,
        "expires_at": record.expires_at,
        "consumed_at": None,
        "consumed_by": None,
    }


def _approval_payload(record: ApprovalRecord) -> dict[str, object]:
    payload = _approval_stable_payload(record)
    payload.update(
        {
            "approval_id": record.approval_id,
            "consumed_at": record.consumed_at,
            "consumed_by": record.consumed_by,
        }
    )
    return payload


def _approval_from_payload(payload: object) -> ApprovalRecord:
    expected = {
        "schema_version",
        "approval_id",
        "run_id",
        "gate",
        "gate_phase",
        "gate_revision",
        "approver_actor",
        "subject",
        "target",
        "operation_digests",
        "failed_release_id",
        "previous_release",
        "issued_at",
        "expires_at",
        "consumed_at",
        "consumed_by",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ReleaseError("approval receipt schema is invalid")
    try:
        subject_payload = payload["subject"]
        if not isinstance(subject_payload, dict):
            raise TypeError
        return ApprovalRecord(
            approval_id=payload["approval_id"],
            run_id=payload["run_id"],
            gate=payload["gate"],
            gate_phase=payload["gate_phase"],
            gate_revision=payload["gate_revision"],
            approver_actor=payload["approver_actor"],
            subject=EvidenceSubject(**subject_payload),
            target=payload["target"],
            operation_digests=tuple(payload["operation_digests"]),
            failed_release_id=payload["failed_release_id"],
            previous_release=payload["previous_release"],
            issued_at=payload["issued_at"],
            expires_at=payload["expires_at"],
            consumed_at=payload["consumed_at"],
            consumed_by=payload["consumed_by"],
            schema_version=payload["schema_version"],
        )
    except (TypeError, ValueError) as error:
        raise ReleaseError("approval receipt is invalid") from error


def _operation_payload(
    spec: OperationSpec,
    variables: Mapping[str, str],
) -> dict[str, object]:
    resolved_target = _resolved_argv((spec.target,), variables)[0]
    resolved_argv = _resolved_argv(spec.argv, variables)
    resolved_probe = (
        _resolved_argv(spec.probe_argv, variables) if spec.probe_argv else ()
    )
    return {
        "name": spec.name,
        "kind": spec.kind,
        "target": resolved_target,
        "argv": list(resolved_argv),
        "effect": spec.effect,
        "idempotency": spec.idempotency,
        "probe_argv": list(resolved_probe),
        "data_impact": spec.data_impact,
        "timeout_seconds": spec.timeout_seconds,
    }


def _operation_digests(
    specs: Sequence[OperationSpec],
    variables: Mapping[str, str],
) -> tuple[str, ...]:
    return tuple(_digest(_operation_payload(spec, variables)) for spec in specs)


def _operation_record_payload(record: OperationRecord) -> dict[str, object]:
    return {
        "schema_version": record.schema_version,
        "run_id": record.run_id,
        "cycle_id": record.cycle_id,
        "mode": record.mode,
        "index": record.index,
        "attempt": record.attempt,
        "status": record.status.value,
        "subject": record.subject.to_dict(),
        "target": record.target,
        "argv": list(record.argv),
        "probe_argv": list(record.probe_argv),
        "command_sha256": record.command_sha256,
        "probe_sha256": record.probe_sha256,
        "approval_id": record.approval_id,
        "idempotency": record.idempotency,
        "idempotency_key": record.idempotency_key,
        "failed_release_id": record.failed_release_id,
        "previous_release": record.previous_release,
        "previous_receipt_sha256": record.previous_receipt_sha256,
        "prepared_at": record.prepared_at,
        "started_at": record.started_at,
        "finished_at": record.finished_at,
        "result": record.result,
    }


_OPERATION_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "cycle_id",
        "mode",
        "index",
        "attempt",
        "status",
        "subject",
        "target",
        "argv",
        "probe_argv",
        "command_sha256",
        "probe_sha256",
        "approval_id",
        "idempotency",
        "idempotency_key",
        "failed_release_id",
        "previous_release",
        "previous_receipt_sha256",
        "prepared_at",
        "started_at",
        "finished_at",
        "result",
    }
)


def _operation_record_from_payload(payload: object) -> OperationRecord:
    if not isinstance(payload, dict) or set(payload) != _OPERATION_RECORD_KEYS:
        raise ReleaseRecoveryError("operation receipt schema is invalid")
    try:
        subject_payload = payload["subject"]
        if not isinstance(subject_payload, dict):
            raise TypeError
        argv = payload["argv"]
        probe_argv = payload["probe_argv"]
        if not isinstance(argv, list) or not isinstance(probe_argv, list):
            raise TypeError
        result = payload["result"]
        if result is not None and not isinstance(result, dict):
            raise TypeError
        return OperationRecord(
            run_id=payload["run_id"],
            cycle_id=payload["cycle_id"],
            mode=payload["mode"],
            index=payload["index"],
            attempt=payload["attempt"],
            status=OperationStatus(payload["status"]),
            subject=EvidenceSubject(**subject_payload),
            target=payload["target"],
            argv=tuple(argv),
            probe_argv=tuple(probe_argv),
            command_sha256=payload["command_sha256"],
            probe_sha256=payload["probe_sha256"],
            approval_id=payload["approval_id"],
            idempotency=payload["idempotency"],
            idempotency_key=payload["idempotency_key"],
            failed_release_id=payload["failed_release_id"],
            previous_release=payload["previous_release"],
            previous_receipt_sha256=payload["previous_receipt_sha256"],
            prepared_at=payload["prepared_at"],
            started_at=payload["started_at"],
            finished_at=payload["finished_at"],
            result=(dict(result) if result is not None else None),
            schema_version=payload["schema_version"],
        )
    except (TypeError, ValueError) as error:
        raise ReleaseRecoveryError("operation receipt is invalid") from error


def _pending_operation_decision_payload(
    *,
    run_id: str,
    cycle_id: str,
    mode: str,
    index: int,
    attempt: int,
    operation_name: str,
    target: str,
    argv: tuple[str, ...],
    reason: str,
    unknown_receipt_sha256: str,
    operation_start_marker_id: str,
    blocked_revision: int,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "cycle_id": cycle_id,
        "mode": mode,
        "index": index,
        "attempt": attempt,
        "operation_name": operation_name,
        "target": target,
        "argv": list(argv),
        "reason": reason,
        "unknown_receipt_sha256": unknown_receipt_sha256,
        "operation_start_marker_id": operation_start_marker_id,
        "blocked_revision": blocked_revision,
    }


_OPERATION_ADJUDICATION_KEYS = frozenset(
    {
        "schema_version",
        "adjudication_id",
        "run_id",
        "cycle_id",
        "mode",
        "index",
        "attempt",
        "subject",
        "target",
        "argv",
        "command_sha256",
        "idempotency_key",
        "unknown_receipt_sha256",
        "operation_start_marker_id",
        "blocked_revision",
        "confirmation_token",
        "actor",
        "outcome",
        "reason",
        "recorded_at",
    }
)


def _operation_adjudication_stable_payload(
    record: OperationAdjudication,
) -> dict[str, object]:
    return {
        "schema_version": record.schema_version,
        "run_id": record.run_id,
        "cycle_id": record.cycle_id,
        "mode": record.mode,
        "index": record.index,
        "attempt": record.attempt,
        "subject": record.subject.to_dict(),
        "target": record.target,
        "argv": list(record.argv),
        "command_sha256": record.command_sha256,
        "idempotency_key": record.idempotency_key,
        "unknown_receipt_sha256": record.unknown_receipt_sha256,
        "operation_start_marker_id": record.operation_start_marker_id,
        "blocked_revision": record.blocked_revision,
        "confirmation_token": record.confirmation_token,
        "actor": record.actor,
        "outcome": record.outcome,
        "reason": record.reason,
        "recorded_at": record.recorded_at,
    }


def _operation_adjudication_payload(
    record: OperationAdjudication,
) -> dict[str, object]:
    return {
        **_operation_adjudication_stable_payload(record),
        "adjudication_id": record.adjudication_id,
    }


def _operation_adjudication_from_payload(
    payload: object,
) -> OperationAdjudication:
    if not isinstance(payload, dict) or set(payload) != _OPERATION_ADJUDICATION_KEYS:
        raise ReleaseRecoveryError("operation adjudication schema is invalid")
    try:
        subject_payload = payload["subject"]
        argv = payload["argv"]
        if not isinstance(subject_payload, dict) or not isinstance(argv, list):
            raise TypeError
        record = OperationAdjudication(
            adjudication_id=payload["adjudication_id"],
            run_id=payload["run_id"],
            cycle_id=payload["cycle_id"],
            mode=payload["mode"],
            index=payload["index"],
            attempt=payload["attempt"],
            subject=EvidenceSubject(**subject_payload),
            target=payload["target"],
            argv=tuple(argv),
            command_sha256=payload["command_sha256"],
            idempotency_key=payload["idempotency_key"],
            unknown_receipt_sha256=payload["unknown_receipt_sha256"],
            operation_start_marker_id=payload["operation_start_marker_id"],
            blocked_revision=payload["blocked_revision"],
            confirmation_token=payload["confirmation_token"],
            actor=payload["actor"],
            outcome=payload["outcome"],
            reason=payload["reason"],
            recorded_at=payload["recorded_at"],
            schema_version=payload["schema_version"],
        )
    except (TypeError, ValueError) as error:
        raise ReleaseRecoveryError("operation adjudication is invalid") from error
    if record.adjudication_id != _digest(
        _operation_adjudication_stable_payload(record)
    ):
        raise ReleaseRecoveryError("operation adjudication identity is invalid")
    return record


def _command_result_payload(result: CommandResult) -> dict[str, object]:
    return {
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "truncated": result.truncated,
        "log_sha256": result.log_sha256,
        "log_size": result.log_size,
        "log_path": str(result.log_path),
    }


_COMMAND_RESULT_KEYS = frozenset(
    {
        "exit_code",
        "timed_out",
        "truncated",
        "log_sha256",
        "log_size",
        "log_path",
    }
)
_PROBE_PROTOCOL_KEYS = frozenset(
    {"schema_version", "kind", "outcome", "target", "version"}
)
_HEALTH_PROTOCOL_KEYS = frozenset(
    {"schema_version", "kind", "status", "target", "version"}
)
_RETRY_AUTHORIZATION_KEYS = frozenset(
    {"retry_authorized", "next_attempt", "probe_digest"}
)
_RETRY_RESULT_KEYS = frozenset(
    {
        "recovered_by_probe",
        "outcome",
        "probe",
        "retry_authorized",
        "next_attempt",
        "probe_digest",
    }
)


def _validated_command_result_payload(payload: object) -> dict[str, object]:
    if (
        not isinstance(payload, dict)
        or set(payload) != _COMMAND_RESULT_KEYS
        or (payload["exit_code"] is not None and type(payload["exit_code"]) is not int)
        or type(payload["timed_out"]) is not bool
        or type(payload["truncated"]) is not bool
        or not isinstance(payload["log_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", payload["log_sha256"]) is None
        or type(payload["log_size"]) is not int
        or payload["log_size"] < 0
        or not isinstance(payload["log_path"], str)
        or not payload["log_path"]
    ):
        raise ReleaseRecoveryError("operation command result is invalid")
    return dict(payload)


def _single_json_object(raw: bytes) -> dict[str, object] | None:
    body = raw[:-1] if raw.endswith(b"\n") else raw
    if not body or b"\n" in body or b"\r" in body:
        return None

    def reject_duplicate_keys(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        payload: dict[str, object] = {}
        for key, value in pairs:
            if key in payload:
                raise ValueError("duplicate JSON key")
            payload[key] = value
        return payload

    try:
        payload = json.loads(
            body.decode("utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    return dict(payload) if isinstance(payload, dict) else None


def _probe_protocol_outcome(
    raw: bytes,
    *,
    result: Mapping[str, object],
    probe_argv: tuple[str, ...],
    target: str,
    expected_version: str,
) -> str | None:
    exit_code = result.get("exit_code")
    if result.get("timed_out") is not False or result.get("truncated") is not False:
        return None
    git_adapter = (
        len(probe_argv) == 5
        and probe_argv[0] == "git"
        and probe_argv[1:3] == ("ls-remote", "--exit-code")
        and probe_argv[4].startswith("refs/")
    )
    if git_adapter:
        if exit_code == 2 and raw == b"":
            return "not_applied"
        body = raw[:-1] if raw.endswith(b"\n") else raw
        expected = f"{expected_version}\t{probe_argv[4]}".encode("utf-8")
        return "applied" if exit_code == 0 and body == expected else None
    if exit_code != 0:
        return None
    payload = _single_json_object(raw)
    if (
        payload is None
        or set(payload) != _PROBE_PROTOCOL_KEYS
        or type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or payload["kind"] != "probe"
        or payload["target"] != target
    ):
        return None
    if payload["outcome"] == "applied" and payload["version"] == expected_version:
        return "applied"
    if payload["outcome"] == "not_applied" and payload["version"] is None:
        return "not_applied"
    return None


def _health_protocol_outcome(
    raw: bytes,
    *,
    result: Mapping[str, object],
    target: str,
    expected_version: str,
) -> str | None:
    payload = _single_json_object(raw)
    if (
        payload is None
        or set(payload) != _HEALTH_PROTOCOL_KEYS
        or type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or payload["kind"] != "health"
        or payload["status"] not in {"healthy", "unhealthy"}
        or payload["target"] != target
        or not isinstance(payload["version"], (str, type(None)))
    ):
        return None
    if payload["status"] == "unhealthy":
        return "unhealthy"
    if (
        result.get("exit_code") == 0
        and result.get("timed_out") is False
        and result.get("truncated") is False
        and payload["status"] == "healthy"
        and payload["version"] == expected_version
    ):
        return "healthy"
    return None


def _health_protocol_passes(
    raw: bytes,
    *,
    result: Mapping[str, object],
    target: str,
    expected_version: str,
) -> bool:
    return (
        _health_protocol_outcome(
            raw,
            result=result,
            target=target,
            expected_version=expected_version,
        )
        == "healthy"
    )


def _retry_authorized_attempt(record: OperationRecord) -> int | None:
    result = record.result
    if result is None or not (_RETRY_AUTHORIZATION_KEYS & set(result)):
        return None
    probe = _validated_command_result_payload(result.get("probe"))
    next_attempt = result.get("next_attempt")
    if (
        record.status is not OperationStatus.FAILED
        or record.idempotency not in {"safe", "probe"}
        or record.probe_sha256 is None
        or set(result) != _RETRY_RESULT_KEYS
        or result.get("recovered_by_probe") is not True
        or result.get("outcome") != "not-applied"
        or result.get("retry_authorized") is not True
        or type(next_attempt) is not int
        or next_attempt != record.attempt + 1
        or result.get("probe_digest") != _digest(probe)
    ):
        raise ReleaseRecoveryError("operation retry authorization is invalid")
    return next_attempt


def _operation_result_evidence(
    record: OperationRecord,
) -> tuple[tuple[str, dict[str, object]], ...]:
    if record.status in {OperationStatus.PREPARED, OperationStatus.RUNNING}:
        return ()
    result = record.result
    if not isinstance(result, dict):
        raise ReleaseRecoveryError("terminal operation result is missing")
    if record.status is OperationStatus.SUCCEEDED:
        if set(result) == {"command"}:
            command = _validated_command_result_payload(result["command"])
            if command["exit_code"] != 0 or command["timed_out"] is not False:
                raise ReleaseRecoveryError("successful command result is invalid")
            return (("command", command),)
        if set(result) == {"recovered_by_probe", "probe", "asserted_version"}:
            probe = _validated_command_result_payload(result["probe"])
            expected_version = (
                record.previous_release
                if record.mode == "rollback"
                else record.subject.candidate_oid
            )
            if (
                result["recovered_by_probe"] is not True
                or result["asserted_version"] != expected_version
                or probe["exit_code"] != 0
                or probe["timed_out"] is not False
                or probe["truncated"] is not False
            ):
                raise ReleaseRecoveryError("successful probe result is invalid")
            return (("probe-applied", probe),)
        raise ReleaseRecoveryError("successful operation result schema is invalid")
    if record.status is OperationStatus.FAILED:
        if set(result) == {"command"}:
            command = _validated_command_result_payload(result["command"])
            if command["exit_code"] == 0 and command["timed_out"] is False:
                raise ReleaseRecoveryError("failed command result is invalid")
            return (("command", command),)
        if _retry_authorized_attempt(record) is None:
            raise ReleaseRecoveryError("failed operation result schema is invalid")
        probe = _validated_command_result_payload(result["probe"])
        return (("probe-not-applied", probe),)
    if record.status is OperationStatus.UNKNOWN:
        if set(result) not in ({"reason"}, {"reason", "probe"}):
            raise ReleaseRecoveryError("unknown operation result schema is invalid")
        if not isinstance(result["reason"], str) or not result["reason"]:
            raise ReleaseRecoveryError("unknown operation reason is invalid")
        if "probe" in result:
            return (
                ("probe-unknown", _validated_command_result_payload(result["probe"])),
            )
        return ()
    raise ReleaseRecoveryError("operation terminal status is invalid")


def _operation_request_identity(record: OperationRecord) -> tuple[object, ...]:
    return (
        record.run_id,
        record.cycle_id,
        record.mode,
        record.index,
        record.subject,
        record.target,
        record.argv,
        record.probe_argv,
        record.command_sha256,
        record.probe_sha256,
        record.approval_id,
        record.idempotency,
        record.idempotency_key,
        record.failed_release_id,
        record.previous_release,
    )


def _valid_operation_stage_transition(
    previous: OperationRecord,
    current: OperationRecord,
    *,
    manual_outcome: str | None = None,
) -> bool:
    if _operation_request_identity(previous) != _operation_request_identity(
        current
    ) or current.previous_receipt_sha256 != _digest(
        _operation_record_payload(previous)
    ):
        return False
    if current.attempt == previous.attempt:
        if current.prepared_at != previous.prepared_at:
            return False
        if (
            previous.status is OperationStatus.PREPARED
            and current.status is OperationStatus.RUNNING
        ):
            return True
        return (
            previous.status is OperationStatus.RUNNING
            and current.status
            in {
                OperationStatus.SUCCEEDED,
                OperationStatus.FAILED,
                OperationStatus.UNKNOWN,
            }
            and current.started_at == previous.started_at
        )
    if (
        current.attempt != previous.attempt + 1
        or current.status is not OperationStatus.PREPARED
    ):
        return False
    if previous.status is OperationStatus.FAILED:
        return _retry_authorized_attempt(previous) == current.attempt
    return (
        previous.status is OperationStatus.UNKNOWN and manual_outcome == "not_applied"
    )


_OPERATION_STAGE_ORDER = {
    OperationStatus.PREPARED: 0,
    OperationStatus.RUNNING: 1,
    OperationStatus.SUCCEEDED: 2,
    OperationStatus.FAILED: 2,
    OperationStatus.UNKNOWN: 2,
}


def _health_command_payload(
    spec: CommandSpec,
    variables: Mapping[str, str],
) -> dict[str, object]:
    return {
        "name": spec.name,
        "category": spec.category,
        "argv": list(_resolved_argv(spec.argv, variables)),
        "timeout_seconds": spec.timeout_seconds,
        "cwd": spec.cwd,
        "env_allowlist": list(spec.env_allowlist),
        "max_log_bytes": spec.max_log_bytes,
        "shell_approved": spec.shell_approved,
    }


_HEALTH_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "cycle_id",
        "mode",
        "index",
        "subject",
        "target",
        "expected_version",
        "command_sha256",
        "argv",
        "started_at",
        "finished_at",
        "result",
        "passed",
        "asserts_expected_version",
    }
)

_CYCLE_HEADER_KEYS = frozenset(
    {
        "schema_version",
        "cycle_id",
        "run_id",
        "gate",
        "gate_revision",
        "approval_id",
        "subject",
        "subject_digest",
        "target",
        "failed_release_id",
        "previous_release",
        "created_at",
    }
)
_CYCLE_IDENTITY_KEYS = _CYCLE_HEADER_KEYS - {"cycle_id", "created_at"}

_CYCLE_SUPERSESSION_KEYS = frozenset(
    {
        "schema_version",
        "supersession_id",
        "run_id",
        "gate",
        "gate_revision",
        "subject_digest",
        "old_cycle_id",
        "old_approval_id",
        "replacement_approval_id",
        "target",
        "reason",
        "recorded_at",
    }
)

_ROLLBACK_CONTEXT_KEYS = frozenset(
    {
        "schema_version",
        "context_id",
        "approval_id",
        "run_id",
        "gate_phase",
        "gate_revision",
        "subject",
        "subject_digest",
        "target",
        "failed_release_id",
        "previous_release",
        "selected_release_cycle_id",
        "confirmed_at",
    }
)

_ABANDONED_APPROVAL_KEYS = frozenset(
    {
        "schema_version",
        "abandonment_id",
        "approval_id",
        "run_id",
        "gate",
        "gate_revision",
        "subject_digest",
        "approval_seal_sha256",
        "reason",
        "recorded_at",
    }
)

_VERIFICATION_PUBLICATION_KEYS = frozenset(
    {
        "schema_version",
        "request",
        "request_digest",
        "report",
        "report_digest",
        "report_file_sha256",
        "artifact_path",
        "handoff_path",
        "handoff_digest",
        "terminal_receipt_sha256",
        "expected_revision",
        "target_phase",
    }
)
_VERIFICATION_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "verifier_actor",
        "subject",
        "subject_digest",
        "handoff_nonce_sha256",
        "manifest_sha256",
        "command_digests",
        "variables_sha256",
        "sensitive_values_sha256",
    }
)


class ReleaseEngine:
    def __init__(
        self,
        *,
        repo: Path | str,
        run_directory: Path | str,
        manifest: Manifest,
        current_subject: EvidenceSubject,
        variables: Mapping[str, str],
        runner: CommandRunner | None = None,
    ) -> None:
        self.repo = Path(repo).resolve()
        self.run_directory = Path(run_directory).resolve()
        self.store = StateStore(self.run_directory)
        self.manifest = manifest
        self.current_subject = current_subject
        self.variables = dict(variables)
        self.runner = runner or CommandRunner()

    def _approval_path(self, approval_id: str) -> Path:
        if re.fullmatch(r"[0-9a-f]{64}", approval_id) is None:
            raise ReleaseError("approval id is invalid")
        return self.run_directory / "approvals" / f"{approval_id}.json"

    def _approval_seal_path(self, approval_id: str) -> Path:
        return self.run_directory / "approvals" / "sealed" / f"{approval_id}.json"

    def _approval_consumed_path(self, approval_id: str) -> Path:
        return self.run_directory / "approvals" / "consumed" / f"{approval_id}.json"

    def _approval_abandoned_path(self, approval_id: str) -> Path:
        return self.run_directory / "approvals" / "abandoned" / f"{approval_id}.json"

    def _abandoned_approval_names(self) -> set[str]:
        paths = self._private_directory_paths(
            self.run_directory / "approvals" / "abandoned",
            label="abandoned approval directory",
            missing_ok=True,
        )
        names: set[str] = set()
        for path in paths:
            payload, _ = self._read_private_canonical_json(
                path,
                label="abandoned approval immutable receipt",
            )
            stable = {
                key: payload.get(key)
                for key in _ABANDONED_APPROVAL_KEYS - {"abandonment_id"}
            }
            if (
                re.fullmatch(r"[0-9a-f]{64}\.json", path.name) is None
                or set(payload) != _ABANDONED_APPROVAL_KEYS
                or payload.get("approval_id") != path.stem
                or payload.get("approval_seal_sha256") != path.stem
                or payload.get("reason") != "expired-unpublished-approval"
                or payload.get("abandonment_id") != _digest(stable)
            ):
                raise ReleaseRecoveryError(
                    "abandoned approval receipt is stale or invalid"
                )
            _parse_utc(str(payload.get("recorded_at")), "recorded_at")
            names.add(path.name)
        return names

    def _abandon_expired_orphan(self, record: ApprovalRecord) -> None:
        stable: dict[str, object] = {
            "schema_version": 1,
            "approval_id": record.approval_id,
            "run_id": record.run_id,
            "gate": record.gate,
            "gate_revision": record.gate_revision,
            "subject_digest": record.subject.digest(),
            "approval_seal_sha256": record.approval_id,
            "reason": "expired-unpublished-approval",
            "recorded_at": _utc_now(),
        }
        try:
            _write_immutable_json(
                self._approval_abandoned_path(record.approval_id),
                {**stable, "abandonment_id": _digest(stable)},
                trusted_root=self.store.trusted_root,
            )
        except Exception as error:
            raise ReleaseRecoveryError(
                "expired orphan approval could not be abandoned safely"
            ) from error

    def _approval_lock(self) -> FileLock:
        trusted_root = self.store.trusted_root
        if isinstance(trusted_root, PrivateRootAnchor):
            return FileLock.at(
                trusted_root.descriptor,
                "approval-publication.lock",
                display_path=self.run_directory / "approval-publication.lock",
            )
        return FileLock(
            self.run_directory / "approval-publication.lock",
            private_root=self.run_directory,
        )

    def _cycle_identity_payload(
        self,
        *,
        gate: str,
        approval_id: str,
        target: str,
        failed_release_id: str | None,
        previous_release: str | None,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "run_id": self.current_subject.run_id,
            "gate": gate,
            "gate_revision": self._current_gate_revision(gate),
            "approval_id": approval_id,
            "subject": self.current_subject.to_dict(),
            "subject_digest": self.current_subject.digest(),
            "target": target,
            "failed_release_id": failed_release_id,
            "previous_release": previous_release,
        }

    def _current_gate_revision(self, gate: str) -> int:
        if gate == "release":
            phase = Phase.AWAITING_RELEASE_APPROVAL
        elif gate == "rollback":
            phase = Phase.ROLLBACK_PENDING
        else:
            raise ReleaseRecoveryError("release cycle gate is invalid")
        events = [event for event in self.store.events() if event.phase is phase]
        if not events:
            raise ReleaseRecoveryError("release cycle has no matching state gate")
        return events[-1].revision

    def _expected_cycle_id(
        self,
        *,
        gate: str,
        approval_id: str,
        target: str,
        failed_release_id: str | None = None,
        previous_release: str | None = None,
    ) -> str:
        return _digest(
            self._cycle_identity_payload(
                gate=gate,
                approval_id=approval_id,
                target=target,
                failed_release_id=failed_release_id,
                previous_release=previous_release,
            )
        )

    def _cycle_root(self) -> Path:
        return self.run_directory / "release-cycles"

    def _cycle_directory(self, cycle_id: str) -> Path:
        if re.fullmatch(r"[0-9a-f]{64}", cycle_id) is None:
            raise ReleaseRecoveryError("release cycle id is invalid")
        return self._cycle_root() / cycle_id

    def _cycle_header_path(self, cycle_id: str) -> Path:
        return self._cycle_directory(cycle_id) / "header.json"

    def _active_cycle_path(self, gate: str) -> Path:
        if gate not in {"release", "rollback"}:
            raise ReleaseRecoveryError("release cycle gate is invalid")
        return self._cycle_root() / f"active-{gate}.json"

    def _rollback_context_path(self, approval_id: str) -> Path:
        if re.fullmatch(r"[0-9a-f]{64}", approval_id) is None:
            raise ReleaseRecoveryError("rollback context approval id is invalid")
        return (
            self.run_directory
            / "approvals"
            / "rollback-contexts"
            / f"{approval_id}.json"
        )

    def _selected_failed_release_cycle_id(
        self,
        *,
        state_phase: Phase,
        target: str,
        failed_release_id: str,
    ) -> str:
        if state_phase is Phase.AWAITING_RELEASE_APPROVAL:
            selected = self._validate_approval(
                failed_release_id,
                gate="release",
                target=target,
            )
            if selected.consumed_at is not None:
                raise ReleaseError("selected release approval is already consumed")
            return self._expected_cycle_id(
                gate="release",
                approval_id=failed_release_id,
                target=target,
            )
        if state_phase is not Phase.ROLLBACK_PENDING:
            raise ReleaseError("rollback context is not at a confirmation gate")
        active = self._load_active_cycle_unbound("release")
        if (
            active.get("approval_id") != failed_release_id
            or active.get("target") != target
            or active.get("subject") != self.current_subject.to_dict()
        ):
            raise ReleaseError("failed release is not the active sealed release")
        cycle_id = str(active["cycle_id"])
        first_spec = self.manifest.release_steps[0]
        _, _, _, _, first_key = self._operation_identity(
            cycle_id=cycle_id,
            mode="release",
            index=1,
            spec=first_spec,
            target=target,
            approval_id=failed_release_id,
        )
        selected = self._validate_approval(
            failed_release_id,
            gate="release",
            target=target,
            allow_consumed_by=self._approval_consumer(
                mode="release",
                idempotency_key=first_key,
            ),
        )
        if selected.consumed_at is None:
            raise ReleaseError("active failed release approval is not consumed")
        return cycle_id

    def _rollback_context_payload(
        self,
        record: ApprovalRecord,
        *,
        selected_release_cycle_id: str,
    ) -> dict[str, object]:
        stable: dict[str, object] = {
            "schema_version": 1,
            "approval_id": record.approval_id,
            "run_id": record.run_id,
            "gate_phase": record.gate_phase,
            "gate_revision": record.gate_revision,
            "subject": record.subject.to_dict(),
            "subject_digest": record.subject.digest(),
            "target": record.target,
            "failed_release_id": record.failed_release_id,
            "previous_release": record.previous_release,
            "selected_release_cycle_id": selected_release_cycle_id,
            "confirmed_at": record.issued_at,
        }
        return {**stable, "context_id": _digest(stable)}

    def _validate_rollback_context_seal(
        self,
        record: ApprovalRecord,
        *,
        selected_release_cycle_id: str | None = None,
    ) -> dict[str, object]:
        if record.gate != "rollback":
            raise ReleaseRecoveryError("rollback context requires rollback approval")
        payload, _ = self._read_private_canonical_json(
            self._rollback_context_path(record.approval_id),
            label="rollback context immutable seal",
        )
        stable = {
            key: payload.get(key) for key in _ROLLBACK_CONTEXT_KEYS - {"context_id"}
        }
        expected_cycle_id = payload.get("selected_release_cycle_id")
        if (
            set(payload) != _ROLLBACK_CONTEXT_KEYS
            or payload.get("context_id") != _digest(stable)
            or payload.get("schema_version") != 1
            or payload.get("approval_id") != record.approval_id
            or payload.get("run_id") != record.run_id
            or payload.get("gate_phase") != record.gate_phase
            or payload.get("gate_revision") != record.gate_revision
            or payload.get("subject") != record.subject.to_dict()
            or payload.get("subject_digest") != record.subject.digest()
            or payload.get("target") != record.target
            or payload.get("failed_release_id") != record.failed_release_id
            or payload.get("previous_release") != record.previous_release
            or payload.get("confirmed_at") != record.issued_at
            or not isinstance(expected_cycle_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_cycle_id) is None
            or (
                selected_release_cycle_id is not None
                and expected_cycle_id != selected_release_cycle_id
            )
        ):
            raise ReleaseRecoveryError("rollback context seal is stale or invalid")
        return payload

    def _validate_intrinsic_cycle_header(
        self,
        payload: object,
        *,
        cycle_id: str,
    ) -> dict[str, object]:
        if (
            not isinstance(payload, dict)
            or set(payload) != _CYCLE_HEADER_KEYS
            or re.fullmatch(r"[0-9a-f]{64}", cycle_id) is None
        ):
            raise ReleaseRecoveryError("release cycle header is invalid")
        subject_payload = payload.get("subject")
        try:
            if not isinstance(subject_payload, dict):
                raise TypeError
            subject = EvidenceSubject(**subject_payload)
            created_at = payload["created_at"]
            if not isinstance(created_at, str):
                raise TypeError
            _parse_utc(created_at, "created_at")
        except (TypeError, ValueError) as error:
            raise ReleaseRecoveryError("release cycle header is invalid") from error
        gate = payload.get("gate")
        failed_release_id = payload.get("failed_release_id")
        previous_release = payload.get("previous_release")
        release_context_is_valid = (
            gate == "release" and failed_release_id is None and previous_release is None
        )
        rollback_context_is_valid = (
            gate == "rollback"
            and isinstance(failed_release_id, str)
            and re.fullmatch(r"[0-9a-f]{64}", failed_release_id) is not None
            and isinstance(previous_release, str)
            and bool(previous_release.strip())
        )
        identity = {key: payload[key] for key in _CYCLE_IDENTITY_KEYS}
        if (
            type(payload.get("schema_version")) is not int
            or payload.get("schema_version") != 1
            or payload.get("cycle_id") != cycle_id
            or _digest(identity) != cycle_id
            or not isinstance(payload.get("run_id"), str)
            or not payload["run_id"]
            or payload["run_id"] != subject.run_id
            or type(payload.get("gate_revision")) is not int
            or payload["gate_revision"] < 0
            or not isinstance(payload.get("approval_id"), str)
            or re.fullmatch(r"[0-9a-f]{64}", payload["approval_id"]) is None
            or payload.get("subject_digest") != subject.digest()
            or not isinstance(payload.get("target"), str)
            or not payload["target"]
            or not (release_context_is_valid or rollback_context_is_valid)
        ):
            raise ReleaseRecoveryError("release cycle header is invalid")
        return dict(payload)

    def _load_sealed_cycle_header(self, cycle_id: str) -> dict[str, object]:
        payload, _ = self._read_private_canonical_json(
            self._cycle_header_path(cycle_id),
            label="sealed release cycle header",
        )
        return self._validate_intrinsic_cycle_header(payload, cycle_id=cycle_id)

    def _validate_cycle_header(
        self,
        payload: object,
        *,
        gate: str,
        approval_id: str,
        target: str,
        failed_release_id: str | None,
        previous_release: str | None,
    ) -> dict[str, object]:
        identity = self._cycle_identity_payload(
            gate=gate,
            approval_id=approval_id,
            target=target,
            failed_release_id=failed_release_id,
            previous_release=previous_release,
        )
        expected_cycle_id = _digest(identity)
        validated = self._validate_intrinsic_cycle_header(
            payload,
            cycle_id=expected_cycle_id,
        )
        if any(validated.get(key) != value for key, value in identity.items()):
            raise ReleaseRecoveryError("release cycle header is invalid or stale")
        return validated

    def _activate_cycle(
        self,
        *,
        gate: str,
        approval_id: str,
        target: str,
        failed_release_id: str | None = None,
        previous_release: str | None = None,
    ) -> dict[str, object]:
        cycle_id = self._expected_cycle_id(
            gate=gate,
            approval_id=approval_id,
            target=target,
            failed_release_id=failed_release_id,
            previous_release=previous_release,
        )
        header_path = self._cycle_header_path(cycle_id)
        if os.path.lexists(header_path):
            header, _ = self._read_private_canonical_json(
                header_path,
                label="release cycle header",
            )
        else:
            header = {
                **self._cycle_identity_payload(
                    gate=gate,
                    approval_id=approval_id,
                    target=target,
                    failed_release_id=failed_release_id,
                    previous_release=previous_release,
                ),
                "cycle_id": cycle_id,
                "created_at": _utc_now(),
            }
            try:
                _write_immutable_json(
                    header_path,
                    header,
                    trusted_root=self.store.trusted_root,
                )
            except Exception as error:
                raise ReleaseRecoveryError(
                    "release cycle header could not be sealed"
                ) from error
        validated = self._validate_cycle_header(
            header,
            gate=gate,
            approval_id=approval_id,
            target=target,
            failed_release_id=failed_release_id,
            previous_release=previous_release,
        )
        _write_canonical_json(
            self._active_cycle_path(gate),
            validated,
            trusted_root=self.store.trusted_root,
        )
        return validated

    def _load_active_cycle(
        self,
        *,
        gate: str,
        approval_id: str,
        target: str,
        failed_release_id: str | None = None,
        previous_release: str | None = None,
    ) -> dict[str, object]:
        active_path = self._active_cycle_path(gate)
        active, _ = self._read_private_canonical_json(
            active_path,
            label="active release cycle header",
        )
        validated = self._validate_cycle_header(
            active,
            gate=gate,
            approval_id=approval_id,
            target=target,
            failed_release_id=failed_release_id,
            previous_release=previous_release,
        )
        sealed, _ = self._read_private_canonical_json(
            self._cycle_header_path(str(validated["cycle_id"])),
            label="sealed release cycle header",
        )
        if sealed != validated:
            raise ReleaseRecoveryError(
                "active release cycle differs from its immutable header"
            )
        return validated

    def _load_active_cycle_unbound(self, gate: str) -> dict[str, object]:
        active, _ = self._read_private_canonical_json(
            self._active_cycle_path(gate),
            label="active release cycle header",
        )
        if (
            set(active) != _CYCLE_HEADER_KEYS
            or active.get("gate") != gate
            or not isinstance(active.get("approval_id"), str)
            or not isinstance(active.get("target"), str)
        ):
            raise ReleaseRecoveryError("active release cycle header is invalid")
        failed_release_id = active.get("failed_release_id")
        previous_release = active.get("previous_release")
        if failed_release_id is not None and not isinstance(failed_release_id, str):
            raise ReleaseRecoveryError("active release cycle context is invalid")
        if previous_release is not None and not isinstance(previous_release, str):
            raise ReleaseRecoveryError("active release cycle context is invalid")
        return self._load_active_cycle(
            gate=gate,
            approval_id=active["approval_id"],
            target=active["target"],
            failed_release_id=failed_release_id,
            previous_release=previous_release,
        )

    def _active_cycle_for_current_gate(self, gate: str) -> dict[str, object] | None:
        active_path = self._active_cycle_path(gate)
        if not os.path.lexists(active_path):
            return None
        active, _ = self._read_private_canonical_json(
            active_path,
            label="active release cycle header",
        )
        cycle_id = active.get("cycle_id")
        if (
            set(active) != _CYCLE_HEADER_KEYS
            or active.get("schema_version") != 1
            or active.get("gate") != gate
            or type(active.get("gate_revision")) is not int
            or not isinstance(cycle_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", cycle_id) is None
            or not isinstance(active.get("created_at"), str)
        ):
            raise ReleaseRecoveryError("active release cycle header is invalid")
        sealed, _ = self._read_private_canonical_json(
            self._cycle_header_path(cycle_id),
            label="sealed release cycle header",
        )
        if sealed != active:
            raise ReleaseRecoveryError(
                "active release cycle differs from its immutable header"
            )
        current_gate_revision = self._current_gate_revision(gate)
        if active["gate_revision"] < current_gate_revision:
            return None
        if active["gate_revision"] != current_gate_revision:
            raise ReleaseRecoveryError("active release cycle gate is invalid")
        return self._load_active_cycle_unbound(gate)

    def _cycle_supersession_directory(self, cycle_id: str) -> Path:
        return self._cycle_directory(cycle_id) / "supersessions"

    def _cycle_supersession_path(
        self,
        cycle_id: str,
        replacement_approval_id: str,
    ) -> Path:
        if re.fullmatch(r"[0-9a-f]{64}", replacement_approval_id) is None:
            raise ReleaseRecoveryError("replacement approval identity is invalid")
        return (
            self._cycle_supersession_directory(cycle_id)
            / f"{replacement_approval_id}.json"
        )

    def _cycle_checkpoint(self, stage: str) -> None:
        del stage

    def _supersede_pure_prepared_cycle(
        self,
        *,
        gate: str,
        active: Mapping[str, object],
        replacement: ApprovalRecord,
    ) -> None:
        old_cycle_id = str(active.get("cycle_id"))
        old_approval_id = str(active.get("approval_id"))
        if (
            replacement.gate != gate
            or replacement.consumed_at is not None
            or active.get("target") != replacement.target
        ):
            raise ReleaseRecoveryError("cycle supersession request is stale")
        old_approval = self._load_approval(old_approval_id)
        if (
            old_approval.gate != gate
            or old_approval.run_id != replacement.run_id
            or old_approval.subject != replacement.subject
            or old_approval.target != replacement.target
            or old_approval.gate_phase != replacement.gate_phase
            or old_approval.gate_revision != replacement.gate_revision
            or old_approval.operation_digests
            != _operation_digests(self._specs_for_gate(gate), self.variables)
            or old_approval.consumed_at is not None
            or old_approval.consumed_by is not None
            or _parse_utc(old_approval.expires_at, "expires_at")
            > datetime.now(timezone.utc)
        ):
            raise ReleaseRecoveryError(
                "only an expired unconsumed cycle can be superseded"
            )
        inspection = validate_external_operation_evidence(
            repo=self.repo,
            run_directory=self.run_directory,
            manifest=self.manifest,
            current_subject=self.current_subject,
            variables=self.variables,
            phase=(
                Phase.AWAITING_RELEASE_APPROVAL
                if gate == "release"
                else Phase.ROLLBACK_PENDING
            ),
        )
        mode = gate
        records = tuple(
            record
            for record in inspection.records
            if record.cycle_id == old_cycle_id and record.mode == mode
        )
        if len(records) > 1 or (
            records
            and (
                records[0].index != 1
                or records[0].attempt != 1
                or records[0].status is not OperationStatus.PREPARED
                or records[0].approval_id != old_approval_id
            )
        ):
            raise ReleaseRecoveryError(
                "cycle has evidence beyond an exact first PREPARED receipt"
            )
        if any(
            event.operation_start is not None
            and event.operation_start.get("cycle_id") == old_cycle_id
            for event in self.store.operation_start_markers()
        ):
            raise ReleaseRecoveryError("cycle supersession has an operation start WAL")
        cycle_entries = {
            path.name
            for path in self._private_directory_paths(
                self._cycle_directory(old_cycle_id),
                label="superseded cycle directory",
            )
        }
        allowed_entries = {"header.json"}
        if records:
            allowed_entries.add("operations")
            operation_root = self._cycle_directory(old_cycle_id) / "operations"
            operation_entries = {
                path.name
                for path in self._private_directory_paths(
                    operation_root,
                    label="superseded cycle operation directory",
                )
            }
            if operation_entries != {
                f"{mode}-0001.json",
                "committed",
                "sealed",
            }:
                raise ReleaseRecoveryError(
                    "superseded cycle operation evidence is not exact"
                )
            pointer, _ = self._read_operation_file(operation_root / f"{mode}-0001.json")
            if pointer != records[0]:
                raise ReleaseRecoveryError(
                    "superseded cycle pointer differs from PREPARED receipt"
                )
        supersession_directory = self._cycle_supersession_directory(old_cycle_id)
        supersession_paths = self._private_directory_paths(
            supersession_directory,
            label="cycle supersession receipt directory",
            missing_ok=True,
        )
        if supersession_paths:
            allowed_entries.add("supersessions")
        for path in supersession_paths:
            existing, _ = self._read_private_canonical_json(
                path,
                label="cycle supersession immutable receipt",
            )
            existing_stable = {
                key: existing.get(key)
                for key in _CYCLE_SUPERSESSION_KEYS - {"supersession_id"}
            }
            if (
                re.fullmatch(r"[0-9a-f]{64}\.json", path.name) is None
                or set(existing) != _CYCLE_SUPERSESSION_KEYS
                or existing.get("supersession_id") != _digest(existing_stable)
                or existing.get("run_id") != replacement.run_id
                or existing.get("gate") != gate
                or existing.get("gate_revision") != active["gate_revision"]
                or existing.get("subject_digest") != replacement.subject.digest()
                or existing.get("old_cycle_id") != old_cycle_id
                or existing.get("old_approval_id") != old_approval_id
                or existing.get("target") != replacement.target
                or existing.get("reason") != "expired-unconsumed-pure-prepared"
                or path.name != f"{existing.get('replacement_approval_id')}.json"
            ):
                raise ReleaseRecoveryError("cycle supersession receipt conflicts")
        if cycle_entries != allowed_entries:
            raise ReleaseRecoveryError("superseded cycle has unknown evidence")
        stable: dict[str, object] = {
            "schema_version": 1,
            "run_id": replacement.run_id,
            "gate": gate,
            "gate_revision": active["gate_revision"],
            "subject_digest": replacement.subject.digest(),
            "old_cycle_id": old_cycle_id,
            "old_approval_id": old_approval_id,
            "replacement_approval_id": replacement.approval_id,
            "target": replacement.target,
            "reason": "expired-unconsumed-pure-prepared",
            "recorded_at": _utc_now(),
        }
        payload = {**stable, "supersession_id": _digest(stable)}
        supersession_path = self._cycle_supersession_path(
            old_cycle_id,
            replacement.approval_id,
        )
        existing_paths = {path.name: path for path in supersession_paths}
        if supersession_path.name in existing_paths:
            existing, _ = self._read_private_canonical_json(
                existing_paths[supersession_path.name],
                label="cycle supersession immutable receipt",
            )
            if (
                set(existing) != _CYCLE_SUPERSESSION_KEYS
                or any(
                    existing.get(key) != value
                    for key, value in stable.items()
                    if key != "recorded_at"
                )
                or existing.get("supersession_id")
                != _digest(
                    {
                        key: existing[key]
                        for key in _CYCLE_SUPERSESSION_KEYS - {"supersession_id"}
                    }
                )
            ):
                raise ReleaseRecoveryError("cycle supersession receipt conflicts")
            self._cycle_checkpoint("supersession-sealed")
            return
        try:
            _write_immutable_json(
                supersession_path,
                payload,
                trusted_root=self.store.trusted_root,
            )
        except Exception as error:
            raise ReleaseRecoveryError(
                "cycle supersession receipt could not be sealed"
            ) from error
        self._cycle_checkpoint("supersession-sealed")

    def _specs_for_gate(self, gate: str) -> tuple[OperationSpec, ...]:
        if gate == "release":
            return self.manifest.release_steps
        if gate == "rollback":
            return self.manifest.rollback_steps
        raise ReleaseError("approval gate is invalid")

    def record_approval(
        self,
        *,
        gate: str,
        target: str,
        approver_actor: str,
        expires_at: str,
        failed_release_id: str | None = None,
        previous_release: str | None = None,
        allow_default_expiry_recovery: bool = False,
    ) -> ApprovalRecord:
        with (
            self._approval_lock() as approval_lock,
            self.store.anchored(approval_lock.trusted_parent),
        ):
            return self._record_approval_locked(
                gate=gate,
                target=target,
                approver_actor=approver_actor,
                expires_at=expires_at,
                failed_release_id=failed_release_id,
                previous_release=previous_release,
                allow_default_expiry_recovery=allow_default_expiry_recovery,
            )

    def inspect_current_unconsumed_approval(
        self,
        *,
        gate: str,
    ) -> ApprovalRecord | None:
        """Return the one current approval without consuming or repairing it."""

        if gate not in {"release", "rollback"}:
            raise ReleaseRecoveryError("approval gate is invalid")
        run_path = Path(os.path.abspath(self.run_directory))
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            run_descriptor = os.open(run_path, flags)
        except OSError as error:
            raise ReleaseRecoveryError(
                "approval run directory cannot be opened safely"
            ) from error
        try:
            metadata = os.fstat(run_descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ReleaseRecoveryError("approval run directory is unsafe")
            anchor = PrivateRootAnchor(run_path, run_descriptor)
            with self.store.anchored(anchor):
                self._assert_run_root_current()
                approval = self._inspect_current_unconsumed_approval_anchored(gate)
                self._assert_run_root_current()
                return approval
        except ReleaseRecoveryError:
            raise
        except (OSError, RuntimeError, ValueError) as error:
            raise ReleaseRecoveryError(
                "approval evidence cannot be inspected safely"
            ) from error
        finally:
            os.close(run_descriptor)

    def inspect_active_external_context(
        self,
        *,
        phase: Phase,
    ) -> ExternalCycleContext | None:
        """Read the sealed active-cycle context without repairing or executing it."""

        release_phases = {
            Phase.AWAITING_RELEASE_APPROVAL,
            Phase.RELEASING,
            Phase.POST_RELEASE_VERIFYING,
        }
        rollback_phases = {
            Phase.ROLLBACK_PENDING,
            Phase.ROLLING_BACK,
            Phase.ROLLBACK_VERIFYING,
        }
        if phase in release_phases:
            gate = "release"
        elif phase in rollback_phases:
            gate = "rollback"
        else:
            raise ReleaseRecoveryError("phase has no active external context")
        run_path = Path(os.path.abspath(self.run_directory))
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(run_path, flags)
        except OSError as error:
            raise ReleaseRecoveryError(
                "external context run directory cannot be opened safely"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ReleaseRecoveryError("external context run directory is unsafe")
            anchor = PrivateRootAnchor(run_path, descriptor)
            with self.store.anchored(anchor):
                self._assert_run_root_current()
                state = self.store.load()
                if state.phase is not phase:
                    raise ReleaseRecoveryError("external context phase is stale")
                active_path = self._active_cycle_path(gate)
                cycle_names = {
                    path.name
                    for path in self._private_directory_paths(
                        self._cycle_root(),
                        label="release-cycle evidence root",
                        missing_ok=True,
                    )
                }
                if active_path.name not in cycle_names:
                    if phase in {
                        Phase.AWAITING_RELEASE_APPROVAL,
                        Phase.ROLLBACK_PENDING,
                    }:
                        self._assert_run_root_current()
                        return None
                    raise ReleaseRecoveryError("active external context is missing")
                active = self._load_active_cycle_unbound(gate)
                approval = self._read_approval_read_only(str(active["approval_id"]))
                if (
                    approval.gate != gate
                    or approval.subject != self.current_subject
                    or approval.target != active.get("target")
                    or approval.failed_release_id != active.get("failed_release_id")
                    or approval.previous_release != active.get("previous_release")
                ):
                    raise ReleaseRecoveryError("active external approval is stale")
                if gate == "rollback":
                    context = self._validate_rollback_context_seal(approval)
                    release_cycle = self._load_active_cycle_unbound("release")
                    if (
                        release_cycle.get("cycle_id")
                        != context.get("selected_release_cycle_id")
                        or release_cycle.get("approval_id")
                        != approval.failed_release_id
                        or release_cycle.get("target") != approval.target
                    ):
                        raise ReleaseRecoveryError(
                            "rollback context is not bound to the active failed release"
                        )
                context = ExternalCycleContext(
                    cycle_id=str(active["cycle_id"]),
                    mode=gate,
                    approval_id=approval.approval_id,
                    target=approval.target,
                    failed_release_id=approval.failed_release_id,
                    previous_release=approval.previous_release,
                )
                self._assert_run_root_current()
                return context
        except ReleaseRecoveryError:
            raise
        except (OSError, RuntimeError, ValueError) as error:
            raise ReleaseRecoveryError(
                "active external context cannot be inspected safely"
            ) from error
        finally:
            os.close(descriptor)

    def _read_approval_read_only(self, approval_id: str) -> ApprovalRecord:
        seal_payload, _ = self._read_private_canonical_json(
            self._approval_seal_path(approval_id),
            label="approval immutable seal",
        )
        pointer_payload, _ = self._read_private_canonical_json(
            self._approval_path(approval_id),
            label="approval pointer",
        )
        consumed_path = self._approval_consumed_path(approval_id)
        consumed_names = {
            path.name
            for path in self._private_directory_paths(
                consumed_path.parent,
                label="approval consumption directory",
                missing_ok=True,
            )
        }
        if any(
            re.fullmatch(r"[0-9a-f]{64}\.json", name) is None for name in consumed_names
        ):
            raise ReleaseRecoveryError(
                "approval consumption directory has unknown entries"
            )
        consumed_exists = consumed_path.name in consumed_names
        if consumed_exists:
            consumed_payload, _ = self._read_private_canonical_json(
                consumed_path,
                label="approval consumption commitment",
            )
            if pointer_payload != consumed_payload:
                try:
                    cached_pointer = _approval_from_payload(pointer_payload)
                except ReleaseError as error:
                    raise ReleaseRecoveryError(
                        "approval pointer conflicts with consumption commitment"
                    ) from error
                if (
                    cached_pointer.approval_id != approval_id
                    or _approval_stable_payload(cached_pointer) != seal_payload
                    or cached_pointer.consumed_at is not None
                    or cached_pointer.consumed_by is not None
                ):
                    raise ReleaseRecoveryError(
                        "approval pointer conflicts with consumption commitment"
                    )
            selected_payload = consumed_payload
        else:
            selected_payload = pointer_payload
        try:
            record = _approval_from_payload(selected_payload)
        except ReleaseError as error:
            raise ReleaseRecoveryError("active approval is invalid") from error
        if (
            record.approval_id != approval_id
            or _approval_stable_payload(record) != seal_payload
            or _digest(seal_payload) != approval_id
            or (
                consumed_exists
                and (record.consumed_at is None or record.consumed_by is None)
            )
            or (
                not consumed_exists
                and (record.consumed_at is not None or record.consumed_by is not None)
            )
        ):
            raise ReleaseRecoveryError("active approval seal is stale or invalid")
        return record

    def _inspect_current_unconsumed_approval_anchored(
        self,
        gate: str,
    ) -> ApprovalRecord | None:
        events = self.store.events()
        if not events:
            raise ReleaseRecoveryError("approval gate has no state evidence")
        state = events[-1].state
        expected_phase = (
            Phase.AWAITING_RELEASE_APPROVAL
            if gate == "release"
            else Phase.ROLLBACK_PENDING
        )
        if (
            state.phase is not expected_phase
            or state.run_id != self.current_subject.run_id
        ):
            raise ReleaseRecoveryError("approval gate is not current")

        approval_root = self.run_directory / "approvals"
        root_paths = self._private_directory_paths(
            approval_root,
            label="approval directory",
            missing_ok=True,
        )
        root_names = {path.name for path in root_paths}
        pointer_names = {
            name
            for name in root_names
            if re.fullmatch(r"[0-9a-f]{64}\.json", name) is not None
        }
        if (
            root_names
            - pointer_names
            - {
                "plan",
                "sealed",
                "consumed",
                "rollback-contexts",
                "abandoned",
            }
        ):
            raise ReleaseRecoveryError("approval directory has unknown entries")

        def receipt_names(directory_name: str) -> set[str]:
            if directory_name not in root_names:
                return set()
            paths = self._private_directory_paths(
                approval_root / directory_name,
                label=f"approval {directory_name} directory",
            )
            names = {path.name for path in paths}
            if any(re.fullmatch(r"[0-9a-f]{64}\.json", name) is None for name in names):
                raise ReleaseRecoveryError(
                    f"approval {directory_name} directory has unknown entries"
                )
            return names

        sealed_names = receipt_names("sealed")
        consumed_names = receipt_names("consumed")
        abandoned_names = self._abandoned_approval_names()
        if (
            sealed_names != pointer_names | abandoned_names
            or pointer_names & abandoned_names
            or not consumed_names <= pointer_names
        ):
            raise ReleaseRecoveryError("approval receipt set is incomplete")

        expected_digests = _operation_digests(
            self._specs_for_gate(gate), self.variables
        )
        candidates: list[ApprovalRecord] = []
        for pointer_name in sorted(pointer_names):
            approval_id = pointer_name.removesuffix(".json")
            pointer_payload, _ = self._read_private_canonical_json(
                approval_root / pointer_name,
                label="approval pointer",
            )
            seal_payload, _ = self._read_private_canonical_json(
                approval_root / "sealed" / pointer_name,
                label="approval immutable seal",
            )
            try:
                pointer = _approval_from_payload(pointer_payload)
            except ReleaseError as error:
                raise ReleaseRecoveryError("approval pointer is invalid") from error
            if (
                pointer.approval_id != approval_id
                or _approval_stable_payload(pointer) != seal_payload
                or _digest(seal_payload) != approval_id
            ):
                raise ReleaseRecoveryError(
                    "approval receipt differs from its immutable seal"
                )
            if pointer.gate == "rollback":
                self._validate_rollback_context_seal(pointer)
            if pointer_name in consumed_names:
                consumed_payload, _ = self._read_private_canonical_json(
                    approval_root / "consumed" / pointer_name,
                    label="approval consumption commitment",
                )
                try:
                    consumed = _approval_from_payload(consumed_payload)
                except ReleaseError as error:
                    raise ReleaseRecoveryError(
                        "approval consumption commitment is invalid"
                    ) from error
                if (
                    consumed.approval_id != approval_id
                    or consumed.consumed_at is None
                    or consumed.consumed_by is None
                    or _approval_stable_payload(consumed) != seal_payload
                ):
                    raise ReleaseRecoveryError(
                        "approval consumption commitment is invalid"
                    )
                if pointer_payload != consumed_payload:
                    if (
                        pointer.approval_id != consumed.approval_id
                        or _approval_stable_payload(pointer) != seal_payload
                        or pointer.consumed_at is not None
                        or pointer.consumed_by is not None
                    ):
                        raise ReleaseRecoveryError(
                            "approval pointer conflicts with consumption commitment"
                        )
                pointer = consumed
            elif pointer.consumed_at is not None or pointer.consumed_by is not None:
                raise ReleaseRecoveryError(
                    "approval consumption is not durably committed"
                )

            is_current_generation = pointer.gate == gate and (
                (
                    pointer.gate_phase == expected_phase.value
                    and pointer.gate_revision == state.revision
                )
                or (
                    gate == "rollback"
                    and pointer.gate_phase == Phase.AWAITING_RELEASE_APPROVAL.value
                    and pointer.gate_revision == self._current_gate_revision("release")
                    and bool(self.manifest.rollback_steps)
                    and all(
                        step.data_impact == "none"
                        for step in self.manifest.rollback_steps
                    )
                )
            )
            if not is_current_generation:
                continue
            if pointer_name in consumed_names:
                raise ReleaseRecoveryError("current approval has been consumed")
            try:
                expired = _parse_utc(pointer.expires_at, "expires_at") <= datetime.now(
                    timezone.utc
                )
            except ValueError as error:
                raise ReleaseRecoveryError("approval expiry is invalid") from error
            if (
                pointer.run_id != state.run_id
                or pointer.subject != self.current_subject
                or pointer.operation_digests != expected_digests
                or manifest_digest(self.manifest)
                != self.current_subject.manifest_sha256
            ):
                raise ReleaseRecoveryError("current approval is stale")
            if expired:
                continue
            candidates.append(pointer)

        if len(candidates) > 1:
            raise ReleaseRecoveryError("current approval is ambiguous")
        return candidates[0] if candidates else None

    def _record_approval_locked(
        self,
        *,
        gate: str,
        target: str,
        approver_actor: str,
        expires_at: str,
        failed_release_id: str | None = None,
        previous_release: str | None = None,
        allow_default_expiry_recovery: bool = False,
    ) -> ApprovalRecord:
        if not isinstance(approver_actor, str) or not approver_actor.strip():
            raise ReleaseError("approval actor must be a non-empty string")
        if not isinstance(target, str) or not target.strip():
            raise ReleaseError("approval target must be a non-empty string")
        try:
            parsed_expiry = _parse_utc(expires_at, "expires_at")
        except ValueError as error:
            raise ReleaseError("approval expiry is invalid") from error
        if parsed_expiry <= datetime.now(timezone.utc):
            raise ReleaseError("approval expiry must be in the future")
        state = self.store.load()
        selected_release_cycle_id: str | None = None
        if gate not in {"release", "rollback"}:
            raise ReleaseError("approval gate is invalid")
        if gate == "release":
            if state.phase is not Phase.AWAITING_RELEASE_APPROVAL:
                raise ReleaseError(
                    "release approval requires AWAITING_RELEASE_APPROVAL"
                )
            if failed_release_id is not None or previous_release is not None:
                raise ReleaseError("release approval cannot bind rollback context")
        else:
            allowed_phase = state.phase is Phase.ROLLBACK_PENDING or (
                state.phase is Phase.AWAITING_RELEASE_APPROVAL
                and self.manifest.rollback_steps
                and all(
                    step.data_impact == "none" for step in self.manifest.rollback_steps
                )
            )
            if not allowed_phase:
                raise ReleaseError(
                    "rollback approval requires action-time confirmation"
                )
            if (
                not isinstance(failed_release_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", failed_release_id) is None
                or not isinstance(previous_release, str)
                or not previous_release.strip()
            ):
                raise ReleaseError("rollback approval context is invalid")
            selected_release_cycle_id = self._selected_failed_release_cycle_id(
                state_phase=state.phase,
                target=target.strip(),
                failed_release_id=failed_release_id,
            )
        if state.run_id != self.current_subject.run_id:
            raise ReleaseError("approval subject belongs to another run")
        specs = self._specs_for_gate(gate)
        if not specs:
            raise ReleaseError(f"{gate} approval has no operations")
        recovered = self._recover_orphaned_approval(
            state=state,
            gate=gate,
            target=target.strip(),
            approver_actor=approver_actor.strip(),
            expires_at=expires_at,
            failed_release_id=failed_release_id,
            previous_release=(
                previous_release.strip() if isinstance(previous_release, str) else None
            ),
            operation_digests=_operation_digests(specs, self.variables),
            selected_release_cycle_id=selected_release_cycle_id,
            allow_default_expiry_recovery=allow_default_expiry_recovery,
        )
        if recovered is not None:
            return recovered
        reusable = self._reuse_published_approval(
            state=state,
            gate=gate,
            target=target.strip(),
            approver_actor=approver_actor.strip(),
            expires_at=expires_at,
            failed_release_id=failed_release_id,
            previous_release=(
                previous_release.strip() if isinstance(previous_release, str) else None
            ),
            operation_digests=_operation_digests(specs, self.variables),
            selected_release_cycle_id=selected_release_cycle_id,
            allow_default_expiry_recovery=allow_default_expiry_recovery,
        )
        if reusable is not None:
            return reusable
        issued_at = _utc_now()
        provisional = ApprovalRecord(
            approval_id="0" * 64,
            run_id=state.run_id,
            gate=gate,
            gate_phase=state.phase.value,
            gate_revision=state.revision,
            approver_actor=approver_actor.strip(),
            subject=self.current_subject,
            target=target.strip(),
            operation_digests=_operation_digests(specs, self.variables),
            failed_release_id=failed_release_id,
            previous_release=(
                previous_release.strip() if isinstance(previous_release, str) else None
            ),
            issued_at=issued_at,
            expires_at=expires_at,
        )
        record = replace(
            provisional,
            approval_id=_digest(_approval_stable_payload(provisional)),
        )
        seal_path = self._approval_seal_path(record.approval_id)
        pointer_path = self._approval_path(record.approval_id)
        try:
            _write_immutable_json(
                seal_path,
                _approval_stable_payload(record),
                trusted_root=self.store.trusted_root,
            )
            if record.gate == "rollback":
                if selected_release_cycle_id is None:
                    raise ReleaseError("rollback context selection is missing")
                _write_immutable_json(
                    self._rollback_context_path(record.approval_id),
                    self._rollback_context_payload(
                        record,
                        selected_release_cycle_id=selected_release_cycle_id,
                    ),
                    trusted_root=self.store.trusted_root,
                )
            _write_canonical_json(
                pointer_path,
                _approval_payload(record),
                trusted_root=self.store.trusted_root,
            )
        except Exception as error:
            raise ReleaseError("approval receipt could not be recorded") from error
        return record

    def _recover_orphaned_approval(
        self,
        *,
        state: object,
        gate: str,
        target: str,
        approver_actor: str,
        expires_at: str,
        failed_release_id: str | None,
        previous_release: str | None,
        operation_digests: tuple[str, ...],
        selected_release_cycle_id: str | None,
        allow_default_expiry_recovery: bool,
    ) -> ApprovalRecord | None:
        approval_root = self.run_directory / "approvals"
        sealed_names = {
            path.name
            for path in self._private_directory_paths(
                approval_root / "sealed",
                label="approval seal directory",
                missing_ok=True,
            )
        }
        pointer_names = {
            path.name
            for path in self._private_directory_paths(
                approval_root,
                label="approval directory",
                missing_ok=True,
            )
            if re.fullmatch(r"[0-9a-f]{64}\.json", path.name) is not None
        }
        abandoned_names = self._abandoned_approval_names()
        if not abandoned_names <= sealed_names or abandoned_names & pointer_names:
            raise ReleaseRecoveryError("abandoned approval set is invalid")
        orphan_names = sealed_names - pointer_names - abandoned_names
        if not orphan_names:
            return None
        if any(
            re.fullmatch(r"[0-9a-f]{64}\.json", name) is None for name in sealed_names
        ):
            raise ReleaseRecoveryError("approval seal directory has unknown entries")
        consumed_names = {
            path.name
            for path in self._private_directory_paths(
                approval_root / "consumed",
                label="approval consumption directory",
                missing_ok=True,
            )
        }
        if orphan_names & consumed_names:
            raise ReleaseRecoveryError("orphan approval is already consumed")
        context_names = {
            path.name
            for path in self._private_directory_paths(
                approval_root / "rollback-contexts",
                label="rollback context directory",
                missing_ok=True,
            )
        }
        matching: list[ApprovalRecord] = []
        live_orphans: list[ApprovalRecord] = []
        for name in sorted(orphan_names):
            approval_id = name.removesuffix(".json")
            seal_payload, _ = self._read_private_canonical_json(
                approval_root / "sealed" / name,
                label="orphan approval immutable seal",
            )
            try:
                record = _approval_from_payload(
                    {**seal_payload, "approval_id": approval_id}
                )
            except ReleaseError as error:
                raise ReleaseRecoveryError("orphan approval seal is invalid") from error
            if (
                _approval_stable_payload(record) != seal_payload
                or _digest(seal_payload) != approval_id
            ):
                raise ReleaseRecoveryError("orphan approval identity is invalid")
            context_name = f"{record.approval_id}.json"
            if record.gate == "rollback" and context_name in context_names:
                self._validate_rollback_context_seal(record)
            elif record.gate == "release" and context_name in context_names:
                raise ReleaseRecoveryError("release approval has a rollback context")
            if _parse_utc(record.expires_at, "expires_at") <= datetime.now(
                timezone.utc
            ):
                self._abandon_expired_orphan(record)
                continue
            live_orphans.append(record)
            if (
                record.run_id == state.run_id
                and record.gate == gate
                and record.gate_phase == state.phase.value
                and record.gate_revision == state.revision
                and record.approver_actor == approver_actor
                and record.subject == self.current_subject
                and record.target == target
                and record.operation_digests == operation_digests
                and record.failed_release_id == failed_release_id
                and record.previous_release == previous_release
                and (
                    record.expires_at == expires_at
                    or (
                        allow_default_expiry_recovery
                        and _parse_utc(record.expires_at, "expires_at")
                        > datetime.now(timezone.utc)
                    )
                )
                and record.consumed_at is None
                and record.consumed_by is None
            ):
                matching.append(record)
        if not live_orphans:
            return None
        if len(matching) != 1 or len(live_orphans) != 1:
            raise ReleaseRecoveryError(
                "orphan approval publication is ambiguous or belongs to another request"
            )
        record = matching[0]
        context_name = f"{record.approval_id}.json"
        if record.gate == "rollback":
            if selected_release_cycle_id is None:
                raise ReleaseRecoveryError("rollback orphan context is incomplete")
            if context_name in context_names:
                self._validate_rollback_context_seal(
                    record,
                    selected_release_cycle_id=selected_release_cycle_id,
                )
            else:
                try:
                    _write_immutable_json(
                        self._rollback_context_path(record.approval_id),
                        self._rollback_context_payload(
                            record,
                            selected_release_cycle_id=selected_release_cycle_id,
                        ),
                        trusted_root=self.store.trusted_root,
                    )
                except Exception as error:
                    raise ReleaseRecoveryError(
                        "rollback orphan context could not be sealed"
                    ) from error
        elif context_name in context_names:
            raise ReleaseRecoveryError("release approval has a rollback context")
        try:
            _write_canonical_json(
                self._approval_path(record.approval_id),
                _approval_payload(record),
                trusted_root=self.store.trusted_root,
            )
        except Exception as error:
            raise ReleaseRecoveryError(
                "orphan approval pointer could not be published"
            ) from error
        return record

    def _reuse_published_approval(
        self,
        *,
        state: object,
        gate: str,
        target: str,
        approver_actor: str,
        expires_at: str,
        failed_release_id: str | None,
        previous_release: str | None,
        operation_digests: tuple[str, ...],
        selected_release_cycle_id: str | None,
        allow_default_expiry_recovery: bool,
    ) -> ApprovalRecord | None:
        approval_root = self.run_directory / "approvals"
        pointer_paths = tuple(
            path
            for path in self._private_directory_paths(
                approval_root,
                label="approval directory",
                missing_ok=True,
            )
            if re.fullmatch(r"[0-9a-f]{64}\.json", path.name) is not None
        )
        matching: list[ApprovalRecord] = []
        for path in pointer_paths:
            record = self._read_approval_read_only(path.stem)
            if (
                record.run_id == state.run_id
                and record.gate == gate
                and record.gate_phase == state.phase.value
                and record.gate_revision == state.revision
                and record.approver_actor == approver_actor
                and record.subject == self.current_subject
                and record.target == target
                and record.operation_digests == operation_digests
                and record.failed_release_id == failed_release_id
                and record.previous_release == previous_release
                and record.consumed_at is None
                and record.consumed_by is None
                and _parse_utc(record.expires_at, "expires_at")
                > datetime.now(timezone.utc)
                and (record.expires_at == expires_at or allow_default_expiry_recovery)
            ):
                if record.gate == "rollback":
                    if selected_release_cycle_id is None:
                        raise ReleaseRecoveryError(
                            "published rollback context is incomplete"
                        )
                    self._validate_rollback_context_seal(
                        record,
                        selected_release_cycle_id=selected_release_cycle_id,
                    )
                matching.append(record)
        if len(matching) > 1:
            raise ReleaseRecoveryError("published approval retry is ambiguous")
        return matching[0] if matching else None

    def _load_approval(self, approval_id: str) -> ApprovalRecord:
        path = self._approval_path(approval_id)
        seal_path = self._approval_seal_path(approval_id)
        seal_payload, _ = self._read_private_canonical_json(
            seal_path,
            label="approval immutable seal",
        )
        consumed_path = self._approval_consumed_path(approval_id)
        consumed_payload: dict[str, object] | None = None
        if os.path.lexists(consumed_path):
            consumed_payload, _ = self._read_private_canonical_json(
                consumed_path,
                label="approval consumption commitment",
            )
        pointer_payload: dict[str, object] | None = None
        if os.path.lexists(path):
            pointer_payload, _ = self._read_private_canonical_json(
                path,
                label="approval pointer",
            )
        if consumed_payload is not None:
            record = _approval_from_payload(consumed_payload)
            if record.consumed_at is None or record.consumed_by is None:
                raise ReleaseError("approval consumption commitment is invalid")
            if pointer_payload != consumed_payload:
                if pointer_payload is not None:
                    pointer_record = _approval_from_payload(pointer_payload)
                    if (
                        _approval_stable_payload(pointer_record) != seal_payload
                        or pointer_record.consumed_at is not None
                        or pointer_record.consumed_by is not None
                    ):
                        raise ReleaseError(
                            "approval pointer conflicts with consumption commitment"
                        )
                _write_canonical_json(
                    path,
                    consumed_payload,
                    trusted_root=self.store.trusted_root,
                )
        else:
            if pointer_payload is None:
                raise ReleaseError("approval receipt is missing or corrupt")
            record = _approval_from_payload(pointer_payload)
            if record.consumed_at is not None or record.consumed_by is not None:
                raise ReleaseError("approval consumption is not durably committed")
        stable = _approval_stable_payload(record)
        if (
            record.approval_id != approval_id
            or seal_payload != stable
            or _digest(seal_payload) != approval_id
        ):
            raise ReleaseError("approval receipt differs from its immutable seal")
        if record.gate == "rollback":
            self._validate_rollback_context_seal(record)
        return record

    def consume_approval(
        self,
        approval_id: str,
        *,
        consumer: str,
    ) -> ApprovalRecord:
        if not isinstance(consumer, str) or not consumer.strip():
            raise ReleaseError("approval consumer must be a non-empty string")
        with (
            self._approval_lock() as approval_lock,
            self.store.anchored(approval_lock.trusted_parent),
        ):
            record = self._load_approval(approval_id)
            if record.consumed_at is not None:
                raise ReleaseError("approval has already been consumed")
            consumed = replace(
                record,
                consumed_at=_utc_now(),
                consumed_by=consumer.strip(),
            )
            try:
                _write_immutable_json(
                    self._approval_consumed_path(approval_id),
                    _approval_payload(consumed),
                    trusted_root=self.store.trusted_root,
                )
            except Exception as error:
                raise ReleaseError(
                    "approval consumption could not be committed"
                ) from error
            _write_canonical_json(
                self._approval_path(approval_id),
                _approval_payload(consumed),
                trusted_root=self.store.trusted_root,
            )
            return consumed

    def _validate_approval(
        self,
        approval_id: str,
        *,
        gate: str,
        target: str,
        allow_consumed_by: str | None = None,
        failed_release_id: str | None = None,
        previous_release: str | None = None,
    ) -> ApprovalRecord:
        record = self._load_approval(approval_id)
        state = self.store.load()
        expected_digests = _operation_digests(
            self._specs_for_gate(gate), self.variables
        )
        try:
            expired = _parse_utc(record.expires_at, "expires_at") <= datetime.now(
                timezone.utc
            )
        except ValueError as error:
            raise ReleaseError("approval expiry is invalid") from error
        if record.gate_phase == Phase.ROLLBACK_PENDING.value:
            gate_generation_is_current = (
                record.gate == "rollback"
                and record.gate_revision == self._current_gate_revision("rollback")
            )
        elif record.gate_phase == Phase.AWAITING_RELEASE_APPROVAL.value:
            gate_generation_is_current = (
                record.gate_revision == self._current_gate_revision("release")
                and (
                    record.gate == "release"
                    or (
                        record.gate == "rollback"
                        and bool(self.manifest.rollback_steps)
                        and all(
                            step.data_impact == "none"
                            for step in self.manifest.rollback_steps
                        )
                    )
                )
            )
        else:
            gate_generation_is_current = False
        if (
            record.gate != gate
            or record.run_id != state.run_id
            or record.subject != self.current_subject
            or record.target != target
            or record.operation_digests != expected_digests
            or record.failed_release_id != failed_release_id
            or record.previous_release != previous_release
            or not gate_generation_is_current
            or (
                record.consumed_at is not None
                and record.consumed_by != allow_consumed_by
            )
            or (expired and record.consumed_at is None)
            or manifest_digest(self.manifest) != self.current_subject.manifest_sha256
        ):
            raise ReleaseError("approval does not authorize this operation")
        return record

    def _git_common_directory(self) -> Path:
        try:
            completed = subprocess.run(
                ("git", "rev-parse", "--git-common-dir"),
                cwd=self.repo,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except OSError as error:
            raise ReleaseError("Git common directory cannot be determined") from error
        value = completed.stdout.strip()
        if completed.returncode != 0 or not value or "\n" in value:
            raise ReleaseError("Git common directory cannot be determined")
        path = Path(value)
        if not path.is_absolute():
            path = self.repo / path
        try:
            return path.resolve(strict=True)
        except OSError as error:
            raise ReleaseError("Git common directory cannot be resolved") from error

    def _git_read(self, *arguments: str) -> str:
        try:
            completed = subprocess.run(
                ("git", *arguments),
                cwd=self.repo,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except OSError as error:
            raise ReleaseError("live Git evidence cannot be inspected") from error
        if completed.returncode != 0:
            raise ReleaseError("live Git evidence cannot be inspected")
        return completed.stdout.strip()

    def _read_private_canonical_json(
        self,
        path: Path,
        *,
        label: str,
    ) -> tuple[dict[str, object], bytes]:
        try:
            raw = _read_bounded_private_file(
                path,
                trusted_root=self.store.trusted_root,
                label=label,
                max_bytes=4 * 1024 * 1024,
            )
        except (OSError, RuntimeError, ValueError) as error:
            raise ReleaseRecoveryError(f"{label} cannot be opened safely") from error
        try:
            payload = json.loads(raw.decode("utf-8"))
            canonical = _canonical_json_bytes(payload) + b"\n"
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            TypeError,
        ) as error:
            raise ReleaseRecoveryError(f"{label} is corrupt") from error
        if not isinstance(payload, dict) or raw != canonical:
            raise ReleaseRecoveryError(f"{label} is not canonical JSON")
        return payload, raw

    def _private_directory_paths(
        self,
        path: Path,
        *,
        label: str,
        missing_ok: bool = False,
    ) -> tuple[Path, ...]:
        try:
            names = _private_directory_names(
                path,
                trusted_root=self.store.trusted_root,
            )
        except StateNotFoundError:
            if missing_ok:
                return ()
            raise ReleaseError(f"{label} is missing") from None
        except (OSError, RuntimeError, ValueError) as error:
            raise ReleaseError(f"{label} cannot be listed safely") from error
        return tuple(path / name for name in names)

    def _assert_run_root_current(self) -> None:
        trusted_root = self.store.trusted_root
        if not isinstance(trusted_root, PrivateRootAnchor):
            return
        try:
            opened = os.fstat(trusted_root.descriptor)
            current = os.stat(self.run_directory, follow_symlinks=False)
        except OSError as error:
            raise ReleaseRecoveryError(
                "release run directory changed during inspection"
            ) from error
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ReleaseRecoveryError(
                "release run directory changed during inspection"
            )

    def _assert_passing_verification_evidence(self) -> None:
        events = self.store.events()
        publication_events = [
            event
            for event in events
            if event.run_id == self.current_subject.run_id
            and event.previous_phase is Phase.VERIFYING
            and event.phase is Phase.AWAITING_RELEASE_APPROVAL
        ]
        if not publication_events:
            raise ReleaseError("passing verification is not bound to the state WAL")
        transition = publication_events[-1]
        expected_revision = transition.revision - 1
        expected_round = sum(
            event.phase is Phase.VERIFYING and event.revision <= expected_revision
            for event in events
        )
        publication_directory = self.run_directory / "verification-publications"
        publication_paths = tuple(
            path
            for path in self._private_directory_paths(
                publication_directory,
                label="verification publication directory",
            )
            if re.fullmatch(
                rf"verification-{expected_round:04d}-[0-9a-f]{{64}}\.json",
                path.name,
            )
        )
        if len(publication_paths) != 1:
            raise ReleaseError("verification publication seal set is invalid")
        publication_path = publication_paths[0]
        publication, publication_raw = self._read_private_canonical_json(
            publication_path,
            label="verification publication seal",
        )
        report_payload = publication.get("report")
        expected_report_path = (
            self.run_directory
            / "verifications"
            / f"verification-{expected_round:04d}.json"
        )
        if not isinstance(report_payload, dict) or publication.get(
            "artifact_path"
        ) != str(expected_report_path):
            raise ReleaseError("verification publication artifact is invalid")
        report_path = expected_report_path
        stored_report, report_raw = self._read_private_canonical_json(
            report_path,
            label="verification report",
        )
        if stored_report != report_payload:
            raise ReleaseError("verification publication report differs from artifact")
        try:
            report = _report_from_payload(report_payload, self.current_subject)
        except Exception as error:
            raise ReleaseError("verification report payload is invalid") from error
        expected_command_digests = [
            _command_digest(spec, _resolved_argv(spec.argv, self.variables))
            for spec in self.manifest.verification_steps
        ]
        if (
            report.verdict != "pass"
            or report.run_id != self.current_subject.run_id
            or len(report.results) != len(expected_command_digests)
            or [result.command_sha256 for result in report.results]
            != expected_command_digests
            or any(
                result.timed_out or result.exit_code != 0 for result in report.results
            )
        ):
            raise ReleaseError("verification report is not a current passing report")
        for result in report.results:
            try:
                _validate_log_evidence(
                    result,
                    self.run_directory / "logs",
                    trusted_root=self.store.trusted_root,
                )
            except Exception as error:
                raise ReleaseError(
                    "verification report log evidence is invalid"
                ) from error

        match = re.fullmatch(
            rf"verification-{expected_round:04d}-([0-9a-f]{{64}})\.json",
            publication_path.name,
        )
        request = publication.get("request")
        if (
            match is None
            or hashlib.sha256(publication_raw[:-1]).hexdigest() != match.group(1)
            or set(publication) != _VERIFICATION_PUBLICATION_KEYS
            or publication.get("schema_version") != 1
            or not isinstance(request, dict)
            or set(request) != _VERIFICATION_REQUEST_KEYS
            or request.get("schema_version") != 1
            or request.get("run_id") != self.current_subject.run_id
            or request.get("subject") != self.current_subject.to_dict()
            or request.get("subject_digest") != self.current_subject.digest()
            or request.get("manifest_sha256") != manifest_digest(self.manifest)
            or request.get("command_digests") != expected_command_digests
            or request.get("variables_sha256") != _digest(self.variables)
            or publication.get("request_digest") != _digest(request)
            or publication.get("report") != report_payload
            or publication.get("report_digest") != _digest(report_payload)
            or publication.get("report_file_sha256")
            != hashlib.sha256(report_raw).hexdigest()
            or publication.get("artifact_path") != str(report_path)
            or report.round != expected_round
            or publication.get("expected_revision") != expected_revision
            or publication.get("terminal_receipt_sha256")
            != report_payload.get("terminal_receipt_sha256")
            or publication.get("target_phase") != Phase.AWAITING_RELEASE_APPROVAL.value
        ):
            raise ReleaseError("verification publication seal is stale or invalid")

    def _assert_live_evidence(self) -> None:
        live_candidate = self._git_read("rev-parse", "HEAD^{commit}")
        live_tree = self._git_read("rev-parse", "HEAD^{tree}")
        live_base = self._git_read(
            "rev-parse",
            f"{self.manifest.base_branch}^{{commit}}",
        )
        dirty = self._git_read("status", "--porcelain=v1", "--untracked-files=all")
        if (
            live_candidate != self.current_subject.candidate_oid
            or live_tree != self.current_subject.tree_oid
            or live_base != self.current_subject.base_oid
            or dirty
            or manifest_digest(self.manifest) != self.current_subject.manifest_sha256
            or verification_commands_digest(self.manifest, self.variables)
            != self.current_subject.commands_sha256
        ):
            raise ReleaseError("live release evidence differs from its subject")
        self._assert_passing_verification_evidence()

    def _enforce_live_evidence(self) -> None:
        try:
            self._assert_live_evidence()
        except Exception as error:
            try:
                self._block()
            except Exception as block_error:
                raise ReleaseRecoveryError(
                    "live evidence drift could not be recorded safely"
                ) from block_error
            raise ReleaseError(
                "live release evidence is stale; run is BLOCKED"
            ) from error

    def _release_publication_lock(self) -> FileLock:
        trusted_root = self.store.trusted_root
        if isinstance(trusted_root, PrivateRootAnchor):
            return FileLock.at(
                trusted_root.descriptor,
                "release-publication.lock",
                display_path=self.run_directory / "release-publication.lock",
            )
        return FileLock(
            self.run_directory / "release-publication.lock",
            private_root=self.run_directory,
        )

    def _operation_pointer_path(self, cycle_id: str, mode: str, index: int) -> Path:
        return (
            self._cycle_directory(cycle_id)
            / "operations"
            / (f"{mode}-{index:04d}.json")
        )

    def _operation_seal_directory(self, cycle_id: str) -> Path:
        return self._cycle_directory(cycle_id) / "operations" / "sealed"

    def _operation_commitment_directory(self, cycle_id: str) -> Path:
        return self._cycle_directory(cycle_id) / "operations" / "committed"

    def _operation_seal_path(
        self,
        record: OperationRecord,
        payload_digest: str,
    ) -> Path:
        return self._operation_seal_directory(record.cycle_id) / (
            f"{record.mode}-{record.index:04d}-attempt-{record.attempt}-"
            f"{record.status.value.lower()}-{payload_digest}.json"
        )

    def _operation_commitment_path(
        self,
        record: OperationRecord,
        payload_digest: str,
    ) -> Path:
        return self._operation_commitment_directory(record.cycle_id) / (
            f"{record.mode}-{record.index:04d}-attempt-{record.attempt}-"
            f"{record.status.value.lower()}-{payload_digest}.json"
        )

    def _adjudication_seal_directory(self, cycle_id: str) -> Path:
        return self._cycle_directory(cycle_id) / "adjudications" / "sealed"

    def _adjudication_seal_path(
        self,
        record: OperationAdjudication,
    ) -> Path:
        return self._adjudication_seal_directory(record.cycle_id) / (
            f"{record.mode}-{record.index:04d}-attempt-{record.attempt}-"
            f"{record.unknown_receipt_sha256}-{record.adjudication_id}.json"
        )

    def _read_adjudication_file(
        self,
        path: Path,
    ) -> tuple[OperationAdjudication, bytes]:
        try:
            raw = _read_bounded_private_bytes(
                path,
                trusted_root=self.store.trusted_root,
                label="operation adjudication",
            )
            payload = json.loads(raw.decode("utf-8"))
            canonical = _canonical_json_bytes(payload) + b"\n"
        except ReleaseRecoveryError:
            raise
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            TypeError,
        ) as error:
            raise ReleaseRecoveryError("operation adjudication is corrupt") from error
        if not isinstance(payload, dict) or raw != canonical:
            raise ReleaseRecoveryError(
                "operation adjudication is not a canonical private file"
            )
        return _operation_adjudication_from_payload(payload), raw

    def _all_adjudications(self) -> tuple[OperationAdjudication, ...]:
        found: list[OperationAdjudication] = []
        for cycle_path in self._private_directory_paths(
            self._cycle_root(),
            label="release-cycle evidence root",
        ):
            if cycle_path.name in {"active-release.json", "active-rollback.json"}:
                continue
            if re.fullmatch(r"[0-9a-f]{64}", cycle_path.name) is None:
                raise ReleaseRecoveryError(
                    "release-cycle evidence has an unknown entry"
                )
            adjudication_root = cycle_path / "adjudications"
            cycle_entry_names = {
                path.name
                for path in self._private_directory_paths(
                    cycle_path,
                    label="release-cycle directory",
                )
            }
            if adjudication_root.name not in cycle_entry_names:
                continue
            entries = self._private_directory_paths(
                adjudication_root,
                label="operation adjudication directory",
            )
            if {entry.name for entry in entries} != {"sealed"}:
                raise ReleaseRecoveryError(
                    "operation adjudication directory has an unknown entry"
                )
            seal_directory = adjudication_root / "sealed"
            for path in self._private_directory_paths(
                seal_directory,
                label="operation adjudication seal directory",
            ):
                if path.suffix != ".json":
                    raise ReleaseRecoveryError(
                        "operation adjudication seal directory has an unknown entry"
                    )
                record, _ = self._read_adjudication_file(path)
                if (
                    record.cycle_id != cycle_path.name
                    or path != self._adjudication_seal_path(record)
                ):
                    raise ReleaseRecoveryError(
                        "operation adjudication seal identity is invalid"
                    )
                self._validate_operation_adjudication(record)
                found.append(record)
        return tuple(found)

    def _find_adjudications(
        self,
        unknown_receipt_sha256: str,
    ) -> tuple[OperationAdjudication, ...]:
        found = tuple(
            record
            for record in self._all_adjudications()
            if record.unknown_receipt_sha256 == unknown_receipt_sha256
        )
        if len(found) > 1:
            raise ReleaseRecoveryError(
                "UNKNOWN operation has conflicting adjudications"
            )
        return found

    def _read_operation_file(self, path: Path) -> tuple[OperationRecord, bytes]:
        try:
            raw = _read_bounded_private_bytes(
                path,
                trusted_root=self.store.trusted_root,
                label="operation receipt",
            )
            payload = json.loads(raw.decode("utf-8"))
            canonical = _canonical_json_bytes(payload) + b"\n"
        except ReleaseRecoveryError:
            raise
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            TypeError,
        ) as error:
            raise ReleaseRecoveryError("operation receipt is corrupt") from error
        if not isinstance(payload, dict) or raw != canonical:
            raise ReleaseRecoveryError(
                "operation receipt is not a canonical private file"
            )
        return _operation_record_from_payload(payload), raw

    def _validate_operation_adjudication(
        self,
        adjudication: OperationAdjudication,
    ) -> tuple[OperationRecord, bool]:
        unknown_path = self._operation_commitment_directory(adjudication.cycle_id) / (
            f"{adjudication.mode}-{adjudication.index:04d}-attempt-"
            f"{adjudication.attempt}-unknown-"
            f"{adjudication.unknown_receipt_sha256}.json"
        )
        unknown, unknown_raw = self._read_operation_file(unknown_path)
        unknown_digest = hashlib.sha256(unknown_raw[:-1]).hexdigest()
        seal_path = self._operation_seal_path(unknown, unknown_digest)
        sealed, sealed_raw = self._read_operation_file(seal_path)
        result = unknown.result
        reason = result.get("reason") if isinstance(result, dict) else None
        if (
            unknown_digest != adjudication.unknown_receipt_sha256
            or unknown.status is not OperationStatus.UNKNOWN
            or unknown.cycle_id != adjudication.cycle_id
            or unknown.mode != adjudication.mode
            or unknown.index != adjudication.index
            or unknown.attempt != adjudication.attempt
            or unknown.run_id != adjudication.run_id
            or unknown.subject != adjudication.subject
            or unknown.target != adjudication.target
            or unknown.argv != adjudication.argv
            or unknown.command_sha256 != adjudication.command_sha256
            or unknown.idempotency_key != adjudication.idempotency_key
            or reason != adjudication.reason
            or sealed != unknown
            or sealed_raw != unknown_raw
        ):
            raise ReleaseRecoveryError(
                "operation adjudication does not match its UNKNOWN receipt"
            )
        specs = self._specs_for_gate(adjudication.mode)
        if adjudication.index > len(specs):
            raise ReleaseRecoveryError(
                "operation adjudication names an unknown operation"
            )
        cycle = self._load_sealed_cycle_header(adjudication.cycle_id)
        if (
            cycle.get("gate") != adjudication.mode
            or cycle.get("run_id") != adjudication.run_id
            or cycle.get("subject") != adjudication.subject.to_dict()
            or cycle.get("target") != adjudication.target
        ):
            raise ReleaseRecoveryError(
                "operation adjudication release cycle is invalid"
            )
        self._validate_operation_identity(
            unknown,
            cycle_id=adjudication.cycle_id,
            mode=adjudication.mode,
            index=adjudication.index,
            spec=specs[adjudication.index - 1],
            target=adjudication.target,
            approval_id=str(cycle["approval_id"]),
            failed_release_id=(
                str(cycle["failed_release_id"])
                if cycle.get("failed_release_id") is not None
                else None
            ),
            previous_release=(
                str(cycle["previous_release"])
                if cycle.get("previous_release") is not None
                else None
            ),
            subject=adjudication.subject,
        )
        events = self.store.events()
        block_events = [
            event
            for event in events
            if event.revision == adjudication.blocked_revision
            and event.event_type == "phase.reconciled"
            and event.phase is Phase.BLOCKED
            and event.previous_phase
            is (
                Phase.RELEASING
                if adjudication.mode == "release"
                else Phase.ROLLING_BACK
            )
            and event.reconciliation_reason == "external-operation-unknown"
        ]
        markers = [
            event.operation_start
            for event in events
            if event.event_type == "operation.started"
            and event.operation_start is not None
            and event.operation_start.get("marker_id")
            == adjudication.operation_start_marker_id
            and event.operation_start.get("running_receipt_sha256")
            == unknown.previous_receipt_sha256
            and event.operation_start.get("cycle_id") == unknown.cycle_id
            and event.operation_start.get("mode") == unknown.mode
            and event.operation_start.get("index") == unknown.index
            and event.operation_start.get("attempt") == unknown.attempt
            and event.operation_start.get("idempotency_key") == unknown.idempotency_key
        ]
        decision_payload = _pending_operation_decision_payload(
            run_id=unknown.run_id,
            cycle_id=unknown.cycle_id,
            mode=unknown.mode,
            index=unknown.index,
            attempt=unknown.attempt,
            operation_name=specs[unknown.index - 1].name,
            target=unknown.target,
            argv=unknown.argv,
            reason=str(reason),
            unknown_receipt_sha256=unknown_digest,
            operation_start_marker_id=adjudication.operation_start_marker_id,
            blocked_revision=adjudication.blocked_revision,
        )
        if (
            len(block_events) != 1
            or len(markers) != 1
            or adjudication.confirmation_token != _digest(decision_payload)
        ):
            raise ReleaseRecoveryError(
                "operation adjudication decision evidence is invalid"
            )
        wal_events = [
            event
            for event in events
            if event.event_type == "operation.adjudicated"
            and event.operation_adjudication is not None
            and event.operation_adjudication.get("adjudication_id")
            == adjudication.adjudication_id
        ]
        if len(wal_events) > 1:
            raise ReleaseRecoveryError(
                "operation adjudication has conflicting state WAL events"
            )
        if wal_events:
            event = wal_events[0]
            if (
                event.revision != adjudication.blocked_revision + 1
                or event.previous_phase is not Phase.BLOCKED
                or event.phase
                is not (
                    Phase.RELEASING
                    if adjudication.mode == "release"
                    else Phase.ROLLING_BACK
                )
                or event.operation_adjudication
                != {
                    "schema_version": 1,
                    "run_id": adjudication.run_id,
                    "mode": adjudication.mode,
                    "adjudication_id": adjudication.adjudication_id,
                }
            ):
                raise ReleaseRecoveryError(
                    "operation adjudication state WAL binding is invalid"
                )
        return unknown, bool(wal_events)

    def _load_adjudication_for_unknown(
        self,
        unknown: OperationRecord,
        *,
        require_wal: bool = True,
    ) -> OperationAdjudication | None:
        unknown_sha256 = _digest(_operation_record_payload(unknown))
        found = self._find_adjudications(unknown_sha256)
        if not found:
            return None
        adjudication = found[0]
        linked, has_wal = self._validate_operation_adjudication(adjudication)
        if linked != unknown:
            raise ReleaseRecoveryError(
                "operation adjudication names another UNKNOWN receipt"
            )
        if require_wal and not has_wal:
            raise ReleaseRecoveryError(
                "operation adjudication is not anchored in the state WAL"
            )
        return adjudication

    def _valid_persisted_operation_transition(
        self,
        previous: OperationRecord,
        current: OperationRecord,
    ) -> bool:
        adjudication = (
            self._load_adjudication_for_unknown(previous)
            if previous.status is OperationStatus.UNKNOWN
            else None
        )
        return _valid_operation_stage_transition(
            previous,
            current,
            manual_outcome=(adjudication.outcome if adjudication is not None else None),
        )

    def _load_operation(
        self, cycle_id: str, mode: str, index: int
    ) -> OperationRecord | None:
        commitment_directory = self._operation_commitment_directory(cycle_id)
        commitment_paths = tuple(
            path
            for path in self._private_directory_paths(
                commitment_directory,
                label="operation commitment directory",
                missing_ok=True,
            )
            if path.name.startswith(f"{mode}-{index:04d}-attempt-")
            and path.suffix == ".json"
        )
        committed: dict[str, OperationRecord] = {}
        for path in commitment_paths:
            record, raw = self._read_operation_file(path)
            digest = hashlib.sha256(raw[:-1]).hexdigest()
            if (
                record.mode != mode
                or record.index != index
                or record.cycle_id != cycle_id
                or path != self._operation_commitment_path(record, digest)
                or digest in committed
            ):
                raise ReleaseRecoveryError("operation commitment identity is invalid")
            self._validate_operation_evidence(record)
            committed[digest] = record
            seal_path = self._operation_seal_path(record, digest)
            if os.path.lexists(seal_path):
                sealed_record, _ = self._read_operation_file(seal_path)
                if sealed_record != record:
                    raise ReleaseRecoveryError(
                        "operation seal differs from its commitment"
                    )
            else:
                try:
                    _write_immutable_json(
                        seal_path,
                        _operation_record_payload(record),
                        trusted_root=self.store.trusted_root,
                    )
                except Exception as error:
                    raise ReleaseRecoveryError(
                        "operation commitment could not restore its seal"
                    ) from error

        seal_directory = self._operation_seal_directory(cycle_id)
        seal_paths = tuple(
            path
            for path in self._private_directory_paths(
                seal_directory,
                label="operation seal directory",
                missing_ok=True,
            )
            if path.name.startswith(f"{mode}-{index:04d}-attempt-")
            and path.suffix == ".json"
        )
        records: list[OperationRecord] = []
        seen_stages: set[tuple[int, OperationStatus]] = set()
        terminal_attempts: set[int] = set()
        for path in seal_paths:
            record, raw = self._read_operation_file(path)
            digest = hashlib.sha256(raw[:-1]).hexdigest()
            if (
                record.mode != mode
                or record.index != index
                or record.cycle_id != cycle_id
                or path != self._operation_seal_path(record, digest)
                or committed.get(digest) != record
            ):
                raise ReleaseRecoveryError(
                    "operation seal identity or commitment is invalid"
                )
            self._validate_operation_evidence(record)
            stage = (record.attempt, record.status)
            if stage in seen_stages:
                raise ReleaseRecoveryError("operation has conflicting sealed stages")
            seen_stages.add(stage)
            if record.status in {
                OperationStatus.SUCCEEDED,
                OperationStatus.FAILED,
                OperationStatus.UNKNOWN,
            }:
                if record.attempt in terminal_attempts:
                    raise ReleaseRecoveryError(
                        "operation has conflicting terminal receipts"
                    )
                terminal_attempts.add(record.attempt)
            records.append(record)
        if records:
            attempts = {record.attempt for record in records}
            if attempts != set(range(1, max(attempts) + 1)):
                raise ReleaseRecoveryError("operation attempt sequence is incomplete")
            for attempt in attempts:
                statuses = {
                    record.status for record in records if record.attempt == attempt
                }
                if OperationStatus.PREPARED not in statuses:
                    raise ReleaseRecoveryError("operation PREPARED seal is missing")
                if (
                    any(
                        status
                        in {
                            OperationStatus.RUNNING,
                            OperationStatus.SUCCEEDED,
                            OperationStatus.FAILED,
                            OperationStatus.UNKNOWN,
                        }
                        for status in statuses
                    )
                    and OperationStatus.RUNNING not in statuses
                ):
                    raise ReleaseRecoveryError("operation RUNNING seal is missing")
                if attempt < max(attempts):
                    failed_records = [
                        record
                        for record in records
                        if record.attempt == attempt
                        and record.status is OperationStatus.FAILED
                    ]
                    unknown_records = [
                        record
                        for record in records
                        if record.attempt == attempt
                        and record.status is OperationStatus.UNKNOWN
                    ]
                    failed_retry = (
                        len(failed_records) == 1
                        and _retry_authorized_attempt(failed_records[0]) == attempt + 1
                    )
                    manual_retry = False
                    if len(unknown_records) == 1:
                        adjudication = self._load_adjudication_for_unknown(
                            unknown_records[0]
                        )
                        manual_retry = (
                            adjudication is not None
                            and adjudication.outcome == "not_applied"
                        )
                    if not failed_retry and not manual_retry:
                        raise ReleaseRecoveryError(
                            "operation retry predecessor is invalid"
                        )
            records.sort(
                key=lambda record: (
                    record.attempt,
                    _OPERATION_STAGE_ORDER[record.status],
                )
            )
            if (
                records[0].attempt != 1
                or records[0].status is not OperationStatus.PREPARED
                or records[0].previous_receipt_sha256 is not None
                or any(
                    not self._valid_persisted_operation_transition(previous, current)
                    for previous, current in zip(records, records[1:])
                )
            ):
                raise ReleaseRecoveryError("operation receipt chain is invalid")
            latest = records[-1]
        else:
            latest = None

        try:
            start_markers = self.store.operation_start_markers()
        except Exception as error:
            raise ReleaseRecoveryError(
                "operation start WAL cannot be validated"
            ) from error
        records_by_digest = {
            _digest(_operation_record_payload(record)): record for record in records
        }
        for event in start_markers:
            marker = event.operation_start
            if (
                marker is None
                or marker.get("cycle_id") != cycle_id
                or marker.get("mode") != mode
                or marker.get("index") != index
            ):
                continue
            running = records_by_digest.get(str(marker["running_receipt_sha256"]))
            if (
                running is None
                or running.status is not OperationStatus.RUNNING
                or running.attempt != marker.get("attempt")
                or running.idempotency_key != marker.get("idempotency_key")
                or running.run_id != marker.get("run_id")
            ):
                raise ReleaseRecoveryError(
                    "operation start WAL has no matching RUNNING receipt"
                )

        pointer = self._operation_pointer_path(cycle_id, mode, index)
        if os.path.lexists(pointer):
            pointer_record, _ = self._read_operation_file(pointer)
            if pointer_record not in records:
                raise ReleaseRecoveryError("operation pointer is not sealed")
            if latest is not None and pointer_record != latest:
                _write_canonical_json(
                    pointer,
                    _operation_record_payload(latest),
                    trusted_root=self.store.trusted_root,
                )
        elif latest is not None:
            _write_canonical_json(
                pointer,
                _operation_record_payload(latest),
                trusted_root=self.store.trusted_root,
            )
        return latest

    def _require_active_first_operation(
        self,
        cycle_id: str,
        mode: str,
        *,
        spec: OperationSpec,
        target: str,
        approval_id: str,
        failed_release_id: str | None = None,
        previous_release: str | None = None,
    ) -> OperationRecord:
        try:
            record = self._load_operation(cycle_id, mode, 1)
        except ReleaseRecoveryError:
            self._block()
            raise
        if record is None:
            record = self._new_prepared_operation(
                cycle_id=cycle_id,
                mode=mode,
                index=1,
                attempt=1,
                spec=spec,
                target=target,
                approval_id=approval_id,
                failed_release_id=failed_release_id,
                previous_release=previous_release,
            )
            self._persist_operation(record)
            self._checkpoint("prepared", record)
        return record

    def _persist_operation(self, record: OperationRecord) -> OperationRecord:
        self._validate_operation_evidence(record)
        current = self._load_operation(record.cycle_id, record.mode, record.index)
        if current is not None and current != record:
            if not self._valid_persisted_operation_transition(current, record):
                raise ReleaseRecoveryError("operation stage transition is invalid")
        elif current is None and not (
            record.attempt == 1 and record.status is OperationStatus.PREPARED
        ):
            raise ReleaseRecoveryError("operation must begin at PREPARED attempt 1")
        payload = _operation_record_payload(record)
        digest = _digest(payload)
        commitment_path = self._operation_commitment_path(record, digest)
        if os.path.lexists(commitment_path):
            committed, _ = self._read_operation_file(commitment_path)
            if committed != record:
                raise ReleaseRecoveryError(
                    "operation commitment conflicts with receipt"
                )
        else:
            try:
                _write_immutable_json(
                    commitment_path,
                    payload,
                    trusted_root=self.store.trusted_root,
                )
            except Exception as error:
                raise ReleaseRecoveryError(
                    "operation stage could not be committed"
                ) from error
        seal_path = self._operation_seal_path(record, digest)
        if os.path.lexists(seal_path):
            existing, _ = self._read_operation_file(seal_path)
            if existing != record:
                raise ReleaseRecoveryError("operation seal conflicts with receipt")
        else:
            try:
                _write_immutable_json(
                    seal_path,
                    payload,
                    trusted_root=self.store.trusted_root,
                )
            except Exception as error:
                raise ReleaseRecoveryError(
                    "operation stage could not be sealed"
                ) from error
        _write_canonical_json(
            self._operation_pointer_path(record.cycle_id, record.mode, record.index),
            payload,
            trusted_root=self.store.trusted_root,
        )
        return record

    def _operation_identity(
        self,
        *,
        cycle_id: str,
        mode: str,
        index: int,
        spec: OperationSpec,
        target: str,
        approval_id: str,
        failed_release_id: str | None = None,
        previous_release: str | None = None,
        subject: EvidenceSubject | None = None,
    ) -> tuple[tuple[str, ...], tuple[str, ...], str, str | None, str]:
        bound_subject = self.current_subject if subject is None else subject
        argv = _resolved_argv(spec.argv, self.variables)
        probe_argv = (
            _resolved_argv(spec.probe_argv, self.variables) if spec.probe_argv else ()
        )
        command_sha256 = _digest(_operation_payload(spec, self.variables))
        probe_sha256 = (
            _digest({"schema_version": 1, "argv": list(probe_argv)})
            if probe_argv
            else None
        )
        idempotency_key = _digest(
            {
                "schema_version": 1,
                "run_id": bound_subject.run_id,
                "cycle_id": cycle_id,
                "mode": mode,
                "index": index,
                "subject": bound_subject.to_dict(),
                "target": target,
                "command_sha256": command_sha256,
                "approval_id": approval_id,
                "failed_release_id": failed_release_id,
                "previous_release": previous_release,
            }
        )
        return argv, probe_argv, command_sha256, probe_sha256, idempotency_key

    def _new_prepared_operation(
        self,
        *,
        cycle_id: str,
        mode: str,
        index: int,
        attempt: int,
        spec: OperationSpec,
        target: str,
        approval_id: str,
        failed_release_id: str | None = None,
        previous_release: str | None = None,
        previous_receipt_sha256: str | None = None,
    ) -> OperationRecord:
        argv, probe_argv, command_sha256, probe_sha256, key = self._operation_identity(
            cycle_id=cycle_id,
            mode=mode,
            index=index,
            spec=spec,
            target=target,
            approval_id=approval_id,
            failed_release_id=failed_release_id,
            previous_release=previous_release,
        )
        return OperationRecord(
            run_id=self.current_subject.run_id,
            cycle_id=cycle_id,
            mode=mode,
            index=index,
            attempt=attempt,
            status=OperationStatus.PREPARED,
            subject=self.current_subject,
            target=target,
            argv=argv,
            probe_argv=probe_argv,
            command_sha256=command_sha256,
            probe_sha256=probe_sha256,
            approval_id=approval_id,
            idempotency=(spec.idempotency or "safe"),
            idempotency_key=key,
            failed_release_id=failed_release_id,
            previous_release=previous_release,
            previous_receipt_sha256=previous_receipt_sha256,
            prepared_at=_utc_now(),
        )

    def _validate_operation_identity(
        self,
        record: OperationRecord,
        *,
        cycle_id: str,
        mode: str,
        index: int,
        spec: OperationSpec,
        target: str,
        approval_id: str,
        failed_release_id: str | None = None,
        previous_release: str | None = None,
        subject: EvidenceSubject | None = None,
    ) -> None:
        bound_subject = self.current_subject if subject is None else subject
        argv, probe_argv, command_sha256, probe_sha256, key = self._operation_identity(
            cycle_id=cycle_id,
            mode=mode,
            index=index,
            spec=spec,
            target=target,
            approval_id=approval_id,
            failed_release_id=failed_release_id,
            previous_release=previous_release,
            subject=bound_subject,
        )
        if (
            record.run_id != bound_subject.run_id
            or record.cycle_id != cycle_id
            or record.mode != mode
            or record.index != index
            or record.subject != bound_subject
            or record.target != target
            or record.argv != argv
            or record.probe_argv != probe_argv
            or record.command_sha256 != command_sha256
            or record.probe_sha256 != probe_sha256
            or record.approval_id != approval_id
            or record.idempotency != (spec.idempotency or "safe")
            or record.idempotency_key != key
            or record.failed_release_id != failed_release_id
            or record.previous_release != previous_release
        ):
            raise ReleaseRecoveryError("operation receipt belongs to another request")

    def _approval_consumer(
        self,
        *,
        mode: str,
        idempotency_key: str,
    ) -> str:
        return f"{mode}:{idempotency_key}"

    def _checkpoint(self, stage: str, record: OperationRecord) -> None:
        del stage, record

    def _command_spec(
        self,
        spec: OperationSpec,
        *,
        probe: bool = False,
    ) -> CommandSpec:
        return CommandSpec(
            name=f"{spec.name}-probe" if probe else spec.name,
            argv=spec.probe_argv if probe else spec.argv,
            category="release-probe" if probe else "release-operation",
            timeout_seconds=spec.timeout_seconds,
        )

    def _run_command(self, spec: CommandSpec, *, log_kind: str) -> CommandResult:
        self._enforce_live_evidence()
        return self.runner.run(
            spec,
            self.variables,
            self.repo,
            self.run_directory / "logs" / log_kind,
            (),
        )

    def _read_persisted_operation_log(
        self,
        payload: dict[str, object],
        *,
        log_kind: str,
    ) -> bytes:
        expected_directory = self.run_directory / "logs" / log_kind
        try:
            log_path = Path(str(payload["log_path"]))
            if Path(os.path.abspath(log_path.parent)) != expected_directory:
                raise ReleaseRecoveryError(
                    "operation log path is outside its evidence directory"
                )
            raw = _read_bounded_private_bytes(
                log_path,
                trusted_root=self.store.trusted_root,
                label="operation log",
            )
            if (
                len(raw) != payload["log_size"]
                or hashlib.sha256(raw).hexdigest() != payload["log_sha256"]
            ):
                raise ReleaseRecoveryError("operation log size or digest is invalid")
            return raw
        except ReleaseRecoveryError:
            raise
        except (OSError, TypeError, ValueError) as error:
            raise ReleaseRecoveryError("operation log cannot be validated") from error

    def _validate_operation_evidence(self, record: OperationRecord) -> None:
        for kind, payload in _operation_result_evidence(record):
            log_kind = (
                f"{record.mode}-operations"
                if kind == "command"
                else f"{record.mode}-probes"
            )
            raw = self._read_persisted_operation_log(payload, log_kind=log_kind)
            if kind in {"probe-applied", "probe-not-applied"}:
                expected_version = (
                    record.previous_release
                    if record.mode == "rollback"
                    else record.subject.candidate_oid
                )
                if expected_version is None:
                    raise ReleaseRecoveryError("probe expected version is missing")
                outcome = _probe_protocol_outcome(
                    raw,
                    result=payload,
                    probe_argv=record.probe_argv,
                    target=record.target,
                    expected_version=expected_version,
                )
                expected_outcome = (
                    "applied" if kind == "probe-applied" else "not_applied"
                )
                if outcome != expected_outcome:
                    raise ReleaseRecoveryError(
                        "probe log does not satisfy the structured protocol"
                    )

    def _read_result_log(self, result: CommandResult) -> bytes:
        try:
            raw = result.log_path.read_bytes()
        except OSError as error:
            raise ReleaseRecoveryError("command evidence log cannot be read") from error
        if (
            len(raw) != result.log_size
            or hashlib.sha256(raw).hexdigest() != result.log_sha256
        ):
            raise ReleaseRecoveryError("command evidence log digest is invalid")
        return raw

    def _block(self, *, reason: str = "release-evidence-invalid") -> None:
        state = self.store.load()
        if state.phase is not Phase.BLOCKED:
            self.store.reconcile_transition(
                Phase.BLOCKED,
                expected_revision=state.revision,
                reason=reason,
            )

    def _unknown_operation(
        self,
        running: OperationRecord,
        *,
        reason: str,
        probe_result: CommandResult | None = None,
    ) -> OperationRecord:
        result: dict[str, object] = {"reason": reason}
        if probe_result is not None:
            result["probe"] = _command_result_payload(probe_result)
        terminal = replace(
            running,
            status=OperationStatus.UNKNOWN,
            previous_receipt_sha256=_digest(_operation_record_payload(running)),
            finished_at=_utc_now(),
            result=result,
        )
        self._persist_operation(terminal)
        self._block(reason="external-operation-unknown")
        return terminal

    def _recover_running(
        self,
        running: OperationRecord,
        *,
        spec: OperationSpec,
    ) -> OperationRecord:
        if not spec.probe_argv:
            self._unknown_operation(running, reason="running-without-probe")
            raise ReleaseRecoveryError(
                "RUNNING operation has no conclusive probe; manual reconciliation required"
            )
        try:
            probe_result = self._run_command(
                self._command_spec(spec, probe=True),
                log_kind=f"{running.mode}-probes",
            )
            probe_log = self._read_result_log(probe_result)
        except Exception as error:
            self._unknown_operation(
                running,
                reason=f"probe-error:{type(error).__name__}",
            )
            raise ReleaseRecoveryError(
                "RUNNING operation probe is unavailable; manual reconciliation required"
            ) from error
        expected_version = (
            running.previous_release
            if running.mode == "rollback"
            else self.current_subject.candidate_oid
        )
        if expected_version is None:
            self._unknown_operation(running, reason="probe-version-is-missing")
            raise ReleaseRecoveryError("RUNNING operation probe version is missing")
        probe_payload = _command_result_payload(probe_result)
        outcome = _probe_protocol_outcome(
            probe_log,
            result=probe_payload,
            probe_argv=running.probe_argv,
            target=running.target,
            expected_version=expected_version,
        )
        if outcome == "applied":
            terminal = replace(
                running,
                status=OperationStatus.SUCCEEDED,
                previous_receipt_sha256=_digest(_operation_record_payload(running)),
                finished_at=_utc_now(),
                result={
                    "recovered_by_probe": True,
                    "probe": probe_payload,
                    "asserted_version": expected_version,
                },
            )
            return self._persist_operation(terminal)
        if outcome == "not_applied" and running.idempotency in {"safe", "probe"}:
            failed = replace(
                running,
                status=OperationStatus.FAILED,
                previous_receipt_sha256=_digest(_operation_record_payload(running)),
                finished_at=_utc_now(),
                result={
                    "recovered_by_probe": True,
                    "outcome": "not-applied",
                    "probe": probe_payload,
                    "retry_authorized": True,
                    "next_attempt": running.attempt + 1,
                    "probe_digest": _digest(probe_payload),
                },
            )
            failed = self._persist_operation(failed)
            self._checkpoint("retry-authorized", failed)
            return self._execute_authorized_retry(failed, spec=spec)
        self._unknown_operation(
            running,
            reason="probe-was-not-conclusive-for-current-candidate",
            probe_result=probe_result,
        )
        raise ReleaseRecoveryError(
            "RUNNING operation probe is inconclusive; manual reconciliation required"
        )

    def _execute_authorized_retry(
        self,
        failed: OperationRecord,
        *,
        spec: OperationSpec,
    ) -> OperationRecord:
        try:
            next_attempt = _retry_authorized_attempt(failed)
        except ReleaseRecoveryError:
            self._block()
            raise
        if next_attempt is None:
            self._block()
            raise ReleaseError(f"{failed.mode} operation {failed.index} failed")
        prepared = self._new_prepared_operation(
            cycle_id=failed.cycle_id,
            mode=failed.mode,
            index=failed.index,
            attempt=next_attempt,
            spec=spec,
            target=failed.target,
            approval_id=failed.approval_id,
            failed_release_id=failed.failed_release_id,
            previous_release=failed.previous_release,
            previous_receipt_sha256=_digest(_operation_record_payload(failed)),
        )
        self._persist_operation(prepared)
        self._checkpoint("prepared", prepared)
        return self._execute_prepared(prepared, spec=spec)

    def _execute_prepared(
        self,
        prepared: OperationRecord,
        *,
        spec: OperationSpec,
    ) -> OperationRecord:
        running = replace(
            prepared,
            status=OperationStatus.RUNNING,
            previous_receipt_sha256=_digest(_operation_record_payload(prepared)),
            started_at=_utc_now(),
        )
        self._persist_operation(running)
        try:
            self.store.record_operation_start(
                cycle_id=running.cycle_id,
                mode=running.mode,
                index=running.index,
                attempt=running.attempt,
                running_receipt_sha256=_digest(_operation_record_payload(running)),
                idempotency_key=running.idempotency_key,
            )
        except Exception as error:
            raise ReleaseRecoveryError(
                "operation start could not be anchored in the state WAL"
            ) from error
        self._checkpoint("running", running)
        try:
            result = self._run_command(
                self._command_spec(spec),
                log_kind=f"{running.mode}-operations",
            )
        except Exception as error:
            self._unknown_operation(
                running,
                reason=f"runner-error:{type(error).__name__}",
            )
            raise ReleaseRecoveryError(
                "operation runner outcome is unknown; manual reconciliation required"
            ) from error
        self._checkpoint("effect-returned", running)
        succeeded = result.exit_code == 0 and not result.timed_out
        terminal = replace(
            running,
            status=(OperationStatus.SUCCEEDED if succeeded else OperationStatus.FAILED),
            previous_receipt_sha256=_digest(_operation_record_payload(running)),
            finished_at=_utc_now(),
            result={"command": _command_result_payload(result)},
        )
        self._checkpoint("before-terminal-persist", terminal)
        self._persist_operation(terminal)
        self._checkpoint("terminal-persisted", terminal)
        if not succeeded:
            self._block()
            raise ReleaseError(f"{running.mode} operation {running.index} failed")
        return terminal

    def _run_one_operation(
        self,
        *,
        cycle_id: str,
        mode: str,
        index: int,
        spec: OperationSpec,
        target: str,
        approval_id: str,
        failed_release_id: str | None = None,
        previous_release: str | None = None,
    ) -> OperationRecord:
        record = self._load_operation(cycle_id, mode, index)
        if record is None:
            record = self._new_prepared_operation(
                cycle_id=cycle_id,
                mode=mode,
                index=index,
                attempt=1,
                spec=spec,
                target=target,
                approval_id=approval_id,
                failed_release_id=failed_release_id,
                previous_release=previous_release,
            )
            self._persist_operation(record)
            self._checkpoint("prepared", record)
        self._validate_operation_identity(
            record,
            cycle_id=cycle_id,
            mode=mode,
            index=index,
            spec=spec,
            target=target,
            approval_id=approval_id,
            failed_release_id=failed_release_id,
            previous_release=previous_release,
        )
        if record.status is OperationStatus.SUCCEEDED:
            return record
        if record.status is OperationStatus.PREPARED:
            return self._execute_prepared(record, spec=spec)
        if record.status is OperationStatus.RUNNING:
            return self._recover_running(record, spec=spec)
        if record.status is OperationStatus.FAILED:
            return self._execute_authorized_retry(record, spec=spec)
        if record.status is OperationStatus.UNKNOWN:
            adjudication = self._load_adjudication_for_unknown(record)
            if adjudication is None:
                self._block()
                raise ReleaseRecoveryError(
                    "operation is UNKNOWN; manual reconciliation required"
                )
            if adjudication.outcome == "applied":
                return record
            prepared = self._new_prepared_operation(
                cycle_id=record.cycle_id,
                mode=record.mode,
                index=record.index,
                attempt=record.attempt + 1,
                spec=spec,
                target=record.target,
                approval_id=record.approval_id,
                failed_release_id=record.failed_release_id,
                previous_release=record.previous_release,
                previous_receipt_sha256=_digest(_operation_record_payload(record)),
            )
            self._persist_operation(prepared)
            self._checkpoint("prepared", prepared)
            return self._execute_prepared(prepared, spec=spec)
        self._block()
        raise ReleaseError(f"{mode} operation {index} failed")

    def _continue_operations(
        self,
        *,
        cycle_id: str,
        mode: str,
        specs: tuple[OperationSpec, ...],
        target: str,
        approval_id: str,
        failed_release_id: str | None = None,
        previous_release: str | None = None,
    ) -> tuple[OperationRecord, ...]:
        completed: list[OperationRecord] = []
        try:
            for index, spec in enumerate(specs, start=1):
                completed.append(
                    self._run_one_operation(
                        cycle_id=cycle_id,
                        mode=mode,
                        index=index,
                        spec=spec,
                        target=target,
                        approval_id=approval_id,
                        failed_release_id=failed_release_id,
                        previous_release=previous_release,
                    )
                )
        except ReleaseRecoveryError:
            self._block()
            raise
        return tuple(completed)

    def _health_pointer_path(self, cycle_id: str, mode: str, index: int) -> Path:
        return self._cycle_directory(cycle_id) / "health" / (f"{mode}-{index:04d}.json")

    def _health_seal_directory(self, cycle_id: str) -> Path:
        return self._cycle_directory(cycle_id) / "health" / "sealed"

    def _validate_health_receipt(
        self,
        payload: object,
        *,
        cycle_id: str,
        mode: str,
        index: int,
        spec: CommandSpec,
        target: str,
        expected_version: str,
    ) -> dict[str, object]:
        command_payload = _health_command_payload(spec, self.variables)
        if (
            not isinstance(payload, dict)
            or set(payload) != _HEALTH_RECEIPT_KEYS
            or payload["schema_version"] != 1
            or payload["run_id"] != self.current_subject.run_id
            or payload["cycle_id"] != cycle_id
            or payload["mode"] != mode
            or payload["index"] != index
            or payload["subject"] != self.current_subject.to_dict()
            or payload["target"] != target
            or payload["expected_version"] != expected_version
            or payload["command_sha256"] != _digest(command_payload)
            or payload["argv"] != command_payload["argv"]
            or not isinstance(payload["started_at"], str)
            or not isinstance(payload["finished_at"], str)
            or not isinstance(payload["result"], dict)
            or type(payload["passed"]) is not bool
            or type(payload["asserts_expected_version"]) is not bool
        ):
            raise ReleaseRecoveryError("health receipt belongs to another request")
        try:
            _parse_utc(payload["started_at"], "started_at")
            _parse_utc(payload["finished_at"], "finished_at")
        except ValueError as error:
            raise ReleaseRecoveryError("health receipt timestamp is invalid") from error
        result_payload = payload["result"]
        if set(result_payload) == _COMMAND_RESULT_KEYS:
            command_result = _validated_command_result_payload(result_payload)
            raw = self._read_persisted_operation_log(
                command_result,
                log_kind=f"{mode}-health",
            )
            protocol_outcome = _health_protocol_outcome(
                raw,
                result=command_result,
                target=target,
                expected_version=expected_version,
            )
            if protocol_outcome is None:
                raise ReleaseRecoveryError(
                    "health log does not satisfy the structured protocol"
                )
            protocol_passed = protocol_outcome == "healthy"
            if (
                payload["passed"] is not protocol_passed
                or payload["asserts_expected_version"] is not protocol_passed
            ):
                raise ReleaseRecoveryError(
                    "health receipt does not match its structured protocol evidence"
                )
        elif set(result_payload) == {"error"}:
            raise ReleaseRecoveryError(
                "health receipt has no verifiable command evidence"
            )
        else:
            raise ReleaseRecoveryError("health result schema is invalid")
        return dict(payload)

    def _read_health_file(self, path: Path) -> tuple[dict[str, object], bytes]:
        try:
            raw = _read_bounded_private_bytes(
                path,
                trusted_root=self.store.trusted_root,
                label="health receipt",
            )
            payload = json.loads(raw.decode("utf-8"))
            canonical = _canonical_json_bytes(payload) + b"\n"
        except ReleaseRecoveryError:
            raise
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            TypeError,
        ) as error:
            raise ReleaseRecoveryError("health receipt is corrupt") from error
        if not isinstance(payload, dict) or raw != canonical:
            raise ReleaseRecoveryError("health receipt is not a canonical private file")
        return payload, raw

    def _load_health_receipt(
        self,
        *,
        cycle_id: str,
        mode: str,
        index: int,
        spec: CommandSpec,
        target: str,
        expected_version: str,
    ) -> dict[str, object] | None:
        seal_directory = self._health_seal_directory(cycle_id)
        paths = tuple(
            path
            for path in self._private_directory_paths(
                seal_directory,
                label="health seal directory",
                missing_ok=True,
            )
            if re.fullmatch(
                rf"{mode}-{index:04d}-[0-9a-f]{{64}}\.json",
                path.name,
            )
        )
        if len(paths) > 1:
            raise ReleaseRecoveryError("health check has conflicting seals")
        pointer = self._health_pointer_path(cycle_id, mode, index)
        if not paths:
            if os.path.lexists(pointer):
                raise ReleaseRecoveryError("health pointer is not sealed")
            return None
        payload, raw = self._read_health_file(paths[0])
        digest = hashlib.sha256(raw[:-1]).hexdigest()
        if paths[0].name != f"{mode}-{index:04d}-{digest}.json":
            raise ReleaseRecoveryError("health seal identity is invalid")
        validated = self._validate_health_receipt(
            payload,
            cycle_id=cycle_id,
            mode=mode,
            index=index,
            spec=spec,
            target=target,
            expected_version=expected_version,
        )
        if os.path.lexists(pointer):
            pointer_payload, _ = self._read_health_file(pointer)
            if pointer_payload != validated:
                raise ReleaseRecoveryError("health pointer differs from its seal")
        else:
            _write_canonical_json(
                pointer,
                validated,
                trusted_root=self.store.trusted_root,
            )
        return validated

    def _run_healthcheck(
        self,
        *,
        cycle_id: str,
        mode: str,
        index: int,
        spec: CommandSpec,
        target: str,
        expected_version: str,
    ) -> dict[str, object]:
        existing = self._load_health_receipt(
            cycle_id=cycle_id,
            mode=mode,
            index=index,
            spec=spec,
            target=target,
            expected_version=expected_version,
        )
        if existing is not None:
            return existing
        started_at = _utc_now()
        try:
            result = self._run_command(spec, log_kind=f"{mode}-health")
            raw = self._read_result_log(result)
            result_payload = _command_result_payload(result)
            protocol_outcome = _health_protocol_outcome(
                raw,
                result=result_payload,
                target=target,
                expected_version=expected_version,
            )
            if protocol_outcome is None:
                raise ReleaseRecoveryError(
                    "health command returned an invalid structured protocol"
                )
            passed = protocol_outcome == "healthy"
            asserted = passed
        except Exception as error:
            raise ReleaseRecoveryError(
                "health command evidence cannot be validated"
            ) from error
        command_payload = _health_command_payload(spec, self.variables)
        receipt: dict[str, object] = {
            "schema_version": 1,
            "run_id": self.current_subject.run_id,
            "cycle_id": cycle_id,
            "mode": mode,
            "index": index,
            "subject": self.current_subject.to_dict(),
            "target": target,
            "expected_version": expected_version,
            "command_sha256": _digest(command_payload),
            "argv": command_payload["argv"],
            "started_at": started_at,
            "finished_at": _utc_now(),
            "result": result_payload,
            "passed": passed,
            "asserts_expected_version": asserted,
        }
        validated = self._validate_health_receipt(
            receipt,
            cycle_id=cycle_id,
            mode=mode,
            index=index,
            spec=spec,
            target=target,
            expected_version=expected_version,
        )
        digest = _digest(validated)
        seal_path = self._health_seal_directory(cycle_id) / (
            f"{mode}-{index:04d}-{digest}.json"
        )
        try:
            _write_immutable_json(
                seal_path,
                validated,
                trusted_root=self.store.trusted_root,
            )
        except Exception as error:
            raise ReleaseRecoveryError("health receipt could not be sealed") from error
        _write_canonical_json(
            self._health_pointer_path(cycle_id, mode, index),
            validated,
            trusted_root=self.store.trusted_root,
        )
        return validated

    def _run_healthchecks(
        self,
        *,
        cycle_id: str,
        mode: str,
        specs: tuple[CommandSpec, ...],
        target: str,
        expected_version: str,
    ) -> bool:
        try:
            receipts = tuple(
                self._run_healthcheck(
                    cycle_id=cycle_id,
                    mode=mode,
                    index=index,
                    spec=spec,
                    target=target,
                    expected_version=expected_version,
                )
                for index, spec in enumerate(specs, start=1)
            )
        except ReleaseRecoveryError:
            self._block()
            raise
        return (
            bool(receipts)
            and all(receipt["passed"] is True for receipt in receipts)
            and any(receipt["asserts_expected_version"] is True for receipt in receipts)
        )

    def _release_locked(
        self,
        *,
        target: str,
        approval_id: str,
        rollback_approval_id: str | None,
        previous_release: str | None,
    ) -> tuple[OperationRecord, ...]:
        state = self.store.load()
        if state.phase not in {
            Phase.AWAITING_RELEASE_APPROVAL,
            Phase.RELEASING,
            Phase.POST_RELEASE_VERIFYING,
            Phase.SYNCING,
        }:
            raise ReleaseError("release is not available in the current phase")
        if not self.manifest.release_steps:
            raise ReleaseError("release has no configured operations")
        self._enforce_live_evidence()
        pending_cycle: dict[str, object] | None = None
        pending_cycle_conflicts = False
        if state.phase is Phase.AWAITING_RELEASE_APPROVAL:
            try:
                pending_cycle = self._active_cycle_for_current_gate("release")
            except ReleaseRecoveryError:
                self._block()
                raise
            pending_cycle_conflicts = pending_cycle is not None and (
                pending_cycle.get("approval_id") != approval_id
                or pending_cycle.get("target") != target
            )
        cycle_id = self._expected_cycle_id(
            gate="release",
            approval_id=approval_id,
            target=target,
        )
        first_spec = self.manifest.release_steps[0]
        _, _, _, _, first_key = self._operation_identity(
            cycle_id=cycle_id,
            mode="release",
            index=1,
            spec=first_spec,
            target=target,
            approval_id=approval_id,
        )
        consumer = self._approval_consumer(mode="release", idempotency_key=first_key)
        approval = self._validate_approval(
            approval_id,
            gate="release",
            target=target,
            allow_consumed_by=consumer,
        )
        if pending_cycle_conflicts:
            assert pending_cycle is not None
            self._supersede_pure_prepared_cycle(
                gate="release",
                active=pending_cycle,
                replacement=approval,
            )
            pending_cycle = None
        if state.phase is Phase.AWAITING_RELEASE_APPROVAL:
            cycle = (
                pending_cycle
                if pending_cycle is not None
                else self._activate_cycle(
                    gate="release",
                    approval_id=approval_id,
                    target=target,
                )
            )
        else:
            cycle = self._load_active_cycle(
                gate="release",
                approval_id=approval_id,
                target=target,
            )
        if cycle.get("cycle_id") != cycle_id:
            raise ReleaseRecoveryError("active release cycle identity is invalid")
        if state.phase is Phase.RELEASING:
            if approval.consumed_at is None or approval.consumed_by != consumer:
                self._block()
                raise ReleaseRecoveryError(
                    "active release cycle has no consumed approval"
                )
            self._require_active_first_operation(
                cycle_id,
                "release",
                spec=first_spec,
                target=target,
                approval_id=approval_id,
            )
        if state.phase is Phase.AWAITING_RELEASE_APPROVAL:
            first = self._load_operation(cycle_id, "release", 1)
            if first is None:
                if approval.consumed_at is not None:
                    raise ReleaseRecoveryError(
                        "consumed approval has no recoverable first operation"
                    )
                first = self._new_prepared_operation(
                    cycle_id=cycle_id,
                    mode="release",
                    index=1,
                    attempt=1,
                    spec=first_spec,
                    target=target,
                    approval_id=approval_id,
                )
                self._persist_operation(first)
                self._checkpoint("prepared", first)
            self._validate_operation_identity(
                first,
                cycle_id=cycle_id,
                mode="release",
                index=1,
                spec=first_spec,
                target=target,
                approval_id=approval_id,
            )
            if approval.consumed_at is None:
                self.consume_approval(approval_id, consumer=consumer)
                self._checkpoint("approval-consumed", first)
            state = self.store.load()
            self.store.transition(Phase.RELEASING, expected_revision=state.revision)
        records = self._continue_operations(
            cycle_id=cycle_id,
            mode="release",
            specs=self.manifest.release_steps,
            target=target,
            approval_id=approval_id,
        )
        state = self.store.load()
        if state.phase is Phase.RELEASING:
            state = self.store.transition(
                Phase.POST_RELEASE_VERIFYING,
                expected_revision=state.revision,
            )
        if state.phase is Phase.POST_RELEASE_VERIFYING:
            if self.manifest.release_healthchecks:
                healthy = self._run_healthchecks(
                    cycle_id=cycle_id,
                    mode="release",
                    specs=self.manifest.release_healthchecks,
                    target=target,
                    expected_version=self.current_subject.candidate_oid,
                )
                target_phase = Phase.SYNCING if healthy else Phase.ROLLBACK_PENDING
                state = self.store.transition(
                    target_phase,
                    expected_revision=state.revision,
                )
            else:
                state = self.store.transition(
                    Phase.SYNCING, expected_revision=state.revision
                )
        if (
            state.phase is Phase.ROLLBACK_PENDING
            and rollback_approval_id is not None
            and previous_release is not None
            and self.manifest.rollback_steps
            and all(step.data_impact == "none" for step in self.manifest.rollback_steps)
        ):
            self._rollback_locked(
                target=target,
                approval_id=rollback_approval_id,
                failed_release_id=approval_id,
                previous_release=previous_release,
            )
        return records

    def release(
        self,
        *,
        target: str,
        approval_id: str,
        rollback_approval_id: str | None = None,
        previous_release: str | None = None,
    ) -> tuple[OperationRecord, ...]:
        if not isinstance(target, str) or not target:
            raise ReleaseError("release target must be a non-empty string")
        # Fixed acquisition order: shared release target, release publication,
        # then StateStore's internal run lock for transitions.
        with FileLock.release_target(self._git_common_directory(), target):
            with (
                self._release_publication_lock() as publication_lock,
                self.store.anchored(publication_lock.trusted_parent),
            ):
                return self._release_locked(
                    target=target,
                    approval_id=approval_id,
                    rollback_approval_id=rollback_approval_id,
                    previous_release=previous_release,
                )

    def resume_external_cycle(
        self,
        *,
        target: str,
    ) -> tuple[OperationRecord, ...]:
        """Resume the active adjudicated cycle without asking for its approval id."""

        if not isinstance(target, str) or not target:
            raise ReleaseError("release target must be a non-empty string")
        with FileLock.release_target(self._git_common_directory(), target):
            with (
                self._release_publication_lock() as publication_lock,
                self.store.anchored(publication_lock.trusted_parent),
            ):
                state = self.store.load()
                if state.phase in {
                    Phase.RELEASING,
                    Phase.POST_RELEASE_VERIFYING,
                    Phase.SYNCING,
                }:
                    active = self._load_active_cycle_unbound("release")
                    if active.get("target") != target:
                        raise ReleaseRecoveryError(
                            "active release cycle target is stale"
                        )
                    return self._release_locked(
                        target=target,
                        approval_id=str(active["approval_id"]),
                        rollback_approval_id=None,
                        previous_release=None,
                    )
                if state.phase in {
                    Phase.ROLLING_BACK,
                    Phase.ROLLBACK_VERIFYING,
                }:
                    active = self._load_active_cycle_unbound("rollback")
                    if (
                        active.get("target") != target
                        or not isinstance(active.get("failed_release_id"), str)
                        or not isinstance(active.get("previous_release"), str)
                    ):
                        raise ReleaseRecoveryError(
                            "active rollback cycle context is stale"
                        )
                    return self._rollback_locked(
                        target=target,
                        approval_id=str(active["approval_id"]),
                        failed_release_id=str(active["failed_release_id"]),
                        previous_release=str(active["previous_release"]),
                    )
                raise ReleaseRecoveryError(
                    "no adjudicated external cycle is ready to resume"
                )

    def _rollback_locked(
        self,
        *,
        target: str,
        approval_id: str,
        failed_release_id: str,
        previous_release: str,
    ) -> tuple[OperationRecord, ...]:
        state = self.store.load()
        if state.phase not in {
            Phase.ROLLBACK_PENDING,
            Phase.ROLLING_BACK,
            Phase.ROLLBACK_VERIFYING,
        }:
            raise ReleaseError("rollback is not available in the current phase")
        if not self.manifest.rollback_steps:
            raise ReleaseError("rollback has no configured operations")
        self._enforce_live_evidence()
        selected_release_cycle_id: str | None = None
        if state.phase is Phase.ROLLBACK_PENDING:
            selected_release_cycle_id = self._selected_failed_release_cycle_id(
                state_phase=state.phase,
                target=target,
                failed_release_id=failed_release_id,
            )
        pending_cycle: dict[str, object] | None = None
        pending_cycle_conflicts = False
        if state.phase is Phase.ROLLBACK_PENDING:
            try:
                pending_cycle = self._active_cycle_for_current_gate("rollback")
            except ReleaseRecoveryError:
                self._block()
                raise
            pending_cycle_conflicts = pending_cycle is not None and (
                pending_cycle.get("approval_id") != approval_id
                or pending_cycle.get("target") != target
                or pending_cycle.get("failed_release_id") != failed_release_id
                or pending_cycle.get("previous_release") != previous_release
            )
        cycle_id = self._expected_cycle_id(
            gate="rollback",
            approval_id=approval_id,
            target=target,
            failed_release_id=failed_release_id,
            previous_release=previous_release,
        )
        first_spec = self.manifest.rollback_steps[0]
        _, _, _, _, first_key = self._operation_identity(
            cycle_id=cycle_id,
            mode="rollback",
            index=1,
            spec=first_spec,
            target=target,
            approval_id=approval_id,
            failed_release_id=failed_release_id,
            previous_release=previous_release,
        )
        consumer = self._approval_consumer(mode="rollback", idempotency_key=first_key)
        approval = self._validate_approval(
            approval_id,
            gate="rollback",
            target=target,
            allow_consumed_by=consumer,
            failed_release_id=failed_release_id,
            previous_release=previous_release,
        )
        if selected_release_cycle_id is not None:
            self._validate_rollback_context_seal(
                approval,
                selected_release_cycle_id=selected_release_cycle_id,
            )
        if pending_cycle_conflicts:
            assert pending_cycle is not None
            self._supersede_pure_prepared_cycle(
                gate="rollback",
                active=pending_cycle,
                replacement=approval,
            )
            pending_cycle = None
        if state.phase is Phase.ROLLBACK_PENDING:
            cycle = (
                pending_cycle
                if pending_cycle is not None
                else self._activate_cycle(
                    gate="rollback",
                    approval_id=approval_id,
                    target=target,
                    failed_release_id=failed_release_id,
                    previous_release=previous_release,
                )
            )
        else:
            cycle = self._load_active_cycle(
                gate="rollback",
                approval_id=approval_id,
                target=target,
                failed_release_id=failed_release_id,
                previous_release=previous_release,
            )
        if cycle.get("cycle_id") != cycle_id:
            raise ReleaseRecoveryError("active rollback cycle identity is invalid")
        if state.phase is Phase.ROLLING_BACK:
            if approval.consumed_at is None or approval.consumed_by != consumer:
                self._block()
                raise ReleaseRecoveryError(
                    "active rollback cycle has no consumed approval"
                )
            self._require_active_first_operation(
                cycle_id,
                "rollback",
                spec=first_spec,
                target=target,
                approval_id=approval_id,
                failed_release_id=failed_release_id,
                previous_release=previous_release,
            )
        if state.phase is Phase.ROLLBACK_PENDING:
            first = self._load_operation(cycle_id, "rollback", 1)
            if first is None:
                if approval.consumed_at is not None:
                    raise ReleaseRecoveryError(
                        "consumed rollback approval has no first operation"
                    )
                first = self._new_prepared_operation(
                    cycle_id=cycle_id,
                    mode="rollback",
                    index=1,
                    attempt=1,
                    spec=first_spec,
                    target=target,
                    approval_id=approval_id,
                    failed_release_id=failed_release_id,
                    previous_release=previous_release,
                )
                self._persist_operation(first)
                self._checkpoint("prepared", first)
            self._validate_operation_identity(
                first,
                cycle_id=cycle_id,
                mode="rollback",
                index=1,
                spec=first_spec,
                target=target,
                approval_id=approval_id,
                failed_release_id=failed_release_id,
                previous_release=previous_release,
            )
            if approval.consumed_at is None:
                self.consume_approval(approval_id, consumer=consumer)
                self._checkpoint("approval-consumed", first)
            state = self.store.load()
            self.store.transition(
                Phase.ROLLING_BACK,
                expected_revision=state.revision,
            )
        records = self._continue_operations(
            cycle_id=cycle_id,
            mode="rollback",
            specs=self.manifest.rollback_steps,
            target=target,
            approval_id=approval_id,
            failed_release_id=failed_release_id,
            previous_release=previous_release,
        )
        state = self.store.load()
        if state.phase is Phase.ROLLING_BACK:
            self.store.transition(
                Phase.ROLLBACK_VERIFYING,
                expected_revision=state.revision,
            )
        return records

    def rollback(
        self,
        *,
        target: str,
        approval_id: str,
        failed_release_id: str | None = None,
        previous_release: str | None = None,
    ) -> tuple[OperationRecord, ...]:
        if not isinstance(target, str) or not target:
            raise ReleaseError("rollback target must be a non-empty string")
        with FileLock.release_target(self._git_common_directory(), target):
            with (
                self._release_publication_lock() as publication_lock,
                self.store.anchored(publication_lock.trusted_parent),
            ):
                approval = self._load_approval(approval_id)
                effective_failed = failed_release_id or approval.failed_release_id
                effective_previous = previous_release or approval.previous_release
                if effective_failed is None or effective_previous is None:
                    raise ReleaseError("rollback context is incomplete")
                return self._rollback_locked(
                    target=target,
                    approval_id=approval_id,
                    failed_release_id=effective_failed,
                    previous_release=effective_previous,
                )

    def verify_rollback(
        self,
        *,
        target: str,
        previous_release: str,
    ) -> bool:
        if (
            not isinstance(target, str)
            or not target
            or not isinstance(previous_release, str)
            or not previous_release
        ):
            raise ReleaseError("rollback verification context is invalid")
        with FileLock.release_target(self._git_common_directory(), target):
            with (
                self._release_publication_lock() as publication_lock,
                self.store.anchored(publication_lock.trusted_parent),
            ):
                state = self.store.load()
                if state.phase is not Phase.ROLLBACK_VERIFYING:
                    raise ReleaseError(
                        "rollback verification requires ROLLBACK_VERIFYING"
                    )
                self._enforce_live_evidence()
                try:
                    cycle = self._load_active_cycle_unbound("rollback")
                    cycle_id = str(cycle["cycle_id"])
                    if (
                        cycle.get("target") != target
                        or cycle.get("previous_release") != previous_release
                        or not isinstance(cycle.get("approval_id"), str)
                        or not isinstance(cycle.get("failed_release_id"), str)
                    ):
                        raise ReleaseRecoveryError(
                            "rollback verification cycle context is stale"
                        )
                    first_spec = self.manifest.rollback_steps[0]
                    _, _, _, _, first_key = self._operation_identity(
                        cycle_id=cycle_id,
                        mode="rollback",
                        index=1,
                        spec=first_spec,
                        target=target,
                        approval_id=str(cycle["approval_id"]),
                        failed_release_id=str(cycle["failed_release_id"]),
                        previous_release=previous_release,
                    )
                    self._validate_approval(
                        str(cycle["approval_id"]),
                        gate="rollback",
                        target=target,
                        allow_consumed_by=self._approval_consumer(
                            mode="rollback", idempotency_key=first_key
                        ),
                        failed_release_id=str(cycle["failed_release_id"]),
                        previous_release=previous_release,
                    )
                    for index, spec in enumerate(self.manifest.rollback_steps, start=1):
                        record = self._load_operation(cycle_id, "rollback", index)
                        adjudication = (
                            self._load_adjudication_for_unknown(record)
                            if record is not None
                            and record.status is OperationStatus.UNKNOWN
                            else None
                        )
                        logically_succeeded = record is not None and (
                            record.status is OperationStatus.SUCCEEDED
                            or (
                                adjudication is not None
                                and adjudication.outcome == "applied"
                            )
                        )
                        if (
                            record is None
                            or not logically_succeeded
                            or record.target != target
                            or record.previous_release != previous_release
                        ):
                            raise ReleaseRecoveryError(
                                "rollback verification context does not match all receipts"
                            )
                        self._validate_operation_identity(
                            record,
                            cycle_id=cycle_id,
                            mode="rollback",
                            index=index,
                            spec=spec,
                            target=target,
                            approval_id=str(cycle["approval_id"]),
                            failed_release_id=str(cycle["failed_release_id"]),
                            previous_release=previous_release,
                        )
                except ReleaseError:
                    self._block()
                    raise
                healthy = self._run_healthchecks(
                    cycle_id=cycle_id,
                    mode="rollback",
                    specs=self.manifest.rollback_healthchecks,
                    target=target,
                    expected_version=previous_release,
                )
                state = self.store.load()
                self.store.transition(
                    Phase.ROLLED_BACK if healthy else Phase.BLOCKED,
                    expected_revision=state.revision,
                )
                return healthy

    def _inspect_unknown_operation_locked(
        self,
        *,
        target: str,
    ) -> tuple[PendingOperationDecision, OperationRecord]:
        events = self.store.events()
        if not events:
            raise ReleaseRecoveryError("run state evidence is missing")
        blocked_event = events[-1]
        if (
            blocked_event.phase is not Phase.BLOCKED
            or blocked_event.event_type != "phase.reconciled"
            or blocked_event.reconciliation_reason != "external-operation-unknown"
            or blocked_event.previous_phase not in {Phase.RELEASING, Phase.ROLLING_BACK}
        ):
            raise ReleaseRecoveryError(
                "run is not blocked on an UNKNOWN external operation"
            )
        mode = (
            "release" if blocked_event.previous_phase is Phase.RELEASING else "rollback"
        )
        gate = mode
        specs = self._specs_for_gate(gate)
        cycle = self._load_active_cycle_unbound(gate)
        if cycle.get("target") != target:
            raise ReleaseRecoveryError("active release cycle target is stale")
        cycle_id = str(cycle["cycle_id"])
        unknowns: list[tuple[OperationRecord, bytes, OperationSpec]] = []
        for index, spec in enumerate(specs, start=1):
            pointer = self._operation_pointer_path(cycle_id, mode, index)
            if not os.path.lexists(pointer):
                continue
            record, raw = self._read_operation_file(pointer)
            if record.status is not OperationStatus.UNKNOWN:
                continue
            digest = hashlib.sha256(raw[:-1]).hexdigest()
            commitment = self._operation_commitment_path(record, digest)
            seal = self._operation_seal_path(record, digest)
            committed, committed_raw = self._read_operation_file(commitment)
            sealed, sealed_raw = self._read_operation_file(seal)
            if (
                committed != record
                or sealed != record
                or committed_raw != raw
                or sealed_raw != raw
            ):
                raise ReleaseRecoveryError(
                    "UNKNOWN operation immutable evidence is invalid"
                )
            self._validate_operation_evidence(record)
            self._validate_operation_identity(
                record,
                cycle_id=cycle_id,
                mode=mode,
                index=index,
                spec=spec,
                target=target,
                approval_id=str(cycle["approval_id"]),
                failed_release_id=(
                    str(cycle["failed_release_id"])
                    if cycle.get("failed_release_id") is not None
                    else None
                ),
                previous_release=(
                    str(cycle["previous_release"])
                    if cycle.get("previous_release") is not None
                    else None
                ),
            )
            if self._load_adjudication_for_unknown(record) is not None:
                continue
            unknowns.append((record, raw, spec))
        if len(unknowns) != 1:
            raise ReleaseRecoveryError(
                "blocked run must contain exactly one current UNKNOWN operation"
            )
        unknown, raw, spec = unknowns[0]
        markers = [
            event.operation_start
            for event in events
            if event.event_type == "operation.started"
            and event.operation_start is not None
            and event.operation_start.get("running_receipt_sha256")
            == unknown.previous_receipt_sha256
            and event.operation_start.get("cycle_id") == unknown.cycle_id
            and event.operation_start.get("mode") == unknown.mode
            and event.operation_start.get("index") == unknown.index
            and event.operation_start.get("attempt") == unknown.attempt
            and event.operation_start.get("idempotency_key") == unknown.idempotency_key
        ]
        if len(markers) != 1:
            raise ReleaseRecoveryError(
                "UNKNOWN operation has no unique start marker in the state WAL"
            )
        marker = markers[0]
        result = unknown.result
        reason = result.get("reason") if isinstance(result, dict) else None
        if not isinstance(reason, str) or not reason:
            raise ReleaseRecoveryError("UNKNOWN operation reason is invalid")
        unknown_sha256 = hashlib.sha256(raw[:-1]).hexdigest()
        payload = _pending_operation_decision_payload(
            run_id=unknown.run_id,
            cycle_id=unknown.cycle_id,
            mode=unknown.mode,
            index=unknown.index,
            attempt=unknown.attempt,
            operation_name=spec.name,
            target=unknown.target,
            argv=unknown.argv,
            reason=reason,
            unknown_receipt_sha256=unknown_sha256,
            operation_start_marker_id=str(marker["marker_id"]),
            blocked_revision=blocked_event.revision,
        )
        decision = PendingOperationDecision(
            run_id=unknown.run_id,
            cycle_id=unknown.cycle_id,
            mode=unknown.mode,
            index=unknown.index,
            attempt=unknown.attempt,
            operation_name=spec.name,
            target=unknown.target,
            argv=unknown.argv,
            reason=reason,
            unknown_receipt_sha256=unknown_sha256,
            operation_start_marker_id=str(marker["marker_id"]),
            blocked_revision=blocked_event.revision,
            confirmation_token=_digest(payload),
        )
        return decision, unknown

    def inspect_unknown_operation(
        self,
        *,
        target: str,
    ) -> PendingOperationDecision:
        """Return the exact human decision without running or repairing anything."""

        if not isinstance(target, str) or not target:
            raise ReleaseError("release target must be a non-empty string")
        with FileLock.release_target(self._git_common_directory(), target):
            with (
                self._release_publication_lock() as publication_lock,
                self.store.anchored(publication_lock.trusted_parent),
            ):
                decision, _ = self._inspect_unknown_operation_locked(target=target)
                return decision

    def record_operation_outcome(
        self,
        *,
        target: str,
        unknown_receipt_sha256: str,
        confirmation_token: str,
        expected_revision: int,
        actor: str,
        outcome: str,
    ) -> OperationAdjudication:
        """Seal one human outcome and restore state without running any command."""

        if not isinstance(target, str) or not target:
            raise ReleaseError("release target must be a non-empty string")
        for label, digest in (
            ("unknown receipt", unknown_receipt_sha256),
            ("confirmation token", confirmation_token),
        ):
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise ReleaseError(f"{label} must be a lowercase SHA-256")
        if type(expected_revision) is not int or expected_revision < 0:
            raise ReleaseError("expected_revision must be a non-negative integer")
        if not isinstance(actor, str) or not actor.strip():
            raise ReleaseError("adjudication actor must be a non-empty string")
        if outcome not in {"applied", "not_applied"}:
            raise ReleaseError("operation outcome must be applied or not_applied")
        normalized_actor = actor.strip()
        with FileLock.release_target(self._git_common_directory(), target):
            with (
                self._release_publication_lock() as publication_lock,
                self.store.anchored(publication_lock.trusted_parent),
            ):
                existing = self._find_adjudications(unknown_receipt_sha256)
                if existing:
                    adjudication = existing[0]
                    linked_unknown, has_wal = self._validate_operation_adjudication(
                        adjudication
                    )
                    if (
                        adjudication.target != target
                        or adjudication.unknown_receipt_sha256 != unknown_receipt_sha256
                        or adjudication.confirmation_token != confirmation_token
                        or adjudication.blocked_revision != expected_revision
                    ):
                        raise ReleaseRecoveryError(
                            "operation adjudication request is stale or invalid"
                        )
                    if (
                        adjudication.actor != normalized_actor
                        or adjudication.outcome != outcome
                    ):
                        raise ReleaseRecoveryError(
                            "UNKNOWN operation already has a conflicting adjudication"
                        )
                    if not has_wal:
                        state = self.store.events()[-1].state
                        if (
                            state.phase is not Phase.BLOCKED
                            or state.revision != expected_revision
                        ):
                            raise ReleaseRecoveryError(
                                "sealed adjudication cannot be restored from current state"
                            )
                        self.store.restore_adjudicated_operation(
                            mode=adjudication.mode,
                            adjudication_id=adjudication.adjudication_id,
                            expected_revision=expected_revision,
                        )
                        self._checkpoint(
                            "adjudication-wal-recorded",
                            linked_unknown,
                        )
                    return adjudication

                decision, unknown = self._inspect_unknown_operation_locked(
                    target=target
                )
                if (
                    decision.unknown_receipt_sha256 != unknown_receipt_sha256
                    or decision.confirmation_token != confirmation_token
                    or decision.blocked_revision != expected_revision
                ):
                    raise ReleaseRecoveryError(
                        "operation adjudication request is stale or invalid"
                    )
                provisional = OperationAdjudication(
                    adjudication_id="0" * 64,
                    run_id=unknown.run_id,
                    cycle_id=unknown.cycle_id,
                    mode=unknown.mode,
                    index=unknown.index,
                    attempt=unknown.attempt,
                    subject=unknown.subject,
                    target=unknown.target,
                    argv=unknown.argv,
                    command_sha256=unknown.command_sha256,
                    idempotency_key=unknown.idempotency_key,
                    unknown_receipt_sha256=unknown_receipt_sha256,
                    operation_start_marker_id=decision.operation_start_marker_id,
                    blocked_revision=expected_revision,
                    confirmation_token=confirmation_token,
                    actor=normalized_actor,
                    outcome=outcome,
                    reason=decision.reason,
                    recorded_at=_utc_now(),
                )
                adjudication = replace(
                    provisional,
                    adjudication_id=_digest(
                        _operation_adjudication_stable_payload(provisional)
                    ),
                )
                try:
                    _write_immutable_json(
                        self._adjudication_seal_path(adjudication),
                        _operation_adjudication_payload(adjudication),
                        trusted_root=self.store.trusted_root,
                    )
                except Exception as error:
                    raise ReleaseRecoveryError(
                        "operation adjudication could not be sealed"
                    ) from error
                self._checkpoint("adjudication-sealed", unknown)
                self.store.restore_adjudicated_operation(
                    mode=adjudication.mode,
                    adjudication_id=adjudication.adjudication_id,
                    expected_revision=expected_revision,
                )
                self._checkpoint("adjudication-wal-recorded", unknown)
                return adjudication

    def reconcile_operation(self, *, target: str) -> OperationRecord:
        if not isinstance(target, str) or not target:
            raise ReleaseError("release target must be a non-empty string")
        with FileLock.release_target(self._git_common_directory(), target):
            with (
                self._release_publication_lock() as publication_lock,
                self.store.anchored(publication_lock.trusted_parent),
            ):
                state = self.store.load()
                if state.phase is Phase.RELEASING:
                    mode = "release"
                    gate = "release"
                    specs = self.manifest.release_steps
                elif state.phase is Phase.ROLLING_BACK:
                    mode = "rollback"
                    gate = "rollback"
                    specs = self.manifest.rollback_steps
                else:
                    raise ReleaseRecoveryError(
                        "no operation is available for reconciliation"
                    )
                cycle = self._load_active_cycle_unbound(gate)
                if cycle.get("target") != target:
                    raise ReleaseRecoveryError("active release cycle target is stale")
                cycle_id = str(cycle["cycle_id"])
                for index, spec in enumerate(specs, start=1):
                    record = self._load_operation(cycle_id, mode, index)
                    if record is None:
                        continue
                    self._validate_operation_identity(
                        record,
                        cycle_id=cycle_id,
                        mode=mode,
                        index=index,
                        spec=spec,
                        target=target,
                        approval_id=record.approval_id,
                        failed_release_id=record.failed_release_id,
                        previous_release=record.previous_release,
                    )
                    if record.status in {
                        OperationStatus.PREPARED,
                        OperationStatus.RUNNING,
                    }:
                        return self._run_one_operation(
                            cycle_id=cycle_id,
                            mode=mode,
                            index=index,
                            spec=spec,
                            target=target,
                            approval_id=record.approval_id,
                            failed_release_id=record.failed_release_id,
                            previous_release=record.previous_release,
                        )
                raise ReleaseRecoveryError(
                    "no incomplete release operation requires reconciliation"
                )


def _validate_pending_human_gate_cycle(
    engine: ReleaseEngine,
    *,
    gate: str,
    records: Sequence[OperationRecord],
    current_subject: EvidenceSubject,
    manifest: Manifest,
    variables: Mapping[str, str],
) -> bool:
    """Validate an activated cycle that crashed before leaving its human gate."""

    active = engine._load_active_cycle_unbound(gate)
    if active.get("gate_revision") != engine._current_gate_revision(gate):
        raise ReleaseRecoveryError("pending active cycle gate generation is stale")
    mode = "release" if gate == "release" else "rollback"
    specs = engine._specs_for_gate(gate)
    if not specs:
        raise ReleaseRecoveryError("pending active cycle has no confirmed operations")
    cycle_id = str(active["cycle_id"])
    active_records = tuple(
        record
        for record in records
        if record.cycle_id == cycle_id and record.mode == mode
    )
    if (
        any(
            record.index != 1 or record.status is not OperationStatus.PREPARED
            for record in active_records
        )
        or len(active_records) > 1
    ):
        raise ReleaseRecoveryError(
            "pending human-gate cycle has evidence beyond its recoverable first step"
        )
    for record in active_records:
        engine._validate_operation_identity(
            record,
            cycle_id=cycle_id,
            mode=mode,
            index=1,
            spec=specs[0],
            target=str(active["target"]),
            approval_id=str(active["approval_id"]),
            failed_release_id=(
                str(active["failed_release_id"])
                if active.get("failed_release_id") is not None
                else None
            ),
            previous_release=(
                str(active["previous_release"])
                if active.get("previous_release") is not None
                else None
            ),
        )

    approval_id = str(active["approval_id"])
    approval_root = engine.run_directory / "approvals"
    sealed_root = approval_root / "sealed"
    try:
        approval_entries = engine._private_directory_paths(
            approval_root,
            label="pending active approval directory",
        )
    except ReleaseError as error:
        raise ExternalEvidenceMissingError(
            "pending active approval evidence is missing"
        ) from error
    approval_entry_names = {path.name for path in approval_entries}
    if sealed_root.name not in approval_entry_names:
        raise ExternalEvidenceMissingError(
            "pending active approval evidence is missing"
        )
    sealed_entry_names = {
        path.name
        for path in engine._private_directory_paths(
            sealed_root,
            label="pending approval seal directory",
        )
    }
    approval_name = f"{approval_id}.json"
    if approval_name not in sealed_entry_names:
        raise ExternalEvidenceMissingError("pending active approval seal is missing")
    seal_payload, _ = engine._read_private_canonical_json(
        engine._approval_seal_path(approval_id),
        label="pending approval immutable seal",
    )
    pointer_payload: dict[str, object] | None = None
    pointer_path = engine._approval_path(approval_id)
    if pointer_path.name in approval_entry_names:
        pointer_payload, _ = engine._read_private_canonical_json(
            pointer_path,
            label="pending approval pointer",
        )
    consumed_payload: dict[str, object] | None = None
    consumed_path = engine._approval_consumed_path(approval_id)
    if consumed_path.parent.name in approval_entry_names:
        consumed_entry_names = {
            path.name
            for path in engine._private_directory_paths(
                consumed_path.parent,
                label="pending approval consumption directory",
            )
        }
        if consumed_path.name not in consumed_entry_names:
            consumed_entry_names = set()
    else:
        consumed_entry_names = set()
    if consumed_path.name in consumed_entry_names:
        consumed_payload, _ = engine._read_private_canonical_json(
            consumed_path,
            label="pending approval consumption commitment",
        )
    selected_payload = consumed_payload or pointer_payload
    if selected_payload is None:
        raise ExternalEvidenceMissingError("pending active approval pointer is missing")
    approval = _approval_from_payload(selected_payload)
    expected_operation_digests = _operation_digests(specs, variables)
    if approval.gate_phase == Phase.ROLLBACK_PENDING.value:
        approval_gate_is_current = (
            gate == "rollback"
            and approval.gate_revision == engine._current_gate_revision("rollback")
        )
    elif approval.gate_phase == Phase.AWAITING_RELEASE_APPROVAL.value:
        approval_gate_is_current = (
            approval.gate_revision == engine._current_gate_revision("release")
            and (
                gate == "release"
                or (
                    gate == "rollback"
                    and bool(manifest.rollback_steps)
                    and all(
                        step.data_impact == "none" for step in manifest.rollback_steps
                    )
                )
            )
        )
    else:
        approval_gate_is_current = False
    if (
        approval.approval_id != approval_id
        or approval.run_id != current_subject.run_id
        or approval.gate != gate
        or not approval_gate_is_current
        or approval.subject != current_subject
        or approval.target != active.get("target")
        or approval.operation_digests != expected_operation_digests
        or approval.failed_release_id != active.get("failed_release_id")
        or approval.previous_release != active.get("previous_release")
        or seal_payload != _approval_stable_payload(approval)
        or _digest(seal_payload) != approval_id
    ):
        raise ReleaseRecoveryError(
            "pending active approval evidence is stale or invalid"
        )
    if consumed_payload is None:
        if (
            approval.consumed_at is not None
            or approval.consumed_by is not None
            or pointer_payload != selected_payload
        ):
            raise ReleaseRecoveryError(
                "pending active approval is consumed or incomplete"
            )
    else:
        if (
            approval.consumed_at is None
            or approval.consumed_by is None
            or not active_records
        ):
            raise ReleaseRecoveryError(
                "pending active approval consumption is incomplete"
            )
        if pointer_payload is not None:
            pointer = _approval_from_payload(pointer_payload)
            if _approval_stable_payload(pointer) != seal_payload or (
                pointer.consumed_at is not None and pointer != approval
            ):
                raise ReleaseRecoveryError(
                    "pending active approval pointer conflicts with commitment"
                )
        _, _, _, _, first_key = engine._operation_identity(
            cycle_id=cycle_id,
            mode=mode,
            index=1,
            spec=specs[0],
            target=str(active["target"]),
            approval_id=approval_id,
            failed_release_id=(
                str(active["failed_release_id"])
                if active.get("failed_release_id") is not None
                else None
            ),
            previous_release=(
                str(active["previous_release"])
                if active.get("previous_release") is not None
                else None
            ),
        )
        if approval.consumed_by != engine._approval_consumer(
            mode=mode,
            idempotency_key=first_key,
        ):
            raise ReleaseRecoveryError("pending active approval consumer is invalid")
    return True


def _validate_external_operation_evidence(
    *,
    engine: ReleaseEngine,
    repo: Path | str,
    run_directory: Path | str,
    manifest: Manifest,
    current_subject: EvidenceSubject,
    variables: Mapping[str, str],
    phase: Phase,
) -> ExternalEvidenceInspection:
    """Inspect operation commitments without repairing pointers or running probes."""

    run_path = engine.run_directory
    if type(phase) is not Phase:
        raise TypeError("phase must be an exact Phase")
    cycle_root = engine._cycle_root()
    markers = engine.store.operation_start_markers()
    run_entry_names = {
        path.name
        for path in engine._private_directory_paths(
            run_path,
            label="run evidence directory",
        )
    }
    if cycle_root.name not in run_entry_names:
        if markers:
            raise ExternalEvidenceMissingError(
                "operation start WAL has no release-cycle evidence"
            )
        if phase in {
            Phase.RELEASING,
            Phase.POST_RELEASE_VERIFYING,
            Phase.ROLLBACK_PENDING,
            Phase.ROLLING_BACK,
            Phase.ROLLBACK_VERIFYING,
        }:
            raise ExternalEvidenceMissingError(
                "active external phase has no release-cycle evidence"
            )
        return ExternalEvidenceInspection(
            records=(),
            in_flight=(),
            active_cycle=False,
        )
    records: list[OperationRecord] = []
    records_by_digest: dict[str, OperationRecord] = {}
    recoverable = False
    cycle_entries = engine._private_directory_paths(
        cycle_root,
        label="release-cycle evidence root",
    )
    for cycle_directory in cycle_entries:
        if cycle_directory.name in {
            "active-release.json",
            "active-rollback.json",
        }:
            continue
        if cycle_directory.name.startswith("active-"):
            raise ReleaseRecoveryError(
                "release-cycle evidence has an unknown active pointer"
            )
        if re.fullmatch(r"[0-9a-f]{64}", cycle_directory.name) is None:
            raise ReleaseRecoveryError("release-cycle evidence has an unknown entry")
        operation_root = cycle_directory / "operations"
        cycle_child_names = {
            path.name
            for path in engine._private_directory_paths(
                cycle_directory,
                label="release-cycle directory",
            )
        }
        if operation_root.name not in cycle_child_names:
            continue
        committed_directory = operation_root / "committed"
        sealed_directory = operation_root / "sealed"
        operation_entries = engine._private_directory_paths(
            operation_root,
            label="operation evidence directory",
        )
        operation_entry_names = {path.name for path in operation_entries}
        committed_exists = committed_directory.name in operation_entry_names
        sealed_exists = sealed_directory.name in operation_entry_names
        if not committed_exists and not sealed_exists:
            continue
        if not committed_exists:
            raise ReleaseRecoveryError(
                "operation seal directory has no immutable commitments"
            )
        committed_entries = set(
            engine._private_directory_paths(
                committed_directory,
                label="operation commitment directory",
            )
        )
        sealed_entries = (
            set(
                engine._private_directory_paths(
                    sealed_directory,
                    label="operation seal directory",
                )
            )
            if sealed_exists
            else set()
        )
        if any(path.suffix != ".json" for path in committed_entries) or any(
            path.suffix != ".json" for path in sealed_entries
        ):
            raise ReleaseRecoveryError(
                "operation commitment or seal directory has an unknown entry"
            )
        expected_seals: set[Path] = set()
        for path in sorted(committed_entries):
            record, raw = engine._read_operation_file(path)
            digest = hashlib.sha256(raw[:-1]).hexdigest()
            if (
                record.cycle_id != cycle_directory.name
                or path != engine._operation_commitment_path(record, digest)
                or digest in records_by_digest
            ):
                raise ReleaseRecoveryError("operation commitment identity is invalid")
            seal_path = engine._operation_seal_path(record, digest)
            expected_seals.add(seal_path)
            if seal_path in sealed_entries:
                sealed, sealed_raw = engine._read_operation_file(seal_path)
                if sealed != record or sealed_raw != raw:
                    raise ReleaseRecoveryError(
                        "operation seal differs from its commitment"
                    )
            engine._validate_operation_evidence(record)
            records.append(record)
            records_by_digest[digest] = record
        if not sealed_entries <= expected_seals:
            raise ReleaseRecoveryError("operation seal set has orphan evidence")

    engine._all_adjudications()
    grouped: dict[tuple[str, str, int], list[OperationRecord]] = {}
    adjudications_by_unknown_sha: dict[str, OperationAdjudication] = {}
    for record in records:
        grouped.setdefault((record.cycle_id, record.mode, record.index), []).append(
            record
        )
        if record.status is OperationStatus.UNKNOWN:
            unknown_sha256 = _digest(_operation_record_payload(record))
            adjudication = engine._load_adjudication_for_unknown(record)
            if adjudication is None:
                raise ExternalEvidenceUnknownError(
                    "operation receipt is UNKNOWN and requires manual reconciliation"
                )
            adjudications_by_unknown_sha[unknown_sha256] = adjudication
    for chain in grouped.values():
        chain.sort(
            key=lambda record: (
                record.attempt,
                _OPERATION_STAGE_ORDER[record.status],
            )
        )
        stages = {(record.attempt, record.status) for record in chain}
        if len(stages) != len(chain):
            raise ReleaseRecoveryError("operation chain has conflicting stages")
        attempts = {record.attempt for record in chain}
        for attempt in attempts:
            statuses = {record.status for record in chain if record.attempt == attempt}
            if OperationStatus.PREPARED not in statuses or (
                any(status is not OperationStatus.PREPARED for status in statuses)
                and OperationStatus.RUNNING not in statuses
            ):
                raise ExternalEvidenceMissingError(
                    "operation receipt chain is incomplete"
                )
        if any(
            not engine._valid_persisted_operation_transition(previous, current)
            for previous, current in zip(chain, chain[1:])
        ):
            raise ReleaseRecoveryError("operation receipt chain is invalid")

    active_release_path = cycle_root / "active-release.json"
    active_rollback_path = cycle_root / "active-rollback.json"
    cycle_entry_names = {path.name for path in cycle_entries}
    active_release_exists = active_release_path.name in cycle_entry_names
    active_rollback_exists = active_rollback_path.name in cycle_entry_names
    pending_active_cycle = False
    if phase is Phase.AWAITING_RELEASE_APPROVAL:
        if active_rollback_exists:
            raise ReleaseRecoveryError(
                "release approval gate has an unexpected active rollback cycle"
            )
        if active_release_exists:
            pending_active_cycle = _validate_pending_human_gate_cycle(
                engine,
                gate="release",
                records=records,
                current_subject=current_subject,
                manifest=manifest,
                variables=variables,
            )
            recoverable = True
    elif phase is Phase.ROLLBACK_PENDING and active_rollback_exists:
        pending_active_cycle = _validate_pending_human_gate_cycle(
            engine,
            gate="rollback",
            records=records,
            current_subject=current_subject,
            manifest=manifest,
            variables=variables,
        )
        recoverable = True

    active_gate: str | None = None
    if phase in {
        Phase.RELEASING,
        Phase.POST_RELEASE_VERIFYING,
        Phase.ROLLBACK_PENDING,
    } or (
        phase
        in {
            Phase.SYNCING,
            Phase.AWAITING_CLEANUP_APPROVAL,
            Phase.COMPLETED,
        }
        and manifest.release_required
    ):
        active_gate = "release"
    elif phase in {
        Phase.ROLLING_BACK,
        Phase.ROLLBACK_VERIFYING,
        Phase.ROLLED_BACK,
    }:
        active_gate = "rollback"
    active: dict[str, object] | None = None
    if active_gate is not None:
        try:
            active = engine._load_active_cycle_unbound(active_gate)
        except ReleaseError as error:
            raise ReleaseRecoveryError(
                "active external cycle is missing or invalid"
            ) from error
        active_cycle_id = str(active["cycle_id"])
        mode = "release" if active_gate == "release" else "rollback"
        specs = engine._specs_for_gate(active_gate)
        if not specs:
            raise ReleaseRecoveryError(
                "active external cycle has no confirmed operations"
            )
        active_records = tuple(
            record
            for record in records
            if record.cycle_id == active_cycle_id and record.mode == mode
        )
        for record in active_records:
            if record.index > len(specs):
                raise ReleaseRecoveryError(
                    "active external cycle has an unknown operation"
                )
            engine._validate_operation_identity(
                record,
                cycle_id=active_cycle_id,
                mode=mode,
                index=record.index,
                spec=specs[record.index - 1],
                target=str(active["target"]),
                approval_id=str(active["approval_id"]),
                failed_release_id=(
                    str(active["failed_release_id"])
                    if active.get("failed_release_id") is not None
                    else None
                ),
                previous_release=(
                    str(active["previous_release"])
                    if active.get("previous_release") is not None
                    else None
                ),
            )

        approval_id = str(active["approval_id"])
        approval_root = engine.run_directory / "approvals"
        approval_entries = engine._private_directory_paths(
            approval_root,
            label="active external approval directory",
        )
        approval_entry_names = {path.name for path in approval_entries}
        if not {"sealed", "consumed"} <= approval_entry_names:
            raise ExternalEvidenceMissingError(
                "active external approval commitment is missing"
            )
        sealed_approval_entries = engine._private_directory_paths(
            approval_root / "sealed",
            label="active external approval seal directory",
        )
        consumed_approval_entries = engine._private_directory_paths(
            approval_root / "consumed",
            label="active external approval consumption directory",
        )
        if f"{approval_id}.json" not in {
            path.name for path in sealed_approval_entries
        } or f"{approval_id}.json" not in {
            path.name for path in consumed_approval_entries
        }:
            raise ExternalEvidenceMissingError(
                "active external approval commitment is missing"
            )
        seal_payload, _ = engine._read_private_canonical_json(
            engine._approval_seal_path(approval_id),
            label="approval immutable seal",
        )
        consumed_payload, _ = engine._read_private_canonical_json(
            engine._approval_consumed_path(approval_id),
            label="approval consumption commitment",
        )
        approval = _approval_from_payload(consumed_payload)
        expected_operation_digests = _operation_digests(specs, variables)
        if approval.gate_phase == Phase.ROLLBACK_PENDING.value:
            approval_gate_generation_is_current = (
                active_gate == "rollback"
                and approval.gate_revision == engine._current_gate_revision("rollback")
            )
        elif approval.gate_phase == Phase.AWAITING_RELEASE_APPROVAL.value:
            approval_gate_generation_is_current = (
                approval.gate_revision == engine._current_gate_revision("release")
                and (
                    active_gate == "release"
                    or (
                        active_gate == "rollback"
                        and bool(manifest.rollback_steps)
                        and all(
                            step.data_impact == "none"
                            for step in manifest.rollback_steps
                        )
                    )
                )
            )
        else:
            approval_gate_generation_is_current = False
        if (
            approval.approval_id != approval_id
            or approval.run_id != current_subject.run_id
            or approval.gate != active_gate
            or (
                active_gate == "release"
                and approval.gate_phase != Phase.AWAITING_RELEASE_APPROVAL.value
            )
            or (
                active_gate == "rollback"
                and approval.gate_phase
                not in {
                    Phase.AWAITING_RELEASE_APPROVAL.value,
                    Phase.ROLLBACK_PENDING.value,
                }
            )
            or not approval_gate_generation_is_current
            or approval.subject != current_subject
            or approval.target != active["target"]
            or approval.operation_digests != expected_operation_digests
            or approval.failed_release_id != active["failed_release_id"]
            or approval.previous_release != active["previous_release"]
            or approval.consumed_at is None
            or approval.consumed_by is None
            or seal_payload != _approval_stable_payload(approval)
            or _digest(seal_payload) != approval_id
        ):
            raise ReleaseRecoveryError(
                "active external approval evidence is stale or invalid"
            )
        pointer_path = engine._approval_path(approval_id)
        if pointer_path.name in approval_entry_names:
            pointer_payload, _ = engine._read_private_canonical_json(
                pointer_path,
                label="approval pointer",
            )
            pointer = _approval_from_payload(pointer_payload)
            if _approval_stable_payload(pointer) != seal_payload or (
                pointer.consumed_at is not None and pointer != approval
            ):
                raise ReleaseRecoveryError(
                    "active external approval pointer conflicts with commitment"
                )
        _, _, _, _, first_key = engine._operation_identity(
            cycle_id=active_cycle_id,
            mode=mode,
            index=1,
            spec=specs[0],
            target=str(active["target"]),
            approval_id=approval_id,
            failed_release_id=(
                str(active["failed_release_id"])
                if active.get("failed_release_id") is not None
                else None
            ),
            previous_release=(
                str(active["previous_release"])
                if active.get("previous_release") is not None
                else None
            ),
        )
        if approval.consumed_by != engine._approval_consumer(
            mode=mode,
            idempotency_key=first_key,
        ):
            raise ReleaseRecoveryError("active external approval consumer is invalid")
        complete_phases = {
            Phase.POST_RELEASE_VERIFYING,
            Phase.ROLLBACK_PENDING,
            Phase.ROLLBACK_VERIFYING,
            Phase.ROLLED_BACK,
            Phase.SYNCING,
            Phase.AWAITING_CLEANUP_APPROVAL,
            Phase.COMPLETED,
        }
        if phase in complete_phases:
            for index in range(1, len(specs) + 1):
                operation_records = tuple(
                    record for record in active_records if record.index == index
                )
                if not operation_records:
                    raise ExternalEvidenceMissingError(
                        "completed external phase has missing operation evidence"
                    )
                latest = max(
                    operation_records,
                    key=lambda record: (
                        record.attempt,
                        _OPERATION_STAGE_ORDER[record.status],
                    ),
                )
                latest_adjudication = (
                    adjudications_by_unknown_sha.get(
                        _digest(_operation_record_payload(latest))
                    )
                    if latest.status is OperationStatus.UNKNOWN
                    else None
                )
                if latest.status is not OperationStatus.SUCCEEDED and not (
                    latest.status is OperationStatus.UNKNOWN
                    and latest_adjudication is not None
                    and latest_adjudication.outcome == "applied"
                ):
                    raise ReleaseRecoveryError(
                        "completed external phase has no successful operation"
                    )

        health_specs = (
            manifest.release_healthchecks
            if active_gate == "release"
            else manifest.rollback_healthchecks
        )
        expected_version = (
            current_subject.candidate_oid
            if active_gate == "release"
            else str(active["previous_release"])
        )
        health_mode = mode
        health_must_exist = phase in {
            Phase.ROLLBACK_PENDING,
            Phase.ROLLED_BACK,
            Phase.SYNCING,
            Phase.AWAITING_CLEANUP_APPROVAL,
            Phase.COMPLETED,
        }
        health_must_pass = phase in {
            Phase.ROLLED_BACK,
            Phase.SYNCING,
            Phase.AWAITING_CLEANUP_APPROVAL,
            Phase.COMPLETED,
        }
        health_receipts: list[dict[str, object]] = []
        if health_specs:
            active_cycle_directory = engine._cycle_directory(active_cycle_id)
            active_cycle_entry_names = {
                path.name
                for path in engine._private_directory_paths(
                    active_cycle_directory,
                    label="active release-cycle directory",
                )
            }
            health_directory = active_cycle_directory / "health"
            seal_directory = engine._health_seal_directory(active_cycle_id)
            if health_directory.name not in active_cycle_entry_names:
                if health_must_exist:
                    raise ExternalEvidenceMissingError(
                        "external health evidence is missing"
                    )
            else:
                health_entries = set(
                    engine._private_directory_paths(
                        health_directory,
                        label="external health evidence directory",
                    )
                )
                health_entry_names = {path.name for path in health_entries}
                if seal_directory.name not in health_entry_names:
                    if health_must_exist:
                        raise ExternalEvidenceMissingError(
                            "external health evidence is missing"
                        )
                    if health_entries:
                        raise ReleaseRecoveryError(
                            "external health evidence has unknown pointers"
                        )
                else:
                    seal_entries = set(
                        engine._private_directory_paths(
                            seal_directory,
                            label="external health seal directory",
                        )
                    )
                    known_health_paths: set[Path] = set()
                    known_health_pointers: set[Path] = set()
                    for index, spec in enumerate(health_specs, start=1):
                        paths = tuple(
                            sorted(
                                path
                                for path in seal_entries
                                if path.name.startswith(f"{health_mode}-{index:04d}-")
                                and path.suffix == ".json"
                            )
                        )
                        if not paths:
                            if health_must_exist:
                                raise ExternalEvidenceMissingError(
                                    "external health receipt is missing"
                                )
                            continue
                        if len(paths) != 1:
                            raise ReleaseRecoveryError(
                                "external health receipt seals conflict"
                            )
                        payload, raw = engine._read_health_file(paths[0])
                        digest = hashlib.sha256(raw[:-1]).hexdigest()
                        if paths[0].name != (
                            f"{health_mode}-{index:04d}-{digest}.json"
                        ):
                            raise ReleaseRecoveryError(
                                "external health receipt identity is invalid"
                            )
                        validated = engine._validate_health_receipt(
                            payload,
                            cycle_id=active_cycle_id,
                            mode=health_mode,
                            index=index,
                            spec=spec,
                            target=str(active["target"]),
                            expected_version=expected_version,
                        )
                        pointer = engine._health_pointer_path(
                            active_cycle_id,
                            health_mode,
                            index,
                        )
                        if pointer.name not in health_entry_names:
                            if phase in {
                                Phase.POST_RELEASE_VERIFYING,
                                Phase.ROLLBACK_VERIFYING,
                            }:
                                recoverable = True
                            else:
                                raise ExternalEvidenceMissingError(
                                    "external health pointer is missing"
                                )
                        else:
                            pointer_payload, pointer_raw = engine._read_health_file(
                                pointer
                            )
                            if pointer_payload != validated or pointer_raw != raw:
                                raise ReleaseRecoveryError(
                                    "external health pointer differs from its seal"
                                )
                            known_health_pointers.add(pointer)
                        known_health_paths.add(paths[0])
                        health_receipts.append(validated)
                    if seal_entries != known_health_paths:
                        raise ReleaseRecoveryError(
                            "external health evidence has orphan seals"
                        )
                    if health_entries != known_health_pointers | {seal_directory}:
                        raise ReleaseRecoveryError(
                            "external health evidence has unknown pointers"
                        )
        if (
            health_must_pass
            and health_specs
            and (
                len(health_receipts) != len(health_specs)
                or not all(receipt["passed"] is True for receipt in health_receipts)
                or not any(
                    receipt["asserts_expected_version"] is True
                    for receipt in health_receipts
                )
            )
        ):
            raise ReleaseRecoveryError(
                "external health evidence does not prove the released version"
            )

    in_flight: list[OperationRecord] = []
    for event in markers:
        marker = event.operation_start
        if marker is None:
            raise ReleaseRecoveryError("operation start WAL marker is invalid")
        running = records_by_digest.get(str(marker.get("running_receipt_sha256")))
        if (
            running is None
            or running.status is not OperationStatus.RUNNING
            or running.run_id != marker.get("run_id")
            or running.cycle_id != marker.get("cycle_id")
            or running.mode != marker.get("mode")
            or running.index != marker.get("index")
            or running.attempt != marker.get("attempt")
            or running.idempotency_key != marker.get("idempotency_key")
        ):
            raise ExternalEvidenceMissingError(
                "operation start WAL has no matching RUNNING receipt"
            )
        terminals = tuple(
            record
            for record in records
            if record.cycle_id == running.cycle_id
            and record.mode == running.mode
            and record.index == running.index
            and record.attempt == running.attempt
            and record.status
            in {
                OperationStatus.SUCCEEDED,
                OperationStatus.FAILED,
                OperationStatus.UNKNOWN,
            }
        )
        if len(terminals) > 1:
            raise ReleaseRecoveryError(
                "operation start WAL has conflicting terminal receipts"
            )
        if not terminals:
            in_flight.append(running)
    return ExternalEvidenceInspection(
        records=tuple(records),
        in_flight=tuple(in_flight),
        active_cycle=active is not None or pending_active_cycle,
        recoverable=recoverable,
    )


def validate_external_operation_evidence(
    *,
    repo: Path | str,
    run_directory: Path | str,
    manifest: Manifest,
    current_subject: EvidenceSubject,
    variables: Mapping[str, str],
    phase: Phase,
) -> ExternalEvidenceInspection:
    """Read and validate external evidence without mutating or probing it."""

    run_path = Path(os.path.abspath(run_directory))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(run_path, flags)
    except OSError as error:
        raise ReleaseRecoveryError(
            "run evidence directory cannot be opened safely"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ReleaseRecoveryError("run evidence directory is unsafe")
        current = os.stat(run_path, follow_symlinks=False)
        if (
            not stat.S_ISDIR(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ReleaseRecoveryError(
                "run evidence directory changed before validation"
            )
        engine = ReleaseEngine(
            repo=repo,
            run_directory=run_path,
            manifest=manifest,
            current_subject=current_subject,
            variables=variables,
        )
        anchor = PrivateRootAnchor(engine.run_directory, descriptor)
        with engine.store.anchored(anchor):
            engine._assert_run_root_current()
            inspection = _validate_external_operation_evidence(
                engine=engine,
                repo=repo,
                run_directory=run_path,
                manifest=manifest,
                current_subject=current_subject,
                variables=variables,
                phase=phase,
            )
            engine._assert_run_root_current()
            return inspection
    except ReleaseRecoveryError:
        raise
    except ReleaseError as error:
        raise ReleaseRecoveryError(
            "external operation evidence cannot be validated"
        ) from error
    except (OSError, RuntimeError, ValueError) as error:
        raise ReleaseRecoveryError(
            "external operation evidence cannot be inspected safely"
        ) from error
    finally:
        os.close(descriptor)
