from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

from .manifest import CommandSpec, Manifest, manifest_digest
from .model import Phase
from .review import (
    _load_handoff,
    _load_handoff_digest,
    _remove_durable_file,
    _write_canonical_json,
    validate_passing_code_review,
)
from .runner import CommandRunner, _resolved_argv
from .store import (
    FileLock,
    PrivateRootAnchor,
    StateCorruptionError,
    StateNotFoundError,
    StateStore,
    _atomic_write_private_json,
    _private_directory_names,
    _read_bounded_private_file,
)
from .subject import EvidenceSubject


class VerificationError(RuntimeError):
    pass


class VerificationRecoveryError(VerificationError):
    pass


class VerificationEvidenceMissingError(VerificationRecoveryError):
    pass


class VerificationEvidenceStaleError(VerificationRecoveryError):
    pass


def _assert_store_root_current(store: StateStore) -> None:
    trusted_root = store.trusted_root
    if not isinstance(trusted_root, PrivateRootAnchor):
        return
    try:
        opened = os.fstat(trusted_root.descriptor)
        current = os.stat(store.run_directory, follow_symlinks=False)
    except OSError as error:
        raise VerificationRecoveryError(
            "verification run directory changed during publication"
        ) from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise VerificationRecoveryError(
            "verification run directory changed during publication"
        )


@dataclass(frozen=True)
class VerificationCommandResult:
    index: int
    command_sha256: str
    started_at: str
    ended_at: str
    duration_seconds: float
    exit_code: int | None
    timed_out: bool
    truncated: bool
    log_sha256: str
    log_size: int
    log_path: Path


@dataclass(frozen=True)
class VerificationReport:
    run_id: str
    round: int
    verifier_actor: str
    subject: EvidenceSubject
    handoff_nonce_sha256: str
    verdict: str
    results: tuple[VerificationCommandResult, ...]
    recorded_at: str


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


def _canonical_json_digest(payload: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def _decode_canonical_json(raw: bytes, *, label: str) -> object:
    try:
        payload = json.loads(raw.decode("utf-8"))
        canonical = _canonical_json_bytes(payload) + b"\n"
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise VerificationRecoveryError(f"{label} is corrupt") from error
    if raw != canonical:
        raise VerificationRecoveryError(f"{label} is not canonical JSON")
    return payload


def _write_immutable_json(
    path: Path,
    payload: dict[str, object],
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> None:
    try:
        _atomic_write_private_json(
            path,
            payload,
            trusted_root=trusted_root,
            immutable=True,
        )
    except FileExistsError as error:
        raise VerificationError(
            "verification report already exists for this round"
        ) from error


def _command_payload(
    spec: CommandSpec,
    resolved_argv: tuple[str, ...],
) -> dict[str, object]:
    return {
        "name": spec.name,
        "category": spec.category,
        "argv": list(resolved_argv),
        "timeout_seconds": spec.timeout_seconds,
        "cwd": spec.cwd,
        "env_allowlist": list(spec.env_allowlist),
        "max_log_bytes": spec.max_log_bytes,
        "shell_approved": spec.shell_approved,
    }


def _command_digest(
    spec: CommandSpec,
    resolved_argv: tuple[str, ...],
) -> str:
    return _canonical_json_digest(_command_payload(spec, resolved_argv))


def verification_commands_digest(
    manifest: Manifest,
    variables: Mapping[str, str],
) -> str:
    """Digest the ordered verification commands exactly as the runner resolves them."""

    if type(manifest) is not Manifest:
        raise VerificationError("manifest is not confirmed")
    commands = [
        _command_payload(spec, _resolved_argv(spec.argv, variables))
        for spec in manifest.verification_steps
    ]
    return _canonical_json_digest(
        {
            "schema_version": 1,
            "commands": commands,
        }
    )


def _verification_report_payload(
    *,
    report: VerificationReport,
    terminal_receipt_sha256: Sequence[str],
) -> dict[str, object]:
    results: list[dict[str, object]] = []
    for result in report.results:
        results.append(
            {
                "index": result.index,
                "command_sha256": result.command_sha256,
                "started_at": result.started_at,
                "ended_at": result.ended_at,
                "duration_seconds": result.duration_seconds,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "truncated": result.truncated,
                "log_path": str(result.log_path),
                "log_sha256": result.log_sha256,
                "log_size": result.log_size,
            }
        )
    return {
        "schema_version": 1,
        "run_id": report.run_id,
        "round": report.round,
        "verifier_actor": report.verifier_actor,
        "subject": report.subject.to_dict(),
        "subject_digest": report.subject.digest(),
        "handoff_nonce_sha256": report.handoff_nonce_sha256,
        "commands_sha256": report.subject.commands_sha256,
        "terminal_receipt_sha256": list(terminal_receipt_sha256),
        "verdict": report.verdict,
        "results": results,
        "recorded_at": report.recorded_at,
    }


_OPERATION_KEYS = {
    "schema_version",
    "stage",
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
    "publication_sha256",
}
_OPERATION_STAGES = {
    "prepared": 0,
    "report-written": 1,
    "handoff-consumed": 2,
    "state-transitioned": 3,
}


def _operation_path(run_directory: Path) -> Path:
    return run_directory / "verification-operation.json"


def _publication_seal_payload(
    operation: dict[str, object],
) -> dict[str, object]:
    return {
        key: value
        for key, value in operation.items()
        if key not in {"stage", "publication_sha256"}
    }


def _publication_seal_path(
    run_directory: Path,
    *,
    round_number: int,
    digest: str,
) -> Path:
    return (
        run_directory
        / "verification-publications"
        / f"verification-{round_number:04d}-{digest}.json"
    )


def _prepare_verification_operation(
    operation: dict[str, object],
) -> dict[str, object]:
    seal_payload = _publication_seal_payload(operation)
    digest = _canonical_json_digest(seal_payload)
    report = operation.get("report")
    if not isinstance(report, dict) or type(report.get("round")) is not int:
        raise VerificationRecoveryError("verification publication round is invalid")
    sealed = dict(operation)
    sealed["publication_sha256"] = digest
    return sealed


def _ensure_verification_publication_seal(
    run_directory: Path,
    operation: dict[str, object],
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> None:
    report = operation.get("report")
    digest = operation.get("publication_sha256")
    if (
        not isinstance(report, dict)
        or type(report.get("round")) is not int
        or re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None
    ):
        raise VerificationRecoveryError(
            "verification publication seal identity is invalid"
        )
    path = _publication_seal_path(
        run_directory,
        round_number=report["round"],
        digest=str(digest),
    )
    try:
        names = _private_directory_names(
            path.parent,
            trusted_root=trusted_root,
        )
    except StateNotFoundError:
        names = ()
    except (OSError, StateCorruptionError) as error:
        raise VerificationRecoveryError(
            "verification publication seal directory is unsafe"
        ) from error
    candidates = tuple(
        name
        for name in names
        if re.fullmatch(
            rf"verification-{report['round']:04d}-[0-9a-f]{{64}}\.json",
            name,
        )
    )
    if not candidates:
        _write_immutable_json(
            path,
            _publication_seal_payload(operation),
            trusted_root=trusted_root,
        )
    _validate_verification_publication_seal(
        run_directory,
        operation,
        trusted_root=trusted_root,
    )


def _validate_verification_publication_seal(
    run_directory: Path,
    operation: dict[str, object],
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> None:
    digest = operation.get("publication_sha256")
    report = operation.get("report")
    if (
        re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None
        or not isinstance(report, dict)
        or type(report.get("round")) is not int
    ):
        raise VerificationRecoveryError(
            "verification publication seal identity is invalid"
        )
    path = _publication_seal_path(
        run_directory,
        round_number=report["round"],
        digest=str(digest),
    )
    try:
        names = _private_directory_names(
            path.parent,
            trusted_root=trusted_root,
        )
    except (OSError, StateNotFoundError, StateCorruptionError) as error:
        raise VerificationRecoveryError(
            "verification publication seal set is invalid"
        ) from error
    candidates = tuple(
        name
        for name in names
        if re.fullmatch(
            rf"verification-{report['round']:04d}-[0-9a-f]{{64}}\.json",
            name,
        )
    )
    if candidates != (path.name,):
        raise VerificationRecoveryError("verification publication seal set is invalid")
    try:
        raw = _read_bounded_private_file(
            path,
            trusted_root=trusted_root,
            label="verification publication seal",
            max_bytes=4 * 1024 * 1024,
        )
    except (OSError, StateNotFoundError, StateCorruptionError) as error:
        raise VerificationRecoveryError(
            "verification publication seal is corrupt"
        ) from error
    payload = _decode_canonical_json(raw, label="verification publication seal")
    expected_payload = _publication_seal_payload(operation)
    if (
        not isinstance(payload, dict)
        or payload != expected_payload
        or _canonical_json_digest(payload) != digest
    ):
        raise VerificationRecoveryError(
            "verification publication differs from immutable seal"
        )


def _write_verification_operation_stage(
    run_directory: Path,
    operation: dict[str, object],
    *,
    stage: str,
    trusted_root: Path | PrivateRootAnchor,
) -> dict[str, object]:
    changed = dict(operation)
    changed["stage"] = stage
    _write_canonical_json(
        _operation_path(run_directory),
        changed,
        trusted_root=trusted_root,
    )
    return changed


def _load_operation(
    run_directory: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> dict[str, object] | None:
    path = _operation_path(run_directory)
    try:
        raw = _read_bounded_private_file(
            path,
            trusted_root=trusted_root,
            label="verification receipt",
            max_bytes=4 * 1024 * 1024,
        )
    except StateNotFoundError:
        return None
    except (OSError, StateCorruptionError) as error:
        raise VerificationRecoveryError(
            "verification receipt cannot be opened safely"
        ) from error
    payload = _decode_canonical_json(raw, label="verification receipt")
    if not isinstance(payload, dict) or set(payload) != _OPERATION_KEYS:
        raise VerificationRecoveryError("verification receipt schema is invalid")
    if payload["schema_version"] != 1 or payload["stage"] not in _OPERATION_STAGES:
        raise VerificationRecoveryError("verification receipt identity is invalid")
    request = payload["request"]
    report = payload["report"]
    if not isinstance(request, dict) or not isinstance(report, dict):
        raise VerificationRecoveryError("verification receipt payload is invalid")
    if payload["request_digest"] != _canonical_json_digest(request):
        raise VerificationRecoveryError("verification request digest is invalid")
    if payload["report_digest"] != _canonical_json_digest(report):
        raise VerificationRecoveryError("verification report digest is invalid")
    expected_file = hashlib.sha256(_canonical_json_bytes(report) + b"\n").hexdigest()
    if payload["report_file_sha256"] != expected_file:
        raise VerificationRecoveryError("verification report file digest is invalid")
    if type(payload["expected_revision"]) is not int:
        raise VerificationRecoveryError("verification receipt revision is invalid")
    if re.fullmatch(r"[0-9a-f]{64}", str(payload["handoff_digest"])) is None:
        raise VerificationRecoveryError("verification handoff digest is invalid")
    terminal_receipt_sha256 = payload["terminal_receipt_sha256"]
    if (
        not isinstance(terminal_receipt_sha256, list)
        or not terminal_receipt_sha256
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None
            for digest in terminal_receipt_sha256
        )
        or report.get("terminal_receipt_sha256") != terminal_receipt_sha256
    ):
        raise VerificationRecoveryError(
            "verification terminal receipt digests are invalid"
        )
    if payload["target_phase"] not in {
        Phase.DEVELOPING.value,
        Phase.AWAITING_RELEASE_APPROVAL.value,
    }:
        raise VerificationRecoveryError("verification receipt target is invalid")
    if payload["publication_sha256"] != _canonical_json_digest(
        _publication_seal_payload(payload)
    ):
        raise VerificationRecoveryError("verification publication digest is invalid")
    return payload


def _request_payload(
    *,
    run_id: str,
    verifier_actor: str,
    subject: EvidenceSubject,
    handoff_nonce_sha256: str,
    manifest: Manifest,
    variables: Mapping[str, str],
    sensitive_values: Sequence[str],
) -> dict[str, object]:
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in variables.items()
    ):
        raise VerificationError("verification variables must map strings to strings")
    if isinstance(sensitive_values, (str, bytes)) or any(
        not isinstance(value, str) for value in sensitive_values
    ):
        raise VerificationError("sensitive values must be a sequence of strings")
    command_digests = [
        _command_digest(spec, _resolved_argv(spec.argv, variables))
        for spec in manifest.verification_steps
    ]
    return {
        "schema_version": 1,
        "run_id": run_id,
        "verifier_actor": verifier_actor,
        "subject": subject.to_dict(),
        "subject_digest": subject.digest(),
        "handoff_nonce_sha256": handoff_nonce_sha256,
        "manifest_sha256": manifest_digest(manifest),
        "command_digests": command_digests,
        "variables_sha256": _canonical_json_digest(dict(variables)),
        "sensitive_values_sha256": _canonical_json_digest(list(sensitive_values)),
    }


_COMMAND_RESULT_KEYS = {
    "index",
    "command_sha256",
    "started_at",
    "ended_at",
    "duration_seconds",
    "exit_code",
    "timed_out",
    "truncated",
    "log_path",
    "log_sha256",
    "log_size",
}


def _command_result_payload(result: VerificationCommandResult) -> dict[str, object]:
    return {
        "index": result.index,
        "command_sha256": result.command_sha256,
        "started_at": result.started_at,
        "ended_at": result.ended_at,
        "duration_seconds": result.duration_seconds,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "truncated": result.truncated,
        "log_path": str(result.log_path),
        "log_sha256": result.log_sha256,
        "log_size": result.log_size,
    }


def _command_result_from_payload(
    payload: object,
    *,
    expected_index: int,
) -> VerificationCommandResult:
    if (
        not isinstance(payload, dict)
        or set(payload) != _COMMAND_RESULT_KEYS
        or payload["index"] != expected_index
        or re.fullmatch(r"[0-9a-f]{64}", str(payload["command_sha256"])) is None
        or not isinstance(payload["started_at"], str)
        or not isinstance(payload["ended_at"], str)
        or type(payload["duration_seconds"]) not in {int, float}
        or not math.isfinite(float(payload["duration_seconds"]))
        or float(payload["duration_seconds"]) < 0
        or (payload["exit_code"] is not None and type(payload["exit_code"]) is not int)
        or type(payload["timed_out"]) is not bool
        or type(payload["truncated"]) is not bool
        or not isinstance(payload["log_path"], str)
        or not payload["log_path"]
        or re.fullmatch(r"[0-9a-f]{64}", str(payload["log_sha256"])) is None
        or type(payload["log_size"]) is not int
        or payload["log_size"] < 0
    ):
        raise VerificationRecoveryError("verification command result is invalid")
    return VerificationCommandResult(
        index=expected_index,
        command_sha256=str(payload["command_sha256"]),
        started_at=payload["started_at"],
        ended_at=payload["ended_at"],
        duration_seconds=float(payload["duration_seconds"]),
        exit_code=payload["exit_code"],
        timed_out=payload["timed_out"],
        truncated=payload["truncated"],
        log_sha256=str(payload["log_sha256"]),
        log_size=payload["log_size"],
        log_path=Path(payload["log_path"]),
    )


_EXECUTION_RECEIPT_KEYS = {
    "schema_version",
    "run_id",
    "round",
    "index",
    "status",
    "request_digest",
    "subject_digest",
    "command_sha256",
    "expected_revision",
    "prepared_at",
    "started_at",
    "finished_at",
    "result",
}
_EXECUTION_STATUSES = {
    "PREPARED",
    "RUNNING",
    "SUCCEEDED",
    "FAILED",
    "UNKNOWN",
}


def _execution_receipt_path(
    run_directory: Path,
    *,
    round_number: int,
    index: int,
) -> Path:
    return (
        run_directory
        / "verification-executions"
        / f"verification-{round_number:04d}-command-{index:04d}.json"
    )


def _write_execution_receipt_stage(
    path: Path,
    receipt: dict[str, object],
    *,
    status: str,
    trusted_root: Path | PrivateRootAnchor,
    result: dict[str, object] | None = None,
) -> dict[str, object]:
    if status not in _EXECUTION_STATUSES:
        raise VerificationRecoveryError("verification execution status is invalid")
    current = _load_execution_receipt_file(path, trusted_root=trusted_root)
    if (status == "PREPARED" and current is not None) or (
        status != "PREPARED" and current != receipt
    ):
        raise VerificationRecoveryError(
            "verification execution receipt changed before transition"
        )
    changed = dict(receipt)
    now = _utc_now()
    changed["status"] = status
    if status == "PREPARED":
        changed["prepared_at"] = now
        changed["started_at"] = None
        changed["finished_at"] = None
        changed["result"] = None
    elif status == "RUNNING":
        if receipt.get("status") != "PREPARED":
            raise VerificationRecoveryError(
                "verification execution transition is invalid"
            )
        changed["started_at"] = now
        changed["finished_at"] = None
        changed["result"] = None
    elif status in {"SUCCEEDED", "FAILED"}:
        if receipt.get("status") != "RUNNING" or result is None:
            raise VerificationRecoveryError(
                "verification execution transition is invalid"
            )
        changed["finished_at"] = now
        changed["result"] = result
    else:
        if receipt.get("status") not in {"RUNNING", "UNKNOWN"}:
            raise VerificationRecoveryError(
                "verification execution transition is invalid"
            )
        changed["finished_at"] = now
        changed["result"] = None
    if status in {"SUCCEEDED", "FAILED"}:
        terminal_digest = _canonical_json_digest(changed)
        _write_immutable_json(
            _execution_terminal_path(path, terminal_digest),
            changed,
            trusted_root=trusted_root,
        )
    _write_canonical_json(path, changed, trusted_root=trusted_root)
    return changed


def _load_execution_receipt_file(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> dict[str, object] | None:
    try:
        raw = _read_bounded_private_file(
            path,
            trusted_root=trusted_root,
            label="verification execution receipt",
            max_bytes=4 * 1024 * 1024,
        )
    except StateNotFoundError:
        return None
    except (OSError, StateCorruptionError) as error:
        raise VerificationRecoveryError(
            "verification execution receipt cannot be opened safely"
        ) from error
    payload = _decode_canonical_json(raw, label="verification execution receipt")
    return _validate_execution_receipt_payload(payload)


def _validate_execution_receipt_payload(
    payload: object,
) -> dict[str, object]:
    if not isinstance(payload, dict) or set(payload) != _EXECUTION_RECEIPT_KEYS:
        raise VerificationRecoveryError(
            "verification execution receipt schema is invalid"
        )
    status_value = payload["status"]
    if (
        payload["schema_version"] != 1
        or not isinstance(payload["run_id"], str)
        or not payload["run_id"]
        or type(payload["round"]) is not int
        or payload["round"] < 1
        or type(payload["index"]) is not int
        or payload["index"] < 1
        or status_value not in _EXECUTION_STATUSES
        or re.fullmatch(r"[0-9a-f]{64}", str(payload["request_digest"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(payload["subject_digest"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(payload["command_sha256"])) is None
        or type(payload["expected_revision"]) is not int
        or payload["expected_revision"] < 0
        or not isinstance(payload["prepared_at"], str)
        or not payload["prepared_at"]
    ):
        raise VerificationRecoveryError(
            "verification execution receipt identity is invalid"
        )
    if status_value == "PREPARED":
        valid_stage = (
            payload["started_at"] is None
            and payload["finished_at"] is None
            and payload["result"] is None
        )
    elif status_value == "RUNNING":
        valid_stage = (
            isinstance(payload["started_at"], str)
            and bool(payload["started_at"])
            and payload["finished_at"] is None
            and payload["result"] is None
        )
    elif status_value == "UNKNOWN":
        valid_stage = (
            isinstance(payload["started_at"], str)
            and bool(payload["started_at"])
            and isinstance(payload["finished_at"], str)
            and bool(payload["finished_at"])
            and payload["result"] is None
        )
    else:
        valid_stage = (
            isinstance(payload["started_at"], str)
            and bool(payload["started_at"])
            and isinstance(payload["finished_at"], str)
            and bool(payload["finished_at"])
            and isinstance(payload["result"], dict)
        )
        if valid_stage:
            result = _command_result_from_payload(
                payload["result"],
                expected_index=payload["index"],
            )
            succeeded = not result.timed_out and result.exit_code == 0
            valid_stage = (status_value == "SUCCEEDED") is succeeded
    if not valid_stage:
        raise VerificationRecoveryError(
            "verification execution receipt stage is invalid"
        )
    return payload


def _execution_terminal_path(path: Path, digest: str) -> Path:
    return path.with_name(f"{path.stem}.terminal-{digest}.json")


def _load_sealed_execution_terminal(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> tuple[dict[str, object], str] | None:
    try:
        names = _private_directory_names(
            path.parent,
            trusted_root=trusted_root,
        )
    except StateNotFoundError:
        return None
    except (OSError, StateCorruptionError) as error:
        raise VerificationRecoveryError(
            "verification terminal receipt directory is unsafe"
        ) from error
    candidates = tuple(
        name
        for name in names
        if re.fullmatch(
            rf"{re.escape(path.stem)}\.terminal-[0-9a-f]{{64}}\.json",
            name,
        )
    )
    if not candidates:
        return None
    if len(candidates) != 1:
        raise VerificationRecoveryError(
            "verification execution has multiple terminal receipts"
        )
    terminal_path = path.parent / candidates[0]
    match = re.fullmatch(
        rf"{re.escape(path.stem)}\.terminal-([0-9a-f]{{64}})\.json",
        terminal_path.name,
    )
    if match is None:
        raise VerificationRecoveryError(
            "verification terminal receipt filename is invalid"
        )
    try:
        raw = _read_bounded_private_file(
            terminal_path,
            trusted_root=trusted_root,
            label="verification terminal receipt",
            max_bytes=4 * 1024 * 1024,
        )
    except (OSError, StateNotFoundError, StateCorruptionError) as error:
        raise VerificationRecoveryError(
            "verification terminal receipt cannot be read"
        ) from error
    payload = _validate_execution_receipt_payload(
        _decode_canonical_json(raw, label="verification terminal receipt")
    )
    if payload["status"] not in {"SUCCEEDED", "FAILED"}:
        raise VerificationRecoveryError("verification terminal receipt is not terminal")
    digest = match.group(1)
    if _canonical_json_digest(payload) != digest:
        raise VerificationRecoveryError(
            "verification terminal receipt digest is invalid"
        )
    return payload, digest


def _load_execution_receipt(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> dict[str, object] | None:
    receipt = _load_execution_receipt_file(path, trusted_root=trusted_root)
    terminal = _load_sealed_execution_terminal(path, trusted_root=trusted_root)
    if terminal is None:
        if receipt is not None and receipt["status"] in {"SUCCEEDED", "FAILED"}:
            raise VerificationRecoveryError(
                "verification terminal receipt is not sealed"
            )
        return receipt
    terminal_receipt, _ = terminal
    if receipt is None:
        return terminal_receipt
    if receipt["status"] in {"SUCCEEDED", "FAILED"}:
        if receipt != terminal_receipt:
            raise VerificationRecoveryError(
                "verification terminal receipt differs from sealed evidence"
            )
        return receipt
    if receipt["status"] == "RUNNING":
        common_keys = _EXECUTION_RECEIPT_KEYS - {
            "status",
            "finished_at",
            "result",
        }
        if any(receipt[key] != terminal_receipt[key] for key in common_keys):
            raise VerificationRecoveryError(
                "verification terminal receipt differs from running evidence"
            )
        return terminal_receipt
    raise VerificationRecoveryError(
        "verification terminal receipt conflicts with execution stage"
    )


def _validate_execution_receipt_binding(
    receipt: dict[str, object],
    *,
    run_id: str,
    round_number: int,
    index: int,
    request_digest: str,
    subject_digest: str,
    command_sha256: str,
    expected_revision: int,
) -> None:
    if (
        receipt["run_id"] != run_id
        or receipt["round"] != round_number
        or receipt["index"] != index
        or receipt["request_digest"] != request_digest
        or receipt["subject_digest"] != subject_digest
        or receipt["command_sha256"] != command_sha256
        or receipt["expected_revision"] != expected_revision
    ):
        raise VerificationRecoveryError(
            "verification execution receipt belongs to a different request"
        )


def _ordered_terminal_receipt_digests(
    *,
    run_directory: Path,
    round_number: int,
    results: Sequence[VerificationCommandResult],
    request: dict[str, object],
    subject_digest: str,
    expected_revision: int,
    trusted_root: Path | PrivateRootAnchor,
) -> tuple[str, ...]:
    command_digests = request.get("command_digests")
    if not isinstance(command_digests, list) or len(results) > len(command_digests):
        raise VerificationRecoveryError(
            "verification terminal command evidence is invalid"
        )
    request_digest = _canonical_json_digest(request)
    terminal_digests: list[str] = []
    for index, result in enumerate(results, start=1):
        path = _execution_receipt_path(
            run_directory,
            round_number=round_number,
            index=index,
        )
        receipt = _load_execution_receipt(path, trusted_root=trusted_root)
        sealed = _load_sealed_execution_terminal(path, trusted_root=trusted_root)
        if receipt is None or sealed is None:
            raise VerificationRecoveryError("verification terminal receipt is missing")
        terminal_receipt, terminal_digest = sealed
        if receipt != terminal_receipt:
            raise VerificationRecoveryError(
                "verification terminal receipt differs from sealed evidence"
            )
        _validate_execution_receipt_binding(
            terminal_receipt,
            run_id=str(request.get("run_id")),
            round_number=round_number,
            index=index,
            request_digest=request_digest,
            subject_digest=subject_digest,
            command_sha256=str(command_digests[index - 1]),
            expected_revision=expected_revision,
        )
        result_payload = _command_result_payload(result)
        succeeded = not result.timed_out and result.exit_code == 0
        if (
            terminal_receipt["result"] != result_payload
            or (terminal_receipt["status"] == "SUCCEEDED") is not succeeded
        ):
            raise VerificationRecoveryError(
                "verification report differs from terminal receipts"
            )
        terminal_digests.append(terminal_digest)
    return tuple(terminal_digests)


def _report_from_payload(
    payload: dict[str, object],
    subject: EvidenceSubject,
) -> VerificationReport:
    expected_keys = {
        "schema_version",
        "run_id",
        "round",
        "verifier_actor",
        "subject",
        "subject_digest",
        "handoff_nonce_sha256",
        "commands_sha256",
        "terminal_receipt_sha256",
        "verdict",
        "results",
        "recorded_at",
    }
    if (
        set(payload) != expected_keys
        or payload["schema_version"] != 1
        or payload["subject"] != subject.to_dict()
        or payload["subject_digest"] != subject.digest()
        or payload["commands_sha256"] != subject.commands_sha256
        or not isinstance(payload["terminal_receipt_sha256"], list)
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None
            for digest in payload["terminal_receipt_sha256"]
        )
        or payload["verdict"] not in {"pass", "fail"}
        or type(payload["round"]) is not int
        or not isinstance(payload["results"], list)
    ):
        raise VerificationRecoveryError("verification report payload is invalid")
    results: list[VerificationCommandResult] = []
    for index, item in enumerate(payload["results"], start=1):
        results.append(_command_result_from_payload(item, expected_index=index))
    return VerificationReport(
        run_id=str(payload["run_id"]),
        round=int(payload["round"]),
        verifier_actor=str(payload["verifier_actor"]),
        subject=subject,
        handoff_nonce_sha256=str(payload["handoff_nonce_sha256"]),
        verdict=str(payload["verdict"]),
        results=tuple(results),
        recorded_at=str(payload["recorded_at"]),
    )


def _git_output(repo: Path, *arguments: str) -> str:
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
    if completed.returncode:
        raise VerificationError("candidate Git identity cannot be inspected")
    return completed.stdout.removesuffix("\n")


def _load_code_review(
    store: StateStore,
    subject: EvidenceSubject,
) -> tuple[dict[str, object], dict[str, object]]:
    try:
        return validate_passing_code_review(store, subject)
    except RuntimeError as error:
        raise VerificationError("a passing code review is required") from error


def _candidate_is_current(repo: Path, subject: EvidenceSubject) -> bool:
    return (
        _git_output(repo, "rev-parse", "--verify", "HEAD^{commit}")
        == subject.candidate_oid
        and _git_output(repo, "rev-parse", "--verify", "HEAD^{tree}")
        == subject.tree_oid
        and not _git_output(
            repo,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        )
    )


def _candidate_base_is_current(repo: Path, subject: EvidenceSubject) -> bool:
    completed = subprocess.run(
        (
            "git",
            "merge-base",
            "--is-ancestor",
            subject.base_oid,
            subject.candidate_oid,
        ),
        cwd=repo,
        check=False,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode not in {0, 1}:
        raise VerificationError("candidate base identity cannot be inspected")
    return completed.returncode == 0


def _validate_log_evidence(
    result: object,
    log_directory: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> None:
    try:
        log_path = Path(getattr(result, "log_path"))
        if Path(os.path.abspath(log_path.parent)) != log_directory:
            raise VerificationError("verification log path is outside the run")
        raw = _read_bounded_private_file(
            log_path,
            trusted_root=trusted_root,
            label="verification log",
            max_bytes=64 * 1024 * 1024,
        )
    except VerificationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise VerificationError("verification log cannot be validated") from error
    if len(raw) != getattr(result, "log_size") or hashlib.sha256(
        raw
    ).hexdigest() != getattr(result, "log_sha256"):
        raise VerificationError("verification log size or hash is invalid")


def _validate_recovery_log_evidence(
    result: object,
    log_directory: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> None:
    try:
        _validate_log_evidence(
            result,
            log_directory,
            trusted_root=trusted_root,
        )
    except VerificationRecoveryError:
        raise
    except VerificationError as error:
        raise VerificationRecoveryError(
            "verification recovery log evidence is invalid"
        ) from error


def _private_file_digest(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> str | None:
    try:
        raw = _read_bounded_private_file(
            path,
            trusted_root=trusted_root,
            label="verification report",
            max_bytes=4 * 1024 * 1024,
        )
    except StateNotFoundError:
        return None
    except (OSError, StateCorruptionError) as error:
        raise VerificationRecoveryError(
            "verification report is not a regular private file"
        ) from error
    return hashlib.sha256(raw).hexdigest()


def _read_private_verification_json(
    run_directory: Path,
    relative_path: tuple[str, ...],
    *,
    label: str,
    trusted_root: Path | PrivateRootAnchor,
) -> tuple[dict[str, object], bytes]:
    if not relative_path or any(
        not component
        or component in {".", ".."}
        or "/" in component
        or "\\" in component
        for component in relative_path
    ):
        raise VerificationRecoveryError(f"{label} path is unsafe")
    path = run_directory.joinpath(*relative_path)
    try:
        raw = _read_bounded_private_file(
            path,
            trusted_root=trusted_root,
            label=label,
            max_bytes=4 * 1024 * 1024,
        )
    except StateNotFoundError:
        raise VerificationEvidenceMissingError(f"{label} is missing") from None
    except (OSError, StateCorruptionError) as error:
        raise VerificationRecoveryError(f"{label} cannot be opened safely") from error
    payload = _decode_canonical_json(raw, label=label)
    if not isinstance(payload, dict):
        raise VerificationRecoveryError(f"{label} is not canonical JSON")
    return payload, raw


_VERIFICATION_REQUEST_KEYS = {
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
_VERIFICATION_PUBLICATION_KEYS = _OPERATION_KEYS - {
    "stage",
    "publication_sha256",
}


def validate_recoverable_verification_publication(
    store: StateStore,
    *,
    manifest: Manifest,
    current_subject: EvidenceSubject,
    variables: Mapping[str, str],
) -> VerificationReport:
    """Validate a pending verification publication without consuming its nonce."""

    if (
        type(store) is not StateStore
        or type(manifest) is not Manifest
        or type(current_subject) is not EvidenceSubject
    ):
        raise TypeError("verification evidence inputs must be exact engine types")
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in variables.items()
    ):
        raise TypeError("verification variables must map strings to strings")
    operation = _load_operation(
        store.run_directory,
        trusted_root=store.trusted_root,
    )
    if operation is None:
        raise VerificationEvidenceMissingError(
            "verification publication receipt is missing"
        )
    _validate_verification_publication_seal(
        store.run_directory,
        operation,
        trusted_root=store.trusted_root,
    )
    request = operation.get("request")
    report_payload = operation.get("report")
    if not isinstance(request, dict) or not isinstance(report_payload, dict):
        raise VerificationRecoveryError(
            "verification publication receipt payload is invalid"
        )
    subject_payload = request.get("subject")
    try:
        if not isinstance(subject_payload, dict):
            raise TypeError
        subject = EvidenceSubject(**subject_payload)
    except (TypeError, ValueError) as error:
        raise VerificationRecoveryError(
            "pending verification subject is invalid"
        ) from error
    report = _report_from_payload(report_payload, subject)
    expected_command_digests = [
        _command_digest(spec, _resolved_argv(spec.argv, variables))
        for spec in manifest.verification_steps
    ]
    sensitive_digest = request.get("sensitive_values_sha256")
    if (
        set(request) != _VERIFICATION_REQUEST_KEYS
        or request.get("schema_version") != 1
        or request.get("run_id") != current_subject.run_id
        or subject != current_subject
        or request.get("subject_digest") != current_subject.digest()
        or request.get("manifest_sha256") != manifest_digest(manifest)
        or request.get("manifest_sha256") != current_subject.manifest_sha256
        or request.get("command_digests") != expected_command_digests
        or request.get("variables_sha256") != _canonical_json_digest(dict(variables))
        or not isinstance(sensitive_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", sensitive_digest) is None
        or report.run_id != current_subject.run_id
        or report.verifier_actor != request.get("verifier_actor")
        or report.handoff_nonce_sha256 != request.get("handoff_nonce_sha256")
        or report_payload.get("terminal_receipt_sha256")
        != operation.get("terminal_receipt_sha256")
        or (
            report.verdict == "pass"
            and (
                len(report.results) != len(expected_command_digests)
                or any(
                    result.timed_out or result.exit_code != 0
                    for result in report.results
                )
            )
        )
        or [result.command_sha256 for result in report.results]
        != expected_command_digests[: len(report.results)]
    ):
        raise VerificationRecoveryError(
            "pending verification request is stale or invalid"
        )

    expected_revision = operation.get("expected_revision")
    if type(expected_revision) is not int or expected_revision < 0:
        raise VerificationRecoveryError("pending verification revision is invalid")
    expected_round = sum(
        event.phase is Phase.VERIFYING and event.revision <= expected_revision
        for event in store.events()
    )
    expected_target = (
        Phase.AWAITING_RELEASE_APPROVAL
        if report.verdict == "pass"
        else Phase.DEVELOPING
    )
    state = store.load()
    source_state = (
        state.phase is Phase.VERIFYING and state.revision == expected_revision
    )
    target_state = (
        state.phase is expected_target and state.revision == expected_revision + 1
    )
    expected_report_path = (
        store.run_directory
        / "verifications"
        / f"verification-{expected_round:04d}.json"
    )
    if (
        not source_state
        and not target_state
        or report.round != expected_round
        or operation.get("target_phase") != expected_target.value
        or operation.get("artifact_path") != str(expected_report_path)
    ):
        raise VerificationRecoveryError(
            "pending verification state or path differs from its receipt"
        )

    terminal_digests = _ordered_terminal_receipt_digests(
        run_directory=store.run_directory,
        round_number=report.round,
        results=report.results,
        request=request,
        subject_digest=current_subject.digest(),
        expected_revision=expected_revision,
        trusted_root=store.trusted_root,
    )
    if list(terminal_digests) != report_payload.get("terminal_receipt_sha256") or list(
        terminal_digests
    ) != operation.get("terminal_receipt_sha256"):
        raise VerificationRecoveryError(
            "pending verification terminal receipts differ from publication"
        )
    for result in report.results:
        _validate_recovery_log_evidence(
            result,
            store.run_directory / "logs",
            trusted_root=store.trusted_root,
        )

    current_report_digest = _private_file_digest(
        expected_report_path,
        trusted_root=store.trusted_root,
    )
    stage = str(operation["stage"])
    if (
        _OPERATION_STAGES[stage] >= _OPERATION_STAGES["report-written"]
        and current_report_digest != operation.get("report_file_sha256")
    ) or (
        _OPERATION_STAGES[stage] < _OPERATION_STAGES["report-written"]
        and current_report_digest not in {None, operation.get("report_file_sha256")}
    ):
        raise VerificationRecoveryError(
            "pending verification report differs from publication"
        )

    handoff_digest = report.handoff_nonce_sha256
    handoff_path = store.run_directory / "handoffs" / f"{handoff_digest}.json"
    if operation.get("handoff_path") != str(handoff_path):
        raise VerificationRecoveryError("pending verification handoff path is invalid")
    handoff, _ = _read_private_verification_json(
        store.run_directory,
        ("handoffs", handoff_path.name),
        label="pending verification handoff",
        trusted_root=store.trusted_root,
    )
    normalized_handoff = dict(handoff)
    normalized_handoff["consumed_at"] = None
    normalized_handoff["consumed_by"] = None
    consumed = (
        handoff.get("consumed_at") == report.recorded_at
        and handoff.get("consumed_by") == report.verifier_actor
    )
    unconsumed = (
        handoff.get("consumed_at") is None and handoff.get("consumed_by") is None
    )
    try:
        review, review_handoff = _load_code_review(
            store,
            current_subject,
        )
    except VerificationError as error:
        raise VerificationRecoveryError(
            "pending verification code review is stale or invalid"
        ) from error
    if (
        set(handoff)
        != {
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
        or operation.get("handoff_digest") != _canonical_json_digest(normalized_handoff)
        or handoff.get("schema_version") != 1
        or handoff.get("run_id") != current_subject.run_id
        or handoff.get("role") != "verifier"
        or handoff.get("nonce_sha256") != handoff_digest
        or handoff.get("subject") != current_subject.to_dict()
        or handoff.get("subject_digest") != current_subject.digest()
        or not (unconsumed or consumed)
        or (
            _OPERATION_STAGES[stage] >= _OPERATION_STAGES["handoff-consumed"]
            and not consumed
        )
        or report.verifier_actor
        in {
            handoff.get("source_actor"),
            review.get("reviewer_actor"),
            review_handoff.get("source_actor"),
        }
    ):
        raise VerificationRecoveryError(
            "pending verification handoff is stale or invalid"
        )
    return report


def _private_verification_directory_names(
    run_directory: Path,
    name: str,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> tuple[str, ...]:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise VerificationRecoveryError(
            "verification evidence directory name is unsafe"
        )
    try:
        return _private_directory_names(
            run_directory / name,
            trusted_root=trusted_root,
        )
    except StateNotFoundError:
        raise VerificationEvidenceMissingError(
            f"verification evidence directory is missing: {name}"
        ) from None
    except (OSError, StateCorruptionError) as error:
        raise VerificationRecoveryError(
            f"verification evidence directory is unsafe: {name}"
        ) from error


def validate_passing_verification(
    store: StateStore,
    *,
    manifest: Manifest,
    current_subject: EvidenceSubject,
    variables: Mapping[str, str],
) -> VerificationReport:
    """Read-only validation of publication, receipt, handoff, and log evidence."""

    if (
        type(store) is not StateStore
        or type(manifest) is not Manifest
        or type(current_subject) is not EvidenceSubject
    ):
        raise TypeError("verification evidence inputs must be exact engine types")
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in variables.items()
    ):
        raise TypeError("verification variables must map strings to strings")
    if os.path.lexists(_operation_path(store.run_directory)):
        raise VerificationRecoveryError(
            "verification publication is incomplete and requires recovery"
        )
    events = store.events()
    publication_events = tuple(
        event
        for event in events
        if event.event_type == "phase.transitioned"
        and event.run_id == current_subject.run_id
        and event.previous_phase is Phase.VERIFYING
        and event.phase is Phase.AWAITING_RELEASE_APPROVAL
    )
    if not publication_events:
        raise VerificationEvidenceMissingError(
            "passing verification is not bound to the state WAL"
        )
    transition = publication_events[-1]
    expected_revision = transition.revision - 1
    expected_round = sum(
        event.phase is Phase.VERIFYING and event.revision <= expected_revision
        for event in events
    )
    publication_names = tuple(
        name
        for name in _private_verification_directory_names(
            store.run_directory,
            "verification-publications",
            trusted_root=store.trusted_root,
        )
        if re.fullmatch(
            rf"verification-{expected_round:04d}-[0-9a-f]{{64}}\.json",
            name,
        )
    )
    if not publication_names:
        raise VerificationEvidenceMissingError(
            "verification publication seal is missing"
        )
    if len(publication_names) != 1:
        raise VerificationRecoveryError(
            "verification publication seal set is ambiguous"
        )
    publication_path = (
        store.run_directory / "verification-publications" / publication_names[0]
    )
    publication, publication_raw = _read_private_verification_json(
        store.run_directory,
        ("verification-publications", publication_path.name),
        label="verification publication seal",
        trusted_root=store.trusted_root,
    )
    match = re.fullmatch(
        rf"verification-{expected_round:04d}-([0-9a-f]{{64}})\.json",
        publication_path.name,
    )
    if (
        match is None
        or set(publication) != _VERIFICATION_PUBLICATION_KEYS
        or publication.get("schema_version") != 1
        or _canonical_json_digest(publication) != match.group(1)
        or hashlib.sha256(publication_raw[:-1]).hexdigest() != match.group(1)
    ):
        raise VerificationRecoveryError(
            "verification publication seal identity is invalid"
        )
    request = publication.get("request")
    report_payload = publication.get("report")
    if not isinstance(request, dict) or not isinstance(report_payload, dict):
        raise VerificationRecoveryError("verification publication payload is invalid")
    subject_payload = request.get("subject")
    try:
        if not isinstance(subject_payload, dict):
            raise TypeError
        verified_subject = EvidenceSubject(**subject_payload)
    except (TypeError, ValueError) as error:
        raise VerificationRecoveryError(
            "verification publication subject is invalid"
        ) from error
    try:
        report = _report_from_payload(report_payload, verified_subject)
    except VerificationRecoveryError:
        raise
    except Exception as error:
        raise VerificationRecoveryError(
            "verification report payload is invalid"
        ) from error
    expected_command_digests = [
        _command_digest(spec, _resolved_argv(spec.argv, variables))
        for spec in manifest.verification_steps
    ]
    sensitive_digest = request.get("sensitive_values_sha256")
    report_path = (
        store.run_directory
        / "verifications"
        / f"verification-{expected_round:04d}.json"
    )
    if (
        set(request) != _VERIFICATION_REQUEST_KEYS
        or request.get("schema_version") != 1
        or request.get("run_id") != verified_subject.run_id
        or request.get("verifier_actor") != report.verifier_actor
        or request.get("subject_digest") != verified_subject.digest()
        or request.get("handoff_nonce_sha256") != report.handoff_nonce_sha256
        or request.get("manifest_sha256") != manifest_digest(manifest)
        or request.get("manifest_sha256") != verified_subject.manifest_sha256
        or request.get("command_digests") != expected_command_digests
        or request.get("variables_sha256") != _canonical_json_digest(dict(variables))
        or not isinstance(sensitive_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", sensitive_digest) is None
        or publication.get("request_digest") != _canonical_json_digest(request)
        or publication.get("report_digest") != _canonical_json_digest(report_payload)
        or publication.get("artifact_path") != str(report_path)
        or publication.get("expected_revision") != expected_revision
        or publication.get("target_phase") != Phase.AWAITING_RELEASE_APPROVAL.value
        or publication.get("terminal_receipt_sha256")
        != report_payload.get("terminal_receipt_sha256")
        or report.run_id != verified_subject.run_id
        or report.round != expected_round
        or report.verdict != "pass"
        or len(report.results) != len(expected_command_digests)
        or [result.command_sha256 for result in report.results]
        != expected_command_digests
        or any(result.timed_out or result.exit_code != 0 for result in report.results)
    ):
        raise VerificationRecoveryError(
            "passing verification publication is stale or invalid"
        )

    stored_report, report_raw = _read_private_verification_json(
        store.run_directory,
        ("verifications", report_path.name),
        label="verification report",
        trusted_root=store.trusted_root,
    )
    if (
        stored_report != report_payload
        or publication.get("report_file_sha256")
        != hashlib.sha256(report_raw).hexdigest()
    ):
        raise VerificationRecoveryError(
            "verification report differs from immutable publication"
        )
    for index in range(1, len(report.results) + 1):
        execution_names = _private_verification_directory_names(
            store.run_directory,
            "verification-executions",
            trusted_root=store.trusted_root,
        )
        execution_path = _execution_receipt_path(
            store.run_directory,
            round_number=expected_round,
            index=index,
        )
        if execution_path.name not in execution_names and not any(
            re.fullmatch(
                rf"{re.escape(execution_path.stem)}\.terminal-"
                r"[0-9a-f]{64}\.json",
                name,
            )
            for name in execution_names
        ):
            raise VerificationEvidenceMissingError(
                "verification terminal receipt is missing"
            )
    terminal_digests = _ordered_terminal_receipt_digests(
        run_directory=store.run_directory,
        round_number=expected_round,
        results=report.results,
        request=request,
        subject_digest=verified_subject.digest(),
        expected_revision=expected_revision,
        trusted_root=store.trusted_root,
    )
    if list(terminal_digests) != report_payload.get("terminal_receipt_sha256") or list(
        terminal_digests
    ) != publication.get("terminal_receipt_sha256"):
        raise VerificationRecoveryError(
            "verification terminal receipts differ from publication"
        )
    for result in report.results:
        _validate_recovery_log_evidence(
            result,
            store.run_directory / "logs",
            trusted_root=store.trusted_root,
        )

    handoff_path = (
        store.run_directory / "handoffs" / f"{report.handoff_nonce_sha256}.json"
    )
    if publication.get("handoff_path") != str(handoff_path):
        raise VerificationRecoveryError("verification handoff path is invalid")
    handoff, _ = _read_private_verification_json(
        store.run_directory,
        ("handoffs", handoff_path.name),
        label="verification handoff",
        trusted_root=store.trusted_root,
    )
    normalized_handoff = dict(handoff)
    normalized_handoff["consumed_at"] = None
    normalized_handoff["consumed_by"] = None
    if (
        set(handoff)
        != {
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
        or publication.get("handoff_digest")
        != _canonical_json_digest(normalized_handoff)
        or handoff.get("schema_version") != 1
        or handoff.get("run_id") != verified_subject.run_id
        or handoff.get("role") != "verifier"
        or handoff.get("nonce_sha256") != report.handoff_nonce_sha256
        or handoff.get("subject") != verified_subject.to_dict()
        or handoff.get("subject_digest") != verified_subject.digest()
        or handoff.get("consumed_at") != report.recorded_at
        or handoff.get("consumed_by") != report.verifier_actor
    ):
        raise VerificationRecoveryError("verification handoff differs from publication")
    if verified_subject != current_subject:
        raise VerificationEvidenceStaleError("passing verification subject is stale")
    return report


class Verifier:
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

    def _assert_subject_evidence_stable(
        self,
        *,
        expected_review: dict[str, object],
        expected_review_handoff: dict[str, object],
        handoff_nonce: str,
        expected_handoff_path: Path,
        expected_handoff: dict[str, object],
    ) -> None:
        try:
            review, review_handoff = _load_code_review(
                self.store,
                self.current_subject,
            )
            handoff_path, handoff = _load_handoff(self.store, handoff_nonce)
        except RuntimeError as error:
            raise VerificationError("verification subject evidence changed") from error
        if (
            review != expected_review
            or review_handoff != expected_review_handoff
            or handoff_path != expected_handoff_path
            or handoff != expected_handoff
        ):
            raise VerificationError("verification subject evidence changed")

    def _block_recovery(self, message: str) -> VerificationRecoveryError:
        state = self.store.load()
        if state.phase is Phase.VERIFYING:
            self.store.transition(Phase.BLOCKED, expected_revision=state.revision)
        return VerificationRecoveryError(message)

    def _load_publication_handoff(
        self,
        operation: dict[str, object],
        handoff_nonce: str | None,
    ) -> tuple[Path, dict[str, object]]:
        request = operation.get("request")
        if not isinstance(request, dict):
            raise VerificationRecoveryError("verification handoff request is invalid")
        nonce_sha256 = request.get("handoff_nonce_sha256")
        if (
            not isinstance(nonce_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", nonce_sha256) is None
        ):
            raise VerificationRecoveryError("verification handoff digest is invalid")
        try:
            if handoff_nonce is None:
                return _load_handoff_digest(self.store, nonce_sha256)
            if (
                hashlib.sha256(handoff_nonce.encode("utf-8")).hexdigest()
                != nonce_sha256
            ):
                raise VerificationRecoveryError(
                    "verification handoff differs from receipt"
                )
            return _load_handoff(self.store, handoff_nonce)
        except VerificationRecoveryError:
            raise
        except RuntimeError as error:
            raise VerificationRecoveryError(
                "verification handoff differs from receipt"
            ) from error

    def _assert_pending_release_gate_current(
        self,
        operation: dict[str, object],
        *,
        report: VerificationReport,
        handoff_nonce: str | None,
        require_consumed_handoff: bool,
    ) -> None:
        if report.verdict != "pass":
            return
        try:
            if (
                manifest_digest(self.manifest) != self.current_subject.manifest_sha256
                or verification_commands_digest(self.manifest, self.variables)
                != self.current_subject.commands_sha256
                or not _candidate_is_current(self.repo, self.current_subject)
                or not _candidate_base_is_current(self.repo, self.current_subject)
            ):
                raise VerificationRecoveryError(
                    "pending verification release gate is stale"
                )
            review, review_handoff = _load_code_review(
                self.store,
                self.current_subject,
            )
            handoff_path, handoff = self._load_publication_handoff(
                operation,
                handoff_nonce,
            )
        except VerificationRecoveryError:
            raise
        except RuntimeError as error:
            raise VerificationRecoveryError(
                "pending verification release gate is stale"
            ) from error
        if operation["handoff_path"] != str(handoff_path):
            raise VerificationRecoveryError("verification handoff differs from receipt")
        normalized_handoff = dict(handoff)
        normalized_handoff["consumed_at"] = None
        normalized_handoff["consumed_by"] = None
        if _canonical_json_digest(normalized_handoff) != operation["handoff_digest"]:
            raise VerificationRecoveryError("verification handoff differs from receipt")
        consumed = (
            handoff.get("consumed_at") == report.recorded_at
            and handoff.get("consumed_by") == report.verifier_actor
        )
        unconsumed = (
            handoff.get("consumed_at") is None and handoff.get("consumed_by") is None
        )
        if (require_consumed_handoff and not consumed) or (
            not require_consumed_handoff and not (unconsumed or consumed)
        ):
            raise VerificationRecoveryError("verification handoff differs from receipt")
        if report.verifier_actor in {
            handoff.get("source_actor"),
            review.get("reviewer_actor"),
            review_handoff.get("source_actor"),
        }:
            raise VerificationRecoveryError(
                "pending verification actor separation is stale"
            )

    def _publication_transition_is_in_wal(
        self,
        operation: dict[str, object],
    ) -> bool:
        expected_revision = operation["expected_revision"]
        if type(expected_revision) is not int:
            return False
        request = operation["request"]
        if not isinstance(request, dict):
            return False
        try:
            target = Phase(str(operation["target_phase"]))
        except ValueError:
            return False
        return any(
            event.revision == expected_revision + 1
            and event.run_id == request.get("run_id")
            and event.previous_phase is Phase.VERIFYING
            and event.phase is target
            for event in self.store.events()
        )

    def _reconcile_completed_operation(
        self,
        operation: dict[str, object],
    ) -> VerificationReport:
        _assert_store_root_current(self.store)
        if not self._publication_transition_is_in_wal(operation):
            raise VerificationRecoveryError(
                "verification publication transition is not proven by the WAL"
            )
        request = operation["request"]
        report_payload = operation["report"]
        if not isinstance(request, dict) or not isinstance(report_payload, dict):
            raise VerificationRecoveryError(
                "verification publication receipt payload is invalid"
            )
        subject_payload = request.get("subject")
        try:
            if not isinstance(subject_payload, dict):
                raise TypeError
            subject = EvidenceSubject(**subject_payload)
        except (TypeError, ValueError) as error:
            raise VerificationRecoveryError(
                "verification publication subject is invalid"
            ) from error
        report = _report_from_payload(report_payload, subject)
        if report.verdict == "pass" and any(
            result.timed_out or result.exit_code != 0 for result in report.results
        ):
            raise VerificationRecoveryError(
                "passing verification report contains failed terminal evidence"
            )
        expected_revision = int(operation["expected_revision"])
        old_round = sum(
            event.phase is Phase.VERIFYING and event.revision <= expected_revision
            for event in self.store.events()
        )
        expected_target = (
            Phase.AWAITING_RELEASE_APPROVAL
            if report.verdict == "pass"
            else Phase.DEVELOPING
        )
        if (
            report.round != old_round
            or report.run_id != request.get("run_id")
            or report.verifier_actor != request.get("verifier_actor")
            or report.handoff_nonce_sha256 != request.get("handoff_nonce_sha256")
            or operation["target_phase"] != expected_target.value
        ):
            raise VerificationRecoveryError(
                "completed verification publication differs from receipt"
            )
        terminal_receipt_sha256 = _ordered_terminal_receipt_digests(
            run_directory=self.run_directory,
            round_number=report.round,
            results=report.results,
            request=request,
            subject_digest=subject.digest(),
            expected_revision=expected_revision,
            trusted_root=self.store.trusted_root,
        )
        if (
            list(terminal_receipt_sha256)
            != report_payload.get("terminal_receipt_sha256")
            or list(terminal_receipt_sha256) != operation["terminal_receipt_sha256"]
        ):
            raise VerificationRecoveryError(
                "completed verification terminal receipts differ from publication"
            )
        report_path = Path(str(operation["artifact_path"]))
        expected_report_path = (
            self.run_directory
            / "verifications"
            / f"verification-{report.round:04d}.json"
        )
        if (
            report_path != expected_report_path
            or _private_file_digest(
                report_path,
                trusted_root=self.store.trusted_root,
            )
            != operation["report_file_sha256"]
        ):
            raise VerificationRecoveryError(
                "completed verification report differs from receipt"
            )
        for result in report.results:
            _validate_recovery_log_evidence(
                result,
                self.run_directory / "logs",
                trusted_root=self.store.trusted_root,
            )
        handoff_path = Path(str(operation["handoff_path"]))
        expected_handoff_path = (
            self.run_directory
            / "handoffs"
            / f"{request.get('handoff_nonce_sha256')}.json"
        )
        if handoff_path != expected_handoff_path:
            raise VerificationRecoveryError(
                "completed verification handoff path is invalid"
            )
        handoff, _ = _read_private_verification_json(
            self.run_directory,
            ("handoffs", handoff_path.name),
            label="completed verification handoff",
            trusted_root=self.store.trusted_root,
        )
        normalized_handoff = dict(handoff)
        normalized_handoff["consumed_at"] = None
        normalized_handoff["consumed_by"] = None
        if (
            _canonical_json_digest(normalized_handoff) != operation["handoff_digest"]
            or handoff.get("schema_version") != 1
            or handoff.get("nonce_sha256") != request.get("handoff_nonce_sha256")
            or handoff.get("run_id") != report.run_id
            or handoff.get("role") != "verifier"
            or handoff.get("subject") != subject.to_dict()
            or handoff.get("subject_digest") != subject.digest()
            or handoff.get("consumed_at") != report.recorded_at
            or handoff.get("consumed_by") != report.verifier_actor
        ):
            raise VerificationRecoveryError(
                "completed verification handoff differs from receipt"
            )
        _validate_verification_publication_seal(
            self.run_directory,
            operation,
            trusted_root=self.store.trusted_root,
        )
        _assert_store_root_current(self.store)
        _remove_durable_file(
            _operation_path(self.run_directory),
            trusted_root=self.store.trusted_root,
        )
        _assert_store_root_current(self.store)
        return report

    def _recover_operation(
        self,
        operation: dict[str, object],
        *,
        request: dict[str, object],
        handoff_nonce: str | None,
    ) -> VerificationReport:
        _assert_store_root_current(self.store)
        _validate_verification_publication_seal(
            self.run_directory,
            operation,
            trusted_root=self.store.trusted_root,
        )
        if operation["request"] != request:
            raise VerificationRecoveryError(
                "pending verification belongs to a different request"
            )
        report_payload = operation["report"]
        if not isinstance(report_payload, dict):
            raise VerificationRecoveryError("verification report payload is invalid")
        report = _report_from_payload(report_payload, self.current_subject)
        if (
            report.run_id != request["run_id"]
            or report.verifier_actor != request["verifier_actor"]
            or report.handoff_nonce_sha256 != request["handoff_nonce_sha256"]
        ):
            raise VerificationRecoveryError(
                "verification report belongs to a different request"
            )
        if report.verdict == "pass" and any(
            result.timed_out or result.exit_code != 0 for result in report.results
        ):
            raise VerificationRecoveryError(
                "passing verification report contains failed terminal evidence"
            )
        current_round = sum(
            event.phase is Phase.VERIFYING for event in self.store.events()
        )
        command_digests = request.get("command_digests")
        payload_results = report_payload.get("results")
        if (
            report.round != current_round
            or not isinstance(command_digests, list)
            or not isinstance(payload_results, list)
            or [result.get("command_sha256") for result in payload_results]
            != command_digests[: len(payload_results)]
            or (
                report.verdict == "pass"
                and len(payload_results) != len(command_digests)
            )
            or not payload_results
        ):
            raise VerificationRecoveryError(
                "verification report command evidence is invalid"
            )
        expected_report_path = (
            self.run_directory
            / "verifications"
            / f"verification-{report.round:04d}.json"
        )
        if operation["artifact_path"] != str(expected_report_path):
            raise VerificationRecoveryError("verification report path is invalid")
        expected_target = (
            Phase.AWAITING_RELEASE_APPROVAL
            if report.verdict == "pass"
            else Phase.DEVELOPING
        )
        if operation["target_phase"] != expected_target.value:
            raise VerificationRecoveryError("verification target phase is invalid")
        state = self.store.load()
        expected_revision_value = operation["expected_revision"]
        if type(expected_revision_value) is not int:
            raise VerificationRecoveryError("verification receipt revision is invalid")
        expected_revision = expected_revision_value
        source_state = (
            state.phase is Phase.VERIFYING and state.revision == expected_revision
        )
        target_state = (
            state.phase is expected_target and state.revision == expected_revision + 1
        )
        if not source_state and not target_state:
            raise VerificationRecoveryError("verification state differs from receipt")

        terminal_receipt_sha256 = _ordered_terminal_receipt_digests(
            run_directory=self.run_directory,
            round_number=report.round,
            results=report.results,
            request=request,
            subject_digest=self.current_subject.digest(),
            expected_revision=expected_revision,
            trusted_root=self.store.trusted_root,
        )
        if (
            list(terminal_receipt_sha256)
            != report_payload.get("terminal_receipt_sha256")
            or list(terminal_receipt_sha256) != operation["terminal_receipt_sha256"]
        ):
            raise VerificationRecoveryError(
                "verification terminal receipt digests differ from publication"
            )

        self._assert_pending_release_gate_current(
            operation,
            report=report,
            handoff_nonce=handoff_nonce,
            require_consumed_handoff=False,
        )

        current_report_digest = _private_file_digest(
            expected_report_path,
            trusted_root=self.store.trusted_root,
        )
        if current_report_digest is None:
            _write_immutable_json(
                expected_report_path,
                report_payload,
                trusted_root=self.store.trusted_root,
            )
        elif current_report_digest != operation["report_file_sha256"]:
            raise VerificationRecoveryError(
                "existing verification report differs from receipt"
            )
        for result in report.results:
            _validate_recovery_log_evidence(
                result,
                self.run_directory / "logs",
                trusted_root=self.store.trusted_root,
            )
        if (
            _OPERATION_STAGES[str(operation["stage"])]
            < _OPERATION_STAGES["report-written"]
        ):
            operation = _write_verification_operation_stage(
                self.run_directory,
                operation,
                stage="report-written",
                trusted_root=self.store.trusted_root,
            )

        handoff_path, handoff = self._load_publication_handoff(
            operation,
            handoff_nonce,
        )
        if (
            operation["handoff_path"] != str(handoff_path)
            or handoff.get("role") != "verifier"
            or handoff.get("subject") != self.current_subject.to_dict()
            or handoff.get("subject_digest") != self.current_subject.digest()
        ):
            raise VerificationRecoveryError("verification handoff differs from receipt")
        if handoff.get("consumed_at") is None and handoff.get("consumed_by") is None:
            consumed_handoff = dict(handoff)
            consumed_handoff["consumed_at"] = report.recorded_at
            consumed_handoff["consumed_by"] = report.verifier_actor
            _write_canonical_json(
                handoff_path,
                consumed_handoff,
                trusted_root=self.store.trusted_root,
            )
        elif (
            handoff.get("consumed_at") != report.recorded_at
            or handoff.get("consumed_by") != report.verifier_actor
        ):
            raise VerificationRecoveryError(
                "verification handoff was consumed by another request"
            )
        if (
            _OPERATION_STAGES[str(operation["stage"])]
            < _OPERATION_STAGES["handoff-consumed"]
        ):
            operation = _write_verification_operation_stage(
                self.run_directory,
                operation,
                stage="handoff-consumed",
                trusted_root=self.store.trusted_root,
            )

        self._assert_pending_release_gate_current(
            operation,
            report=report,
            handoff_nonce=handoff_nonce,
            require_consumed_handoff=True,
        )
        if terminal_receipt_sha256 != _ordered_terminal_receipt_digests(
            run_directory=self.run_directory,
            round_number=report.round,
            results=report.results,
            request=request,
            subject_digest=self.current_subject.digest(),
            expected_revision=expected_revision,
            trusted_root=self.store.trusted_root,
        ):
            raise VerificationRecoveryError(
                "verification terminal receipts changed before transition"
            )
        _validate_verification_publication_seal(
            self.run_directory,
            operation,
            trusted_root=self.store.trusted_root,
        )

        state = self.store.load()
        source_state = (
            state.phase is Phase.VERIFYING and state.revision == expected_revision
        )
        target_state = (
            state.phase is expected_target and state.revision == expected_revision + 1
        )
        _assert_store_root_current(self.store)
        if source_state:
            self.store.transition(expected_target, expected_revision=expected_revision)
        elif not target_state:
            raise VerificationRecoveryError("verification transition is invalid")
        _assert_store_root_current(self.store)
        if (
            _OPERATION_STAGES[str(operation["stage"])]
            < _OPERATION_STAGES["state-transitioned"]
        ):
            _write_verification_operation_stage(
                self.run_directory,
                operation,
                stage="state-transitioned",
                trusted_root=self.store.trusted_root,
            )
        _remove_durable_file(
            _operation_path(self.run_directory),
            trusted_root=self.store.trusted_root,
        )
        _assert_store_root_current(self.store)
        return report

    def resume_publication(self) -> VerificationReport:
        """Finish a sealed verification publication after a process restart."""

        lock = FileLock(
            self.run_directory / "verification.lock",
            private_root=self.run_directory,
        )
        with lock as acquired_lock, self.store.anchored(acquired_lock.trusted_parent):
            try:
                validate_recoverable_verification_publication(
                    self.store,
                    manifest=self.manifest,
                    current_subject=self.current_subject,
                    variables=self.variables,
                )
                _assert_store_root_current(self.store)
                operation = _load_operation(
                    self.run_directory,
                    trusted_root=self.store.trusted_root,
                )
                if operation is None:  # pragma: no cover - lock makes this defensive
                    raise VerificationEvidenceMissingError(
                        "verification publication receipt is missing"
                    )
                request = operation.get("request")
                if not isinstance(request, dict):
                    raise VerificationRecoveryError(
                        "verification publication request is invalid"
                    )
                return self._recover_operation(
                    operation,
                    request=request,
                    handoff_nonce=None,
                )
            except VerificationRecoveryError as error:
                raise self._block_recovery(str(error)) from error

    def verify(
        self,
        run_id: str,
        verifier_actor: str,
        handoff_nonce: str,
        sensitive_values: Sequence[str],
    ) -> VerificationReport:
        lock = FileLock(
            self.run_directory / "verification.lock",
            private_root=self.run_directory,
        )
        with lock as acquired_lock, self.store.anchored(acquired_lock.trusted_parent):
            return self._verify_locked(
                run_id,
                verifier_actor,
                handoff_nonce,
                sensitive_values,
            )

    def _verify_locked(
        self,
        run_id: str,
        verifier_actor: str,
        handoff_nonce: str,
        sensitive_values: Sequence[str],
    ) -> VerificationReport:
        _assert_store_root_current(self.store)
        if not isinstance(verifier_actor, str) or not verifier_actor.strip():
            raise VerificationError("verifier actor must be a non-empty string")
        if not isinstance(handoff_nonce, str) or not handoff_nonce:
            raise VerificationError("verifier handoff nonce must be non-empty")
        if type(self.manifest) is not Manifest:
            raise VerificationError("manifest is not confirmed")
        nonce_sha256 = hashlib.sha256(handoff_nonce.encode("utf-8")).hexdigest()
        request = _request_payload(
            run_id=run_id,
            verifier_actor=verifier_actor,
            subject=self.current_subject,
            handoff_nonce_sha256=nonce_sha256,
            manifest=self.manifest,
            variables=self.variables,
            sensitive_values=sensitive_values,
        )
        try:
            pending = _load_operation(
                self.run_directory,
                trusted_root=self.store.trusted_root,
            )
            if pending is not None:
                _ensure_verification_publication_seal(
                    self.run_directory,
                    pending,
                    trusted_root=self.store.trusted_root,
                )
                if pending[
                    "request"
                ] != request and self._publication_transition_is_in_wal(pending):
                    self._reconcile_completed_operation(pending)
                    pending = None
            if pending is not None:
                return self._recover_operation(
                    pending,
                    request=request,
                    handoff_nonce=handoff_nonce,
                )
        except VerificationRecoveryError as error:
            raise self._block_recovery(str(error)) from error

        state = self.store.load()
        verification_events = tuple(
            event for event in self.store.events() if event.phase is Phase.VERIFYING
        )
        round_number = len(verification_events)
        try:
            publication_names = _private_directory_names(
                self.run_directory / "verification-publications",
                trusted_root=self.store.trusted_root,
            )
        except StateNotFoundError:
            publication_names = ()
        except (OSError, StateCorruptionError) as error:
            raise self._block_recovery(
                "verification publication directory is unsafe"
            ) from error
        current_round_seals = tuple(
            name
            for name in publication_names
            if re.fullmatch(
                rf"verification-{round_number:04d}-[0-9a-f]{{64}}\.json",
                name,
            )
        )
        if pending is None and state.phase is Phase.VERIFYING and current_round_seals:
            raise self._block_recovery(
                "orphan verification publication seal requires manual reconciliation"
            )
        request_digest = _canonical_json_digest(request)
        if verification_events:
            expected_execution_revision = verification_events[-1].revision
            try:
                command_digests = request["command_digests"]
                if not isinstance(command_digests, list):
                    raise VerificationRecoveryError(
                        "verification command digests are invalid"
                    )
                for index, command_sha256 in enumerate(command_digests, start=1):
                    receipt_path = _execution_receipt_path(
                        self.run_directory,
                        round_number=round_number,
                        index=index,
                    )
                    receipt = _load_execution_receipt(
                        receipt_path,
                        trusted_root=self.store.trusted_root,
                    )
                    if receipt is None:
                        continue
                    _validate_execution_receipt_binding(
                        receipt,
                        run_id=run_id,
                        round_number=round_number,
                        index=index,
                        request_digest=request_digest,
                        subject_digest=self.current_subject.digest(),
                        command_sha256=str(command_sha256),
                        expected_revision=expected_execution_revision,
                    )
                    if receipt["status"] == "RUNNING":
                        receipt = _write_execution_receipt_stage(
                            receipt_path,
                            receipt,
                            status="UNKNOWN",
                            trusted_root=self.store.trusted_root,
                        )
                    if receipt["status"] == "UNKNOWN":
                        raise VerificationRecoveryError(
                            "verification execution is UNKNOWN and requires "
                            "manual reconciliation"
                        )
            except VerificationRecoveryError as error:
                raise self._block_recovery(str(error)) from error
        if state.phase is not Phase.VERIFYING:
            raise VerificationError("verification requires VERIFYING")
        if run_id != state.run_id or run_id != self.current_subject.run_id:
            raise VerificationError("verification evidence belongs to another run")
        if not self.manifest.verification_steps:
            self.store.transition(Phase.BLOCKED, expected_revision=state.revision)
            raise VerificationError("manifest has no confirmed verification commands")
        if manifest_digest(self.manifest) != self.current_subject.manifest_sha256:
            raise VerificationError("confirmed manifest is stale")
        if (
            verification_commands_digest(self.manifest, self.variables)
            != self.current_subject.commands_sha256
        ):
            self.store.transition(Phase.BLOCKED, expected_revision=state.revision)
            raise VerificationError("confirmed verification commands are stale")
        if round_number > self.manifest.max_verification_rounds:
            self.store.transition(Phase.BLOCKED, expected_revision=state.revision)
            raise VerificationError("verification round limit was reached")
        round_report_path = (
            self.run_directory
            / "verifications"
            / f"verification-{round_number:04d}.json"
        )
        try:
            round_report_exists = (
                _private_file_digest(
                    round_report_path,
                    trusted_root=self.store.trusted_root,
                )
                is not None
            )
        except VerificationRecoveryError as error:
            raise self._block_recovery(str(error)) from error
        if round_report_exists:
            self.store.transition(Phase.BLOCKED, expected_revision=state.revision)
            raise VerificationRecoveryError(
                "foreign verification report exists for the current round"
            )

        review, review_handoff = _load_code_review(
            self.store,
            self.current_subject,
        )
        try:
            handoff_path, handoff = _load_handoff(self.store, handoff_nonce)
        except RuntimeError as error:
            raise VerificationError("verifier handoff is invalid") from error
        if handoff.get("role") != "verifier":
            raise VerificationError("handoff nonce has the wrong verifier role")
        if (
            handoff.get("run_id") != run_id
            or handoff.get("subject") != self.current_subject.to_dict()
            or handoff.get("subject_digest") != self.current_subject.digest()
        ):
            raise VerificationError("verifier handoff evidence subject is stale")
        if (
            handoff.get("consumed_at") is not None
            or handoff.get("consumed_by") is not None
        ):
            raise VerificationError("verifier handoff nonce was already consumed")
        separated_actors = {
            handoff.get("source_actor"),
            review.get("reviewer_actor"),
            review_handoff.get("source_actor"),
        }
        if verifier_actor in separated_actors:
            raise VerificationError(
                "verifier actor must differ from developer and reviewer"
            )
        if not _candidate_is_current(self.repo, self.current_subject):
            self.store.transition(
                Phase.DEVELOPING,
                expected_revision=state.revision,
            )
            raise VerificationError("verification candidate must be current and clean")

        results: list[VerificationCommandResult] = []
        verdict = "pass"
        for index, spec in enumerate(self.manifest.verification_steps, start=1):
            if type(spec) is not CommandSpec:
                raise VerificationError("manifest verification command is invalid")
            resolved_argv = _resolved_argv(spec.argv, self.variables)
            command_sha256 = _command_digest(spec, resolved_argv)
            receipt_path = _execution_receipt_path(
                self.run_directory,
                round_number=round_number,
                index=index,
            )
            try:
                receipt = _load_execution_receipt(
                    receipt_path,
                    trusted_root=self.store.trusted_root,
                )
                if receipt is not None:
                    _validate_execution_receipt_binding(
                        receipt,
                        run_id=run_id,
                        round_number=round_number,
                        index=index,
                        request_digest=request_digest,
                        subject_digest=self.current_subject.digest(),
                        command_sha256=command_sha256,
                        expected_revision=state.revision,
                    )
            except VerificationRecoveryError as error:
                raise self._block_recovery(str(error)) from error

            if receipt is not None and receipt["status"] in {
                "SUCCEEDED",
                "FAILED",
            }:
                try:
                    command_result = _command_result_from_payload(
                        receipt["result"],
                        expected_index=index,
                    )
                    _validate_recovery_log_evidence(
                        command_result,
                        self.run_directory / "logs",
                        trusted_root=self.store.trusted_root,
                    )
                except VerificationError as error:
                    raise self._block_recovery(str(error)) from error
            else:
                try:
                    self._assert_subject_evidence_stable(
                        expected_review=review,
                        expected_review_handoff=review_handoff,
                        handoff_nonce=handoff_nonce,
                        expected_handoff_path=handoff_path,
                        expected_handoff=handoff,
                    )
                except VerificationError:
                    self.store.transition(
                        Phase.BLOCKED,
                        expected_revision=state.revision,
                    )
                    raise
                if not _candidate_is_current(self.repo, self.current_subject):
                    self.store.transition(
                        Phase.DEVELOPING,
                        expected_revision=state.revision,
                    )
                    raise VerificationError(
                        "verification candidate changed before command"
                    )
                if receipt is None:
                    receipt = {
                        "schema_version": 1,
                        "run_id": run_id,
                        "round": round_number,
                        "index": index,
                        "status": "PREPARED",
                        "request_digest": request_digest,
                        "subject_digest": self.current_subject.digest(),
                        "command_sha256": command_sha256,
                        "expected_revision": state.revision,
                        "prepared_at": "",
                        "started_at": None,
                        "finished_at": None,
                        "result": None,
                    }
                    receipt = _write_execution_receipt_stage(
                        receipt_path,
                        receipt,
                        status="PREPARED",
                        trusted_root=self.store.trusted_root,
                    )
                if receipt["status"] != "PREPARED":
                    raise self._block_recovery(
                        "verification execution is UNKNOWN and requires "
                        "manual reconciliation"
                    )
                receipt = _write_execution_receipt_stage(
                    receipt_path,
                    receipt,
                    status="RUNNING",
                    trusted_root=self.store.trusted_root,
                )
                started = time.monotonic()
                try:
                    _assert_store_root_current(self.store)
                    result = self.runner.run(
                        spec,
                        self.variables,
                        self.repo,
                        self.run_directory / "logs",
                        sensitive_values,
                    )
                except BaseException as error:
                    try:
                        _write_execution_receipt_stage(
                            receipt_path,
                            receipt,
                            status="UNKNOWN",
                            trusted_root=self.store.trusted_root,
                        )
                    except BaseException:
                        pass
                    raise self._block_recovery(
                        "verification execution is UNKNOWN and requires "
                        "manual reconciliation"
                    ) from error
                ended_at = _utc_now()
                try:
                    _assert_store_root_current(self.store)
                    command_result = VerificationCommandResult(
                        index=index,
                        command_sha256=command_sha256,
                        started_at=str(receipt["started_at"]),
                        ended_at=ended_at,
                        duration_seconds=max(0.0, time.monotonic() - started),
                        exit_code=result.exit_code,
                        timed_out=result.timed_out,
                        truncated=result.truncated,
                        log_sha256=result.log_sha256,
                        log_size=result.log_size,
                        log_path=result.log_path,
                    )
                    _validate_log_evidence(
                        command_result,
                        self.run_directory / "logs",
                        trusted_root=self.store.trusted_root,
                    )
                except BaseException:
                    try:
                        _write_execution_receipt_stage(
                            receipt_path,
                            receipt,
                            status="UNKNOWN",
                            trusted_root=self.store.trusted_root,
                        )
                    except BaseException:
                        pass
                    current_state = self.store.load()
                    if current_state.phase is Phase.VERIFYING:
                        self.store.transition(
                            Phase.BLOCKED,
                            expected_revision=current_state.revision,
                        )
                    raise
                terminal_status = (
                    "SUCCEEDED"
                    if not command_result.timed_out and command_result.exit_code == 0
                    else "FAILED"
                )
                _write_execution_receipt_stage(
                    receipt_path,
                    receipt,
                    status=terminal_status,
                    trusted_root=self.store.trusted_root,
                    result=_command_result_payload(command_result),
                )

            try:
                self._assert_subject_evidence_stable(
                    expected_review=review,
                    expected_review_handoff=review_handoff,
                    handoff_nonce=handoff_nonce,
                    expected_handoff_path=handoff_path,
                    expected_handoff=handoff,
                )
            except VerificationError:
                self.store.transition(Phase.BLOCKED, expected_revision=state.revision)
                raise
            results.append(command_result)
            if not _candidate_is_current(self.repo, self.current_subject):
                verdict = "fail"
                break
            if command_result.timed_out or command_result.exit_code != 0:
                verdict = "fail"
                break

        _assert_store_root_current(self.store)
        recorded_at = _utc_now()
        report = VerificationReport(
            run_id=run_id,
            round=round_number,
            verifier_actor=verifier_actor,
            subject=self.current_subject,
            handoff_nonce_sha256=nonce_sha256,
            verdict=verdict,
            results=tuple(results),
            recorded_at=recorded_at,
        )
        terminal_receipt_sha256 = _ordered_terminal_receipt_digests(
            run_directory=self.run_directory,
            round_number=round_number,
            results=report.results,
            request=request,
            subject_digest=self.current_subject.digest(),
            expected_revision=state.revision,
            trusted_root=self.store.trusted_root,
        )
        report_path = (
            self.run_directory
            / "verifications"
            / f"verification-{round_number:04d}.json"
        )
        report_payload = _verification_report_payload(
            report=report,
            terminal_receipt_sha256=terminal_receipt_sha256,
        )
        target_phase = (
            Phase.AWAITING_RELEASE_APPROVAL if verdict == "pass" else Phase.DEVELOPING
        )
        report_file_sha256 = hashlib.sha256(
            _canonical_json_bytes(report_payload) + b"\n"
        ).hexdigest()
        operation: dict[str, object] = {
            "schema_version": 1,
            "stage": "prepared",
            "request": request,
            "request_digest": _canonical_json_digest(request),
            "report": report_payload,
            "report_digest": _canonical_json_digest(report_payload),
            "report_file_sha256": report_file_sha256,
            "artifact_path": str(report_path),
            "handoff_path": str(handoff_path),
            "handoff_digest": _canonical_json_digest(handoff),
            "terminal_receipt_sha256": list(terminal_receipt_sha256),
            "expected_revision": state.revision,
            "target_phase": target_phase.value,
        }
        operation = _prepare_verification_operation(operation)
        _write_canonical_json(
            _operation_path(self.run_directory),
            operation,
            trusted_root=self.store.trusted_root,
        )
        _ensure_verification_publication_seal(
            self.run_directory,
            operation,
            trusted_root=self.store.trusted_root,
        )
        try:
            return self._recover_operation(
                operation,
                request=request,
                handoff_nonce=handoff_nonce,
            )
        except VerificationRecoveryError as error:
            raise self._block_recovery(str(error)) from error
