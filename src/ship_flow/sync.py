from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping

from .model import Phase
from .store import FileLock, PrivateRootAnchor, StateStore
from .subject import EvidenceSubject


class SyncError(RuntimeError):
    pass


class SyncRecoveryError(SyncError):
    pass


_CATEGORIES = ("code", "docs", "rules", "project_knowledge")
_CATEGORY_SET = frozenset(_CATEGORIES)
_STATUSES = frozenset({"current", "not_applicable", "changes_required"})
_ITEM_KEYS = frozenset({"category", "status", "paths"})
_DRAFT_KEYS = frozenset({"reporter", "items"})
_REPORT_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "reporter",
        "subject",
        "subject_digest",
        "items",
        "sync_gate_revision",
        "sync_round",
        "recorded_at",
    }
)


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _is_canonical_utc(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") == value


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


def _file_bytes_digest(payload: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(payload) + b"\n").hexdigest()


_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "reporter",
        "subject",
        "subject_digest",
        "items",
        "sync_gate_revision",
        "sync_round",
    }
)
_OPERATION_KEYS = frozenset(
    {
        "schema_version",
        "stage",
        "request",
        "request_digest",
        "report",
        "report_digest",
        "report_file_sha256",
        "previous_report_file_sha256",
        "expected_revision",
        "source_phase",
        "target_phase",
        "artifact_path",
        "publication_sha256",
    }
)
_OPERATION_STAGES = {"prepared": 0, "report-written": 1, "state-transitioned": 2}
_LOWER_HEX = frozenset("0123456789abcdef")


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _LOWER_HEX for character in value)
    )


def _publication_payload(operation: Mapping[str, object]) -> dict[str, object]:
    return {key: value for key, value in operation.items() if key != "stage"}


def _publication_commitment(operation: Mapping[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in operation.items()
        if key not in {"stage", "publication_sha256"}
    }


def _seal_path(store: StateStore, operation: Mapping[str, object]) -> Path:
    request = operation.get("request")
    if not isinstance(request, Mapping):
        raise SyncRecoveryError("sync publication request is invalid")
    subject_digest = request.get("subject_digest")
    request_digest = operation.get("request_digest")
    gate_revision = request.get("sync_gate_revision")
    if (
        not _is_sha256(subject_digest)
        or not _is_sha256(request_digest)
        or type(gate_revision) is not int
        or gate_revision < 0
    ):
        raise SyncRecoveryError("sync publication identity is invalid")
    return (
        store.run_directory
        / "sync-publications"
        / f"sync-{subject_digest}-gate-{gate_revision:08d}-{request_digest}.json"
    )


_MAX_SYNC_EVIDENCE_BYTES = 4 * 1024 * 1024
_DIRECTORY_FLAGS = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)


def _validate_private_directory_fd(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SyncRecoveryError("sync evidence directory is not private")


def _open_run_directory(
    store: StateStore,
    *,
    trusted_boundary: Path,
) -> int:
    """Open a run below a caller-verified Git common directory.

    The trusted boundary itself is opened once.  Every runtime component below it
    is then traversed relative to a directory descriptor with ``O_NOFOLLOW``.
    No path derived from ``store`` is opened until its lexical location and exact
    ``ship-flow/runs/<run-id>`` shape have been checked.
    """

    run_directory = Path(os.path.abspath(store.run_directory))
    boundary = Path(os.path.abspath(trusted_boundary))
    try:
        relative = run_directory.relative_to(boundary)
    except ValueError as error:
        raise SyncRecoveryError(
            "sync run directory escapes its trusted repository boundary"
        ) from error
    if (
        len(relative.parts) != 3
        or relative.parts[:2] != ("ship-flow", "runs")
        or relative.parts[2] in {"", ".", ".."}
    ):
        raise SyncRecoveryError("sync run directory layout is invalid")
    trusted_root = store.trusted_root
    if isinstance(trusted_root, PrivateRootAnchor):
        if Path(os.path.abspath(trusted_root.path)) != run_directory:
            raise SyncRecoveryError("sync run anchor identifies another directory")
        descriptor = os.dup(trusted_root.descriptor)
        try:
            _validate_private_directory_fd(descriptor)
            current = os.stat(run_directory, follow_symlinks=False)
            anchored = os.fstat(descriptor)
            if not stat.S_ISDIR(current.st_mode) or (
                current.st_dev,
                current.st_ino,
            ) != (anchored.st_dev, anchored.st_ino):
                raise SyncRecoveryError("sync run directory changed during publication")
        except OSError as error:
            os.close(descriptor)
            raise SyncRecoveryError(
                "sync run directory changed during publication"
            ) from error
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor
    descriptor = -1
    try:
        descriptor = os.open(boundary, _DIRECTORY_FLAGS)
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise SyncRecoveryError("trusted Git boundary is not a directory")
        for component in relative.parts:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                _validate_private_directory_fd(child)
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except SyncRecoveryError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise SyncRecoveryError("sync run directory cannot be opened safely") from error


def _open_private_subdirectory(
    parent_descriptor: int,
    name: str,
    *,
    missing_ok: bool,
) -> int | None:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise SyncRecoveryError("sync evidence directory name is unsafe")
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_descriptor)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise SyncRecoveryError(f"sync evidence directory is missing: {name}") from None
    except OSError as error:
        raise SyncRecoveryError(
            f"sync evidence directory cannot be opened safely: {name}"
        ) from error
    try:
        _validate_private_directory_fd(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _safe_evidence_name(name: str) -> None:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise SyncRecoveryError("sync evidence filename is unsafe")


def _write_json_at(
    directory_descriptor: int,
    name: str,
    payload: Mapping[str, object],
    *,
    immutable: bool,
) -> None:
    """Publish canonical JSON relative to one already-verified directory FD."""

    _safe_evidence_name(name)
    raw = _canonical_json_bytes(payload) + b"\n"
    if len(raw) > _MAX_SYNC_EVIDENCE_BYTES:
        raise SyncRecoveryError("sync evidence is too large to publish")
    temporary_name = f".{name}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    temporary_exists = False
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        temporary_exists = True
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("short write while publishing sync evidence")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if immutable:
            try:
                os.link(
                    temporary_name,
                    name,
                    src_dir_fd=directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise SyncRecoveryError(
                    "sync publication seal already exists"
                ) from error
            os.unlink(temporary_name, dir_fd=directory_descriptor)
            temporary_exists = False
        else:
            os.replace(
                temporary_name,
                name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            temporary_exists = False
        os.fsync(directory_descriptor)
    except SyncRecoveryError:
        raise
    except OSError as error:
        raise SyncRecoveryError("sync evidence cannot be written safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_exists:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
            except OSError as error:
                raise SyncRecoveryError(
                    "temporary sync evidence cannot be removed safely"
                ) from error


def _write_run_json(
    store: StateStore,
    name: str,
    payload: Mapping[str, object],
    *,
    trusted_boundary: Path,
) -> None:
    descriptor = _open_run_directory(store, trusted_boundary=trusted_boundary)
    try:
        _write_json_at(descriptor, name, payload, immutable=False)
    finally:
        os.close(descriptor)


def _write_publication_json(
    store: StateStore,
    name: str,
    payload: Mapping[str, object],
    *,
    trusted_boundary: Path,
) -> None:
    run_descriptor = _open_run_directory(store, trusted_boundary=trusted_boundary)
    publication_descriptor: int | None = None
    created = False
    try:
        publication_descriptor = _open_private_subdirectory(
            run_descriptor,
            "sync-publications",
            missing_ok=True,
        )
        if publication_descriptor is None:
            try:
                os.mkdir("sync-publications", 0o700, dir_fd=run_descriptor)
                created = True
            except FileExistsError:
                pass
            try:
                publication_descriptor = os.open(
                    "sync-publications",
                    _DIRECTORY_FLAGS,
                    dir_fd=run_descriptor,
                )
            except OSError as error:
                raise SyncRecoveryError(
                    "sync publication directory cannot be opened safely"
                ) from error
            if created:
                os.fchmod(publication_descriptor, 0o700)
                os.fsync(publication_descriptor)
                os.fsync(run_descriptor)
            _validate_private_directory_fd(publication_descriptor)
        _write_json_at(publication_descriptor, name, payload, immutable=True)
    except SyncRecoveryError:
        raise
    except OSError as error:
        raise SyncRecoveryError(
            "sync publication directory cannot be created safely"
        ) from error
    finally:
        if publication_descriptor is not None:
            os.close(publication_descriptor)
        os.close(run_descriptor)


def _unlink_run_file(
    store: StateStore,
    name: str,
    *,
    trusted_boundary: Path,
) -> None:
    _safe_evidence_name(name)
    descriptor = _open_run_directory(store, trusted_boundary=trusted_boundary)
    try:
        os.unlink(name, dir_fd=descriptor)
        os.fsync(descriptor)
    except FileNotFoundError as error:
        raise SyncRecoveryError(f"sync evidence is missing: {name}") from error
    except OSError as error:
        raise SyncRecoveryError("sync evidence cannot be removed safely") from error
    finally:
        os.close(descriptor)


def _read_private_json_at(
    directory_descriptor: int,
    name: str,
    *,
    missing_ok: bool,
) -> dict[str, object] | None:
    _safe_evidence_name(name)
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=directory_descriptor)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise SyncRecoveryError(f"sync evidence is missing: {name}") from None
    except OSError as error:
        raise SyncRecoveryError(
            f"sync evidence cannot be opened safely: {name}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > _MAX_SYNC_EVIDENCE_BYTES
        ):
            raise SyncRecoveryError(
                f"sync evidence is not a bounded private file: {name}"
            )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(
                descriptor, min(65_536, _MAX_SYNC_EVIDENCE_BYTES + 1 - size)
            )
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _MAX_SYNC_EVIDENCE_BYTES:
                raise SyncRecoveryError(f"sync evidence is too large: {name}")
        raw = b"".join(chunks)
        payload = json.loads(raw.decode("utf-8"))
        after_read = os.fstat(descriptor)
        current = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        identity_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(metadata, field) != getattr(after_read, field)
            or getattr(metadata, field) != getattr(current, field)
            for field in identity_fields
        ):
            raise SyncRecoveryError(f"sync evidence changed while loading: {name}")
    except SyncRecoveryError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SyncRecoveryError(f"sync evidence is corrupt: {name}") from error
    finally:
        os.close(descriptor)
    try:
        canonical = _canonical_json_bytes(payload) + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise SyncRecoveryError(f"sync evidence is not canonical: {name}") from error
    if not isinstance(payload, dict) or raw != canonical:
        raise SyncRecoveryError(f"sync evidence is not canonical: {name}")
    return payload


def _read_run_private_json(
    store: StateStore,
    name: str,
    *,
    trusted_boundary: Path,
    missing_ok: bool = False,
) -> dict[str, object] | None:
    run_descriptor = _open_run_directory(
        store,
        trusted_boundary=trusted_boundary,
    )
    try:
        return _read_private_json_at(
            run_descriptor,
            name,
            missing_ok=missing_ok,
        )
    finally:
        os.close(run_descriptor)


def _read_publication_set(
    store: StateStore,
    *,
    subject_digest: str,
    gate_revision: int,
    trusted_boundary: Path,
    missing_ok: bool,
) -> dict[str, dict[str, object]]:
    if not _is_sha256(subject_digest):
        raise SyncRecoveryError("sync subject digest is invalid")
    if type(gate_revision) is not int or gate_revision < 0:
        raise SyncRecoveryError("sync gate revision is invalid")
    run_descriptor = _open_run_directory(
        store,
        trusted_boundary=trusted_boundary,
    )
    publication_descriptor: int | None = None
    try:
        publication_descriptor = _open_private_subdirectory(
            run_descriptor,
            "sync-publications",
            missing_ok=missing_ok,
        )
        if publication_descriptor is None:
            return {}
        gate_pattern = re.compile(
            rf"sync-[0-9a-f]{{64}}-gate-{gate_revision:08d}-[0-9a-f]{{64}}\.json"
        )
        names = tuple(
            sorted(
                name
                for name in os.listdir(publication_descriptor)
                if gate_pattern.fullmatch(name) is not None
            )
        )
        return {
            name: _read_private_json_at(
                publication_descriptor,
                name,
                missing_ok=False,
            )
            for name in names
        }
    except OSError as error:
        raise SyncRecoveryError(
            "sync publication directory cannot be listed safely"
        ) from error
    finally:
        if publication_descriptor is not None:
            os.close(publication_descriptor)
        os.close(run_descriptor)


def _validate_operation(
    operation: Mapping[str, object], store: StateStore
) -> dict[str, object]:
    if set(operation) != _OPERATION_KEYS:
        raise SyncRecoveryError("sync publication receipt schema is invalid")
    request = operation["request"]
    report = operation["report"]
    if (
        type(operation["schema_version"]) is not int
        or operation["schema_version"] != 1
        or not isinstance(operation["stage"], str)
        or operation["stage"] not in _OPERATION_STAGES
        or not isinstance(request, Mapping)
        or set(request) != _REQUEST_KEYS
        or not isinstance(report, Mapping)
        or operation["request_digest"] != _canonical_json_digest(request)
        or operation["report_digest"] != _canonical_json_digest(report)
        or operation["report_file_sha256"] != _file_bytes_digest(report)
        or (
            operation["previous_report_file_sha256"] is not None
            and (not _is_sha256(operation["previous_report_file_sha256"]))
        )
        or type(operation["expected_revision"]) is not int
        or operation["expected_revision"] < 0
        or operation["source_phase"] != Phase.SYNCING.value
        or operation["target_phase"]
        not in {Phase.DEVELOPING.value, Phase.AWAITING_CLEANUP_APPROVAL.value}
        or operation["artifact_path"] != str(store.run_directory / "sync-report.json")
        or operation["publication_sha256"]
        != _canonical_json_digest(_publication_commitment(operation))
    ):
        raise SyncRecoveryError("sync publication receipt is invalid")
    try:
        parsed_report = SyncReport.from_dict(report)
    except SyncError as error:
        raise SyncRecoveryError("sync publication report is invalid") from error
    if (
        type(request["schema_version"]) is not int
        or request["schema_version"] != 1
        or type(request["sync_gate_revision"]) is not int
        or request["sync_gate_revision"] < 0
        or type(request["sync_round"]) is not int
        or request["sync_round"] < 1
        or request["run_id"] != parsed_report.run_id
        or request["reporter"] != parsed_report.reporter
        or request["subject"] != parsed_report.subject.to_dict()
        or request["subject_digest"] != parsed_report.subject_digest
        or request["items"] != [item.to_dict() for item in parsed_report.items]
        or request["sync_gate_revision"] != parsed_report.sync_gate_revision
        or request["sync_round"] != parsed_report.sync_round
        or operation["expected_revision"] != parsed_report.sync_gate_revision
    ):
        raise SyncRecoveryError("sync publication request and report differ")
    expected_target = (
        Phase.DEVELOPING.value
        if any(item.status == "changes_required" for item in parsed_report.items)
        else Phase.AWAITING_CLEANUP_APPROVAL.value
    )
    if operation["target_phase"] != expected_target:
        raise SyncRecoveryError("sync publication target is invalid")
    return dict(operation)


def _load_operation(
    store: StateStore,
    *,
    trusted_boundary: Path,
) -> dict[str, object] | None:
    payload = _read_run_private_json(
        store,
        "sync-operation.json",
        trusted_boundary=trusted_boundary,
        missing_ok=True,
    )
    return None if payload is None else _validate_operation(payload, store)


def _validate_publication_seal(
    store: StateStore,
    operation: Mapping[str, object],
    *,
    trusted_boundary: Path,
) -> None:
    expected_path = _seal_path(store, operation)
    request = operation["request"]
    assert isinstance(request, Mapping)
    subject_digest = str(request["subject_digest"])
    gate_revision = request["sync_gate_revision"]
    if type(gate_revision) is not int:
        raise SyncRecoveryError("sync gate revision is invalid")
    publications = _read_publication_set(
        store,
        subject_digest=subject_digest,
        gate_revision=gate_revision,
        trusted_boundary=trusted_boundary,
        missing_ok=False,
    )
    if set(publications) != {expected_path.name}:
        raise SyncRecoveryError(
            "sync gate has a missing or different publication commitment"
        )
    if publications[expected_path.name] != _publication_payload(operation):
        raise SyncRecoveryError("sync publication differs from immutable seal")


def _ensure_publication_seal(
    store: StateStore,
    operation: Mapping[str, object],
    *,
    trusted_boundary: Path,
) -> None:
    expected_path = _seal_path(store, operation)
    request = operation["request"]
    assert isinstance(request, Mapping)
    subject_digest = str(request["subject_digest"])
    gate_revision = request["sync_gate_revision"]
    if type(gate_revision) is not int:
        raise SyncRecoveryError("sync gate revision is invalid")
    publications = _read_publication_set(
        store,
        subject_digest=subject_digest,
        gate_revision=gate_revision,
        trusted_boundary=trusted_boundary,
        missing_ok=True,
    )
    if not publications:
        _write_publication_json(
            store,
            expected_path.name,
            _publication_payload(operation),
            trusted_boundary=trusted_boundary,
        )
    _validate_publication_seal(
        store,
        operation,
        trusted_boundary=trusted_boundary,
    )


def _write_operation_stage(
    store: StateStore,
    operation: Mapping[str, object],
    stage: str,
    *,
    trusted_boundary: Path,
) -> dict[str, object]:
    changed = dict(operation)
    changed["stage"] = stage
    _write_run_json(
        store,
        "sync-operation.json",
        changed,
        trusted_boundary=trusted_boundary,
    )
    return changed


@dataclass(frozen=True)
class SyncItem:
    category: str
    status: str
    paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.category not in _CATEGORY_SET:
            raise SyncError("sync item category is invalid")
        if self.status not in _STATUSES:
            raise SyncError("sync item status is invalid")
        if type(self.paths) is not tuple or any(
            not isinstance(path, str) or not path for path in self.paths
        ):
            raise SyncError("sync item paths must be non-empty strings")
        if len(set(self.paths)) != len(self.paths):
            raise SyncError("sync item paths must not repeat")
        if self.category == "code" and self.status == "not_applicable":
            raise SyncError("code cannot be not_applicable")
        if self.status == "not_applicable" and self.paths:
            raise SyncError("not_applicable items cannot name paths")
        if self.status != "not_applicable" and not self.paths:
            raise SyncError("current and changes_required items must name paths")

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "status": self.status,
            "paths": list(self.paths),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> SyncItem:
        if not isinstance(value, Mapping) or set(value) != _ITEM_KEYS:
            raise SyncError("sync item schema is invalid")
        paths = value["paths"]
        if not isinstance(paths, list):
            raise SyncError("sync item paths must be an array")
        return cls(
            category=value["category"],  # type: ignore[arg-type]
            status=value["status"],  # type: ignore[arg-type]
            paths=tuple(paths),  # type: ignore[arg-type]
        )


@dataclass(frozen=True)
class SyncReportDraft:
    reporter: str
    items: tuple[SyncItem, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.reporter, str) or not self.reporter.strip():
            raise SyncError("sync reporter must be a non-empty string")
        if type(self.items) is not tuple or any(
            type(item) is not SyncItem for item in self.items
        ):
            raise SyncError("sync report items must be SyncItem values")
        categories = tuple(item.category for item in self.items)
        if len(categories) != len(_CATEGORIES) or set(categories) != _CATEGORY_SET:
            raise SyncError("sync report must contain every category exactly once")
        if len(set(categories)) != len(categories):
            raise SyncError("sync report categories must not repeat")
        positions = {category: index for index, category in enumerate(_CATEGORIES)}
        object.__setattr__(
            self,
            "items",
            tuple(sorted(self.items, key=lambda item: positions[item.category])),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "reporter": self.reporter,
            "items": [item.to_dict() for item in self.items],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> SyncReportDraft:
        if not isinstance(value, Mapping) or set(value) != _DRAFT_KEYS:
            raise SyncError("sync report draft schema is invalid")
        items = value["items"]
        if not isinstance(items, list):
            raise SyncError("sync report items must be an array")
        return cls(
            reporter=value["reporter"],  # type: ignore[arg-type]
            items=tuple(SyncItem.from_dict(item) for item in items),  # type: ignore[arg-type]
        )


@dataclass(frozen=True)
class SyncReport:
    run_id: str
    reporter: str
    subject: EvidenceSubject
    subject_digest: str
    items: tuple[SyncItem, ...]
    sync_gate_revision: int
    sync_round: int
    recorded_at: str
    schema_version: int = 1

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or type(self.subject) is not EvidenceSubject
            or not isinstance(self.run_id, str)
            or self.run_id != self.subject.run_id
            or not isinstance(self.subject_digest, str)
            or type(self.sync_gate_revision) is not int
            or self.sync_gate_revision < 0
            or type(self.sync_round) is not int
            or self.sync_round < 1
        ):
            raise SyncError("sync report identity is invalid")
        if self.subject_digest != self.subject.digest():
            raise SyncError("sync report subject digest is invalid")
        normalized = SyncReportDraft(self.reporter, self.items)
        if normalized.items != self.items:
            raise SyncError("sync report categories are not in canonical order")
        if not _is_canonical_utc(self.recorded_at):
            raise SyncError("sync report timestamp is invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "reporter": self.reporter,
            "subject": self.subject.to_dict(),
            "subject_digest": self.subject_digest,
            "items": [item.to_dict() for item in self.items],
            "sync_gate_revision": self.sync_gate_revision,
            "sync_round": self.sync_round,
            "recorded_at": self.recorded_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> SyncReport:
        if not isinstance(value, Mapping) or set(value) != _REPORT_KEYS:
            raise SyncRecoveryError("sync report schema is invalid")
        subject_payload = value["subject"]
        if not isinstance(subject_payload, Mapping):
            raise SyncRecoveryError("sync report subject is invalid")
        try:
            subject = EvidenceSubject(**dict(subject_payload))
        except (TypeError, ValueError) as error:
            raise SyncRecoveryError("sync report subject is invalid") from error
        items = value["items"]
        if not isinstance(items, list):
            raise SyncRecoveryError("sync report items are invalid")
        return cls(
            run_id=value["run_id"],  # type: ignore[arg-type]
            reporter=value["reporter"],  # type: ignore[arg-type]
            subject=subject,
            subject_digest=value["subject_digest"],  # type: ignore[arg-type]
            items=tuple(SyncItem.from_dict(item) for item in items),  # type: ignore[arg-type]
            sync_gate_revision=value["sync_gate_revision"],  # type: ignore[arg-type]
            sync_round=value["sync_round"],  # type: ignore[arg-type]
            recorded_at=value["recorded_at"],  # type: ignore[arg-type]
            schema_version=value["schema_version"],  # type: ignore[arg-type]
        )


def _load_committed_sync_report(
    store: StateStore,
    expected_subject: EvidenceSubject,
    *,
    trusted_boundary: Path,
    require_current_state: bool,
    allow_completed: bool = False,
) -> SyncReport:
    if type(store) is not StateStore or type(expected_subject) is not EvidenceSubject:
        raise TypeError("store and expected_subject must be exact sync types")
    if type(allow_completed) is not bool:
        raise TypeError("allow_completed must be a bool")
    if Path(os.path.abspath(store.run_directory)).name != expected_subject.run_id:
        raise SyncRecoveryError("sync store directory does not match the run identity")
    try:
        report_payload = _read_run_private_json(
            store,
            "sync-report.json",
            trusted_boundary=trusted_boundary,
        )
        assert report_payload is not None
        report = SyncReport.from_dict(report_payload)
        if report.subject != expected_subject:
            raise SyncRecoveryError("sync report subject is stale")
        seals = _read_publication_set(
            store,
            subject_digest=expected_subject.digest(),
            gate_revision=report.sync_gate_revision,
            trusted_boundary=trusted_boundary,
            missing_ok=False,
        )
        if len(seals) != 1:
            raise SyncRecoveryError(
                "sync report publication seal is missing or ambiguous"
            )
        seal_payload = next(iter(seals.values()))
        if set(seal_payload) != _OPERATION_KEYS - {"stage"}:
            raise SyncRecoveryError("sync publication seal schema is invalid")
        operation = _validate_operation(
            {**seal_payload, "stage": "state-transitioned"},
            store,
        )
        if operation["report"] != report_payload:
            raise SyncRecoveryError("sync report differs from immutable publication")
        _validate_publication_seal(
            store,
            operation,
            trusted_boundary=trusted_boundary,
        )
        expected_revision = int(operation["expected_revision"])
        target = Phase(str(operation["target_phase"]))
        events = store.events()
        transition_proofs = tuple(
            event
            for event in events
            if event.event_type == "phase.transitioned"
            and event.run_id == expected_subject.run_id
            and event.previous_phase is Phase.SYNCING
            and event.phase is target
            and event.revision == expected_revision + 1
            and event.state.phase is target
            and event.state.revision == expected_revision + 1
        )
        if len(transition_proofs) != 1:
            raise SyncRecoveryError(
                "sync report transition is not proven by the state WAL"
            )
        gate_states = tuple(
            event
            for event in events
            if event.revision == expected_revision
            and event.phase is Phase.SYNCING
            and event.state.phase is Phase.SYNCING
            and event.state.revision == expected_revision
        )
        sync_entries = tuple(
            event
            for event in events
            if event.revision <= expected_revision
            and event.event_type in {"phase.transitioned", "phase.reconciled"}
            and event.phase is Phase.SYNCING
            and event.previous_phase is not Phase.SYNCING
        )
        if len(gate_states) != 1 or len(sync_entries) != report.sync_round:
            raise SyncRecoveryError("sync report gate generation is not proven")
        if require_current_state:
            state = store.load()
            target_is_current = (
                state.phase is target and state.revision == expected_revision + 1
            )
            completed_is_current = (
                allow_completed
                and target is Phase.AWAITING_CLEANUP_APPROVAL
                and state.phase is Phase.COMPLETED
                and state.revision == expected_revision + 2
            )
            if completed_is_current:
                cleanup_proofs = tuple(
                    event
                    for event in events
                    if event.event_type == "phase.transitioned"
                    and event.run_id == expected_subject.run_id
                    and event.previous_phase is Phase.AWAITING_CLEANUP_APPROVAL
                    and event.phase is Phase.COMPLETED
                    and event.revision == expected_revision + 2
                    and event.state.phase is Phase.COMPLETED
                    and event.state.revision == expected_revision + 2
                    and event.sequence == transition_proofs[0].sequence + 1
                )
                if len(cleanup_proofs) != 1:
                    raise SyncRecoveryError(
                        "completed sync cleanup is not uniquely proven by the state WAL"
                    )
            elif not target_is_current:
                raise SyncRecoveryError("sync report is not current for the run state")
        return report
    except SyncRecoveryError:
        raise
    except RuntimeError as error:
        raise SyncRecoveryError("sync report evidence cannot be validated") from error


def _trusted_boundary_from_store(store: StateStore) -> Path:
    if type(store) is not StateStore:
        raise TypeError("store must be a StateStore")
    run_directory = Path(os.path.abspath(store.run_directory))
    if (
        run_directory.parent.name != "runs"
        or run_directory.parent.parent.name != "ship-flow"
    ):
        raise SyncRecoveryError("sync run directory layout is invalid")
    return run_directory.parent.parent.parent


def _load_completed_sync_report_locked(
    store: StateStore,
    expected_subject: EvidenceSubject | None,
) -> SyncReport:
    if expected_subject is not None and type(expected_subject) is not EvidenceSubject:
        raise TypeError("expected_subject must be an EvidenceSubject or None")
    trusted_boundary = _trusted_boundary_from_store(store)
    state = store.load()
    if state.phase is not Phase.COMPLETED:
        raise SyncRecoveryError("run is not completed")
    payload = _read_run_private_json(
        store,
        "sync-report.json",
        trusted_boundary=trusted_boundary,
    )
    assert payload is not None
    report = SyncReport.from_dict(payload)
    if expected_subject is not None and report.subject != expected_subject:
        raise SyncRecoveryError("completed sync report subject is stale")
    return _load_committed_sync_report(
        store,
        report.subject,
        trusted_boundary=trusted_boundary,
        require_current_state=True,
        allow_completed=True,
    )


def load_current_sync_report(
    store: StateStore,
    expected_subject: EvidenceSubject | None,
    *,
    worktree: Path | str,
    current_subject: Callable[[], EvidenceSubject],
    allow_completed: bool = False,
) -> SyncReport:
    """Load current or explicitly allowed completed sync evidence under lock."""

    if type(allow_completed) is not bool:
        raise TypeError("allow_completed must be a bool")
    if allow_completed:
        trusted_boundary = _trusted_boundary_from_store(store)
        with FileLock.repository(trusted_boundary):
            if store.load().phase is Phase.COMPLETED:
                return _load_completed_sync_report_locked(store, expected_subject)
            if type(expected_subject) is not EvidenceSubject:
                raise TypeError("expected_subject must be an EvidenceSubject")
            return SyncRecorder(
                store=store,
                worktree=worktree,
                current_subject=current_subject,
            )._load_current_report_locked(expected_subject)
    if type(expected_subject) is not EvidenceSubject:
        raise TypeError("expected_subject must be an EvidenceSubject")
    recorder = SyncRecorder(
        store=store,
        worktree=worktree,
        current_subject=current_subject,
    )
    with FileLock.repository(recorder.git_common_directory):
        return recorder._load_current_report_locked(expected_subject)


def _load_current_sync_report_locked(
    store: StateStore,
    expected_subject: EvidenceSubject | None,
    *,
    worktree: Path | str,
    current_subject: Callable[[], EvidenceSubject],
    allow_completed: bool = False,
) -> SyncReport:
    """Variant for callers owning repository and sync-publication locks."""

    if type(allow_completed) is not bool:
        raise TypeError("allow_completed must be a bool")
    if allow_completed and store.load().phase is Phase.COMPLETED:
        return _load_completed_sync_report_locked(store, expected_subject)
    if type(expected_subject) is not EvidenceSubject:
        raise TypeError("expected_subject must be an EvidenceSubject")
    return SyncRecorder(
        store=store,
        worktree=worktree,
        current_subject=current_subject,
    )._load_current_report_locked(expected_subject)


def _git_output(worktree: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=worktree,
            check=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SyncError("sync worktree Git identity cannot be verified") from error
    return completed.stdout.strip()


def _git_bytes_output(worktree: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=worktree,
            check=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SyncError("sync worktree Git tree cannot be verified") from error
    return completed.stdout


def _request_payload(
    draft: SyncReportDraft,
    subject: EvidenceSubject,
    *,
    gate_revision: int,
    sync_round: int,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": subject.run_id,
        "reporter": draft.reporter,
        "subject": subject.to_dict(),
        "subject_digest": subject.digest(),
        "items": [item.to_dict() for item in draft.items],
        "sync_gate_revision": gate_revision,
        "sync_round": sync_round,
    }


def _sync_round_at_gate(store: StateStore, gate_revision: int) -> int:
    if type(gate_revision) is not int or gate_revision < 0:
        raise SyncRecoveryError("sync gate revision is invalid")
    events = store.events()
    gate_states = tuple(
        event
        for event in events
        if event.revision == gate_revision
        and event.phase is Phase.SYNCING
        and event.state.phase is Phase.SYNCING
        and event.state.revision == gate_revision
    )
    rounds = sum(
        event.revision <= gate_revision
        and event.event_type in {"phase.transitioned", "phase.reconciled"}
        and event.phase is Phase.SYNCING
        and event.previous_phase is not Phase.SYNCING
        for event in events
    )
    if len(gate_states) != 1 or rounds < 1:
        raise SyncRecoveryError("sync gate is not proven by the state WAL")
    return rounds


class SyncRecorder:
    def __init__(
        self,
        *,
        store: StateStore,
        worktree: Path | str,
        current_subject: Callable[[], EvidenceSubject],
    ) -> None:
        if type(store) is not StateStore:
            raise TypeError("store must be a StateStore")
        if not callable(current_subject):
            raise TypeError("current_subject must be a live subject provider")
        self.store = store
        self.worktree = Path(worktree).resolve()
        self._subject_provider = current_subject
        common_output = _git_output(self.worktree, "rev-parse", "--git-common-dir")
        common_path = Path(common_output)
        if not common_path.is_absolute():
            common_path = self.worktree / common_path
        self.git_common_directory = common_path.resolve()

    def _live_subject(self) -> EvidenceSubject:
        subject = self._subject_provider()
        if type(subject) is not EvidenceSubject:
            raise SyncError("current sync subject is invalid")
        if (
            Path(_git_output(self.worktree, "rev-parse", "--show-toplevel")).resolve()
            != self.worktree
        ):
            raise SyncError("sync worktree is not the canonical Git worktree")
        if _git_output(self.worktree, "rev-parse", "HEAD") != subject.candidate_oid:
            raise SyncError("sync evidence subject is stale")
        if _git_output(self.worktree, "rev-parse", "HEAD^{tree}") != subject.tree_oid:
            raise SyncError("sync evidence subject is stale")
        _git_output(
            self.worktree,
            "cat-file",
            "-e",
            f"{subject.base_oid}^{{commit}}",
        )
        _git_output(
            self.worktree,
            "merge-base",
            "--is-ancestor",
            subject.base_oid,
            subject.candidate_oid,
        )
        if _git_output(
            self.worktree, "status", "--porcelain=v1", "--untracked-files=all"
        ):
            raise SyncError("sync worktree must be clean")
        return subject

    def _validate_paths(self, draft: SyncReportDraft) -> None:
        for item in draft.items:
            for raw_path in item.paths:
                if (
                    "\x00" in raw_path
                    or "\\" in raw_path
                    or raw_path.startswith("~")
                    or Path(raw_path).is_absolute()
                ):
                    raise SyncError("sync report path must be project-relative")
                path = PurePosixPath(raw_path)
                if (
                    raw_path in {"", "."}
                    or path.is_absolute()
                    or ".." in path.parts
                    or any(part.casefold() == ".git" for part in path.parts)
                    or path.as_posix() != raw_path
                ):
                    raise SyncError("sync report path is unsafe")
                resolved = (self.worktree / Path(*path.parts)).resolve(strict=False)
                try:
                    resolved.relative_to(self.worktree)
                except ValueError as error:
                    raise SyncError("sync report path escapes the worktree") from error

    def _regular_worktree_file(self, raw_path: str, expected_blob_oid: str) -> None:
        components = PurePosixPath(raw_path).parts
        descriptor = -1
        try:
            descriptor = os.open(self.worktree, _DIRECTORY_FLAGS)
            if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise SyncError("sync worktree is not a directory")
            for component in components[:-1]:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            leaf = os.open(components[-1], _FILE_FLAGS, dir_fd=descriptor)
            try:
                before = os.fstat(leaf)
                if not stat.S_ISREG(before.st_mode):
                    raise SyncError("current sync path is not a regular file")
                algorithm = (
                    "sha1"
                    if len(expected_blob_oid) == 40
                    else "sha256"
                    if len(expected_blob_oid) == 64
                    else ""
                )
                if not algorithm:
                    raise SyncError("current sync path blob identity is invalid")
                digest = hashlib.new(algorithm)
                digest.update(f"blob {before.st_size}\0".encode("ascii"))
                while True:
                    chunk = os.read(leaf, 65_536)
                    if not chunk:
                        break
                    digest.update(chunk)
                after = os.fstat(leaf)
                current = os.stat(
                    components[-1],
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                identity_fields = (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
                if any(
                    getattr(before, field) != getattr(after, field)
                    or getattr(before, field) != getattr(current, field)
                    for field in identity_fields
                ):
                    raise SyncError("current sync path changed while hashing")
                if digest.hexdigest() != expected_blob_oid:
                    raise SyncError(
                        "current sync path content differs from the subject tree"
                    )
            finally:
                os.close(leaf)
        except SyncError:
            raise
        except OSError as error:
            raise SyncError(
                "current sync path cannot be opened as a regular file"
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _tracked_blob_at_subject(
        self,
        raw_path: str,
        subject: EvidenceSubject,
    ) -> str:
        raw = _git_bytes_output(
            self.worktree,
            "--literal-pathspecs",
            "ls-tree",
            "-z",
            "--full-tree",
            subject.tree_oid,
            "--",
            raw_path,
        )
        records = raw.split(b"\0")
        if not records or records[-1] != b"":
            raise SyncError("current sync path tree evidence is malformed")
        records.pop()
        try:
            expected_path = raw_path.encode("utf-8")
        except UnicodeEncodeError as error:
            raise SyncError("sync report path is not valid UTF-8") from error
        if len(records) != 1 or b"\t" not in records[0]:
            raise SyncError("current sync path is not tracked by the subject tree")
        metadata, tree_path = records[0].split(b"\t", 1)
        fields = metadata.split(b" ")
        if (
            tree_path != expected_path
            or len(fields) != 3
            or fields[0] not in {b"100644", b"100755"}
            or fields[1] != b"blob"
        ):
            raise SyncError("current sync path is not a regular tracked blob")
        try:
            blob_oid = fields[2].decode("ascii")
        except UnicodeDecodeError as error:
            raise SyncError("current sync path blob identity is invalid") from error
        if len(blob_oid) not in {40, 64} or any(
            character not in _LOWER_HEX for character in blob_oid
        ):
            raise SyncError("current sync path blob identity is invalid")
        return blob_oid

    def _reject_index_flags(self, raw_path: str) -> None:
        try:
            expected_path = raw_path.encode("utf-8")
        except UnicodeEncodeError as error:
            raise SyncError("sync report path is not valid UTF-8") from error
        entry = _git_bytes_output(
            self.worktree,
            "--literal-pathspecs",
            "ls-files",
            "-v",
            "-z",
            "--",
            raw_path,
        )
        if entry != b"H " + expected_path + b"\0":
            raise SyncError("current sync path has unsupported Git index flags")

    def _validate_current_paths(
        self,
        items: tuple[SyncItem, ...],
        subject: EvidenceSubject,
    ) -> None:
        for item in items:
            if item.status != "current":
                continue
            for raw_path in item.paths:
                expected_blob_oid = self._tracked_blob_at_subject(raw_path, subject)
                self._reject_index_flags(raw_path)
                self._regular_worktree_file(raw_path, expected_blob_oid)

    def _load_current_report_locked(
        self,
        expected_subject: EvidenceSubject,
    ) -> SyncReport:
        if type(expected_subject) is not EvidenceSubject:
            raise TypeError("expected_subject must be an EvidenceSubject")
        first_subject = self._live_subject()
        if first_subject != expected_subject:
            raise SyncError("sync evidence subject is stale")
        report = _load_committed_sync_report(
            self.store,
            expected_subject,
            trusted_boundary=self.git_common_directory,
            require_current_state=True,
        )
        self._validate_paths(SyncReportDraft(report.reporter, report.items))
        self._validate_current_paths(report.items, expected_subject)
        if self._live_subject() != expected_subject:
            raise SyncError("sync evidence subject changed while loading")
        self._validate_current_paths(report.items, expected_subject)
        if self._live_subject() != expected_subject:
            raise SyncError("sync evidence subject changed while loading")
        return report

    def _finalize_historical_publication(
        self,
        operation: Mapping[str, object],
    ) -> None:
        operation = _validate_operation(operation, self.store)
        expected_revision = int(operation["expected_revision"])
        state = self.store.load()
        if state.revision <= expected_revision + 1:
            raise SyncRecoveryError(
                "pending sync publication is not an historical journal"
            )
        if operation["stage"] == "prepared":
            raise SyncRecoveryError(
                "historical sync publication was not written before transition"
            )
        report_payload = operation["report"]
        assert isinstance(report_payload, Mapping)
        report = SyncReport.from_dict(report_payload)
        committed = _load_committed_sync_report(
            self.store,
            report.subject,
            trusted_boundary=self.git_common_directory,
            require_current_state=False,
        )
        if committed.to_dict() != dict(report_payload):
            raise SyncRecoveryError(
                "historical sync report differs from its publication journal"
            )
        if operation["stage"] == "report-written":
            operation = _write_operation_stage(
                self.store,
                operation,
                "state-transitioned",
                trusted_boundary=self.git_common_directory,
            )
        _validate_publication_seal(
            self.store,
            operation,
            trusted_boundary=self.git_common_directory,
        )
        _unlink_run_file(
            self.store,
            "sync-operation.json",
            trusted_boundary=self.git_common_directory,
        )

    def _recover_publication(
        self,
        operation: Mapping[str, object],
        *,
        request: Mapping[str, object],
        subject: EvidenceSubject,
    ) -> SyncReport:
        operation = _validate_operation(operation, self.store)
        if operation["request"] != request:
            raise SyncRecoveryError(
                "pending sync publication belongs to a different request"
            )
        report_payload = operation["report"]
        assert isinstance(report_payload, Mapping)
        report = SyncReport.from_dict(report_payload)
        if report.subject != subject:
            raise SyncRecoveryError("pending sync publication subject is stale")

        expected_revision = int(operation["expected_revision"])
        target = Phase(str(operation["target_phase"]))
        state = self.store.load()
        source_state = (
            state.phase is Phase.SYNCING and state.revision == expected_revision
        )
        target_state = state.phase is target and state.revision == expected_revision + 1
        if not source_state and not target_state:
            raise SyncRecoveryError("sync publication state differs from receipt")
        stage = str(operation["stage"])
        if (source_state and stage == "state-transitioned") or (
            target_state and stage == "prepared"
        ):
            raise SyncRecoveryError("sync publication stage disagrees with its state")
        _ensure_publication_seal(
            self.store,
            operation,
            trusted_boundary=self.git_common_directory,
        )

        current_payload = _read_run_private_json(
            self.store,
            "sync-report.json",
            trusted_boundary=self.git_common_directory,
            missing_ok=True,
        )
        current_digest = (
            None if current_payload is None else _file_bytes_digest(current_payload)
        )
        previous_digest = operation["previous_report_file_sha256"]
        if current_digest == operation["report_file_sha256"]:
            pass
        elif current_payload is None and previous_digest is None:
            _write_run_json(
                self.store,
                "sync-report.json",
                report_payload,
                trusted_boundary=self.git_common_directory,
            )
        elif current_digest == previous_digest:
            _write_run_json(
                self.store,
                "sync-report.json",
                report_payload,
                trusted_boundary=self.git_common_directory,
            )
        else:
            raise SyncRecoveryError("existing sync report differs from receipt")
        if (
            _OPERATION_STAGES[str(operation["stage"])]
            < _OPERATION_STAGES["report-written"]
        ):
            operation = _write_operation_stage(
                self.store,
                operation,
                "report-written",
                trusted_boundary=self.git_common_directory,
            )

        _validate_publication_seal(
            self.store,
            operation,
            trusted_boundary=self.git_common_directory,
        )
        state = self.store.load()
        source_state = (
            state.phase is Phase.SYNCING and state.revision == expected_revision
        )
        target_state = state.phase is target and state.revision == expected_revision + 1
        if not source_state and not target_state:
            raise SyncRecoveryError("sync publication state changed during recovery")
        self._validate_current_paths(report.items, subject)
        if self._live_subject() != subject:
            raise SyncRecoveryError("sync evidence subject changed before transition")
        self._validate_current_paths(report.items, subject)
        if self._live_subject() != subject:
            raise SyncRecoveryError("sync evidence subject changed before transition")
        if source_state:
            self.store.transition(target, expected_revision=expected_revision)
        if (
            _OPERATION_STAGES[str(operation["stage"])]
            < _OPERATION_STAGES["state-transitioned"]
        ):
            operation = _write_operation_stage(
                self.store,
                operation,
                "state-transitioned",
                trusted_boundary=self.git_common_directory,
            )
        _unlink_run_file(
            self.store,
            "sync-operation.json",
            trusted_boundary=self.git_common_directory,
        )
        self._validate_current_paths(report.items, subject)
        if self._live_subject() != subject:
            raise SyncRecoveryError("sync evidence subject changed before return")
        return report

    def record_sync_report(
        self,
        report: SyncReportDraft | Mapping[str, object],
        subject: EvidenceSubject,
    ) -> SyncReport:
        draft = (
            report
            if type(report) is SyncReportDraft
            else SyncReportDraft.from_dict(report)
        )
        if type(subject) is not EvidenceSubject:
            raise SyncError("sync evidence subject is invalid")
        self._validate_paths(draft)
        lock = FileLock(
            self.store.run_directory / "sync-publication.lock",
            private_root=self.store.run_directory,
        )
        with (
            FileLock.repository(self.git_common_directory),
            lock as acquired_lock,
            self.store.anchored(acquired_lock.trusted_parent),
        ):
            live_subject = self._live_subject()
            state = self.store.load()
            if (
                subject != live_subject
                or state.run_id != subject.run_id
                or Path(os.path.abspath(self.store.run_directory)).name
                != subject.run_id
            ):
                raise SyncError("sync evidence subject is stale")
            self._validate_current_paths(draft.items, subject)
            pending = _load_operation(
                self.store,
                trusted_boundary=self.git_common_directory,
            )
            if pending is not None:
                pending_revision = pending["expected_revision"]
                if type(pending_revision) is not int:
                    raise SyncRecoveryError("pending sync gate identity is invalid")
                if state.revision > pending_revision + 1:
                    self._finalize_historical_publication(pending)
                    state = self.store.load()
                    pending = None
            if pending is not None:
                pending_request = pending["request"]
                assert isinstance(pending_request, Mapping)
                gate_revision = pending_request["sync_gate_revision"]
                sync_round = pending_request["sync_round"]
                if type(gate_revision) is not int or type(sync_round) is not int:
                    raise SyncRecoveryError("pending sync gate identity is invalid")
                request = _request_payload(
                    draft,
                    subject,
                    gate_revision=gate_revision,
                    sync_round=sync_round,
                )
                return self._recover_publication(
                    pending,
                    request=request,
                    subject=subject,
                )
            if state.phase is not Phase.SYNCING:
                existing = _load_committed_sync_report(
                    self.store,
                    subject,
                    trusted_boundary=self.git_common_directory,
                    require_current_state=True,
                )
                existing_request = _request_payload(
                    SyncReportDraft(existing.reporter, existing.items),
                    existing.subject,
                    gate_revision=existing.sync_gate_revision,
                    sync_round=existing.sync_round,
                )
                request = _request_payload(
                    draft,
                    subject,
                    gate_revision=existing.sync_gate_revision,
                    sync_round=existing.sync_round,
                )
                if existing_request != request:
                    raise SyncRecoveryError(
                        "completed sync publication belongs to a different request"
                    )
                self._validate_current_paths(existing.items, subject)
                if self._live_subject() != subject:
                    raise SyncError("sync evidence subject changed while loading")
                self._validate_current_paths(existing.items, subject)
                if self._live_subject() != subject:
                    raise SyncError("sync evidence subject changed while loading")
                return existing
            gate_revision = state.revision
            sync_round = _sync_round_at_gate(self.store, gate_revision)
            request = _request_payload(
                draft,
                subject,
                gate_revision=gate_revision,
                sync_round=sync_round,
            )
            subject_seals = _read_publication_set(
                self.store,
                subject_digest=subject.digest(),
                gate_revision=gate_revision,
                trusted_boundary=self.git_common_directory,
                missing_ok=True,
            )
            if subject_seals:
                raise SyncRecoveryError(
                    "orphan sync publication seal requires manual reconciliation"
                )
            previous_payload = _read_run_private_json(
                self.store,
                "sync-report.json",
                trusted_boundary=self.git_common_directory,
                missing_ok=True,
            )
            previous_report_file_sha256: str | None = None
            if previous_payload is not None:
                previous_report = SyncReport.from_dict(previous_payload)
                _load_committed_sync_report(
                    self.store,
                    previous_report.subject,
                    trusted_boundary=self.git_common_directory,
                    require_current_state=False,
                )
                previous_report_file_sha256 = _file_bytes_digest(previous_payload)
            completed = SyncReport(
                run_id=state.run_id,
                reporter=draft.reporter,
                subject=subject,
                subject_digest=subject.digest(),
                items=draft.items,
                sync_gate_revision=gate_revision,
                sync_round=sync_round,
                recorded_at=_utc_now(),
            )
            payload = completed.to_dict()
            target = (
                Phase.DEVELOPING
                if any(item.status == "changes_required" for item in draft.items)
                else Phase.AWAITING_CLEANUP_APPROVAL
            )
            request_digest = _canonical_json_digest(request)
            report_path = self.store.run_directory / "sync-report.json"
            operation = {
                "schema_version": 1,
                "stage": "prepared",
                "request": request,
                "request_digest": request_digest,
                "report": payload,
                "report_digest": _canonical_json_digest(payload),
                "report_file_sha256": _file_bytes_digest(payload),
                "previous_report_file_sha256": previous_report_file_sha256,
                "expected_revision": state.revision,
                "source_phase": Phase.SYNCING.value,
                "target_phase": target.value,
                "artifact_path": str(report_path),
            }
            publication_sha256 = _canonical_json_digest(
                _publication_commitment(operation)
            )
            operation["publication_sha256"] = publication_sha256
            operation = _validate_operation(operation, self.store)
            _write_run_json(
                self.store,
                "sync-operation.json",
                operation,
                trusted_boundary=self.git_common_directory,
            )
            _ensure_publication_seal(
                self.store,
                operation,
                trusted_boundary=self.git_common_directory,
            )
            return self._recover_publication(
                operation,
                request=request,
                subject=subject,
            )


def record_sync_report(
    store: StateStore,
    report: SyncReportDraft | Mapping[str, object],
    subject: EvidenceSubject,
    *,
    worktree: Path | str,
    current_subject: Callable[[], EvidenceSubject],
) -> SyncReport:
    return SyncRecorder(
        store=store,
        worktree=worktree,
        current_subject=current_subject,
    ).record_sync_report(report, subject)
