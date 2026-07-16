from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .model import (
    LEGAL_TRANSITIONS,
    RECONCILIATION_TRANSITIONS,
    STATE_SCHEMA_VERSION,
    Phase,
    RunState,
)


class StateStoreError(RuntimeError):
    pass


class StateAlreadyExistsError(StateStoreError):
    pass


class StateNotFoundError(StateStoreError):
    pass


class StateCorruptionError(StateStoreError):
    pass


class InvalidTransitionError(StateStoreError):
    pass


class StaleRevisionError(StateStoreError):
    pass


class LockUnavailableError(StateStoreError):
    pass


class UnsafeLockPathError(StateStoreError):
    pass


_MAX_STATE_WAL_BYTES = 64 * 1024 * 1024
_MAX_STATE_SNAPSHOT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class PrivateRootAnchor:
    """A stable descriptor for a trusted private directory."""

    path: Path
    descriptor: int


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_private_file_at(
    directory_descriptor: int,
    name: str,
    *,
    label: str,
    max_bytes: int,
    missing_ok: bool = False,
) -> bytes | None:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    except FileNotFoundError:
        if missing_ok:
            return None
        raise StateNotFoundError(f"{label} is missing") from None
    except OSError as error:
        raise StateCorruptionError(f"{label} cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > max_bytes
        ):
            raise StateCorruptionError(f"{label} is not a bounded private regular file")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65_536, max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise StateCorruptionError(f"{label} exceeds its size limit")
        try:
            current = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise StateCorruptionError(f"{label} changed while being read") from error
        if _file_identity(current) != _file_identity(metadata):
            raise StateCorruptionError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _private_entry_exists_at(directory_descriptor: int, name: str) -> bool:
    try:
        metadata = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return False
    except OSError as error:
        raise StateCorruptionError("state evidence cannot be inspected") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise StateCorruptionError("state evidence path is a symbolic link")
    return True


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


def _payload_digest(payload: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


_OPERATION_START_KEYS = frozenset(
    {
        "schema_version",
        "marker_id",
        "run_id",
        "cycle_id",
        "mode",
        "index",
        "attempt",
        "running_receipt_sha256",
        "idempotency_key",
    }
)


def _operation_start_payload(
    *,
    run_id: str,
    cycle_id: str,
    mode: str,
    index: int,
    attempt: int,
    running_receipt_sha256: str,
    idempotency_key: str,
) -> dict[str, Any]:
    stable: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "cycle_id": cycle_id,
        "mode": mode,
        "index": index,
        "attempt": attempt,
        "running_receipt_sha256": running_receipt_sha256,
        "idempotency_key": idempotency_key,
    }
    return {**stable, "marker_id": _payload_digest(stable)}


def _validate_operation_start_payload(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _OPERATION_START_KEYS:
        raise ValueError("operation start marker schema is invalid")
    stable = {key: value for key, value in payload.items() if key != "marker_id"}
    if (
        payload.get("schema_version") != 1
        or not isinstance(payload.get("run_id"), str)
        or not payload["run_id"]
        or not isinstance(payload.get("cycle_id"), str)
        or re.fullmatch(r"[0-9a-f]{64}", payload["cycle_id"]) is None
        or payload.get("mode") not in {"release", "rollback"}
        or type(payload.get("index")) is not int
        or payload["index"] < 1
        or type(payload.get("attempt")) is not int
        or payload["attempt"] < 1
        or not isinstance(payload.get("running_receipt_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", payload["running_receipt_sha256"]) is None
        or not isinstance(payload.get("idempotency_key"), str)
        or re.fullmatch(r"[0-9a-f]{64}", payload["idempotency_key"]) is None
        or payload.get("marker_id") != _payload_digest(stable)
    ):
        raise ValueError("operation start marker is invalid")
    return dict(payload)


_OPERATION_ADJUDICATION_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "mode",
        "adjudication_id",
    }
)


def _operation_adjudication_payload(
    *,
    run_id: str,
    mode: str,
    adjudication_id: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "mode": mode,
        "adjudication_id": adjudication_id,
    }
    return _validate_operation_adjudication_payload(payload)


def _validate_operation_adjudication_payload(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _OPERATION_ADJUDICATION_KEYS:
        raise ValueError("operation adjudication marker schema is invalid")
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 1
        or not isinstance(payload.get("run_id"), str)
        or not payload["run_id"]
        or payload.get("mode") not in {"release", "rollback"}
        or not isinstance(payload.get("adjudication_id"), str)
        or re.fullmatch(r"[0-9a-f]{64}", payload["adjudication_id"]) is None
    ):
        raise ValueError("operation adjudication marker is invalid")
    return dict(payload)


def _open_private_directory(path: Path, *, private_root: Path | None = None) -> int:
    root = Path(os.path.abspath(path if private_root is None else private_root))
    path = Path(os.path.abspath(path))
    try:
        relative_path = path.relative_to(root)
    except ValueError as error:
        raise ValueError("private directory must be below its private root") from error
    if ".." in relative_path.parts:
        raise ValueError("private directory must be below its private root")

    boundary = root.parent
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        current_descriptor = os.open(boundary, directory_flags)
    except OSError as error:
        raise UnsafeLockPathError(
            f"private directory boundary cannot be opened safely: {boundary}"
        ) from error
    current_path = boundary
    components = (root.name, *relative_path.parts)
    try:
        for component in components:
            if not component or component in {".", ".."}:
                raise UnsafeLockPathError("private directory has an unsafe component")
            try:
                metadata = os.stat(
                    component,
                    dir_fd=current_descriptor,
                    follow_symlinks=False,
                )
                created = False
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_descriptor)
                    created = True
                except FileExistsError:
                    created = False
                metadata = os.stat(
                    component,
                    dir_fd=current_descriptor,
                    follow_symlinks=False,
                )
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise UnsafeLockPathError(
                    f"private directory is not a real directory: {current_path / component}"
                )
            try:
                child_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=current_descriptor,
                )
            except OSError as error:
                raise UnsafeLockPathError(
                    f"private directory cannot be opened safely: {current_path / component}"
                ) from error
            try:
                opened_metadata = os.fstat(child_descriptor)
                if not stat.S_ISDIR(opened_metadata.st_mode) or (
                    opened_metadata.st_dev,
                    opened_metadata.st_ino,
                ) != (metadata.st_dev, metadata.st_ino):
                    raise UnsafeLockPathError(
                        f"private directory changed while opening: {current_path / component}"
                    )
                os.fchmod(child_descriptor, 0o700)
                if created:
                    _fsync_directory(current_path, descriptor=current_descriptor)
            except Exception:
                os.close(child_descriptor)
                raise
            os.close(current_descriptor)
            current_descriptor = child_descriptor
            current_path /= component
        return current_descriptor
    except Exception:
        os.close(current_descriptor)
        raise


def _private_directory(path: Path, *, private_root: Path | None = None) -> None:
    descriptor = _open_private_directory(path, private_root=private_root)
    os.close(descriptor)


def _trusted_root_path(trusted_root: Path | PrivateRootAnchor) -> Path:
    return Path(
        os.path.abspath(
            trusted_root.path
            if isinstance(trusted_root, PrivateRootAnchor)
            else trusted_root
        )
    )


def _open_private_directory_from_anchor(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> int:
    root = _trusted_root_path(trusted_root)
    path = Path(os.path.abspath(path))
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ValueError("private directory must be below its trusted root") from error
    if not isinstance(trusted_root, PrivateRootAnchor):
        return _open_private_directory(path, private_root=root)

    root_metadata = os.fstat(trusted_root.descriptor)
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise UnsafeLockPathError("trusted private root descriptor is unsafe")
    current_descriptor = os.dup(trusted_root.descriptor)
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        for component in relative.parts:
            if not component or component in {".", ".."}:
                raise UnsafeLockPathError("private directory has an unsafe component")
            try:
                metadata = os.stat(
                    component,
                    dir_fd=current_descriptor,
                    follow_symlinks=False,
                )
                created = False
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_descriptor)
                    created = True
                except FileExistsError:
                    created = False
                metadata = os.stat(
                    component,
                    dir_fd=current_descriptor,
                    follow_symlinks=False,
                )
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise UnsafeLockPathError(
                    f"private directory is not a real directory: {path}"
                )
            child_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=current_descriptor,
            )
            try:
                opened_metadata = os.fstat(child_descriptor)
                if not stat.S_ISDIR(opened_metadata.st_mode) or (
                    opened_metadata.st_dev,
                    opened_metadata.st_ino,
                ) != (metadata.st_dev, metadata.st_ino):
                    raise UnsafeLockPathError(
                        f"private directory changed while opening: {path}"
                    )
                os.fchmod(child_descriptor, 0o700)
                if created:
                    os.fsync(current_descriptor)
            except Exception:
                os.close(child_descriptor)
                raise
            os.close(current_descriptor)
            current_descriptor = child_descriptor
        return current_descriptor
    except Exception:
        os.close(current_descriptor)
        raise


def _open_existing_private_directory_from_anchor(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> int:
    root = _trusted_root_path(trusted_root)
    path = Path(os.path.abspath(path))
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ValueError("private directory must be below its trusted root") from error
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    if isinstance(trusted_root, PrivateRootAnchor):
        current_descriptor = os.dup(trusted_root.descriptor)
    else:
        try:
            current_descriptor = os.open(root, directory_flags)
        except OSError as error:
            raise StateCorruptionError(
                "private evidence root cannot be opened safely"
            ) from error
    try:
        root_metadata = os.fstat(current_descriptor)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise StateCorruptionError(
                "private evidence root is not a private directory"
            )
        for component in relative.parts:
            if not component or component in {".", ".."}:
                raise StateCorruptionError(
                    "private evidence directory has an unsafe component"
                )
            child_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=current_descriptor,
            )
            try:
                metadata = os.fstat(child_descriptor)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise StateCorruptionError("private evidence directory is unsafe")
            except Exception:
                os.close(child_descriptor)
                raise
            os.close(current_descriptor)
            current_descriptor = child_descriptor
        return current_descriptor
    except Exception:
        os.close(current_descriptor)
        raise


def _read_bounded_private_file(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
    label: str,
    max_bytes: int,
) -> bytes:
    path = Path(os.path.abspath(path))
    try:
        parent_descriptor = _open_existing_private_directory_from_anchor(
            path.parent,
            trusted_root=trusted_root,
        )
    except FileNotFoundError:
        raise StateNotFoundError(f"{label} is missing") from None
    try:
        raw = _read_private_file_at(
            parent_descriptor,
            path.name,
            label=label,
            max_bytes=max_bytes,
        )
        assert raw is not None
        return raw
    finally:
        os.close(parent_descriptor)


def _private_directory_names(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> tuple[str, ...]:
    try:
        descriptor = _open_existing_private_directory_from_anchor(
            path,
            trusted_root=trusted_root,
        )
    except FileNotFoundError:
        raise StateNotFoundError("private evidence directory is missing") from None
    try:
        return tuple(sorted(os.listdir(descriptor)))
    except OSError as error:
        raise StateCorruptionError(
            "private evidence directory cannot be listed safely"
        ) from error
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("private evidence write did not make progress")
        remaining = remaining[written:]


def _atomic_write_private_bytes(
    path: Path,
    payload: bytes,
    *,
    trusted_root: Path | PrivateRootAnchor,
    immutable: bool = False,
) -> None:
    path = Path(os.path.abspath(path))
    if not path.name or path.name in {".", ".."}:
        raise ValueError("private evidence file name is unsafe")
    parent_descriptor = _open_private_directory_from_anchor(
        path.parent,
        trusted_root=trusted_root,
    )
    temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    temporary_exists = False
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        temporary_exists = True
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise StateCorruptionError("private evidence temporary file is unsafe")
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if immutable:
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            os.unlink(temporary_name, dir_fd=parent_descriptor)
            temporary_exists = False
        else:
            os.rename(
                temporary_name,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            temporary_exists = False
        os.fsync(parent_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_exists:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)


def _create_private_directory_anchor(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> PrivateRootAnchor:
    path = Path(os.path.abspath(path))
    if not path.name or path.name in {".", ".."}:
        raise ValueError("private directory name is unsafe")
    parent_descriptor = _open_private_directory_from_anchor(
        path.parent,
        trusted_root=trusted_root,
    )
    child_descriptor = -1
    try:
        os.mkdir(path.name, mode=0o700, dir_fd=parent_descriptor)
        metadata = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        child_descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        opened_metadata = os.fstat(child_descriptor)
        if not stat.S_ISDIR(opened_metadata.st_mode) or (
            opened_metadata.st_dev,
            opened_metadata.st_ino,
        ) != (metadata.st_dev, metadata.st_ino):
            raise UnsafeLockPathError("private directory changed while creating")
        os.fchmod(child_descriptor, 0o700)
        os.fsync(parent_descriptor)
        anchor = PrivateRootAnchor(path, child_descriptor)
        child_descriptor = -1
        return anchor
    finally:
        if child_descriptor >= 0:
            os.close(child_descriptor)
        os.close(parent_descriptor)


def _atomic_write_private_json(
    path: Path,
    payload: object,
    *,
    trusted_root: Path | PrivateRootAnchor,
    immutable: bool = False,
) -> None:
    _atomic_write_private_bytes(
        path,
        _canonical_json_bytes(payload) + b"\n",
        trusted_root=trusted_root,
        immutable=immutable,
    )


def _remove_private_file(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
    missing_ok: bool = False,
) -> None:
    path = Path(os.path.abspath(path))
    parent_descriptor = _open_private_directory_from_anchor(
        path.parent,
        trusted_root=trusted_root,
    )
    try:
        try:
            metadata = os.stat(
                path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            if missing_ok:
                return
            raise
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise StateCorruptionError("private evidence file is unsafe")
        os.unlink(path.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _run_private_root(run_directory: Path) -> Path:
    runs_directory = run_directory.parent
    if runs_directory.name != "runs":
        return run_directory
    runtime_root = runs_directory.parent
    return runtime_root if runtime_root.name == "ship-flow" else runs_directory


def _fsync_directory(path: Path, *, descriptor: int | None = None) -> None:
    if descriptor is not None:
        os.fsync(descriptor)
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class FileLock:
    """A private, non-blocking advisory lock backed by ``fcntl.flock``."""

    def __init__(
        self,
        path: Path | str,
        *,
        private_root: Path | str | None = None,
        parent_descriptor: int | None = None,
    ):
        self.path = Path(os.path.abspath(path))
        self._private_root = (
            self.path.parent
            if private_root is None
            else Path(os.path.abspath(private_root))
        )
        self._descriptor: int | None = None
        self._parent_descriptor: int | None = None
        self._anchor_source_descriptor = parent_descriptor

    @classmethod
    def at(
        cls,
        parent_descriptor: int,
        name: str,
        *,
        display_path: Path | str,
    ) -> "FileLock":
        if not name or name in {".", ".."} or Path(name).name != name:
            raise ValueError("lock file name is unsafe")
        display = Path(display_path)
        if display.name != name:
            raise ValueError("lock display path does not match its file name")
        return cls(
            display,
            private_root=display.parent,
            parent_descriptor=parent_descriptor,
        )

    @classmethod
    def repository(cls, git_common_directory: Path | str) -> "FileLock":
        runtime_root = Path(git_common_directory) / "ship-flow"
        return cls(
            runtime_root / "locks" / "repository.lock",
            private_root=runtime_root,
        )

    @classmethod
    def run(cls, run_directory: Path | str) -> "FileLock":
        directory = Path(run_directory)
        return cls(
            directory / "run.lock",
            private_root=_run_private_root(directory),
        )

    @classmethod
    def authorization(cls, run_directory: Path | str) -> "FileLock":
        directory = Path(run_directory)
        return cls(
            directory / "authorization.lock",
            private_root=_run_private_root(directory),
        )

    @classmethod
    def release_target(
        cls, git_common_directory: Path | str, target: str
    ) -> "FileLock":
        if not target:
            raise ValueError("release target must be non-empty")
        digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
        runtime_root = Path(git_common_directory) / "ship-flow"
        return cls(
            runtime_root / "locks" / "release-targets" / f"{digest}.lock",
            private_root=runtime_root,
        )

    def acquire(self) -> "FileLock":
        if self._descriptor is not None:
            raise RuntimeError("lock is already acquired by this object")
        try:
            self.path.relative_to(self._private_root)
        except ValueError as error:
            raise UnsafeLockPathError(
                f"lock file escapes its private root: {self.path}"
            ) from error
        if self._anchor_source_descriptor is None:
            parent_descriptor = _open_private_directory(
                self.path.parent,
                private_root=self._private_root,
            )
        else:
            parent_descriptor = os.dup(self._anchor_source_descriptor)
            metadata = os.fstat(parent_descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                os.close(parent_descriptor)
                raise UnsafeLockPathError(
                    "lock parent descriptor is not a private directory"
                )
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(
                self.path.name,
                flags,
                0o600,
                dir_fd=parent_descriptor,
            )
        except OSError as error:
            os.close(parent_descriptor)
            if error.errno in (errno.ELOOP, errno.EMLINK):
                raise UnsafeLockPathError(
                    f"lock file is a symbolic link: {self.path}"
                ) from error
            raise
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            os.close(parent_descriptor)
            raise UnsafeLockPathError(f"lock file is not regular: {self.path}")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(descriptor)
            os.close(parent_descriptor)
            if error.errno in (errno.EACCES, errno.EAGAIN):
                raise LockUnavailableError(
                    f"lock is already held: {self.path}"
                ) from error
            raise
        self._descriptor = descriptor
        self._parent_descriptor = parent_descriptor
        return self

    @property
    def trusted_parent(self) -> PrivateRootAnchor:
        if self._parent_descriptor is None:
            raise RuntimeError("lock is not acquired")
        return PrivateRootAnchor(
            path=self.path.parent,
            descriptor=self._parent_descriptor,
        )

    def release(self) -> None:
        if self._descriptor is None:
            return
        descriptor, self._descriptor = self._descriptor, None
        parent_descriptor, self._parent_descriptor = self._parent_descriptor, None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
            if parent_descriptor is not None:
                os.close(parent_descriptor)

    def __enter__(self) -> "FileLock":
        return self.acquire()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


@dataclass(frozen=True)
class StateEvent:
    event_type: str
    run_id: str
    sequence: int
    revision: int
    previous_phase: Phase | None
    phase: Phase
    occurred_at: str
    state: RunState
    previous_event_sha256: str | None
    operation_start: dict[str, Any] | None
    operation_adjudication: dict[str, Any] | None
    reconciliation_reason: str | None
    schema_version: int = STATE_SCHEMA_VERSION
    _reconciliation_reason_present: bool = field(
        default=True,
        compare=False,
        repr=False,
    )
    _operation_adjudication_present: bool = field(
        default=True,
        compare=False,
        repr=False,
    )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "event_type": self.event_type,
            "run_id": self.run_id,
            "sequence": self.sequence,
            "revision": self.revision,
            "previous_phase": (
                self.previous_phase.value if self.previous_phase is not None else None
            ),
            "phase": self.phase.value,
            "occurred_at": self.occurred_at,
            "state": self.state.to_dict(),
            "previous_event_sha256": self.previous_event_sha256,
            "operation_start": self.operation_start,
        }
        if self._operation_adjudication_present:
            payload["operation_adjudication"] = self.operation_adjudication
        if self._reconciliation_reason_present:
            payload["reconciliation_reason"] = self.reconciliation_reason
        return payload

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "StateEvent":
        expected_keys = {
            "schema_version",
            "event_type",
            "run_id",
            "sequence",
            "revision",
            "previous_phase",
            "phase",
            "occurred_at",
            "state",
            "previous_event_sha256",
            "operation_start",
            "operation_adjudication",
            "reconciliation_reason",
        }
        accepted_key_sets = {
            frozenset(expected_keys),
            frozenset(expected_keys - {"reconciliation_reason"}),
            frozenset(expected_keys - {"operation_adjudication"}),
            frozenset(
                expected_keys - {"reconciliation_reason", "operation_adjudication"}
            ),
        }
        actual_keys = set(value)
        reconciliation_reason_present = "reconciliation_reason" in value
        operation_adjudication_present = "operation_adjudication" in value
        if frozenset(actual_keys) not in accepted_key_sets:
            raise ValueError("state event has unexpected or missing fields")
        if value["schema_version"] != STATE_SCHEMA_VERSION:
            raise ValueError("unsupported state event schema")
        if value["event_type"] not in {
            "run.created",
            "phase.transitioned",
            "phase.reconciled",
            "operation.started",
            "operation.adjudicated",
        }:
            raise ValueError("unknown state event type")
        if not isinstance(value["run_id"], str) or not value["run_id"]:
            raise ValueError("event run_id must be a non-empty string")
        if type(value["revision"]) is not int or value["revision"] < 0:
            raise ValueError("event revision must be a non-negative integer")
        if type(value["sequence"]) is not int or value["sequence"] < 0:
            raise ValueError("event sequence must be a non-negative integer")
        previous_event_sha256 = value["previous_event_sha256"]
        if previous_event_sha256 is not None and (
            not isinstance(previous_event_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", previous_event_sha256) is None
        ):
            raise ValueError("previous event digest is invalid")
        if not isinstance(value["occurred_at"], str):
            raise ValueError("event timestamp must be a string")
        try:
            phase = Phase(value["phase"])
            previous_phase = (
                None
                if value["previous_phase"] is None
                else Phase(value["previous_phase"])
            )
        except (TypeError, ValueError) as error:
            raise ValueError("unknown event phase") from error
        if not isinstance(value["state"], Mapping):
            raise ValueError("event state must be an object")
        state = RunState.from_dict(value["state"])
        operation_start = value["operation_start"]
        operation_adjudication = value.get("operation_adjudication")
        reconciliation_reason = value.get("reconciliation_reason")
        if value["event_type"] == "operation.started":
            operation_start = _validate_operation_start_payload(operation_start)
            if operation_start["run_id"] != value["run_id"]:
                raise ValueError("operation marker run identity is invalid")
            if operation_adjudication is not None:
                raise ValueError("operation start cannot contain an adjudication")
        elif value["event_type"] == "operation.adjudicated":
            if operation_start is not None:
                raise ValueError("operation adjudication cannot contain a start marker")
            operation_adjudication = _validate_operation_adjudication_payload(
                operation_adjudication
            )
            if operation_adjudication["run_id"] != value["run_id"]:
                raise ValueError("operation adjudication run identity is invalid")
        elif operation_start is not None:
            raise ValueError("phase event cannot contain an operation marker")
        elif operation_adjudication is not None:
            raise ValueError("phase event cannot contain an operation adjudication")
        if value["event_type"] == "phase.reconciled":
            if (
                not reconciliation_reason_present
                or not isinstance(reconciliation_reason, str)
                or re.fullmatch(
                    r"[a-z0-9][a-z0-9._-]{0,127}",
                    reconciliation_reason,
                )
                is None
            ):
                raise ValueError("reconciliation reason is invalid")
        elif reconciliation_reason is not None:
            raise ValueError(
                "non-reconciliation event cannot contain a reconciliation reason"
            )
        return cls(
            event_type=value["event_type"],
            run_id=value["run_id"],
            sequence=value["sequence"],
            revision=value["revision"],
            previous_phase=previous_phase,
            phase=phase,
            occurred_at=value["occurred_at"],
            state=state,
            previous_event_sha256=previous_event_sha256,
            operation_start=operation_start,
            operation_adjudication=operation_adjudication,
            reconciliation_reason=reconciliation_reason,
            schema_version=value["schema_version"],
            _reconciliation_reason_present=reconciliation_reason_present,
            _operation_adjudication_present=operation_adjudication_present,
        )


def _event_digest(event: StateEvent) -> str:
    return _payload_digest(event.to_dict())


class StateStore:
    def __init__(self, run_directory: Path | str):
        self.run_directory = Path(run_directory)
        self.state_path = self.run_directory / "state.json"
        self.events_path = self.run_directory / "events.jsonl"
        self.lock_path = self.run_directory / "run.lock"
        self._run_anchor: PrivateRootAnchor | None = None

    @property
    def trusted_root(self) -> Path | PrivateRootAnchor:
        return self._run_anchor or Path(os.path.abspath(self.run_directory))

    @contextmanager
    def anchored(self, trusted_root: PrivateRootAnchor):
        expected = Path(os.path.abspath(self.run_directory))
        if Path(os.path.abspath(trusted_root.path)) != expected:
            raise ValueError("state anchor does not identify this run directory")
        descriptor = os.dup(trusted_root.descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            os.close(descriptor)
            raise UnsafeLockPathError("state anchor is not a private directory")
        previous = self._run_anchor
        self._run_anchor = PrivateRootAnchor(expected, descriptor)
        try:
            yield self
        finally:
            self._run_anchor = previous
            os.close(descriptor)

    @contextmanager
    def _opened_run_directory(self):
        if self._run_anchor is None:
            descriptor = _open_private_directory(
                self.run_directory,
                private_root=_run_private_root(self.run_directory),
            )
        else:
            descriptor = os.dup(self._run_anchor.descriptor)
        try:
            yield descriptor
        finally:
            os.close(descriptor)

    @contextmanager
    def _locked_run_directory(self):
        with self._opened_run_directory() as run_fd:
            with FileLock.at(
                run_fd,
                self.lock_path.name,
                display_path=self.lock_path,
            ):
                yield run_fd

    def create(self, run_id: str) -> RunState:
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        _private_directory(
            self.run_directory,
            private_root=_run_private_root(self.run_directory),
        )
        with self._locked_run_directory() as run_fd:
            if _private_entry_exists_at(
                run_fd, self.state_path.name
            ) or _private_entry_exists_at(run_fd, self.events_path.name):
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
            self._append_event(event, truncate_to=0, run_descriptor=run_fd)
            self._write_snapshot(state, run_descriptor=run_fd)
            return state

    def load(self) -> RunState:
        with self._locked_run_directory() as run_fd:
            self._require_events(run_descriptor=run_fd)
            state, _, _ = self._state_from_events(run_descriptor=run_fd)
            self._assert_snapshot_not_ahead(state, run_descriptor=run_fd)
            snapshot = self._read_snapshot_if_valid(run_descriptor=run_fd)
            if snapshot != state:
                self._write_snapshot(state, run_descriptor=run_fd)
            return state

    def transition(
        self, next_phase: Phase | str, *, expected_revision: int
    ) -> RunState:
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected_revision must be a non-negative integer")
        try:
            target = Phase(next_phase)
        except (TypeError, ValueError) as error:
            raise InvalidTransitionError(
                f"unknown target phase: {next_phase}"
            ) from error
        with self._locked_run_directory() as run_fd:
            self._require_events(run_descriptor=run_fd)
            current, events, parse_info = self._state_from_events(
                include_parse_info=True,
                run_descriptor=run_fd,
            )
            valid_end, torn = parse_info
            self._assert_snapshot_not_ahead(current, run_descriptor=run_fd)
            if current.revision != expected_revision:
                raise StaleRevisionError(
                    f"expected revision {expected_revision}, found {current.revision}"
                )
            if target not in LEGAL_TRANSITIONS[current.phase]:
                raise InvalidTransitionError(
                    f"cannot transition from {current.phase.value} to {target.value}"
                )
            now = _utc_now()
            changed = RunState(
                run_id=current.run_id,
                phase=target,
                revision=current.revision + 1,
                created_at=current.created_at,
                updated_at=now,
            )
            event = StateEvent(
                event_type="phase.transitioned",
                run_id=changed.run_id,
                sequence=events[-1].sequence + 1,
                revision=changed.revision,
                previous_phase=current.phase,
                phase=target,
                occurred_at=now,
                state=changed,
                previous_event_sha256=_event_digest(events[-1]),
                operation_start=None,
                operation_adjudication=None,
                reconciliation_reason=None,
            )
            self._append_event(
                event,
                truncate_to=valid_end if torn else None,
                run_descriptor=run_fd,
            )
            self._write_snapshot(changed, run_descriptor=run_fd)
            return changed

    def reconcile_transition(
        self,
        next_phase: Phase | str,
        *,
        expected_revision: int,
        reason: str = "state-reconciled",
    ) -> RunState:
        """Record a conservative state correction without widening normal flow."""

        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected_revision must be a non-negative integer")
        try:
            target = Phase(next_phase)
        except (TypeError, ValueError) as error:
            raise InvalidTransitionError(
                f"unknown reconciliation target phase: {next_phase}"
            ) from error
        if (
            not isinstance(reason, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", reason) is None
        ):
            raise ValueError("reconciliation reason is invalid")
        with self._locked_run_directory() as run_fd:
            self._require_events(run_descriptor=run_fd)
            current, events, parse_info = self._state_from_events(
                include_parse_info=True,
                run_descriptor=run_fd,
            )
            valid_end, torn = parse_info
            self._assert_snapshot_not_ahead(current, run_descriptor=run_fd)
            if current.revision != expected_revision:
                raise StaleRevisionError(
                    f"expected revision {expected_revision}, found {current.revision}"
                )
            if target not in RECONCILIATION_TRANSITIONS[current.phase]:
                raise InvalidTransitionError(
                    f"cannot reconcile from {current.phase.value} to {target.value}"
                )
            now = _utc_now()
            changed = RunState(
                run_id=current.run_id,
                phase=target,
                revision=current.revision + 1,
                created_at=current.created_at,
                updated_at=now,
            )
            event = StateEvent(
                event_type="phase.reconciled",
                run_id=changed.run_id,
                sequence=events[-1].sequence + 1,
                revision=changed.revision,
                previous_phase=current.phase,
                phase=target,
                occurred_at=now,
                state=changed,
                previous_event_sha256=_event_digest(events[-1]),
                operation_start=None,
                operation_adjudication=None,
                reconciliation_reason=reason,
            )
            self._append_event(
                event,
                truncate_to=valid_end if torn else None,
                run_descriptor=run_fd,
            )
            self._write_snapshot(changed, run_descriptor=run_fd)
            return changed

    def events(self) -> tuple[StateEvent, ...]:
        with self._locked_run_directory() as run_fd:
            self._require_events(run_descriptor=run_fd)
            state, events, _ = self._state_from_events(run_descriptor=run_fd)
            self._assert_snapshot_not_ahead(state, run_descriptor=run_fd)
            return events

    def restore_adjudicated_operation(
        self,
        *,
        mode: str,
        adjudication_id: str,
        expected_revision: int,
    ) -> RunState:
        """Restore only an explicitly adjudicated blocked external operation."""

        if mode not in {"release", "rollback"}:
            raise ValueError("adjudicated operation mode is invalid")
        if (
            not isinstance(adjudication_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", adjudication_id) is None
        ):
            raise ValueError("adjudication_id must be a lowercase SHA-256")
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected_revision must be a non-negative integer")
        target = Phase.RELEASING if mode == "release" else Phase.ROLLING_BACK
        with self._locked_run_directory() as run_fd:
            self._require_events(run_descriptor=run_fd)
            current, events, parse_info = self._state_from_events(
                include_parse_info=True,
                run_descriptor=run_fd,
            )
            valid_end, torn = parse_info
            self._assert_snapshot_not_ahead(current, run_descriptor=run_fd)
            payload = _operation_adjudication_payload(
                run_id=current.run_id,
                mode=mode,
                adjudication_id=adjudication_id,
            )
            existing = [
                event
                for event in events
                if event.event_type == "operation.adjudicated"
                and event.operation_adjudication is not None
                and event.operation_adjudication.get("adjudication_id")
                == adjudication_id
            ]
            if existing:
                event = existing[0]
                if (
                    len(existing) != 1
                    or event.operation_adjudication != payload
                    or event.previous_phase is not Phase.BLOCKED
                    or event.phase is not target
                    or event.revision != expected_revision + 1
                ):
                    raise StateCorruptionError(
                        "operation adjudication restore identity conflicts"
                    )
                if torn:
                    self._truncate_events(valid_end, run_descriptor=run_fd)
                return event.state
            if current.revision != expected_revision:
                raise StaleRevisionError(
                    f"expected revision {expected_revision}, found {current.revision}"
                )
            if current.phase is not Phase.BLOCKED:
                raise InvalidTransitionError(
                    "operation adjudication can restore only a BLOCKED run"
                )
            blocked_event = events[-1]
            blocked_from = Phase.RELEASING if mode == "release" else Phase.ROLLING_BACK
            if (
                blocked_event.event_type != "phase.reconciled"
                or blocked_event.phase is not Phase.BLOCKED
                or blocked_event.previous_phase is not blocked_from
                or blocked_event.reconciliation_reason != "external-operation-unknown"
            ):
                raise InvalidTransitionError(
                    "operation adjudication requires the matching "
                    "external-operation-unknown block"
                )
            now = _utc_now()
            changed = RunState(
                run_id=current.run_id,
                phase=target,
                revision=current.revision + 1,
                created_at=current.created_at,
                updated_at=now,
            )
            event = StateEvent(
                event_type="operation.adjudicated",
                run_id=changed.run_id,
                sequence=events[-1].sequence + 1,
                revision=changed.revision,
                previous_phase=Phase.BLOCKED,
                phase=target,
                occurred_at=now,
                state=changed,
                previous_event_sha256=_event_digest(events[-1]),
                operation_start=None,
                operation_adjudication=payload,
                reconciliation_reason=None,
            )
            self._append_event(
                event,
                truncate_to=valid_end if torn else None,
                run_descriptor=run_fd,
            )
            self._write_snapshot(changed, run_descriptor=run_fd)
            return changed

    def record_operation_start(
        self,
        *,
        cycle_id: str,
        mode: str,
        index: int,
        attempt: int,
        running_receipt_sha256: str,
        idempotency_key: str,
    ) -> StateEvent:
        with self._locked_run_directory() as run_fd:
            self._require_events(run_descriptor=run_fd)
            state, events, parse_info = self._state_from_events(
                include_parse_info=True,
                run_descriptor=run_fd,
            )
            valid_end, torn = parse_info
            self._assert_snapshot_not_ahead(state, run_descriptor=run_fd)
            payload = _operation_start_payload(
                run_id=state.run_id,
                cycle_id=cycle_id,
                mode=mode,
                index=index,
                attempt=attempt,
                running_receipt_sha256=running_receipt_sha256,
                idempotency_key=idempotency_key,
            )
            marker_id = payload["marker_id"]
            existing = [
                event
                for event in events
                if event.event_type == "operation.started"
                and event.operation_start is not None
                and event.operation_start.get("marker_id") == marker_id
            ]
            if existing:
                if len(existing) != 1 or existing[0].operation_start != payload:
                    raise StateCorruptionError(
                        "operation start marker identity conflicts"
                    )
                if torn:
                    self._truncate_events(valid_end, run_descriptor=run_fd)
                return existing[0]
            previous = events[-1]
            now = _utc_now()
            changed = RunState(
                run_id=state.run_id,
                phase=state.phase,
                revision=state.revision + 1,
                created_at=state.created_at,
                updated_at=now,
            )
            event = StateEvent(
                event_type="operation.started",
                run_id=state.run_id,
                sequence=previous.sequence + 1,
                revision=changed.revision,
                previous_phase=state.phase,
                phase=state.phase,
                occurred_at=now,
                state=changed,
                previous_event_sha256=_event_digest(previous),
                operation_start=payload,
                operation_adjudication=None,
                reconciliation_reason=None,
            )
            self._append_event(
                event,
                truncate_to=valid_end if torn else None,
                run_descriptor=run_fd,
            )
            self._write_snapshot(changed, run_descriptor=run_fd)
            return event

    def operation_start_markers(self) -> tuple[StateEvent, ...]:
        return tuple(
            event for event in self.events() if event.event_type == "operation.started"
        )

    def rebuild(self) -> RunState:
        with self._locked_run_directory() as run_fd:
            self._require_events(run_descriptor=run_fd)
            state, _, parse_info = self._state_from_events(
                include_parse_info=True,
                run_descriptor=run_fd,
            )
            valid_end, torn = parse_info
            self._assert_snapshot_not_ahead(state, run_descriptor=run_fd)
            if torn:
                self._truncate_events(valid_end, run_descriptor=run_fd)
            self._write_snapshot(state, run_descriptor=run_fd)
            return state

    def _assert_snapshot_not_ahead(
        self,
        state: RunState,
        *,
        run_descriptor: int,
    ) -> None:
        snapshot = self._read_snapshot_if_valid(run_descriptor=run_descriptor)
        if (
            snapshot is not None
            and snapshot.run_id == state.run_id
            and snapshot.revision > state.revision
        ):
            raise StateCorruptionError(
                "state snapshot proves the event WAL was truncated"
            )

    def _require_events(self, *, run_descriptor: int) -> None:
        try:
            metadata = os.stat(
                self.events_path.name,
                dir_fd=run_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            raise StateNotFoundError(
                f"event log not found: {self.events_path}"
            ) from None
        except OSError as error:
            raise StateCorruptionError(
                "event log cannot be inspected safely"
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > _MAX_STATE_WAL_BYTES
        ):
            raise StateCorruptionError(
                "event log is not a bounded private regular file"
            )

    def _state_from_events(
        self,
        *,
        include_parse_info: bool = False,
        run_descriptor: int,
    ) -> tuple[RunState, tuple[StateEvent, ...], Any]:
        events, valid_end, torn = self._read_events(run_descriptor=run_descriptor)
        if not events:
            raise StateCorruptionError("event log has no complete creation event")
        first = events[0]
        if (
            first.event_type != "run.created"
            or first.sequence != 0
            or first.revision != 0
            or first.previous_phase is not None
            or first.phase is not Phase.INITIALIZED
            or first.previous_event_sha256 is not None
            or first.operation_start is not None
            or first.operation_adjudication is not None
        ):
            raise StateCorruptionError(
                "event log does not start with a valid creation event"
            )
        self._validate_event_state(first)
        previous = first
        for event in events[1:]:
            self._validate_event_state(event)
            if (
                event.run_id != previous.run_id
                or event.sequence != previous.sequence + 1
                or event.previous_event_sha256 != _event_digest(previous)
            ):
                raise StateCorruptionError("event log hash chain is invalid")
            if event.event_type in {"phase.transitioned", "phase.reconciled"}:
                transition_graph = (
                    LEGAL_TRANSITIONS
                    if event.event_type == "phase.transitioned"
                    else RECONCILIATION_TRANSITIONS
                )
                valid = (
                    event.revision == previous.revision + 1
                    and event.previous_phase is previous.phase
                    and event.phase in transition_graph[previous.phase]
                    and event.state.created_at == previous.state.created_at
                    and event.operation_start is None
                )
            elif event.event_type == "operation.started":
                valid = (
                    event.revision == previous.revision + 1
                    and event.previous_phase is previous.phase
                    and event.phase is previous.phase
                    and event.state.created_at == previous.state.created_at
                    and event.operation_start is not None
                    and event.operation_adjudication is None
                )
            elif event.event_type == "operation.adjudicated":
                marker = event.operation_adjudication
                target = (
                    Phase.RELEASING
                    if marker is not None and marker.get("mode") == "release"
                    else Phase.ROLLING_BACK
                )
                valid = (
                    event.revision == previous.revision + 1
                    and event.previous_phase is Phase.BLOCKED
                    and previous.phase is Phase.BLOCKED
                    and event.phase is target
                    and event.state.created_at == previous.state.created_at
                    and event.operation_start is None
                    and marker is not None
                )
            else:
                valid = False
            if not valid:
                raise StateCorruptionError("event log transition chain is invalid")
            previous = event
        parse_info: Any = (valid_end, torn) if include_parse_info else torn
        return previous.state, tuple(events), parse_info

    @staticmethod
    def _validate_event_state(event: StateEvent) -> None:
        if (
            event.state.run_id != event.run_id
            or event.state.revision != event.revision
            or event.state.phase is not event.phase
            or event.state.updated_at != event.occurred_at
        ):
            raise StateCorruptionError("event headers do not match the embedded state")

    def _read_events(
        self,
        *,
        run_descriptor: int,
    ) -> tuple[list[StateEvent], int, bool]:
        data = _read_private_file_at(
            run_descriptor,
            self.events_path.name,
            label="event log",
            max_bytes=_MAX_STATE_WAL_BYTES,
        )
        if data is None:
            raise StateNotFoundError(f"event log not found: {self.events_path}")
        lines = data.splitlines(keepends=True)
        events: list[StateEvent] = []
        valid_end = 0
        torn = False
        for index, line in enumerate(lines):
            is_final = index == len(lines) - 1
            has_newline = line.endswith(b"\n")
            if is_final and not has_newline:
                torn = True
                break
            payload = line[:-1] if has_newline else line
            try:
                raw = json.loads(payload.decode("utf-8"))
                if not isinstance(raw, Mapping):
                    raise ValueError("event must be an object")
                event = StateEvent.from_dict(raw)
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                ValueError,
                TypeError,
            ) as error:
                if is_final and not has_newline:
                    torn = True
                    break
                raise StateCorruptionError(
                    f"corrupt event at line {index + 1}"
                ) from error
            events.append(event)
            valid_end += len(line)
        return events, valid_end, torn

    def _append_event(
        self,
        event: StateEvent,
        *,
        truncate_to: int | None,
        run_descriptor: int,
    ) -> None:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(
                self.events_path.name,
                flags,
                0o600,
                dir_fd=run_descriptor,
            )
        except OSError as error:
            raise StateCorruptionError(
                "event log cannot be opened safely for append"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > _MAX_STATE_WAL_BYTES
            ):
                raise StateCorruptionError(
                    "event log is not a bounded private regular file"
                )
            if truncate_to is not None:
                if truncate_to < 0 or truncate_to > metadata.st_size:
                    raise StateCorruptionError(
                        "event log truncation boundary is invalid"
                    )
                os.ftruncate(descriptor, truncate_to)
            os.lseek(descriptor, 0, os.SEEK_END)
            payload = (
                json.dumps(
                    event.to_dict(),
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
            current_size = os.lseek(descriptor, 0, os.SEEK_CUR)
            if current_size + len(payload) > _MAX_STATE_WAL_BYTES:
                raise StateCorruptionError("event log exceeds its size limit")
            try:
                current = os.stat(
                    self.events_path.name,
                    dir_fd=run_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise StateCorruptionError("event log changed before append") from error
            if (metadata.st_dev, metadata.st_ino) != (
                current.st_dev,
                current.st_ino,
            ):
                raise StateCorruptionError("event log changed before append")
            while payload:
                written = os.write(descriptor, payload)
                payload = payload[written:]
            os.fsync(descriptor)
            after = os.stat(
                self.events_path.name,
                dir_fd=run_descriptor,
                follow_symlinks=False,
            )
            opened_after = os.fstat(descriptor)
            if (opened_after.st_dev, opened_after.st_ino) != (
                after.st_dev,
                after.st_ino,
            ):
                raise StateCorruptionError("event log changed during append")
        finally:
            os.close(descriptor)
        os.fsync(run_descriptor)

    def _truncate_events(self, valid_end: int, *, run_descriptor: int) -> None:
        try:
            descriptor = os.open(
                self.events_path.name,
                os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=run_descriptor,
            )
        except OSError as error:
            raise StateCorruptionError(
                "event log cannot be opened safely for truncation"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or valid_end < 0
                or valid_end > metadata.st_size
            ):
                raise StateCorruptionError("event log truncation target is invalid")
            os.ftruncate(descriptor, valid_end)
            os.fsync(descriptor)
            current = os.stat(
                self.events_path.name,
                dir_fd=run_descriptor,
                follow_symlinks=False,
            )
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (
                current.st_dev,
                current.st_ino,
            ):
                raise StateCorruptionError("event log changed during truncation")
        finally:
            os.close(descriptor)
        os.fsync(run_descriptor)

    def _read_snapshot_if_valid(self, *, run_descriptor: int) -> RunState | None:
        try:
            data = _read_private_file_at(
                run_descriptor,
                self.state_path.name,
                label="state snapshot",
                max_bytes=_MAX_STATE_SNAPSHOT_BYTES,
                missing_ok=True,
            )
            if data is None:
                return None
            raw = json.loads(data.decode("utf-8"))
            if not isinstance(raw, Mapping):
                return None
            return RunState.from_dict(raw)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            TypeError,
        ):
            return None

    def _write_snapshot(self, state: RunState, *, run_descriptor: int) -> None:
        if _private_entry_exists_at(run_descriptor, self.state_path.name):
            metadata = os.stat(
                self.state_path.name,
                dir_fd=run_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise StateCorruptionError(
                    "state snapshot is not a private regular file"
                )
        temporary_name = f".state.{secrets.token_hex(16)}.tmp"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=run_descriptor,
            )
            os.fchmod(descriptor, 0o600)
            payload = _canonical_json_bytes(state.to_dict())
            if len(payload) > _MAX_STATE_SNAPSHOT_BYTES:
                raise StateCorruptionError("state snapshot exceeds its size limit")
            while payload:
                written = os.write(descriptor, payload)
                payload = payload[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.rename(
                temporary_name,
                self.state_path.name,
                src_dir_fd=run_descriptor,
                dst_dir_fd=run_descriptor,
            )
            os.chmod(
                self.state_path.name,
                0o600,
                dir_fd=run_descriptor,
                follow_symlinks=False,
            )
            os.fsync(run_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=run_descriptor)
            except FileNotFoundError:
                pass
