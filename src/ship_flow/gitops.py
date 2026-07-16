from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
from contextlib import nullcontext
from dataclasses import asdict, dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Sequence

from .store import (
    FileLock,
    PrivateRootAnchor,
    StateCorruptionError,
    StateNotFoundError,
    _atomic_write_private_json as _store_atomic_write_private_json,
    _create_private_directory_anchor,
    _open_existing_private_directory_from_anchor,
    _read_bounded_private_file,
    _remove_private_file,
)


class GitOperationError(RuntimeError):
    pass


class GitCommandError(GitOperationError):
    def __init__(self, arguments: Sequence[str], stderr: str):
        self.arguments = tuple(arguments)
        self.stderr = stderr
        super().__init__(f"git command failed: {stderr.strip()}")


class InvalidBranchError(GitOperationError):
    pass


class BareRepositoryError(GitOperationError):
    pass


class ResourceCollisionError(GitOperationError):
    pass


class DirtyBaseError(GitOperationError):
    pass


class OwnershipError(GitOperationError):
    pass


@dataclass(frozen=True)
class CandidateSafetyFinding:
    path: str
    reasons: tuple[str, ...]


class CandidateSafetyError(GitOperationError):
    def __init__(self, findings: Sequence[CandidateSafetyFinding]):
        self.findings = tuple(findings)
        super().__init__("candidate contains files that require confirmation")


class CandidateCommitPartialError(GitOperationError):
    def __init__(
        self,
        identity: "CandidateIdentity",
        *,
        stage: str,
        cause: BaseException,
    ):
        self.identity = identity
        self.stage = stage
        self.cause = cause
        super().__init__(
            f"candidate {identity.commit_oid} was created but {stage} did not finish"
        )


class CandidateRecoveryBlockedError(GitOperationError):
    def __init__(self, observed_oid: str, *, old_oid: str, new_oid: str):
        self.observed_oid = observed_oid
        self.old_oid = old_oid
        self.new_oid = new_oid
        super().__init__(
            "candidate recovery blocked: branch is at neither recorded OID "
            f"({observed_oid})"
        )


class CleanupRefusedError(GitOperationError):
    def __init__(self, conditions: Sequence[str]):
        self.conditions = tuple(sorted(set(conditions)))
        super().__init__("cleanup refused: " + ", ".join(self.conditions))


class CleanupPartialError(GitOperationError):
    def __init__(self, *, stage: str, cause: BaseException):
        self.stage = stage
        self.cause = cause
        super().__init__(f"cleanup started but {stage} did not finish")


class CleanupRecoveryBlockedError(GitOperationError):
    def __init__(self, condition: str):
        self.condition = condition
        super().__init__(f"cleanup recovery blocked: {condition}")


@dataclass(frozen=True)
class GitRepository:
    primary_checkout: Path
    git_common_directory: Path

    @classmethod
    def discover(cls, start: Path | str) -> "GitRepository":
        location = Path(start).expanduser().resolve()
        if location.is_file():
            location = location.parent
        is_bare = _git(
            location, "rev-parse", "--is-bare-repository"
        ).stdout.removesuffix("\n")
        if is_bare == "true":
            raise BareRepositoryError(f"bare repositories are unsupported: {location}")
        common_output = _git_output_line(
            _git(location, "rev-parse", "--git-common-dir").stdout
        )
        common_path = Path(common_output)
        if not common_path.is_absolute():
            common_path = location / common_path
        common_directory = common_path.resolve()

        listing = _git(location, "worktree", "list", "--porcelain", "-z").stdout.split(
            "\0"
        )
        try:
            first_worktree = next(
                item.removeprefix("worktree ")
                for item in listing
                if item.startswith("worktree ")
            )
        except StopIteration as error:
            raise GitOperationError("repository has no primary checkout") from error
        return cls(
            primary_checkout=Path(first_worktree).resolve(),
            git_common_directory=common_directory,
        )


@dataclass
class WorktreeOwnership:
    run_id: str
    primary_checkout: Path
    git_common_directory: Path
    worktree_path: Path
    branch: str
    base_oid: str
    last_known_oid: str
    git_backlink: Path
    record_path: Path


@dataclass(frozen=True)
class CandidateIdentity:
    commit_oid: str
    tree_oid: str


@dataclass(frozen=True)
class CleanupPreflight:
    target_oid: str
    ownership_record_sha256: str
    branch_oid: str
    approved_conditions: tuple[str, ...]
    delete_branch: bool


def load_run_worktree(
    repository: GitRepository,
    run_id: str,
) -> WorktreeOwnership:
    """Load an existing run worktree after validating its ownership record."""

    return _load_run_worktree(repository, run_id, lock_held=False)


def _load_run_worktree_locked(
    repository: GitRepository,
    run_id: str,
) -> WorktreeOwnership:
    """Load ownership while the caller holds the repository lock."""

    return _load_run_worktree(repository, run_id, lock_held=True)


def _load_run_worktree(
    repository: GitRepository,
    run_id: str,
    *,
    lock_held: bool,
) -> WorktreeOwnership:
    if not isinstance(repository, GitRepository):
        raise TypeError("repository must be a discovered GitRepository")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id):
        raise ValueError("run_id contains unsafe characters")
    record_path = _ownership_path(repository, run_id)
    expected_keys = {
        "run_id",
        "primary_checkout",
        "git_common_directory",
        "worktree_path",
        "branch",
        "base_oid",
        "last_known_oid",
        "git_backlink",
    }
    lock_context = (
        nullcontext()
        if lock_held
        else FileLock.repository(repository.git_common_directory)
    )
    with lock_context:
        directory_flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        run_descriptor: int | None = None
        try:
            run_descriptor = os.open(repository.git_common_directory, directory_flags)
            for component in ("ship-flow", "runs", run_id):
                metadata = os.stat(
                    component,
                    dir_fd=run_descriptor,
                    follow_symlinks=False,
                )
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise OwnershipError(
                        "run ownership path contains an unsafe ancestor"
                    )
                child_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=run_descriptor,
                )
                os.close(run_descriptor)
                run_descriptor = child_descriptor
            descriptor = os.open(
                "worktree.json",
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=run_descriptor,
            )
        except OwnershipError:
            if run_descriptor is not None:
                os.close(run_descriptor)
            raise
        except OSError as error:
            if run_descriptor is not None:
                os.close(run_descriptor)
            raise OwnershipError(
                "run ownership record cannot be opened safely"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise OwnershipError(
                    "run ownership record is not a regular private file"
                )
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = os.read(descriptor, 65_536)
                if not chunk:
                    break
                size += len(chunk)
                if size > 65_536:
                    raise OwnershipError("run ownership record is too large")
                chunks.append(chunk)
            raw = b"".join(chunks)
            current = os.stat(
                "worktree.json",
                dir_fd=run_descriptor,
                follow_symlinks=False,
            )
            if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
                raise OwnershipError("run ownership record changed while loading")
        except OwnershipError:
            raise
        except OSError as error:
            raise OwnershipError("run ownership record cannot be inspected") from error
        finally:
            os.close(descriptor)
            if run_descriptor is not None:
                os.close(run_descriptor)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise OwnershipError("run ownership record is corrupt") from error
        if (
            not isinstance(payload, dict)
            or set(payload) != expected_keys
            or any(not isinstance(payload[key], str) for key in expected_keys)
            or payload["run_id"] != run_id
            or not payload["branch"]
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", payload["base_oid"])
            is None
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", payload["last_known_oid"])
            is None
        ):
            raise OwnershipError("run ownership record schema is invalid")

        path_fields = {
            key: Path(payload[key])
            for key in (
                "primary_checkout",
                "git_common_directory",
                "worktree_path",
                "git_backlink",
            )
        }
        if any(
            not path.is_absolute() or path.resolve(strict=False) != path
            for path in path_fields.values()
        ):
            raise OwnershipError("run ownership paths are not canonical")
        ownership = WorktreeOwnership(
            run_id=run_id,
            primary_checkout=path_fields["primary_checkout"],
            git_common_directory=path_fields["git_common_directory"],
            worktree_path=path_fields["worktree_path"],
            branch=payload["branch"],
            base_oid=payload["base_oid"],
            last_known_oid=payload["last_known_oid"],
            git_backlink=path_fields["git_backlink"],
            record_path=record_path,
        )
        try:
            _ownership_record_state(ownership)
            _recover_pending_candidate_locked(ownership)
        except OwnershipError:
            raise
        except GitOperationError:
            raise
        if (
            ownership.primary_checkout != repository.primary_checkout
            or ownership.git_common_directory != repository.git_common_directory
            or _current_ownership_record_sha256(ownership) is None
        ):
            raise OwnershipError("run worktree ownership is not current")
        _finalize_creation_intent_for_ownership_locked(repository, ownership)
        return ownership


def _git_output_line(output: str) -> str:
    return output.removesuffix("\n")


def _git(
    cwd: Path,
    *arguments: str,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    process_environment = os.environ.copy()
    if env:
        process_environment.update(env)
    completed = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        env=process_environment,
        check=False,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and completed.returncode:
        raise GitCommandError(arguments, completed.stderr)
    return completed


def _git_bytes(
    cwd: Path,
    *arguments: str,
    env: dict[str, str] | None = None,
) -> bytes:
    process_environment = os.environ.copy()
    if env:
        process_environment.update(env)
    completed = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        env=process_environment,
        check=False,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode:
        raise GitCommandError(
            arguments, completed.stderr.decode("utf-8", errors="replace")
        )
    return completed.stdout


def _resolve_commit(cwd: Path, revision: str) -> str:
    return _git(
        cwd,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{revision}^{{commit}}",
    ).stdout.removesuffix("\n")


def _ownership_path(repository: GitRepository, run_id: str) -> Path:
    return (
        repository.git_common_directory
        / "ship-flow"
        / "runs"
        / run_id
        / "worktree.json"
    )


def _fsync_directory_path(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_private_json(
    path: Path,
    payload: dict[str, object],
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> None:
    _store_atomic_write_private_json(
        path,
        payload,
        trusted_root=trusted_root,
    )


def _remove_durable_file(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> None:
    _remove_private_file(path, trusted_root=trusted_root)


def _candidate_receipt_path(ownership: WorktreeOwnership) -> Path:
    return ownership.record_path.parent / "candidate-operation.json"


def _cleanup_receipt_path(ownership: WorktreeOwnership) -> Path:
    return ownership.record_path.parent / "cleanup-operation.json"


def _ownership_runtime_root(ownership: WorktreeOwnership) -> Path:
    return ownership.git_common_directory / "ship-flow"


def _create_staged_ownership_anchor(
    ownership: WorktreeOwnership,
) -> PrivateRootAnchor:
    directory = ownership.record_path.parent
    runtime_root = _ownership_runtime_root(ownership)
    for _ in range(16):
        staged_directory = directory.parent / (
            f".{directory.name}.creating-{secrets.token_hex(16)}"
        )
        try:
            return _create_private_directory_anchor(
                staged_directory,
                trusted_root=runtime_root,
            )
        except FileExistsError:
            continue
    raise ResourceCollisionError("could not allocate a private ownership staging path")


def _rename_directory_noreplace_at(
    parent_descriptor: int,
    source_name: str,
    destination_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameatx_np", None)
    flags = 0x00000004  # Darwin RENAME_EXCL
    if function is None:
        function = getattr(libc, "renameat2", None)
        flags = 0x00000001  # Linux RENAME_NOREPLACE
    if function is None:
        raise OwnershipError(
            "this platform cannot publish ownership without replacement"
        )
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = function(
        parent_descriptor,
        os.fsencode(source_name),
        parent_descriptor,
        os.fsencode(destination_name),
        flags,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ResourceCollisionError(
            "run ownership destination appeared before publication"
        )
    raise OSError(error_number, os.strerror(error_number), destination_name)


def _require_visible_private_directory_identity(
    path: Path,
    descriptor: int,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> tuple[int, int]:
    try:
        opened = os.fstat(descriptor)
        visible = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise ResourceCollisionError(
            "ownership publication parent cannot be inspected safely"
        ) from error
    opened_identity = (opened.st_dev, opened.st_ino)
    visible_identity = (visible.st_dev, visible.st_ino)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != 0o700
        or not stat.S_ISDIR(visible.st_mode)
        or stat.S_IMODE(visible.st_mode) != 0o700
        or visible_identity != opened_identity
        or (expected_identity is not None and opened_identity != expected_identity)
    ):
        raise ResourceCollisionError(
            "ownership publication parent changed during publication"
        )
    return opened_identity


def _publish_staged_ownership_directory_locked(
    ownership: WorktreeOwnership,
    anchor: PrivateRootAnchor,
) -> None:
    staged_directory = Path(os.path.abspath(anchor.path))
    directory = ownership.record_path.parent
    if staged_directory.parent != directory.parent or staged_directory == directory:
        raise OwnershipError("ownership staging directory is invalid")
    expected = os.fstat(anchor.descriptor)
    if not stat.S_ISDIR(expected.st_mode) or stat.S_IMODE(expected.st_mode) != 0o700:
        raise OwnershipError("ownership staging directory is not private")
    parent_descriptor = _open_existing_private_directory_from_anchor(
        directory.parent,
        trusted_root=_ownership_runtime_root(ownership),
    )
    try:
        parent_identity = _require_visible_private_directory_identity(
            directory.parent,
            parent_descriptor,
        )
        staged = os.stat(
            staged_directory.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(staged.st_mode) or (staged.st_dev, staged.st_ino) != (
            expected.st_dev,
            expected.st_ino,
        ):
            raise ResourceCollisionError(
                "ownership staging directory changed before publication"
            )
        _require_staged_ownership_record(ownership, anchor)
        _require_visible_private_directory_identity(
            directory.parent,
            parent_descriptor,
            expected_identity=parent_identity,
        )
        _rename_directory_noreplace_at(
            parent_descriptor,
            staged_directory.name,
            directory.name,
        )
        _require_visible_private_directory_identity(
            directory.parent,
            parent_descriptor,
            expected_identity=parent_identity,
        )
        published = os.stat(
            directory.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(published.st_mode) or (
            published.st_dev,
            published.st_ino,
        ) != (expected.st_dev, expected.st_ino):
            raise OwnershipError(
                "published ownership directory changed during publication"
            )
        _require_staged_ownership_record(ownership, anchor)
        os.fsync(parent_descriptor)
        _require_visible_private_directory_identity(
            directory.parent,
            parent_descriptor,
            expected_identity=parent_identity,
        )
    finally:
        os.close(parent_descriptor)


def _write_ownership(ownership: WorktreeOwnership) -> None:
    anchor = _create_staged_ownership_anchor(ownership)
    payload = {
        key: str(value) if isinstance(value, Path) else value
        for key, value in asdict(ownership).items()
        if key != "record_path"
    }
    try:
        _atomic_write_private_json(
            anchor.path / ownership.record_path.name,
            payload,
            trusted_root=anchor,
        )
        _record_creation_run_directory_locked(ownership, anchor)
    finally:
        os.close(anchor.descriptor)


def _replace_ownership_record(ownership: WorktreeOwnership) -> None:
    if ownership.record_path.is_symlink() or not ownership.record_path.is_file():
        raise OwnershipError("ownership record is not a regular file")
    _atomic_write_private_json(
        ownership.record_path,
        _ownership_payload(ownership),
        trusted_root=_ownership_runtime_root(ownership),
    )


def _ownership_payload(ownership: WorktreeOwnership) -> dict[str, str]:
    return {
        key: str(value) if isinstance(value, Path) else value
        for key, value in asdict(ownership).items()
        if key != "record_path"
    }


def _canonical_json_sha256(payload: object) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _ownership_record_state(ownership: WorktreeOwnership) -> tuple[str, str]:
    try:
        repository = GitRepository.discover(ownership.primary_checkout)
        expected_record_path = _ownership_path(repository, ownership.run_id)
        if repository.git_common_directory != ownership.git_common_directory:
            raise OwnershipError("ownership Git directory changed")
        if repository.primary_checkout != ownership.primary_checkout:
            raise OwnershipError("ownership primary checkout changed")
        if ownership.record_path != expected_record_path:
            raise OwnershipError("ownership record path changed")
        if ownership.record_path.is_symlink() or not ownership.record_path.is_file():
            raise OwnershipError("ownership record is not a regular file")
        record = json.loads(ownership.record_path.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            raise OwnershipError("ownership record is not an object")
        last_known_oid = record.get("last_known_oid")
        if not isinstance(last_known_oid, str):
            raise OwnershipError("ownership record has no last known OID")
        expected = _ownership_payload(ownership)
        expected["last_known_oid"] = last_known_oid
        if record != expected:
            raise OwnershipError("ownership record does not match this run")
        if ownership.worktree_path.is_symlink() or not ownership.worktree_path.is_dir():
            raise OwnershipError("owned worktree is not a real directory")
        if ownership.worktree_path.resolve() != ownership.worktree_path:
            raise OwnershipError("owned worktree path is not canonical")
        if GitRepository.discover(ownership.worktree_path) != repository:
            raise OwnershipError("owned worktree repository changed")
        backlink = _linked_git_backlink(ownership.worktree_path)
        if backlink != ownership.git_backlink:
            raise OwnershipError("owned worktree backlink changed")
        backlink.relative_to(repository.git_common_directory / "worktrees")
        current_branch = _git_output_line(
            _git(ownership.worktree_path, "branch", "--show-current").stdout
        )
        if current_branch != ownership.branch:
            raise OwnershipError("owned worktree branch changed")
        return last_known_oid, _canonical_json_sha256(record)
    except OwnershipError:
        raise
    except (GitOperationError, OSError, ValueError, json.JSONDecodeError) as error:
        raise OwnershipError("ownership record could not be validated") from error


def _ownership_record_last_known(ownership: WorktreeOwnership) -> str:
    return _ownership_record_state(ownership)[0]


def _current_ownership_record_sha256(
    ownership: WorktreeOwnership,
) -> str | None:
    try:
        record_last_known, record_sha256 = _ownership_record_state(ownership)
        if record_last_known != ownership.last_known_oid:
            return None
        head_oid = _git_output_line(
            _git(
                ownership.worktree_path, "rev-parse", "--verify", "HEAD^{commit}"
            ).stdout
        )
        branch_oid = _git_output_line(
            _git(
                ownership.worktree_path,
                "rev-parse",
                "--verify",
                f"refs/heads/{ownership.branch}^{{commit}}",
            ).stdout
        )
        if (
            head_oid != ownership.last_known_oid
            or branch_oid != ownership.last_known_oid
        ):
            return None
        ancestor = _git(
            ownership.worktree_path,
            "merge-base",
            "--is-ancestor",
            ownership.base_oid,
            record_last_known,
            check=False,
        )
        if ancestor.returncode != 0:
            return None
        return record_sha256
    except (GitOperationError, OSError, ValueError):
        return None


def _ownership_is_current(ownership: WorktreeOwnership) -> bool:
    return _current_ownership_record_sha256(ownership) is not None


def _linked_git_backlink(worktree_path: Path) -> Path:
    marker = worktree_path / ".git"
    if marker.is_symlink() or not marker.is_file():
        raise GitOperationError("linked worktree Git backlink is not a regular file")
    try:
        value = _git_output_line(marker.read_text(encoding="utf-8"))
    except OSError as error:
        raise GitOperationError(
            "linked worktree has no readable Git backlink"
        ) from error
    prefix = "gitdir: "
    if not value.startswith(prefix):
        raise GitOperationError("linked worktree Git backlink is malformed")
    backlink = Path(value.removeprefix(prefix))
    if not backlink.is_absolute():
        backlink = marker.parent / backlink
    return backlink.resolve()


def _is_registered_run_worktree(
    repository: GitRepository,
    *,
    worktree_path: Path,
    branch: str,
    base_oid: str,
) -> bool:
    fields = _git(
        repository.primary_checkout,
        "worktree",
        "list",
        "--porcelain",
        "-z",
    ).stdout.split("\0")
    for index, field in enumerate(fields):
        if not field.startswith("worktree "):
            continue
        listed_path = Path(field.removeprefix("worktree ")).resolve()
        if listed_path != worktree_path:
            continue
        record: set[str] = set()
        for detail in fields[index + 1 :]:
            if not detail or detail.startswith("worktree "):
                break
            record.add(detail)
        if f"HEAD {base_oid}" not in record:
            return False
        if f"branch refs/heads/{branch}" not in record:
            return False
        try:
            backlink = _linked_git_backlink(worktree_path)
            backlink.relative_to(repository.git_common_directory / "worktrees")
        except (GitOperationError, ValueError):
            return False
        return True
    return False


def _compensate_run_creation(
    repository: GitRepository,
    *,
    worktree_path: Path,
    branch: str,
    base_oid: str,
    created_branch: bool = True,
) -> None:
    if not created_branch:
        return
    branch_ref = f"refs/heads/{branch}"
    if _is_registered_run_worktree(
        repository,
        worktree_path=worktree_path,
        branch=branch,
        base_oid=base_oid,
    ):
        removed = _git(
            repository.primary_checkout,
            "worktree",
            "remove",
            "--",
            str(worktree_path),
            check=False,
        )
        if removed.returncode:
            return
    _git(
        repository.primary_checkout,
        "update-ref",
        "-d",
        branch_ref,
        base_oid,
        check=False,
    )


_CREATION_INTENT_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "primary_checkout",
        "git_common_directory",
        "worktree_path",
        "branch",
        "base_ref",
        "base_oid",
        "require_clean_base",
        "git_backlink",
        "staging_directory",
        "run_directory_device",
        "run_directory_inode",
        "stage",
    }
)


def _creation_intent_path(repository: GitRepository, run_id: str) -> Path:
    return (
        repository.git_common_directory
        / "ship-flow"
        / "creation-intents"
        / f"{run_id}.json"
    )


def _validate_creation_intent(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict) or set(payload) != _CREATION_INTENT_KEYS:
        raise OwnershipError("worktree creation intent schema is invalid")
    backlink = payload.get("git_backlink")
    staging_directory = payload.get("staging_directory")
    run_device = payload.get("run_directory_device")
    run_inode = payload.get("run_directory_inode")
    stage = payload.get("stage")
    if (
        payload.get("schema_version") != 1
        or not isinstance(payload.get("run_id"), str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", str(payload["run_id"]))
        is None
        or not isinstance(payload.get("primary_checkout"), str)
        or not isinstance(payload.get("git_common_directory"), str)
        or not isinstance(payload.get("worktree_path"), str)
        or not isinstance(payload.get("branch"), str)
        or not payload["branch"]
        or not isinstance(payload.get("base_ref"), str)
        or not payload["base_ref"]
        or not isinstance(payload.get("base_oid"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", str(payload["base_oid"]))
        is None
        or type(payload.get("require_clean_base")) is not bool
        or stage
        not in {
            "prepared",
            "worktree-added",
            "run-directory-staged",
            "run-directory-created",
        }
        or (stage == "prepared" and backlink is not None)
        or (
            stage
            in {
                "worktree-added",
                "run-directory-staged",
                "run-directory-created",
            }
            and (not isinstance(backlink, str) or not backlink)
        )
        or (
            stage in {"prepared", "worktree-added"}
            and (
                staging_directory is not None
                or run_device is not None
                or run_inode is not None
            )
        )
        or (
            stage in {"run-directory-staged", "run-directory-created"}
            and (
                type(run_device) is not int
                or run_device < 0
                or type(run_inode) is not int
                or run_inode < 1
            )
        )
        or (
            stage == "run-directory-staged"
            and (not isinstance(staging_directory, str) or not staging_directory)
        )
        or (stage == "run-directory-created" and staging_directory is not None)
    ):
        raise OwnershipError("worktree creation intent is invalid")
    path_keys = ("primary_checkout", "git_common_directory", "worktree_path")
    if backlink is not None:
        path_keys = (*path_keys, "git_backlink")
    if staging_directory is not None:
        path_keys = (*path_keys, "staging_directory")
    for key in path_keys:
        value = Path(str(payload[key]))
        if not value.is_absolute() or value.resolve(strict=False) != value:
            raise OwnershipError("worktree creation intent paths are not canonical")
    if staging_directory is not None:
        staged_path = Path(staging_directory)
        expected_parent = (
            Path(str(payload["git_common_directory"])) / "ship-flow" / "runs"
        )
        expected_name = re.compile(
            rf"\.{re.escape(str(payload['run_id']))}\.creating-[0-9a-f]{{32}}"
        )
        if (
            staged_path.parent != expected_parent
            or expected_name.fullmatch(staged_path.name) is None
        ):
            raise OwnershipError("worktree creation staging path is invalid")
    return dict(payload)


def _load_creation_intent_locked(
    repository: GitRepository,
    run_id: str,
) -> dict[str, object] | None:
    path = _creation_intent_path(repository, run_id)
    try:
        raw = _read_bounded_private_file(
            path,
            trusted_root=repository.git_common_directory / "ship-flow",
            label="worktree creation intent",
            max_bytes=65_536,
        )
    except StateNotFoundError:
        return None
    except StateCorruptionError as error:
        raise OwnershipError(
            "worktree creation intent cannot be opened safely"
        ) from error
    try:
        payload = json.loads(raw.decode("utf-8"))
        canonical = (
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise OwnershipError("worktree creation intent is corrupt") from error
    if raw != canonical:
        raise OwnershipError("worktree creation intent is not canonical")
    return _validate_creation_intent(payload)


def _write_creation_intent_locked(
    repository: GitRepository,
    payload: dict[str, object],
    *,
    stage: str,
    git_backlink: Path | None,
    staging_directory: Path | None = None,
    run_directory_identity: tuple[int, int] | None = None,
) -> dict[str, object]:
    changed = {
        **payload,
        "stage": stage,
        "git_backlink": None if git_backlink is None else str(git_backlink),
        "staging_directory": (
            None if staging_directory is None else str(staging_directory)
        ),
        "run_directory_device": (
            None if run_directory_identity is None else run_directory_identity[0]
        ),
        "run_directory_inode": (
            None if run_directory_identity is None else run_directory_identity[1]
        ),
    }
    changed = _validate_creation_intent(changed)
    _atomic_write_private_json(
        _creation_intent_path(repository, str(changed["run_id"])),
        changed,
        trusted_root=repository.git_common_directory / "ship-flow",
    )
    return changed


def _record_creation_run_directory_locked(
    ownership: WorktreeOwnership,
    anchor: PrivateRootAnchor,
) -> None:
    repository = GitRepository(
        primary_checkout=ownership.primary_checkout,
        git_common_directory=ownership.git_common_directory,
    )
    intent = _load_creation_intent_locked(repository, ownership.run_id)
    if intent is None:
        raise OwnershipError("worktree ownership has no creation intent")
    if (
        intent["primary_checkout"] != str(ownership.primary_checkout)
        or intent["git_common_directory"] != str(ownership.git_common_directory)
        or intent["worktree_path"] != str(ownership.worktree_path)
        or intent["branch"] != ownership.branch
        or intent["base_oid"] != ownership.base_oid
        or intent["git_backlink"] != str(ownership.git_backlink)
    ):
        raise OwnershipError(
            "worktree creation intent does not match the ownership record"
        )
    if intent["stage"] != "worktree-added":
        raise OwnershipError(
            "worktree creation intent cannot stage another run directory"
        )
    metadata = os.fstat(anchor.descriptor)
    identity = (metadata.st_dev, metadata.st_ino)
    _write_creation_intent_locked(
        repository,
        intent,
        stage="run-directory-staged",
        git_backlink=ownership.git_backlink,
        staging_directory=anchor.path,
        run_directory_identity=identity,
    )
    _require_staged_ownership_record(ownership, anchor)
    _publish_staged_ownership_directory_locked(ownership, anchor)


def _open_intent_owned_directory_locked(
    repository: GitRepository,
    directory: Path,
    intent: dict[str, object],
) -> int:
    if intent["stage"] not in {
        "run-directory-staged",
        "run-directory-created",
    }:
        raise ResourceCollisionError(
            "run directory is not bound by the creation intent"
        )
    expected_identity = (
        intent["run_directory_device"],
        intent["run_directory_inode"],
    )
    try:
        descriptor = _open_existing_private_directory_from_anchor(
            directory,
            trusted_root=repository.git_common_directory / "ship-flow",
        )
    except (OSError, StateCorruptionError, ValueError) as error:
        raise ResourceCollisionError(
            "intent-owned run directory cannot be opened safely"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != expected_identity:
            raise ResourceCollisionError(
                "run directory inode does not match the creation intent"
            )
        current = os.stat(directory, follow_symlinks=False)
        if (
            not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino) != expected_identity
        ):
            raise ResourceCollisionError("intent-owned run directory was replaced")
        return descriptor
    except ResourceCollisionError:
        os.close(descriptor)
        raise
    except OSError as error:
        os.close(descriptor)
        raise ResourceCollisionError(
            "intent-owned run directory changed while being inspected"
        ) from error


def _require_staged_ownership_record(
    ownership: WorktreeOwnership,
    anchor: PrivateRootAnchor,
) -> None:
    if os.listdir(anchor.descriptor) != [ownership.record_path.name]:
        raise ResourceCollisionError(
            "ownership staging directory contains foreign entries"
        )
    try:
        raw = _read_bounded_private_file(
            anchor.path / ownership.record_path.name,
            trusted_root=anchor,
            label="staged worktree ownership",
            max_bytes=65_536,
        )
        payload = json.loads(raw.decode("utf-8"))
        canonical = (
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
    except (
        OSError,
        StateCorruptionError,
        StateNotFoundError,
        UnicodeDecodeError,
        ValueError,
    ) as error:
        raise ResourceCollisionError(
            "staged worktree ownership cannot be validated"
        ) from error
    if raw != canonical or payload != _ownership_payload(ownership):
        raise ResourceCollisionError("staged worktree ownership changed")


def _recover_staged_ownership_directory_locked(
    repository: GitRepository,
    ownership: WorktreeOwnership,
    intent: dict[str, object],
) -> None:
    directory = ownership.record_path.parent
    if os.path.lexists(directory):
        descriptor = _open_intent_owned_directory_locked(
            repository,
            directory,
            intent,
        )
        os.close(descriptor)
        return

    staged_directory = Path(str(intent["staging_directory"]))
    descriptor = _open_intent_owned_directory_locked(
        repository,
        staged_directory,
        intent,
    )
    try:
        anchor = PrivateRootAnchor(staged_directory, descriptor)
        _require_staged_ownership_record(ownership, anchor)
        _publish_staged_ownership_directory_locked(ownership, anchor)
    finally:
        os.close(descriptor)


def _write_recovered_ownership_locked(
    repository: GitRepository,
    ownership: WorktreeOwnership,
    intent: dict[str, object],
) -> None:
    directory = ownership.record_path.parent
    if intent["stage"] != "run-directory-created":
        raise ResourceCollisionError(
            "existing run directory is not bound by the creation intent"
        )
    descriptor = _open_intent_owned_directory_locked(
        repository,
        directory,
        intent,
    )
    try:
        expected_identity = (
            intent["run_directory_device"],
            intent["run_directory_inode"],
        )
        if os.listdir(descriptor):
            raise ResourceCollisionError(
                "intent-owned run directory contains foreign entries"
            )
        try:
            current = os.stat(directory, follow_symlinks=False)
        except OSError as error:
            raise ResourceCollisionError(
                "intent-owned run directory cannot be inspected"
            ) from error
        if (current.st_dev, current.st_ino) != expected_identity:
            raise ResourceCollisionError(
                "intent-owned run directory was replaced before recovery"
            )
        anchor = PrivateRootAnchor(directory, descriptor)
        _atomic_write_private_json(
            ownership.record_path,
            _ownership_payload(ownership),
            trusted_root=anchor,
        )
        current = os.stat(directory, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != expected_identity:
            raise ResourceCollisionError(
                "intent-owned run directory was replaced during recovery"
            )
    finally:
        os.close(descriptor)


def _remove_creation_intent_locked(
    repository: GitRepository,
    run_id: str,
) -> None:
    _remove_private_file(
        _creation_intent_path(repository, run_id),
        trusted_root=repository.git_common_directory / "ship-flow",
        missing_ok=True,
    )


def _creation_request_matches(
    intent: dict[str, object],
    repository: GitRepository,
    *,
    run_id: str,
    branch: str,
    worktree_path: Path,
    base_ref: str,
    require_clean_base: bool,
) -> bool:
    return (
        intent["run_id"] == run_id
        and intent["primary_checkout"] == str(repository.primary_checkout)
        and intent["git_common_directory"] == str(repository.git_common_directory)
        and intent["worktree_path"] == str(worktree_path)
        and intent["branch"] == branch
        and intent["base_ref"] == base_ref
        and intent["require_clean_base"] is require_clean_base
    )


def _staged_creation_requires_recovery(
    repository: GitRepository,
    *,
    run_id: str,
    branch: str,
    worktree_path: Path,
    base_ref: str,
    base_oid: str,
    require_clean_base: bool,
) -> bool:
    try:
        intent = _load_creation_intent_locked(repository, run_id)
    except OwnershipError:
        return False
    return (
        intent is not None
        and intent["stage"] == "run-directory-staged"
        and intent["base_oid"] == base_oid
        and _creation_request_matches(
            intent,
            repository,
            run_id=run_id,
            branch=branch,
            worktree_path=worktree_path,
            base_ref=base_ref,
            require_clean_base=require_clean_base,
        )
    )


def _creation_resources_are_absent(
    repository: GitRepository,
    *,
    branch: str,
    worktree_path: Path,
    record_path: Path,
) -> bool:
    return (
        _branch_oid_or_none(repository, branch) is None
        and not os.path.lexists(worktree_path)
        and _registered_worktree_details(repository, worktree_path) is None
        and not os.path.lexists(record_path.parent)
    )


def _recover_creation_intent_locked(
    repository: GitRepository,
    intent: dict[str, object],
) -> WorktreeOwnership:
    run_id = str(intent["run_id"])
    branch = str(intent["branch"])
    worktree_path = Path(str(intent["worktree_path"]))
    base_oid = str(intent["base_oid"])
    record_path = _ownership_path(repository, run_id)

    if os.path.lexists(record_path):
        ownership = _load_run_worktree_locked(repository, run_id)
        backlink = intent["git_backlink"]
        if (
            ownership.branch != branch
            or ownership.worktree_path != worktree_path
            or ownership.base_oid != base_oid
            or (backlink is not None and ownership.git_backlink != Path(str(backlink)))
        ):
            raise OwnershipError(
                "worktree creation intent conflicts with existing ownership"
            )
        _finalize_creation_intent_for_ownership_locked(repository, ownership)
        return ownership

    branch_oid = _branch_oid_or_none(repository, branch)
    details = _registered_worktree_details(repository, worktree_path)
    path_exists = os.path.lexists(worktree_path)
    if branch_oid is None and details is None and not path_exists:
        if intent["stage"] != "prepared":
            raise OwnershipError("created worktree disappeared before ownership")
        if (
            bool(intent["require_clean_base"])
            and _git(
                repository.primary_checkout,
                "status",
                "--porcelain",
                "--untracked-files=all",
            ).stdout
        ):
            raise DirtyBaseError("primary checkout is dirty")
        _git(
            repository.primary_checkout,
            "update-ref",
            f"refs/heads/{branch}",
            base_oid,
            "0" * len(base_oid),
        )
        branch_oid = base_oid

    if branch_oid == base_oid and details is None and not path_exists:
        if intent["stage"] != "prepared":
            raise OwnershipError("created worktree disappeared before ownership")
        _git(
            repository.primary_checkout,
            "worktree",
            "add",
            "--",
            str(worktree_path),
            branch,
        )
        details = _registered_worktree_details(repository, worktree_path)
        path_exists = os.path.lexists(worktree_path)

    expected_details = {f"HEAD {base_oid}", f"branch refs/heads/{branch}"}
    if (
        branch_oid != base_oid
        or not path_exists
        or details is None
        or not expected_details.issubset(details)
        or worktree_path.is_symlink()
        or not worktree_path.is_dir()
    ):
        raise ResourceCollisionError(
            "pending worktree creation no longer matches its exact resources"
        )
    backlink = _linked_git_backlink(worktree_path)
    try:
        backlink.relative_to(repository.git_common_directory / "worktrees")
    except ValueError as error:
        raise ResourceCollisionError(
            "pending worktree creation backlink escaped the repository"
        ) from error
    recorded_backlink = intent["git_backlink"]
    if recorded_backlink is not None and backlink != Path(str(recorded_backlink)):
        raise ResourceCollisionError(
            "pending worktree creation backlink no longer matches"
        )
    if intent["stage"] == "prepared":
        intent = _write_creation_intent_locked(
            repository,
            intent,
            stage="worktree-added",
            git_backlink=backlink,
        )

    ownership = WorktreeOwnership(
        run_id=run_id,
        primary_checkout=repository.primary_checkout,
        git_common_directory=repository.git_common_directory,
        worktree_path=worktree_path,
        branch=branch,
        base_oid=base_oid,
        last_known_oid=base_oid,
        git_backlink=backlink,
        record_path=record_path,
    )
    if intent["stage"] == "run-directory-staged":
        _recover_staged_ownership_directory_locked(
            repository,
            ownership,
            intent,
        )
    elif os.path.lexists(record_path.parent):
        _write_recovered_ownership_locked(repository, ownership, intent)
    else:
        if intent["stage"] == "run-directory-created":
            raise ResourceCollisionError(
                "intent-owned run directory disappeared before recovery"
            )
        _write_ownership(ownership)
    if _current_ownership_record_sha256(ownership) is None:
        raise OwnershipError("recovered worktree ownership is not current")
    _finalize_creation_intent_for_ownership_locked(repository, ownership)
    return ownership


def _finalize_creation_intent_for_ownership_locked(
    repository: GitRepository,
    ownership: WorktreeOwnership,
) -> None:
    intent = _load_creation_intent_locked(repository, ownership.run_id)
    if intent is None:
        return
    backlink = intent["git_backlink"]
    if (
        intent["primary_checkout"] != str(ownership.primary_checkout)
        or intent["git_common_directory"] != str(ownership.git_common_directory)
        or intent["worktree_path"] != str(ownership.worktree_path)
        or intent["branch"] != ownership.branch
        or intent["base_oid"] != ownership.base_oid
        or (backlink is not None and backlink != str(ownership.git_backlink))
    ):
        raise OwnershipError(
            "worktree ownership conflicts with its pending creation intent"
        )
    try:
        descriptor = _open_intent_owned_directory_locked(
            repository,
            ownership.record_path.parent,
            intent,
        )
    except ResourceCollisionError as error:
        raise OwnershipError(
            "worktree ownership directory is not bound by its creation intent"
        ) from error
    try:
        anchor = PrivateRootAnchor(ownership.record_path.parent, descriptor)
        _require_staged_ownership_record(ownership, anchor)
    finally:
        os.close(descriptor)
    _remove_creation_intent_locked(repository, ownership.run_id)


def create_run_worktree(
    repository: GitRepository,
    *,
    run_id: str,
    branch: str,
    worktree_path: Path | str,
    base_ref: str = "HEAD",
    require_clean_base: bool = True,
) -> WorktreeOwnership:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id):
        raise ValueError("run_id contains unsafe characters")
    if not isinstance(base_ref, str) or not base_ref:
        raise ValueError("base_ref must be a non-empty string")
    if type(require_clean_base) is not bool:
        raise TypeError("require_clean_base must be a boolean")
    requested_path = Path(worktree_path).expanduser().absolute()
    canonical_path = requested_path.resolve(strict=False)

    with FileLock.repository(repository.git_common_directory):
        if _git(
            repository.primary_checkout,
            "check-ref-format",
            "--branch",
            branch,
            check=False,
        ).returncode:
            raise InvalidBranchError(f"invalid branch name: {branch}")
        intent = _load_creation_intent_locked(repository, run_id)
        if intent is not None:
            if not _creation_request_matches(
                intent,
                repository,
                run_id=run_id,
                branch=branch,
                worktree_path=canonical_path,
                base_ref=base_ref,
                require_clean_base=require_clean_base,
            ):
                raise ResourceCollisionError(
                    "pending worktree creation belongs to another request"
                )
            return _recover_creation_intent_locked(repository, intent)

        branch_ref = f"refs/heads/{branch}"
        if not _git(
            repository.primary_checkout,
            "show-ref",
            "--verify",
            "--quiet",
            branch_ref,
            check=False,
        ).returncode:
            raise ResourceCollisionError(f"branch already exists: {branch}")
        if os.path.lexists(requested_path) or os.path.lexists(canonical_path):
            raise ResourceCollisionError(
                f"worktree path already exists: {requested_path}"
            )
        record_path = _ownership_path(repository, run_id)
        if os.path.lexists(record_path.parent):
            raise ResourceCollisionError(f"run ownership already exists: {run_id}")
        if (
            require_clean_base
            and _git(
                repository.primary_checkout,
                "status",
                "--porcelain",
                "--untracked-files=all",
            ).stdout
        ):
            raise DirtyBaseError("primary checkout is dirty")

        base_oid = _git_output_line(
            _git(
                repository.primary_checkout,
                "rev-parse",
                "--verify",
                f"{base_ref}^{{commit}}",
            ).stdout
        )
        intent = _write_creation_intent_locked(
            repository,
            {
                "schema_version": 1,
                "run_id": run_id,
                "primary_checkout": str(repository.primary_checkout),
                "git_common_directory": str(repository.git_common_directory),
                "worktree_path": str(canonical_path),
                "branch": branch,
                "base_ref": base_ref,
                "base_oid": base_oid,
                "require_clean_base": require_clean_base,
                "git_backlink": None,
                "stage": "prepared",
            },
            stage="prepared",
            git_backlink=None,
        )
        zero_oid = "0" * len(base_oid)
        branch_created = False
        try:
            _git(
                repository.primary_checkout,
                "update-ref",
                branch_ref,
                base_oid,
                zero_oid,
            )
            branch_created = True
            _git(
                repository.primary_checkout,
                "worktree",
                "add",
                "--",
                str(canonical_path),
                branch,
            )
            backlink = _linked_git_backlink(canonical_path)
            intent = _write_creation_intent_locked(
                repository,
                intent,
                stage="worktree-added",
                git_backlink=backlink,
            )
            ownership = WorktreeOwnership(
                run_id=run_id,
                primary_checkout=repository.primary_checkout,
                git_common_directory=repository.git_common_directory,
                worktree_path=canonical_path,
                branch=branch,
                base_oid=base_oid,
                last_known_oid=base_oid,
                git_backlink=backlink,
                record_path=record_path,
            )
            _write_ownership(ownership)
        except Exception:
            recovery_required = _staged_creation_requires_recovery(
                repository,
                run_id=run_id,
                branch=branch,
                worktree_path=canonical_path,
                base_ref=base_ref,
                base_oid=base_oid,
                require_clean_base=require_clean_base,
            )
            if not recovery_required:
                _compensate_run_creation(
                    repository,
                    worktree_path=canonical_path,
                    branch=branch,
                    base_oid=base_oid,
                    created_branch=branch_created,
                )
                if _creation_resources_are_absent(
                    repository,
                    branch=branch,
                    worktree_path=canonical_path,
                    record_path=record_path,
                ):
                    _remove_creation_intent_locked(repository, run_id)
            raise
        _finalize_creation_intent_for_ownership_locked(repository, ownership)
        return ownership


def _candidate_identity_locked(ownership: WorktreeOwnership) -> CandidateIdentity:
    if not _ownership_is_current(ownership):
        raise OwnershipError("candidate worktree is not owned by this run")
    commit_oid = _git_output_line(
        _git(ownership.worktree_path, "rev-parse", "--verify", "HEAD^{commit}").stdout
    )
    tree_oid = _git_output_line(
        _git(ownership.worktree_path, "rev-parse", "--verify", "HEAD^{tree}").stdout
    )
    return CandidateIdentity(commit_oid=commit_oid, tree_oid=tree_oid)


def candidate_identity(ownership: WorktreeOwnership) -> CandidateIdentity:
    with FileLock.repository(ownership.git_common_directory):
        recovered = _recover_pending_candidate_locked(ownership)
        if recovered is not None:
            return recovered
        return _candidate_identity_locked(ownership)


_CANDIDATE_RECEIPT_KEYS = {
    "schema_version",
    "run_id",
    "branch",
    "old_oid",
    "new_oid",
    "tree_oid",
    "stage",
    "subject",
}
_CANDIDATE_STAGE_ORDER = {
    "prepared": 0,
    "ref-updated": 1,
    "ownership-updated": 2,
}


def _load_candidate_receipt(
    ownership: WorktreeOwnership,
) -> dict[str, object] | None:
    path = _candidate_receipt_path(ownership)
    if not os.path.lexists(path):
        return None
    if path.is_symlink() or not path.is_file():
        raise OwnershipError("candidate operation receipt is not a regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OwnershipError("candidate operation receipt is corrupt") from error
    if not isinstance(payload, dict) or set(payload) != _CANDIDATE_RECEIPT_KEYS:
        raise OwnershipError("candidate operation receipt has an invalid schema")
    if payload["schema_version"] != 1:
        raise OwnershipError("candidate operation receipt version is unsupported")
    for key in (
        "run_id",
        "branch",
        "old_oid",
        "new_oid",
        "tree_oid",
        "stage",
        "subject",
    ):
        if not isinstance(payload[key], str):
            raise OwnershipError(f"candidate operation receipt {key} is invalid")
    if payload["run_id"] != ownership.run_id or payload["branch"] != ownership.branch:
        raise OwnershipError("candidate operation receipt belongs to another run")
    if payload["stage"] not in _CANDIDATE_STAGE_ORDER:
        raise OwnershipError("candidate operation receipt stage is invalid")
    return payload


def _write_candidate_receipt(
    ownership: WorktreeOwnership,
    receipt: dict[str, object],
    *,
    stage: str,
) -> dict[str, object]:
    changed = dict(receipt)
    changed["stage"] = stage
    _atomic_write_private_json(
        _candidate_receipt_path(ownership),
        changed,
        trusted_root=_ownership_runtime_root(ownership),
    )
    return changed


def _validate_candidate_receipt_identity_locked(
    ownership: WorktreeOwnership,
    receipt: dict[str, object],
) -> CandidateIdentity:
    old_oid = str(receipt["old_oid"])
    new_oid = str(receipt["new_oid"])
    tree_oid = str(receipt["tree_oid"])
    if _resolve_commit(ownership.worktree_path, new_oid) != new_oid:
        raise OwnershipError("pending candidate commit no longer resolves")
    if _resolve_commit(ownership.worktree_path, f"{new_oid}^1") != old_oid:
        raise OwnershipError("pending candidate parent does not match its receipt")
    actual_tree = _git_output_line(
        _git(
            ownership.worktree_path,
            "rev-parse",
            "--verify",
            f"{new_oid}^{{tree}}",
        ).stdout
    )
    if actual_tree != tree_oid:
        raise OwnershipError("pending candidate tree does not match its receipt")
    actual_subject = _git_output_line(
        _git(
            ownership.worktree_path,
            "show",
            "-s",
            "--format=%s",
            new_oid,
        ).stdout
    )
    if actual_subject != receipt["subject"]:
        raise OwnershipError("pending candidate subject does not match its receipt")
    ancestor = _git(
        ownership.worktree_path,
        "merge-base",
        "--is-ancestor",
        ownership.base_oid,
        old_oid,
        check=False,
    )
    if ancestor.returncode != 0:
        raise OwnershipError("pending candidate is not based on the owned history")
    return CandidateIdentity(commit_oid=new_oid, tree_oid=tree_oid)


def _recover_pending_candidate_locked(
    ownership: WorktreeOwnership,
) -> CandidateIdentity | None:
    receipt = _load_candidate_receipt(ownership)
    if receipt is None:
        return None
    record_oid = _ownership_record_last_known(ownership)
    identity = _validate_candidate_receipt_identity_locked(ownership, receipt)
    old_oid = str(receipt["old_oid"])
    new_oid = identity.commit_oid
    observed_oid = _resolve_commit(
        ownership.worktree_path,
        f"refs/heads/{ownership.branch}",
    )
    if observed_oid not in {old_oid, new_oid} or record_oid not in {old_oid, new_oid}:
        raise CandidateRecoveryBlockedError(
            observed_oid,
            old_oid=old_oid,
            new_oid=new_oid,
        )

    if observed_oid == old_oid:
        try:
            _git(
                ownership.worktree_path,
                "update-ref",
                f"refs/heads/{ownership.branch}",
                new_oid,
                old_oid,
            )
        except GitCommandError as error:
            raise CandidateCommitPartialError(
                identity,
                stage="ref-update",
                cause=error,
            ) from error
    if (
        _CANDIDATE_STAGE_ORDER[str(receipt["stage"])]
        < _CANDIDATE_STAGE_ORDER["ref-updated"]
    ):
        try:
            receipt = _write_candidate_receipt(
                ownership,
                receipt,
                stage="ref-updated",
            )
        except Exception as error:
            raise CandidateCommitPartialError(
                identity,
                stage="receipt-update",
                cause=error,
            ) from error

    if record_oid == old_oid:
        ownership.last_known_oid = new_oid
        try:
            _replace_ownership_record(ownership)
        except Exception as error:
            raise CandidateCommitPartialError(
                identity,
                stage="ownership-record",
                cause=error,
            ) from error
    else:
        ownership.last_known_oid = new_oid
    if (
        _CANDIDATE_STAGE_ORDER[str(receipt["stage"])]
        < _CANDIDATE_STAGE_ORDER["ownership-updated"]
    ):
        try:
            receipt = _write_candidate_receipt(
                ownership,
                receipt,
                stage="ownership-updated",
            )
        except Exception as error:
            raise CandidateCommitPartialError(
                identity,
                stage="receipt-update",
                cause=error,
            ) from error

    try:
        _git(ownership.worktree_path, "read-tree", new_oid)
    except GitCommandError as error:
        raise CandidateCommitPartialError(
            identity,
            stage="index-sync",
            cause=error,
        ) from error
    try:
        _remove_durable_file(
            _candidate_receipt_path(ownership),
            trusted_root=_ownership_runtime_root(ownership),
        )
    except OSError as error:
        raise CandidateCommitPartialError(
            identity,
            stage="receipt-cleanup",
            cause=error,
        ) from error
    return identity


def _normalize_approved_paths(paths: Sequence[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in paths:
        candidate = PurePosixPath(value)
        if not value or candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError(f"approved path is unsafe: {value!r}")
        normalized.append(candidate.as_posix().rstrip("/"))
    if not normalized:
        raise ValueError("approved_paths must be non-empty")
    return tuple(normalized)


def _path_is_approved(path: str, approved_paths: Sequence[str]) -> bool:
    return any(
        approved == "." or path == approved or path.startswith(f"{approved}/")
        for approved in approved_paths
    )


def _candidate_findings(
    worktree: Path,
    *,
    index_environment: dict[str, str],
    approved_paths: Sequence[str],
    max_file_bytes: int,
) -> tuple[CandidateSafetyFinding, ...]:
    changed = _git(
        worktree,
        "diff",
        "--cached",
        "--name-only",
        "--no-renames",
        "-z",
        env=index_environment,
    ).stdout.split("\0")
    findings: list[CandidateSafetyFinding] = []
    for path in sorted(item for item in changed if item):
        reasons: list[str] = []
        if not _path_is_approved(path, approved_paths):
            reasons.append("outside-approved-plan")
        name = PurePosixPath(path).name.lower()
        if name == ".env" or name.startswith(".env."):
            reasons.append("environment-file")

        size_result = _git(
            worktree,
            "cat-file",
            "-s",
            f":{path}",
            check=False,
            env=index_environment,
        )
        if not size_result.returncode:
            size = int(_git_output_line(size_result.stdout))
            if size > max_file_bytes:
                reasons.append("oversized")
            private_key_name = name in {
                "id_dsa",
                "id_ecdsa",
                "id_ed25519",
                "id_rsa",
            } or name.endswith((".key", ".pem", ".p12", ".pfx"))
            private_key_content = False
            if size <= 1024 * 1024:
                content = _git_bytes(
                    worktree,
                    "cat-file",
                    "blob",
                    f":{path}",
                    env=index_environment,
                )
                private_key_content = bool(
                    re.search(
                        rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
                        content,
                    )
                )
            if private_key_name or private_key_content:
                reasons.append("private-key")
        if reasons:
            findings.append(CandidateSafetyFinding(path=path, reasons=tuple(reasons)))
    return tuple(findings)


def commit_candidate(
    ownership: WorktreeOwnership,
    *,
    message: str,
    approved_paths: Sequence[str],
    max_file_bytes: int = 10 * 1024 * 1024,
) -> CandidateIdentity:
    if not message.strip():
        raise ValueError("candidate commit message must be non-empty")
    normalized_paths = _normalize_approved_paths(approved_paths)
    if type(max_file_bytes) is not int or max_file_bytes < 0:
        raise ValueError("max_file_bytes must be a non-negative integer")

    with FileLock.repository(ownership.git_common_directory):
        recovered = _recover_pending_candidate_locked(ownership)
        if recovered is not None:
            return recovered
        current_identity = _candidate_identity_locked(ownership)
        with tempfile.TemporaryDirectory(prefix="ship-flow-index-") as directory:
            temporary_index = Path(directory) / "index"
            real_index_output = _git_output_line(
                _git(ownership.worktree_path, "rev-parse", "--git-path", "index").stdout
            )
            real_index = Path(real_index_output)
            if not real_index.is_absolute():
                real_index = ownership.worktree_path / real_index
            shutil.copyfile(real_index, temporary_index)
            index_environment = {"GIT_INDEX_FILE": str(temporary_index)}
            _git(
                ownership.worktree_path,
                "add",
                "--all",
                "--",
                ".",
                env=index_environment,
            )
            findings = _candidate_findings(
                ownership.worktree_path,
                index_environment=index_environment,
                approved_paths=normalized_paths,
                max_file_bytes=max_file_bytes,
            )
            if findings:
                raise CandidateSafetyError(findings)
            changed = _git(
                ownership.worktree_path,
                "diff",
                "--cached",
                "--quiet",
                check=False,
                env=index_environment,
            )
            if changed.returncode not in (0, 1):
                raise GitCommandError(("diff", "--cached", "--quiet"), changed.stderr)
            if changed.returncode == 0:
                try:
                    _git(
                        ownership.worktree_path,
                        "read-tree",
                        current_identity.commit_oid,
                    )
                except GitCommandError as error:
                    raise CandidateCommitPartialError(
                        current_identity,
                        stage="index-sync",
                        cause=error,
                    ) from error
                return current_identity

            tree_oid = _git_output_line(
                _git(
                    ownership.worktree_path,
                    "write-tree",
                    env=index_environment,
                ).stdout
            )
            commit_oid = _git_output_line(
                _git(
                    ownership.worktree_path,
                    "commit-tree",
                    tree_oid,
                    "-p",
                    ownership.last_known_oid,
                    "-m",
                    message,
                ).stdout
            )
            identity = CandidateIdentity(commit_oid=commit_oid, tree_oid=tree_oid)
            subject = _git_output_line(
                _git(
                    ownership.worktree_path,
                    "show",
                    "-s",
                    "--format=%s",
                    identity.commit_oid,
                ).stdout
            )
            receipt: dict[str, object] = {
                "schema_version": 1,
                "run_id": ownership.run_id,
                "branch": ownership.branch,
                "old_oid": ownership.last_known_oid,
                "new_oid": identity.commit_oid,
                "tree_oid": identity.tree_oid,
                "stage": "prepared",
                "subject": subject,
            }
            _write_candidate_receipt(
                ownership,
                receipt,
                stage="prepared",
            )

        recovered = _recover_pending_candidate_locked(ownership)
        if recovered is None:
            raise GitOperationError("candidate receipt disappeared before publication")
        return recovered


_CLEANUP_RECEIPT_KEYS = {
    "schema_version",
    "run_id",
    "branch",
    "branch_oid",
    "base_oid",
    "target_oid",
    "worktree_path",
    "git_backlink",
    "record_path",
    "ownership_record_sha256",
    "delete_branch",
    "stage",
}
_CLEANUP_STAGE_ORDER = {
    "prepared": 0,
    "worktree-removed": 1,
    "branch-handled": 2,
    "ownership-removed": 3,
}


def _load_cleanup_receipt(
    ownership: WorktreeOwnership,
) -> dict[str, object] | None:
    path = _cleanup_receipt_path(ownership)
    if not os.path.lexists(path):
        return None
    if path.is_symlink() or not path.is_file():
        raise OwnershipError("cleanup operation receipt is not a regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OwnershipError("cleanup operation receipt is corrupt") from error
    if not isinstance(payload, dict) or set(payload) != _CLEANUP_RECEIPT_KEYS:
        raise OwnershipError("cleanup operation receipt has an invalid schema")
    if payload["schema_version"] != 1:
        raise OwnershipError("cleanup operation receipt version is unsupported")
    for key in (
        "run_id",
        "branch",
        "branch_oid",
        "base_oid",
        "target_oid",
        "worktree_path",
        "git_backlink",
        "record_path",
        "ownership_record_sha256",
        "stage",
    ):
        if not isinstance(payload[key], str):
            raise OwnershipError(f"cleanup operation receipt {key} is invalid")
    if type(payload["delete_branch"]) is not bool:
        raise OwnershipError("cleanup operation receipt delete_branch is invalid")
    if re.fullmatch(r"[0-9a-f]{64}", str(payload["ownership_record_sha256"])) is None:
        raise OwnershipError("cleanup operation receipt ownership digest is invalid")
    if payload["stage"] not in _CLEANUP_STAGE_ORDER:
        raise OwnershipError("cleanup operation receipt stage is invalid")
    expected = {
        "run_id": ownership.run_id,
        "branch": ownership.branch,
        "branch_oid": ownership.last_known_oid,
        "base_oid": ownership.base_oid,
        "worktree_path": str(ownership.worktree_path),
        "git_backlink": str(ownership.git_backlink),
        "record_path": str(ownership.record_path),
    }
    if any(payload[key] != value for key, value in expected.items()):
        raise OwnershipError("cleanup operation receipt belongs to another run")
    return payload


def _write_cleanup_receipt(
    ownership: WorktreeOwnership,
    receipt: dict[str, object],
    *,
    stage: str,
) -> dict[str, object]:
    changed = dict(receipt)
    changed["stage"] = stage
    _atomic_write_private_json(
        _cleanup_receipt_path(ownership),
        changed,
        trusted_root=_ownership_runtime_root(ownership),
    )
    return changed


def _registered_worktree_details(
    repository: GitRepository,
    worktree_path: Path,
) -> set[str] | None:
    fields = _git(
        repository.primary_checkout,
        "worktree",
        "list",
        "--porcelain",
        "-z",
    ).stdout.split("\0")
    for index, field in enumerate(fields):
        if not field.startswith("worktree "):
            continue
        if Path(field.removeprefix("worktree ")) != worktree_path:
            continue
        details: set[str] = set()
        for detail in fields[index + 1 :]:
            if not detail or detail.startswith("worktree "):
                break
            details.add(detail)
        return details
    return None


def _branch_oid_or_none(repository: GitRepository, branch: str) -> str | None:
    result = _git(
        repository.primary_checkout,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"refs/heads/{branch}^{{commit}}",
        check=False,
    )
    if result.returncode:
        return None
    return _git_output_line(result.stdout)


def _validate_cleanup_receipt_history_locked(
    repository: GitRepository,
    receipt: dict[str, object],
) -> None:
    branch_oid = str(receipt["branch_oid"])
    target_oid = str(receipt["target_oid"])
    base_oid = str(receipt["base_oid"])
    if _resolve_commit(repository.primary_checkout, branch_oid) != branch_oid:
        raise OwnershipError("cleanup branch OID no longer resolves")
    if _resolve_commit(repository.primary_checkout, target_oid) != target_oid:
        raise OwnershipError("cleanup target OID no longer resolves")
    ancestor = _git(
        repository.primary_checkout,
        "merge-base",
        "--is-ancestor",
        base_oid,
        branch_oid,
        check=False,
    )
    if ancestor.returncode != 0:
        raise OwnershipError("cleanup branch is not based on the owned history")


def _recover_pending_cleanup_locked(
    ownership: WorktreeOwnership,
    repository: GitRepository,
) -> bool:
    receipt = _load_cleanup_receipt(ownership)
    if receipt is None:
        return False
    _validate_cleanup_receipt_history_locked(repository, receipt)
    stage = str(receipt["stage"])
    branch_oid = str(receipt["branch_oid"])
    worktree_path = Path(str(receipt["worktree_path"]))
    details = _registered_worktree_details(repository, worktree_path)
    path_exists = os.path.lexists(worktree_path)

    if path_exists:
        if _CLEANUP_STAGE_ORDER[stage] > _CLEANUP_STAGE_ORDER["prepared"]:
            raise CleanupRecoveryBlockedError("worktree path was recreated")
        expected_details = {
            f"HEAD {branch_oid}",
            f"branch refs/heads/{ownership.branch}",
        }
        if (
            worktree_path.is_symlink()
            or not worktree_path.is_dir()
            or details is None
            or not expected_details.issubset(details)
            or _linked_git_backlink(worktree_path) != ownership.git_backlink
            or _branch_oid_or_none(repository, ownership.branch) != branch_oid
        ):
            raise CleanupRecoveryBlockedError("worktree no longer matches receipt")
        try:
            _git(
                repository.primary_checkout,
                "worktree",
                "remove",
                "--",
                str(worktree_path),
            )
        except Exception as error:
            raise CleanupPartialError(stage="worktree-remove", cause=error) from error
    elif details is not None:
        raise CleanupRecoveryBlockedError("missing worktree is still registered")

    if _CLEANUP_STAGE_ORDER[stage] < _CLEANUP_STAGE_ORDER["worktree-removed"]:
        try:
            receipt = _write_cleanup_receipt(
                ownership,
                receipt,
                stage="worktree-removed",
            )
        except Exception as error:
            raise CleanupPartialError(
                stage="receipt-worktree-removed",
                cause=error,
            ) from error
        stage = "worktree-removed"

    observed_branch_oid = _branch_oid_or_none(repository, ownership.branch)
    delete_branch = bool(receipt["delete_branch"])
    if delete_branch:
        if observed_branch_oid == branch_oid:
            if _CLEANUP_STAGE_ORDER[stage] >= _CLEANUP_STAGE_ORDER["branch-handled"]:
                raise CleanupRecoveryBlockedError("deleted branch was recreated")
            try:
                _git(
                    repository.primary_checkout,
                    "update-ref",
                    "-d",
                    f"refs/heads/{ownership.branch}",
                    branch_oid,
                )
            except Exception as error:
                raise CleanupPartialError(stage="branch-remove", cause=error) from error
        elif observed_branch_oid is not None:
            raise CleanupRecoveryBlockedError("branch moved away from recorded OID")
    elif observed_branch_oid != branch_oid:
        raise CleanupRecoveryBlockedError("preserved branch changed")

    if _CLEANUP_STAGE_ORDER[stage] < _CLEANUP_STAGE_ORDER["branch-handled"]:
        try:
            receipt = _write_cleanup_receipt(
                ownership,
                receipt,
                stage="branch-handled",
            )
        except Exception as error:
            raise CleanupPartialError(
                stage="receipt-branch-handled",
                cause=error,
            ) from error
        stage = "branch-handled"

    record_path = Path(str(receipt["record_path"]))
    if os.path.lexists(record_path):
        if _CLEANUP_STAGE_ORDER[stage] >= _CLEANUP_STAGE_ORDER["ownership-removed"]:
            raise CleanupRecoveryBlockedError("ownership record was recreated")
        if record_path.is_symlink() or not record_path.is_file():
            raise CleanupRecoveryBlockedError("ownership record path was replaced")
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise OwnershipError(
                "cleanup ownership record could not be validated"
            ) from error
        if (
            not isinstance(record, dict)
            or _canonical_json_sha256(record) != receipt["ownership_record_sha256"]
        ):
            raise OwnershipError("cleanup ownership record does not match its receipt")
        try:
            _remove_durable_file(
                record_path,
                trusted_root=_ownership_runtime_root(ownership),
            )
        except Exception as error:
            raise CleanupPartialError(stage="ownership-remove", cause=error) from error

    if _CLEANUP_STAGE_ORDER[stage] < _CLEANUP_STAGE_ORDER["ownership-removed"]:
        try:
            receipt = _write_cleanup_receipt(
                ownership,
                receipt,
                stage="ownership-removed",
            )
        except Exception as error:
            raise CleanupPartialError(
                stage="receipt-ownership-removed",
                cause=error,
            ) from error

    try:
        _remove_durable_file(
            _cleanup_receipt_path(ownership),
            trusted_root=_ownership_runtime_root(ownership),
        )
    except Exception as error:
        raise CleanupPartialError(stage="receipt-cleanup", cause=error) from error
    try:
        ownership.record_path.parent.rmdir()
        _fsync_directory_path(ownership.record_path.parent.parent)
    except OSError:
        pass
    return True


def _cleanup_conditions(
    *,
    approved: bool,
    approved_conditions: Sequence[str],
) -> frozenset[str]:
    if isinstance(approved_conditions, (str, bytes)):
        raise TypeError("approved_conditions must be a sequence of condition names")
    conditions_approved = frozenset(approved_conditions)
    if any(not isinstance(item, str) for item in conditions_approved):
        raise TypeError("approved_conditions must contain strings")
    unknown = conditions_approved - {"unmerged"}
    if unknown:
        raise ValueError(
            "unknown cleanup approval conditions: " + ", ".join(sorted(unknown))
        )
    if not approved:
        raise CleanupRefusedError(("approval",))
    return conditions_approved


def _preflight_owned_worktree_cleanup_locked(
    ownership: WorktreeOwnership,
    repository: GitRepository,
    *,
    approved_conditions: frozenset[str],
    merged_into: str,
) -> CleanupPreflight:
    ownership_record_sha256 = _current_ownership_record_sha256(ownership)
    if ownership_record_sha256 is None:
        raise CleanupRefusedError(("unowned",))
    target_oid = _resolve_commit(repository.primary_checkout, merged_into)
    branch_oid = ownership.last_known_oid
    refusal_conditions: list[str] = []
    if _git(
        ownership.worktree_path,
        "status",
        "--porcelain",
        "--untracked-files=all",
    ).stdout:
        refusal_conditions.append("dirty")

    merge_check = _git(
        repository.primary_checkout,
        "merge-base",
        "--is-ancestor",
        branch_oid,
        target_oid,
        check=False,
    )
    if merge_check.returncode not in (0, 1):
        raise GitCommandError(
            ("merge-base", "--is-ancestor", ownership.branch, merged_into),
            merge_check.stderr,
        )
    unmerged = merge_check.returncode == 1
    if unmerged and "unmerged" not in approved_conditions:
        refusal_conditions.append("unmerged")
    if refusal_conditions:
        raise CleanupRefusedError(refusal_conditions)
    return CleanupPreflight(
        target_oid=target_oid,
        ownership_record_sha256=ownership_record_sha256,
        branch_oid=branch_oid,
        approved_conditions=tuple(sorted(approved_conditions)),
        delete_branch=not unmerged,
    )


def preflight_owned_worktree_cleanup(
    ownership: WorktreeOwnership,
    *,
    approved: bool,
    approved_conditions: Sequence[str] = (),
    merged_into: str = "HEAD",
) -> CleanupPreflight:
    """Validate cleanup without writing a receipt or mutating Git resources."""

    conditions_approved = _cleanup_conditions(
        approved=approved,
        approved_conditions=approved_conditions,
    )
    repository = GitRepository(
        primary_checkout=ownership.primary_checkout,
        git_common_directory=ownership.git_common_directory,
    )
    with FileLock.repository(repository.git_common_directory):
        if _load_cleanup_receipt(ownership) is not None:
            raise CleanupRecoveryBlockedError("cleanup has already started")
        return _preflight_owned_worktree_cleanup_locked(
            ownership,
            repository,
            approved_conditions=conditions_approved,
            merged_into=merged_into,
        )


def cleanup_owned_worktree(
    ownership: WorktreeOwnership,
    *,
    approved: bool,
    approved_conditions: Sequence[str] = (),
    merged_into: str = "HEAD",
) -> None:
    conditions_approved = _cleanup_conditions(
        approved=approved,
        approved_conditions=approved_conditions,
    )

    repository = GitRepository(
        primary_checkout=ownership.primary_checkout,
        git_common_directory=ownership.git_common_directory,
    )
    with FileLock.repository(repository.git_common_directory):
        if _recover_pending_cleanup_locked(ownership, repository):
            return
        preflight = _preflight_owned_worktree_cleanup_locked(
            ownership,
            repository,
            approved_conditions=conditions_approved,
            merged_into=merged_into,
        )
        receipt: dict[str, object] = {
            "schema_version": 1,
            "run_id": ownership.run_id,
            "branch": ownership.branch,
            "branch_oid": preflight.branch_oid,
            "base_oid": ownership.base_oid,
            "target_oid": preflight.target_oid,
            "worktree_path": str(ownership.worktree_path),
            "git_backlink": str(ownership.git_backlink),
            "record_path": str(ownership.record_path),
            "ownership_record_sha256": preflight.ownership_record_sha256,
            "delete_branch": preflight.delete_branch,
            "stage": "prepared",
        }
        try:
            _write_cleanup_receipt(
                ownership,
                receipt,
                stage="prepared",
            )
        except Exception as error:
            raise CleanupPartialError(stage="receipt-prepare", cause=error) from error
        if not _recover_pending_cleanup_locked(ownership, repository):
            raise GitOperationError("cleanup receipt disappeared before removal")
