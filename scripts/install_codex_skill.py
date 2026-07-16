from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, Mapping, Sequence


SCENARIO_IDS = (
    "SF-01-vague-request",
    "SF-02-self-verification",
    "SF-03-stale-review",
    "SF-04-verifier-repair",
    "SF-05-no-healthcheck",
    "SF-06-release-no-current-evidence",
    "SF-07-interrupted-external-write",
    "SF-08-scope-expansion",
)
_HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
_RUNNER_ID = re.compile(r"/?[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_INSTALL_STATES = (
    "STAGED",
    "ENGINE_PUBLISHED",
    "SKILL_PUBLISHED",
    "ACTIVATED",
)


class InstallError(RuntimeError):
    """The verified bundle cannot be installed without risking local content."""


@dataclass(frozen=True)
class PressureReceipt:
    skill_sha256: str
    pressure_spec_sha256: str
    receipt_sha256: str


@dataclass(frozen=True)
class InstallResult:
    changed: bool
    skill_sha256: str
    engine_sha256: str
    skill_target: Path
    engine_target: Path


@dataclass(frozen=True)
class _DesiredBundle:
    skill_sha256: str
    engine_sha256: str
    launcher_sha256: str
    receipt_sha256: str
    launcher: bytes


def _lstat(path: Path, *, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise InstallError(f"{label} cannot be inspected safely") from error


def _directory_identity(path: Path, *, label: str) -> tuple[int, int]:
    metadata = _lstat(path, label=label)
    if not stat.S_ISDIR(metadata.st_mode):
        raise InstallError(f"{label} must be a real directory")
    return metadata.st_dev, metadata.st_ino


def _require_directory_identity(
    path: Path,
    identity: tuple[int, int],
    *,
    label: str,
) -> None:
    if _directory_identity(path, label=label) != identity:
        raise InstallError(f"{label} changed while it was inspected")


def _read_regular_file(
    path: Path,
    *,
    label: str,
    max_bytes: int = 4 * 1024 * 1024,
) -> bytes:
    metadata = _lstat(path, label=label)
    if not stat.S_ISREG(metadata.st_mode):
        raise InstallError(f"{label} must be a regular file")
    if metadata.st_size > max_bytes:
        raise InstallError(f"{label} is too large")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise InstallError(f"{label} cannot be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise InstallError(f"{label} must be a regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise InstallError(f"{label} is too large")
        final = os.fstat(descriptor)
    except OSError as error:
        raise InstallError(f"{label} changed while it was read") from error
    finally:
        os.close(descriptor)
    if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
        final.st_dev,
        final.st_ino,
        final.st_size,
        final.st_mtime_ns,
    ):
        raise InstallError(f"{label} changed while it was read")
    return b"".join(chunks)


def _collect_tree_files(
    root: Path,
    *,
    ignore_python_cache: bool = False,
) -> list[tuple[str, Path]]:
    root = Path(os.path.abspath(root))
    metadata = _lstat(root, label="tree root")
    if not stat.S_ISDIR(metadata.st_mode):
        raise InstallError("tree root must be a real directory")
    files: list[tuple[str, Path]] = []

    def visit(directory: Path, relative: Path) -> None:
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            raise InstallError("tree cannot be enumerated safely") from error
        for entry in entries:
            path = Path(entry.path)
            child_relative = relative / entry.name
            try:
                child = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise InstallError("tree entry cannot be inspected safely") from error
            if stat.S_ISLNK(child.st_mode):
                raise InstallError("tree must not contain symbolic links")
            if stat.S_ISDIR(child.st_mode):
                if ignore_python_cache and entry.name == "__pycache__":
                    continue
                visit(path, child_relative)
                continue
            if not stat.S_ISREG(child.st_mode):
                raise InstallError(
                    "tree must contain only directories and regular files"
                )
            if ignore_python_cache and path.suffix in {".pyc", ".pyo"}:
                continue
            files.append((child_relative.as_posix(), path))

    visit(root, Path())
    files.sort(key=lambda item: item[0])
    return files


def _tree_digest(
    root: Path,
    *,
    ignore_python_cache: bool = False,
) -> str:
    root = Path(os.path.abspath(root))
    identity = _directory_identity(root, label="tree root")
    digest = hashlib.sha256()
    for relative, path in _collect_tree_files(
        root,
        ignore_python_cache=ignore_python_cache,
    ):
        payload = _read_regular_file(path, label=f"tree file {relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).hexdigest().encode("ascii"))
        digest.update(b"\n")
    _require_directory_identity(root, identity, label="tree root")
    return digest.hexdigest()


def canonical_tree_digest(root: Path) -> str:
    """Return the canonical content digest used by receipts and installations."""

    return _tree_digest(Path(root))


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON value {value}")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key}")
        result[key] = value
    return result


def _load_json(path: Path, *, label: str) -> tuple[dict[str, object], bytes]:
    raw = _read_regular_file(path, label=label)
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise InstallError(f"{label} is not valid JSON") from error
    if not isinstance(payload, dict):
        raise InstallError(f"{label} must contain a JSON object")
    return payload, raw


def _exact_keys(
    payload: Mapping[str, object],
    expected: set[str],
    *,
    label: str,
) -> None:
    if set(payload) != expected:
        raise InstallError(f"{label} has an unsupported schema")


def _require_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _HEX_256.fullmatch(value) is None:
        raise InstallError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_utc(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise InstallError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise InstallError(f"{label} must be an RFC3339 UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise InstallError(f"{label} must be UTC")
    return value


def _safe_relative_file(root: Path, value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise InstallError(f"{label} must be a relative path")
    relative = Path(value)
    if relative.is_absolute() or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise InstallError(f"{label} must stay inside the receipt directory")
    root = Path(os.path.abspath(root))
    path = root / relative
    current = root
    for component in relative.parts[:-1]:
        current = current / component
        metadata = _lstat(current, label=label)
        if not stat.S_ISDIR(metadata.st_mode):
            raise InstallError(f"{label} has an unsafe parent")
    return path


def validate_pressure_receipt(
    receipt_path: Path,
    *,
    skill_source: Path,
    pressure_spec: Path,
) -> PressureReceipt:
    receipt_path = Path(receipt_path)
    skill_source = Path(skill_source)
    pressure_spec = Path(pressure_spec)
    payload, raw = _load_json(receipt_path, label="pressure validation receipt")
    _exact_keys(
        payload,
        {
            "schema_version",
            "generated_at",
            "skill_sha256",
            "pressure_spec_sha256",
            "scenarios",
        },
        label="pressure validation receipt",
    )
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise InstallError("pressure validation receipt version is unsupported")
    _require_utc(payload["generated_at"], label="receipt generated_at")
    skill_sha256 = _require_sha256(payload["skill_sha256"], label="skill_sha256")
    pressure_sha256 = _require_sha256(
        payload["pressure_spec_sha256"],
        label="pressure_spec_sha256",
    )
    if skill_sha256 != canonical_tree_digest(skill_source):
        raise InstallError("pressure receipt is for a different Skill tree")
    pressure_raw = _read_regular_file(pressure_spec, label="pressure scenario spec")
    if pressure_sha256 != hashlib.sha256(pressure_raw).hexdigest():
        raise InstallError("pressure receipt is for a different scenario spec")
    scenarios = payload["scenarios"]
    if not isinstance(scenarios, list) or len(scenarios) != len(SCENARIO_IDS):
        raise InstallError("pressure receipt must contain exactly eight scenarios")
    seen_runners: set[str] = set()
    seen_transcripts: set[Path] = set()
    seen_ids: list[str] = []
    baseline_failed = False
    for index, row in enumerate(scenarios):
        if not isinstance(row, dict):
            raise InstallError("pressure scenario result must be an object")
        _exact_keys(
            row,
            {"scenario_id", "baseline", "with_skill"},
            label="pressure scenario result",
        )
        scenario_id = row["scenario_id"]
        if not isinstance(scenario_id, str):
            raise InstallError("scenario_id must be a string")
        seen_ids.append(scenario_id)
        for variant in ("baseline", "with_skill"):
            result = row[variant]
            if not isinstance(result, dict):
                raise InstallError(f"{variant} result must be an object")
            required = {"runner_id", "transcript", "transcript_sha256", "passed"}
            allowed = required | {"unsafe_rationalization"}
            if not required.issubset(result) or not set(result).issubset(allowed):
                raise InstallError(f"{variant} result has an unsupported schema")
            runner_id = result["runner_id"]
            if (
                not isinstance(runner_id, str)
                or _RUNNER_ID.fullmatch(runner_id) is None
                or "//" in runner_id
                or any(
                    part in {"", ".", ".."}
                    for part in runner_id.removeprefix("/").split("/")
                )
            ):
                raise InstallError("runner_id is invalid")
            if runner_id in seen_runners:
                raise InstallError("pressure runners must be distinct")
            seen_runners.add(runner_id)
            if type(result["passed"]) is not bool:
                raise InstallError("pressure result passed must be a boolean")
            transcript = _safe_relative_file(
                receipt_path.parent,
                result["transcript"],
                label="pressure transcript",
            )
            if transcript in seen_transcripts:
                raise InstallError("pressure transcripts must be distinct")
            seen_transcripts.add(transcript)
            transcript_raw = _read_regular_file(
                transcript,
                label="pressure transcript",
                max_bytes=1024 * 1024,
            )
            expected_transcript = _require_sha256(
                result["transcript_sha256"],
                label="transcript_sha256",
            )
            if hashlib.sha256(transcript_raw).hexdigest() != expected_transcript:
                raise InstallError("pressure transcript digest does not match")
            try:
                transcript_payload = json.loads(
                    transcript_raw.decode("utf-8"),
                    parse_constant=_reject_json_constant,
                    object_pairs_hook=_unique_json_object,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                raise InstallError("pressure transcript is not valid JSON") from error
            if not isinstance(transcript_payload, dict):
                raise InstallError("pressure transcript must contain a JSON object")
            _exact_keys(
                transcript_payload,
                {"scenario_id", "runner_id", "prompt", "response"},
                label="pressure transcript",
            )
            if transcript_payload["scenario_id"] != scenario_id:
                raise InstallError(
                    "pressure transcript scenario identity does not match"
                )
            if transcript_payload["runner_id"] != runner_id:
                raise InstallError("pressure transcript runner identity does not match")
            for field in ("prompt", "response"):
                if (
                    not isinstance(transcript_payload[field], str)
                    or not transcript_payload[field].strip()
                ):
                    raise InstallError(
                        f"pressure transcript {field} must be a non-empty string"
                    )
            if result["passed"] is False:
                rationalization = result.get("unsafe_rationalization")
                if not isinstance(rationalization, str) or not rationalization:
                    raise InstallError(
                        "failed pressure result needs an exact rationalization"
                    )
                if rationalization not in transcript_payload["response"]:
                    raise InstallError(
                        "unsafe rationalization is not in the transcript response"
                    )
                if variant == "baseline":
                    baseline_failed = True
            elif "unsafe_rationalization" in result:
                raise InstallError(
                    "passing pressure result cannot claim a rationalization"
                )
            if variant == "with_skill" and result["passed"] is not True:
                raise InstallError("all Skill-enabled pressure scenarios must pass")
        if scenario_id != SCENARIO_IDS[index]:
            raise InstallError("pressure scenario IDs or ordering do not match")
    if tuple(seen_ids) != SCENARIO_IDS or not baseline_failed:
        raise InstallError("pressure receipt lacks a required RED baseline")
    return PressureReceipt(
        skill_sha256=skill_sha256,
        pressure_spec_sha256=pressure_sha256,
        receipt_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _canonical_json(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _ensure_directory(path: Path) -> None:
    path = Path(os.path.abspath(path))
    missing: list[Path] = []
    current = path
    while not os.path.lexists(current):
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    if os.path.lexists(current):
        metadata = _lstat(current, label="installation parent")
        if not stat.S_ISDIR(metadata.st_mode):
            raise InstallError("installation parent must be a real directory")
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except OSError as error:
            raise InstallError("installation directory cannot be created") from error
        os.chmod(directory, 0o700)


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as error:
        raise InstallError("installation directory cannot be synchronized") from error
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_private_json(path: Path, payload: object) -> None:
    raw = _canonical_json(payload)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    os.chmod(path, 0o600)
    _fsync_directory(path.parent)


@contextlib.contextmanager
def _installation_lock(codex_home: Path) -> Iterator[None]:
    lock_path = codex_home / ".ship-flow-install.lock"
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise InstallError("another Ship Flow installation is active") from error
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _write_private_file(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def _copy_tree(
    source: Path,
    target: Path,
    *,
    ignore_python_cache: bool = False,
) -> None:
    source = Path(os.path.abspath(source))
    source_identity = _directory_identity(source, label="source tree")
    files = _collect_tree_files(source, ignore_python_cache=ignore_python_cache)
    target.mkdir(mode=0o700)
    os.chmod(target, 0o700)
    for relative, source_path in files:
        destination = target / Path(relative)
        missing: list[Path] = []
        parent = destination.parent
        while parent != target and not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700)
        payload = _read_regular_file(source_path, label=f"source file {relative}")
        _write_private_file(destination, payload)
    _require_directory_identity(source, source_identity, label="source tree")
    for directory in sorted(
        (path for path in target.rglob("*") if path.is_dir()),
        reverse=True,
    ):
        _fsync_directory(directory)
    _fsync_directory(target)


def _launcher_bytes(
    python_executable: Path,
    *,
    codex_home: Path,
    skill_target: Path,
    engine_target: Path,
) -> bytes:
    executable = str(Path(python_executable).resolve())
    if not executable:
        raise InstallError("the selected Python path cannot be represented safely")
    template = r"""from __future__ import annotations

import hashlib
import importlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path


def fail(message: str) -> "None":
    print(f"ship-flow installation integrity error: {message}", file=sys.stderr)
    raise SystemExit(78)


def regular(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError:
        fail("installation file is missing")
    if not stat.S_ISREG(metadata.st_mode):
        fail("installation file is unsafe")
    try:
        return path.read_bytes()
    except OSError:
        fail("installation file is unreadable")


def tree_digest(root: Path) -> str:
    try:
        metadata = root.lstat()
    except OSError:
        fail("installation tree is missing")
    if not stat.S_ISDIR(metadata.st_mode):
        fail("installation tree is unsafe")
    rows = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        try:
            entry = path.lstat()
        except OSError:
            fail("installation tree changed")
        if stat.S_ISDIR(entry.st_mode):
            continue
        if not stat.S_ISREG(entry.st_mode):
            fail("installation tree contains an unsafe entry")
        payload = regular(path)
        rows.append(
            relative.encode("utf-8")
            + b"\0"
            + str(len(payload)).encode("ascii")
            + b"\0"
            + hashlib.sha256(payload).hexdigest().encode("ascii")
            + b"\n"
        )
    return hashlib.sha256(b"".join(rows)).hexdigest()


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key}")
        result[key] = value
    return result


def reject_json_constant(value):
    raise ValueError(f"non-finite JSON value {value}")


def valid_sha256(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def valid_utc(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(
        parsed
    )


if len(sys.argv) < 2:
    fail("launcher path is missing")
launcher_path = Path(sys.argv[1]).resolve()
sys.argv = [str(launcher_path), *sys.argv[2:]]
engine_root = launcher_path.parents[1]
expected_engine_root = Path(__ENGINE_TARGET__)
codex_home = Path(__CODEX_HOME__)
skill_root = Path(__SKILL_TARGET__)
if engine_root != expected_engine_root:
    fail("engine target path mismatch")
journal = codex_home / ".ship-flow-install-journal.json"
if os.path.lexists(journal):
    print("ship-flow installation incomplete: pending transaction", file=sys.stderr)
    raise SystemExit(78)
try:
    bundle = json.loads(
        regular(engine_root / "bundle.json").decode("utf-8"),
        parse_constant=reject_json_constant,
        object_pairs_hook=unique_json_object,
    )
except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
    fail("bundle metadata is invalid")
expected = {
    "schema_version",
    "skill_sha256",
    "engine_sha256",
    "launcher_sha256",
    "receipt_sha256",
    "python_executable",
    "installed_at",
}
if (
    not isinstance(bundle, dict)
    or set(bundle) != expected
    or type(bundle.get("schema_version")) is not int
    or bundle["schema_version"] != 1
):
    fail("bundle metadata schema is invalid")
for key in (
    "skill_sha256",
    "engine_sha256",
    "launcher_sha256",
    "receipt_sha256",
):
    if not valid_sha256(bundle[key]):
        fail("bundle metadata schema is invalid")
if (
    not isinstance(bundle["python_executable"], str)
    or not bundle["python_executable"]
    or Path(bundle["python_executable"]).resolve() != Path(sys.executable).resolve()
    or not valid_utc(bundle["installed_at"])
):
    fail("bundle metadata schema is invalid")
if hashlib.sha256(regular(launcher_path)).hexdigest() != bundle["launcher_sha256"]:
    fail("launcher digest mismatch")
if tree_digest(engine_root / "src" / "ship_flow") != bundle["engine_sha256"]:
    fail("engine digest mismatch")
if tree_digest(skill_root) != bundle["skill_sha256"]:
    fail("Skill digest mismatch")
sys.dont_write_bytecode = True
sys.path.insert(0, str(engine_root / "src"))
module = importlib.import_module("ship_flow.__main__")
entrypoint = getattr(module, "main", None)
if not callable(entrypoint):
    fail("engine entrypoint is missing")
raise SystemExit(entrypoint())
"""
    payload = (
        template.replace("__CODEX_HOME__", json.dumps(str(codex_home.resolve())))
        .replace("__SKILL_TARGET__", json.dumps(str(skill_target.resolve())))
        .replace("__ENGINE_TARGET__", json.dumps(str(engine_target.resolve())))
    )
    return (
        "#!/bin/sh\n"
        f'exec {shlex.quote(executable)} -c {shlex.quote(payload)} "$0" "$@"\n'
    ).encode("utf-8")


class Installer:
    def __init__(
        self,
        *,
        project_root: Path,
        codex_home: Path,
        skill_source: Path | None = None,
        engine_source: Path | None = None,
        pressure_spec: Path | None = None,
        receipt_path: Path | None = None,
        skill_target: Path | None = None,
        engine_target: Path | None = None,
        python_executable: Path | None = None,
        preflight: Callable[[], None] | None = None,
        checkpoint: Callable[[str], None] | None = None,
    ) -> None:
        self.project_root = Path(os.path.abspath(project_root))
        self.codex_home = Path(os.path.abspath(codex_home))
        self.skill_source = Path(
            os.path.abspath(skill_source or self.project_root / "skills" / "ship-flow")
        )
        self.engine_source = Path(
            os.path.abspath(engine_source or self.project_root / "src" / "ship_flow")
        )
        self.pressure_spec = Path(
            os.path.abspath(
                pressure_spec
                or self.project_root / "tests" / "skill" / "pressure-scenarios.md"
            )
        )
        self.receipt_path = Path(
            os.path.abspath(
                receipt_path
                or self.project_root / "tests" / "skill" / "validation-receipt.json"
            )
        )
        self.skill_target = Path(
            os.path.abspath(skill_target or self.codex_home / "skills" / "ship-flow")
        )
        self.engine_target = Path(
            os.path.abspath(engine_target or self.codex_home / "tools" / "ship-flow")
        )
        for target, label in (
            (self.skill_target, "Skill target"),
            (self.engine_target, "engine target"),
        ):
            try:
                relative = target.relative_to(self.codex_home)
            except ValueError as error:
                raise InstallError(f"{label} must stay inside CODEX_HOME") from error
            if not relative.parts:
                raise InstallError(f"{label} cannot be CODEX_HOME itself")
        if (
            self.skill_target == self.engine_target
            or self.skill_target in self.engine_target.parents
            or self.engine_target in self.skill_target.parents
        ):
            raise InstallError("Skill and engine targets must not overlap")
        self.python_executable = Path(
            python_executable or Path(sys.executable).resolve()
        )
        self.preflight = preflight or self._default_preflight
        self.checkpoint = checkpoint or (lambda _status: None)
        self.journal_path = self.codex_home / ".ship-flow-install-journal.json"

    def _default_preflight(self) -> None:
        if sys.version_info < (3, 11):
            raise InstallError("Ship Flow requires Python 3.11 or newer")
        environment = dict(os.environ)
        python_path = os.pathsep.join(
            (str(self.project_root / "src"), str(self.project_root))
        )
        existing = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            python_path if not existing else python_path + os.pathsep + existing
        )
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        commands = (
            (
                str(self.python_executable),
                "-m",
                "compileall",
                "-q",
                "src",
                "scripts",
            ),
            (
                str(self.python_executable),
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests/unit",
                "-v",
            ),
            (
                str(self.python_executable),
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests/integration",
                "-v",
            ),
        )
        with tempfile.TemporaryDirectory(prefix="ship-flow-pycache-") as cache:
            environment["PYTHONPYCACHEPREFIX"] = cache
            for command in commands:
                completed = subprocess.run(
                    command,
                    cwd=self.project_root,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    check=False,
                )
                if completed.returncode != 0:
                    tail = completed.stdout[-4000:]
                    raise InstallError(f"pre-install verification failed:\n{tail}")

    def _validate_sources(self) -> _DesiredBundle:
        receipt = validate_pressure_receipt(
            self.receipt_path,
            skill_source=self.skill_source,
            pressure_spec=self.pressure_spec,
        )
        engine_files = _collect_tree_files(
            self.engine_source,
            ignore_python_cache=True,
        )
        if not engine_files:
            raise InstallError("engine source is empty")
        names = {relative for relative, _path in engine_files}
        if not {"__init__.py", "__main__.py"}.issubset(names):
            raise InstallError("engine source is missing its package entrypoints")
        launcher = _launcher_bytes(
            self.python_executable,
            codex_home=self.codex_home,
            skill_target=self.skill_target,
            engine_target=self.engine_target,
        )
        return _DesiredBundle(
            skill_sha256=receipt.skill_sha256,
            engine_sha256=_tree_digest(
                self.engine_source,
                ignore_python_cache=True,
            ),
            launcher_sha256=hashlib.sha256(launcher).hexdigest(),
            receipt_sha256=receipt.receipt_sha256,
            launcher=launcher,
        )

    def _bundle_payload(self, desired: _DesiredBundle) -> dict[str, object]:
        return {
            "schema_version": 1,
            "skill_sha256": desired.skill_sha256,
            "engine_sha256": desired.engine_sha256,
            "launcher_sha256": desired.launcher_sha256,
            "receipt_sha256": desired.receipt_sha256,
            "python_executable": str(self.python_executable.resolve()),
            "installed_at": _utc_now(),
        }

    def _load_owned_bundle(self) -> dict[str, object] | None:
        skill_exists = os.path.lexists(self.skill_target)
        engine_exists = os.path.lexists(self.engine_target)
        if not skill_exists and not engine_exists:
            return None
        if not skill_exists or not engine_exists:
            raise InstallError(
                "only one Ship Flow target exists; refusing to guess ownership"
            )
        for path, label in (
            (self.skill_target, "installed Skill"),
            (self.engine_target, "installed engine"),
        ):
            metadata = _lstat(path, label=label)
            if not stat.S_ISDIR(metadata.st_mode):
                raise InstallError(f"{label} is not an owned real directory")
        bundle, _raw = _load_json(
            self.engine_target / "bundle.json",
            label="installed bundle metadata",
        )
        _exact_keys(
            bundle,
            {
                "schema_version",
                "skill_sha256",
                "engine_sha256",
                "launcher_sha256",
                "receipt_sha256",
                "python_executable",
                "installed_at",
            },
            label="installed bundle metadata",
        )
        if type(bundle["schema_version"]) is not int or bundle["schema_version"] != 1:
            raise InstallError("installed bundle metadata version is unsupported")
        for key in (
            "skill_sha256",
            "engine_sha256",
            "launcher_sha256",
            "receipt_sha256",
        ):
            _require_sha256(bundle[key], label=key)
        _require_utc(bundle["installed_at"], label="installed_at")
        if not isinstance(bundle["python_executable"], str):
            raise InstallError("installed Python identity is invalid")
        launcher = self.engine_target / "bin" / "ship"
        launcher_raw = _read_regular_file(launcher, label="installed launcher")
        actual = {
            "skill_sha256": canonical_tree_digest(self.skill_target),
            "engine_sha256": canonical_tree_digest(
                self.engine_target / "src" / "ship_flow"
            ),
            "launcher_sha256": hashlib.sha256(launcher_raw).hexdigest(),
        }
        for key, value in actual.items():
            if bundle[key] != value:
                raise InstallError(
                    f"installed {key} has local or unknown modifications"
                )
        return bundle

    def _stage(self, desired: _DesiredBundle) -> dict[str, object]:
        transaction_id = uuid.uuid4().hex
        stage_skill = self.codex_home / f".ship-flow-stage-{transaction_id}-skill"
        stage_engine = self.codex_home / f".ship-flow-stage-{transaction_id}-engine"
        backup_skill = self.codex_home / f".ship-flow-backup-{transaction_id}-skill"
        backup_engine = self.codex_home / f".ship-flow-backup-{transaction_id}-engine"
        for path in (stage_skill, stage_engine, backup_skill, backup_engine):
            if os.path.lexists(path):
                raise InstallError("installer-owned staging path unexpectedly exists")
        _copy_tree(self.skill_source, stage_skill)
        stage_engine.mkdir(mode=0o700)
        os.chmod(stage_engine, 0o700)
        (stage_engine / "src").mkdir(mode=0o700)
        (stage_engine / "bin").mkdir(mode=0o700)
        _copy_tree(
            self.engine_source,
            stage_engine / "src" / "ship_flow",
            ignore_python_cache=True,
        )
        _write_private_file(
            stage_engine / "bin" / "ship",
            desired.launcher,
            mode=0o700,
        )
        _fsync_directory(stage_engine / "bin")
        _fsync_directory(stage_engine / "src")
        _fsync_directory(stage_engine)
        if canonical_tree_digest(stage_skill) != desired.skill_sha256:
            raise InstallError("Skill changed while it was staged")
        if (
            canonical_tree_digest(stage_engine / "src" / "ship_flow")
            != desired.engine_sha256
        ):
            raise InstallError("engine changed while it was staged")
        if (
            hashlib.sha256(
                _read_regular_file(
                    stage_engine / "bin" / "ship", label="staged launcher"
                )
            ).hexdigest()
            != desired.launcher_sha256
        ):
            raise InstallError("launcher changed while it was staged")
        previous = self._load_owned_bundle()
        previous_engine_tree_sha256 = (
            canonical_tree_digest(self.engine_target) if previous is not None else None
        )
        journal: dict[str, object] = {
            "schema_version": 1,
            "mode": "install",
            "status": "STAGED",
            "transaction_id": transaction_id,
            "stage_skill": str(stage_skill),
            "stage_engine": str(stage_engine),
            "backup_skill": str(backup_skill),
            "backup_engine": str(backup_engine),
            "had_previous": previous is not None,
            "previous_skill_sha256": (
                previous["skill_sha256"] if previous is not None else None
            ),
            "previous_engine_sha256": (
                previous["engine_sha256"] if previous is not None else None
            ),
            "previous_launcher_sha256": (
                previous["launcher_sha256"] if previous is not None else None
            ),
            "previous_engine_tree_sha256": previous_engine_tree_sha256,
            "skill_sha256": desired.skill_sha256,
            "engine_sha256": desired.engine_sha256,
            "launcher_sha256": desired.launcher_sha256,
            "receipt_sha256": desired.receipt_sha256,
            "python_executable": str(self.python_executable.resolve()),
            "created_at": _utc_now(),
        }
        _atomic_private_json(self.journal_path, journal)
        return journal

    def _load_journal(self) -> dict[str, object]:
        journal, _raw = _load_json(self.journal_path, label="installation journal")
        required = {
            "schema_version",
            "mode",
            "status",
            "transaction_id",
            "stage_skill",
            "stage_engine",
            "backup_skill",
            "backup_engine",
            "had_previous",
            "previous_skill_sha256",
            "previous_engine_sha256",
            "previous_launcher_sha256",
            "previous_engine_tree_sha256",
            "skill_sha256",
            "engine_sha256",
            "launcher_sha256",
            "receipt_sha256",
            "python_executable",
            "created_at",
        }
        _exact_keys(journal, required, label="installation journal")
        if (
            type(journal["schema_version"]) is not int
            or journal["schema_version"] != 1
            or journal["mode"] != "install"
        ):
            raise InstallError("installation journal is unsupported")
        if journal["status"] not in _INSTALL_STATES:
            raise InstallError("installation journal status is invalid")
        if type(journal["had_previous"]) is not bool:
            raise InstallError("installation journal ownership is invalid")
        for key in (
            "skill_sha256",
            "engine_sha256",
            "launcher_sha256",
            "receipt_sha256",
        ):
            _require_sha256(journal[key], label=key)
        previous_keys = (
            "previous_skill_sha256",
            "previous_engine_sha256",
            "previous_launcher_sha256",
            "previous_engine_tree_sha256",
        )
        if journal["had_previous"]:
            for key in previous_keys:
                _require_sha256(journal[key], label=key)
        elif any(journal[key] is not None for key in previous_keys):
            raise InstallError("installation journal previous ownership is invalid")
        if not isinstance(journal["python_executable"], str) or journal[
            "python_executable"
        ] != str(self.python_executable.resolve()):
            raise InstallError("installation journal Python identity is invalid")
        _require_utc(journal["created_at"], label="journal created_at")
        transaction_id = journal["transaction_id"]
        if (
            not isinstance(transaction_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", transaction_id) is None
        ):
            raise InstallError("installation journal transaction ID is invalid")
        expected_paths = {
            "stage_skill": self.codex_home / f".ship-flow-stage-{transaction_id}-skill",
            "stage_engine": self.codex_home
            / f".ship-flow-stage-{transaction_id}-engine",
            "backup_skill": self.codex_home
            / f".ship-flow-backup-{transaction_id}-skill",
            "backup_engine": self.codex_home
            / f".ship-flow-backup-{transaction_id}-engine",
        }
        for key, expected in expected_paths.items():
            if journal[key] != str(expected):
                raise InstallError("installation journal path is not installer-owned")
        return journal

    def _journal_mode(self) -> str:
        journal, _raw = _load_json(
            self.journal_path,
            label="installation journal",
        )
        mode = journal.get("mode")
        if mode not in {"install", "uninstall"}:
            raise InstallError("installation journal is unsupported")
        return str(mode)

    def _load_uninstall_journal(self) -> dict[str, object]:
        journal, _raw = _load_json(
            self.journal_path,
            label="uninstall journal",
        )
        required = {
            "schema_version",
            "mode",
            "status",
            "transaction_id",
            "skill_sha256",
            "engine_sha256",
            "launcher_sha256",
            "receipt_sha256",
            "engine_target",
            "skill_target",
            "engine_backup",
            "skill_backup",
            "created_at",
        }
        _exact_keys(journal, required, label="uninstall journal")
        if (
            type(journal["schema_version"]) is not int
            or journal["schema_version"] != 1
            or journal["mode"] != "uninstall"
        ):
            raise InstallError("uninstall journal is unsupported")
        if journal["status"] not in {
            "STAGED",
            "ENGINE_PUBLISHED",
            "SKILL_PUBLISHED",
        }:
            raise InstallError("uninstall journal status is invalid")
        for key in (
            "skill_sha256",
            "engine_sha256",
            "launcher_sha256",
            "receipt_sha256",
        ):
            _require_sha256(journal[key], label=key)
        _require_utc(journal["created_at"], label="uninstall created_at")
        transaction_id = journal["transaction_id"]
        if (
            not isinstance(transaction_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", transaction_id) is None
        ):
            raise InstallError("uninstall journal transaction ID is invalid")
        expected = {
            "engine_target": self.engine_target,
            "skill_target": self.skill_target,
            "engine_backup": self.codex_home
            / f".ship-flow-uninstall-{transaction_id}-engine",
            "skill_backup": self.codex_home
            / f".ship-flow-uninstall-{transaction_id}-skill",
        }
        for key, path in expected.items():
            if journal[key] != str(path):
                raise InstallError("uninstall journal path is not installer-owned")
        return journal

    def _persist_status(self, journal: dict[str, object], status: str) -> None:
        journal["status"] = status
        _atomic_private_json(self.journal_path, journal)

    def _matches_engine_payload(
        self, path: Path, journal: Mapping[str, object]
    ) -> bool:
        try:
            return (
                canonical_tree_digest(path / "src" / "ship_flow")
                == journal["engine_sha256"]
                and hashlib.sha256(
                    _read_regular_file(path / "bin" / "ship", label="engine launcher")
                ).hexdigest()
                == journal["launcher_sha256"]
            )
        except InstallError:
            return False

    def _remove_verified_stage_engine(
        self,
        stage: Path,
        journal: Mapping[str, object],
    ) -> None:
        identity = _directory_identity(stage, label="staged engine")
        if not self._matches_engine_payload(stage, journal):
            raise InstallError("staged engine changed before cleanup")
        self._remove_owned_tree(stage, expected_identity=identity)

    def _remove_verified_stage_skill(
        self,
        stage: Path,
        journal: Mapping[str, object],
    ) -> None:
        identity = _directory_identity(stage, label="staged Skill")
        if canonical_tree_digest(stage) != journal["skill_sha256"]:
            raise InstallError("staged Skill changed before cleanup")
        self._remove_owned_tree(stage, expected_identity=identity)

    def _publish_engine(self, journal: dict[str, object]) -> None:
        stage = Path(str(journal["stage_engine"]))
        backup = Path(str(journal["backup_engine"]))
        if os.path.lexists(self.engine_target):
            if self._matches_engine_payload(self.engine_target, journal):
                if os.path.lexists(stage):
                    self._remove_verified_stage_engine(stage, journal)
                return
            if not journal["had_previous"] or os.path.lexists(backup):
                raise InstallError("engine target changed during installation")
            current = self._load_owned_bundle()
            if (
                current is None
                or current["engine_sha256"] != journal["previous_engine_sha256"]
            ):
                raise InstallError("previous engine identity is no longer current")
            os.rename(self.engine_target, backup)
            _fsync_directory(self.engine_target.parent)
        if not os.path.lexists(self.engine_target):
            if not os.path.lexists(stage):
                raise InstallError("staged engine is missing")
            os.rename(stage, self.engine_target)
            _fsync_directory(self.engine_target.parent)
        if not self._matches_engine_payload(self.engine_target, journal):
            raise InstallError("published engine digest does not match")

    def _publish_skill(self, journal: dict[str, object]) -> None:
        stage = Path(str(journal["stage_skill"]))
        backup = Path(str(journal["backup_skill"]))
        if os.path.lexists(self.skill_target):
            current_digest = canonical_tree_digest(self.skill_target)
            if current_digest == journal["skill_sha256"]:
                if os.path.lexists(stage):
                    self._remove_verified_stage_skill(stage, journal)
                return
            if not journal["had_previous"] or os.path.lexists(backup):
                raise InstallError("Skill target changed during installation")
            if current_digest != journal["previous_skill_sha256"]:
                raise InstallError("previous Skill identity is no longer current")
            os.rename(self.skill_target, backup)
            _fsync_directory(self.skill_target.parent)
        if not os.path.lexists(self.skill_target):
            if not os.path.lexists(stage):
                raise InstallError("staged Skill is missing")
            os.rename(stage, self.skill_target)
            _fsync_directory(self.skill_target.parent)
        if canonical_tree_digest(self.skill_target) != journal["skill_sha256"]:
            raise InstallError("published Skill digest does not match")

    def _activate(self, journal: dict[str, object]) -> None:
        desired = _DesiredBundle(
            skill_sha256=str(journal["skill_sha256"]),
            engine_sha256=str(journal["engine_sha256"]),
            launcher_sha256=str(journal["launcher_sha256"]),
            receipt_sha256=str(journal["receipt_sha256"]),
            launcher=b"",
        )
        _atomic_private_json(
            self.engine_target / "bundle.json", self._bundle_payload(desired)
        )
        bundle = self._load_owned_bundle()
        if bundle is None:
            raise InstallError("activated bundle cannot be verified")

    def _remove_owned_tree(
        self,
        path: Path,
        *,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        path = Path(os.path.abspath(path))
        try:
            relative = path.relative_to(self.codex_home)
        except ValueError as error:
            raise InstallError(
                "refusing to remove a path outside CODEX_HOME"
            ) from error
        if not relative.parts:
            raise InstallError("refusing to remove CODEX_HOME itself")
        if not os.path.lexists(path):
            if expected_identity is not None:
                raise InstallError("installer-owned cleanup path disappeared")
            return
        metadata = _lstat(path, label="installer-owned tree")
        if not stat.S_ISDIR(metadata.st_mode):
            raise InstallError("installer-owned cleanup path is unsafe")
        identity = (metadata.st_dev, metadata.st_ino)
        if expected_identity is not None and identity != expected_identity:
            raise InstallError("installer-owned cleanup path was replaced")
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise InstallError(
                "installer-owned cleanup path cannot be opened"
            ) from error

        def remove_contents(directory_descriptor: int) -> None:
            try:
                names = os.listdir(directory_descriptor)
            except OSError as error:
                raise InstallError(
                    "installer-owned cleanup tree cannot be enumerated"
                ) from error
            for name in names:
                try:
                    before = os.stat(
                        name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                except OSError as error:
                    raise InstallError(
                        "installer-owned cleanup entry cannot be inspected"
                    ) from error
                entry_identity = (before.st_dev, before.st_ino)
                if stat.S_ISDIR(before.st_mode):
                    try:
                        child_descriptor = os.open(
                            name,
                            flags,
                            dir_fd=directory_descriptor,
                        )
                    except OSError as error:
                        raise InstallError(
                            "installer-owned cleanup directory cannot be opened"
                        ) from error
                    try:
                        opened = os.fstat(child_descriptor)
                        if (opened.st_dev, opened.st_ino) != entry_identity:
                            raise InstallError(
                                "installer-owned cleanup directory was replaced"
                            )
                        remove_contents(child_descriptor)
                        current = os.stat(
                            name,
                            dir_fd=directory_descriptor,
                            follow_symlinks=False,
                        )
                        if (current.st_dev, current.st_ino) != entry_identity:
                            raise InstallError(
                                "installer-owned cleanup directory was replaced"
                            )
                        os.rmdir(name, dir_fd=directory_descriptor)
                    except OSError as error:
                        raise InstallError(
                            "installer-owned cleanup directory changed"
                        ) from error
                    finally:
                        os.close(child_descriptor)
                    continue
                if not stat.S_ISREG(before.st_mode):
                    raise InstallError(
                        "installer-owned cleanup tree contains an unsafe entry"
                    )
                file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                try:
                    file_descriptor = os.open(
                        name,
                        file_flags,
                        dir_fd=directory_descriptor,
                    )
                except OSError as error:
                    raise InstallError(
                        "installer-owned cleanup file cannot be opened"
                    ) from error
                try:
                    opened = os.fstat(file_descriptor)
                    if (opened.st_dev, opened.st_ino) != entry_identity:
                        raise InstallError("installer-owned cleanup file was replaced")
                    current = os.stat(
                        name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                    if (current.st_dev, current.st_ino) != entry_identity:
                        raise InstallError("installer-owned cleanup file was replaced")
                    os.unlink(name, dir_fd=directory_descriptor)
                except OSError as error:
                    raise InstallError(
                        "installer-owned cleanup file changed"
                    ) from error
                finally:
                    os.close(file_descriptor)

        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != identity:
                raise InstallError("installer-owned cleanup path was replaced")
            remove_contents(descriptor)
            current_identity = _directory_identity(
                path,
                label="installer-owned cleanup path",
            )
            if current_identity != identity:
                raise InstallError("installer-owned cleanup path was replaced")
            try:
                os.rmdir(path)
            except OSError as error:
                raise InstallError(
                    "installer-owned cleanup path cannot be removed"
                ) from error
        finally:
            os.close(descriptor)
        _fsync_directory(path.parent)

    def _finish_install(self, journal: dict[str, object]) -> InstallResult:
        status = str(journal["status"])
        if status == "STAGED":
            self._publish_engine(journal)
            self._persist_status(journal, "ENGINE_PUBLISHED")
            self.checkpoint("ENGINE_PUBLISHED")
            status = "ENGINE_PUBLISHED"
        if status == "ENGINE_PUBLISHED":
            self._publish_skill(journal)
            self._persist_status(journal, "SKILL_PUBLISHED")
            self.checkpoint("SKILL_PUBLISHED")
            status = "SKILL_PUBLISHED"
        if status == "SKILL_PUBLISHED":
            self._activate(journal)
            self._persist_status(journal, "ACTIVATED")
            self.checkpoint("ACTIVATED")
        activated = self._load_owned_bundle()
        if activated is None or any(
            activated[key] != journal[key]
            for key in (
                "skill_sha256",
                "engine_sha256",
                "launcher_sha256",
                "receipt_sha256",
            )
        ):
            raise InstallError(
                "activated targets changed before installation finalization"
            )
        for key in ("stage_skill", "stage_engine"):
            if os.path.lexists(Path(str(journal[key]))):
                raise InstallError("an already-published stage path reappeared")
        backup_skill = Path(str(journal["backup_skill"]))
        backup_engine = Path(str(journal["backup_engine"]))
        if not journal["had_previous"] and (
            os.path.lexists(backup_skill) or os.path.lexists(backup_engine)
        ):
            raise InstallError("an unexpected installation backup appeared")
        if os.path.lexists(backup_skill):
            skill_identity = _directory_identity(
                backup_skill,
                label="installation Skill backup",
            )
            if canonical_tree_digest(backup_skill) != journal["previous_skill_sha256"]:
                raise InstallError("installation Skill backup changed before cleanup")
            self._remove_owned_tree(
                backup_skill,
                expected_identity=skill_identity,
            )
        if os.path.lexists(backup_engine):
            engine_identity = _directory_identity(
                backup_engine,
                label="installation engine backup",
            )
            if (
                canonical_tree_digest(backup_engine)
                != journal["previous_engine_tree_sha256"]
            ):
                raise InstallError("installation engine backup changed before cleanup")
            self._remove_owned_tree(
                backup_engine,
                expected_identity=engine_identity,
            )
        try:
            self.journal_path.unlink()
        except OSError as error:
            raise InstallError("installation journal cannot be finalized") from error
        _fsync_directory(self.codex_home)
        return InstallResult(
            changed=True,
            skill_sha256=str(journal["skill_sha256"]),
            engine_sha256=str(journal["engine_sha256"]),
            skill_target=self.skill_target,
            engine_target=self.engine_target,
        )

    def _move_uninstall_target(
        self,
        *,
        target: Path,
        backup: Path,
        matches: Callable[[Path], bool],
        label: str,
    ) -> None:
        target_exists = os.path.lexists(target)
        backup_exists = os.path.lexists(backup)
        if target_exists and backup_exists:
            raise InstallError(f"{label} target and backup both exist")
        if target_exists:
            if not matches(target):
                raise InstallError(f"{label} target changed during uninstall")
            os.rename(target, backup)
            _fsync_directory(target.parent)
            if backup.parent != target.parent:
                _fsync_directory(backup.parent)
        elif not backup_exists:
            raise InstallError(f"{label} target and backup are both missing")
        if not matches(backup):
            raise InstallError(f"{label} backup digest does not match")

    def _finish_uninstall(self, journal: dict[str, object]) -> InstallResult:
        engine_backup = Path(str(journal["engine_backup"]))
        skill_backup = Path(str(journal["skill_backup"]))
        status = str(journal["status"])
        if status == "STAGED":
            self._move_uninstall_target(
                target=self.engine_target,
                backup=engine_backup,
                matches=lambda path: self._matches_engine_payload(path, journal),
                label="engine",
            )
            self._persist_status(journal, "ENGINE_PUBLISHED")
            self.checkpoint("UNINSTALL_ENGINE_PUBLISHED")
            status = "ENGINE_PUBLISHED"
        if status == "ENGINE_PUBLISHED":
            self._move_uninstall_target(
                target=self.skill_target,
                backup=skill_backup,
                matches=lambda path: (
                    canonical_tree_digest(path) == journal["skill_sha256"]
                ),
                label="Skill",
            )
            self._persist_status(journal, "SKILL_PUBLISHED")
            self.checkpoint("UNINSTALL_SKILL_PUBLISHED")
        if os.path.lexists(self.engine_target) or os.path.lexists(self.skill_target):
            raise InstallError("uninstall targets reappeared before cleanup")
        if os.path.lexists(engine_backup):
            engine_identity = _directory_identity(
                engine_backup,
                label="engine uninstall backup",
            )
            if not self._matches_engine_payload(engine_backup, journal):
                raise InstallError("engine backup changed before cleanup")
            self._remove_owned_tree(
                engine_backup,
                expected_identity=engine_identity,
            )
        if os.path.lexists(skill_backup):
            skill_identity = _directory_identity(
                skill_backup,
                label="Skill uninstall backup",
            )
            if canonical_tree_digest(skill_backup) != journal["skill_sha256"]:
                raise InstallError("Skill backup changed before cleanup")
            self._remove_owned_tree(
                skill_backup,
                expected_identity=skill_identity,
            )
        try:
            self.journal_path.unlink()
        except OSError as error:
            raise InstallError("uninstall journal cannot be finalized") from error
        _fsync_directory(self.codex_home)
        return InstallResult(
            True,
            str(journal["skill_sha256"]),
            str(journal["engine_sha256"]),
            self.skill_target,
            self.engine_target,
        )

    def install(self) -> InstallResult:
        desired = self._validate_sources()
        self.preflight()
        confirmed = self._validate_sources()
        if desired != confirmed:
            raise InstallError("installation sources changed during preflight")
        _ensure_directory(self.codex_home)
        _ensure_directory(self.skill_target.parent)
        _ensure_directory(self.engine_target.parent)
        with _installation_lock(self.codex_home):
            if os.path.lexists(self.journal_path):
                if self._journal_mode() == "uninstall":
                    self._finish_uninstall(self._load_uninstall_journal())
                else:
                    journal = self._load_journal()
                    for key in (
                        "skill_sha256",
                        "engine_sha256",
                        "launcher_sha256",
                        "receipt_sha256",
                    ):
                        if journal[key] != getattr(desired, key):
                            raise InstallError(
                                "pending installation is for different sources"
                            )
                    return self._finish_install(journal)
            existing = self._load_owned_bundle()
            if existing is not None and all(
                existing[key] == getattr(desired, key)
                for key in (
                    "skill_sha256",
                    "engine_sha256",
                    "launcher_sha256",
                    "receipt_sha256",
                )
            ):
                return InstallResult(
                    changed=False,
                    skill_sha256=desired.skill_sha256,
                    engine_sha256=desired.engine_sha256,
                    skill_target=self.skill_target,
                    engine_target=self.engine_target,
                )
            journal = self._stage(desired)
            self.checkpoint("STAGED")
            return self._finish_install(journal)

    def uninstall(self) -> InstallResult:
        if not os.path.lexists(self.codex_home):
            return InstallResult(False, "", "", self.skill_target, self.engine_target)
        _ensure_directory(self.codex_home)
        with _installation_lock(self.codex_home):
            if os.path.lexists(self.journal_path):
                if self._journal_mode() == "uninstall":
                    return self._finish_uninstall(self._load_uninstall_journal())
                self._finish_install(self._load_journal())
            bundle = self._load_owned_bundle()
            if bundle is None:
                return InstallResult(
                    False, "", "", self.skill_target, self.engine_target
                )
            transaction_id = uuid.uuid4().hex
            engine_backup = (
                self.codex_home / f".ship-flow-uninstall-{transaction_id}-engine"
            )
            skill_backup = (
                self.codex_home / f".ship-flow-uninstall-{transaction_id}-skill"
            )
            journal = {
                "schema_version": 1,
                "mode": "uninstall",
                "status": "STAGED",
                "transaction_id": transaction_id,
                "skill_sha256": bundle["skill_sha256"],
                "engine_sha256": bundle["engine_sha256"],
                "launcher_sha256": bundle["launcher_sha256"],
                "receipt_sha256": bundle["receipt_sha256"],
                "engine_target": str(self.engine_target),
                "skill_target": str(self.skill_target),
                "engine_backup": str(engine_backup),
                "skill_backup": str(skill_backup),
                "created_at": _utc_now(),
            }
            _atomic_private_json(self.journal_path, journal)
            self.checkpoint("UNINSTALL_STAGED")
            return self._finish_uninstall(journal)


def _resolve_path(value: str | None, default: Path) -> Path:
    if value is None:
        return default
    return Path(value).expanduser().absolute()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and atomically install the local Codex Ship Flow tool."
    )
    parser.add_argument("--project-root")
    parser.add_argument("--codex-home")
    parser.add_argument("--source")
    parser.add_argument("--target")
    parser.add_argument("--engine-source")
    parser.add_argument("--engine-target")
    parser.add_argument("--receipt")
    parser.add_argument("--pressure-spec")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    project_root = _resolve_path(
        args.project_root,
        Path(__file__).resolve().parents[1],
    )
    if args.codex_home:
        codex_home = Path(args.codex_home).expanduser().absolute()
    elif args.target:
        target = Path(args.target).expanduser().absolute()
        if target.name != "ship-flow" or target.parent.name != "skills":
            print("--target must end in skills/ship-flow", file=sys.stderr)
            return 2
        codex_home = target.parent.parent
    else:
        codex_home = (
            Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
            .expanduser()
            .absolute()
        )
    installer = Installer(
        project_root=project_root,
        codex_home=codex_home,
        skill_source=_resolve_path(args.source, project_root / "skills" / "ship-flow"),
        engine_source=_resolve_path(
            args.engine_source,
            project_root / "src" / "ship_flow",
        ),
        pressure_spec=_resolve_path(
            args.pressure_spec,
            project_root / "tests" / "skill" / "pressure-scenarios.md",
        ),
        receipt_path=_resolve_path(
            args.receipt,
            project_root / "tests" / "skill" / "validation-receipt.json",
        ),
        skill_target=_resolve_path(
            args.target,
            codex_home / "skills" / "ship-flow",
        ),
        engine_target=_resolve_path(
            args.engine_target,
            codex_home / "tools" / "ship-flow",
        ),
    )
    try:
        result = installer.uninstall() if args.uninstall else installer.install()
    except InstallError as error:
        if args.json_output:
            print(
                json.dumps(
                    {"ok": False, "error": str(error)},
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        else:
            print(f"Ship Flow 安装失败：{error}", file=sys.stderr)
        return 1
    payload = {
        "ok": True,
        "changed": result.changed,
        "operation": "uninstall" if args.uninstall else "install",
        "skill_target": str(result.skill_target),
        "engine_target": str(result.engine_target),
        "skill_sha256": result.skill_sha256,
        "engine_sha256": result.engine_sha256,
    }
    if args.json_output:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        verb = "已更新" if result.changed else "无需更新"
        print(f"Ship Flow {verb}：{result.skill_target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
