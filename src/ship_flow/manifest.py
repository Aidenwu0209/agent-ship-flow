from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, TypeVar


MANIFEST_VERSION = 1
_ALLOWED_PLACEHOLDERS = frozenset(
    {"repo", "worktree", "branch", "base_branch", "remote"}
)
_PLACEHOLDER = re.compile(r"\$\{([^}]*)\}")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DEFAULT_MAX_LOG_BYTES = 1_048_576


def _non_empty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _validate_placeholders(value: str, field: str) -> None:
    for placeholder in _PLACEHOLDER.findall(value):
        if placeholder not in _ALLOWED_PLACEHOLDERS:
            raise ValueError(f"{field} contains an unknown placeholder")
    if "${" in _PLACEHOLDER.sub("", value):
        raise ValueError(f"{field} contains an invalid placeholder")


def _argv(value: object, field: str = "argv") -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise ValueError(f"{field} must be an argv array")
    result = tuple(value)
    if not result and field == "argv":
        raise ValueError("argv array must not be empty")
    for token in result:
        if not isinstance(token, str):
            raise ValueError(f"{field} array must contain only strings")
        _validate_placeholders(token, field)
    return result


def _positive_integer(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _environment_allowlist(value: object) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise ValueError("env_allowlist must be an array")
    result = tuple(value)
    if any(
        not isinstance(name, str) or _ENVIRONMENT_NAME.fullmatch(name) is None
        for name in result
    ):
        raise ValueError("env_allowlist must contain environment variable names")
    return result


@dataclass(frozen=True)
class CommandSpec:
    name: str
    argv: tuple[str, ...]
    category: str | None = None
    timeout_seconds: int = 900
    cwd: str = "."
    env_allowlist: tuple[str, ...] = ()
    max_log_bytes: int = _DEFAULT_MAX_LOG_BYTES
    shell_approved: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _non_empty_string(self.name, "name"))
        object.__setattr__(self, "argv", _argv(self.argv))
        if self.category is not None:
            object.__setattr__(
                self, "category", _non_empty_string(self.category, "category")
            )
        object.__setattr__(
            self,
            "timeout_seconds",
            _positive_integer(self.timeout_seconds, "timeout_seconds"),
        )
        object.__setattr__(self, "cwd", _non_empty_string(self.cwd, "cwd"))
        if "\x00" in self.cwd:
            raise ValueError("cwd must not contain NUL")
        object.__setattr__(
            self,
            "env_allowlist",
            _environment_allowlist(self.env_allowlist),
        )
        object.__setattr__(
            self,
            "max_log_bytes",
            _positive_integer(self.max_log_bytes, "max_log_bytes"),
        )
        if type(self.shell_approved) is not bool:
            raise ValueError("shell_approved must be a boolean")


@dataclass(frozen=True)
class OperationSpec:
    name: str
    target: str
    argv: tuple[str, ...]
    kind: str = ""
    effect: str = "read_only"
    idempotency: str | None = None
    probe_argv: tuple[str, ...] = ()
    data_impact: str = "none"
    timeout_seconds: int = 900

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _non_empty_string(self.name, "name"))
        object.__setattr__(self, "target", _non_empty_string(self.target, "target"))
        _validate_placeholders(self.target, "target")
        object.__setattr__(self, "argv", _argv(self.argv))
        if self.kind:
            object.__setattr__(self, "kind", _non_empty_string(self.kind, "kind"))
        object.__setattr__(self, "effect", _non_empty_string(self.effect, "effect"))
        if self.effect not in {"read_only", "external_write", "destructive"}:
            raise ValueError("unknown effect")
        object.__setattr__(self, "probe_argv", _argv(self.probe_argv, "probe_argv"))
        object.__setattr__(
            self,
            "timeout_seconds",
            _positive_integer(self.timeout_seconds, "timeout_seconds"),
        )

        if self.idempotency not in (None, "safe", "probe", "manual_reconcile"):
            raise ValueError("unknown idempotency policy")
        if (
            self.effect in {"external_write", "destructive"}
            and self.idempotency is None
        ):
            raise ValueError(f"{self.effect} operations require idempotency")
        if self.idempotency == "probe" and not self.probe_argv:
            raise ValueError("probe idempotency requires probe_argv")
        if self.data_impact not in {"none", "possible"}:
            raise ValueError("data_impact must be none or possible")


_Spec = TypeVar("_Spec", CommandSpec, OperationSpec)


def _spec_tuple(value: object, expected: type[_Spec], field: str) -> tuple[_Spec, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise ValueError(f"{field} must be an array")
    result = tuple(value)
    if not all(isinstance(item, expected) for item in result):
        raise ValueError(f"{field} contains an invalid specification")
    return result


@dataclass(frozen=True)
class Manifest:
    project_name: str
    base_branch: str
    remote: str
    verification_steps: tuple[CommandSpec, ...]
    release_required: bool
    development_setup: tuple[CommandSpec, ...] = ()
    release_steps: tuple[OperationSpec, ...] = ()
    release_healthchecks: tuple[CommandSpec, ...] = ()
    rollback_steps: tuple[OperationSpec, ...] = ()
    rollback_healthchecks: tuple[CommandSpec, ...] = ()
    max_review_rounds: int = 3
    max_verification_rounds: int = 3
    require_plan_approval: bool = True
    require_release_approval: bool = True
    require_cleanup_approval: bool = True
    require_clean_base: bool = True
    version: int = MANIFEST_VERSION

    def __post_init__(self) -> None:
        for field in ("project_name", "base_branch", "remote"):
            object.__setattr__(
                self, field, _non_empty_string(getattr(self, field), field)
            )
        if type(self.version) is not int or self.version != MANIFEST_VERSION:
            raise ValueError("unsupported manifest version")
        if type(self.release_required) is not bool:
            raise ValueError("release_required must be a boolean")

        command_fields = (
            "development_setup",
            "verification_steps",
            "release_healthchecks",
            "rollback_healthchecks",
        )
        for field in command_fields:
            object.__setattr__(
                self,
                field,
                _spec_tuple(getattr(self, field), CommandSpec, field),
            )
        for field in ("release_steps", "rollback_steps"):
            object.__setattr__(
                self,
                field,
                _spec_tuple(getattr(self, field), OperationSpec, field),
            )

        if not self.verification_steps:
            raise ValueError("manifest requires at least one verification command")
        if self.release_required and not self.release_steps:
            raise ValueError("release.required=true requires at least one release step")
        if any(step.kind for step in self.rollback_steps):
            raise ValueError("rollback steps must use the canonical empty kind")
        if (
            any(step.kind == "deploy" for step in self.release_steps)
            and not self.release_healthchecks
        ):
            raise ValueError("deploy release steps require a healthcheck")

        for field in ("max_review_rounds", "max_verification_rounds"):
            object.__setattr__(
                self, field, _positive_integer(getattr(self, field), field)
            )
        for field in (
            "require_plan_approval",
            "require_release_approval",
            "require_cleanup_approval",
            "require_clean_base",
        ):
            if type(getattr(self, field)) is not bool:
                raise ValueError(f"{field} must be a boolean")


def detect_manifest(repository: Path | str) -> Manifest:
    root = Path(repository)
    if (root / "package.json").is_file():
        command = CommandSpec("test", ("npm", "test"), "unit")
    elif any((root / marker).is_file() for marker in ("pyproject.toml", "setup.py")):
        command = CommandSpec(
            "unit",
            ("python3", "-m", "unittest", "discover", "-s", "tests", "-v"),
            "unit",
        )
    elif (root / "go.mod").is_file():
        command = CommandSpec("test", ("go", "test", "./..."), "unit")
    elif (root / "Cargo.toml").is_file():
        command = CommandSpec("test", ("cargo", "test"), "unit")
    else:
        command = CommandSpec("diff-check", ("git", "diff", "--check"), "lint")
    return Manifest(
        project_name=root.name,
        base_branch="main",
        remote="origin",
        verification_steps=(command,),
        release_required=False,
    )


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a table")
    return value


def _fields(
    value: Mapping[str, Any],
    field: str,
    allowed: set[str],
    required: set[str] = frozenset(),
) -> None:
    unexpected = set(value) - allowed
    if unexpected:
        raise ValueError(
            f"{field} has unexpected fields: {', '.join(sorted(unexpected))}"
        )
    missing = required - set(value)
    if missing:
        raise ValueError(f"{field} is missing fields: {', '.join(sorted(missing))}")


def _entries(value: object, field: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array of tables")
    return [_mapping(item, field) for item in value]


def _parse_command(
    value: Mapping[str, Any], field: str, *, category_allowed: bool
) -> CommandSpec:
    allowed = {
        "name",
        "argv",
        "timeout_seconds",
        "cwd",
        "env_allowlist",
        "max_log_bytes",
        "shell_approved",
    }
    if category_allowed:
        allowed.add("category")
    _fields(value, field, allowed, {"name", "argv"})
    return CommandSpec(
        name=value["name"],
        category=value.get("category"),
        argv=_argv(value["argv"]),
        timeout_seconds=value.get("timeout_seconds", 900),
        cwd=value.get("cwd", "."),
        env_allowlist=value.get("env_allowlist", []),
        max_log_bytes=value.get("max_log_bytes", _DEFAULT_MAX_LOG_BYTES),
        shell_approved=value.get("shell_approved", False),
    )


def _parse_operation(
    value: Mapping[str, Any], field: str, *, rollback: bool
) -> OperationSpec:
    common = {
        "name",
        "target",
        "argv",
        "effect",
        "idempotency",
        "probe_argv",
        "timeout_seconds",
    }
    allowed = common | ({"data_impact"} if rollback else {"kind"})
    required = {"name", "target", "argv", "effect"}
    required.add("data_impact" if rollback else "kind")
    _fields(value, field, allowed, required)
    probe_argv = value.get("probe_argv", [])
    return OperationSpec(
        name=value["name"],
        kind="" if rollback else value["kind"],
        target=value["target"],
        argv=_argv(value["argv"]),
        effect=value["effect"],
        idempotency=value.get("idempotency"),
        probe_argv=_argv(probe_argv, "probe_argv"),
        data_impact=value.get("data_impact", "none"),
        timeout_seconds=value.get("timeout_seconds", 900),
    )


def load_manifest(path: Path | str) -> Manifest:
    with Path(path).open("rb") as source:
        data = tomllib.load(source)
    _fields(
        data,
        "manifest",
        {
            "version",
            "project",
            "development",
            "verification",
            "release",
            "rollback",
            "policy",
        },
        {"version", "project", "verification", "release"},
    )
    project = _mapping(data["project"], "project")
    _fields(
        project,
        "project",
        {"name", "base_branch", "remote"},
        {"name", "base_branch", "remote"},
    )

    development = _mapping(data.get("development", {}), "development")
    _fields(development, "development", {"setup"})
    verification = _mapping(data["verification"], "verification")
    _fields(verification, "verification", {"steps"}, {"steps"})
    release = _mapping(data["release"], "release")
    _fields(release, "release", {"required", "steps", "healthchecks"}, {"required"})
    rollback = _mapping(data.get("rollback", {}), "rollback")
    _fields(rollback, "rollback", {"steps", "healthchecks"})
    policy = _mapping(data.get("policy", {}), "policy")
    policy_fields = {
        "max_review_rounds",
        "max_verification_rounds",
        "require_plan_approval",
        "require_release_approval",
        "require_cleanup_approval",
        "require_clean_base",
    }
    _fields(policy, "policy", policy_fields)

    return Manifest(
        version=data["version"],
        project_name=project["name"],
        base_branch=project["base_branch"],
        remote=project["remote"],
        development_setup=tuple(
            _parse_command(item, "development.setup", category_allowed=True)
            for item in _entries(development.get("setup", []), "development.setup")
        ),
        verification_steps=tuple(
            _parse_command(item, "verification.steps", category_allowed=True)
            for item in _entries(verification["steps"], "verification.steps")
        ),
        release_required=release["required"],
        release_steps=tuple(
            _parse_operation(item, "release.steps", rollback=False)
            for item in _entries(release.get("steps", []), "release.steps")
        ),
        release_healthchecks=tuple(
            _parse_command(item, "release.healthchecks", category_allowed=True)
            for item in _entries(
                release.get("healthchecks", []), "release.healthchecks"
            )
        ),
        rollback_steps=tuple(
            _parse_operation(item, "rollback.steps", rollback=True)
            for item in _entries(rollback.get("steps", []), "rollback.steps")
        ),
        rollback_healthchecks=tuple(
            _parse_command(item, "rollback.healthchecks", category_allowed=True)
            for item in _entries(
                rollback.get("healthchecks", []), "rollback.healthchecks"
            )
        ),
        max_review_rounds=policy.get("max_review_rounds", 3),
        max_verification_rounds=policy.get("max_verification_rounds", 3),
        require_plan_approval=policy.get("require_plan_approval", True),
        require_release_approval=policy.get("require_release_approval", True),
        require_cleanup_approval=policy.get("require_cleanup_approval", True),
        require_clean_base=policy.get("require_clean_base", True),
    )


def _quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_argv(value: tuple[str, ...]) -> str:
    return "[" + ", ".join(_quoted(token) for token in value) + "]"


def _command_lines(command: CommandSpec, *, category: bool) -> list[str]:
    lines = [f"name = {_quoted(command.name)}"]
    if category and command.category is not None:
        lines.append(f"category = {_quoted(command.category)}")
    lines.extend(
        [
            f"argv = {_toml_argv(command.argv)}",
            f"timeout_seconds = {command.timeout_seconds}",
            f"cwd = {_quoted(command.cwd)}",
            f"env_allowlist = {_toml_argv(command.env_allowlist)}",
            f"max_log_bytes = {command.max_log_bytes}",
            f"shell_approved = {str(command.shell_approved).lower()}",
        ]
    )
    return lines


def _operation_lines(operation: OperationSpec, *, rollback: bool) -> list[str]:
    lines = [f"name = {_quoted(operation.name)}"]
    if not rollback:
        lines.append(f"kind = {_quoted(operation.kind)}")
    lines.extend(
        [
            f"target = {_quoted(operation.target)}",
            f"argv = {_toml_argv(operation.argv)}",
            f"effect = {_quoted(operation.effect)}",
        ]
    )
    if operation.idempotency is not None:
        lines.append(f"idempotency = {_quoted(operation.idempotency)}")
    if operation.probe_argv:
        lines.append(f"probe_argv = {_toml_argv(operation.probe_argv)}")
    if rollback:
        lines.append(f"data_impact = {_quoted(operation.data_impact)}")
    lines.append(f"timeout_seconds = {operation.timeout_seconds}")
    return lines


def _dump_manifest(manifest: Manifest) -> str:
    if type(manifest.version) is not int or manifest.version != MANIFEST_VERSION:
        raise ValueError("unsupported manifest version")
    lines = [
        f"version = {manifest.version}",
        "",
        "[project]",
        f"name = {_quoted(manifest.project_name)}",
        f"base_branch = {_quoted(manifest.base_branch)}",
        f"remote = {_quoted(manifest.remote)}",
    ]
    for command in manifest.development_setup:
        lines.extend(
            ["", "[[development.setup]]", *_command_lines(command, category=True)]
        )
    for command in manifest.verification_steps:
        lines.extend(
            ["", "[[verification.steps]]", *_command_lines(command, category=True)]
        )
    lines.extend(
        ["", "[release]", f"required = {str(manifest.release_required).lower()}"]
    )
    for operation in manifest.release_steps:
        lines.extend(
            ["", "[[release.steps]]", *_operation_lines(operation, rollback=False)]
        )
    for command in manifest.release_healthchecks:
        lines.extend(
            ["", "[[release.healthchecks]]", *_command_lines(command, category=True)]
        )
    for operation in manifest.rollback_steps:
        lines.extend(
            ["", "[[rollback.steps]]", *_operation_lines(operation, rollback=True)]
        )
    for command in manifest.rollback_healthchecks:
        lines.extend(
            ["", "[[rollback.healthchecks]]", *_command_lines(command, category=True)]
        )
    lines.extend(
        [
            "",
            "[policy]",
            f"max_review_rounds = {manifest.max_review_rounds}",
            f"max_verification_rounds = {manifest.max_verification_rounds}",
            f"require_plan_approval = {str(manifest.require_plan_approval).lower()}",
            f"require_release_approval = {str(manifest.require_release_approval).lower()}",
            f"require_cleanup_approval = {str(manifest.require_cleanup_approval).lower()}",
            f"require_clean_base = {str(manifest.require_clean_base).lower()}",
        ]
    )
    return "\n".join(lines) + "\n"


def write_manifest(path: Path | str, manifest: Manifest) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(_dump_manifest(manifest), encoding="utf-8")


def manifest_digest(manifest: Manifest) -> str:
    normalized = _dump_manifest(manifest).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()
