from __future__ import annotations

import hashlib
import json
import re
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterator, Mapping

from .model import LEGAL_TRANSITIONS, Phase, RunState
from .store import (
    FileLock,
    InvalidTransitionError,
    StateCorruptionError,
    StateNotFoundError,
    StateStore,
    StaleRevisionError,
    _atomic_write_private_json,
    _private_directory_names,
    _read_bounded_private_file,
    _remove_private_file,
)


_SCHEMA_VERSION = 1
_MAX_AUTHORIZATION_BYTES = 1024 * 1024
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class ExecutionMode(str, Enum):
    AUTONOMOUS = "autonomous"
    STRICT = "strict"


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


def _require_exact_keys(value: Mapping[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise ValueError("authorization record has unexpected or missing fields")


def _require_non_empty(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _require_optional_non_empty(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    return _require_non_empty(value, label=label)


def _require_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _require_non_negative_int(value: object, *, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _require_positive_int(value: object, *, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


@dataclass(frozen=True)
class AuthorizationContract:
    run_id: str
    generation: int
    mode: ExecutionMode
    goal: str
    repository: str
    worktree: str
    branch: str
    manifest_sha256: str
    release_target: str | None
    previous_release: str | None
    state_revision: int
    created_at: str
    schema_version: int = _SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "generation": self.generation,
            "mode": self.mode.value,
            "goal": self.goal,
            "repository": self.repository,
            "worktree": self.worktree,
            "branch": self.branch,
            "manifest_sha256": self.manifest_sha256,
            "release_target": self.release_target,
            "previous_release": self.previous_release,
            "state_revision": self.state_revision,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> AuthorizationContract:
        _require_exact_keys(
            value,
            {
                "schema_version",
                "run_id",
                "generation",
                "mode",
                "goal",
                "repository",
                "worktree",
                "branch",
                "manifest_sha256",
                "release_target",
                "previous_release",
                "state_revision",
                "created_at",
            },
        )
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise ValueError("unsupported authorization contract schema")
        try:
            mode = ExecutionMode(value["mode"])
        except (TypeError, ValueError) as error:
            raise ValueError("unknown execution mode") from error
        return cls(
            run_id=_require_non_empty(value["run_id"], label="run_id"),
            generation=_require_positive_int(value["generation"], label="generation"),
            mode=mode,
            goal=_require_non_empty(value["goal"], label="goal"),
            repository=_require_non_empty(value["repository"], label="repository"),
            worktree=_require_non_empty(value["worktree"], label="worktree"),
            branch=_require_non_empty(value["branch"], label="branch"),
            manifest_sha256=_require_sha256(
                value["manifest_sha256"], label="manifest_sha256"
            ),
            release_target=_require_optional_non_empty(
                value["release_target"], label="release_target"
            ),
            previous_release=_require_optional_non_empty(
                value["previous_release"], label="previous_release"
            ),
            state_revision=_require_non_negative_int(
                value["state_revision"], label="state_revision"
            ),
            created_at=_require_non_empty(value["created_at"], label="created_at"),
            schema_version=1,
        )

    def digest(self) -> str:
        return _digest(self.to_dict())


@dataclass(frozen=True)
class ScopeChangeRequest:
    request_id: str
    run_id: str
    contract_digest: str
    contract_generation: int
    reason: str
    summary: str
    proposed_goal: str
    proposed_manifest_sha256: str
    proposed_release_target: str | None
    proposed_previous_release: str | None
    requested_at: str
    gate_revision: int
    schema_version: int = _SCHEMA_VERSION

    def _identity_payload(self) -> dict[str, object]:
        payload = self.to_dict()
        payload.pop("request_id")
        return payload

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "run_id": self.run_id,
            "contract_digest": self.contract_digest,
            "contract_generation": self.contract_generation,
            "reason": self.reason,
            "summary": self.summary,
            "proposed_goal": self.proposed_goal,
            "proposed_manifest_sha256": self.proposed_manifest_sha256,
            "proposed_release_target": self.proposed_release_target,
            "proposed_previous_release": self.proposed_previous_release,
            "requested_at": self.requested_at,
            "gate_revision": self.gate_revision,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ScopeChangeRequest:
        _require_exact_keys(
            value,
            {
                "schema_version",
                "request_id",
                "run_id",
                "contract_digest",
                "contract_generation",
                "reason",
                "summary",
                "proposed_goal",
                "proposed_manifest_sha256",
                "proposed_release_target",
                "proposed_previous_release",
                "requested_at",
                "gate_revision",
            },
        )
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise ValueError("unsupported scope-change request schema")
        request = cls(
            request_id=_require_sha256(value["request_id"], label="request_id"),
            run_id=_require_non_empty(value["run_id"], label="run_id"),
            contract_digest=_require_sha256(
                value["contract_digest"], label="contract_digest"
            ),
            contract_generation=_require_positive_int(
                value["contract_generation"], label="contract_generation"
            ),
            reason=_require_non_empty(value["reason"], label="reason"),
            summary=_require_non_empty(value["summary"], label="summary"),
            proposed_goal=_require_non_empty(
                value["proposed_goal"], label="proposed_goal"
            ),
            proposed_manifest_sha256=_require_sha256(
                value["proposed_manifest_sha256"],
                label="proposed_manifest_sha256",
            ),
            proposed_release_target=_require_optional_non_empty(
                value["proposed_release_target"],
                label="proposed_release_target",
            ),
            proposed_previous_release=_require_optional_non_empty(
                value["proposed_previous_release"],
                label="proposed_previous_release",
            ),
            requested_at=_require_non_empty(
                value["requested_at"], label="requested_at"
            ),
            gate_revision=_require_non_negative_int(
                value["gate_revision"], label="gate_revision"
            ),
            schema_version=1,
        )
        if request.request_id != _digest(request._identity_payload()):
            raise ValueError("scope-change request digest is invalid")
        return request

    def digest(self) -> str:
        return _digest(self.to_dict())


@dataclass(frozen=True)
class ScopeChangeResolution:
    resolution_id: str
    request_id: str
    run_id: str
    decision: str
    actor: str
    previous_contract_digest: str
    resulting_contract_digest: str
    resolved_at: str
    gate_revision: int
    schema_version: int = _SCHEMA_VERSION

    def _identity_payload(self) -> dict[str, object]:
        payload = self.to_dict()
        payload.pop("resolution_id")
        return payload

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "resolution_id": self.resolution_id,
            "request_id": self.request_id,
            "run_id": self.run_id,
            "decision": self.decision,
            "actor": self.actor,
            "previous_contract_digest": self.previous_contract_digest,
            "resulting_contract_digest": self.resulting_contract_digest,
            "resolved_at": self.resolved_at,
            "gate_revision": self.gate_revision,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ScopeChangeResolution:
        _require_exact_keys(
            value,
            {
                "schema_version",
                "resolution_id",
                "request_id",
                "run_id",
                "decision",
                "actor",
                "previous_contract_digest",
                "resulting_contract_digest",
                "resolved_at",
                "gate_revision",
            },
        )
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise ValueError("unsupported scope-change resolution schema")
        decision = value["decision"]
        if decision not in {"approve", "reject"}:
            raise ValueError("scope-change decision is invalid")
        resolution = cls(
            resolution_id=_require_sha256(
                value["resolution_id"], label="resolution_id"
            ),
            request_id=_require_sha256(value["request_id"], label="request_id"),
            run_id=_require_non_empty(value["run_id"], label="run_id"),
            decision=str(decision),
            actor=_require_non_empty(value["actor"], label="actor"),
            previous_contract_digest=_require_sha256(
                value["previous_contract_digest"],
                label="previous_contract_digest",
            ),
            resulting_contract_digest=_require_sha256(
                value["resulting_contract_digest"],
                label="resulting_contract_digest",
            ),
            resolved_at=_require_non_empty(value["resolved_at"], label="resolved_at"),
            gate_revision=_require_non_negative_int(
                value["gate_revision"], label="gate_revision"
            ),
            schema_version=1,
        )
        if resolution.resolution_id != _digest(resolution._identity_payload()):
            raise ValueError("scope-change resolution digest is invalid")
        return resolution

    def digest(self) -> str:
        return _digest(self.to_dict())


class AuthorizationStore:
    def __init__(self, store: StateStore) -> None:
        if type(store) is not StateStore:
            raise TypeError("store must be a StateStore")
        self.store = store
        self.authorization_directory = store.run_directory / "authorization"
        self.contracts_directory = self.authorization_directory / "contracts"
        self.requests_directory = self.authorization_directory / "requests"
        self.resolutions_directory = self.authorization_directory / "resolutions"
        self.current_path = self.authorization_directory / "current.json"
        self.pending_path = self.authorization_directory / "pending-scope-change.json"
        self.lock_path = store.run_directory / "authorization.lock"

    @contextmanager
    def _locked(self) -> Iterator[None]:
        lock = FileLock.authorization(self.store.run_directory)
        with lock as acquired_lock, self.store.anchored(acquired_lock.trusted_parent):
            yield

    def _read_json(
        self,
        path: Path,
        *,
        label: str,
        missing_ok: bool = False,
    ) -> dict[str, object] | None:
        try:
            raw = _read_bounded_private_file(
                path,
                trusted_root=self.store.trusted_root,
                label=label,
                max_bytes=_MAX_AUTHORIZATION_BYTES,
            )
        except StateNotFoundError:
            if missing_ok:
                return None
            raise StateCorruptionError(f"{label} is missing") from None
        except (OSError, StateCorruptionError) as error:
            raise StateCorruptionError(f"{label} cannot be opened safely") from error
        try:
            payload = json.loads(raw.decode("utf-8"))
            canonical = _canonical_json_bytes(payload) + b"\n"
        except (UnicodeDecodeError, TypeError, ValueError) as error:
            raise StateCorruptionError(f"{label} is corrupt") from error
        if not isinstance(payload, dict) or raw != canonical:
            raise StateCorruptionError(f"{label} is not canonical JSON")
        return payload

    def _load_contract(
        self,
        *,
        generation: int,
        digest: str,
    ) -> AuthorizationContract:
        path = self.contracts_directory / f"{generation:04d}-{digest}.json"
        payload = self._read_json(path, label="authorization contract")
        assert payload is not None
        try:
            contract = AuthorizationContract.from_dict(payload)
        except (TypeError, ValueError) as error:
            raise StateCorruptionError("authorization contract is invalid") from error
        if contract.generation != generation or contract.digest() != digest:
            raise StateCorruptionError("authorization contract pointer is invalid")
        return contract

    def _contracts_for_generation_locked(
        self,
        generation: int,
    ) -> tuple[AuthorizationContract, ...]:
        try:
            names = _private_directory_names(
                self.contracts_directory,
                trusted_root=self.store.trusted_root,
            )
        except StateNotFoundError:
            return ()
        contracts: list[AuthorizationContract] = []
        for name in names:
            match = re.fullmatch(r"([0-9]{4,})-([0-9a-f]{64})\.json", name)
            if match is None or match.group(1) != f"{int(match.group(1)):04d}":
                raise StateCorruptionError(
                    "authorization contracts directory has unknown files"
                )
            file_generation = int(match.group(1))
            if file_generation != generation:
                continue
            contracts.append(
                self._load_contract(
                    generation=file_generation,
                    digest=match.group(2),
                )
            )
        if len(contracts) > 1:
            raise StateCorruptionError(
                "authorization generation has conflicting immutable records"
            )
        return tuple(contracts)

    def _current_locked(self) -> AuthorizationContract | None:
        pointer = self._read_json(
            self.current_path,
            label="current authorization pointer",
            missing_ok=True,
        )
        if pointer is None:
            return None
        if set(pointer) != {"schema_version", "generation", "digest"}:
            raise StateCorruptionError("current authorization pointer is invalid")
        try:
            if (
                type(pointer["schema_version"]) is not int
                or pointer["schema_version"] != 1
            ):
                raise ValueError
            generation = _require_positive_int(
                pointer["generation"], label="generation"
            )
            digest = _require_sha256(pointer["digest"], label="digest")
        except (TypeError, ValueError) as error:
            raise StateCorruptionError(
                "current authorization pointer is invalid"
            ) from error
        contract = self._load_contract(generation=generation, digest=digest)
        if contract.run_id != self.store.load().run_id:
            raise StateCorruptionError("authorization contract belongs to another run")
        return contract

    def _write_contract(self, contract: AuthorizationContract) -> None:
        digest = contract.digest()
        path = self.contracts_directory / f"{contract.generation:04d}-{digest}.json"
        try:
            _atomic_write_private_json(
                path,
                contract.to_dict(),
                trusted_root=self.store.trusted_root,
                immutable=True,
            )
        except FileExistsError:
            existing = self._load_contract(
                generation=contract.generation,
                digest=digest,
            )
            if existing != contract:
                raise StateCorruptionError(
                    "immutable authorization contract conflicts"
                ) from None

    def _write_current(self, contract: AuthorizationContract) -> None:
        _atomic_write_private_json(
            self.current_path,
            {
                "schema_version": 1,
                "generation": contract.generation,
                "digest": contract.digest(),
            },
            trusted_root=self.store.trusted_root,
        )

    def create_initial(
        self,
        *,
        mode: ExecutionMode,
        goal: str,
        repository: Path,
        worktree: Path,
        branch: str,
        manifest_sha256: str,
        release_target: str | None,
        previous_release: str | None,
        state_revision: int,
    ) -> AuthorizationContract:
        try:
            execution_mode = ExecutionMode(mode)
        except (TypeError, ValueError) as error:
            raise ValueError("unknown execution mode") from error
        normalized = {
            "mode": execution_mode,
            "goal": _require_non_empty(goal, label="goal"),
            "repository": str(Path(repository).resolve()),
            "worktree": str(Path(worktree).resolve()),
            "branch": _require_non_empty(branch, label="branch"),
            "manifest_sha256": _require_sha256(
                manifest_sha256, label="manifest_sha256"
            ),
            "release_target": _require_optional_non_empty(
                release_target, label="release_target"
            ),
            "previous_release": _require_optional_non_empty(
                previous_release, label="previous_release"
            ),
            "state_revision": _require_non_negative_int(
                state_revision, label="state_revision"
            ),
        }
        with self._locked():
            existing = self._current_locked()
            prepared = self._contracts_for_generation_locked(1)
            if existing is not None and prepared != (existing,):
                raise StateCorruptionError(
                    "initial authorization generation conflicts with current pointer"
                )
            expected = {
                "generation": 1,
                "mode": normalized["mode"],
                "goal": normalized["goal"],
                "repository": normalized["repository"],
                "worktree": normalized["worktree"],
                "branch": normalized["branch"],
                "manifest_sha256": normalized["manifest_sha256"],
                "release_target": normalized["release_target"],
                "previous_release": normalized["previous_release"],
                "state_revision": normalized["state_revision"],
            }
            if existing is not None:
                if all(
                    getattr(existing, key) == value for key, value in expected.items()
                ):
                    return existing
                raise ValueError("initial authorization contract already exists")
            state = self.store.load()
            if state.revision != state_revision:
                raise StaleRevisionError(
                    f"expected revision {state_revision}, found {state.revision}"
                )
            if prepared:
                contract = prepared[0]
                if contract.run_id != state.run_id or not all(
                    getattr(contract, key) == value for key, value in expected.items()
                ):
                    raise StateCorruptionError(
                        "prepared initial authorization contract conflicts"
                    )
                self._write_current(contract)
                return contract
            contract = AuthorizationContract(
                run_id=state.run_id,
                generation=1,
                mode=execution_mode,
                goal=str(normalized["goal"]),
                repository=str(normalized["repository"]),
                worktree=str(normalized["worktree"]),
                branch=str(normalized["branch"]),
                manifest_sha256=str(normalized["manifest_sha256"]),
                release_target=normalized["release_target"],  # type: ignore[arg-type]
                previous_release=normalized["previous_release"],  # type: ignore[arg-type]
                state_revision=state_revision,
                created_at=_utc_now(),
            )
            self._write_contract(contract)
            self._write_current(contract)
            return contract

    def current(self) -> AuthorizationContract | None:
        with self._locked():
            return self._current_locked()

    def mode(self) -> ExecutionMode:
        contract = self.current()
        return contract.mode if contract is not None else ExecutionMode.STRICT

    def _pending_locked(self) -> ScopeChangeRequest | None:
        payload = self._read_json(
            self.pending_path,
            label="pending scope-change request",
            missing_ok=True,
        )
        if payload is None:
            return None
        try:
            request = ScopeChangeRequest.from_dict(payload)
        except (TypeError, ValueError) as error:
            raise StateCorruptionError(
                "pending scope-change request is invalid"
            ) from error
        if request.run_id != self.store.load().run_id:
            raise StateCorruptionError(
                "pending scope-change request belongs to another run"
            )
        if self._load_request_archive_locked(request.request_id) != request:
            raise StateCorruptionError(
                "pending scope-change request differs from immutable archive"
            )
        return request

    def _remove_pending_if_matches_locked(
        self,
        request: ScopeChangeRequest,
    ) -> None:
        pending = self._pending_locked()
        if pending is None or (
            pending.request_id != request.request_id
            or pending.digest() != request.digest()
        ):
            return
        if pending != request:
            raise StateCorruptionError(
                "pending scope-change request identity conflicts"
            )
        _remove_private_file(
            self.pending_path,
            trusted_root=self.store.trusted_root,
        )

    def _reconcile_orphan_pending_locked(
        self,
        pending: ScopeChangeRequest | None,
        *,
        state: RunState,
    ) -> ScopeChangeRequest | None:
        if pending is None:
            return None
        owns_current_approval = (
            state.phase is Phase.AWAITING_SCOPE_APPROVAL
            and state.revision == pending.gate_revision + 1
        )
        if state.revision <= pending.gate_revision or owns_current_approval:
            return pending
        contract = self._load_contract(
            generation=pending.contract_generation,
            digest=pending.contract_digest,
        )
        if contract.run_id != state.run_id:
            raise StateCorruptionError(
                "orphan scope-change request contract belongs to another run"
            )
        self._remove_pending_if_matches_locked(pending)
        return self._pending_locked()

    def _load_request_archive_locked(
        self,
        request_id: str,
    ) -> ScopeChangeRequest:
        request_id = _require_sha256(request_id, label="request_id")
        payload = self._read_json(
            self.requests_directory / f"{request_id}.json",
            label="scope-change request archive",
        )
        assert payload is not None
        try:
            request = ScopeChangeRequest.from_dict(payload)
        except (TypeError, ValueError) as error:
            raise StateCorruptionError(
                "scope-change request archive is invalid"
            ) from error
        if request.request_id != request_id:
            raise StateCorruptionError(
                "scope-change request archive filename is invalid"
            )
        return request

    def _write_request_archive(self, request: ScopeChangeRequest) -> None:
        path = self.requests_directory / f"{request.request_id}.json"
        try:
            _atomic_write_private_json(
                path,
                request.to_dict(),
                trusted_root=self.store.trusted_root,
                immutable=True,
            )
        except FileExistsError:
            existing = self._load_request_archive_locked(request.request_id)
            if existing != request:
                raise StateCorruptionError(
                    "immutable scope-change request archive conflicts"
                ) from None

    def _request_archives_locked(
        self,
        *,
        run_id: str,
    ) -> tuple[ScopeChangeRequest, ...]:
        try:
            names = _private_directory_names(
                self.requests_directory,
                trusted_root=self.store.trusted_root,
            )
        except StateNotFoundError:
            return ()
        requests: list[ScopeChangeRequest] = []
        for name in names:
            match = re.fullmatch(r"([0-9a-f]{64})\.json", name)
            if match is None:
                raise StateCorruptionError(
                    "scope-change requests directory has unknown files"
                )
            request = self._load_request_archive_locked(match.group(1))
            if request.run_id != run_id:
                raise StateCorruptionError(
                    "scope-change request archive belongs to another run"
                )
            requests.append(request)
        return tuple(requests)

    def pending(self) -> ScopeChangeRequest | None:
        with self._locked():
            return self._pending_locked()

    def _resolutions_locked(self) -> tuple[ScopeChangeResolution, ...]:
        try:
            names = _private_directory_names(
                self.resolutions_directory,
                trusted_root=self.store.trusted_root,
            )
        except StateNotFoundError:
            return ()
        run_id = self.store.load().run_id
        resolutions: list[ScopeChangeResolution] = []
        for name in names:
            match = re.fullmatch(r"([0-9a-f]{64})-([0-9a-f]{64})\.json", name)
            if match is None:
                raise StateCorruptionError(
                    "scope-change resolutions directory has unknown files"
                )
            payload = self._read_json(
                self.resolutions_directory / name,
                label="scope-change resolution",
            )
            assert payload is not None
            try:
                resolution = ScopeChangeResolution.from_dict(payload)
            except (TypeError, ValueError) as error:
                raise StateCorruptionError(
                    "scope-change resolution is invalid"
                ) from error
            if resolution.request_id != match.group(
                1
            ) or resolution.resolution_id != match.group(2):
                raise StateCorruptionError(
                    "scope-change resolution filename is invalid"
                )
            self._validate_resolution_audit_locked(
                resolution,
                run_id=run_id,
            )
            resolutions.append(resolution)
        return tuple(resolutions)

    def _validate_resolution_audit_locked(
        self,
        resolution: ScopeChangeResolution,
        *,
        run_id: str,
    ) -> None:
        if resolution.run_id != run_id:
            raise StateCorruptionError("scope-change resolution belongs to another run")
        request = self._load_request_archive_locked(resolution.request_id)
        if request.run_id != run_id:
            raise StateCorruptionError(
                "scope-change resolution request belongs to another run"
            )
        previous = self._load_contract(
            generation=request.contract_generation,
            digest=request.contract_digest,
        )
        if (
            previous.run_id != run_id
            or resolution.previous_contract_digest != previous.digest()
            or resolution.gate_revision != request.gate_revision + 1
        ):
            raise StateCorruptionError(
                "scope-change resolution has invalid request or contract binding"
            )
        if resolution.decision == "reject":
            if resolution.resulting_contract_digest != previous.digest():
                raise StateCorruptionError(
                    "rejected scope change has invalid resulting contract"
                )
            return
        resulting = self._load_contract(
            generation=previous.generation + 1,
            digest=resolution.resulting_contract_digest,
        )
        if not self._contract_matches_request(
            resulting,
            previous,
            request,
            resolution.gate_revision,
        ):
            raise StateCorruptionError(
                "approved scope change has invalid resulting contract"
            )

    def latest_resolution(self) -> ScopeChangeResolution | None:
        with self._locked():
            resolutions = self._resolutions_locked()
            if not resolutions:
                return None
            return max(
                resolutions,
                key=lambda item: (
                    item.resolved_at,
                    item.gate_revision,
                    item.resolution_id,
                ),
            )

    @staticmethod
    def _request_matches(
        request: ScopeChangeRequest,
        *,
        contract: AuthorizationContract,
        reason: str,
        summary: str,
        proposed_goal: str,
        proposed_manifest_sha256: str,
        proposed_release_target: str | None,
        proposed_previous_release: str | None,
        expected_revision: int,
    ) -> bool:
        return (
            request.contract_digest == contract.digest()
            and request.contract_generation == contract.generation
            and request.reason == reason
            and request.summary == summary
            and request.proposed_goal == proposed_goal
            and request.proposed_manifest_sha256 == proposed_manifest_sha256
            and request.proposed_release_target == proposed_release_target
            and request.proposed_previous_release == proposed_previous_release
            and request.gate_revision == expected_revision
        )

    def _prepared_request_locked(
        self,
        *,
        run_id: str,
        contract: AuthorizationContract,
        reason: str,
        summary: str,
        proposed_goal: str,
        proposed_manifest_sha256: str,
        proposed_release_target: str | None,
        proposed_previous_release: str | None,
        expected_revision: int,
    ) -> ScopeChangeRequest | None:
        same_context = [
            request
            for request in self._request_archives_locked(run_id=run_id)
            if request.contract_digest == contract.digest()
            and request.contract_generation == contract.generation
            and request.gate_revision == expected_revision
        ]
        if not same_context:
            return None
        if len(same_context) != 1 or not self._request_matches(
            same_context[0],
            contract=contract,
            reason=reason,
            summary=summary,
            proposed_goal=proposed_goal,
            proposed_manifest_sha256=proposed_manifest_sha256,
            proposed_release_target=proposed_release_target,
            proposed_previous_release=proposed_previous_release,
            expected_revision=expected_revision,
        ):
            raise StateCorruptionError(
                "prepared scope-change request publication conflicts"
            )
        return same_context[0]

    def request_change(
        self,
        *,
        reason: str,
        summary: str,
        proposed_goal: str,
        proposed_manifest_sha256: str,
        proposed_release_target: str | None,
        proposed_previous_release: str | None,
        expected_revision: int,
    ) -> ScopeChangeRequest:
        reason = _require_non_empty(reason, label="reason")
        summary = _require_non_empty(summary, label="summary")
        proposed_goal = _require_non_empty(proposed_goal, label="proposed_goal")
        proposed_manifest_sha256 = _require_sha256(
            proposed_manifest_sha256,
            label="proposed_manifest_sha256",
        )
        proposed_release_target = _require_optional_non_empty(
            proposed_release_target,
            label="proposed_release_target",
        )
        proposed_previous_release = _require_optional_non_empty(
            proposed_previous_release,
            label="proposed_previous_release",
        )
        expected_revision = _require_non_negative_int(
            expected_revision, label="expected_revision"
        )
        with self._locked():
            contract = self._current_locked()
            if contract is None:
                raise ValueError("scope changes require an authorization contract")
            state = self.store.load()
            if (
                state.phase is not Phase.AWAITING_SCOPE_APPROVAL
                and Phase.AWAITING_SCOPE_APPROVAL not in LEGAL_TRANSITIONS[state.phase]
            ):
                raise InvalidTransitionError(
                    f"cannot transition from {state.phase.value} "
                    f"to {Phase.AWAITING_SCOPE_APPROVAL.value}"
                )
            pending = self._reconcile_orphan_pending_locked(
                self._pending_locked(),
                state=state,
            )
            if pending is not None:
                if not self._request_matches(
                    pending,
                    contract=contract,
                    reason=reason,
                    summary=summary,
                    proposed_goal=proposed_goal,
                    proposed_manifest_sha256=proposed_manifest_sha256,
                    proposed_release_target=proposed_release_target,
                    proposed_previous_release=proposed_previous_release,
                    expected_revision=expected_revision,
                ):
                    raise ValueError("a scope-change request is already pending")
                if (
                    state.phase is Phase.AWAITING_SCOPE_APPROVAL
                    and state.revision == expected_revision + 1
                ):
                    return pending
                if state.revision != expected_revision:
                    raise StaleRevisionError(
                        f"expected revision {expected_revision}, found {state.revision}"
                    )
                self.store.reconcile_transition(
                    Phase.AWAITING_SCOPE_APPROVAL,
                    expected_revision=expected_revision,
                    reason="scope-request-publication-recovered",
                )
                return pending
            if state.phase is Phase.AWAITING_SCOPE_APPROVAL:
                raise InvalidTransitionError(
                    "scope approval state is missing its pending request"
                )
            if state.revision != expected_revision:
                raise StaleRevisionError(
                    f"expected revision {expected_revision}, found {state.revision}"
                )
            request = self._prepared_request_locked(
                run_id=state.run_id,
                contract=contract,
                reason=reason,
                summary=summary,
                proposed_goal=proposed_goal,
                proposed_manifest_sha256=proposed_manifest_sha256,
                proposed_release_target=proposed_release_target,
                proposed_previous_release=proposed_previous_release,
                expected_revision=expected_revision,
            )
            if request is None:
                requested_at = _utc_now()
                identity: dict[str, object] = {
                    "schema_version": 1,
                    "run_id": state.run_id,
                    "contract_digest": contract.digest(),
                    "contract_generation": contract.generation,
                    "reason": reason,
                    "summary": summary,
                    "proposed_goal": proposed_goal,
                    "proposed_manifest_sha256": proposed_manifest_sha256,
                    "proposed_release_target": proposed_release_target,
                    "proposed_previous_release": proposed_previous_release,
                    "requested_at": requested_at,
                    "gate_revision": expected_revision,
                }
                request = ScopeChangeRequest(
                    request_id=_digest(identity),
                    run_id=state.run_id,
                    contract_digest=contract.digest(),
                    contract_generation=contract.generation,
                    reason=reason,
                    summary=summary,
                    proposed_goal=proposed_goal,
                    proposed_manifest_sha256=proposed_manifest_sha256,
                    proposed_release_target=proposed_release_target,
                    proposed_previous_release=proposed_previous_release,
                    requested_at=requested_at,
                    gate_revision=expected_revision,
                )
                self._write_request_archive(request)
            _atomic_write_private_json(
                self.pending_path,
                request.to_dict(),
                trusted_root=self.store.trusted_root,
            )
            try:
                self.store.transition(
                    Phase.AWAITING_SCOPE_APPROVAL,
                    expected_revision=expected_revision,
                )
            except StaleRevisionError:
                self._remove_pending_if_matches_locked(request)
                raise
            return request

    @staticmethod
    def _contract_matches_request(
        contract: AuthorizationContract,
        previous: AuthorizationContract,
        request: ScopeChangeRequest,
        expected_revision: int,
    ) -> bool:
        return (
            contract.run_id == previous.run_id
            and contract.generation == request.contract_generation + 1
            and contract.mode is previous.mode
            and contract.repository == previous.repository
            and contract.worktree == previous.worktree
            and contract.branch == previous.branch
            and contract.goal == request.proposed_goal
            and contract.manifest_sha256 == request.proposed_manifest_sha256
            and contract.release_target == request.proposed_release_target
            and contract.previous_release == request.proposed_previous_release
            and contract.state_revision == expected_revision
        )

    def _resolution_for_request_locked(
        self,
        request_id: str,
    ) -> ScopeChangeResolution | None:
        matching = [
            resolution
            for resolution in self._resolutions_locked()
            if resolution.request_id == request_id
        ]
        if len(matching) > 1:
            raise StateCorruptionError(
                "scope-change request has multiple resolution records"
            )
        return matching[0] if matching else None

    def _write_resolution(self, resolution: ScopeChangeResolution) -> None:
        path = (
            self.resolutions_directory
            / f"{resolution.request_id}-{resolution.resolution_id}.json"
        )
        try:
            _atomic_write_private_json(
                path,
                resolution.to_dict(),
                trusted_root=self.store.trusted_root,
                immutable=True,
            )
        except FileExistsError:
            payload = self._read_json(path, label="scope-change resolution")
            assert payload is not None
            try:
                existing = ScopeChangeResolution.from_dict(payload)
            except (TypeError, ValueError) as error:
                raise StateCorruptionError(
                    "scope-change resolution is invalid"
                ) from error
            if existing != resolution:
                raise StateCorruptionError(
                    "immutable scope-change resolution conflicts"
                ) from None

    def resolve_change(
        self,
        *,
        decision: str,
        actor: str,
        expected_revision: int,
    ) -> AuthorizationContract:
        if decision not in {"approve", "reject"}:
            raise ValueError("scope-change decision must be approve or reject")
        actor = _require_non_empty(actor, label="actor")
        expected_revision = _require_non_negative_int(
            expected_revision, label="expected_revision"
        )
        with self._locked():
            request = self._pending_locked()
            if request is None:
                raise ValueError("no scope-change request is pending")
            previous = self._load_contract(
                generation=request.contract_generation,
                digest=request.contract_digest,
            )
            state = self.store.load()
            current = self._current_locked()
            if current is None:
                raise StateCorruptionError("authorization contract is missing")
            existing_resolution = self._resolution_for_request_locked(
                request.request_id
            )
            if existing_resolution is not None:
                if (
                    existing_resolution.decision != decision
                    or existing_resolution.actor != actor
                    or existing_resolution.previous_contract_digest != previous.digest()
                    or existing_resolution.resulting_contract_digest != current.digest()
                    or existing_resolution.gate_revision != expected_revision
                ):
                    raise StateCorruptionError(
                        "scope-change resolution conflicts with retry"
                    )
                if (
                    state.phase is Phase.AWAITING_SCOPE_APPROVAL
                    and state.revision == expected_revision
                ):
                    self.store.reconcile_transition(
                        Phase.PLANNING,
                        expected_revision=expected_revision,
                        reason="scope-resolution-publication-recovered",
                    )
                elif not (
                    state.phase is Phase.PLANNING
                    and state.revision == expected_revision + 1
                ):
                    if state.revision != expected_revision:
                        raise StaleRevisionError(
                            f"expected revision {expected_revision}, "
                            f"found {state.revision}"
                        )
                    raise ValueError("run is not awaiting scope approval")
                _remove_private_file(
                    self.pending_path,
                    trusted_root=self.store.trusted_root,
                )
                return current
            if state.revision != expected_revision:
                raise StaleRevisionError(
                    f"expected revision {expected_revision}, found {state.revision}"
                )
            if state.phase is not Phase.AWAITING_SCOPE_APPROVAL:
                raise ValueError("run is not awaiting scope approval")
            if decision == "approve":
                if current.digest() == previous.digest():
                    prepared = self._contracts_for_generation_locked(
                        previous.generation + 1
                    )
                    if prepared:
                        resulting = prepared[0]
                        if not self._contract_matches_request(
                            resulting,
                            previous,
                            request,
                            expected_revision,
                        ):
                            raise StateCorruptionError(
                                "prepared authorization expansion conflicts"
                            )
                    else:
                        resulting = AuthorizationContract(
                            run_id=previous.run_id,
                            generation=previous.generation + 1,
                            mode=previous.mode,
                            goal=request.proposed_goal,
                            repository=previous.repository,
                            worktree=previous.worktree,
                            branch=previous.branch,
                            manifest_sha256=request.proposed_manifest_sha256,
                            release_target=request.proposed_release_target,
                            previous_release=request.proposed_previous_release,
                            state_revision=expected_revision,
                            created_at=_utc_now(),
                        )
                        self._write_contract(resulting)
                    self._write_current(resulting)
                elif self._contract_matches_request(
                    current,
                    previous,
                    request,
                    expected_revision,
                ):
                    if self._contracts_for_generation_locked(current.generation) != (
                        current,
                    ):
                        raise StateCorruptionError(
                            "current authorization expansion conflicts"
                        )
                    resulting = current
                else:
                    raise StateCorruptionError(
                        "current authorization contract changed during approval"
                    )
            else:
                if current.digest() != previous.digest():
                    raise StateCorruptionError(
                        "current authorization contract changed during rejection"
                    )
                resulting = previous
            resolved_at = _utc_now()
            identity: dict[str, object] = {
                "schema_version": 1,
                "request_id": request.request_id,
                "run_id": request.run_id,
                "decision": decision,
                "actor": actor,
                "previous_contract_digest": previous.digest(),
                "resulting_contract_digest": resulting.digest(),
                "resolved_at": resolved_at,
                "gate_revision": expected_revision,
            }
            resolution = ScopeChangeResolution(
                resolution_id=_digest(identity),
                request_id=request.request_id,
                run_id=request.run_id,
                decision=decision,
                actor=actor,
                previous_contract_digest=previous.digest(),
                resulting_contract_digest=resulting.digest(),
                resolved_at=resolved_at,
                gate_revision=expected_revision,
            )
            self._write_resolution(resolution)
            self.store.transition(
                Phase.PLANNING,
                expected_revision=expected_revision,
            )
            _remove_private_file(
                self.pending_path,
                trusted_root=self.store.trusted_root,
            )
            return resulting
