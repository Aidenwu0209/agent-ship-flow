from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Mapping, Sequence

from .model import Phase
from .store import (
    FileLock,
    PrivateRootAnchor,
    StateCorruptionError,
    StateNotFoundError,
    StateStore,
    _atomic_write_private_json,
    _private_directory_names,
    _read_bounded_private_file,
    _remove_private_file,
)
from .subject import EvidenceSubject


class ReviewError(RuntimeError):
    pass


class ReviewRecoveryError(ReviewError):
    pass


class ReviewEvidenceMissingError(ReviewRecoveryError):
    pass


class ReviewEvidenceStaleError(ReviewRecoveryError):
    pass


class ReviewRole(str, Enum):
    PLAN_CRITIC = "plan_critic"
    REVIEWER = "reviewer"
    VERIFIER = "verifier"


@dataclass(frozen=True)
class ReviewReport:
    review_type: str
    run_id: str
    reviewer_actor: str
    subject: EvidenceSubject
    verdict: str
    findings: tuple[dict[str, str], ...]
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


def _decode_canonical_json_object(raw: bytes, *, label: str) -> dict[str, object]:
    try:
        payload = json.loads(raw.decode("utf-8"))
        canonical = _canonical_json_bytes(payload) + b"\n"
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise ReviewRecoveryError(f"{label} is corrupt") from error
    if not isinstance(payload, dict) or raw != canonical:
        raise ReviewRecoveryError(f"{label} is not canonical JSON")
    return payload


def _bytes_digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_canonical_json(
    path: Path,
    payload: dict[str, object],
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> None:
    _atomic_write_private_json(path, payload, trusted_root=trusted_root)


def _remove_durable_file(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> None:
    _remove_private_file(path, trusted_root=trusted_root)


def _assert_store_root_current(store: StateStore) -> None:
    trusted_root = store.trusted_root
    if not isinstance(trusted_root, PrivateRootAnchor):
        return
    try:
        opened = os.fstat(trusted_root.descriptor)
        current = os.stat(store.run_directory, follow_symlinks=False)
    except OSError as error:
        raise ReviewRecoveryError(
            "review run directory changed during publication"
        ) from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise ReviewRecoveryError("review run directory changed during publication")


def issue_handoff(
    store: StateStore,
    *,
    subject: EvidenceSubject,
    source_actor: str,
    role: ReviewRole | str,
) -> str:
    try:
        handoff_role = ReviewRole(role)
    except (TypeError, ValueError) as error:
        raise ReviewError("unknown handoff role") from error
    if not isinstance(source_actor, str) or not source_actor.strip():
        raise ReviewError("source actor must be a non-empty string")
    state = store.load()
    if state.run_id != subject.run_id:
        raise ReviewError("evidence subject belongs to another run")
    expected_phase = {
        ReviewRole.PLAN_CRITIC: Phase.PLAN_REVIEW,
        ReviewRole.REVIEWER: Phase.CODE_REVIEW,
        ReviewRole.VERIFIER: Phase.VERIFYING,
    }[handoff_role]
    if state.phase is not expected_phase:
        raise ReviewError(
            f"{handoff_role.value} handoff requires {expected_phase.value}"
        )
    nonce = secrets.token_urlsafe(32)
    nonce_sha256 = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
    payload: dict[str, object] = {
        "schema_version": 1,
        "run_id": state.run_id,
        "role": handoff_role.value,
        "source_actor": source_actor,
        "subject": subject.to_dict(),
        "subject_digest": subject.digest(),
        "nonce_sha256": nonce_sha256,
        "issued_at": _utc_now(),
        "consumed_at": None,
        "consumed_by": None,
    }
    _write_canonical_json(
        store.run_directory / "handoffs" / f"{nonce_sha256}.json",
        payload,
        trusted_root=store.trusted_root,
    )
    return nonce


_HANDOFF_KEYS = {
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
_FINDING_KEYS = {"category", "severity", "message", "location"}
_FINDING_CATEGORIES = frozenset(
    {
        "requirement",
        "correctness",
        "security",
        "maintainability",
        "migration-safety",
        "testing",
    }
)
_FINDING_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
_EXACT_LOCATION = re.compile(r"^[^:\r\n]+:[1-9][0-9]*(?::[1-9][0-9]*)?$")


def _normalize_findings(
    findings: Sequence[Mapping[str, str]],
) -> tuple[dict[str, str], ...]:
    try:
        raw_findings = tuple(findings)
    except TypeError as error:
        raise ReviewError("review findings must be a sequence") from error
    normalized: list[dict[str, str]] = []
    for finding in raw_findings:
        if not isinstance(finding, Mapping) or set(finding) != _FINDING_KEYS:
            raise ReviewError("review finding schema is invalid")
        if any(
            not isinstance(finding[key], str) or not finding[key].strip()
            for key in _FINDING_KEYS
        ):
            raise ReviewError("review finding values must be non-empty strings")
        if finding["category"] not in _FINDING_CATEGORIES:
            raise ReviewError("review finding category is invalid")
        if finding["severity"] not in _FINDING_SEVERITIES:
            raise ReviewError("review finding severity is invalid")
        if _EXACT_LOCATION.fullmatch(finding["location"]) is None:
            raise ReviewError("review finding location must be an exact path and line")
        normalized.append({key: finding[key] for key in sorted(_FINDING_KEYS)})
    return tuple(normalized)


def _load_handoff_digest(
    store: StateStore,
    nonce_sha256: str,
) -> tuple[Path, dict[str, object]]:
    if re.fullmatch(r"[0-9a-f]{64}", nonce_sha256) is None:
        raise ReviewError("handoff nonce digest is invalid")
    path = store.run_directory / "handoffs" / f"{nonce_sha256}.json"
    payload = _read_private_review_json(
        store.run_directory,
        ("handoffs", path.name),
        label="handoff receipt",
        trusted_root=store.trusted_root,
    )
    if not isinstance(payload, dict) or set(payload) != _HANDOFF_KEYS:
        raise ReviewError("handoff receipt schema is invalid")
    if payload["schema_version"] != 1 or payload["nonce_sha256"] != nonce_sha256:
        raise ReviewError("handoff receipt identity is invalid")
    return path, payload


def _load_handoff(store: StateStore, nonce: str) -> tuple[Path, dict[str, object]]:
    if not isinstance(nonce, str) or not nonce:
        raise ReviewError("handoff nonce must be a non-empty string")
    return _load_handoff_digest(
        store,
        hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
    )


_REVIEW_SOURCE_PHASE = {
    "plan": Phase.PLAN_REVIEW,
    "code": Phase.CODE_REVIEW,
}
_REVIEW_ROLE = {
    "plan": ReviewRole.PLAN_CRITIC,
    "code": ReviewRole.REVIEWER,
}
_REVIEW_TARGET_PHASE = {
    ("plan", "pass"): Phase.AWAITING_PLAN_APPROVAL,
    ("plan", "changes_requested"): Phase.PLANNING,
    ("code", "pass"): Phase.VERIFYING,
    ("code", "changes_requested"): Phase.DEVELOPING,
}
_REVIEW_OPERATION_KEYS = {
    "schema_version",
    "stage",
    "run_id",
    "review_type",
    "request",
    "request_digest",
    "report",
    "report_digest",
    "previous_report_digest",
    "new_report_digest",
    "subject",
    "subject_digest",
    "handoff_nonce_sha256",
    "reviewer_actor",
    "source_actor",
    "role",
    "expected_source_phase",
    "expected_revision",
    "target_phase",
    "artifact_path",
    "handoff_path",
    "publication_sha256",
}
_REVIEW_OPERATION_STAGES = {
    "prepared": 0,
    "report-written": 1,
    "handoff-consumed": 2,
    "state-transitioned": 3,
}


def _review_operation_path(store: StateStore) -> Path:
    return store.run_directory / "review-operation.json"


def _review_publication_payload(
    operation: Mapping[str, object],
) -> dict[str, object]:
    return {
        key: value
        for key, value in operation.items()
        if key not in {"stage", "publication_sha256"}
    }


def _prepare_review_operation(
    operation: dict[str, object],
) -> dict[str, object]:
    prepared = dict(operation)
    prepared["publication_sha256"] = _canonical_json_digest(
        _review_publication_payload(prepared)
    )
    return prepared


def _review_publication_path(
    store: StateStore,
    operation: Mapping[str, object],
) -> Path:
    review_type = operation.get("review_type")
    expected_revision = operation.get("expected_revision")
    digest = operation.get("publication_sha256")
    if (
        review_type not in {"plan", "code"}
        or type(expected_revision) is not int
        or expected_revision < 0
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise ReviewRecoveryError("review publication seal identity is invalid")
    return (
        store.run_directory
        / "review-publications"
        / f"{review_type}-{expected_revision:08d}-{digest}.json"
    )


def _validate_review_publication_seal(
    store: StateStore,
    operation: Mapping[str, object],
) -> None:
    path = _review_publication_path(store, operation)
    try:
        raw = _read_bounded_private_file(
            path,
            trusted_root=store.trusted_root,
            label="review publication seal",
            max_bytes=1_048_576,
        )
    except (StateNotFoundError, StateCorruptionError, OSError) as error:
        raise ReviewRecoveryError(
            "review publication seal is missing or unsafe"
        ) from error
    payload = _decode_canonical_json_object(raw, label="review publication seal")
    expected = _review_publication_payload(operation)
    digest = operation.get("publication_sha256")
    if payload != expected or _canonical_json_digest(payload) != digest:
        raise ReviewRecoveryError("review publication differs from immutable seal")


def _ensure_review_publication_seal(
    store: StateStore,
    operation: Mapping[str, object],
) -> None:
    path = _review_publication_path(store, operation)
    try:
        _atomic_write_private_json(
            path,
            _review_publication_payload(operation),
            trusted_root=store.trusted_root,
            immutable=True,
        )
    except FileExistsError:
        pass
    _validate_review_publication_seal(store, operation)


def validate_completed_review_publication(
    store: StateStore,
    report: Mapping[str, object],
    *,
    review_type: str,
) -> dict[str, object]:
    """Validate the immutable publication that produced a completed review."""

    if type(store) is not StateStore or not isinstance(report, Mapping):
        raise TypeError("completed review inputs must use exact evidence types")
    if review_type not in {"plan", "code"}:
        raise ValueError("completed review type is invalid")
    directory = store.run_directory / "review-publications"
    try:
        names = _private_directory_names(
            directory,
            trusted_root=store.trusted_root,
        )
    except (StateNotFoundError, StateCorruptionError) as error:
        raise ReviewEvidenceMissingError(
            "completed review publication seal is missing"
        ) from error
    pattern = re.compile(rf"{review_type}-([0-9]+)-([0-9a-f]{{64}})\.json")
    matches: list[dict[str, object]] = []
    for name in names:
        identity = pattern.fullmatch(name)
        if identity is None:
            continue
        try:
            raw = _read_bounded_private_file(
                directory / name,
                trusted_root=store.trusted_root,
                label="completed review publication seal",
                max_bytes=1_048_576,
            )
        except (
            OSError,
            StateNotFoundError,
            StateCorruptionError,
        ) as error:
            raise ReviewRecoveryError(
                "completed review publication seal is corrupt"
            ) from error
        payload = _decode_canonical_json_object(
            raw,
            label="completed review publication seal",
        )
        if _canonical_json_digest(payload) != identity.group(2):
            raise ReviewRecoveryError(
                "completed review publication seal identity is invalid"
            )
        if payload.get("review_type") == review_type and payload.get("report") == dict(
            report
        ):
            operation = {
                **payload,
                "stage": "state-transitioned",
                "publication_sha256": identity.group(2),
            }
            if set(operation) != _REVIEW_OPERATION_KEYS:
                raise ReviewRecoveryError(
                    "completed review publication schema is invalid"
                )
            _validate_review_publication_seal(store, operation)
            expected_revision = operation.get("expected_revision")
            expected_source = operation.get("expected_source_phase")
            expected_target = operation.get("target_phase")
            try:
                source_phase = Phase(str(expected_source))
                target_phase = Phase(str(expected_target))
            except ValueError as error:
                raise ReviewRecoveryError(
                    "completed review publication phase is invalid"
                ) from error
            if (
                type(expected_revision) is not int
                or int(identity.group(1)) != expected_revision
                or operation.get("new_report_digest")
                != _bytes_digest(_canonical_json_bytes(dict(report)) + b"\n")
                or not any(
                    event.event_type == "phase.transitioned"
                    and event.previous_phase is source_phase
                    and event.phase is target_phase
                    and event.revision == expected_revision + 1
                    for event in store.events()
                )
            ):
                raise ReviewRecoveryError(
                    "completed review publication is not bound to the state WAL"
                )
            matches.append(operation)
    if not matches:
        raise ReviewEvidenceMissingError("completed review publication seal is missing")
    if len(matches) != 1:
        raise ReviewRecoveryError("completed review publication seal is ambiguous")
    return matches[0]


def _load_review_operation(store: StateStore) -> dict[str, object] | None:
    path = _review_operation_path(store)
    try:
        raw = _read_bounded_private_file(
            path,
            trusted_root=store.trusted_root,
            label="review publication receipt",
            max_bytes=1_048_576,
        )
    except StateNotFoundError:
        return None
    except (OSError, StateCorruptionError) as error:
        raise ReviewRecoveryError(
            "review publication receipt cannot be opened safely"
        ) from error
    payload = _decode_canonical_json_object(
        raw,
        label="review publication receipt",
    )
    if set(payload) != _REVIEW_OPERATION_KEYS:
        raise ReviewRecoveryError("review publication receipt schema is invalid")
    if payload["schema_version"] != 1:
        raise ReviewRecoveryError("review publication receipt version is unsupported")
    if payload["stage"] not in _REVIEW_OPERATION_STAGES:
        raise ReviewRecoveryError("review publication receipt stage is invalid")
    if not isinstance(payload["request"], dict) or not isinstance(
        payload["report"], dict
    ):
        raise ReviewRecoveryError("review publication receipt payload is invalid")
    if payload["request_digest"] != _canonical_json_digest(payload["request"]):
        raise ReviewRecoveryError("review publication request digest is invalid")
    if payload["report_digest"] != _canonical_json_digest(payload["report"]):
        raise ReviewRecoveryError("review publication report digest is invalid")
    previous_report_digest = payload["previous_report_digest"]
    if previous_report_digest is not None and (
        not isinstance(previous_report_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", previous_report_digest) is None
    ):
        raise ReviewRecoveryError("previous review report digest is invalid")
    expected_report_bytes = _canonical_json_bytes(payload["report"]) + b"\n"
    if payload["new_report_digest"] != _bytes_digest(expected_report_bytes):
        raise ReviewRecoveryError("new review report digest is invalid")
    if payload["publication_sha256"] != _canonical_json_digest(
        _review_publication_payload(payload)
    ):
        raise ReviewRecoveryError("review publication seal digest is invalid")
    return payload


def _write_review_operation_stage(
    store: StateStore,
    operation: dict[str, object],
    *,
    stage: str,
) -> dict[str, object]:
    changed = dict(operation)
    changed["stage"] = stage
    _write_canonical_json(
        _review_operation_path(store),
        changed,
        trusted_root=store.trusted_root,
    )
    return changed


def _request_payload(
    *,
    review_type: str,
    current_subject: EvidenceSubject,
    reviewer_actor: str,
    handoff_nonce_sha256: str,
    handoff: dict[str, object],
    verdict: str,
    findings: tuple[dict[str, str], ...],
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "review_type": review_type,
        "run_id": current_subject.run_id,
        "reviewer_actor": reviewer_actor,
        "source_actor": handoff["source_actor"],
        "role": handoff["role"],
        "subject": current_subject.to_dict(),
        "subject_digest": current_subject.digest(),
        "handoff_nonce_sha256": handoff_nonce_sha256,
        "verdict": verdict,
        "findings": list(findings),
    }


def _report_payload(
    request: dict[str, object],
    *,
    recorded_at: str,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 1,
        "review_type": request["review_type"],
        "run_id": request["run_id"],
        "reviewer_actor": request["reviewer_actor"],
        "role": request["role"],
        "subject": request["subject"],
        "subject_digest": request["subject_digest"],
        "verdict": request["verdict"],
        "findings": request["findings"],
        "recorded_at": recorded_at,
        "handoff_nonce_sha256": request["handoff_nonce_sha256"],
    }
    if request["review_type"] == "plan":
        subject = request["subject"]
        if not isinstance(subject, dict):
            raise ReviewRecoveryError("review publication subject is invalid")
        payload["plan_sha256"] = subject["plan_sha256"]
    return payload


def _validate_operation_request(
    store: StateStore,
    operation: dict[str, object],
    *,
    request: dict[str, object],
    handoff_path: Path,
) -> None:
    review_type = str(request["review_type"])
    verdict = str(request["verdict"])
    report_path = store.run_directory / "reviews" / f"{review_type}-review.json"
    expected = {
        "run_id": request["run_id"],
        "review_type": review_type,
        "request": request,
        "request_digest": _canonical_json_digest(request),
        "subject": request["subject"],
        "subject_digest": request["subject_digest"],
        "handoff_nonce_sha256": request["handoff_nonce_sha256"],
        "reviewer_actor": request["reviewer_actor"],
        "source_actor": request["source_actor"],
        "role": request["role"],
        "expected_source_phase": _REVIEW_SOURCE_PHASE[review_type].value,
        "target_phase": _REVIEW_TARGET_PHASE[(review_type, verdict)].value,
        "artifact_path": str(report_path),
        "handoff_path": str(handoff_path),
    }
    if any(operation[key] != value for key, value in expected.items()):
        raise ReviewRecoveryError(
            "pending review publication belongs to a different request"
        )
    if (
        type(operation["expected_revision"]) is not int
        or operation["expected_revision"] < 0
    ):
        raise ReviewRecoveryError("review publication revision is invalid")


def _state_matches_operation(
    store: StateStore,
    operation: dict[str, object],
) -> tuple[bool, bool]:
    state = store.load()
    expected_revision = int(operation["expected_revision"])
    source = (
        state.phase.value == operation["expected_source_phase"]
        and state.revision == expected_revision
    )
    target = (
        state.phase.value == operation["target_phase"]
        and state.revision == expected_revision + 1
    )
    if not source and not target:
        raise ReviewRecoveryError(
            "run state is neither the recorded source nor target review phase"
        )
    return source, target


def _review_report_digest(
    path: Path,
    *,
    trusted_root: Path | PrivateRootAnchor,
) -> str | None:
    try:
        raw = _read_bounded_private_file(
            path,
            trusted_root=trusted_root,
            label="review report",
            max_bytes=1_048_576,
        )
    except StateNotFoundError:
        return None
    except (OSError, StateCorruptionError) as error:
        raise ReviewRecoveryError("review report cannot be read") from error
    return _bytes_digest(raw)


def _recover_review_publication(
    store: StateStore,
    *,
    operation: dict[str, object],
    current_subject: EvidenceSubject,
    handoff_nonce: str | None,
) -> ReviewReport:
    _assert_store_root_current(store)
    _validate_review_publication_seal(store, operation)
    source_state, _ = _state_matches_operation(store, operation)
    report = operation["report"]
    if not isinstance(report, dict):
        raise ReviewRecoveryError("review publication report is invalid")
    report_path = Path(str(operation["artifact_path"]))
    current_report_digest = _review_report_digest(
        report_path,
        trusted_root=store.trusted_root,
    )
    previous_report_digest = operation["previous_report_digest"]
    new_report_digest = operation["new_report_digest"]
    if current_report_digest == new_report_digest:
        pass
    elif current_report_digest is None and previous_report_digest is None:
        _write_canonical_json(
            report_path,
            report,
            trusted_root=store.trusted_root,
        )
    elif current_report_digest == previous_report_digest:
        _write_canonical_json(
            report_path,
            report,
            trusted_root=store.trusted_root,
        )
    else:
        raise ReviewRecoveryError("existing review report differs from receipt")
    if (
        _REVIEW_OPERATION_STAGES[str(operation["stage"])]
        < _REVIEW_OPERATION_STAGES["report-written"]
    ):
        operation = _write_review_operation_stage(
            store,
            operation,
            stage="report-written",
        )

    if handoff_nonce is None:
        handoff_digest = operation.get("handoff_nonce_sha256")
        if not isinstance(handoff_digest, str):
            raise ReviewRecoveryError("review handoff digest is invalid")
        handoff_path, handoff = _load_handoff_digest(store, handoff_digest)
    else:
        handoff_path, handoff = _load_handoff(store, handoff_nonce)
    if str(handoff_path) != operation["handoff_path"]:
        raise ReviewRecoveryError("review handoff path differs from receipt")
    recorded_at = report.get("recorded_at")
    reviewer_actor = report.get("reviewer_actor")
    if handoff["consumed_at"] is None and handoff["consumed_by"] is None:
        consumed_handoff = dict(handoff)
        consumed_handoff["consumed_at"] = recorded_at
        consumed_handoff["consumed_by"] = reviewer_actor
        _write_canonical_json(
            handoff_path,
            consumed_handoff,
            trusted_root=store.trusted_root,
        )
    elif (
        handoff["consumed_at"] != recorded_at
        or handoff["consumed_by"] != reviewer_actor
    ):
        raise ReviewRecoveryError("handoff nonce was consumed by another publication")
    if (
        _REVIEW_OPERATION_STAGES[str(operation["stage"])]
        < _REVIEW_OPERATION_STAGES["handoff-consumed"]
    ):
        operation = _write_review_operation_stage(
            store,
            operation,
            stage="handoff-consumed",
        )

    source_state, target_state = _state_matches_operation(store, operation)
    _assert_store_root_current(store)
    if source_state:
        store.transition(
            Phase(str(operation["target_phase"])),
            expected_revision=int(operation["expected_revision"]),
        )
    elif not target_state:
        raise ReviewRecoveryError("review transition state is invalid")
    _assert_store_root_current(store)
    if (
        _REVIEW_OPERATION_STAGES[str(operation["stage"])]
        < _REVIEW_OPERATION_STAGES["state-transitioned"]
    ):
        operation = _write_review_operation_stage(
            store,
            operation,
            stage="state-transitioned",
        )
    _remove_durable_file(
        _review_operation_path(store),
        trusted_root=store.trusted_root,
    )
    _assert_store_root_current(store)
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ReviewRecoveryError("review report findings are invalid")
    return ReviewReport(
        review_type=str(report["review_type"]),
        run_id=str(report["run_id"]),
        reviewer_actor=str(report["reviewer_actor"]),
        subject=current_subject,
        verdict=str(report["verdict"]),
        findings=tuple(dict(finding) for finding in findings),
        recorded_at=str(report["recorded_at"]),
    )


def _record_review(
    store: StateStore,
    *,
    current_subject: EvidenceSubject,
    reviewer_actor: str,
    handoff_nonce: str,
    verdict: str,
    findings: Sequence[Mapping[str, str]],
    review_type: str,
) -> ReviewReport:
    expected_role = _REVIEW_ROLE[review_type]
    expected_phase = _REVIEW_SOURCE_PHASE[review_type]
    if not isinstance(reviewer_actor, str) or not reviewer_actor.strip():
        raise ReviewError("reviewer actor must be a non-empty string")
    if verdict not in {"pass", "changes_requested"}:
        raise ReviewError("review verdict is invalid")
    normalized_findings = _normalize_findings(findings)
    if verdict == "changes_requested" and not normalized_findings:
        raise ReviewError("changes_requested requires at least one finding")

    publication_lock = FileLock(
        store.run_directory / "review-publication.lock",
        private_root=store.run_directory,
    )
    # Fixed order: review-publication lock, then StateStore's internal run lock.
    with (
        publication_lock as acquired_lock,
        store.anchored(acquired_lock.trusted_parent),
    ):
        pending = _load_review_operation(store)
        try:
            handoff_path, handoff = _load_handoff(store, handoff_nonce)
        except ReviewError as error:
            if pending is not None:
                raise ReviewRecoveryError(
                    "pending review publication cannot use this handoff"
                ) from error
            raise
        if handoff["role"] != expected_role.value:
            error = ReviewError("handoff nonce has the wrong review role")
            if pending is not None:
                raise ReviewRecoveryError(
                    "pending review publication belongs to a different role"
                ) from error
            raise error
        if handoff["source_actor"] == reviewer_actor:
            raise ReviewError("reviewer actor must differ from the source actor")
        if (
            handoff["subject"] != current_subject.to_dict()
            or handoff["subject_digest"] != current_subject.digest()
        ):
            error = ReviewError("handoff evidence subject is stale")
            if pending is not None:
                raise ReviewRecoveryError(
                    "pending review publication belongs to a stale subject"
                ) from error
            raise error

        nonce_sha256 = hashlib.sha256(handoff_nonce.encode("utf-8")).hexdigest()
        request = _request_payload(
            review_type=review_type,
            current_subject=current_subject,
            reviewer_actor=reviewer_actor,
            handoff_nonce_sha256=nonce_sha256,
            handoff=handoff,
            verdict=verdict,
            findings=normalized_findings,
        )
        if pending is not None:
            _validate_operation_request(
                store,
                pending,
                request=request,
                handoff_path=handoff_path,
            )
            _ensure_review_publication_seal(store, pending)
            return _recover_review_publication(
                store,
                operation=pending,
                current_subject=current_subject,
                handoff_nonce=handoff_nonce,
            )

        if handoff["consumed_at"] is not None or handoff["consumed_by"] is not None:
            raise ReviewError("handoff nonce was already consumed")
        state = store.load()
        if state.run_id != current_subject.run_id or handoff["run_id"] != state.run_id:
            raise ReviewError("review evidence belongs to another run")
        if state.phase is not expected_phase:
            raise ReviewError(f"{review_type} review requires {expected_phase.value}")

        report = _report_payload(request, recorded_at=_utc_now())
        report_path = store.run_directory / "reviews" / f"{review_type}-review.json"
        previous_report_digest = _review_report_digest(
            report_path,
            trusted_root=store.trusted_root,
        )
        new_report_digest = _bytes_digest(_canonical_json_bytes(report) + b"\n")
        operation = _prepare_review_operation(
            {
                "schema_version": 1,
                "stage": "prepared",
                "run_id": state.run_id,
                "review_type": review_type,
                "request": request,
                "request_digest": _canonical_json_digest(request),
                "report": report,
                "report_digest": _canonical_json_digest(report),
                "previous_report_digest": previous_report_digest,
                "new_report_digest": new_report_digest,
                "subject": current_subject.to_dict(),
                "subject_digest": current_subject.digest(),
                "handoff_nonce_sha256": nonce_sha256,
                "reviewer_actor": reviewer_actor,
                "source_actor": handoff["source_actor"],
                "role": expected_role.value,
                "expected_source_phase": expected_phase.value,
                "expected_revision": state.revision,
                "target_phase": _REVIEW_TARGET_PHASE[(review_type, verdict)].value,
                "artifact_path": str(report_path),
                "handoff_path": str(handoff_path),
            }
        )
        _write_canonical_json(
            _review_operation_path(store),
            operation,
            trusted_root=store.trusted_root,
        )
        _ensure_review_publication_seal(store, operation)
        return _recover_review_publication(
            store,
            operation=operation,
            current_subject=current_subject,
            handoff_nonce=handoff_nonce,
        )


def record_plan_review(
    store: StateStore,
    *,
    current_subject: EvidenceSubject,
    reviewer_actor: str,
    handoff_nonce: str,
    verdict: str,
    findings: Sequence[Mapping[str, str]],
) -> ReviewReport:
    return _record_review(
        store,
        current_subject=current_subject,
        reviewer_actor=reviewer_actor,
        handoff_nonce=handoff_nonce,
        verdict=verdict,
        findings=findings,
        review_type="plan",
    )


def record_code_review(
    store: StateStore,
    *,
    current_subject: EvidenceSubject,
    reviewer_actor: str,
    handoff_nonce: str,
    verdict: str,
    findings: Sequence[Mapping[str, str]],
) -> ReviewReport:
    return _record_review(
        store,
        current_subject=current_subject,
        reviewer_actor=reviewer_actor,
        handoff_nonce=handoff_nonce,
        verdict=verdict,
        findings=findings,
        review_type="code",
    )


def _read_private_review_json(
    run_directory: Path,
    relative_path: tuple[str, ...],
    *,
    label: str,
    trusted_root: Path | PrivateRootAnchor,
    missing_error: type[ReviewRecoveryError] = ReviewEvidenceMissingError,
) -> dict[str, object]:
    if not relative_path or any(
        not component
        or component in {".", ".."}
        or "/" in component
        or "\\" in component
        for component in relative_path
    ):
        raise ReviewRecoveryError(f"{label} path is unsafe")
    path = run_directory.joinpath(*relative_path)
    try:
        raw = _read_bounded_private_file(
            path,
            trusted_root=trusted_root,
            label=label,
            max_bytes=1_048_576,
        )
    except StateNotFoundError:
        raise missing_error(f"{label} is missing") from None
    except (OSError, StateCorruptionError) as error:
        raise ReviewRecoveryError(f"{label} cannot be opened safely") from error
    return _decode_canonical_json_object(raw, label=label)


_REVIEW_REQUEST_KEYS = {
    "schema_version",
    "review_type",
    "run_id",
    "reviewer_actor",
    "source_actor",
    "role",
    "subject",
    "subject_digest",
    "handoff_nonce_sha256",
    "verdict",
    "findings",
}


def validate_recoverable_review_publication(
    store: StateStore,
    current_subject: EvidenceSubject,
) -> str:
    """Validate a pending review receipt without consuming its secret handoff."""

    if type(store) is not StateStore or type(current_subject) is not EvidenceSubject:
        raise TypeError("store and current_subject must be exact evidence types")
    operation = _load_review_operation(store)
    if operation is None:
        raise ReviewEvidenceMissingError("review publication receipt is missing")
    _validate_review_publication_seal(store, operation)
    request = operation.get("request")
    report = operation.get("report")
    if not isinstance(request, dict) or not isinstance(report, dict):
        raise ReviewRecoveryError("review publication receipt payload is invalid")
    review_type = request.get("review_type")
    verdict = request.get("verdict")
    if review_type not in _REVIEW_SOURCE_PHASE or verdict not in {
        "pass",
        "changes_requested",
    }:
        raise ReviewRecoveryError("pending review request identity is invalid")
    if (review_type, verdict) not in _REVIEW_TARGET_PHASE:
        raise ReviewRecoveryError("pending review target is invalid")
    subject_payload = request.get("subject")
    try:
        if not isinstance(subject_payload, dict):
            raise TypeError
        subject = EvidenceSubject(**subject_payload)
    except (TypeError, ValueError) as error:
        raise ReviewRecoveryError("pending review subject is invalid") from error
    findings = request.get("findings")
    try:
        normalized_findings = _normalize_findings(findings)  # type: ignore[arg-type]
    except (ReviewError, TypeError) as error:
        raise ReviewRecoveryError("pending review findings are invalid") from error
    handoff_digest = request.get("handoff_nonce_sha256")
    reviewer_actor = request.get("reviewer_actor")
    source_actor = request.get("source_actor")
    expected_role = _REVIEW_ROLE[str(review_type)].value
    if (
        set(request) != _REVIEW_REQUEST_KEYS
        or request.get("schema_version") != 1
        or request.get("run_id") != current_subject.run_id
        or subject != current_subject
        or request.get("subject_digest") != current_subject.digest()
        or request.get("role") != expected_role
        or list(normalized_findings) != findings
        or not isinstance(handoff_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", handoff_digest) is None
        or not isinstance(reviewer_actor, str)
        or not reviewer_actor
        or not isinstance(source_actor, str)
        or not source_actor
        or reviewer_actor == source_actor
    ):
        raise ReviewRecoveryError("pending review request is stale or invalid")
    handoff_path = store.run_directory / "handoffs" / f"{handoff_digest}.json"
    _validate_operation_request(
        store,
        operation,
        request=request,
        handoff_path=handoff_path,
    )
    _state_matches_operation(store, operation)
    recorded_at = report.get("recorded_at")
    if not isinstance(recorded_at, str) or not recorded_at.endswith("Z"):
        raise ReviewRecoveryError("pending review timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(recorded_at[:-1] + "+00:00")
    except ValueError as error:
        raise ReviewRecoveryError("pending review timestamp is invalid") from error
    if parsed.utcoffset() != timezone.utc.utcoffset(
        parsed
    ) or report != _report_payload(
        request,
        recorded_at=recorded_at,
    ):
        raise ReviewRecoveryError("pending review report is invalid")

    stage = str(operation["stage"])
    current_report_digest = _review_report_digest(
        Path(str(operation["artifact_path"])),
        trusted_root=store.trusted_root,
    )
    previous_report_digest = operation["previous_report_digest"]
    new_report_digest = operation["new_report_digest"]
    if _REVIEW_OPERATION_STAGES[stage] >= _REVIEW_OPERATION_STAGES["report-written"]:
        if current_report_digest != new_report_digest:
            raise ReviewRecoveryError("pending review report differs from its receipt")
    elif current_report_digest not in {
        previous_report_digest,
        new_report_digest,
    }:
        raise ReviewRecoveryError("pending review report conflicts with its receipt")

    handoff = _read_private_review_json(
        store.run_directory,
        ("handoffs", handoff_path.name),
        label="pending review handoff",
        trusted_root=store.trusted_root,
    )
    consumed = (
        handoff.get("consumed_at") == recorded_at
        and handoff.get("consumed_by") == reviewer_actor
    )
    unconsumed = (
        handoff.get("consumed_at") is None and handoff.get("consumed_by") is None
    )
    if (
        set(handoff) != _HANDOFF_KEYS
        or handoff.get("schema_version") != 1
        or handoff.get("run_id") != current_subject.run_id
        or handoff.get("role") != expected_role
        or handoff.get("source_actor") != source_actor
        or handoff.get("subject") != current_subject.to_dict()
        or handoff.get("subject_digest") != current_subject.digest()
        or handoff.get("nonce_sha256") != handoff_digest
        or not (unconsumed or consumed)
        or (
            _REVIEW_OPERATION_STAGES[stage]
            >= _REVIEW_OPERATION_STAGES["handoff-consumed"]
            and not consumed
        )
    ):
        raise ReviewRecoveryError("pending review handoff is stale or invalid")
    return str(review_type)


def resume_review_publication(
    store: StateStore,
    *,
    current_subject: EvidenceSubject,
) -> ReviewReport:
    """Finish a sealed review publication after a fresh-process restart."""

    if type(store) is not StateStore or type(current_subject) is not EvidenceSubject:
        raise TypeError("store and current_subject must be exact evidence types")
    publication_lock = FileLock(
        store.run_directory / "review-publication.lock",
        private_root=store.run_directory,
    )
    with (
        publication_lock as acquired_lock,
        store.anchored(acquired_lock.trusted_parent),
    ):
        validate_recoverable_review_publication(store, current_subject)
        operation = _load_review_operation(store)
        if operation is None:  # pragma: no cover - lock makes this defensive only
            raise ReviewEvidenceMissingError("review publication receipt is missing")
        return _recover_review_publication(
            store,
            operation=operation,
            current_subject=current_subject,
            handoff_nonce=None,
        )


def validate_passing_code_review(
    store: StateStore,
    current_subject: EvidenceSubject,
) -> tuple[dict[str, object], dict[str, object]]:
    """Read-only validation of the complete passing code-review evidence chain."""

    if type(store) is not StateStore or type(current_subject) is not EvidenceSubject:
        raise TypeError("store and current_subject must be exact evidence types")
    if os.path.lexists(_review_operation_path(store)):
        raise ReviewRecoveryError(
            "code review publication is incomplete and requires recovery"
        )
    report = _read_private_review_json(
        store.run_directory,
        ("reviews", "code-review.json"),
        label="code review report",
        trusted_root=store.trusted_root,
    )
    expected_report_keys = {
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
    }
    subject_payload = report.get("subject")
    try:
        if not isinstance(subject_payload, dict):
            raise TypeError
        reviewed_subject = EvidenceSubject(**subject_payload)
    except (TypeError, ValueError) as error:
        raise ReviewRecoveryError("code review subject is invalid") from error
    findings = report.get("findings")
    try:
        normalized_findings = _normalize_findings(findings)  # type: ignore[arg-type]
    except (ReviewError, TypeError) as error:
        raise ReviewRecoveryError("code review findings are invalid") from error
    reviewer_actor = report.get("reviewer_actor")
    recorded_at = report.get("recorded_at")
    handoff_digest = report.get("handoff_nonce_sha256")
    if (
        set(report) != expected_report_keys
        or report.get("schema_version") != 1
        or report.get("review_type") != "code"
        or report.get("role") != ReviewRole.REVIEWER.value
        or report.get("verdict") != "pass"
        or report.get("run_id") != reviewed_subject.run_id
        or report.get("subject_digest") != reviewed_subject.digest()
        or list(normalized_findings) != findings
        or not isinstance(reviewer_actor, str)
        or not reviewer_actor
        or not isinstance(recorded_at, str)
        or not recorded_at.endswith("Z")
        or not isinstance(handoff_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", handoff_digest) is None
    ):
        raise ReviewRecoveryError("passing code review evidence is invalid")
    try:
        parsed_time = datetime.fromisoformat(recorded_at[:-1] + "+00:00")
    except ValueError as error:
        raise ReviewRecoveryError("code review timestamp is invalid") from error
    if parsed_time.utcoffset() != timezone.utc.utcoffset(parsed_time):
        raise ReviewRecoveryError("code review timestamp is invalid")

    handoff = _read_private_review_json(
        store.run_directory,
        ("handoffs", f"{handoff_digest}.json"),
        label="code review handoff",
        trusted_root=store.trusted_root,
    )
    if (
        set(handoff) != _HANDOFF_KEYS
        or handoff.get("schema_version") != 1
        or handoff.get("run_id") != reviewed_subject.run_id
        or handoff.get("role") != ReviewRole.REVIEWER.value
        or handoff.get("nonce_sha256") != handoff_digest
        or handoff.get("subject") != reviewed_subject.to_dict()
        or handoff.get("subject_digest") != reviewed_subject.digest()
        or handoff.get("consumed_by") != reviewer_actor
        or handoff.get("consumed_at") != recorded_at
        or not isinstance(handoff.get("source_actor"), str)
        or not handoff["source_actor"]
        or handoff.get("source_actor") == reviewer_actor
    ):
        raise ReviewRecoveryError("code review handoff evidence is invalid")
    transition_proven = any(
        event.event_type == "phase.transitioned"
        and event.run_id == reviewed_subject.run_id
        and event.previous_phase is Phase.CODE_REVIEW
        and event.phase is Phase.VERIFYING
        for event in store.events()
    )
    if not transition_proven:
        raise ReviewRecoveryError("passing code review is not bound to the state WAL")
    validate_completed_review_publication(
        store,
        report,
        review_type="code",
    )
    if reviewed_subject != current_subject:
        raise ReviewEvidenceStaleError("passing code review subject is stale")
    return report, handoff
