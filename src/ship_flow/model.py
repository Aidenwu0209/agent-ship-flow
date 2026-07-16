from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


STATE_SCHEMA_VERSION = 1


class Phase(str, Enum):
    INITIALIZED = "INITIALIZED"
    PLANNING = "PLANNING"
    PLAN_REVIEW = "PLAN_REVIEW"
    AWAITING_PLAN_APPROVAL = "AWAITING_PLAN_APPROVAL"
    DEVELOPING = "DEVELOPING"
    CODE_REVIEW = "CODE_REVIEW"
    VERIFYING = "VERIFYING"
    AWAITING_RELEASE_APPROVAL = "AWAITING_RELEASE_APPROVAL"
    RELEASING = "RELEASING"
    POST_RELEASE_VERIFYING = "POST_RELEASE_VERIFYING"
    ROLLBACK_PENDING = "ROLLBACK_PENDING"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLBACK_VERIFYING = "ROLLBACK_VERIFYING"
    ROLLED_BACK = "ROLLED_BACK"
    SYNCING = "SYNCING"
    AWAITING_CLEANUP_APPROVAL = "AWAITING_CLEANUP_APPROVAL"
    AWAITING_SCOPE_APPROVAL = "AWAITING_SCOPE_APPROVAL"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class OperationStatus(str, Enum):
    PREPARED = "PREPARED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


LEGAL_TRANSITIONS: Mapping[Phase, frozenset[Phase]] = MappingProxyType(
    {
        Phase.INITIALIZED: frozenset(
            {Phase.PLANNING, Phase.AWAITING_SCOPE_APPROVAL, Phase.BLOCKED}
        ),
        Phase.PLANNING: frozenset(
            {Phase.PLAN_REVIEW, Phase.AWAITING_SCOPE_APPROVAL, Phase.BLOCKED}
        ),
        Phase.PLAN_REVIEW: frozenset(
            {
                Phase.AWAITING_PLAN_APPROVAL,
                Phase.AWAITING_SCOPE_APPROVAL,
                Phase.PLANNING,
                Phase.BLOCKED,
            }
        ),
        Phase.AWAITING_PLAN_APPROVAL: frozenset(
            {Phase.DEVELOPING, Phase.AWAITING_SCOPE_APPROVAL, Phase.CANCELLED}
        ),
        Phase.DEVELOPING: frozenset(
            {Phase.CODE_REVIEW, Phase.AWAITING_SCOPE_APPROVAL, Phase.BLOCKED}
        ),
        Phase.CODE_REVIEW: frozenset(
            {
                Phase.VERIFYING,
                Phase.DEVELOPING,
                Phase.AWAITING_SCOPE_APPROVAL,
                Phase.BLOCKED,
            }
        ),
        Phase.VERIFYING: frozenset(
            {
                Phase.AWAITING_RELEASE_APPROVAL,
                Phase.DEVELOPING,
                Phase.AWAITING_SCOPE_APPROVAL,
                Phase.BLOCKED,
            }
        ),
        Phase.AWAITING_RELEASE_APPROVAL: frozenset(
            {
                Phase.RELEASING,
                Phase.AWAITING_SCOPE_APPROVAL,
                Phase.BLOCKED,
                Phase.CANCELLED,
            }
        ),
        Phase.RELEASING: frozenset(
            {
                Phase.POST_RELEASE_VERIFYING,
                Phase.ROLLBACK_PENDING,
                Phase.BLOCKED,
            }
        ),
        Phase.POST_RELEASE_VERIFYING: frozenset(
            {
                Phase.SYNCING,
                Phase.ROLLBACK_PENDING,
                Phase.ROLLING_BACK,
                Phase.BLOCKED,
            }
        ),
        Phase.ROLLBACK_PENDING: frozenset({Phase.ROLLING_BACK, Phase.BLOCKED}),
        Phase.ROLLING_BACK: frozenset(
            {
                Phase.ROLLBACK_VERIFYING,
                Phase.BLOCKED,
            }
        ),
        Phase.ROLLBACK_VERIFYING: frozenset({Phase.ROLLED_BACK, Phase.BLOCKED}),
        Phase.ROLLED_BACK: frozenset(),
        Phase.SYNCING: frozenset(
            {
                Phase.AWAITING_CLEANUP_APPROVAL,
                Phase.DEVELOPING,
                Phase.AWAITING_SCOPE_APPROVAL,
                Phase.BLOCKED,
            }
        ),
        Phase.AWAITING_CLEANUP_APPROVAL: frozenset(
            {Phase.COMPLETED, Phase.AWAITING_SCOPE_APPROVAL, Phase.BLOCKED}
        ),
        Phase.AWAITING_SCOPE_APPROVAL: frozenset({Phase.PLANNING}),
        Phase.COMPLETED: frozenset(),
        Phase.BLOCKED: frozenset(),
        Phase.CANCELLED: frozenset(),
    }
)


RECONCILIATION_TRANSITIONS: Mapping[Phase, frozenset[Phase]] = MappingProxyType(
    {
        **{phase: frozenset() for phase in Phase},
        Phase.INITIALIZED: frozenset({Phase.AWAITING_SCOPE_APPROVAL}),
        Phase.PLANNING: frozenset({Phase.AWAITING_SCOPE_APPROVAL}),
        Phase.PLAN_REVIEW: frozenset(
            {Phase.PLANNING, Phase.AWAITING_SCOPE_APPROVAL, Phase.BLOCKED}
        ),
        Phase.AWAITING_PLAN_APPROVAL: frozenset(
            {Phase.PLANNING, Phase.AWAITING_SCOPE_APPROVAL, Phase.BLOCKED}
        ),
        Phase.DEVELOPING: frozenset(
            {
                Phase.PLANNING,
                Phase.CODE_REVIEW,
                Phase.AWAITING_SCOPE_APPROVAL,
                Phase.BLOCKED,
            }
        ),
        Phase.CODE_REVIEW: frozenset(
            {
                Phase.PLANNING,
                Phase.DEVELOPING,
                Phase.AWAITING_SCOPE_APPROVAL,
                Phase.BLOCKED,
            }
        ),
        Phase.VERIFYING: frozenset(
            {
                Phase.PLANNING,
                Phase.DEVELOPING,
                Phase.CODE_REVIEW,
                Phase.AWAITING_SCOPE_APPROVAL,
                Phase.BLOCKED,
            }
        ),
        Phase.AWAITING_RELEASE_APPROVAL: frozenset(
            {
                Phase.PLANNING,
                Phase.DEVELOPING,
                Phase.CODE_REVIEW,
                Phase.SYNCING,
                Phase.AWAITING_SCOPE_APPROVAL,
                Phase.BLOCKED,
            }
        ),
        Phase.RELEASING: frozenset({Phase.BLOCKED}),
        Phase.POST_RELEASE_VERIFYING: frozenset({Phase.BLOCKED}),
        Phase.ROLLBACK_PENDING: frozenset({Phase.BLOCKED}),
        Phase.ROLLING_BACK: frozenset({Phase.BLOCKED}),
        Phase.ROLLBACK_VERIFYING: frozenset({Phase.BLOCKED}),
        Phase.SYNCING: frozenset(
            {
                Phase.PLANNING,
                Phase.DEVELOPING,
                Phase.CODE_REVIEW,
                Phase.AWAITING_SCOPE_APPROVAL,
                Phase.BLOCKED,
            }
        ),
        Phase.AWAITING_CLEANUP_APPROVAL: frozenset(
            {
                Phase.PLANNING,
                Phase.DEVELOPING,
                Phase.CODE_REVIEW,
                Phase.SYNCING,
                Phase.AWAITING_SCOPE_APPROVAL,
                Phase.BLOCKED,
            }
        ),
        Phase.AWAITING_SCOPE_APPROVAL: frozenset({Phase.PLANNING}),
    }
)


@dataclass(frozen=True)
class RunState:
    run_id: str
    phase: Phase
    revision: int
    created_at: str
    updated_at: str
    schema_version: int = STATE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "phase": self.phase.value,
            "revision": self.revision,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RunState":
        expected_keys = {
            "schema_version",
            "run_id",
            "phase",
            "revision",
            "created_at",
            "updated_at",
        }
        if set(value) != expected_keys:
            raise ValueError("run state has unexpected or missing fields")
        if value["schema_version"] != STATE_SCHEMA_VERSION:
            raise ValueError("unsupported run state schema")
        if not isinstance(value["run_id"], str) or not value["run_id"]:
            raise ValueError("run_id must be a non-empty string")
        if type(value["revision"]) is not int or value["revision"] < 0:
            raise ValueError("revision must be a non-negative integer")
        if not isinstance(value["created_at"], str) or not isinstance(
            value["updated_at"], str
        ):
            raise ValueError("state timestamps must be strings")
        try:
            phase = Phase(value["phase"])
        except (TypeError, ValueError) as error:
            raise ValueError("unknown run phase") from error
        return cls(
            run_id=value["run_id"],
            phase=phase,
            revision=value["revision"],
            created_at=value["created_at"],
            updated_at=value["updated_at"],
            schema_version=value["schema_version"],
        )
