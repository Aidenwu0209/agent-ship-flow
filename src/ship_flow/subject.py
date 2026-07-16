from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class EvidenceSubject:
    run_id: str
    base_oid: str
    candidate_oid: str
    tree_oid: str
    plan_sha256: str
    manifest_sha256: str
    commands_sha256: str
    engine_version: str
    schema_version: int

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not self.run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        for field_name in ("base_oid", "candidate_oid", "tree_oid"):
            value = getattr(self, field_name)
            if (
                not isinstance(value, str)
                or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None
            ):
                raise ValueError(f"{field_name} must be a lowercase Git object ID")
        for field_name in (
            "plan_sha256",
            "manifest_sha256",
            "commands_sha256",
        ):
            value = getattr(self, field_name)
            if (
                not isinstance(value, str)
                or re.fullmatch(r"[0-9a-f]{64}", value) is None
            ):
                raise ValueError(f"{field_name} must be a lowercase SHA-256")
        if not isinstance(self.engine_version, str) or not self.engine_version.strip():
            raise ValueError("engine_version must be a non-empty string")
        if type(self.schema_version) is not int or self.schema_version < 1:
            raise ValueError("schema_version must be a positive integer")

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()
