from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import nullcontext
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from ship_flow import release as release_module
from ship_flow.manifest import CommandSpec, Manifest, OperationSpec, manifest_digest
from ship_flow.model import Phase
from ship_flow.release import (
    ApprovalRecord,
    OperationRecord,
    ReleaseEngine,
    ReleaseError,
    ReleaseRecoveryError,
    _health_protocol_passes,
    _probe_protocol_outcome,
    validate_external_operation_evidence,
)
from ship_flow.runner import CommandResult, CommandRunner, _resolved_argv
from ship_flow.store import FileLock, LockUnavailableError, StateStore
from ship_flow.subject import EvidenceSubject
from ship_flow.verify import _command_digest, verification_commands_digest
from tests.support import git, git_output, initialize_repository


class CountingRunner:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, *args: object, **kwargs: object):
        self.calls += 1
        raise AssertionError("release effect must not run")


class CorruptingHealthRunner:
    def __init__(self, corruption: str) -> None:
        self.corruption = corruption
        self.delegate = CommandRunner()

    def run(self, spec: CommandSpec, *args: object, **kwargs: object) -> CommandResult:
        result = self.delegate.run(spec, *args, **kwargs)
        if spec.category == "health":
            if self.corruption == "deleted":
                result.log_path.unlink()
            elif self.corruption == "digest":
                result.log_path.write_bytes(result.log_path.read_bytes() + b"tampered")
        return result


class SimulatedCrash(RuntimeError):
    pass


class ApprovalWindowDateTime(datetime):
    @classmethod
    def now(cls, tz: object = None) -> datetime:
        del tz
        return cls(2026, 1, 1, tzinfo=timezone.utc)


class ReplacementWindowDateTime(datetime):
    @classmethod
    def now(cls, tz: object = None) -> datetime:
        del tz
        return cls(2026, 1, 1, 0, 2, tzinfo=timezone.utc)


class CrashOnceReleaseEngine(ReleaseEngine):
    def __init__(self, *args: object, crash_stage: str, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.crash_stage = crash_stage

    def _checkpoint(self, stage: str, record: OperationRecord) -> None:
        del record
        if self.crash_stage == stage:
            self.crash_stage = ""
            raise SimulatedCrash(stage)


class CrashOnceModeReleaseEngine(CrashOnceReleaseEngine):
    def __init__(
        self,
        *args: object,
        crash_mode: str,
        crash_stage: str,
        **kwargs: object,
    ) -> None:
        super().__init__(*args, crash_stage=crash_stage, **kwargs)
        self.crash_mode = crash_mode

    def _checkpoint(self, stage: str, record: OperationRecord) -> None:
        if record.mode == self.crash_mode:
            super()._checkpoint(stage, record)


class CrashOnceIndexedReleaseEngine(CrashOnceReleaseEngine):
    def __init__(
        self,
        *args: object,
        crash_mode: str,
        crash_index: int,
        crash_stage: str,
        **kwargs: object,
    ) -> None:
        super().__init__(*args, crash_stage=crash_stage, **kwargs)
        self.crash_mode = crash_mode
        self.crash_index = crash_index

    def _checkpoint(self, stage: str, record: OperationRecord) -> None:
        if record.mode == self.crash_mode and record.index == self.crash_index:
            super()._checkpoint(stage, record)


class CrashAfterSupersessionEngine(ReleaseEngine):
    def _cycle_checkpoint(self, stage: str) -> None:
        if stage == "supersession-sealed":
            raise SimulatedCrash(stage)


def release_manifest(marker: Path) -> Manifest:
    return Manifest(
        project_name="fixture",
        base_branch="main",
        remote="origin",
        verification_steps=(
            CommandSpec("unit", (sys.executable, "-c", "pass"), "unit"),
        ),
        release_required=True,
        release_steps=(
            OperationSpec(
                name="fake-release",
                kind="push",
                target="production",
                argv=(
                    sys.executable,
                    "-c",
                    "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                    str(marker),
                ),
                effect="external_write",
                idempotency="safe",
            ),
        ),
    )


def variables(repo: Path) -> dict[str, str]:
    return {
        "repo": str(repo),
        "worktree": str(repo),
        "branch": "main",
        "base_branch": "main",
        "remote": "origin",
    }


def subject_for(repo: Path, manifest: Manifest) -> EvidenceSubject:
    return EvidenceSubject(
        run_id="run-001",
        base_oid=git_output(repo, "rev-parse", "HEAD^{commit}"),
        candidate_oid=git_output(repo, "rev-parse", "HEAD^{commit}"),
        tree_oid=git_output(repo, "rev-parse", "HEAD^{tree}"),
        plan_sha256="4" * 64,
        manifest_sha256=manifest_digest(manifest),
        commands_sha256=verification_commands_digest(manifest, variables(repo)),
        engine_version="0.1.0",
        schema_version=1,
    )


def canonical_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_digest(payload: object) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def write_private_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(canonical_bytes(payload) + b"\n")
    os.chmod(path, 0o600)


def seal_passing_verification(
    run_directory: Path,
    manifest: Manifest,
    subject: EvidenceSubject,
    resolved_variables: dict[str, str],
    *,
    retain_existing: bool = False,
) -> None:
    run_directory = run_directory.resolve()
    if not retain_existing:
        for directory_name in ("verifications", "verification-publications"):
            directory = run_directory / directory_name
            if directory.is_dir():
                for path in directory.iterdir():
                    if path.is_file():
                        path.unlink()
    publication_events = [
        event
        for event in StateStore(run_directory).events()
        if event.previous_phase is Phase.VERIFYING
        and event.phase is Phase.AWAITING_RELEASE_APPROVAL
    ]
    if not publication_events:
        raise AssertionError("fixture requires a published verification transition")
    expected_revision = publication_events[-1].revision - 1
    round_number = sum(
        event.phase is Phase.VERIFYING and event.revision <= expected_revision
        for event in StateStore(run_directory).events()
    )
    log_path = run_directory / "logs" / "verified-unit.log"
    log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    log_path.write_bytes(b"")
    os.chmod(log_path, 0o600)
    command_digest = _command_digest(
        manifest.verification_steps[0],
        _resolved_argv(manifest.verification_steps[0].argv, resolved_variables),
    )
    terminal_digest = "a" * 64
    report: dict[str, object] = {
        "schema_version": 1,
        "run_id": subject.run_id,
        "round": round_number,
        "verifier_actor": "verifier",
        "subject": subject.to_dict(),
        "subject_digest": subject.digest(),
        "handoff_nonce_sha256": "b" * 64,
        "commands_sha256": subject.commands_sha256,
        "terminal_receipt_sha256": [terminal_digest],
        "verdict": "pass",
        "results": [
            {
                "index": 1,
                "command_sha256": command_digest,
                "started_at": "2026-07-15T00:00:00Z",
                "ended_at": "2026-07-15T00:00:01Z",
                "duration_seconds": 1.0,
                "exit_code": 0,
                "timed_out": False,
                "truncated": False,
                "log_path": str(log_path),
                "log_sha256": hashlib.sha256(b"").hexdigest(),
                "log_size": 0,
            }
        ],
        "recorded_at": "2026-07-15T00:00:01Z",
    }
    report_path = (
        run_directory / "verifications" / f"verification-{round_number:04d}.json"
    )
    write_private_json(report_path, report)
    request: dict[str, object] = {
        "schema_version": 1,
        "run_id": subject.run_id,
        "verifier_actor": "verifier",
        "subject": subject.to_dict(),
        "subject_digest": subject.digest(),
        "handoff_nonce_sha256": "b" * 64,
        "manifest_sha256": manifest_digest(manifest),
        "command_digests": [command_digest],
        "variables_sha256": canonical_digest(resolved_variables),
        "sensitive_values_sha256": canonical_digest([]),
    }
    publication: dict[str, object] = {
        "schema_version": 1,
        "request": request,
        "request_digest": canonical_digest(request),
        "report": report,
        "report_digest": canonical_digest(report),
        "report_file_sha256": hashlib.sha256(
            canonical_bytes(report) + b"\n"
        ).hexdigest(),
        "artifact_path": str(report_path),
        "handoff_path": str(run_directory / "handoffs" / f"{'b' * 64}.json"),
        "handoff_digest": "c" * 64,
        "terminal_receipt_sha256": [terminal_digest],
        "expected_revision": expected_revision,
        "target_phase": Phase.AWAITING_RELEASE_APPROVAL.value,
    }
    publication_digest = canonical_digest(publication)
    write_private_json(
        run_directory
        / "verification-publications"
        / f"verification-{round_number:04d}-{publication_digest}.json",
        publication,
    )


def counter_manifest(
    root: Path,
    *,
    candidate_oid: str,
    with_probe: bool,
    idempotency: str = "safe",
) -> Manifest:
    counter = root / "external-counter"
    effect = (
        sys.executable,
        "-c",
        (
            "from pathlib import Path; import sys; p=Path(sys.argv[1]); "
            "n=int(p.read_text()) if p.exists() else 0; p.write_text(str(n+1))"
        ),
        str(counter),
    )
    probe = (
        sys.executable,
        "-c",
        (
            "from pathlib import Path; import json,sys; p=Path(sys.argv[1]); "
            "applied=p.exists() and p.read_text()=='1'; "
            "print(json.dumps({'schema_version':1,'kind':'probe',"
            "'outcome':'applied' if applied else 'not_applied',"
            "'target':sys.argv[3],'version':sys.argv[2] if applied else None},"
            "sort_keys=True,separators=(',',':')))"
        ),
        str(counter),
        candidate_oid,
        "production",
    )
    return Manifest(
        project_name="fixture",
        base_branch="main",
        remote="origin",
        verification_steps=(
            CommandSpec("unit", (sys.executable, "-c", "pass"), "unit"),
        ),
        release_required=True,
        release_steps=(
            OperationSpec(
                name="counter-release",
                kind="push",
                target="production",
                argv=effect,
                effect="external_write",
                idempotency=idempotency,
                probe_argv=(probe if with_probe else ()),
            ),
        ),
    )


def health_manifest(
    root: Path,
    *,
    health_output: str,
    health_exit_code: int = 0,
) -> Manifest:
    marker = root / "deployed"
    return Manifest(
        project_name="fixture",
        base_branch="main",
        remote="origin",
        verification_steps=(
            CommandSpec("unit", (sys.executable, "-c", "pass"), "unit"),
        ),
        release_required=True,
        release_steps=(
            OperationSpec(
                name="fake-deploy",
                kind="deploy",
                target="production",
                argv=(
                    sys.executable,
                    "-c",
                    "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                    str(marker),
                ),
                effect="external_write",
                idempotency="safe",
            ),
        ),
        release_healthchecks=(
            CommandSpec(
                "production-health",
                (
                    sys.executable,
                    "-c",
                    (
                        "import json,sys; print(json.dumps({'schema_version':1,"
                        "'kind':'health','status':'healthy','target':sys.argv[2],"
                        "'version':sys.argv[1]},sort_keys=True,separators=(',',':'))); "
                        "raise SystemExit(int(sys.argv[3]))"
                    ),
                    health_output,
                    "production",
                    str(health_exit_code),
                ),
                "health",
            ),
        ),
    )


def rollback_manifest(
    root: Path,
    *,
    data_impact: str,
    rollback_health_output: str,
    rollback_health_status: str = "healthy",
) -> Manifest:
    deployed = root / "deployed"
    rollback_counter = root / "rollback-counter"
    return Manifest(
        project_name="fixture",
        base_branch="main",
        remote="origin",
        verification_steps=(
            CommandSpec("unit", (sys.executable, "-c", "pass"), "unit"),
        ),
        release_required=True,
        release_steps=(
            OperationSpec(
                name="fake-deploy",
                kind="deploy",
                target="production",
                argv=(
                    sys.executable,
                    "-c",
                    "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                    str(deployed),
                ),
                effect="external_write",
                idempotency="safe",
            ),
        ),
        release_healthchecks=(
            CommandSpec(
                "failing-release-health",
                (
                    sys.executable,
                    "-c",
                    (
                        "import json; print(json.dumps({'schema_version':1,"
                        "'kind':'health','status':'unhealthy','target':'production',"
                        "'version':'wrong-release'},sort_keys=True,"
                        "separators=(',',':')))"
                    ),
                ),
                "health",
            ),
        ),
        rollback_steps=(
            OperationSpec(
                name="restore-previous",
                target="production",
                argv=(
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path; import sys; p=Path(sys.argv[1]); "
                        "n=int(p.read_text()) if p.exists() else 0; "
                        "p.write_text(str(n+1))"
                    ),
                    str(rollback_counter),
                ),
                effect="external_write",
                idempotency="safe",
                data_impact=data_impact,
            ),
        ),
        rollback_healthchecks=(
            CommandSpec(
                "rollback-health",
                (
                    sys.executable,
                    "-c",
                    (
                        "import json,sys; print(json.dumps({'schema_version':1,"
                        "'kind':'health','status':sys.argv[2],"
                        "'target':'production','version':sys.argv[1]},"
                        "sort_keys=True,separators=(',',':')))"
                    ),
                    rollback_health_output,
                    rollback_health_status,
                ),
                "health",
            ),
        ),
    )


def prepare_release_gate(
    root: Path,
) -> tuple[Path, Path, StateStore, Manifest, EvidenceSubject]:
    repo = root / "repo"
    base_oid = initialize_repository(repo)
    (root / "runtime").mkdir()
    run_directory = root / "runtime" / "runs" / "run-001"
    store = StateStore(run_directory)
    state = store.create("run-001")
    for phase in (
        Phase.PLANNING,
        Phase.PLAN_REVIEW,
        Phase.AWAITING_PLAN_APPROVAL,
        Phase.DEVELOPING,
        Phase.CODE_REVIEW,
        Phase.VERIFYING,
        Phase.AWAITING_RELEASE_APPROVAL,
    ):
        state = store.transition(phase, expected_revision=state.revision)
    manifest = release_manifest(root / "effect-ran")
    subject = EvidenceSubject(
        run_id="run-001",
        base_oid=base_oid,
        candidate_oid=git_output(repo, "rev-parse", "HEAD^{commit}"),
        tree_oid=git_output(repo, "rev-parse", "HEAD^{tree}"),
        plan_sha256="4" * 64,
        manifest_sha256=manifest_digest(manifest),
        commands_sha256=verification_commands_digest(manifest, variables(repo)),
        engine_version="0.1.0",
        schema_version=1,
    )
    seal_passing_verification(run_directory, manifest, subject, variables(repo))
    return repo, run_directory, store, manifest, subject


class ReleaseImportTests(unittest.TestCase):
    def test_release_interfaces_import(self) -> None:
        self.assertTrue(ApprovalRecord)
        self.assertTrue(OperationRecord)
        self.assertTrue(ReleaseEngine)

    def test_manual_operation_decision_interfaces_are_frozen(self) -> None:
        self.assertTrue(
            release_module.PendingOperationDecision.__dataclass_params__.frozen
        )
        self.assertTrue(
            release_module.OperationAdjudication.__dataclass_params__.frozen
        )


class ReleaseApprovalTests(unittest.TestCase):
    def test_nonfinite_json_is_always_a_release_recovery_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject = prepare_release_gate(root)
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            poisoned = run_directory / "nonfinite.json"
            poisoned.write_bytes(b'{"value":NaN}\n')
            os.chmod(poisoned, 0o600)

            for reader in (
                lambda: engine._read_private_canonical_json(
                    poisoned,
                    label="active external context",
                ),
                lambda: engine._read_operation_file(poisoned),
                lambda: engine._read_adjudication_file(poisoned),
                lambda: engine._read_health_file(poisoned),
            ):
                with (
                    self.subTest(reader=reader),
                    self.assertRaises(ReleaseRecoveryError),
                ):
                    reader()

    def test_expired_unpublished_approval_is_audited_before_new_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject = prepare_release_gate(root)
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            original_write = release_module._write_canonical_json

            def crash_before_pointer(
                path: Path,
                payload: dict[str, object],
                *,
                trusted_root: object,
            ) -> None:
                if path.parent.name == "approvals":
                    raise OSError("simulated approval publication loss")
                original_write(path, payload, trusted_root=trusted_root)

            with (
                patch.object(release_module, "datetime", ApprovalWindowDateTime),
                patch.object(
                    release_module,
                    "_write_canonical_json",
                    side_effect=crash_before_pointer,
                ),
                self.assertRaises(ReleaseError),
            ):
                engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="first-human",
                    expires_at="2026-01-01T00:01:00Z",
                )
            orphan = next((run_directory / "approvals" / "sealed").glob("*.json"))

            replacement = engine.record_approval(
                gate="release",
                target="production",
                approver_actor="replacement-human",
                expires_at="2999-01-01T00:00:00Z",
            )

            self.assertTrue(
                (run_directory / "approvals" / "abandoned" / orphan.name).is_file()
            )
            self.assertFalse((run_directory / "approvals" / orphan.name).exists())
            self.assertEqual(
                engine.inspect_current_unconsumed_approval(gate="release"),
                replacement,
            )

    def test_record_approval_rejects_an_already_expired_deadline_without_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject = prepare_release_gate(root)
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            approval_root = run_directory / "approvals"
            before = tuple(approval_root.rglob("*")) if approval_root.exists() else ()

            with self.assertRaises(ReleaseError):
                engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="human",
                    expires_at="2000-01-01T00:00:00Z",
                )

            after = tuple(approval_root.rglob("*")) if approval_root.exists() else ()
            self.assertEqual(after, before)

    def test_expired_current_approval_is_ignored_after_full_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject = prepare_release_gate(root)
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            with patch.object(release_module, "datetime", ApprovalWindowDateTime):
                expired = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="expired-human",
                    expires_at="2026-01-01T00:01:00Z",
                )
            valid = engine.record_approval(
                gate="release",
                target="production",
                approver_actor="valid-human",
                expires_at="2999-01-01T00:00:00Z",
            )

            inspected = engine.inspect_current_unconsumed_approval(gate="release")

            self.assertNotEqual(expired.approval_id, valid.approval_id)
            self.assertEqual(inspected, valid)

    def test_only_expired_current_approval_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject = prepare_release_gate(root)
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            with patch.object(release_module, "datetime", ApprovalWindowDateTime):
                engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="expired-human",
                    expires_at="2026-01-01T00:01:00Z",
                )

            self.assertIsNone(
                engine.inspect_current_unconsumed_approval(gate="release")
            )

    def test_two_valid_approvals_remain_ambiguous_beside_an_expired_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject = prepare_release_gate(root)
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            with patch.object(release_module, "datetime", ApprovalWindowDateTime):
                engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="expired-human",
                    expires_at="2026-01-01T00:01:00Z",
                )
            for actor in ("valid-one", "valid-two"):
                engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor=actor,
                    expires_at="2999-01-01T00:00:00Z",
                )

            with self.assertRaises(ReleaseRecoveryError):
                engine.inspect_current_unconsumed_approval(gate="release")

    def test_corrupt_expired_current_approval_still_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject = prepare_release_gate(root)
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            with patch.object(release_module, "datetime", ApprovalWindowDateTime):
                expired = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="expired-human",
                    expires_at="2026-01-01T00:01:00Z",
                )
            pointer = run_directory / "approvals" / f"{expired.approval_id}.json"
            pointer.write_bytes(pointer.read_bytes() + b"corrupt")

            with self.assertRaises(ReleaseRecoveryError):
                engine.inspect_current_unconsumed_approval(gate="release")

    def test_inspection_returns_none_when_current_gate_has_no_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject = prepare_release_gate(root)
            runner = CountingRunner()
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                runner=runner,
            )
            before = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }

            inspected = engine.inspect_current_unconsumed_approval(gate="release")

            after = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }
            self.assertIsNone(inspected)
            self.assertEqual(after, before)
            self.assertEqual(runner.calls, 0)

    def test_inspects_one_current_unconsumed_approval_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject = prepare_release_gate(root)
            runner = CountingRunner()
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                runner=runner,
            )
            approval = engine.record_approval(
                gate="release",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
            )
            before = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }

            inspected = engine.inspect_current_unconsumed_approval(gate="release")

            after = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }
            self.assertEqual(inspected, approval)
            self.assertEqual(after, before)
            self.assertEqual(runner.calls, 0)

    def test_inspection_rejects_ambiguous_current_approvals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject = prepare_release_gate(root)
            runner = CountingRunner()
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                runner=runner,
            )
            for actor in ("human-one", "human-two"):
                engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor=actor,
                    expires_at="2999-01-01T00:00:00Z",
                )
            before = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }

            with self.assertRaises(ReleaseRecoveryError):
                engine.inspect_current_unconsumed_approval(gate="release")

            after = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)
            self.assertEqual(runner.calls, 0)

    def test_inspection_rejects_consumed_and_corrupt_current_approval(
        self,
    ) -> None:
        for case in ("consumed", "corrupt"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo, run_directory, _, manifest, subject = prepare_release_gate(root)
                runner = CountingRunner()
                engine = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    runner=runner,
                )
                approval = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                )
                if case == "consumed":
                    engine.consume_approval(
                        approval.approval_id,
                        consumer="abandoned-release",
                    )
                elif case == "corrupt":
                    pointer = (
                        run_directory / "approvals" / f"{approval.approval_id}.json"
                    )
                    pointer.write_bytes(pointer.read_bytes() + b"corrupt")
                before = {
                    path.relative_to(run_directory): path.read_bytes()
                    for path in run_directory.rglob("*")
                    if path.is_file()
                }

                with self.assertRaises(ReleaseRecoveryError):
                    engine.inspect_current_unconsumed_approval(gate="release")

                after = {
                    path.relative_to(run_directory): path.read_bytes()
                    for path in run_directory.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(after, before)
                self.assertEqual(runner.calls, 0)

    def test_inspection_rejects_current_approval_for_another_subject(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject = prepare_release_gate(root)
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            engine.record_approval(
                gate="release",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
            )
            observer = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=replace(subject, plan_sha256="9" * 64),
                variables=variables(repo),
                runner=CountingRunner(),
            )

            with self.assertRaises(ReleaseRecoveryError):
                observer.inspect_current_unconsumed_approval(gate="release")

    def test_approval_observation_and_write_share_the_locked_run_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject = prepare_release_gate(root)
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            detached = root / "detached-run"
            real_acquire = FileLock.acquire
            swapped = False

            def acquire_then_replace(lock: FileLock) -> FileLock:
                nonlocal swapped
                acquired = real_acquire(lock)
                if not swapped and lock.path.name == "approval-publication.lock":
                    run_directory.rename(detached)
                    shutil.copytree(detached, run_directory)
                    swapped = True
                return acquired

            with patch.object(
                FileLock,
                "acquire",
                autospec=True,
                side_effect=acquire_then_replace,
            ):
                approval = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                )

            self.assertTrue(swapped)
            self.assertFalse(
                (run_directory / "approvals" / f"{approval.approval_id}.json").exists()
            )
            self.assertTrue(
                (detached / "approvals" / f"{approval.approval_id}.json").is_file()
            )
            self.assertTrue(
                (
                    detached / "approvals" / "sealed" / f"{approval.approval_id}.json"
                ).is_file()
            )

    def test_live_git_drift_blocks_before_consuming_approval_or_effect(self) -> None:
        for case in ("dirty", "new-commit"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo, run_directory, store, manifest, subject = prepare_release_gate(
                    root
                )
                runner = CountingRunner()
                engine = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    runner=runner,
                )
                approval = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                )
                (repo / "README.md").write_text(case, encoding="utf-8")
                if case == "new-commit":
                    git(repo, "add", "README.md")
                    git(repo, "commit", "-m", "candidate drift")

                with self.assertRaises(ReleaseError):
                    engine.release(
                        target="production", approval_id=approval.approval_id
                    )

                approval_payload = json.loads(
                    (
                        run_directory / "approvals" / f"{approval.approval_id}.json"
                    ).read_text(encoding="utf-8")
                )
                self.assertIsNone(approval_payload["consumed_at"])
                self.assertEqual(runner.calls, 0)
                self.assertFalse((root / "effect-ran").exists())
                self.assertEqual(store.load().phase, Phase.BLOCKED)

    def test_invalid_approvals_execute_zero_effects(self) -> None:
        for case in (
            "missing",
            "expired",
            "wrong-target",
            "wrong-subject",
            "changed-command",
            "consumed",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo, run_directory, store, manifest, subject = prepare_release_gate(
                    root
                )
                runner = CountingRunner()
                engine = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    runner=runner,
                )
                approval_id = "missing"
                if case != "missing":
                    expiry = (
                        "2026-01-01T00:01:00Z"
                        if case == "expired"
                        else "2999-01-01T00:00:00Z"
                    )
                    clock = (
                        patch.object(
                            release_module,
                            "datetime",
                            ApprovalWindowDateTime,
                        )
                        if case == "expired"
                        else nullcontext()
                    )
                    with clock:
                        approval = engine.record_approval(
                            gate="release",
                            target=(
                                "staging" if case == "wrong-target" else "production"
                            ),
                            approver_actor="human",
                            expires_at=expiry,
                        )
                    approval_id = approval.approval_id
                if case == "wrong-subject":
                    engine = ReleaseEngine(
                        repo=repo,
                        run_directory=run_directory,
                        manifest=manifest,
                        current_subject=replace(subject, plan_sha256="9" * 64),
                        variables=variables(repo),
                        runner=runner,
                    )
                elif case == "changed-command":
                    changed = replace(
                        manifest,
                        release_steps=(
                            replace(
                                manifest.release_steps[0],
                                argv=(sys.executable, "-c", "pass"),
                            ),
                        ),
                    )
                    engine = ReleaseEngine(
                        repo=repo,
                        run_directory=run_directory,
                        manifest=changed,
                        current_subject=subject,
                        variables=variables(repo),
                        runner=runner,
                    )
                elif case == "consumed":
                    engine.consume_approval(approval_id, consumer="previous-release")

                with self.assertRaises(ReleaseError):
                    engine.release(target="production", approval_id=approval_id)

                self.assertEqual(runner.calls, 0)
                self.assertFalse((root / "effect-ran").exists())
                self.assertEqual(
                    store.load().phase,
                    (
                        Phase.BLOCKED
                        if case in {"wrong-subject", "changed-command"}
                        else Phase.AWAITING_RELEASE_APPROVAL
                    ),
                )

    def test_records_are_frozen(self) -> None:
        self.assertTrue(FrozenInstanceError)
        self.assertTrue(ApprovalRecord.__dataclass_params__.frozen)
        self.assertTrue(OperationRecord.__dataclass_params__.frozen)


class ReleaseOperationRecoveryTests(unittest.TestCase):
    def _fixture(
        self,
        root: Path,
        *,
        with_probe: bool,
        idempotency: str = "safe",
    ) -> tuple[Path, Path, StateStore, Manifest, EvidenceSubject, ApprovalRecord]:
        repo, run_directory, store, _, initial_subject = prepare_release_gate(root)
        manifest = counter_manifest(
            root,
            candidate_oid=initial_subject.candidate_oid,
            with_probe=with_probe,
            idempotency=idempotency,
        )
        subject = subject_for(repo, manifest)
        seal_passing_verification(run_directory, manifest, subject, variables(repo))
        engine = ReleaseEngine(
            repo=repo,
            run_directory=run_directory,
            manifest=manifest,
            current_subject=subject,
            variables=variables(repo),
        )
        approval = engine.record_approval(
            gate="release",
            target="production",
            approver_actor="human",
            expires_at="2999-01-01T00:00:00Z",
        )
        return repo, run_directory, store, manifest, subject, approval

    @staticmethod
    def _leave_operation_commitment_only(
        run_directory: Path,
        *,
        status: str,
    ) -> tuple[Path, Path]:
        active = json.loads(
            (run_directory / "release-cycles" / "active-release.json").read_text(
                encoding="utf-8"
            )
        )
        operation_directory = (
            run_directory / "release-cycles" / active["cycle_id"] / "operations"
        )
        pattern = f"release-0001-attempt-1-{status.lower()}-*.json"
        commitments = tuple((operation_directory / "committed").glob(pattern))
        seals = tuple((operation_directory / "sealed").glob(pattern))
        if len(commitments) != 1 or len(seals) != 1:
            raise AssertionError(
                f"fixture expected one {status} commitment and seal, got "
                f"{len(commitments)} and {len(seals)}"
            )
        seals[0].unlink()
        pointer = operation_directory / "release-0001.json"
        if pointer.exists():
            pointer.unlink()
        return commitments[0], seals[0]

    def _unknown_fixture(
        self,
        root: Path,
    ) -> tuple[
        Path,
        Path,
        StateStore,
        Manifest,
        EvidenceSubject,
        ApprovalRecord,
        ReleaseEngine,
    ]:
        repo, run_directory, store, manifest, subject, approval = self._fixture(
            root,
            with_probe=False,
            idempotency="manual_reconcile",
        )
        crashing = CrashOnceReleaseEngine(
            repo=repo,
            run_directory=run_directory,
            manifest=manifest,
            current_subject=subject,
            variables=variables(repo),
            crash_stage="effect-returned",
        )
        with self.assertRaises(SimulatedCrash):
            crashing.release(target="production", approval_id=approval.approval_id)
        engine = ReleaseEngine(
            repo=repo,
            run_directory=run_directory,
            manifest=manifest,
            current_subject=subject,
            variables=variables(repo),
        )
        with self.assertRaises(ReleaseRecoveryError):
            engine.reconcile_operation(target="production")
        self.assertEqual(store.load().phase, Phase.BLOCKED)
        return repo, run_directory, store, manifest, subject, approval, engine

    def test_prepared_commitment_without_seal_is_recoverable_and_resumable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root,
                with_probe=False,
            )
            crashing = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="prepared",
            )
            with self.assertRaises(SimulatedCrash):
                crashing.release(
                    target="production",
                    approval_id=approval.approval_id,
                )
            commitment, missing_seal = self._leave_operation_commitment_only(
                run_directory,
                status="PREPARED",
            )

            inspection = validate_external_operation_evidence(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                phase=Phase.AWAITING_RELEASE_APPROVAL,
            )

            self.assertTrue(inspection.recoverable)
            self.assertEqual(
                [record.status.value for record in inspection.records], ["PREPARED"]
            )
            self.assertTrue(commitment.is_file())
            self.assertFalse(missing_seal.exists())
            self.assertFalse((root / "external-counter").exists())

            ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            ).release(
                target="production",
                approval_id=approval.approval_id,
            )

            self.assertTrue(missing_seal.is_file())
            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.SYNCING)

    def test_running_commitment_without_seal_is_current_and_resumes_safely(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root,
                with_probe=True,
            )
            crashing = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="running",
            )
            with self.assertRaises(SimulatedCrash):
                crashing.release(
                    target="production",
                    approval_id=approval.approval_id,
                )
            _, missing_seal = self._leave_operation_commitment_only(
                run_directory,
                status="RUNNING",
            )

            inspection = validate_external_operation_evidence(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                phase=Phase.RELEASING,
            )

            self.assertEqual(inspection.in_flight[-1].status.value, "RUNNING")
            self.assertFalse((root / "external-counter").exists())

            ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            ).release(
                target="production",
                approval_id=approval.approval_id,
            )

            self.assertTrue(missing_seal.is_file())
            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.SYNCING)

    def test_terminal_commitment_without_seal_is_not_replayed_on_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root,
                with_probe=False,
            )
            crashing = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="terminal-persisted",
            )
            with self.assertRaises(SimulatedCrash):
                crashing.release(
                    target="production",
                    approval_id=approval.approval_id,
                )
            _, missing_seal = self._leave_operation_commitment_only(
                run_directory,
                status="SUCCEEDED",
            )
            self.assertEqual((root / "external-counter").read_text(), "1")

            inspection = validate_external_operation_evidence(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                phase=Phase.RELEASING,
            )

            self.assertEqual(inspection.records[-1].status.value, "SUCCEEDED")
            self.assertEqual(inspection.in_flight, ())

            ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            ).release(
                target="production",
                approval_id=approval.approval_id,
            )

            self.assertTrue(missing_seal.is_file())
            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.SYNCING)

    def test_operation_seal_without_commitment_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject, approval = self._fixture(
                root,
                with_probe=False,
            )
            crashing = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="prepared",
            )
            with self.assertRaises(SimulatedCrash):
                crashing.release(
                    target="production",
                    approval_id=approval.approval_id,
                )
            active = json.loads(
                (run_directory / "release-cycles" / "active-release.json").read_text(
                    encoding="utf-8"
                )
            )
            commitments = tuple(
                (
                    run_directory
                    / "release-cycles"
                    / active["cycle_id"]
                    / "operations"
                    / "committed"
                ).glob("release-0001-attempt-1-prepared-*.json")
            )
            self.assertEqual(len(commitments), 1)
            commitments[0].unlink()

            with self.assertRaises(ReleaseRecoveryError):
                validate_external_operation_evidence(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    phase=Phase.AWAITING_RELEASE_APPROVAL,
                )

            self.assertFalse((root / "external-counter").exists())

    def test_global_validation_keeps_anchor_during_replace_read_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject, approval = self._fixture(
                root,
                with_probe=False,
            )
            crashing = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="prepared",
            )
            with self.assertRaises(SimulatedCrash):
                crashing.release(
                    target="production",
                    approval_id=approval.approval_id,
                )
            active = json.loads(
                (run_directory / "release-cycles" / "active-release.json").read_text(
                    encoding="utf-8"
                )
            )
            clean_snapshot = root / "clean-run-snapshot"
            shutil.copytree(run_directory, clean_snapshot)
            orphan = (
                run_directory
                / "release-cycles"
                / active["cycle_id"]
                / "adjudications"
                / "sealed"
                / "orphan.json"
            )
            write_private_json(orphan, {"schema_version": 1})
            detached = root / "detached-run"
            original = ReleaseEngine._all_adjudications
            swapped = False

            def replace_read_restore(engine: ReleaseEngine):
                nonlocal swapped
                run_directory.rename(detached)
                shutil.copytree(clean_snapshot, run_directory)
                try:
                    return original(engine)
                finally:
                    shutil.rmtree(run_directory)
                    detached.rename(run_directory)
                    swapped = True

            with (
                patch.object(
                    ReleaseEngine,
                    "_all_adjudications",
                    autospec=True,
                    side_effect=replace_read_restore,
                ),
                self.assertRaises(ReleaseRecoveryError),
            ):
                validate_external_operation_evidence(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    phase=Phase.AWAITING_RELEASE_APPROVAL,
                )

            self.assertTrue(swapped)
            self.assertTrue(orphan.is_file())

    def test_global_validation_reads_logs_from_anchored_run_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject, approval = self._fixture(
                root,
                with_probe=False,
            )
            ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            ).release(
                target="production",
                approval_id=approval.approval_id,
            )
            active = json.loads(
                (run_directory / "release-cycles" / "active-release.json").read_text(
                    encoding="utf-8"
                )
            )
            pointer = (
                run_directory
                / "release-cycles"
                / active["cycle_id"]
                / "operations"
                / "release-0001.json"
            )
            operation = json.loads(pointer.read_text(encoding="utf-8"))
            log_path = Path(operation["result"]["command"]["log_path"])
            clean_snapshot = root / "clean-run-snapshot"
            shutil.copytree(run_directory, clean_snapshot)
            log_path.write_bytes(log_path.read_bytes() + b"tampered")
            detached = root / "detached-run"
            original = ReleaseEngine._read_persisted_operation_log
            swapped = False

            def replace_read_restore(
                engine: ReleaseEngine,
                payload: dict[str, object],
                *,
                log_kind: str,
            ) -> bytes:
                nonlocal swapped
                run_directory.rename(detached)
                shutil.copytree(clean_snapshot, run_directory)
                try:
                    return original(engine, payload, log_kind=log_kind)
                finally:
                    shutil.rmtree(run_directory)
                    detached.rename(run_directory)
                    swapped = True

            with (
                patch.object(
                    ReleaseEngine,
                    "_read_persisted_operation_log",
                    autospec=True,
                    side_effect=replace_read_restore,
                ),
                self.assertRaises(ReleaseRecoveryError),
            ):
                validate_external_operation_evidence(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    phase=Phase.SYNCING,
                )

            self.assertTrue(swapped)
            self.assertTrue(log_path.read_bytes().endswith(b"tampered"))

    def test_inspect_unknown_operation_is_exact_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                _,
                run_directory,
                store,
                manifest,
                _,
                _,
                engine,
            ) = self._unknown_fixture(root)
            before = {
                str(path.relative_to(run_directory)): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }

            decision = engine.inspect_unknown_operation(target="production")

            after = {
                str(path.relative_to(run_directory)): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }
            unknown_pointer = next(
                (run_directory / "release-cycles").glob(
                    "*/operations/release-0001.json"
                )
            )
            unknown_payload = json.loads(unknown_pointer.read_text(encoding="utf-8"))
            marker = store.operation_start_markers()[-1].operation_start
            self.assertIsNotNone(marker)
            self.assertEqual(before, after)
            self.assertEqual(decision.mode, "release")
            self.assertEqual(decision.index, 1)
            self.assertEqual(decision.attempt, 1)
            self.assertEqual(decision.operation_name, manifest.release_steps[0].name)
            self.assertEqual(decision.target, "production")
            self.assertEqual(
                decision.argv,
                _resolved_argv(manifest.release_steps[0].argv, variables(engine.repo)),
            )
            self.assertEqual(decision.reason, "running-without-probe")
            self.assertEqual(
                decision.unknown_receipt_sha256,
                canonical_digest(unknown_payload),
            )
            self.assertEqual(
                decision.operation_start_marker_id,
                marker["marker_id"],
            )
            self.assertEqual(decision.blocked_revision, store.load().revision)
            self.assertRegex(decision.confirmation_token, r"^[0-9a-f]{64}$")

    def test_applied_outcome_is_sealed_restored_and_skips_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                repo,
                run_directory,
                store,
                _,
                _,
                _,
                engine,
            ) = self._unknown_fixture(root)
            decision = engine.inspect_unknown_operation(target="production")
            runner = CountingRunner()
            engine.runner = runner

            adjudication = engine.record_operation_outcome(
                target="production",
                unknown_receipt_sha256=decision.unknown_receipt_sha256,
                confirmation_token=decision.confirmation_token,
                expected_revision=decision.blocked_revision,
                actor="human-operator",
                outcome="applied",
            )
            repeated = engine.record_operation_outcome(
                target="production",
                unknown_receipt_sha256=decision.unknown_receipt_sha256,
                confirmation_token=decision.confirmation_token,
                expected_revision=decision.blocked_revision,
                actor="human-operator",
                outcome="applied",
            )

            self.assertEqual(adjudication, repeated)
            self.assertEqual(adjudication.outcome, "applied")
            self.assertEqual(adjudication.actor, "human-operator")
            self.assertEqual(store.load().phase, Phase.RELEASING)
            self.assertEqual(runner.calls, 0)
            self.assertEqual((root / "external-counter").read_text(), "1")
            seals = tuple(
                (run_directory / "release-cycles").glob(
                    "*/adjudications/sealed/release-0001-attempt-1-*.json"
                )
            )
            self.assertEqual(len(seals), 1)
            self.assertIn(
                f"-{decision.unknown_receipt_sha256}-{adjudication.adjudication_id}",
                seals[0].name,
            )
            adjudication_events = [
                event
                for event in store.events()
                if event.event_type == "operation.adjudicated"
            ]
            self.assertEqual(len(adjudication_events), 1)
            self.assertEqual(
                adjudication_events[0].operation_adjudication["adjudication_id"],
                adjudication.adjudication_id,
            )

            resumed = ReleaseEngine(
                repo=engine.repo,
                run_directory=run_directory,
                manifest=engine.manifest,
                current_subject=engine.current_subject,
                variables=variables(repo),
                runner=runner,
            )
            first_resume = resumed.resume_external_cycle(target="production")
            repeated_resume = resumed.resume_external_cycle(target="production")

            self.assertEqual(first_resume, repeated_resume)
            self.assertEqual(runner.calls, 0)
            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.SYNCING)
            inspection = validate_external_operation_evidence(
                repo=engine.repo,
                run_directory=run_directory,
                manifest=engine.manifest,
                current_subject=engine.current_subject,
                variables=variables(repo),
                phase=Phase.SYNCING,
            )
            self.assertEqual(len(inspection.records), 3)
            self.assertEqual(inspection.records[-1].status.value, "UNKNOWN")

    def test_not_applied_outcome_authorizes_exactly_one_next_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                _,
                run_directory,
                store,
                _,
                _,
                _,
                engine,
            ) = self._unknown_fixture(root)
            decision = engine.inspect_unknown_operation(target="production")

            adjudication = engine.record_operation_outcome(
                target="production",
                unknown_receipt_sha256=decision.unknown_receipt_sha256,
                confirmation_token=decision.confirmation_token,
                expected_revision=decision.blocked_revision,
                actor="human-operator",
                outcome="not_applied",
            )

            self.assertEqual(adjudication.outcome, "not_applied")
            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.RELEASING)

            records = engine.resume_external_cycle(target="production")
            repeated_records = engine.resume_external_cycle(target="production")

            self.assertEqual((root / "external-counter").read_text(), "2")
            self.assertEqual(records, repeated_records)
            self.assertEqual(store.load().phase, Phase.SYNCING)
            self.assertEqual(records[-1].attempt, 2)
            self.assertEqual(records[-1].status.value, "SUCCEEDED")
            prepared_attempt_two = next(
                (run_directory / "release-cycles").glob(
                    "*/operations/committed/release-0001-attempt-2-prepared-*.json"
                )
            )
            prepared_payload = json.loads(
                prepared_attempt_two.read_text(encoding="utf-8")
            )
            self.assertEqual(
                prepared_payload["previous_receipt_sha256"],
                decision.unknown_receipt_sha256,
            )
            inspection = validate_external_operation_evidence(
                repo=engine.repo,
                run_directory=run_directory,
                manifest=engine.manifest,
                current_subject=engine.current_subject,
                variables=variables(engine.repo),
                phase=Phase.SYNCING,
            )
            attempts = {
                record.attempt
                for record in inspection.records
                if record.mode == "release" and record.index == 1
            }
            self.assertEqual(attempts, {1, 2})

    def test_inspect_selects_only_the_latest_unresolved_unknown_in_release_cycle(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, _, initial_subject = prepare_release_gate(root)
            base_manifest = counter_manifest(
                root,
                candidate_oid=initial_subject.candidate_oid,
                with_probe=False,
                idempotency="manual_reconcile",
            )
            first = base_manifest.release_steps[0]
            second = replace(
                first,
                name="counter-release-2",
                argv=(*first.argv[:-1], str(root / "external-counter-2")),
            )
            manifest = replace(base_manifest, release_steps=(first, second))
            subject = subject_for(repo, manifest)
            seal_passing_verification(
                run_directory,
                manifest,
                subject,
                variables(repo),
            )
            approval_engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            approval = approval_engine.record_approval(
                gate="release",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
            )
            first_crash = CrashOnceIndexedReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_mode="release",
                crash_index=1,
                crash_stage="effect-returned",
            )
            with self.assertRaises(SimulatedCrash):
                first_crash.release(
                    target="production",
                    approval_id=approval.approval_id,
                )
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            with self.assertRaises(ReleaseRecoveryError):
                engine.reconcile_operation(target="production")
            first_decision = engine.inspect_unknown_operation(target="production")
            self.assertEqual(first_decision.index, 1)
            engine.record_operation_outcome(
                target="production",
                unknown_receipt_sha256=first_decision.unknown_receipt_sha256,
                confirmation_token=first_decision.confirmation_token,
                expected_revision=first_decision.blocked_revision,
                actor="human-operator",
                outcome="applied",
            )

            second_crash = CrashOnceIndexedReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_mode="release",
                crash_index=2,
                crash_stage="effect-returned",
            )
            with self.assertRaises(SimulatedCrash):
                second_crash.resume_external_cycle(target="production")
            resumed = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            with self.assertRaises(ReleaseRecoveryError):
                resumed.reconcile_operation(target="production")

            second_decision = resumed.inspect_unknown_operation(target="production")

            self.assertEqual(second_decision.mode, "release")
            self.assertEqual(second_decision.index, 2)
            self.assertNotEqual(
                second_decision.unknown_receipt_sha256,
                first_decision.unknown_receipt_sha256,
            )
            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual((root / "external-counter-2").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.BLOCKED)

    def test_adjudication_crash_boundaries_are_idempotent_without_effect(self) -> None:
        for stage, phase_after_crash in (
            ("adjudication-sealed", Phase.BLOCKED),
            ("adjudication-wal-recorded", Phase.RELEASING),
        ):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (
                    repo,
                    run_directory,
                    store,
                    manifest,
                    subject,
                    _,
                    engine,
                ) = self._unknown_fixture(root)
                decision = engine.inspect_unknown_operation(target="production")
                crashing = CrashOnceReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    crash_stage=stage,
                )

                with self.assertRaises(SimulatedCrash):
                    crashing.record_operation_outcome(
                        target="production",
                        unknown_receipt_sha256=decision.unknown_receipt_sha256,
                        confirmation_token=decision.confirmation_token,
                        expected_revision=decision.blocked_revision,
                        actor="human-operator",
                        outcome="applied",
                    )

                self.assertEqual(store.load().phase, phase_after_crash)
                self.assertEqual((root / "external-counter").read_text(), "1")
                resumed = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    runner=CountingRunner(),
                )
                adjudication = resumed.record_operation_outcome(
                    target="production",
                    unknown_receipt_sha256=decision.unknown_receipt_sha256,
                    confirmation_token=decision.confirmation_token,
                    expected_revision=decision.blocked_revision,
                    actor="human-operator",
                    outcome="applied",
                )

                self.assertRegex(adjudication.adjudication_id, r"^[0-9a-f]{64}$")
                self.assertEqual(store.load().phase, Phase.RELEASING)
                self.assertEqual((root / "external-counter").read_text(), "1")
                self.assertEqual(
                    len(
                        [
                            event
                            for event in store.events()
                            if event.event_type == "operation.adjudicated"
                        ]
                    ),
                    1,
                )

    def test_adjudication_rejects_stale_and_conflicting_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, run_directory, store, _, _, _, engine = self._unknown_fixture(root)
            decision = engine.inspect_unknown_operation(target="production")
            invalid_requests = (
                {"target": "staging"},
                {"unknown_receipt_sha256": "f" * 64},
                {"confirmation_token": "e" * 64},
                {"expected_revision": decision.blocked_revision + 1},
                {"actor": ""},
                {"outcome": "force"},
            )
            base = {
                "target": "production",
                "unknown_receipt_sha256": decision.unknown_receipt_sha256,
                "confirmation_token": decision.confirmation_token,
                "expected_revision": decision.blocked_revision,
                "actor": "human-operator",
                "outcome": "applied",
            }
            for changed in invalid_requests:
                with self.subTest(changed=changed), self.assertRaises(ReleaseError):
                    engine.record_operation_outcome(**{**base, **changed})
                self.assertEqual(store.load().phase, Phase.BLOCKED)
                self.assertEqual((root / "external-counter").read_text(), "1")

            engine.record_operation_outcome(**base)
            for changed in ({"actor": "another-human"}, {"outcome": "not_applied"}):
                with (
                    self.subTest(conflict=changed),
                    self.assertRaises(ReleaseRecoveryError),
                ):
                    engine.record_operation_outcome(**{**base, **changed})

            self.assertEqual(store.load().phase, Phase.RELEASING)
            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(
                len(
                    tuple(
                        (run_directory / "release-cycles").glob(
                            "*/adjudications/sealed/*.json"
                        )
                    )
                ),
                1,
            )

    def test_missing_or_unanchored_adjudication_fails_closed(self) -> None:
        for case in ("unanchored", "missing", "tampered"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (
                    repo,
                    run_directory,
                    store,
                    manifest,
                    subject,
                    _,
                    engine,
                ) = self._unknown_fixture(root)
                decision = engine.inspect_unknown_operation(target="production")
                if case == "unanchored":
                    crashing = CrashOnceReleaseEngine(
                        repo=repo,
                        run_directory=run_directory,
                        manifest=manifest,
                        current_subject=subject,
                        variables=variables(repo),
                        crash_stage="adjudication-sealed",
                    )
                    with self.assertRaises(SimulatedCrash):
                        crashing.record_operation_outcome(
                            target="production",
                            unknown_receipt_sha256=decision.unknown_receipt_sha256,
                            confirmation_token=decision.confirmation_token,
                            expected_revision=decision.blocked_revision,
                            actor="human-operator",
                            outcome="applied",
                        )
                    phase = Phase.RELEASING
                else:
                    engine.record_operation_outcome(
                        target="production",
                        unknown_receipt_sha256=decision.unknown_receipt_sha256,
                        confirmation_token=decision.confirmation_token,
                        expected_revision=decision.blocked_revision,
                        actor="human-operator",
                        outcome="applied",
                    )
                    seal = next(
                        (run_directory / "release-cycles").glob(
                            "*/adjudications/sealed/*.json"
                        )
                    )
                    if case == "missing":
                        seal.unlink()
                    else:
                        payload = json.loads(seal.read_text(encoding="utf-8"))
                        payload["actor"] = "tampered-actor"
                        write_private_json(seal, payload)
                    phase = Phase.RELEASING

                with self.assertRaises(ReleaseRecoveryError):
                    validate_external_operation_evidence(
                        repo=repo,
                        run_directory=run_directory,
                        manifest=manifest,
                        current_subject=subject,
                        variables=variables(repo),
                        phase=phase,
                    )

                self.assertEqual((root / "external-counter").read_text(), "1")
                self.assertIn(store.load().phase, {Phase.BLOCKED, Phase.RELEASING})

    def test_resume_rejects_unknown_missing_approval_and_approval_substitution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, store, _, _, _, engine = self._unknown_fixture(root)
            decision = engine.inspect_unknown_operation(target="production")

            with self.assertRaises(ReleaseRecoveryError):
                engine.resume_external_cycle(target="production")

            restored = store.restore_adjudicated_operation(
                mode="release",
                adjudication_id="f" * 64,
                expected_revision=decision.blocked_revision,
            )
            self.assertEqual(restored.phase, Phase.RELEASING)
            with self.assertRaises(ReleaseRecoveryError):
                engine.resume_external_cycle(target="production")
            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.BLOCKED)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                _,
                run_directory,
                store,
                _,
                _,
                _,
                engine,
            ) = self._unknown_fixture(root)
            decision = engine.inspect_unknown_operation(target="production")
            engine.record_operation_outcome(
                target="production",
                unknown_receipt_sha256=decision.unknown_receipt_sha256,
                confirmation_token=decision.confirmation_token,
                expected_revision=decision.blocked_revision,
                actor="human-operator",
                outcome="applied",
            )
            consumed = next((run_directory / "approvals" / "consumed").glob("*.json"))
            consumed.unlink()

            with self.assertRaises(ReleaseError):
                engine.resume_external_cycle(target="production")
            with self.assertRaises(TypeError):
                engine.resume_external_cycle(
                    target="production",
                    approval_id="a" * 64,
                )

            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.RELEASING)

    def test_orphan_adjudication_seal_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                repo,
                run_directory,
                _,
                manifest,
                subject,
                _,
                engine,
            ) = self._unknown_fixture(root)
            decision = engine.inspect_unknown_operation(target="production")
            engine.record_operation_outcome(
                target="production",
                unknown_receipt_sha256=decision.unknown_receipt_sha256,
                confirmation_token=decision.confirmation_token,
                expected_revision=decision.blocked_revision,
                actor="human-operator",
                outcome="applied",
            )
            seal = next(
                (run_directory / "release-cycles").glob("*/adjudications/sealed/*.json")
            )
            orphan = json.loads(seal.read_text(encoding="utf-8"))
            orphan["unknown_receipt_sha256"] = "f" * 64
            stable = {
                key: value for key, value in orphan.items() if key != "adjudication_id"
            }
            orphan["adjudication_id"] = canonical_digest(stable)
            orphan_path = seal.parent / (
                f"release-0001-attempt-1-{'f' * 64}-{orphan['adjudication_id']}.json"
            )
            write_private_json(orphan_path, orphan)

            with self.assertRaises(ReleaseRecoveryError):
                validate_external_operation_evidence(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    phase=Phase.RELEASING,
                )

    def test_consumed_active_cycle_without_first_receipt_is_reconcilable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root, with_probe=False
            )
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            cycle = engine._activate_cycle(
                gate="release",
                approval_id=approval.approval_id,
                target="production",
            )
            _, _, _, _, first_key = engine._operation_identity(
                cycle_id=str(cycle["cycle_id"]),
                mode="release",
                index=1,
                spec=manifest.release_steps[0],
                target="production",
                approval_id=approval.approval_id,
            )
            engine.consume_approval(
                approval.approval_id,
                consumer=engine._approval_consumer(
                    mode="release",
                    idempotency_key=first_key,
                ),
            )
            state = store.load()
            store.transition(Phase.RELEASING, expected_revision=state.revision)

            inspection = validate_external_operation_evidence(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                phase=Phase.RELEASING,
            )

            self.assertTrue(inspection.active_cycle)
            self.assertEqual(inspection.records, ())
            self.assertEqual(inspection.in_flight, ())

            engine.release(
                target="production",
                approval_id=approval.approval_id,
            )
            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.SYNCING)

    def test_unknown_active_pointer_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject, _ = self._fixture(
                root, with_probe=False
            )
            unknown = run_directory / "release-cycles" / "active-surprise.json"
            write_private_json(unknown, {"schema_version": 1})

            with self.assertRaises(ReleaseRecoveryError):
                validate_external_operation_evidence(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    phase=Phase.AWAITING_RELEASE_APPROVAL,
                )

    def test_corrupt_known_active_release_pointer_fails_closed_at_human_gate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject, _ = self._fixture(
                root,
                with_probe=False,
            )
            write_private_json(
                run_directory / "release-cycles" / "active-release.json",
                {},
            )

            with self.assertRaises(ReleaseRecoveryError):
                validate_external_operation_evidence(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    phase=Phase.AWAITING_RELEASE_APPROVAL,
                )

    def test_valid_unconsumed_active_release_is_recoverable_at_human_gate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root,
                with_probe=False,
            )
            engine = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="prepared",
            )
            with self.assertRaises(SimulatedCrash):
                engine.release(
                    target="production",
                    approval_id=approval.approval_id,
                )

            self.assertEqual(store.load().phase, Phase.AWAITING_RELEASE_APPROVAL)
            self.assertFalse((root / "external-counter").exists())
            inspection = validate_external_operation_evidence(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                phase=Phase.AWAITING_RELEASE_APPROVAL,
            )
            self.assertTrue(inspection.active_cycle)
            self.assertTrue(inspection.recoverable)

            engine.release(
                target="production",
                approval_id=approval.approval_id,
            )
            self.assertEqual(store.load().phase, Phase.SYNCING)
            self.assertEqual((root / "external-counter").read_text(), "1")

    def test_expired_pure_prepared_cycle_is_audited_and_safely_superseded(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, _ = self._fixture(
                root,
                with_probe=False,
            )
            with patch.object(release_module, "datetime", ApprovalWindowDateTime):
                expired = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                ).record_approval(
                    gate="release",
                    target="production",
                    approver_actor="first-human",
                    expires_at="2026-01-01T00:01:00Z",
                )
                crashing = CrashOnceReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    crash_stage="prepared",
                )
                with self.assertRaises(SimulatedCrash):
                    crashing.release(
                        target="production",
                        approval_id=expired.approval_id,
                    )
            active_path = run_directory / "release-cycles" / "active-release.json"
            expired_cycle = json.loads(active_path.read_text(encoding="utf-8"))
            expired_cycle_id = str(expired_cycle["cycle_id"])

            inspection = validate_external_operation_evidence(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                phase=Phase.AWAITING_RELEASE_APPROVAL,
            )
            self.assertTrue(inspection.recoverable)
            replacement = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            ).record_approval(
                gate="release",
                target="production",
                approver_actor="replacement-human",
                expires_at="2999-01-01T00:00:00Z",
            )

            ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            ).release(
                target="production",
                approval_id=replacement.approval_id,
            )

            supersession_path = (
                run_directory
                / "release-cycles"
                / expired_cycle_id
                / "supersessions"
                / f"{replacement.approval_id}.json"
            )
            supersession = json.loads(supersession_path.read_text(encoding="utf-8"))
            active = json.loads(active_path.read_text(encoding="utf-8"))
            expired_pointer = json.loads(
                (run_directory / "approvals" / f"{expired.approval_id}.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(supersession["old_cycle_id"], expired_cycle_id)
            self.assertEqual(supersession["old_approval_id"], expired.approval_id)
            self.assertEqual(
                supersession["replacement_approval_id"], replacement.approval_id
            )
            self.assertEqual(active["approval_id"], replacement.approval_id)
            self.assertIsNone(expired_pointer["consumed_at"])
            self.assertEqual(store.load().phase, Phase.SYNCING)
            self.assertEqual((root / "external-counter").read_text(), "1")
            old_records = [
                record
                for record in inspection.records
                if record.cycle_id == expired_cycle_id
            ]
            self.assertEqual(len(old_records), 1)
            self.assertEqual(old_records[0].status.value, "PREPARED")

    def test_supersession_rejects_consumed_cycle_with_start_wal_and_running_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject, _ = self._fixture(
                root,
                with_probe=False,
            )
            with patch.object(release_module, "datetime", ApprovalWindowDateTime):
                engine = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                )
                expired = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="first-human",
                    expires_at="2026-01-01T00:01:00Z",
                )
                replacement = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="replacement-human",
                    expires_at="2999-01-01T00:00:00Z",
                )
                crashing = CrashOnceReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    crash_stage="running",
                )
                with self.assertRaises(SimulatedCrash):
                    crashing.release(
                        target="production",
                        approval_id=expired.approval_id,
                    )
            active_path = run_directory / "release-cycles" / "active-release.json"
            active_before = active_path.read_bytes()
            active = json.loads(active_before)

            with self.assertRaises(ReleaseRecoveryError):
                ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    runner=CountingRunner(),
                )._supersede_pure_prepared_cycle(
                    gate="release",
                    active=active,
                    replacement=replacement,
                )

            self.assertEqual(active_path.read_bytes(), active_before)
            self.assertFalse((root / "external-counter").exists())

    def test_supersession_rejects_unknown_cycle_entry_without_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject, _ = self._fixture(
                root,
                with_probe=False,
            )
            with patch.object(release_module, "datetime", ApprovalWindowDateTime):
                engine = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                )
                expired = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="first-human",
                    expires_at="2026-01-01T00:01:00Z",
                )
                crashing = CrashOnceReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    crash_stage="prepared",
                )
                with self.assertRaises(SimulatedCrash):
                    crashing.release(
                        target="production",
                        approval_id=expired.approval_id,
                    )
            active_path = run_directory / "release-cycles" / "active-release.json"
            active_before = active_path.read_bytes()
            cycle_id = str(json.loads(active_before)["cycle_id"])
            write_private_json(
                run_directory / "release-cycles" / cycle_id / "foreign.json",
                {"schema_version": 1},
            )
            replacement = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            ).record_approval(
                gate="release",
                target="production",
                approver_actor="replacement-human",
                expires_at="2999-01-01T00:00:00Z",
            )

            with self.assertRaises(ReleaseRecoveryError):
                ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    runner=CountingRunner(),
                ).release(
                    target="production",
                    approval_id=replacement.approval_id,
                )

            self.assertEqual(active_path.read_bytes(), active_before)
            self.assertFalse((root / "external-counter").exists())

    def test_expired_crashed_supersession_can_be_superseded_again(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, _ = self._fixture(
                root,
                with_probe=False,
            )
            with patch.object(release_module, "datetime", ApprovalWindowDateTime):
                engine = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                )
                expired = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="first-human",
                    expires_at="2026-01-01T00:01:00Z",
                )
                crashing = CrashOnceReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    crash_stage="prepared",
                )
                with self.assertRaises(SimulatedCrash):
                    crashing.release(
                        target="production",
                        approval_id=expired.approval_id,
                    )
            with patch.object(release_module, "datetime", ReplacementWindowDateTime):
                engine = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                )
                first_replacement = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="replacement-one",
                    expires_at="2026-01-01T00:03:00Z",
                )
                with self.assertRaises(SimulatedCrash):
                    CrashAfterSupersessionEngine(
                        repo=repo,
                        run_directory=run_directory,
                        manifest=manifest,
                        current_subject=subject,
                        variables=variables(repo),
                    ).release(
                        target="production",
                        approval_id=first_replacement.approval_id,
                    )
            active_path = run_directory / "release-cycles" / "active-release.json"
            old_cycle_id = str(json.loads(active_path.read_bytes())["cycle_id"])
            second_replacement = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            ).record_approval(
                gate="release",
                target="production",
                approver_actor="replacement-two",
                expires_at="2999-01-01T00:00:00Z",
            )

            ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            ).release(
                target="production",
                approval_id=second_replacement.approval_id,
            )

            receipts = tuple(
                (
                    run_directory / "release-cycles" / old_cycle_id / "supersessions"
                ).glob("*.json")
            )
            self.assertEqual(len(receipts), 2)
            self.assertEqual(store.load().phase, Phase.SYNCING)
            self.assertEqual((root / "external-counter").read_text(), "1")

    def test_active_release_context_is_read_only_and_bound_to_the_run_inode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, _, manifest, subject, approval = self._fixture(
                root,
                with_probe=False,
            )
            crashing = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="running",
            )
            with self.assertRaises(SimulatedCrash):
                crashing.release(
                    target="production",
                    approval_id=approval.approval_id,
                )
            observer = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                runner=CountingRunner(),
            )
            before = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }

            context = observer.inspect_active_external_context(phase=Phase.RELEASING)

            after = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }
            self.assertEqual(context.approval_id, approval.approval_id)
            self.assertEqual(context.target, "production")
            self.assertEqual(context.mode, "release")
            self.assertEqual(after, before)
            self.assertFalse((root / "external-counter").exists())

            detached = root / "detached-run"
            original_read = observer._read_approval_read_only

            def replace_root(approval_id: str) -> ApprovalRecord:
                run_directory.rename(detached)
                shutil.copytree(detached, run_directory)
                return original_read(approval_id)

            with (
                patch.object(
                    observer,
                    "_read_approval_read_only",
                    side_effect=replace_root,
                ),
                self.assertRaises(ReleaseRecoveryError),
            ):
                observer.inspect_active_external_context(phase=Phase.RELEASING)

    def test_second_release_cycle_uses_a_fresh_receipt_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, first_approval = (
                self._fixture(root, with_probe=False)
            )
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )

            engine.release(target="production", approval_id=first_approval.approval_id)
            self.assertEqual((root / "external-counter").read_text(), "1")
            state = store.load()
            for phase in (
                Phase.DEVELOPING,
                Phase.CODE_REVIEW,
                Phase.VERIFYING,
                Phase.AWAITING_RELEASE_APPROVAL,
            ):
                state = store.transition(phase, expected_revision=state.revision)
            seal_passing_verification(
                run_directory,
                manifest,
                subject,
                variables(repo),
                retain_existing=True,
            )
            second_approval = engine.record_approval(
                gate="release",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
            )

            engine.release(target="production", approval_id=second_approval.approval_id)

            self.assertEqual((root / "external-counter").read_text(), "2")
            self.assertEqual(store.load().phase, Phase.SYNCING)
            self.assertEqual(
                len(list((run_directory / "verifications").glob("*.json"))), 2
            )
            cycle_directories = sorted(
                path
                for path in (run_directory / "release-cycles").iterdir()
                if path.is_dir()
            )
            self.assertEqual(len(cycle_directories), 2)
            self.assertTrue(
                all(
                    (path / "operations" / "sealed").is_dir()
                    for path in cycle_directories
                )
            )
            active = json.loads(
                (run_directory / "release-cycles" / "active-release.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(active["approval_id"], second_approval.approval_id)

    def test_historical_adjudication_uses_its_sealed_cycle_after_next_release_cycle(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                repo,
                run_directory,
                store,
                manifest,
                subject,
                _,
                engine,
            ) = self._unknown_fixture(root)
            decision = engine.inspect_unknown_operation(target="production")
            adjudication = engine.record_operation_outcome(
                target="production",
                unknown_receipt_sha256=decision.unknown_receipt_sha256,
                confirmation_token=decision.confirmation_token,
                expected_revision=decision.blocked_revision,
                actor="human-operator",
                outcome="applied",
            )
            engine.resume_external_cycle(target="production")
            self.assertEqual(store.load().phase, Phase.SYNCING)

            state = store.load()
            for phase in (
                Phase.DEVELOPING,
                Phase.CODE_REVIEW,
                Phase.VERIFYING,
                Phase.AWAITING_RELEASE_APPROVAL,
            ):
                state = store.transition(phase, expected_revision=state.revision)
            seal_passing_verification(
                run_directory,
                manifest,
                subject,
                variables(repo),
                retain_existing=True,
            )
            second_approval = engine.record_approval(
                gate="release",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
            )
            engine.release(
                target="production",
                approval_id=second_approval.approval_id,
            )

            active = json.loads(
                (run_directory / "release-cycles" / "active-release.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertNotEqual(active["cycle_id"], adjudication.cycle_id)
            inspection = validate_external_operation_evidence(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                phase=Phase.SYNCING,
            )
            self.assertEqual(len(inspection.records), 6)
            self.assertEqual((root / "external-counter").read_text(), "2")

    def test_effect_return_crash_is_probed_and_never_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root, with_probe=True
            )
            crashing = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                runner=CommandRunner(),
                crash_stage="effect-returned",
            )

            with self.assertRaises(SimulatedCrash):
                crashing.release(target="production", approval_id=approval.approval_id)
            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.RELEASING)

            resumed = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            resumed.release(target="production", approval_id=approval.approval_id)

            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.SYNCING)
            statuses = {
                path.name.split("-")[4]
                for path in (run_directory / "release-cycles").glob(
                    "*/operations/sealed/release-0001-attempt-1-*.json"
                )
            }
            self.assertEqual(statuses, {"prepared", "running", "succeeded"})

    def test_deleted_terminal_tail_is_recovered_without_replaying_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root, with_probe=False
            )
            engine = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="terminal-persisted",
            )
            with self.assertRaises(SimulatedCrash):
                engine.release(target="production", approval_id=approval.approval_id)
            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.RELEASING)

            active = json.loads(
                (run_directory / "release-cycles" / "active-release.json").read_text()
            )
            operations = (
                run_directory / "release-cycles" / active["cycle_id"] / "operations"
            )
            (operations / "release-0001.json").unlink()
            for path in (operations / "sealed").glob("release-0001-attempt-1-*.json"):
                if "-running-" in path.name or "-succeeded-" in path.name:
                    path.unlink()

            engine.release(target="production", approval_id=approval.approval_id)

            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.SYNCING)
            restored = {
                path.name.split("-")[4]
                for path in (operations / "sealed").glob(
                    "release-0001-attempt-1-*.json"
                )
            }
            self.assertEqual(restored, {"prepared", "running", "succeeded"})

    def test_operation_start_wal_blocks_replay_when_both_stage_tails_are_deleted(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root, with_probe=False
            )
            engine = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="terminal-persisted",
            )
            with self.assertRaises(SimulatedCrash):
                engine.release(target="production", approval_id=approval.approval_id)
            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.RELEASING)

            active = json.loads(
                (run_directory / "release-cycles" / "active-release.json").read_text()
            )
            operations = (
                run_directory / "release-cycles" / active["cycle_id"] / "operations"
            )
            (operations / "release-0001.json").unlink()
            for directory_name in ("sealed", "committed"):
                for path in (operations / directory_name).glob(
                    "release-0001-attempt-1-*.json"
                ):
                    if "-running-" in path.name or "-succeeded-" in path.name:
                        path.unlink()

            resumed = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            with self.assertRaises(ReleaseRecoveryError):
                resumed.release(target="production", approval_id=approval.approval_id)

            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.BLOCKED)

    def test_consumed_approval_pointer_rollback_cannot_reuse_one_shot_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root, with_probe=False
            )
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            approval_path = run_directory / "approvals" / f"{approval.approval_id}.json"
            unconsumed_pointer = approval_path.read_bytes()
            engine.release(target="production", approval_id=approval.approval_id)
            self.assertEqual((root / "external-counter").read_text(), "1")

            state = store.load()
            for phase in (
                Phase.DEVELOPING,
                Phase.CODE_REVIEW,
                Phase.VERIFYING,
                Phase.AWAITING_RELEASE_APPROVAL,
            ):
                state = store.transition(phase, expected_revision=state.revision)
            seal_passing_verification(
                run_directory,
                manifest,
                subject,
                variables(repo),
                retain_existing=True,
            )
            approval_path.write_bytes(unconsumed_pointer)
            os.chmod(approval_path, 0o600)

            with self.assertRaises(ReleaseError):
                engine.release(target="production", approval_id=approval.approval_id)

            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.AWAITING_RELEASE_APPROVAL)
            restored = json.loads(approval_path.read_text())
            self.assertIsNotNone(restored["consumed_at"])
            self.assertIsNotNone(restored["consumed_by"])

    def test_unconsumed_approval_is_bound_to_its_release_gate_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root, with_probe=False
            )
            state = store.load()
            for phase in (
                Phase.RELEASING,
                Phase.POST_RELEASE_VERIFYING,
                Phase.SYNCING,
                Phase.DEVELOPING,
                Phase.CODE_REVIEW,
                Phase.VERIFYING,
                Phase.AWAITING_RELEASE_APPROVAL,
            ):
                state = store.transition(phase, expected_revision=state.revision)
            seal_passing_verification(
                run_directory,
                manifest,
                subject,
                variables(repo),
                retain_existing=True,
            )
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )

            with self.assertRaises(ReleaseError):
                engine.release(target="production", approval_id=approval.approval_id)

            self.assertFalse((root / "external-counter").exists())
            self.assertEqual(store.load().phase, Phase.AWAITING_RELEASE_APPROVAL)

    def test_consumed_approval_cycle_cannot_be_overwritten_before_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, first_approval = (
                self._fixture(root, with_probe=False)
            )
            crashing = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="approval-consumed",
            )
            with (
                patch(
                    "ship_flow.release._utc_now", return_value="2000-01-01T00:00:00Z"
                ),
                self.assertRaises(SimulatedCrash),
            ):
                crashing.release(
                    target="production", approval_id=first_approval.approval_id
                )
            self.assertEqual(store.load().phase, Phase.AWAITING_RELEASE_APPROVAL)
            self.assertFalse((root / "external-counter").exists())
            original_active = json.loads(
                (run_directory / "release-cycles" / "active-release.json").read_text()
            )

            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            second_approval = engine.record_approval(
                gate="release",
                target="production",
                approver_actor="other-human",
                expires_at="2999-01-01T00:00:00Z",
            )
            with self.assertRaises(ReleaseRecoveryError):
                engine.release(
                    target="production", approval_id=second_approval.approval_id
                )
            self.assertEqual(
                json.loads(
                    (
                        run_directory / "release-cycles" / "active-release.json"
                    ).read_text()
                ),
                original_active,
            )
            self.assertFalse((root / "external-counter").exists())

            engine.release(target="production", approval_id=first_approval.approval_id)
            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.SYNCING)

    def test_active_cycle_missing_first_receipt_blocks_without_replay(self) -> None:
        for mode in ("release", "rollback"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                previous_release = "release-v1"
                if mode == "release":
                    repo, run_directory, store, manifest, subject, approval = (
                        self._fixture(root, with_probe=False)
                    )
                    crashing = CrashOnceReleaseEngine(
                        repo=repo,
                        run_directory=run_directory,
                        manifest=manifest,
                        current_subject=subject,
                        variables=variables(repo),
                        crash_stage="effect-returned",
                    )
                    with self.assertRaises(SimulatedCrash):
                        crashing.release(
                            target="production", approval_id=approval.approval_id
                        )
                    counter = root / "external-counter"

                    def resume(engine: ReleaseEngine) -> None:
                        engine.release(
                            target="production", approval_id=approval.approval_id
                        )

                    expected_phase = Phase.RELEASING
                else:
                    repo, run_directory, store, _, _ = prepare_release_gate(root)
                    manifest = rollback_manifest(
                        root,
                        data_impact="none",
                        rollback_health_output=previous_release,
                    )
                    subject = subject_for(repo, manifest)
                    seal_passing_verification(
                        run_directory, manifest, subject, variables(repo)
                    )
                    approval_engine = ReleaseEngine(
                        repo=repo,
                        run_directory=run_directory,
                        manifest=manifest,
                        current_subject=subject,
                        variables=variables(repo),
                    )
                    release_approval = approval_engine.record_approval(
                        gate="release",
                        target="production",
                        approver_actor="human",
                        expires_at="2999-01-01T00:00:00Z",
                    )
                    approval = approval_engine.record_approval(
                        gate="rollback",
                        target="production",
                        approver_actor="human",
                        expires_at="2999-01-01T00:00:00Z",
                        failed_release_id=release_approval.approval_id,
                        previous_release=previous_release,
                    )
                    crashing = CrashOnceModeReleaseEngine(
                        repo=repo,
                        run_directory=run_directory,
                        manifest=manifest,
                        current_subject=subject,
                        variables=variables(repo),
                        crash_mode="rollback",
                        crash_stage="effect-returned",
                    )
                    with self.assertRaises(SimulatedCrash):
                        crashing.release(
                            target="production",
                            approval_id=release_approval.approval_id,
                            rollback_approval_id=approval.approval_id,
                            previous_release=previous_release,
                        )
                    counter = root / "rollback-counter"

                    def resume(engine: ReleaseEngine) -> None:
                        engine.rollback(
                            target="production",
                            approval_id=approval.approval_id,
                            failed_release_id=release_approval.approval_id,
                            previous_release=previous_release,
                        )

                    expected_phase = Phase.ROLLING_BACK

                self.assertEqual(counter.read_text(), "1")
                self.assertEqual(store.load().phase, expected_phase)
                active_path = run_directory / "release-cycles" / f"active-{mode}.json"
                active = json.loads(active_path.read_text(encoding="utf-8"))
                cycle_directory = run_directory / "release-cycles" / active["cycle_id"]
                self.assertTrue((cycle_directory / "header.json").is_file())
                operations = cycle_directory / "operations"
                pointer = operations / f"{mode}-0001.json"
                if pointer.exists():
                    pointer.unlink()
                sealed = operations / "sealed"
                for receipt in sealed.glob(f"{mode}-0001-attempt-*.json"):
                    receipt.unlink()
                self.assertEqual(list(sealed.glob(f"{mode}-0001-*.json")), [])

                resumed = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                )
                with self.assertRaises(ReleaseRecoveryError):
                    resume(resumed)

                self.assertEqual(counter.read_text(), "1")
                self.assertEqual(store.load().phase, Phase.BLOCKED)
                self.assertTrue((cycle_directory / "header.json").is_file())

    def test_running_before_effect_uses_not_applied_probe_then_safe_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root, with_probe=True
            )
            crashing = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="running",
            )
            with self.assertRaises(SimulatedCrash):
                crashing.release(target="production", approval_id=approval.approval_id)
            self.assertFalse((root / "external-counter").exists())

            resumed = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            resumed.release(target="production", approval_id=approval.approval_id)

            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.SYNCING)

    def test_probe_idempotency_not_applied_authorizes_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root,
                with_probe=True,
                idempotency="probe",
            )
            crashing = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="running",
            )
            with self.assertRaises(SimulatedCrash):
                crashing.release(target="production", approval_id=approval.approval_id)

            resumed = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            resumed.release(target="production", approval_id=approval.approval_id)

            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.SYNCING)

    def test_probe_authorizes_a_gap_free_retry_after_crash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root, with_probe=True
            )
            before_effect = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="running",
            )
            with self.assertRaises(SimulatedCrash):
                before_effect.release(
                    target="production", approval_id=approval.approval_id
                )

            after_retry_authorization = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="retry-authorized",
            )
            with self.assertRaises(SimulatedCrash):
                after_retry_authorization.release(
                    target="production", approval_id=approval.approval_id
                )

            self.assertFalse((root / "external-counter").exists())
            active = json.loads(
                (run_directory / "release-cycles" / "active-release.json").read_text(
                    encoding="utf-8"
                )
            )
            operation_pointer = (
                run_directory
                / "release-cycles"
                / active["cycle_id"]
                / "operations"
                / "release-0001.json"
            )
            failed = json.loads(operation_pointer.read_text(encoding="utf-8"))
            self.assertEqual(failed["attempt"], 1)
            self.assertEqual(failed["status"], "FAILED")
            self.assertIs(failed["result"]["retry_authorized"], True)
            self.assertEqual(failed["result"]["next_attempt"], 2)
            self.assertEqual(
                failed["result"]["probe_digest"],
                canonical_digest(failed["result"]["probe"]),
            )

            resumed = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            resumed.release(target="production", approval_id=approval.approval_id)

            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.SYNCING)
            attempt_two_statuses = {
                path.name.split("-")[4]
                for path in operation_pointer.parent.glob(
                    "sealed/release-0001-attempt-2-*.json"
                )
            }
            self.assertEqual(attempt_two_statuses, {"prepared", "running", "succeeded"})

    def test_fabricated_terminal_receipt_is_rejected_and_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root, with_probe=False
            )
            crashing = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="running",
            )
            with self.assertRaises(SimulatedCrash):
                crashing.release(target="production", approval_id=approval.approval_id)
            self.assertFalse((root / "external-counter").exists())

            active = json.loads(
                (run_directory / "release-cycles" / "active-release.json").read_text(
                    encoding="utf-8"
                )
            )
            operation_directory = (
                run_directory / "release-cycles" / active["cycle_id"] / "operations"
            )
            pointer = operation_directory / "release-0001.json"
            running = json.loads(pointer.read_text(encoding="utf-8"))
            fake_log = run_directory / "logs" / "release-operations" / "fake.log"
            fake_log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(fake_log.parent, 0o700)
            fake_log.write_bytes(b"")
            os.chmod(fake_log, 0o600)
            fabricated = dict(running)
            fabricated.update(
                {
                    "status": "SUCCEEDED",
                    "finished_at": "2026-07-15T00:00:00Z",
                    "result": {
                        "command": {
                            "exit_code": 0,
                            "timed_out": False,
                            "truncated": False,
                            "log_sha256": hashlib.sha256(b"").hexdigest(),
                            "log_size": 0,
                            "log_path": str(fake_log),
                        }
                    },
                }
            )
            fabricated_digest = canonical_digest(fabricated)
            write_private_json(
                operation_directory
                / "sealed"
                / (f"release-0001-attempt-1-succeeded-{fabricated_digest}.json"),
                fabricated,
            )
            write_private_json(pointer, fabricated)

            resumed = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            with self.assertRaises(ReleaseRecoveryError):
                resumed.release(target="production", approval_id=approval.approval_id)

            self.assertFalse((root / "external-counter").exists())
            self.assertEqual(store.load().phase, Phase.BLOCKED)

    def test_succeeded_log_loss_or_tampering_blocks_recovery(self) -> None:
        for case in ("deleted", "tampered"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo, run_directory, store, manifest, subject, approval = self._fixture(
                    root, with_probe=False
                )
                engine = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                )
                engine.release(target="production", approval_id=approval.approval_id)
                self.assertEqual((root / "external-counter").read_text(), "1")
                active = json.loads(
                    (
                        run_directory / "release-cycles" / "active-release.json"
                    ).read_text(encoding="utf-8")
                )
                pointer = (
                    run_directory
                    / "release-cycles"
                    / active["cycle_id"]
                    / "operations"
                    / "release-0001.json"
                )
                succeeded = json.loads(pointer.read_text(encoding="utf-8"))
                log_path = Path(succeeded["result"]["command"]["log_path"])
                if case == "deleted":
                    log_path.unlink()
                else:
                    log_path.write_bytes(log_path.read_bytes() + b"tampered")

                with self.assertRaises(ReleaseRecoveryError):
                    engine.release(
                        target="production", approval_id=approval.approval_id
                    )

                self.assertEqual((root / "external-counter").read_text(), "1")
                self.assertEqual(store.load().phase, Phase.BLOCKED)

    def test_running_without_probe_becomes_unknown_and_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject, approval = self._fixture(
                root, with_probe=False
            )
            crashing = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="effect-returned",
            )
            with self.assertRaises(SimulatedCrash):
                crashing.release(target="production", approval_id=approval.approval_id)
            self.assertEqual((root / "external-counter").read_text(), "1")

            resumed = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            with self.assertRaises(ReleaseRecoveryError):
                resumed.reconcile_operation(target="production")

            self.assertEqual((root / "external-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.BLOCKED)


class ReleaseHealthAndLockTests(unittest.TestCase):
    def test_structured_protocol_and_git_ls_remote_adapter_are_exact(self) -> None:
        candidate_oid = "a" * 40
        command_result: dict[str, object] = {
            "exit_code": 0,
            "timed_out": False,
            "truncated": False,
        }
        probe_payload = {
            "schema_version": 1,
            "kind": "probe",
            "outcome": "applied",
            "target": "production",
            "version": candidate_oid,
        }
        self.assertEqual(
            _probe_protocol_outcome(
                canonical_bytes(probe_payload) + b"\n",
                result=command_result,
                probe_argv=("tool", "probe"),
                target="production",
                expected_version=candidate_oid,
            ),
            "applied",
        )
        self.assertIsNone(
            _probe_protocol_outcome(
                canonical_bytes({**probe_payload, "extra": True}) + b"\n",
                result=command_result,
                probe_argv=("tool", "probe"),
                target="production",
                expected_version=candidate_oid,
            )
        )
        health_payload = {
            "schema_version": 1,
            "kind": "health",
            "status": "healthy",
            "target": "production",
            "version": candidate_oid,
        }
        self.assertTrue(
            _health_protocol_passes(
                canonical_bytes(health_payload) + b"\n",
                result=command_result,
                target="production",
                expected_version=candidate_oid,
            )
        )
        self.assertFalse(
            _health_protocol_passes(
                canonical_bytes(health_payload) + b" trailing text",
                result=command_result,
                target="production",
                expected_version=candidate_oid,
            )
        )

        ref = "refs/heads/main"
        ls_remote_argv = ("git", "ls-remote", "--exit-code", "origin", ref)
        exact_line = f"{candidate_oid}\t{ref}\n".encode()
        self.assertEqual(
            _probe_protocol_outcome(
                exact_line,
                result=command_result,
                probe_argv=ls_remote_argv,
                target="production",
                expected_version=candidate_oid,
            ),
            "applied",
        )
        self.assertIsNone(
            _probe_protocol_outcome(
                exact_line + exact_line,
                result=command_result,
                probe_argv=ls_remote_argv,
                target="production",
                expected_version=candidate_oid,
            )
        )
        self.assertEqual(
            _probe_protocol_outcome(
                b"",
                result={**command_result, "exit_code": 2},
                probe_argv=ls_remote_argv,
                target="production",
                expected_version=candidate_oid,
            ),
            "not_applied",
        )

    def test_structured_protocol_rejects_duplicate_control_keys(self) -> None:
        candidate_oid = "a" * 40
        command_result: dict[str, object] = {
            "exit_code": 0,
            "timed_out": False,
            "truncated": False,
        }
        duplicate_probe = (
            b'{"schema_version":1,"kind":"probe","outcome":"not_applied",'
            b'"outcome":"applied","target":"production","version":"'
            + candidate_oid.encode()
            + b'"}'
        )
        self.assertIsNone(
            _probe_protocol_outcome(
                duplicate_probe,
                result=command_result,
                probe_argv=("tool", "probe"),
                target="production",
                expected_version=candidate_oid,
            )
        )
        duplicate_health = (
            b'{"schema_version":1,"kind":"health","status":"unhealthy",'
            b'"status":"healthy","target":"production","version":"'
            + candidate_oid.encode()
            + b'"}'
        )
        self.assertFalse(
            _health_protocol_passes(
                duplicate_health,
                result=command_result,
                target="production",
                expected_version=candidate_oid,
            )
        )

    def test_release_target_lock_rejects_a_second_run_with_zero_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, manifest, subject = prepare_release_gate(root)
            runner = CountingRunner()
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                runner=runner,
            )
            approval = engine.record_approval(
                gate="release",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
            )
            git_common = Path(git_output(repo, "rev-parse", "--git-common-dir"))
            if not git_common.is_absolute():
                git_common = repo / git_common

            with FileLock.release_target(git_common.resolve(), "production"):
                with self.assertRaises(LockUnavailableError):
                    engine.release(
                        target="production", approval_id=approval.approval_id
                    )

            self.assertEqual(runner.calls, 0)
            self.assertEqual(store.load().phase, Phase.AWAITING_RELEASE_APPROVAL)

    def test_health_requires_an_exact_current_candidate_assertion(self) -> None:
        for case in (
            "current-candidate",
            "explicit-unhealthy",
            "healthy-old-version",
            "failed-command",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo, run_directory, store, _, initial_subject = prepare_release_gate(
                    root
                )
                health_output = (
                    "old-version"
                    if case == "healthy-old-version"
                    else initial_subject.candidate_oid
                )
                manifest = health_manifest(
                    root,
                    health_output=health_output,
                    health_exit_code=(1 if case == "failed-command" else 0),
                )
                if case == "explicit-unhealthy":
                    unhealthy = replace(
                        manifest.release_healthchecks[0],
                        argv=(
                            sys.executable,
                            "-c",
                            (
                                "import json,sys; print(json.dumps({"
                                "'schema_version':1,'kind':'health',"
                                "'status':'unhealthy','target':'production',"
                                "'version':sys.argv[1]},sort_keys=True,"
                                "separators=(',',':')))"
                            ),
                            initial_subject.candidate_oid,
                        ),
                    )
                    manifest = replace(manifest, release_healthchecks=(unhealthy,))
                subject = subject_for(repo, manifest)
                seal_passing_verification(
                    run_directory, manifest, subject, variables(repo)
                )
                engine = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                )
                approval = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                )

                if case in {"healthy-old-version", "failed-command"}:
                    with self.assertRaises(ReleaseRecoveryError):
                        engine.release(
                            target="production", approval_id=approval.approval_id
                        )
                    expected_phase = Phase.BLOCKED
                else:
                    engine.release(
                        target="production", approval_id=approval.approval_id
                    )
                    expected_phase = (
                        Phase.SYNCING
                        if case == "current-candidate"
                        else Phase.ROLLBACK_PENDING
                    )
                self.assertEqual(store.load().phase, expected_phase)
                self.assertTrue((root / "deployed").exists())
                seals = list(
                    (run_directory / "release-cycles").glob(
                        "*/health/sealed/release-0001-*.json"
                    )
                )
                if case in {"healthy-old-version", "failed-command"}:
                    self.assertEqual(seals, [])
                else:
                    self.assertEqual(len(seals), 1)
                    evidence = json.loads(seals[0].read_text())
                    self.assertEqual(
                        evidence["expected_version"], subject.candidate_oid
                    )
                    self.assertEqual(
                        evidence["asserts_expected_version"],
                        case == "current-candidate",
                    )

    def test_health_evidence_damage_blocks_instead_of_triggering_rollback(self) -> None:
        for corruption in ("deleted", "digest"):
            with (
                self.subTest(corruption=corruption),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                repo, run_directory, store, _, initial_subject = prepare_release_gate(
                    root
                )
                manifest = health_manifest(
                    root, health_output=initial_subject.candidate_oid
                )
                subject = subject_for(repo, manifest)
                seal_passing_verification(
                    run_directory, manifest, subject, variables(repo)
                )
                engine = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    runner=CorruptingHealthRunner(corruption),
                )
                approval = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                )

                with self.assertRaises(ReleaseRecoveryError):
                    engine.release(
                        target="production", approval_id=approval.approval_id
                    )

                self.assertEqual(store.load().phase, Phase.BLOCKED)
                self.assertNotEqual(store.load().phase, Phase.ROLLBACK_PENDING)

    def test_health_seal_without_pointer_is_reported_as_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, _, initial_subject = prepare_release_gate(root)
            manifest = health_manifest(
                root,
                health_output=initial_subject.candidate_oid,
            )
            subject = subject_for(repo, manifest)
            seal_passing_verification(
                run_directory,
                manifest,
                subject,
                variables(repo),
            )
            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            approval = engine.record_approval(
                gate="release",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
            )
            original_write = release_module._write_canonical_json
            crashed = False

            def crash_before_health_pointer(
                path: Path,
                payload: dict[str, object],
                *,
                trusted_root: object,
            ) -> None:
                nonlocal crashed
                if (
                    not crashed
                    and path.parent.name == "health"
                    and path.name == "release-0001.json"
                ):
                    crashed = True
                    raise OSError("simulated crash before health pointer")
                original_write(path, payload, trusted_root=trusted_root)

            with patch.object(
                release_module,
                "_write_canonical_json",
                side_effect=crash_before_health_pointer,
            ):
                with self.assertRaisesRegex(OSError, "health pointer"):
                    engine.release(
                        target="production",
                        approval_id=approval.approval_id,
                    )

            self.assertEqual(store.load().phase, Phase.POST_RELEASE_VERIFYING)
            inspection = validate_external_operation_evidence(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                phase=Phase.POST_RELEASE_VERIFYING,
            )
            self.assertTrue(inspection.recoverable)

            engine.release(
                target="production",
                approval_id=approval.approval_id,
            )
            self.assertEqual(store.load().phase, Phase.SYNCING)

    def test_reconciliation_revalidates_release_health_seal_and_log(self) -> None:
        for corruption in ("deleted-seal", "tampered-log"):
            with (
                self.subTest(corruption=corruption),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                repo, run_directory, store, _, initial_subject = prepare_release_gate(
                    root
                )
                manifest = health_manifest(
                    root,
                    health_output=initial_subject.candidate_oid,
                )
                subject = subject_for(repo, manifest)
                seal_passing_verification(
                    run_directory,
                    manifest,
                    subject,
                    variables(repo),
                )
                engine = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                )
                approval = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                )
                engine.release(
                    target="production",
                    approval_id=approval.approval_id,
                )
                self.assertEqual(store.load().phase, Phase.SYNCING)
                validate_external_operation_evidence(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    phase=Phase.SYNCING,
                )
                health_seal = next(
                    (run_directory / "release-cycles").glob(
                        "*/health/sealed/release-0001-*.json"
                    )
                )
                if corruption == "deleted-seal":
                    health_seal.unlink()
                else:
                    health_receipt = json.loads(health_seal.read_text())
                    log_path = Path(health_receipt["result"]["log_path"])
                    log_path.write_bytes(log_path.read_bytes() + b"tampered")

                with self.assertRaises(ReleaseRecoveryError):
                    validate_external_operation_evidence(
                        repo=repo,
                        run_directory=run_directory,
                        manifest=manifest,
                        current_subject=subject,
                        variables=variables(repo),
                        phase=Phase.SYNCING,
                    )

    def test_invalid_health_protocol_blocks_with_zero_rollback_effects(self) -> None:
        previous_release = "release-v1"
        for invalid_protocol in ("duplicate-key", "malformed"):
            with (
                self.subTest(invalid_protocol=invalid_protocol),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                repo, run_directory, store, _, _ = prepare_release_gate(root)
                manifest = rollback_manifest(
                    root,
                    data_impact="none",
                    rollback_health_output=previous_release,
                )
                output = (
                    'print(\'{"schema_version":1,"kind":"health",'
                    '"status":"unhealthy","status":"healthy",'
                    '"target":"production","version":"candidate"}\')'
                    if invalid_protocol == "duplicate-key"
                    else "print('{')"
                )
                invalid = replace(
                    manifest.release_healthchecks[0],
                    argv=(sys.executable, "-c", output),
                )
                manifest = replace(manifest, release_healthchecks=(invalid,))
                subject = subject_for(repo, manifest)
                seal_passing_verification(
                    run_directory, manifest, subject, variables(repo)
                )
                engine = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                )
                release_approval = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                )
                rollback_approval = engine.record_approval(
                    gate="rollback",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                    failed_release_id=release_approval.approval_id,
                    previous_release=previous_release,
                )

                with self.assertRaises(ReleaseRecoveryError):
                    engine.release(
                        target="production",
                        approval_id=release_approval.approval_id,
                        rollback_approval_id=rollback_approval.approval_id,
                        previous_release=previous_release,
                    )

                self.assertEqual(store.load().phase, Phase.BLOCKED)
                self.assertFalse((root / "rollback-counter").exists())

    def test_plain_text_version_mentions_are_not_protocol_assertions(self) -> None:
        for kind in ("probe", "health"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo, run_directory, store, _, initial_subject = prepare_release_gate(
                    root
                )
                if kind == "probe":
                    base_manifest = counter_manifest(
                        root,
                        candidate_oid=initial_subject.candidate_oid,
                        with_probe=True,
                    )
                    operation = replace(
                        base_manifest.release_steps[0],
                        probe_argv=(
                            sys.executable,
                            "-c",
                            "import sys; print('diagnostic', sys.argv[1])",
                            initial_subject.candidate_oid,
                        ),
                    )
                    manifest = replace(base_manifest, release_steps=(operation,))
                else:
                    base_manifest = health_manifest(
                        root,
                        health_output=initial_subject.candidate_oid,
                    )
                    healthcheck = replace(
                        base_manifest.release_healthchecks[0],
                        argv=(
                            sys.executable,
                            "-c",
                            "import sys; print('diagnostic', sys.argv[1])",
                            initial_subject.candidate_oid,
                        ),
                    )
                    manifest = replace(
                        base_manifest,
                        release_healthchecks=(healthcheck,),
                    )
                subject = subject_for(repo, manifest)
                seal_passing_verification(
                    run_directory, manifest, subject, variables(repo)
                )
                engine_type = (
                    CrashOnceReleaseEngine if kind == "probe" else ReleaseEngine
                )
                engine_kwargs: dict[str, object] = {}
                if kind == "probe":
                    engine_kwargs["crash_stage"] = "running"
                engine = engine_type(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    **engine_kwargs,
                )
                approval = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                )

                if kind == "probe":
                    with self.assertRaises(SimulatedCrash):
                        engine.release(
                            target="production", approval_id=approval.approval_id
                        )
                    resumed = ReleaseEngine(
                        repo=repo,
                        run_directory=run_directory,
                        manifest=manifest,
                        current_subject=subject,
                        variables=variables(repo),
                    )
                    with self.assertRaises(ReleaseRecoveryError):
                        resumed.release(
                            target="production", approval_id=approval.approval_id
                        )
                    self.assertEqual(store.load().phase, Phase.BLOCKED)
                    self.assertFalse((root / "external-counter").exists())
                else:
                    with self.assertRaises(ReleaseRecoveryError):
                        engine.release(
                            target="production", approval_id=approval.approval_id
                        )
                    self.assertEqual(store.load().phase, Phase.BLOCKED)


class RollbackTests(unittest.TestCase):
    def _fixture(
        self,
        root: Path,
        *,
        data_impact: str,
        rollback_health_output: str,
        rollback_health_status: str = "healthy",
    ) -> tuple[
        Path,
        Path,
        StateStore,
        Manifest,
        EvidenceSubject,
        ReleaseEngine,
        ApprovalRecord,
    ]:
        repo, run_directory, store, _, _ = prepare_release_gate(root)
        manifest = rollback_manifest(
            root,
            data_impact=data_impact,
            rollback_health_output=rollback_health_output,
            rollback_health_status=rollback_health_status,
        )
        subject = subject_for(repo, manifest)
        seal_passing_verification(run_directory, manifest, subject, variables(repo))
        engine = ReleaseEngine(
            repo=repo,
            run_directory=run_directory,
            manifest=manifest,
            current_subject=subject,
            variables=variables(repo),
        )
        release_approval = engine.record_approval(
            gate="release",
            target="production",
            approver_actor="human",
            expires_at="2999-01-01T00:00:00Z",
        )
        return (
            repo,
            run_directory,
            store,
            manifest,
            subject,
            engine,
            release_approval,
        )

    def test_inspects_sealed_failed_release_context_without_mutation(self) -> None:
        previous_release = "release-v1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                repo,
                run_directory,
                store,
                manifest,
                subject,
                engine,
                release_approval,
            ) = self._fixture(
                root,
                data_impact="possible",
                rollback_health_output=previous_release,
            )
            engine.release(
                target="production",
                approval_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            self.assertEqual(store.load().phase, Phase.ROLLBACK_PENDING)
            runner = CountingRunner()
            observer = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                runner=runner,
            )
            before = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }

            context = observer.inspect_failed_release_context()

            after = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }
            self.assertEqual(context.mode, "release")
            self.assertEqual(context.approval_id, release_approval.approval_id)
            self.assertEqual(context.target, "production")
            self.assertIsNone(context.failed_release_id)
            self.assertIsNone(context.previous_release)
            self.assertEqual(after, before)
            self.assertEqual(runner.calls, 0)

    def test_failed_release_context_rejects_missing_immutable_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                _,
                run_directory,
                store,
                _,
                _,
                engine,
                release_approval,
            ) = self._fixture(
                root,
                data_impact="possible",
                rollback_health_output="release-v1",
            )
            engine.release(
                target="production",
                approval_id=release_approval.approval_id,
                previous_release="release-v1",
            )
            self.assertEqual(store.load().phase, Phase.ROLLBACK_PENDING)
            active = json.loads(
                (run_directory / "release-cycles" / "active-release.json").read_text(
                    encoding="utf-8"
                )
            )
            header = (
                run_directory
                / "release-cycles"
                / str(active["cycle_id"])
                / "header.json"
            )
            header.unlink()
            before = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }

            with self.assertRaises(ReleaseRecoveryError):
                engine.inspect_failed_release_context()

            after = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)

    def test_inspects_one_current_rollback_approval_without_running_effects(
        self,
    ) -> None:
        previous_release = "release-v1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                repo,
                run_directory,
                store,
                manifest,
                subject,
                engine,
                release_approval,
            ) = self._fixture(
                root,
                data_impact="possible",
                rollback_health_output=previous_release,
            )
            engine.release(
                target="production",
                approval_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            self.assertEqual(store.load().phase, Phase.ROLLBACK_PENDING)
            rollback_approval = engine.record_approval(
                gate="rollback",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
                failed_release_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            runner = CountingRunner()
            observer = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                runner=runner,
            )
            before = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }

            inspected = observer.inspect_current_unconsumed_approval(gate="rollback")

            after = {
                path.relative_to(run_directory): path.read_bytes()
                for path in run_directory.rglob("*")
                if path.is_file()
            }
            self.assertEqual(inspected, rollback_approval)
            self.assertEqual(after, before)
            self.assertEqual(runner.calls, 0)

    def test_rollback_approval_rejects_a_fake_failed_release_in_both_gates(
        self,
    ) -> None:
        for phase in ("preapproval", "action-time"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (
                    _,
                    run_directory,
                    _,
                    _,
                    _,
                    engine,
                    release_approval,
                ) = self._fixture(
                    root,
                    data_impact=("none" if phase == "preapproval" else "possible"),
                    rollback_health_output="release-v1",
                )
                if phase == "action-time":
                    engine.release(
                        target="production",
                        approval_id=release_approval.approval_id,
                        previous_release="release-v1",
                    )
                approval_root = run_directory / "approvals"
                before = {
                    path.relative_to(approval_root): path.read_bytes()
                    for path in approval_root.rglob("*")
                    if path.is_file()
                }

                with self.assertRaises(ReleaseError):
                    engine.record_approval(
                        gate="rollback",
                        target="production",
                        approver_actor="human",
                        expires_at="2999-01-01T00:00:00Z",
                        failed_release_id="f" * 64,
                        previous_release="release-v1",
                    )

                after = {
                    path.relative_to(approval_root): path.read_bytes()
                    for path in approval_root.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(after, before)
                self.assertFalse((root / "rollback-counter").exists())

    def test_rollback_approval_retry_recovers_seal_and_context_orphans(self) -> None:
        previous_release = "release-v1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                _,
                run_directory,
                _,
                _,
                _,
                engine,
                release_approval,
            ) = self._fixture(
                root,
                data_impact="possible",
                rollback_health_output=previous_release,
            )
            engine.release(
                target="production",
                approval_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            original_write = release_module._write_canonical_json
            crashed = False

            def crash_before_pointer(
                path: Path,
                payload: dict[str, object],
                *,
                trusted_root: object,
            ) -> None:
                nonlocal crashed
                if path.parent.name == "approvals" and not crashed:
                    crashed = True
                    raise OSError("simulated approval pointer power loss")
                original_write(path, payload, trusted_root=trusted_root)

            with (
                patch.object(
                    release_module,
                    "_write_canonical_json",
                    side_effect=crash_before_pointer,
                ),
                self.assertRaises(ReleaseError),
            ):
                engine.record_approval(
                    gate="rollback",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                    failed_release_id=release_approval.approval_id,
                    previous_release=previous_release,
                )
            orphan = next((run_directory / "approvals" / "sealed").glob("*.json"))
            if orphan.stem == release_approval.approval_id:
                orphan = next(
                    path
                    for path in (run_directory / "approvals" / "sealed").glob("*.json")
                    if path.stem != release_approval.approval_id
                )
            self.assertFalse((run_directory / "approvals" / orphan.name).exists())
            self.assertTrue(
                (
                    run_directory / "approvals" / "rollback-contexts" / orphan.name
                ).is_file()
            )

            recovered = engine.record_approval(
                gate="rollback",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
                failed_release_id=release_approval.approval_id,
                previous_release=previous_release,
            )

            self.assertEqual(recovered.approval_id, orphan.stem)
            self.assertEqual(
                engine.inspect_current_unconsumed_approval(gate="rollback"),
                recovered,
            )

    def test_consumed_rollback_cycle_without_first_receipt_resumes_safely(
        self,
    ) -> None:
        previous_release = "release-v1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                repo,
                run_directory,
                store,
                manifest,
                subject,
                engine,
                release_approval,
            ) = self._fixture(
                root,
                data_impact="possible",
                rollback_health_output=previous_release,
            )
            engine.release(
                target="production",
                approval_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            self.assertEqual(store.load().phase, Phase.ROLLBACK_PENDING)
            rollback_approval = engine.record_approval(
                gate="rollback",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
                failed_release_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            cycle = engine._activate_cycle(
                gate="rollback",
                approval_id=rollback_approval.approval_id,
                target="production",
                failed_release_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            _, _, _, _, first_key = engine._operation_identity(
                cycle_id=str(cycle["cycle_id"]),
                mode="rollback",
                index=1,
                spec=manifest.rollback_steps[0],
                target="production",
                approval_id=rollback_approval.approval_id,
                failed_release_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            engine.consume_approval(
                rollback_approval.approval_id,
                consumer=engine._approval_consumer(
                    mode="rollback",
                    idempotency_key=first_key,
                ),
            )
            state = store.load()
            store.transition(Phase.ROLLING_BACK, expected_revision=state.revision)

            inspection = validate_external_operation_evidence(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                phase=Phase.ROLLING_BACK,
            )
            self.assertTrue(inspection.active_cycle)

            engine.rollback(
                target="production",
                approval_id=rollback_approval.approval_id,
                failed_release_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            self.assertEqual((root / "rollback-counter").read_text(), "1")
            self.assertEqual(store.load().phase, Phase.ROLLBACK_VERIFYING)

    def test_applied_rollback_adjudication_skips_replay_and_can_verify(self) -> None:
        previous_release = "release-v1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, run_directory, store, _, _ = prepare_release_gate(root)
            base_manifest = rollback_manifest(
                root,
                data_impact="none",
                rollback_health_output=previous_release,
            )
            first = replace(
                base_manifest.rollback_steps[0],
                idempotency="manual_reconcile",
            )
            second = replace(
                first,
                name="restore-previous-2",
                argv=(*first.argv[:-1], str(root / "rollback-counter-2")),
            )
            manifest = replace(
                base_manifest,
                rollback_steps=(first, second),
            )
            subject = subject_for(repo, manifest)
            seal_passing_verification(
                run_directory,
                manifest,
                subject,
                variables(repo),
            )
            approval_engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            release_approval = approval_engine.record_approval(
                gate="release",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
            )
            rollback_approval = approval_engine.record_approval(
                gate="rollback",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
                failed_release_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            crashing = CrashOnceModeReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_mode="rollback",
                crash_stage="effect-returned",
            )
            with self.assertRaises(SimulatedCrash):
                crashing.release(
                    target="production",
                    approval_id=release_approval.approval_id,
                    rollback_approval_id=rollback_approval.approval_id,
                    previous_release=previous_release,
                )
            self.assertEqual((root / "rollback-counter").read_text(), "1")

            engine = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            with self.assertRaises(ReleaseRecoveryError):
                engine.reconcile_operation(target="production")
            first_decision = engine.inspect_unknown_operation(target="production")
            self.assertEqual(first_decision.mode, "rollback")
            self.assertEqual(first_decision.index, 1)
            engine.record_operation_outcome(
                target="production",
                unknown_receipt_sha256=first_decision.unknown_receipt_sha256,
                confirmation_token=first_decision.confirmation_token,
                expected_revision=first_decision.blocked_revision,
                actor="human-operator",
                outcome="applied",
            )

            second_crash = CrashOnceIndexedReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_mode="rollback",
                crash_index=2,
                crash_stage="effect-returned",
            )
            with self.assertRaises(SimulatedCrash):
                second_crash.resume_external_cycle(target="production")
            resumed = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
            )
            with self.assertRaises(ReleaseRecoveryError):
                resumed.reconcile_operation(target="production")
            second_decision = resumed.inspect_unknown_operation(target="production")
            self.assertEqual(second_decision.mode, "rollback")
            self.assertEqual(second_decision.index, 2)
            self.assertNotEqual(
                second_decision.unknown_receipt_sha256,
                first_decision.unknown_receipt_sha256,
            )
            resumed.record_operation_outcome(
                target="production",
                unknown_receipt_sha256=second_decision.unknown_receipt_sha256,
                confirmation_token=second_decision.confirmation_token,
                expected_revision=second_decision.blocked_revision,
                actor="human-operator",
                outcome="applied",
            )

            first_resume = resumed.resume_external_cycle(target="production")
            repeated_resume = resumed.resume_external_cycle(target="production")
            self.assertEqual(first_resume, repeated_resume)
            self.assertEqual(store.load().phase, Phase.ROLLBACK_VERIFYING)
            validate_external_operation_evidence(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                phase=Phase.ROLLBACK_VERIFYING,
            )
            engine.verify_rollback(
                target="production",
                previous_release=previous_release,
            )

            self.assertEqual(store.load().phase, Phase.ROLLED_BACK)
            self.assertEqual((root / "rollback-counter").read_text(), "1")
            self.assertEqual((root / "rollback-counter-2").read_text(), "1")

    def test_optional_active_rollback_is_recoverable_at_rollback_gate(self) -> None:
        previous_release = "release-v1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                repo,
                run_directory,
                store,
                manifest,
                subject,
                initial_engine,
                release_approval,
            ) = self._fixture(
                root,
                data_impact="possible",
                rollback_health_output=previous_release,
            )
            initial_engine.release(
                target="production",
                approval_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            self.assertEqual(store.load().phase, Phase.ROLLBACK_PENDING)
            rollback_approval = initial_engine.record_approval(
                gate="rollback",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
                failed_release_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            engine = CrashOnceReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                crash_stage="prepared",
            )
            with self.assertRaises(SimulatedCrash):
                engine.rollback(
                    target="production",
                    approval_id=rollback_approval.approval_id,
                    failed_release_id=release_approval.approval_id,
                    previous_release=previous_release,
                )

            self.assertEqual(store.load().phase, Phase.ROLLBACK_PENDING)
            self.assertFalse((root / "rollback-counter").exists())
            inspection = validate_external_operation_evidence(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                phase=Phase.ROLLBACK_PENDING,
            )
            self.assertTrue(inspection.active_cycle)
            self.assertTrue(inspection.recoverable)

            engine.rollback(
                target="production",
                approval_id=rollback_approval.approval_id,
                failed_release_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            self.assertEqual(store.load().phase, Phase.ROLLBACK_VERIFYING)
            self.assertEqual((root / "rollback-counter").read_text(), "1")

    def test_safe_preapproved_rollback_runs_and_health_binds_previous(self) -> None:
        previous_release = "release-v1"
        for health_passes in (True, False):
            with (
                self.subTest(health_passes=health_passes),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                (
                    _,
                    run_directory,
                    store,
                    _,
                    _,
                    engine,
                    release_approval,
                ) = self._fixture(
                    root,
                    data_impact="none",
                    rollback_health_output=(
                        previous_release if health_passes else "different-release"
                    ),
                    rollback_health_status=(
                        "healthy" if health_passes else "unhealthy"
                    ),
                )
                rollback_approval = engine.record_approval(
                    gate="rollback",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                    failed_release_id=release_approval.approval_id,
                    previous_release=previous_release,
                )

                engine.release(
                    target="production",
                    approval_id=release_approval.approval_id,
                    rollback_approval_id=rollback_approval.approval_id,
                    previous_release=previous_release,
                )

                self.assertEqual(store.load().phase, Phase.ROLLBACK_VERIFYING)
                self.assertEqual((root / "rollback-counter").read_text(), "1")
                engine.verify_rollback(
                    target="production", previous_release=previous_release
                )
                self.assertEqual(
                    store.load().phase,
                    Phase.ROLLED_BACK if health_passes else Phase.BLOCKED,
                )
                seals = list(
                    (run_directory / "release-cycles").glob(
                        "*/health/sealed/rollback-0001-*.json"
                    )
                )
                self.assertEqual(len(seals), 1)
                evidence = json.loads(seals[0].read_text())
                self.assertEqual(evidence["expected_version"], previous_release)
                self.assertEqual(evidence["asserts_expected_version"], health_passes)

    def test_reconciliation_revalidates_rollback_health_evidence(self) -> None:
        previous_release = "release-v1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                repo,
                run_directory,
                store,
                manifest,
                subject,
                engine,
                release_approval,
            ) = self._fixture(
                root,
                data_impact="none",
                rollback_health_output=previous_release,
            )
            rollback_approval = engine.record_approval(
                gate="rollback",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
                failed_release_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            engine.release(
                target="production",
                approval_id=release_approval.approval_id,
                rollback_approval_id=rollback_approval.approval_id,
                previous_release=previous_release,
            )
            self.assertEqual(store.load().phase, Phase.ROLLBACK_VERIFYING)
            with (
                patch.object(
                    engine.store,
                    "transition",
                    side_effect=SimulatedCrash("before-rolled-back"),
                ),
                self.assertRaises(SimulatedCrash),
            ):
                engine.verify_rollback(
                    target="production",
                    previous_release=previous_release,
                )
            validate_external_operation_evidence(
                repo=repo,
                run_directory=run_directory,
                manifest=manifest,
                current_subject=subject,
                variables=variables(repo),
                phase=Phase.ROLLBACK_VERIFYING,
            )
            health_seal = next(
                (run_directory / "release-cycles").glob(
                    "*/health/sealed/rollback-0001-*.json"
                )
            )
            health_receipt = json.loads(health_seal.read_text())
            log_path = Path(health_receipt["result"]["log_path"])
            log_path.write_bytes(log_path.read_bytes() + b"tampered")

            with self.assertRaises(ReleaseRecoveryError):
                validate_external_operation_evidence(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    phase=Phase.ROLLBACK_VERIFYING,
                )

    def test_rolled_back_terminal_revalidates_health_evidence(self) -> None:
        previous_release = "release-v1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                repo,
                run_directory,
                store,
                manifest,
                subject,
                engine,
                release_approval,
            ) = self._fixture(
                root,
                data_impact="none",
                rollback_health_output=previous_release,
            )
            rollback_approval = engine.record_approval(
                gate="rollback",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
                failed_release_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            engine.release(
                target="production",
                approval_id=release_approval.approval_id,
                rollback_approval_id=rollback_approval.approval_id,
                previous_release=previous_release,
            )
            engine.verify_rollback(
                target="production",
                previous_release=previous_release,
            )
            self.assertEqual(store.load().phase, Phase.ROLLED_BACK)
            health_seal = next(
                (run_directory / "release-cycles").glob(
                    "*/health/sealed/rollback-0001-*.json"
                )
            )
            health_seal.unlink()

            with self.assertRaises(ReleaseRecoveryError):
                validate_external_operation_evidence(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                    phase=Phase.ROLLED_BACK,
                )

    def test_rollback_verification_blocks_manifest_drift_before_receipt_checks(
        self,
    ) -> None:
        previous_release = "release-v1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                repo,
                run_directory,
                store,
                manifest,
                subject,
                engine,
                release_approval,
            ) = self._fixture(
                root,
                data_impact="none",
                rollback_health_output=previous_release,
            )
            rollback_approval = engine.record_approval(
                gate="rollback",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
                failed_release_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            engine.release(
                target="production",
                approval_id=release_approval.approval_id,
                rollback_approval_id=rollback_approval.approval_id,
                previous_release=previous_release,
            )
            self.assertEqual(store.load().phase, Phase.ROLLBACK_VERIFYING)
            with (
                patch.object(
                    engine.store,
                    "transition",
                    side_effect=SimulatedCrash("before-rolled-back"),
                ),
                self.assertRaises(SimulatedCrash),
            ):
                engine.verify_rollback(
                    target="production", previous_release=previous_release
                )
            self.assertEqual(store.load().phase, Phase.ROLLBACK_VERIFYING)
            health_seals = list(
                (run_directory / "release-cycles").glob(
                    "*/health/sealed/rollback-*.json"
                )
            )
            self.assertEqual(len(health_seals), 1)
            drifted = ReleaseEngine(
                repo=repo,
                run_directory=run_directory,
                manifest=replace(manifest, rollback_steps=()),
                current_subject=subject,
                variables=variables(repo),
            )

            with self.assertRaises(ReleaseError):
                drifted.verify_rollback(
                    target="production", previous_release=previous_release
                )

            self.assertEqual(store.load().phase, Phase.BLOCKED)
            self.assertEqual(
                list(
                    (run_directory / "release-cycles").glob(
                        "*/health/sealed/rollback-*.json"
                    )
                ),
                health_seals,
            )

    def test_rollback_verification_revalidates_consumed_approval_evidence(
        self,
    ) -> None:
        previous_release = "release-v1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                _,
                run_directory,
                store,
                _,
                _,
                engine,
                release_approval,
            ) = self._fixture(
                root,
                data_impact="none",
                rollback_health_output=previous_release,
            )
            rollback_approval = engine.record_approval(
                gate="rollback",
                target="production",
                approver_actor="human",
                expires_at="2999-01-01T00:00:00Z",
                failed_release_id=release_approval.approval_id,
                previous_release=previous_release,
            )
            engine.release(
                target="production",
                approval_id=release_approval.approval_id,
                rollback_approval_id=rollback_approval.approval_id,
                previous_release=previous_release,
            )
            self.assertEqual(store.load().phase, Phase.ROLLBACK_VERIFYING)
            (
                run_directory / "approvals" / f"{rollback_approval.approval_id}.json"
            ).unlink()
            (
                run_directory
                / "approvals"
                / "sealed"
                / f"{rollback_approval.approval_id}.json"
            ).unlink()

            with self.assertRaises(ReleaseError):
                engine.verify_rollback(
                    target="production", previous_release=previous_release
                )

            self.assertEqual(store.load().phase, Phase.BLOCKED)

    def test_rollback_verification_requires_every_step_receipt_and_log(self) -> None:
        previous_release = "release-v1"
        for corruption in ("missing-receipt", "tampered-log"):
            with (
                self.subTest(corruption=corruption),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                repo, run_directory, store, _, _ = prepare_release_gate(root)
                manifest = rollback_manifest(
                    root,
                    data_impact="none",
                    rollback_health_output=previous_release,
                )
                first_step = manifest.rollback_steps[0]
                second_step = replace(
                    first_step,
                    name="restore-previous-second-step",
                    argv=(*first_step.argv[:-1], str(root / "rollback-counter-2")),
                )
                manifest = replace(manifest, rollback_steps=(first_step, second_step))
                subject = subject_for(repo, manifest)
                seal_passing_verification(
                    run_directory, manifest, subject, variables(repo)
                )
                engine = ReleaseEngine(
                    repo=repo,
                    run_directory=run_directory,
                    manifest=manifest,
                    current_subject=subject,
                    variables=variables(repo),
                )
                release_approval = engine.record_approval(
                    gate="release",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                )
                rollback_approval = engine.record_approval(
                    gate="rollback",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                    failed_release_id=release_approval.approval_id,
                    previous_release=previous_release,
                )
                engine.release(
                    target="production",
                    approval_id=release_approval.approval_id,
                    rollback_approval_id=rollback_approval.approval_id,
                    previous_release=previous_release,
                )
                self.assertEqual(store.load().phase, Phase.ROLLBACK_VERIFYING)

                active = json.loads(
                    (
                        run_directory / "release-cycles" / "active-rollback.json"
                    ).read_text()
                )
                operations = (
                    run_directory / "release-cycles" / active["cycle_id"] / "operations"
                )
                second_pointer = operations / "rollback-0002.json"
                if corruption == "missing-receipt":
                    second_pointer.unlink()
                    for directory_name in ("sealed", "committed"):
                        directory = operations / directory_name
                        if directory.is_dir():
                            for path in directory.glob("rollback-0002-attempt-*.json"):
                                path.unlink()
                else:
                    second_receipt = json.loads(second_pointer.read_text())
                    log_path = Path(second_receipt["result"]["command"]["log_path"])
                    log_path.write_bytes(log_path.read_bytes() + b"tampered")

                with self.assertRaises(ReleaseRecoveryError):
                    engine.verify_rollback(
                        target="production", previous_release=previous_release
                    )

                self.assertEqual(store.load().phase, Phase.BLOCKED)

    def test_data_impacting_rollback_waits_for_action_time_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                _,
                _,
                store,
                _,
                _,
                engine,
                release_approval,
            ) = self._fixture(
                root,
                data_impact="possible",
                rollback_health_output="release-v1",
            )
            with self.assertRaises(ReleaseError):
                engine.record_approval(
                    gate="rollback",
                    target="production",
                    approver_actor="human",
                    expires_at="2999-01-01T00:00:00Z",
                    failed_release_id=release_approval.approval_id,
                    previous_release="release-v1",
                )

            engine.release(
                target="production",
                approval_id=release_approval.approval_id,
                previous_release="release-v1",
            )

            self.assertEqual(store.load().phase, Phase.ROLLBACK_PENDING)
            self.assertFalse((root / "rollback-counter").exists())


if __name__ == "__main__":
    unittest.main()
