from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ship_flow import verify as verify_module
from ship_flow.manifest import CommandSpec, Manifest, manifest_digest
from ship_flow.model import Phase
from ship_flow.review import ReviewRole, issue_handoff, record_code_review
from ship_flow.runner import CommandRunner
from ship_flow.store import FileLock, StateStore
from ship_flow.subject import EvidenceSubject
from ship_flow.verify import (
    VerificationError,
    VerificationRecoveryError,
    VerificationReport,
    Verifier,
    verification_commands_digest,
)
from tests.support import git, git_output, initialize_repository


class TamperingRunner:
    """Delegate real execution, then simulate post-return log replacement."""

    def __init__(self) -> None:
        self.delegate = CommandRunner()

    def run(self, *args: object, **kwargs: object):
        result = self.delegate.run(*args, **kwargs)
        result.log_path.write_bytes(b"tampered after runner return\n")
        return result


class CountingRunner:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, *args: object, **kwargs: object):
        self.calls += 1
        raise AssertionError("verification command must not run")


class RaisingRunner:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, *args: object, **kwargs: object):
        self.calls += 1
        raise OSError("runner failed after invocation boundary")


class VerificationImportTests(unittest.TestCase):
    def test_verification_interfaces_import(self) -> None:
        self.assertTrue(Verifier)
        self.assertTrue(VerificationReport)


class VerificationCommandDigestTests(unittest.TestCase):
    def test_digest_binds_ordered_resolved_command_specs(self) -> None:
        command = CommandSpec(
            "check",
            (sys.executable, "-c", "print('ok')", "${branch}"),
            "unit",
            timeout_seconds=5,
            cwd="checks",
            env_allowlist=("PATH",),
            max_log_bytes=4096,
            shell_approved=False,
        )
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(command,),
            release_required=False,
        )
        variables = {"branch": "ship/one"}

        digest = verification_commands_digest(manifest, variables)

        self.assertEqual(digest, verification_commands_digest(manifest, variables))
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            digest,
            verification_commands_digest(manifest, {"branch": "ship/two"}),
        )
        changed = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "check",
                    command.argv,
                    "unit",
                    timeout_seconds=6,
                    cwd="checks",
                    env_allowlist=("PATH",),
                    max_log_bytes=4096,
                    shell_approved=False,
                ),
            ),
            release_required=False,
        )
        self.assertNotEqual(
            digest,
            verification_commands_digest(changed, variables),
        )


class VerificationWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.repo = self.root / "repo"
        self.base_oid = initialize_repository(self.repo)
        (self.root / "runtime").mkdir()
        self.run_directory = self.root / "runtime" / "runs" / "run-001"
        self.store = StateStore(self.run_directory)

    def prepare_verification(self, manifest: Manifest) -> tuple[EvidenceSubject, str]:
        state = self.store.create("run-001")
        for phase in (
            Phase.PLANNING,
            Phase.PLAN_REVIEW,
            Phase.AWAITING_PLAN_APPROVAL,
            Phase.DEVELOPING,
            Phase.CODE_REVIEW,
        ):
            state = self.store.transition(phase, expected_revision=state.revision)
        subject = EvidenceSubject(
            run_id="run-001",
            base_oid=self.base_oid,
            candidate_oid=git_output(self.repo, "rev-parse", "HEAD^{commit}"),
            tree_oid=git_output(self.repo, "rev-parse", "HEAD^{tree}"),
            plan_sha256="4" * 64,
            manifest_sha256=manifest_digest(manifest),
            commands_sha256=verification_commands_digest(
                manifest,
                self.verification_variables(),
            ),
            engine_version="0.1.0",
            schema_version=1,
        )
        review_nonce = issue_handoff(
            self.store,
            subject=subject,
            source_actor="developer-context",
            role=ReviewRole.REVIEWER,
        )
        record_code_review(
            self.store,
            current_subject=subject,
            reviewer_actor="reviewer-context",
            handoff_nonce=review_nonce,
            verdict="pass",
            findings=(),
        )
        verifier_nonce = issue_handoff(
            self.store,
            subject=subject,
            source_actor="reviewer-context",
            role="verifier",
        )
        return subject, verifier_nonce

    def verifier(
        self,
        manifest: Manifest,
        subject: EvidenceSubject,
        *,
        runner: object | None = None,
        variables: dict[str, str] | None = None,
    ) -> Verifier:
        return Verifier(
            repo=self.repo,
            run_directory=self.run_directory,
            manifest=manifest,
            current_subject=subject,
            variables=(
                self.verification_variables() if variables is None else variables
            ),
            runner=runner,
        )

    def verification_variables(self) -> dict[str, str]:
        return {
            "repo": str(self.repo),
            "worktree": str(self.repo),
            "branch": "main",
            "base_branch": "main",
            "remote": "origin",
        }

    def execution_receipt_path(self, index: int = 1) -> Path:
        return (
            self.run_directory
            / "verification-executions"
            / f"verification-0001-command-{index:04d}.json"
        )

    def test_failed_command_stops_and_returns_to_development(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "fail",
                    (sys.executable, "-c", "raise SystemExit(7)"),
                    "unit",
                    timeout_seconds=5,
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)

        report = self.verifier(manifest, subject).verify(
            "run-001",
            verifier_actor="verifier-context",
            handoff_nonce=nonce,
            sensitive_values=(),
        )

        self.assertEqual(report.verdict, "fail")
        self.assertEqual(len(report.results), 1)
        self.assertEqual(report.results[0].exit_code, 7)
        self.assertEqual(self.store.load().phase, Phase.DEVELOPING)
        receipt = json.loads(self.execution_receipt_path().read_text())
        self.assertEqual(receipt["status"], "FAILED")
        self.assertEqual(receipt["result"]["exit_code"], 7)

    def test_all_commands_pass_in_order_and_reach_release_gate(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "first",
                    (sys.executable, "-c", "print('first')"),
                    "unit",
                    timeout_seconds=5,
                ),
                CommandSpec(
                    "second",
                    (sys.executable, "-c", "print('second')"),
                    "build",
                    timeout_seconds=5,
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)

        report = self.verifier(manifest, subject).verify(
            "run-001",
            verifier_actor="verifier-context",
            handoff_nonce=nonce,
            sensitive_values=(),
        )

        self.assertEqual(report.verdict, "pass")
        self.assertEqual(
            tuple(result.index for result in report.results),
            (1, 2),
        )
        self.assertEqual(
            json.loads(self.execution_receipt_path(1).read_text())["status"],
            "SUCCEEDED",
        )
        self.assertEqual(
            json.loads(self.execution_receipt_path(2).read_text())["status"],
            "SUCCEEDED",
        )
        self.assertEqual(self.store.load().phase, Phase.AWAITING_RELEASE_APPROVAL)

    def test_failure_stops_before_later_commands(self) -> None:
        marker = self.root / "later-command-ran"
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "fail-first",
                    (sys.executable, "-c", "raise SystemExit(9)"),
                    "unit",
                    timeout_seconds=5,
                ),
                CommandSpec(
                    "must-not-run",
                    (
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                        str(marker),
                    ),
                    "build",
                    timeout_seconds=5,
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)

        report = self.verifier(manifest, subject).verify(
            "run-001",
            verifier_actor="verifier-context",
            handoff_nonce=nonce,
            sensitive_values=(),
        )

        self.assertEqual(tuple(result.index for result in report.results), (1,))
        self.assertFalse(marker.exists())

    def test_verifier_actor_must_differ_from_developer_and_reviewer(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec("pass", (sys.executable, "-c", "pass"), "unit"),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)

        for actor in ("developer-context", "reviewer-context"):
            with self.subTest(actor=actor):
                with self.assertRaisesRegex(VerificationError, "differ"):
                    self.verifier(manifest, subject).verify(
                        "run-001",
                        verifier_actor=actor,
                        handoff_nonce=nonce,
                        sensitive_values=(),
                    )

        self.assertEqual(self.store.load().phase, Phase.VERIFYING)

    def test_verification_rejects_a_missing_completed_code_review_seal(
        self,
    ) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec("must-not-run", (sys.executable, "-c", "pass"), "unit"),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        seal = next((self.run_directory / "review-publications").glob("code-*.json"))
        seal.unlink()
        runner = CountingRunner()

        with self.assertRaisesRegex(VerificationError, "passing code review"):
            self.verifier(manifest, subject, runner=runner).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )

        self.assertEqual(runner.calls, 0)
        self.assertEqual(self.store.load().phase, Phase.VERIFYING)

    def test_verification_rejects_a_rewritten_completed_code_review(
        self,
    ) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec("must-not-run", (sys.executable, "-c", "pass"), "unit"),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        report_path = self.run_directory / "reviews" / "code-review.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["recorded_at"] = "2099-01-01T00:00:00.000000Z"
        report_path.write_text(
            json.dumps(
                report,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        runner = CountingRunner()

        with self.assertRaisesRegex(VerificationError, "passing code review"):
            self.verifier(manifest, subject, runner=runner).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )

        self.assertEqual(runner.calls, 0)
        self.assertEqual(self.store.load().phase, Phase.VERIFYING)

    def test_command_cannot_modify_candidate_and_verifier_does_not_repair(self) -> None:
        changed_contents = "verification changed the candidate\n"
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "mutate",
                    (
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; Path('README.md').write_text(sys.argv[1])",
                        changed_contents,
                    ),
                    "unit",
                    timeout_seconds=5,
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)

        report = self.verifier(manifest, subject).verify(
            "run-001",
            verifier_actor="verifier-context",
            handoff_nonce=nonce,
            sensitive_values=(),
        )

        self.assertEqual(report.verdict, "fail")
        self.assertEqual(self.store.load().phase, Phase.DEVELOPING)
        self.assertEqual((self.repo / "README.md").read_text(), changed_contents)

    def test_dirty_candidate_runs_zero_commands_and_returns_to_development(
        self,
    ) -> None:
        marker = self.root / "command-ran"
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "must-not-run",
                    (
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                        str(marker),
                    ),
                    "unit",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        (self.repo / "README.md").write_text("dirty\n", encoding="utf-8")

        with self.assertRaisesRegex(VerificationError, "current and clean"):
            self.verifier(manifest, subject).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )

        self.assertFalse(marker.exists())
        self.assertEqual(self.store.load().phase, Phase.DEVELOPING)

    def test_log_tampering_after_runner_return_blocks_publication(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "pass",
                    (sys.executable, "-c", "print('verified')"),
                    "unit",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)

        with self.assertRaisesRegex(VerificationError, "log"):
            self.verifier(
                manifest,
                subject,
                runner=TamperingRunner(),
            ).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )

        self.assertEqual(self.store.load().phase, Phase.BLOCKED)
        self.assertFalse((self.run_directory / "verification.json").exists())

    def test_subject_change_between_commands_blocks_and_stops(self) -> None:
        marker = self.root / "second-command-ran"
        review_path = self.run_directory / "reviews" / "code-review.json"
        mutate_review = (
            "from pathlib import Path; import json,sys; "
            "p=Path(sys.argv[1]); d=json.loads(p.read_text()); "
            "d['subject_digest']='0'*64; p.write_text(json.dumps(d))"
        )
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "tamper-subject",
                    (sys.executable, "-c", mutate_review, str(review_path)),
                    "unit",
                ),
                CommandSpec(
                    "must-not-run",
                    (
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                        str(marker),
                    ),
                    "build",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)

        with self.assertRaisesRegex(VerificationError, "subject"):
            self.verifier(manifest, subject).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )

        self.assertFalse(marker.exists())
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)

    def test_report_is_private_versioned_and_binds_ordered_evidence(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "unit",
                    (sys.executable, "-c", "print('unit')"),
                    "unit",
                ),
                CommandSpec(
                    "build",
                    (sys.executable, "-c", "print('build')"),
                    "build",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)

        report = self.verifier(manifest, subject).verify(
            "run-001",
            verifier_actor="verifier-context",
            handoff_nonce=nonce,
            sensitive_values=(),
        )

        report_path = self.run_directory / "verifications" / "verification-0001.json"
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(report_path.parent.stat().st_mode), 0o700)
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["round"], 1)
        self.assertEqual(payload["run_id"], "run-001")
        self.assertEqual(payload["verifier_actor"], "verifier-context")
        self.assertEqual(payload["subject"], subject.to_dict())
        self.assertEqual(payload["subject_digest"], subject.digest())
        self.assertEqual(
            payload["handoff_nonce_sha256"],
            hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(payload["commands_sha256"], subject.commands_sha256)
        self.assertEqual(payload["verdict"], "pass")
        self.assertEqual(
            tuple(result["log_sha256"] for result in payload["results"]),
            tuple(result.log_sha256 for result in report.results),
        )
        for index, result in enumerate(payload["results"], start=1):
            self.assertEqual(result["index"], index)
            self.assertRegex(result["command_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                set(result),
                {
                    "index",
                    "command_sha256",
                    "started_at",
                    "ended_at",
                    "duration_seconds",
                    "exit_code",
                    "timed_out",
                    "truncated",
                    "log_path",
                    "log_sha256",
                    "log_size",
                },
            )
        self.assertEqual(
            report_path.read_bytes(),
            (
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
        )

    def test_report_keeps_command_names_and_sensitive_argv_hash_only(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "[REDACTED]-REDACTED-command",
                    (
                        sys.executable,
                        "-c",
                        "print('safe')",
                        "[REDACTED]",
                        "REDACTED",
                    ),
                    "unit",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)

        report = self.verifier(manifest, subject).verify(
            "run-001",
            verifier_actor="verifier-context",
            handoff_nonce=nonce,
            sensitive_values=("[REDACTED]", "REDACTED"),
        )

        report_path = self.run_directory / "verifications" / "verification-0001.json"
        report_bytes = report_path.read_bytes()
        self.assertNotIn(b"[REDACTED]", report_bytes)
        self.assertNotIn(b"REDACTED", report_bytes)
        self.assertNotIn("name", report.results[0].__dict__)
        self.assertNotIn("argv", report.results[0].__dict__)

    def test_zero_confirmed_verification_commands_blocks_without_execution(
        self,
    ) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec("placeholder", (sys.executable, "-c", "pass"), "unit"),
            ),
            release_required=False,
        )
        object.__setattr__(manifest, "verification_steps", ())
        subject, nonce = self.prepare_verification(manifest)
        runner = CountingRunner()

        with self.assertRaisesRegex(VerificationError, "no confirmed"):
            self.verifier(manifest, subject, runner=runner).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )

        self.assertEqual(runner.calls, 0)
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)

    def test_resolved_command_digest_drift_blocks_without_execution(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "pass",
                    (sys.executable, "-c", "pass", "${branch}"),
                    "unit",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        changed_variables = self.verification_variables()
        changed_variables["branch"] = "ship/changed"
        runner = CountingRunner()

        with self.assertRaisesRegex(VerificationError, "command"):
            self.verifier(
                manifest,
                subject,
                runner=runner,
                variables=changed_variables,
            ).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )

        self.assertEqual(runner.calls, 0)
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)

    def test_round_limit_blocks_a_new_candidate_before_running_commands(self) -> None:
        marker = self.root / "verification-runs"
        append_and_fail = (
            "from pathlib import Path; import sys; "
            "p=Path(sys.argv[1]); p.write_text(p.read_text()+'x' if p.exists() else 'x'); "
            "raise SystemExit(8)"
        )
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "always-fail",
                    (sys.executable, "-c", append_and_fail, str(marker)),
                    "unit",
                ),
            ),
            max_verification_rounds=1,
            release_required=False,
        )
        first_subject, first_nonce = self.prepare_verification(manifest)
        first = self.verifier(manifest, first_subject).verify(
            "run-001",
            verifier_actor="first-verifier",
            handoff_nonce=first_nonce,
            sensitive_values=(),
        )
        self.assertEqual(first.verdict, "fail")
        self.assertEqual(marker.read_text(), "x")

        (self.repo / "README.md").write_text("second candidate\n", encoding="utf-8")
        git(self.repo, "add", "README.md")
        git(self.repo, "commit", "-m", "second candidate")
        state = self.store.load()
        state = self.store.transition(
            Phase.CODE_REVIEW, expected_revision=state.revision
        )
        second_subject = EvidenceSubject(
            run_id="run-001",
            base_oid=self.base_oid,
            candidate_oid=git_output(self.repo, "rev-parse", "HEAD^{commit}"),
            tree_oid=git_output(self.repo, "rev-parse", "HEAD^{tree}"),
            plan_sha256="4" * 64,
            manifest_sha256=manifest_digest(manifest),
            commands_sha256=verification_commands_digest(
                manifest,
                self.verification_variables(),
            ),
            engine_version="0.1.0",
            schema_version=1,
        )
        review_nonce = issue_handoff(
            self.store,
            subject=second_subject,
            source_actor="second-developer",
            role=ReviewRole.REVIEWER,
        )
        record_code_review(
            self.store,
            current_subject=second_subject,
            reviewer_actor="second-reviewer",
            handoff_nonce=review_nonce,
            verdict="pass",
            findings=(),
        )
        second_nonce = issue_handoff(
            self.store,
            subject=second_subject,
            source_actor="second-reviewer",
            role=ReviewRole.VERIFIER,
        )

        with self.assertRaisesRegex(VerificationError, "round limit"):
            self.verifier(manifest, second_subject).verify(
                "run-001",
                verifier_actor="second-verifier",
                handoff_nonce=second_nonce,
                sensitive_values=(),
            )

        self.assertEqual(marker.read_text(), "x")
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)
        self.assertFalse(
            (self.run_directory / "verifications" / "verification-0002.json").exists()
        )

    def test_same_request_recovers_without_rerunning_after_publication_crashes(
        self,
    ) -> None:
        for crash_stage, drift in (
            ("report-written", None),
            ("handoff-consumed", None),
            ("state-transitioned", None),
            ("report-written", "dirty-candidate"),
            ("report-written", "stale-review"),
        ):
            with self.subTest(crash_stage=crash_stage, drift=drift):
                with tempfile.TemporaryDirectory() as temporary:
                    self.root = Path(temporary)
                    self.repo = self.root / "repo"
                    self.base_oid = initialize_repository(self.repo)
                    (self.root / "runtime").mkdir()
                    self.run_directory = self.root / "runtime" / "runs" / "run-001"
                    self.store = StateStore(self.run_directory)
                    marker = self.root / "verification-runs"
                    append = (
                        "from pathlib import Path; import sys; "
                        "p=Path(sys.argv[1]); "
                        "p.write_text(p.read_text()+'x' if p.exists() else 'x')"
                    )
                    manifest = Manifest(
                        project_name="fixture",
                        base_branch="main",
                        remote="origin",
                        verification_steps=(
                            CommandSpec(
                                "pass-once",
                                (sys.executable, "-c", append, str(marker)),
                                "unit",
                            ),
                        ),
                        release_required=False,
                    )
                    subject, nonce = self.prepare_verification(manifest)
                    real_stage_write = verify_module._write_verification_operation_stage
                    crashed = False

                    def crash_after_stage(
                        run_directory: Path,
                        operation: dict[str, object],
                        *,
                        stage: str,
                        trusted_root: object,
                    ) -> dict[str, object]:
                        nonlocal crashed
                        changed = real_stage_write(
                            run_directory,
                            operation,
                            stage=stage,
                            trusted_root=trusted_root,
                        )
                        if stage == crash_stage and not crashed:
                            crashed = True
                            raise OSError(f"crash after {stage}")
                        return changed

                    with mock.patch.object(
                        verify_module,
                        "_write_verification_operation_stage",
                        side_effect=crash_after_stage,
                    ):
                        with self.assertRaisesRegex(OSError, crash_stage):
                            self.verifier(manifest, subject).verify(
                                "run-001",
                                verifier_actor="verifier-context",
                                handoff_nonce=nonce,
                                sensitive_values=(),
                            )

                    self.assertEqual(marker.read_text(), "x")
                    if drift == "dirty-candidate":
                        (self.repo / "README.md").write_text(
                            "dirty after verification\n",
                            encoding="utf-8",
                        )
                    elif drift == "stale-review":
                        review_path = (
                            self.run_directory / "reviews" / "code-review.json"
                        )
                        review = json.loads(review_path.read_text(encoding="utf-8"))
                        review["subject_digest"] = "0" * 64
                        review_path.write_text(json.dumps(review), encoding="utf-8")
                    if drift is not None:
                        retry_runner = CountingRunner()
                        with self.assertRaisesRegex(
                            VerificationRecoveryError,
                            "stale",
                        ):
                            self.verifier(
                                manifest,
                                subject,
                                runner=retry_runner,
                            ).verify(
                                "run-001",
                                verifier_actor="verifier-context",
                                handoff_nonce=nonce,
                                sensitive_values=(),
                            )
                        self.assertEqual(retry_runner.calls, 0)
                        self.assertEqual(self.store.load().phase, Phase.BLOCKED)
                        self.assertNotEqual(
                            self.store.load().phase,
                            Phase.AWAITING_RELEASE_APPROVAL,
                        )
                        continue
                    recovered = self.verifier(manifest, subject).verify(
                        "run-001",
                        verifier_actor="verifier-context",
                        handoff_nonce=nonce,
                        sensitive_values=(),
                    )
                    self.assertEqual(recovered.verdict, "pass")
                    self.assertEqual(marker.read_text(), "x")
                    self.assertEqual(
                        self.store.load().phase,
                        Phase.AWAITING_RELEASE_APPROVAL,
                    )
                    self.assertFalse(
                        (self.run_directory / "verification-operation.json").exists()
                    )

    def test_fresh_process_resumes_verification_without_raw_handoff_nonce(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec("pass", (sys.executable, "-c", "pass"), "unit"),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        real_stage_write = verify_module._write_verification_operation_stage
        crashed = False

        def crash_after_report(
            run_directory: Path,
            operation: dict[str, object],
            *,
            stage: str,
            trusted_root: object,
        ) -> dict[str, object]:
            nonlocal crashed
            changed = real_stage_write(
                run_directory,
                operation,
                stage=stage,
                trusted_root=trusted_root,
            )
            if stage == "report-written" and not crashed:
                crashed = True
                raise OSError("simulated crash after verification report")
            return changed

        with mock.patch.object(
            verify_module,
            "_write_verification_operation_stage",
            side_effect=crash_after_report,
        ):
            with self.assertRaisesRegex(OSError, "verification report"):
                self.verifier(manifest, subject).verify(
                    "run-001",
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )

        del nonce
        runner = CountingRunner()
        restarted = self.verifier(manifest, subject, runner=runner)
        report = restarted.resume_publication()

        self.assertEqual(report.verdict, "pass")
        self.assertEqual(runner.calls, 0)
        self.assertEqual(
            self.store.load().phase,
            Phase.AWAITING_RELEASE_APPROVAL,
        )
        self.assertFalse((self.run_directory / "verification-operation.json").exists())

    def test_fresh_resume_blocks_missing_code_review_seal_without_rerun(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec("pass", (sys.executable, "-c", "pass"), "unit"),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        with mock.patch.object(
            Verifier,
            "_recover_operation",
            side_effect=OSError("crash after sealed verification publication"),
        ):
            with self.assertRaisesRegex(OSError, "sealed verification"):
                self.verifier(manifest, subject).verify(
                    "run-001",
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )
        next((self.run_directory / "review-publications").glob("code-*.json")).unlink()
        runner = CountingRunner()

        with self.assertRaises(VerificationRecoveryError):
            self.verifier(manifest, subject, runner=runner).resume_publication()

        self.assertEqual(runner.calls, 0)
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)

    def test_fresh_resume_blocks_tampered_log_without_rerun(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec("pass", (sys.executable, "-c", "pass"), "unit"),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        with mock.patch.object(
            Verifier,
            "_recover_operation",
            side_effect=OSError("crash after sealed verification publication"),
        ):
            with self.assertRaisesRegex(OSError, "sealed verification"):
                self.verifier(manifest, subject).verify(
                    "run-001",
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )
        operation = json.loads(
            (self.run_directory / "verification-operation.json").read_text(
                encoding="utf-8"
            )
        )
        log_path = Path(operation["report"]["results"][0]["log_path"])
        log_path.write_bytes(log_path.read_bytes() + b"tampered\n")
        runner = CountingRunner()

        with self.assertRaises(VerificationRecoveryError):
            self.verifier(manifest, subject, runner=runner).resume_publication()

        self.assertEqual(runner.calls, 0)
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)

    def test_terminal_receipt_log_tampering_blocks_retry_without_rerun(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec("pass", (sys.executable, "-c", "pass"), "unit"),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        with mock.patch.object(
            verify_module,
            "_prepare_verification_operation",
            side_effect=OSError("crash before verification operation"),
        ):
            with self.assertRaisesRegex(OSError, "verification operation"):
                self.verifier(manifest, subject).verify(
                    "run-001",
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )
        self.assertFalse((self.run_directory / "verification-operation.json").exists())
        receipt = json.loads(self.execution_receipt_path().read_text(encoding="utf-8"))
        log_path = Path(receipt["result"]["log_path"])
        log_path.write_bytes(log_path.read_bytes() + b"tampered\n")
        runner = CountingRunner()

        with self.assertRaises(VerificationRecoveryError):
            self.verifier(manifest, subject, runner=runner).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )

        self.assertEqual(runner.calls, 0)
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)

    def test_fresh_resume_blocks_nonfinite_operation_as_recovery_error(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec("pass", (sys.executable, "-c", "pass"), "unit"),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        with mock.patch.object(
            Verifier,
            "_recover_operation",
            side_effect=OSError("crash after verification publication"),
        ):
            with self.assertRaisesRegex(OSError, "publication"):
                self.verifier(manifest, subject).verify(
                    "run-001",
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )
        (self.run_directory / "verification-operation.json").write_bytes(
            b'{"nonfinite":NaN}\n'
        )

        with self.assertRaises(VerificationRecoveryError):
            self.verifier(
                manifest, subject, runner=CountingRunner()
            ).resume_publication()

        self.assertEqual(self.store.load().phase, Phase.BLOCKED)

    def test_completed_recovery_rejects_run_directory_replacement_before_read(
        self,
    ) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "fail",
                    (sys.executable, "-c", "raise SystemExit(7)"),
                    "unit",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        with mock.patch.object(
            verify_module,
            "_remove_durable_file",
            side_effect=OSError("crash before receipt removal"),
        ):
            with self.assertRaisesRegex(OSError, "receipt removal"):
                self.verifier(manifest, subject).verify(
                    "run-001",
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )
        operation = json.loads(
            (self.run_directory / "verification-operation.json").read_text(
                encoding="utf-8"
            )
        )
        verifier = self.verifier(manifest, subject, runner=CountingRunner())
        detached = verifier.run_directory.with_name("run-001-completed-detached")
        lock = FileLock(
            verifier.run_directory / "verification.lock",
            private_root=verifier.run_directory,
        )
        with (
            lock as acquired_lock,
            verifier.store.anchored(acquired_lock.trusted_parent),
        ):
            os.rename(verifier.run_directory, detached)
            shutil.copytree(
                detached,
                verifier.run_directory,
                copy_function=shutil.copy2,
            )
            with self.assertRaisesRegex(
                VerificationRecoveryError,
                "directory changed",
            ):
                verifier._reconcile_completed_operation(operation)

        self.assertTrue(
            (detached / "verification-operation.json").is_file(),
        )

    def test_symlinked_publication_directory_blocks_before_any_command(self) -> None:
        marker = self.root / "must-not-run"
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "must-not-run",
                    (
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                        str(marker),
                    ),
                    "unit",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        outside = self.root / "outside-publications"
        outside.mkdir()
        (self.run_directory / "verification-publications").symlink_to(
            outside,
            target_is_directory=True,
        )

        with self.assertRaises(VerificationRecoveryError):
            self.verifier(manifest, subject).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )

        self.assertFalse(marker.exists())
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)

    def test_fresh_resume_rejects_run_directory_replacement_after_lock(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec("pass", (sys.executable, "-c", "pass"), "unit"),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        real_stage_write = verify_module._write_verification_operation_stage
        crashed = False

        def crash_after_report(
            run_directory: Path,
            operation: dict[str, object],
            *,
            stage: str,
            trusted_root: object,
        ) -> dict[str, object]:
            nonlocal crashed
            changed = real_stage_write(
                run_directory,
                operation,
                stage=stage,
                trusted_root=trusted_root,
            )
            if stage == "report-written" and not crashed:
                crashed = True
                raise OSError("simulated crash after verification report")
            return changed

        with mock.patch.object(
            verify_module,
            "_write_verification_operation_stage",
            side_effect=crash_after_report,
        ):
            with self.assertRaisesRegex(OSError, "verification report"):
                self.verifier(manifest, subject).verify(
                    "run-001",
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )

        detached = self.run_directory.with_name("run-001-detached")
        real_validate = verify_module.validate_recoverable_verification_publication
        replaced = False

        def replace_root_after_lock(*args: object, **kwargs: object) -> object:
            nonlocal replaced
            if not replaced:
                replaced = True
                os.rename(self.run_directory, detached)
                shutil.copytree(
                    detached, self.run_directory, copy_function=shutil.copy2
                )
            return real_validate(*args, **kwargs)

        del nonce
        runner = CountingRunner()
        restarted = self.verifier(manifest, subject, runner=runner)
        with mock.patch.object(
            verify_module,
            "validate_recoverable_verification_publication",
            side_effect=replace_root_after_lock,
        ):
            with self.assertRaisesRegex(VerificationRecoveryError, "directory changed"):
                restarted.resume_publication()

        self.assertEqual(runner.calls, 0)
        self.assertEqual(StateStore(self.run_directory).load().phase, Phase.VERIFYING)
        self.assertEqual(StateStore(detached).load().phase, Phase.BLOCKED)

    def test_tampered_terminal_receipt_blocks_publication_recovery(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "fail",
                    (sys.executable, "-c", "raise SystemExit(7)"),
                    "unit",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        real_stage_write = verify_module._write_verification_operation_stage

        def crash_after_report(
            run_directory: Path,
            operation: dict[str, object],
            *,
            stage: str,
            trusted_root: object,
        ) -> dict[str, object]:
            changed = real_stage_write(
                run_directory,
                operation,
                stage=stage,
                trusted_root=trusted_root,
            )
            if stage == "report-written":
                raise OSError("crash after report-written")
            return changed

        with mock.patch.object(
            verify_module,
            "_write_verification_operation_stage",
            side_effect=crash_after_report,
        ):
            with self.assertRaisesRegex(OSError, "report-written"):
                self.verifier(manifest, subject).verify(
                    "run-001",
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )

        receipt_path = self.execution_receipt_path()
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "FAILED")
        self.assertEqual(receipt["result"]["exit_code"], 7)
        receipt["status"] = "SUCCEEDED"
        receipt["result"]["exit_code"] = 0
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

        retry_runner = CountingRunner()
        with self.assertRaises(VerificationRecoveryError):
            self.verifier(manifest, subject, runner=retry_runner).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )

        self.assertEqual(retry_runner.calls, 0)
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)

    def test_prepared_publication_pointer_survives_crash_before_seal(self) -> None:
        marker = self.root / "verification-runs"
        append = (
            "from pathlib import Path; import sys; p=Path(sys.argv[1]); "
            "p.write_text(p.read_text()+'x' if p.exists() else 'x')"
        )
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "pass-once",
                    (sys.executable, "-c", append, str(marker)),
                    "unit",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        real_write = verify_module._write_immutable_json
        crashed = False

        def crash_before_publication_seal(
            path: Path,
            payload: dict[str, object],
            *,
            trusted_root: object,
        ) -> None:
            nonlocal crashed
            if path.parent.name == "verification-publications" and not crashed:
                crashed = True
                raise OSError("crash before publication seal")
            real_write(path, payload, trusted_root=trusted_root)

        with mock.patch.object(
            verify_module,
            "_write_immutable_json",
            side_effect=crash_before_publication_seal,
        ):
            with self.assertRaisesRegex(OSError, "publication seal"):
                self.verifier(manifest, subject).verify(
                    "run-001",
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )

        operation_path = self.run_directory / "verification-operation.json"
        self.assertTrue(operation_path.exists())
        prepared = json.loads(operation_path.read_text(encoding="utf-8"))
        self.assertEqual(prepared["stage"], "prepared")
        self.assertEqual(marker.read_text(), "x")
        self.assertFalse(
            list((self.run_directory / "verification-publications").glob("*.json"))
        )

        recovered = self.verifier(manifest, subject).verify(
            "run-001",
            verifier_actor="verifier-context",
            handoff_nonce=nonce,
            sensitive_values=(),
        )

        seals = list((self.run_directory / "verification-publications").glob("*.json"))
        self.assertEqual(recovered.recorded_at, prepared["report"]["recorded_at"])
        self.assertEqual(marker.read_text(), "x")
        self.assertEqual(len(seals), 1)
        self.assertFalse(operation_path.exists())

    def test_completed_old_receipt_reconciles_before_a_new_round(self) -> None:
        marker = self.root / "verification-runs"
        fail_once = (
            "from pathlib import Path; import sys; p=Path(sys.argv[1]); "
            "old=p.read_text() if p.exists() else ''; p.write_text(old+'x'); "
            "raise SystemExit(7 if not old else 0)"
        )
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "fail-once",
                    (sys.executable, "-c", fail_once, str(marker)),
                    "unit",
                ),
            ),
            release_required=False,
        )
        first_subject, first_nonce = self.prepare_verification(manifest)

        with mock.patch.object(
            verify_module,
            "_remove_durable_file",
            side_effect=OSError("crash before publication receipt removal"),
        ):
            with self.assertRaisesRegex(OSError, "receipt removal"):
                self.verifier(manifest, first_subject).verify(
                    "run-001",
                    verifier_actor="first-verifier",
                    handoff_nonce=first_nonce,
                    sensitive_values=(),
                )

        self.assertEqual(marker.read_text(), "x")
        self.assertEqual(self.store.load().phase, Phase.DEVELOPING)
        operation_path = self.run_directory / "verification-operation.json"
        self.assertEqual(
            json.loads(operation_path.read_text())["stage"],
            "state-transitioned",
        )

        (self.repo / "README.md").write_text("second candidate\n", encoding="utf-8")
        git(self.repo, "add", "README.md")
        git(self.repo, "commit", "-m", "second candidate")
        state = self.store.transition(
            Phase.CODE_REVIEW,
            expected_revision=self.store.load().revision,
        )
        second_subject = EvidenceSubject(
            run_id="run-001",
            base_oid=self.base_oid,
            candidate_oid=git_output(self.repo, "rev-parse", "HEAD^{commit}"),
            tree_oid=git_output(self.repo, "rev-parse", "HEAD^{tree}"),
            plan_sha256="4" * 64,
            manifest_sha256=manifest_digest(manifest),
            commands_sha256=verification_commands_digest(
                manifest,
                self.verification_variables(),
            ),
            engine_version="0.1.0",
            schema_version=1,
        )
        review_nonce = issue_handoff(
            self.store,
            subject=second_subject,
            source_actor="second-developer",
            role=ReviewRole.REVIEWER,
        )
        record_code_review(
            self.store,
            current_subject=second_subject,
            reviewer_actor="second-reviewer",
            handoff_nonce=review_nonce,
            verdict="pass",
            findings=(),
        )
        second_nonce = issue_handoff(
            self.store,
            subject=second_subject,
            source_actor="second-reviewer",
            role=ReviewRole.VERIFIER,
        )
        self.assertGreater(self.store.load().revision, state.revision)

        report = self.verifier(manifest, second_subject).verify(
            "run-001",
            verifier_actor="second-verifier",
            handoff_nonce=second_nonce,
            sensitive_values=(),
        )

        self.assertEqual(report.round, 2)
        self.assertEqual(report.verdict, "pass")
        self.assertEqual(marker.read_text(), "xx")
        self.assertEqual(self.store.load().phase, Phase.AWAITING_RELEASE_APPROVAL)
        self.assertFalse(operation_path.exists())

    def test_prepared_execution_receipt_is_safe_to_resume_before_invocation(
        self,
    ) -> None:
        marker = self.root / "verification-runs"
        append = (
            "from pathlib import Path; import sys; p=Path(sys.argv[1]); "
            "p.write_text(p.read_text()+'x' if p.exists() else 'x')"
        )
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "pass-once",
                    (sys.executable, "-c", append, str(marker)),
                    "unit",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        real_stage_write = verify_module._write_execution_receipt_stage
        crashed = False

        def crash_after_prepared(
            path: Path,
            receipt: dict[str, object],
            *,
            status: str,
            trusted_root: object,
            result: dict[str, object] | None = None,
        ) -> dict[str, object]:
            nonlocal crashed
            changed = real_stage_write(
                path,
                receipt,
                status=status,
                trusted_root=trusted_root,
                result=result,
            )
            if status == "PREPARED" and not crashed:
                crashed = True
                raise OSError("crash after PREPARED")
            return changed

        with mock.patch.object(
            verify_module,
            "_write_execution_receipt_stage",
            side_effect=crash_after_prepared,
        ):
            with self.assertRaisesRegex(OSError, "PREPARED"):
                self.verifier(manifest, subject).verify(
                    "run-001",
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )

        self.assertFalse(marker.exists())
        self.assertEqual(
            json.loads(self.execution_receipt_path().read_text())["status"],
            "PREPARED",
        )
        recovered = self.verifier(manifest, subject).verify(
            "run-001",
            verifier_actor="verifier-context",
            handoff_nonce=nonce,
            sensitive_values=(),
        )
        self.assertEqual(recovered.verdict, "pass")
        self.assertEqual(marker.read_text(), "x")

    def test_running_receipt_before_invocation_becomes_unknown_without_replay(
        self,
    ) -> None:
        marker = self.root / "verification-runs"
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "must-not-run",
                    (
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                        str(marker),
                    ),
                    "unit",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        real_stage_write = verify_module._write_execution_receipt_stage
        crashed = False

        def crash_after_running(
            path: Path,
            receipt: dict[str, object],
            *,
            status: str,
            trusted_root: object,
            result: dict[str, object] | None = None,
        ) -> dict[str, object]:
            nonlocal crashed
            changed = real_stage_write(
                path,
                receipt,
                status=status,
                trusted_root=trusted_root,
                result=result,
            )
            if status == "RUNNING" and not crashed:
                crashed = True
                raise OSError("crash after RUNNING")
            return changed

        with mock.patch.object(
            verify_module,
            "_write_execution_receipt_stage",
            side_effect=crash_after_running,
        ):
            with self.assertRaisesRegex(OSError, "RUNNING"):
                self.verifier(manifest, subject).verify(
                    "run-001",
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )

        self.assertFalse(marker.exists())
        retry_runner = CountingRunner()
        with self.assertRaisesRegex(VerificationRecoveryError, "UNKNOWN"):
            self.verifier(manifest, subject, runner=retry_runner).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )
        self.assertEqual(retry_runner.calls, 0)
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)
        self.assertEqual(
            json.loads(self.execution_receipt_path().read_text())["status"],
            "UNKNOWN",
        )

    def test_effect_before_terminal_receipt_is_unknown_and_never_replayed(
        self,
    ) -> None:
        marker = self.root / "verification-runs"
        append = (
            "from pathlib import Path; import sys; p=Path(sys.argv[1]); "
            "p.write_text(p.read_text()+'x' if p.exists() else 'x')"
        )
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "effect",
                    (sys.executable, "-c", append, str(marker)),
                    "unit",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        real_stage_write = verify_module._write_execution_receipt_stage

        def crash_before_terminal(
            path: Path,
            receipt: dict[str, object],
            *,
            status: str,
            trusted_root: object,
            result: dict[str, object] | None = None,
        ) -> dict[str, object]:
            if status == "SUCCEEDED":
                raise OSError("crash before terminal receipt")
            return real_stage_write(
                path,
                receipt,
                status=status,
                trusted_root=trusted_root,
                result=result,
            )

        with mock.patch.object(
            verify_module,
            "_write_execution_receipt_stage",
            side_effect=crash_before_terminal,
        ):
            with self.assertRaisesRegex(OSError, "terminal receipt"):
                self.verifier(manifest, subject).verify(
                    "run-001",
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )

        self.assertEqual(marker.read_text(), "x")
        retry_runner = CountingRunner()
        with self.assertRaisesRegex(VerificationRecoveryError, "UNKNOWN"):
            self.verifier(manifest, subject, runner=retry_runner).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )
        self.assertEqual(retry_runner.calls, 0)
        self.assertEqual(marker.read_text(), "x")

    def test_runner_exception_is_recorded_unknown_and_blocks_retry(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec("raises", (sys.executable, "-c", "pass"), "unit"),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        runner = RaisingRunner()

        with self.assertRaisesRegex(VerificationRecoveryError, "UNKNOWN"):
            self.verifier(manifest, subject, runner=runner).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )

        self.assertEqual(runner.calls, 1)
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)
        self.assertEqual(
            json.loads(self.execution_receipt_path().read_text())["status"],
            "UNKNOWN",
        )
        retry_runner = CountingRunner()
        with self.assertRaisesRegex(VerificationRecoveryError, "UNKNOWN"):
            self.verifier(manifest, subject, runner=retry_runner).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )
        self.assertEqual(retry_runner.calls, 0)

    def test_foreign_receipt_blocks_without_running_commands(self) -> None:
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec("pass", (sys.executable, "-c", "pass"), "unit"),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        receipt_path = self.run_directory / "verification-operation.json"
        receipt_path.write_text('{"foreign":true}\n', encoding="utf-8")
        receipt_path.chmod(0o600)
        runner = CountingRunner()

        with self.assertRaisesRegex(VerificationRecoveryError, "receipt"):
            self.verifier(manifest, subject, runner=runner).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )

        self.assertEqual(runner.calls, 0)
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)

    def test_foreign_round_report_blocks_before_running_commands(self) -> None:
        marker = self.root / "command-ran"
        manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "pass",
                    (
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                        str(marker),
                    ),
                    "unit",
                ),
            ),
            release_required=False,
        )
        subject, nonce = self.prepare_verification(manifest)
        report_directory = self.run_directory / "verifications"
        report_directory.mkdir(mode=0o700)
        report_path = report_directory / "verification-0001.json"
        report_path.write_text('{"foreign":true}\n', encoding="utf-8")
        report_path.chmod(0o600)

        with self.assertRaisesRegex(VerificationRecoveryError, "report"):
            self.verifier(manifest, subject).verify(
                "run-001",
                verifier_actor="verifier-context",
                handoff_nonce=nonce,
                sensitive_values=(),
            )

        self.assertFalse(marker.exists())
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)


if __name__ == "__main__":
    unittest.main()
