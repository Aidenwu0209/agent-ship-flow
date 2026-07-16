from __future__ import annotations

import json
import hashlib
import os
import shutil
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ship_flow import gitops as gitops_module
from ship_flow import reconcile as reconcile_module
from ship_flow import release as release_module
from ship_flow.gitops import (
    CandidateCommitPartialError,
    GitRepository,
    OwnershipError,
    commit_candidate,
    create_run_worktree,
    load_run_worktree,
)
from ship_flow.manifest import CommandSpec, Manifest, manifest_digest, write_manifest
from ship_flow.model import OperationStatus, Phase, RunState
from ship_flow.reconcile import (
    EvidenceInventory,
    EvidenceStatus,
    NextAction,
    PlanApprovalRecord,
    ReconciliationRecoveryError,
    Reconciler,
    next_action,
    record_plan_approval,
)
from ship_flow.review import (
    ReviewRole,
    issue_handoff,
    record_code_review,
    record_plan_review,
)
from ship_flow.release import OperationRecord
from ship_flow.store import (
    FileLock,
    InvalidTransitionError,
    LockUnavailableError,
    StateStore,
)
from ship_flow.subject import EvidenceSubject
from ship_flow.sync import SyncItem, SyncRecorder, SyncReportDraft
from ship_flow.verify import Verifier, verification_commands_digest
from tests.support import git, git_output, initialize_repository


class ReconciliationImportTests(unittest.TestCase):
    def test_public_reconciliation_interfaces_import(self) -> None:
        self.assertTrue(load_run_worktree)
        self.assertTrue(EvidenceInventory)
        self.assertTrue(EvidenceStatus)
        self.assertTrue(NextAction)
        self.assertTrue(PlanApprovalRecord)
        self.assertTrue(Reconciler)
        self.assertTrue(record_plan_approval)
        self.assertTrue(next_action)


class ReconciliationCanonicalEvidenceTests(unittest.TestCase):
    def test_nonfinite_private_json_is_a_recovery_error(self) -> None:
        for token in ("NaN", "Infinity"):
            with self.subTest(token=token), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                root.chmod(0o700)
                evidence = root / "evidence.json"
                evidence.write_bytes(f'{{"value":{token}}}\n'.encode("ascii"))
                evidence.chmod(0o600)

                with self.assertRaises(ReconciliationRecoveryError):
                    reconcile_module._read_private_canonical_json(
                        evidence,
                        root=root,
                        label="test evidence",
                    )


class RunWorktreeLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.primary = self.root / "中文 repo"
        initialize_repository(self.primary)
        self.repository = GitRepository.discover(self.primary)
        self.ownership = create_run_worktree(
            self.repository,
            run_id="run-load-001",
            branch="ship/load-001",
            worktree_path=self.root / "owned worktree",
        )

    def test_load_run_worktree_returns_only_fully_validated_ownership(self) -> None:
        loaded = load_run_worktree(self.repository, "run-load-001")

        self.assertEqual(loaded, self.ownership)

    def test_load_run_worktree_rejects_tampered_or_replaced_records(self) -> None:
        original = self.ownership.record_path.read_bytes()
        payload = json.loads(original)
        payload["branch"] = "ship/foreign"
        self.ownership.record_path.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(self.ownership.record_path, 0o600)

        with self.assertRaises(OwnershipError):
            load_run_worktree(self.repository, "run-load-001")

        self.ownership.record_path.unlink()
        self.ownership.record_path.symlink_to(self.primary / "README.md")
        with self.assertRaises(OwnershipError):
            load_run_worktree(self.repository, "run-load-001")

    def test_load_run_worktree_rejects_unsafe_run_identity(self) -> None:
        with self.assertRaises(ValueError):
            load_run_worktree(self.repository, "../run-load-001")

    def test_load_run_worktree_finishes_an_owned_candidate_publication(self) -> None:
        (self.ownership.worktree_path / "feature.txt").write_text(
            "candidate\n", encoding="utf-8"
        )
        with mock.patch.object(
            gitops_module,
            "_replace_ownership_record",
            side_effect=OSError("simulated ownership publication crash"),
        ):
            with self.assertRaises(CandidateCommitPartialError):
                commit_candidate(
                    self.ownership,
                    message="candidate",
                    approved_paths=("feature.txt",),
                )

        loaded = load_run_worktree(self.repository, "run-load-001")

        self.assertEqual(
            loaded.last_known_oid,
            git_output(loaded.worktree_path, "rev-parse", "HEAD^{commit}"),
        )
        self.assertFalse(
            (loaded.record_path.parent / "candidate-operation.json").exists()
        )

    def test_load_run_worktree_rejects_symlinked_runtime_ancestor(self) -> None:
        runs = self.ownership.record_path.parent.parent
        real_runs = runs.with_name("runs-real")
        runs.rename(real_runs)
        runs.symlink_to(real_runs, target_is_directory=True)

        with self.assertRaises(OwnershipError):
            load_run_worktree(self.repository, "run-load-001")

    def test_load_run_worktree_rejects_oversized_ownership_json(self) -> None:
        self.ownership.record_path.write_bytes(b"{" + b" " * 70_000 + b"}")
        os.chmod(self.ownership.record_path, 0o600)

        with mock.patch.object(
            gitops_module.json,
            "loads",
            side_effect=AssertionError("oversized JSON must not be parsed"),
        ):
            with self.assertRaises(OwnershipError):
                load_run_worktree(self.repository, "run-load-001")


class ReconciliationStateTransitionTests(unittest.TestCase):
    def test_reconciliation_uses_a_distinct_audited_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            runtime.mkdir()
            store = StateStore(runtime / "runs" / "run-state")
            state = store.create("run-state")
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

            with self.assertRaises(InvalidTransitionError):
                store.transition(Phase.CODE_REVIEW, expected_revision=state.revision)

            state = store.reconcile_transition(
                Phase.CODE_REVIEW,
                expected_revision=state.revision,
                reason="candidate-needs-current-code-review",
            )

            self.assertEqual(state.phase, Phase.CODE_REVIEW)
            self.assertEqual(store.events()[-1].event_type, "phase.reconciled")
            self.assertEqual(
                store.events()[-1].reconciliation_reason,
                "candidate-needs-current-code-review",
            )


class PlanApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.primary = self.root / "repo"
        initialize_repository(self.primary)
        self.manifest = Manifest(
            project_name="fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "unit",
                    (sys.executable, "-c", "pass"),
                    "unit",
                    timeout_seconds=5,
                ),
            ),
            release_required=False,
        )
        write_manifest(self.primary / ".ship" / "manifest.toml", self.manifest)
        git(self.primary, "add", ".ship/manifest.toml")
        git(self.primary, "commit", "-m", "add manifest")
        self.repository = GitRepository.discover(self.primary)
        self.ownership = create_run_worktree(
            self.repository,
            run_id="run-plan-001",
            branch="ship/plan-001",
            worktree_path=self.root / "run worktree",
            base_ref="main",
        )
        self.run_directory = self.ownership.record_path.parent
        self.store = StateStore(self.run_directory)
        state = self.store.create("run-plan-001")
        self.plan_path = self.run_directory / "plan.md"
        self.plan_path.write_text("# Plan\n\nShip safely.\n", encoding="utf-8")
        os.chmod(self.plan_path, 0o600)
        for phase in (Phase.PLANNING, Phase.PLAN_REVIEW):
            state = self.store.transition(phase, expected_revision=state.revision)
        self.variables = {
            "repo": str(self.ownership.primary_checkout),
            "worktree": str(self.ownership.worktree_path),
            "branch": self.ownership.branch,
            "base_branch": self.manifest.base_branch,
            "remote": self.manifest.remote,
        }
        self.subject = EvidenceSubject(
            run_id="run-plan-001",
            base_oid=self.ownership.base_oid,
            candidate_oid=git_output(
                self.ownership.worktree_path, "rev-parse", "HEAD^{commit}"
            ),
            tree_oid=git_output(
                self.ownership.worktree_path, "rev-parse", "HEAD^{tree}"
            ),
            plan_sha256=hashlib.sha256(self.plan_path.read_bytes()).hexdigest(),
            manifest_sha256=manifest_digest(self.manifest),
            commands_sha256=verification_commands_digest(self.manifest, self.variables),
            engine_version="0.1.0",
            schema_version=1,
        )
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        record_plan_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="plan-critic-context",
            handoff_nonce=nonce,
            verdict="pass",
            findings=(),
        )

    def prepare_code_review(self) -> EvidenceSubject:
        record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )
        (self.ownership.worktree_path / "feature.txt").write_text(
            "implemented\n", encoding="utf-8"
        )
        commit_candidate(
            self.ownership,
            message="implement feature",
            approved_paths=("feature.txt",),
        )
        run = Reconciler(self.repository).reconcile("run-plan-001")
        self.assertEqual(run.state.phase, Phase.CODE_REVIEW)
        return run.subject

    def prepare_verifying(self) -> EvidenceSubject:
        subject = self.prepare_code_review()
        nonce = issue_handoff(
            self.store,
            subject=subject,
            source_actor="developer-context",
            role=ReviewRole.REVIEWER,
        )
        record_code_review(
            self.store,
            current_subject=subject,
            reviewer_actor="reviewer-context",
            handoff_nonce=nonce,
            verdict="pass",
            findings=(),
        )
        self.assertEqual(self.store.load().phase, Phase.VERIFYING)
        return subject

    def prepare_release_gate(self) -> EvidenceSubject:
        subject = self.prepare_verifying()
        nonce = issue_handoff(
            self.store,
            subject=subject,
            source_actor="reviewer-context",
            role=ReviewRole.VERIFIER,
        )
        Verifier(
            repo=self.ownership.worktree_path,
            run_directory=self.run_directory,
            manifest=self.manifest,
            current_subject=subject,
            variables=self.variables,
        ).verify(
            "run-plan-001",
            verifier_actor="verifier-context",
            handoff_nonce=nonce,
            sensitive_values=(),
        )
        self.assertEqual(
            self.store.load().phase,
            Phase.AWAITING_RELEASE_APPROVAL,
        )
        return subject

    def test_plan_approval_is_immutable_idempotent_and_candidate_independent(
        self,
    ) -> None:
        approval = record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )
        repeated = record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )

        self.assertEqual(repeated, approval)
        self.assertEqual(self.store.load().phase, Phase.DEVELOPING)
        approval_path = (
            self.run_directory / "approvals" / "plan" / f"{approval.approval_id}.json"
        )
        self.assertTrue(approval_path.is_file())
        self.assertEqual(approval_path.stat().st_mode & 0o777, 0o600)
        payload = json.loads(approval_path.read_text(encoding="utf-8"))
        self.assertNotIn("candidate_oid", payload)
        self.assertNotIn("tree_oid", payload)
        self.assertEqual(payload["plan_sha256"], self.subject.plan_sha256)
        self.assertEqual(payload["manifest_sha256"], self.subject.manifest_sha256)
        self.assertRegex(payload["plan_review_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(list(approval_path.parent.glob("*.json"))), 1)

    def test_dirty_worktree_at_plan_gate_never_bypasses_human_approval(self) -> None:
        before = self.store.load()
        (self.ownership.worktree_path / "unapproved.txt").write_text(
            "not approved\n",
            encoding="utf-8",
        )

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.AWAITING_PLAN_APPROVAL)
        self.assertEqual(run.state.revision, before.revision)
        self.assertEqual(run.reason, "awaiting-plan-approval-worktree-dirty")
        self.assertEqual(next_action(run).kind, "human")

    def test_plan_approval_recovers_seal_before_transition_and_rejects_conflict(
        self,
    ) -> None:
        with mock.patch.object(
            self.store,
            "transition",
            side_effect=RuntimeError("simulated crash after seal"),
        ):
            with self.assertRaises(RuntimeError):
                record_plan_approval(
                    self.store,
                    current_subject=self.subject,
                    approver_actor="human-owner",
                )

        self.assertEqual(self.store.load().phase, Phase.AWAITING_PLAN_APPROVAL)
        self.assertTrue((self.run_directory / "plan-approval-operation.json").is_file())
        self.assertEqual(
            len(list((self.run_directory / "approvals" / "plan").glob("*.json"))),
            1,
        )
        with self.assertRaises(ReconciliationRecoveryError):
            record_plan_approval(
                self.store,
                current_subject=self.subject,
                approver_actor="different-human",
            )

        recovered = record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )

        self.assertEqual(self.store.load().phase, Phase.DEVELOPING)
        self.assertFalse((self.run_directory / "plan-approval-operation.json").exists())
        self.assertEqual(
            record_plan_approval(
                self.store,
                current_subject=self.subject,
                approver_actor="human-owner",
            ),
            recovered,
        )

    def test_status_finishes_a_valid_pending_plan_approval_publication(self) -> None:
        with mock.patch.object(
            self.store,
            "transition",
            side_effect=RuntimeError("simulated crash after plan approval seal"),
        ):
            with self.assertRaises(RuntimeError):
                record_plan_approval(
                    self.store,
                    current_subject=self.subject,
                    approver_actor="human-owner",
                )

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.DEVELOPING)
        self.assertEqual(run.evidence.plan_approval, EvidenceStatus.CURRENT)
        self.assertFalse((self.run_directory / "plan-approval-operation.json").exists())
        self.assertEqual(next_action(run).action, "develop")

    def test_plan_approval_revalidates_consumed_plan_critic_handoff(self) -> None:
        report = json.loads(
            (self.run_directory / "reviews" / "plan-review.json").read_text(
                encoding="utf-8"
            )
        )
        handoff_path = (
            self.run_directory / "handoffs" / f"{report['handoff_nonce_sha256']}.json"
        )
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        handoff["consumed_by"] = "foreign-reviewer"
        handoff_path.write_text(
            json.dumps(
                handoff,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(handoff_path, 0o600)

        with self.assertRaises(ReconciliationRecoveryError):
            record_plan_approval(
                self.store,
                current_subject=self.subject,
                approver_actor="human-owner",
            )

    def test_clean_engine_owned_candidate_returns_to_code_review_and_keeps_plan_approval(
        self,
    ) -> None:
        approval = record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )
        (self.ownership.worktree_path / "feature.txt").write_text(
            "implemented\n", encoding="utf-8"
        )
        commit_candidate(
            self.ownership,
            message="implement feature",
            approved_paths=("feature.txt",),
        )

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.CODE_REVIEW)
        self.assertEqual(run.plan_approval, approval)
        self.assertNotEqual(run.subject.candidate_oid, run.subject.base_oid)
        self.assertEqual(
            len(list((self.run_directory / "approvals" / "plan").glob("*.json"))),
            1,
        )

    def test_dirty_worktree_reconciles_back_to_developing(self) -> None:
        record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )
        state = self.store.load()
        self.store.transition(Phase.CODE_REVIEW, expected_revision=state.revision)
        (self.ownership.worktree_path / "dirty.txt").write_text(
            "not committed\n", encoding="utf-8"
        )

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.DEVELOPING)
        self.assertEqual(self.store.events()[-1].event_type, "phase.reconciled")

    def test_plan_drift_returns_to_planning_and_preserves_history(self) -> None:
        approval = record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )
        state = self.store.load()
        self.store.transition(Phase.CODE_REVIEW, expected_revision=state.revision)
        self.plan_path.write_text(
            "# Changed plan\n\nDifferent scope.\n",
            encoding="utf-8",
        )

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.PLANNING)
        self.assertIsNone(run.plan_approval)
        self.assertEqual(run.evidence.plan_approval, EvidenceStatus.STALE)
        self.assertTrue(
            (
                self.run_directory
                / "approvals"
                / "plan"
                / f"{approval.approval_id}.json"
            ).is_file()
        )

    def test_deleted_approved_plan_seal_blocks_when_plan_is_unchanged(self) -> None:
        approval = record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )
        approval_path = (
            self.run_directory / "approvals" / "plan" / f"{approval.approval_id}.json"
        )
        approval_path.unlink()

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.BLOCKED)
        self.assertEqual(run.reason, "plan-approval-evidence-missing")
        self.assertEqual(run.evidence.plan_approval, EvidenceStatus.MISSING)
        self.assertEqual(next_action(run).kind, "manual")

        restarted = Reconciler(self.repository).reconcile("run-plan-001")
        self.assertEqual(restarted.state.phase, Phase.BLOCKED)
        self.assertEqual(restarted.reason, "plan-approval-evidence-missing")
        self.assertEqual(next_action(restarted).kind, "manual")

    def test_corrupt_approved_plan_seal_blocks_when_plan_is_unchanged(self) -> None:
        approval = record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )
        approval_path = (
            self.run_directory / "approvals" / "plan" / f"{approval.approval_id}.json"
        )
        approval_path.write_text("{}\n", encoding="utf-8")
        approval_path.chmod(0o600)

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.BLOCKED)
        self.assertEqual(run.reason, "plan-approval-evidence-invalid")
        self.assertEqual(run.evidence.plan_approval, EvidenceStatus.INVALID)

    def test_normalized_manifest_drift_returns_to_planning(self) -> None:
        record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )
        state = self.store.load()
        self.store.transition(Phase.CODE_REVIEW, expected_revision=state.revision)
        write_manifest(
            self.ownership.worktree_path / ".ship" / "manifest.toml",
            replace(self.manifest, max_review_rounds=4),
        )

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.PLANNING)
        self.assertIsNone(run.plan_approval)

    def test_new_plan_gate_ignores_old_approval_and_waits_for_human(self) -> None:
        record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )
        self.plan_path.write_text(
            "# Revised plan\n\nA new approved scope.\n",
            encoding="utf-8",
        )
        planning = Reconciler(self.repository).reconcile("run-plan-001")
        self.assertEqual(planning.state.phase, Phase.PLANNING)
        state = self.store.transition(
            Phase.PLAN_REVIEW,
            expected_revision=planning.state.revision,
        )
        current = Reconciler(self.repository).reconcile("run-plan-001")
        self.assertIsNotNone(current.subject)
        nonce = issue_handoff(
            self.store,
            subject=current.subject,
            source_actor="new-planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        record_plan_review(
            self.store,
            current_subject=current.subject,
            reviewer_actor="new-plan-critic-context",
            handoff_nonce=nonce,
            verdict="pass",
            findings=(),
        )
        self.assertGreater(self.store.load().revision, state.revision)

        waiting = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(waiting.state.phase, Phase.AWAITING_PLAN_APPROVAL)
        self.assertEqual(waiting.reason, "awaiting-plan-approval")
        self.assertEqual(
            waiting.evidence.plan_approval,
            EvidenceStatus.MISSING,
        )
        self.assertEqual(next_action(waiting).kind, "human")

    def test_format_only_manifest_change_preserves_approval_but_dirty_state_wins(
        self,
    ) -> None:
        approval = record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )
        state = self.store.load()
        self.store.transition(Phase.CODE_REVIEW, expected_revision=state.revision)
        manifest_path = self.ownership.worktree_path / ".ship" / "manifest.toml"
        manifest_path.write_text(
            manifest_path.read_text(encoding="utf-8") + "\n# formatting only\n",
            encoding="utf-8",
        )

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.DEVELOPING)
        self.assertEqual(run.plan_approval, approval)

    def test_review_then_verification_are_required_in_order(self) -> None:
        subject = self.prepare_code_review()

        before_review = Reconciler(self.repository).reconcile("run-plan-001")
        self.assertEqual(before_review.state.phase, Phase.CODE_REVIEW)

        nonce = issue_handoff(
            self.store,
            subject=subject,
            source_actor="developer-context",
            role=ReviewRole.REVIEWER,
        )
        record_code_review(
            self.store,
            current_subject=subject,
            reviewer_actor="reviewer-context",
            handoff_nonce=nonce,
            verdict="pass",
            findings=(),
        )

        before_verification = Reconciler(self.repository).reconcile("run-plan-001")
        self.assertEqual(before_verification.state.phase, Phase.VERIFYING)

    def test_current_verification_with_no_release_moves_to_syncing_without_running_commands(
        self,
    ) -> None:
        self.prepare_release_gate()

        with mock.patch(
            "ship_flow.runner.CommandRunner.run",
            side_effect=AssertionError("reconcile must not run commands"),
        ):
            run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.SYNCING)
        self.assertEqual(run.reason, "release-not-required")

    def test_candidate_or_engine_drift_at_release_gate_returns_to_code_review(
        self,
    ) -> None:
        self.prepare_release_gate()
        (self.ownership.worktree_path / "follow-up.txt").write_text(
            "new candidate\n", encoding="utf-8"
        )
        commit_candidate(
            self.ownership,
            message="follow-up candidate",
            approved_paths=("follow-up.txt",),
        )

        candidate_drift = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(candidate_drift.state.phase, Phase.CODE_REVIEW)
        self.assertIsNotNone(candidate_drift.plan_approval)
        self.assertTrue(
            (self.run_directory / "verifications" / "verification-0001.json").is_file()
        )

    def test_engine_schema_drift_invalidates_code_review_not_plan_approval(
        self,
    ) -> None:
        self.prepare_release_gate()

        run = Reconciler(
            self.repository,
            engine_version="0.2.0",
            evidence_schema_version=2,
        ).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.CODE_REVIEW)
        self.assertIsNotNone(run.plan_approval)

    def test_deleted_code_review_or_verification_blocks_and_requires_manual_action(
        self,
    ) -> None:
        self.prepare_release_gate()
        (self.run_directory / "reviews" / "code-review.json").unlink()

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.BLOCKED)
        self.assertEqual(next_action(run).kind, "manual")
        self.assertEqual(next_action(run).action, "manual_reconciliation")

    def test_deleted_verification_blocks_instead_of_claiming_release_ready(
        self,
    ) -> None:
        self.prepare_release_gate()
        (self.run_directory / "verifications" / "verification-0001.json").unlink()

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.BLOCKED)
        self.assertEqual(next_action(run).kind, "manual")

    def test_base_branch_advance_requires_a_new_run_without_external_effects(
        self,
    ) -> None:
        self.prepare_release_gate()
        (self.primary / "upstream.txt").write_text(
            "new upstream work\n",
            encoding="utf-8",
        )
        git(self.primary, "add", "upstream.txt")
        git(self.primary, "commit", "-m", "advance base branch")

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.BLOCKED)
        self.assertEqual(run.reason, "base-branch-drift-start-new-run")
        self.assertEqual(next_action(run).kind, "manual")
        self.assertEqual(
            next_action(run).action,
            "start_new_run_from_latest_base",
        )
        self.assertEqual(self.store.operation_start_markers(), ())
        self.assertFalse((self.run_directory / "release-cycles").exists())

    def test_completed_terminal_revalidates_required_sync_evidence(self) -> None:
        self.prepare_release_gate()
        syncing = Reconciler(self.repository).reconcile("run-plan-001")
        self.assertEqual(syncing.state.phase, Phase.SYNCING)
        state = self.store.transition(
            Phase.AWAITING_CLEANUP_APPROVAL,
            expected_revision=syncing.state.revision,
        )
        self.store.transition(
            Phase.COMPLETED,
            expected_revision=state.revision,
        )

        terminal = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(terminal.state.phase, Phase.COMPLETED)
        self.assertEqual(terminal.evidence.sync, EvidenceStatus.INVALID)
        self.assertEqual(terminal.reason, "sync-evidence-invalid")
        self.assertEqual(next_action(terminal).kind, "manual")

    def test_completed_terminal_audits_sync_after_worktree_cleanup(self) -> None:
        subject = self.prepare_release_gate()
        syncing = Reconciler(self.repository).reconcile("run-plan-001")
        self.assertEqual(syncing.state.phase, Phase.SYNCING)
        SyncRecorder(
            store=self.store,
            worktree=self.ownership.worktree_path,
            current_subject=lambda: subject,
        ).record_sync_report(
            SyncReportDraft(
                reporter="sync-agent",
                items=(
                    SyncItem("code", "current", ("feature.txt",)),
                    SyncItem("docs", "current", ("README.md",)),
                    SyncItem("rules", "not_applicable", ()),
                    SyncItem("project_knowledge", "not_applicable", ()),
                ),
            ),
            subject,
        )
        cleanup_gate = self.store.load()
        self.store.transition(
            Phase.COMPLETED,
            expected_revision=cleanup_gate.revision,
        )
        self.ownership.record_path.unlink()
        shutil.rmtree(self.ownership.worktree_path)

        terminal = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(terminal.state.phase, Phase.COMPLETED)
        self.assertEqual(terminal.subject, subject)
        self.assertEqual(terminal.evidence.sync, EvidenceStatus.CURRENT)
        self.assertEqual(terminal.reason, "terminal-evidence-is-current")
        self.assertEqual(next_action(terminal).kind, "terminal")

    def test_deleted_terminal_receipt_or_tampered_log_blocks_release_readiness(
        self,
    ) -> None:
        self.prepare_release_gate()
        terminal = next(
            (self.run_directory / "verification-executions").glob("*.terminal-*.json")
        )
        terminal.unlink()

        missing_terminal = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(missing_terminal.state.phase, Phase.BLOCKED)
        self.assertIn(
            missing_terminal.evidence.verification,
            {EvidenceStatus.MISSING, EvidenceStatus.INVALID},
        )

    def test_symlinked_runtime_evidence_ancestor_is_never_trusted(self) -> None:
        self.prepare_release_gate()
        reviews = self.run_directory / "reviews"
        real_reviews = self.run_directory / "reviews-real"
        fake_reviews = self.root / "attacker-reviews"
        reviews.rename(real_reviews)
        shutil.copytree(real_reviews, fake_reviews)
        reviews.symlink_to(fake_reviews, target_is_directory=True)

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.BLOCKED)
        self.assertEqual(run.reason, "runtime-evidence-ancestor-unsafe")
        self.assertEqual(next_action(run).kind, "manual")

    def test_symlinked_ship_directory_is_blocked_without_following_manifest(
        self,
    ) -> None:
        record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )
        ship_directory = self.ownership.worktree_path / ".ship"
        real_ship_directory = self.ownership.worktree_path / ".ship-real"
        ship_directory.rename(real_ship_directory)
        ship_directory.symlink_to(real_ship_directory, target_is_directory=True)

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.BLOCKED)
        self.assertEqual(next_action(run).kind, "manual")

    def test_repository_lock_covers_observation_through_state_cas(self) -> None:
        record_plan_approval(
            self.store,
            current_subject=self.subject,
            approver_actor="human-owner",
        )
        observed_errors: list[BaseException] = []
        original_git_read = reconcile_module._git_read
        attempted = False

        def racing_git_read(repo: Path, *arguments: str) -> str:
            nonlocal attempted
            if not attempted and arguments[:2] == ("rev-parse", "--verify"):
                attempted = True

                def publish_candidate() -> None:
                    try:
                        (self.ownership.worktree_path / "racing.txt").write_text(
                            "racing candidate\n", encoding="utf-8"
                        )
                        commit_candidate(
                            self.ownership,
                            message="racing candidate",
                            approved_paths=("racing.txt",),
                        )
                    except BaseException as error:
                        observed_errors.append(error)

                thread = threading.Thread(target=publish_candidate)
                thread.start()
                thread.join()
            return original_git_read(repo, *arguments)

        with mock.patch.object(
            reconcile_module,
            "_git_read",
            side_effect=racing_git_read,
        ):
            run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.DEVELOPING)
        self.assertEqual(len(observed_errors), 1)
        self.assertIsInstance(observed_errors[0], LockUnavailableError)

    def test_status_does_not_block_an_in_progress_review_publication(self) -> None:
        self.prepare_code_review()
        operation_path = self.run_directory / "review-operation.json"
        operation_path.write_text("{}\n", encoding="utf-8")
        os.chmod(operation_path, 0o600)
        publication_lock = FileLock(
            self.run_directory / "review-publication.lock",
            private_root=self.run_directory,
        )

        with publication_lock:
            run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.CODE_REVIEW)
        self.assertEqual(run.reason, "publication-in-progress")
        self.assertEqual(self.store.load().phase, Phase.CODE_REVIEW)

    def test_status_preserves_a_recoverable_code_review_publication(self) -> None:
        subject = self.prepare_code_review()
        nonce = issue_handoff(
            self.store,
            subject=subject,
            source_actor="developer-context",
            role=ReviewRole.REVIEWER,
        )
        with mock.patch.object(
            self.store,
            "transition",
            side_effect=RuntimeError("simulated crash before review transition"),
        ):
            with self.assertRaises(RuntimeError):
                record_code_review(
                    self.store,
                    current_subject=subject,
                    reviewer_actor="reviewer-context",
                    handoff_nonce=nonce,
                    verdict="pass",
                    findings=(),
                )

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.CODE_REVIEW)
        self.assertEqual(run.evidence.code_review, EvidenceStatus.RECOVERABLE)
        self.assertEqual(run.reason, "code-review-publication-recoverable")
        self.assertEqual(
            next_action(run).action,
            "resume_code_review_publication",
        )
        record_code_review(
            self.store,
            current_subject=subject,
            reviewer_actor="reviewer-context",
            handoff_nonce=nonce,
            verdict="pass",
            findings=(),
        )
        self.assertEqual(self.store.load().phase, Phase.VERIFYING)
        self.assertFalse((self.run_directory / "review-operation.json").exists())

    def test_status_preserves_a_recoverable_verification_publication(self) -> None:
        subject = self.prepare_verifying()
        nonce = issue_handoff(
            self.store,
            subject=subject,
            source_actor="reviewer-context",
            role=ReviewRole.VERIFIER,
        )
        original_transition = StateStore.transition

        def crash_before_release_gate(
            store: StateStore,
            target: Phase,
            *,
            expected_revision: int,
        ) -> RunState:
            if target is Phase.AWAITING_RELEASE_APPROVAL:
                raise RuntimeError("simulated crash before verification transition")
            return original_transition(
                store,
                target,
                expected_revision=expected_revision,
            )

        verifier = Verifier(
            repo=self.ownership.worktree_path,
            run_directory=self.run_directory,
            manifest=self.manifest,
            current_subject=subject,
            variables=self.variables,
        )
        with mock.patch.object(
            StateStore,
            "transition",
            autospec=True,
            side_effect=crash_before_release_gate,
        ):
            with self.assertRaises(RuntimeError):
                verifier.verify(
                    "run-plan-001",
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.VERIFYING)
        self.assertEqual(run.evidence.verification, EvidenceStatus.RECOVERABLE)
        self.assertEqual(run.reason, "verification-publication-recoverable")
        self.assertEqual(
            next_action(run).action,
            "resume_verification_publication",
        )
        verifier.verify(
            "run-plan-001",
            verifier_actor="verifier-context",
            handoff_nonce=nonce,
            sensitive_values=(),
        )
        self.assertEqual(self.store.load().phase, Phase.AWAITING_RELEASE_APPROVAL)
        self.assertFalse((self.run_directory / "verification-operation.json").exists())

    def test_operation_start_marker_plus_drift_is_fail_closed(self) -> None:
        self.prepare_release_gate()
        self.store.record_operation_start(
            cycle_id="a" * 64,
            mode="release",
            index=1,
            attempt=1,
            running_receipt_sha256="b" * 64,
            idempotency_key="c" * 64,
        )
        (self.ownership.worktree_path / "dirty-after-effect.txt").write_text(
            "drift\n", encoding="utf-8"
        )

        run = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(run.state.phase, Phase.BLOCKED)
        self.assertEqual(next_action(run).kind, "manual")

    def test_unknown_operation_receipt_blocks_and_reason_survives_restart(self) -> None:
        subject = self.prepare_release_gate()
        prepared_at = "2026-07-15T00:00:00Z"
        common = {
            "run_id": "run-plan-001",
            "cycle_id": "a" * 64,
            "mode": "release",
            "index": 1,
            "attempt": 1,
            "subject": subject,
            "target": "production",
            "argv": ("deploy",),
            "probe_argv": (),
            "command_sha256": "b" * 64,
            "probe_sha256": None,
            "approval_id": "c" * 64,
            "idempotency": "manual_reconcile",
            "idempotency_key": "d" * 64,
            "failed_release_id": None,
            "previous_release": None,
            "prepared_at": prepared_at,
        }
        prepared = OperationRecord(
            **common,
            status=OperationStatus.PREPARED,
            previous_receipt_sha256=None,
        )
        prepared_payload = release_module._operation_record_payload(prepared)
        running = OperationRecord(
            **common,
            status=OperationStatus.RUNNING,
            previous_receipt_sha256=release_module._digest(prepared_payload),
            started_at="2026-07-15T00:00:01Z",
        )
        running_payload = release_module._operation_record_payload(running)
        unknown = OperationRecord(
            **common,
            status=OperationStatus.UNKNOWN,
            previous_receipt_sha256=release_module._digest(running_payload),
            started_at="2026-07-15T00:00:01Z",
            finished_at="2026-07-15T00:00:02Z",
            result={"reason": "simulated-unknown"},
        )
        operation_root = (
            self.run_directory / "release-cycles" / ("a" * 64) / "operations"
        )
        committed = operation_root / "committed"
        sealed = operation_root / "sealed"
        committed.mkdir(parents=True)
        sealed.mkdir()
        for directory in (
            self.run_directory / "release-cycles",
            self.run_directory / "release-cycles" / ("a" * 64),
            operation_root,
            committed,
            sealed,
        ):
            directory.chmod(0o700)
        for record in (prepared, running, unknown):
            payload = release_module._operation_record_payload(record)
            digest = release_module._digest(payload)
            name = f"release-0001-attempt-1-{record.status.value.lower()}-{digest}.json"
            raw = release_module._canonical_json_bytes(payload) + b"\n"
            for directory in (committed, sealed):
                path = directory / name
                path.write_bytes(raw)
                path.chmod(0o600)
        self.store.record_operation_start(
            cycle_id="a" * 64,
            mode="release",
            index=1,
            attempt=1,
            running_receipt_sha256=release_module._digest(running_payload),
            idempotency_key="d" * 64,
        )

        blocked = Reconciler(self.repository).reconcile("run-plan-001")
        restarted = Reconciler(self.repository).reconcile("run-plan-001")

        self.assertEqual(blocked.state.phase, Phase.BLOCKED)
        self.assertEqual(blocked.reason, "external-operation-unknown")
        self.assertEqual(restarted.reason, "external-operation-unknown")
        self.assertEqual(next_action(restarted).kind, "manual")


class PreGateReconciliationTests(unittest.TestCase):
    def test_initialized_and_planning_status_do_not_require_a_plan_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            primary = root / "repo"
            initialize_repository(primary)
            manifest = Manifest(
                project_name="fixture",
                base_branch="main",
                remote="origin",
                verification_steps=(
                    CommandSpec(
                        "unit",
                        (sys.executable, "-c", "pass"),
                        "unit",
                    ),
                ),
                release_required=False,
            )
            write_manifest(primary / ".ship" / "manifest.toml", manifest)
            git(primary, "add", ".ship/manifest.toml")
            git(primary, "commit", "-m", "add manifest")
            repository = GitRepository.discover(primary)
            ownership = create_run_worktree(
                repository,
                run_id="run-pregate",
                branch="ship/pregate",
                worktree_path=root / "worktree",
            )
            store = StateStore(ownership.record_path.parent)
            state = store.create("run-pregate")

            initialized = Reconciler(repository).reconcile("run-pregate")
            self.assertEqual(initialized.state.phase, Phase.INITIALIZED)
            self.assertEqual(
                initialized.evidence,
                EvidenceInventory.not_applicable(),
            )

            store.transition(Phase.PLANNING, expected_revision=state.revision)
            planning = Reconciler(repository).reconcile("run-pregate")
            self.assertEqual(planning.state.phase, Phase.PLANNING)
            self.assertEqual(
                planning.evidence,
                EvidenceInventory.not_applicable(),
            )

            plan_path = ownership.record_path.parent / "plan.md"
            plan_path.write_text("# Plan\n\nVerify it.\n", encoding="utf-8")
            plan_path.chmod(0o600)
            plan_review_state = store.transition(
                Phase.PLAN_REVIEW,
                expected_revision=planning.state.revision,
            )
            plan_review = Reconciler(repository).reconcile("run-pregate")
            self.assertEqual(plan_review.state, plan_review_state)
            self.assertIsNotNone(plan_review.subject)
            self.assertIsNotNone(plan_review.manifest)
            self.assertEqual(
                plan_review.evidence.plan_approval,
                EvidenceStatus.NOT_APPLICABLE,
            )


class NextActionTests(unittest.TestCase):
    def test_every_phase_has_exactly_one_stable_typed_next_action(self) -> None:
        human = {
            Phase.AWAITING_PLAN_APPROVAL,
            Phase.AWAITING_RELEASE_APPROVAL,
            Phase.AWAITING_SCOPE_APPROVAL,
            Phase.ROLLBACK_PENDING,
            Phase.AWAITING_CLEANUP_APPROVAL,
        }
        manual = {Phase.BLOCKED}
        terminal = {
            Phase.ROLLED_BACK,
            Phase.COMPLETED,
            Phase.CANCELLED,
        }
        for phase in Phase:
            with self.subTest(phase=phase.value):
                state = RunState(
                    run_id="run-actions",
                    phase=phase,
                    revision=1,
                    created_at="2026-07-15T00:00:00Z",
                    updated_at="2026-07-15T00:00:01Z",
                )

                first = next_action(state)
                second = next_action(state)

                self.assertIsInstance(first, NextAction)
                self.assertEqual(first, second)
                self.assertEqual(first.phase, phase)
                expected_kind = (
                    "human"
                    if phase in human
                    else "manual"
                    if phase in manual
                    else "terminal"
                    if phase in terminal
                    else "automatic"
                )
                self.assertEqual(first.kind, expected_kind)
                self.assertTrue(first.action)


if __name__ == "__main__":
    unittest.main()
