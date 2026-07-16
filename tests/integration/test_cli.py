from __future__ import annotations

import json
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from ship_flow import release as release_module
from ship_flow.authorization import AuthorizationStore, ExecutionMode
from ship_flow.cli import _approval_aware_next_action, main as cli_main
from ship_flow.gitops import GitRepository, commit_candidate
from ship_flow.manifest import (
    CommandSpec,
    Manifest,
    OperationSpec,
    load_manifest,
    manifest_digest,
    write_manifest,
)
from ship_flow.model import Phase, RunState
from ship_flow.reconcile import (
    EvidenceInventory,
    ReconciledRun,
    Reconciler,
    record_plan_approval,
)
from ship_flow.release import ReleaseEngine
from ship_flow.review import (
    ReviewRole,
    issue_handoff,
    record_code_review,
    record_plan_review,
)
from ship_flow.store import StateStore
from ship_flow.verify import Verifier
from ship_flow.workflow import set_plan, start_run
from tests.support import git, initialize_repository


class BeginnerCliFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.primary = self.root / "beginner repo"
        initialize_repository(self.primary)
        self.run_id = "run-cli-001"
        self.worktree = self.root / "ship worktree"
        self.sentinel = self.root / "release-must-not-run"

    def cli(self, command: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        source_root = Path(__file__).resolve().parents[2] / "src"
        environment["PYTHONPATH"] = str(source_root)
        return subprocess.run(
            (
                sys.executable,
                "-m",
                "ship_flow",
                command,
                *arguments,
                "--json",
            ),
            cwd=self.primary,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def success(self, command: str, *arguments: str) -> dict[str, object]:
        completed = self.cli(command, *arguments)
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}",
        )
        self.assertEqual(completed.stderr, "")
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], command)
        self.assertNotIn("nonce", completed.stdout.lower())
        self.assertNotIn("secret", completed.stdout.lower())
        return payload

    def state(self, payload: dict[str, object]) -> dict[str, object]:
        state = payload["state"]
        self.assertIsInstance(state, dict)
        return state  # type: ignore[return-value]

    def start_awaiting_plan_approval(
        self,
        *,
        mode: str = "autonomous",
    ) -> tuple[dict[str, object], int, dict[str, object]]:
        self.success(
            "init",
            "--repo",
            str(self.primary),
            "--mode",
            mode,
            "--accept-detected",
        )
        git(self.primary, "add", ".ship/manifest.toml")
        git(self.primary, "commit", "-m", "confirm scope manifest")
        started = self.success(
            "start",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--goal",
            "ship the requested repository change",
            "--branch",
            "ship/scope-cli-001",
            "--worktree",
            str(self.worktree),
            "--release-target",
            "production",
            "--mode",
            mode,
        )
        plan_source = self.root / "scope plan.md"
        plan_source.write_text(
            "# Plan\n\nImplement and independently verify the requested change.\n",
            encoding="utf-8",
        )
        planned = self.success(
            "set-plan",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(self.state(started)["revision"]),
            "--file",
            str(plan_source),
        )
        reviewed = self.success(
            "record-plan-review",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(self.state(planned)["revision"]),
            "--source-actor",
            "planner-context",
            "--reviewer",
            "plan-critic-context",
            "--verdict",
            "pass",
        )
        return started, int(self.state(reviewed)["revision"]), reviewed

    def start_developing(self) -> tuple[dict[str, object], int]:
        started, revision, _ = self.start_awaiting_plan_approval()
        approved = self.success(
            "approve",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(revision),
            "--gate",
            "plan",
            "--actor",
            "human-owner",
        )
        self.assertEqual(self.state(approved)["phase"], "DEVELOPING")
        return started, int(self.state(approved)["revision"])

    def test_beginner_flow_reaches_release_gate_without_external_effects(self) -> None:
        initialized = self.success(
            "init",
            "--repo",
            str(self.primary),
            "--accept-detected",
        )
        manifest_path = Path(str(initialized["evidence"]["manifest"]))  # type: ignore[index]
        self.assertEqual(
            manifest_path.resolve(),
            (self.primary / ".ship" / "manifest.toml").resolve(),
        )
        self.assertTrue(manifest_path.is_file())
        self.assertEqual(
            initialized["next_action"],
            {
                "kind": "automatic",
                "action": "commit_manifest",
                "manifest": str(manifest_path),
            },
        )
        git(self.primary, "add", ".ship/manifest.toml")
        git(self.primary, "commit", "-m", "confirm ship manifest")

        started = self.success(
            "start",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--goal",
            "add a safe beginner feature",
            "--branch",
            "ship/cli-001",
            "--worktree",
            str(self.worktree),
        )
        self.assertEqual(self.state(started)["phase"], "PLANNING")
        self.assertEqual(started["authorization"]["mode"], "autonomous")  # type: ignore[index]
        self.assertEqual(started["authorization"]["generation"], 1)  # type: ignore[index]
        self.assertRegex(
            str(started["authorization"]["digest"]),  # type: ignore[index]
            r"^[0-9a-f]{64}$",
        )
        revision = int(self.state(started)["revision"])
        self.assertEqual(
            Path(str(started["worktree"])).resolve(), self.worktree.resolve()
        )

        recovered = self.success(
            "start",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--goal",
            "add a safe beginner feature",
            "--branch",
            "ship/cli-001",
            "--worktree",
            str(self.worktree),
        )
        self.assertEqual(recovered["authorization"], started["authorization"])

        plan_source = self.root / "approved plan.md"
        plan_source.write_text(
            "# Plan\n\n1. Add feature.txt.\n2. Review independently.\n3. Verify.\n",
            encoding="utf-8",
        )
        planned = self.success(
            "set-plan",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(revision),
            "--file",
            str(plan_source),
        )
        self.assertEqual(self.state(planned)["phase"], "PLAN_REVIEW")
        revision = int(self.state(planned)["revision"])

        plan_reviewed = self.success(
            "record-plan-review",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(revision),
            "--source-actor",
            "planner-context",
            "--reviewer",
            "plan-critic-context",
            "--verdict",
            "pass",
        )
        self.assertEqual(self.state(plan_reviewed)["phase"], "AWAITING_PLAN_APPROVAL")
        self.assertEqual(
            plan_reviewed["next_action"],
            {
                "phase": "AWAITING_PLAN_APPROVAL",
                "kind": "automatic",
                "action": "authorize_plan",
                "authorization_source": "contract",
            },
        )
        revision = int(self.state(plan_reviewed)["revision"])

        approved = self.success(
            "approve",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(revision),
            "--gate",
            "plan",
            "--actor",
            "human-owner",
        )
        self.assertEqual(self.state(approved)["phase"], "DEVELOPING")
        revision = int(self.state(approved)["revision"])

        (self.worktree / "feature.txt").write_text(
            "implemented safely\n", encoding="utf-8"
        )
        ready = self.success(
            "development-ready",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(revision),
            "--message",
            "implement safe beginner feature",
            "--approved-path",
            "feature.txt",
        )
        self.assertEqual(self.state(ready)["phase"], "CODE_REVIEW")
        revision = int(self.state(ready)["revision"])

        repository = subprocess.run(
            ("git", "rev-parse", "--git-common-dir"),
            cwd=self.primary,
            stdout=subprocess.PIPE,
            text=True,
            check=True,
        ).stdout.strip()
        git_common = Path(repository)
        if not git_common.is_absolute():
            git_common = (self.primary / git_common).resolve()
        run_directory = git_common / "ship-flow" / "runs" / self.run_id
        state_before = (run_directory / "state.json").read_bytes()
        events_before = (run_directory / "events.jsonl").read_bytes()

        illegal = self.cli(
            "release",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(revision),
            "--target",
            "production",
        )
        self.assertEqual(illegal.returncode, 4)
        illegal_payload = json.loads(illegal.stdout)
        self.assertFalse(illegal_payload["ok"])
        self.assertEqual(illegal_payload["error"]["code"], "phase_conflict")
        self.assertEqual((run_directory / "state.json").read_bytes(), state_before)
        self.assertEqual((run_directory / "events.jsonl").read_bytes(), events_before)
        self.assertFalse(self.sentinel.exists())

        reviewed = self.success(
            "record-review",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(revision),
            "--source-actor",
            "developer-context",
            "--reviewer",
            "reviewer-context",
            "--verdict",
            "pass",
        )
        self.assertEqual(self.state(reviewed)["phase"], "VERIFYING")
        revision = int(self.state(reviewed)["revision"])

        verified = self.success(
            "verify",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(revision),
            "--source-actor",
            "reviewer-context",
            "--verifier",
            "verifier-context",
        )
        self.assertEqual(self.state(verified)["phase"], "AWAITING_RELEASE_APPROVAL")
        self.assertEqual(
            verified["next_action"],
            {
                "phase": "AWAITING_RELEASE_APPROVAL",
                "kind": "automatic",
                "action": "authorize_release",
                "authorization_source": "contract",
            },
        )
        self.assertFalse(self.sentinel.exists())

        resumed = self.success(
            "resume",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
        )
        self.assertEqual(
            resumed["next_action"],
            {
                "phase": "SYNCING",
                "kind": "automatic",
                "action": "sync_project",
            },
        )
        self.assertNotIn("actions", resumed)
        self.assertFalse(self.sentinel.exists())

        synced = self.success(
            "record-sync",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(self.state(resumed)["revision"]),
            "--report-json",
            json.dumps(
                {
                    "reporter": "sync-context",
                    "items": [
                        {
                            "category": "code",
                            "status": "current",
                            "paths": ["feature.txt"],
                        },
                        {
                            "category": "docs",
                            "status": "not_applicable",
                            "paths": [],
                        },
                        {
                            "category": "rules",
                            "status": "not_applicable",
                            "paths": [],
                        },
                        {
                            "category": "project_knowledge",
                            "status": "not_applicable",
                            "paths": [],
                        },
                    ],
                },
                ensure_ascii=False,
            ),
        )
        self.assertEqual(
            self.state(synced)["phase"],
            "AWAITING_CLEANUP_APPROVAL",
        )
        self.assertEqual(
            synced["next_action"],
            {
                "phase": "AWAITING_CLEANUP_APPROVAL",
                "kind": "automatic",
                "action": "cleanup",
                "authorization_source": "contract",
            },
        )
        self.assertFalse(self.sentinel.exists())

    def test_immediate_plan_review_response_uses_selected_mode_policy(self) -> None:
        _, _, autonomous = self.start_awaiting_plan_approval()
        self.assertEqual(
            autonomous["next_action"],
            {
                "phase": "AWAITING_PLAN_APPROVAL",
                "kind": "automatic",
                "action": "authorize_plan",
                "authorization_source": "contract",
            },
        )

    def test_immediate_strict_plan_review_response_keeps_human_gate(self) -> None:
        _, _, strict = self.start_awaiting_plan_approval(mode="strict")
        self.assertEqual(
            strict["next_action"],
            {
                "phase": "AWAITING_PLAN_APPROVAL",
                "kind": "human",
                "action": "approve_plan",
            },
        )

    def test_repeated_identical_start_recovers_after_progress_and_rejects_mismatch(
        self,
    ) -> None:
        started, revision, _ = self.start_awaiting_plan_approval()

        recovered = self.success(
            "start",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--goal",
            "ship the requested repository change",
            "--branch",
            "ship/scope-cli-001",
            "--worktree",
            str(self.worktree),
            "--release-target",
            "production",
        )
        self.assertEqual(self.state(recovered)["revision"], revision)
        self.assertEqual(recovered["authorization"], started["authorization"])

        repository = GitRepository.discover(self.primary)
        store = StateStore(
            repository.git_common_directory / "ship-flow" / "runs" / self.run_id
        )
        state_before = store.state_path.read_bytes()
        events_before = store.events_path.read_bytes()
        mismatched = self.cli(
            "start",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--goal",
            "silently expand the original goal",
            "--branch",
            "ship/scope-cli-001",
            "--worktree",
            str(self.worktree),
            "--release-target",
            "production",
        )
        self.assertEqual(mismatched.returncode, 5)
        self.assertEqual(
            json.loads(mismatched.stdout)["error"]["code"], "invalid_input"
        )
        self.assertEqual(store.state_path.read_bytes(), state_before)
        self.assertEqual(store.events_path.read_bytes(), events_before)

    def test_strict_mode_is_selected_before_start(self) -> None:
        detected = self.success(
            "init",
            "--repo",
            str(self.primary),
            "--mode",
            "strict",
        )
        self.assertEqual(
            detected["next_action"],
            {"kind": "human", "action": "confirm_detected_manifest"},
        )
        self.assertFalse((self.primary / ".ship" / "manifest.toml").exists())

        initialized = self.success(
            "init",
            "--repo",
            str(self.primary),
            "--mode",
            "strict",
            "--accept-detected",
        )
        git(self.primary, "add", ".ship/manifest.toml")
        git(self.primary, "commit", "-m", "confirm strict manifest")

        started = self.success(
            "start",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--goal",
            "audit every workflow gate",
            "--branch",
            "ship/strict-cli-001",
            "--worktree",
            str(self.worktree),
            "--mode",
            "strict",
        )
        self.assertEqual(initialized["next_action"]["kind"], "human")  # type: ignore[index]
        self.assertEqual(started["authorization"]["mode"], "strict")  # type: ignore[index]
        self.assertEqual(started["authorization"]["source"], "contract")  # type: ignore[index]
        self.assertEqual(started["authorization"]["generation"], 1)  # type: ignore[index]

    def test_direct_library_run_without_contract_uses_strict_compatibility(
        self,
    ) -> None:
        write_manifest(
            self.primary / ".ship" / "manifest.toml",
            Manifest(
                project_name="legacy-cli-fixture",
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
            ),
        )
        git(self.primary, "add", ".ship/manifest.toml")
        git(self.primary, "commit", "-m", "confirm legacy manifest")
        repository = GitRepository.discover(self.primary)
        started = start_run(
            repository,
            run_id=self.run_id,
            branch="ship/legacy-cli-001",
            worktree_path=self.worktree,
        )

        status = self.success(
            "status",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
        )

        self.assertEqual(self.state(status)["revision"], started.state.revision)
        self.assertEqual(
            status["authorization"],
            {
                "mode": "strict",
                "source": "legacy_default",
                "generation": None,
                "digest": None,
            },
        )

    def test_autonomous_status_has_no_routine_human_gate_and_keeps_blocked_manual(
        self,
    ) -> None:
        _, revision, _ = self.start_awaiting_plan_approval()

        status = self.success(
            "status",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
        )
        self.assertEqual(
            status["next_action"],
            {
                "phase": "AWAITING_PLAN_APPROVAL",
                "kind": "automatic",
                "action": "authorize_plan",
                "authorization_source": "contract",
            },
        )

        repository = GitRepository.discover(self.primary)
        store = StateStore(
            repository.git_common_directory / "ship-flow" / "runs" / self.run_id
        )
        store.reconcile_transition(
            Phase.BLOCKED,
            expected_revision=revision,
            reason="test-manual-reconciliation",
        )
        blocked = self.success(
            "status",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
        )
        self.assertEqual(
            blocked["next_action"],
            {
                "phase": "BLOCKED",
                "kind": "manual",
                "action": "manual_reconciliation",
            },
        )

    def test_scope_change_can_be_requested_and_approved(self) -> None:
        _, revision = self.start_developing()
        current_manifest_sha256 = manifest_digest(
            load_manifest(self.worktree / ".ship" / "manifest.toml")
        )

        requested = self.success(
            "request-scope-change",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(revision),
            "--reason",
            "feature_expansion",
            "--summary",
            "add deployment dashboard",
            "--goal",
            "ship the feature and deployment dashboard",
            "--manifest-sha256",
            current_manifest_sha256,
            "--release-target",
            "production",
        )
        request_id = str(requested["scope_change"]["request_id"])  # type: ignore[index]
        self.assertRegex(request_id, r"^[0-9a-f]{64}$")
        self.assertEqual(self.state(requested)["phase"], "AWAITING_SCOPE_APPROVAL")
        self.assertEqual(
            requested["next_action"],
            {
                "phase": "AWAITING_SCOPE_APPROVAL",
                "kind": "human",
                "action": "approve_scope_change",
                "request_id": request_id,
            },
        )

        status = self.success(
            "status",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
        )
        self.assertEqual(status["next_action"], requested["next_action"])
        resolved = self.success(
            "resolve-scope-change",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(self.state(status)["revision"]),
            "--decision",
            "approve",
            "--actor",
            "human-owner",
        )
        self.assertEqual(self.state(resolved)["phase"], "PLANNING")
        self.assertEqual(resolved["authorization"]["generation"], 2)  # type: ignore[index]

    def test_rejected_scope_change_keeps_current_contract(self) -> None:
        started, revision = self.start_developing()
        current_manifest_sha256 = manifest_digest(
            load_manifest(self.worktree / ".ship" / "manifest.toml")
        )
        requested = self.success(
            "request-scope-change",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(revision),
            "--reason",
            "feature_expansion",
            "--summary",
            "add deployment dashboard",
            "--goal",
            "ship the feature and deployment dashboard",
            "--manifest-sha256",
            current_manifest_sha256,
            "--release-target",
            "production",
        )
        rejected = self.success(
            "resolve-scope-change",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(self.state(requested)["revision"]),
            "--decision",
            "reject",
            "--actor",
            "human-owner",
        )
        self.assertEqual(self.state(rejected)["phase"], "PLANNING")
        self.assertEqual(rejected["authorization"]["generation"], 1)  # type: ignore[index]
        self.assertEqual(
            rejected["authorization"]["digest"],  # type: ignore[index]
            started["authorization"]["digest"],  # type: ignore[index]
        )

    def test_manifest_drift_status_is_read_only_and_requests_scope_change(
        self,
    ) -> None:
        started, _ = self.start_developing()
        repository = GitRepository.discover(self.primary)
        store = StateStore(
            repository.git_common_directory / "ship-flow" / "runs" / self.run_id
        )
        manifest_path = self.worktree / ".ship" / "manifest.toml"
        changed_manifest = replace(
            load_manifest(manifest_path),
            max_review_rounds=4,
        )
        write_manifest(manifest_path, changed_manifest)
        proposed_digest = manifest_digest(changed_manifest)
        state_before = store.state_path.read_bytes()
        events_before = store.events_path.read_bytes()

        status = self.success(
            "status",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
        )

        self.assertEqual(store.state_path.read_bytes(), state_before)
        self.assertEqual(store.events_path.read_bytes(), events_before)
        self.assertIsNone(AuthorizationStore(store).pending())
        self.assertEqual(
            status["next_action"],
            {
                "phase": "DEVELOPING",
                "kind": "automatic",
                "action": "request_scope_change",
                "reason": "manifest_drift",
                "contract_digest": started["authorization"]["digest"],  # type: ignore[index]
                "proposed_manifest_sha256": proposed_digest,
            },
        )

        requested = self.success(
            "request-scope-change",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(self.state(status)["revision"]),
            "--reason",
            "manifest_drift",
            "--summary",
            "verification manifest changed",
            "--goal",
            "ship the requested repository change",
            "--manifest-sha256",
            proposed_digest,
            "--release-target",
            "production",
        )
        request_id = str(requested["scope_change"]["request_id"])  # type: ignore[index]
        scope_state_before = store.state_path.read_bytes()
        scope_events_before = store.events_path.read_bytes()

        pending = self.success(
            "status",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
        )

        self.assertEqual(store.state_path.read_bytes(), scope_state_before)
        self.assertEqual(store.events_path.read_bytes(), scope_events_before)
        self.assertEqual(
            pending["next_action"],
            {
                "phase": "AWAITING_SCOPE_APPROVAL",
                "kind": "human",
                "action": "approve_scope_change",
                "request_id": request_id,
            },
        )


class ResumePublicationCliTests(unittest.TestCase):
    run_id = "run-resume-cli"

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.primary = self.root / "resume repo"
        initialize_repository(self.primary)
        self.command_sentinel = self.root / "verification-command-count.txt"
        command = (
            "from pathlib import Path; import sys; "
            "p=Path(sys.argv[1]); "
            "p.write_text((p.read_text() if p.exists() else '') + 'run\\n')"
        )
        self.manifest = Manifest(
            project_name="resume-fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec(
                    "sentinel",
                    (sys.executable, "-c", command, str(self.command_sentinel)),
                    "integration",
                    timeout_seconds=10,
                ),
            ),
            release_required=False,
        )
        write_manifest(self.primary / ".ship" / "manifest.toml", self.manifest)
        git(self.primary, "add", ".ship/manifest.toml")
        git(self.primary, "commit", "-m", "confirm resume manifest")
        self.repository = GitRepository.discover(self.primary)
        started = start_run(
            self.repository,
            run_id=self.run_id,
            branch="ship/resume-cli",
            worktree_path=self.root / "resume worktree",
        )
        planned = set_plan(
            self.repository,
            self.run_id,
            "# Plan\n\nImplement, review, and verify safely.\n",
            expected_revision=started.state.revision,
        )
        self.ownership = planned.ownership
        self.store = planned.store
        self.plan_subject = planned.subject
        self.assertIsNotNone(self.plan_subject)
        self.variables = {
            "repo": str(self.ownership.primary_checkout),
            "worktree": str(self.ownership.worktree_path),
            "branch": self.ownership.branch,
            "base_branch": self.manifest.base_branch,
            "remote": self.manifest.remote,
        }

    def cli(self, command: str, *arguments: str) -> dict[str, object]:
        environment = os.environ.copy()
        source_root = Path(__file__).resolve().parents[2] / "src"
        environment["PYTHONPATH"] = str(source_root)
        completed = subprocess.run(
            (
                sys.executable,
                "-m",
                "ship_flow",
                command,
                *arguments,
                "--json",
            ),
            cwd=self.primary,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}",
        )
        self.assertEqual(completed.stderr, "")
        return json.loads(completed.stdout)

    def resume(self) -> dict[str, object]:
        return self.cli(
            "resume",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
        )

    def approve_plan_normally(self) -> None:
        assert self.plan_subject is not None
        nonce = issue_handoff(
            self.store,
            subject=self.plan_subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        record_plan_review(
            self.store,
            current_subject=self.plan_subject,
            reviewer_actor="critic-context",
            handoff_nonce=nonce,
            verdict="pass",
            findings=(),
        )
        record_plan_approval(
            self.store,
            current_subject=self.plan_subject,
            approver_actor="human-owner",
        )

    def prepare_code_review(self):
        self.approve_plan_normally()
        (self.ownership.worktree_path / "feature.txt").write_text(
            "implemented\n",
            encoding="utf-8",
        )
        commit_candidate(
            self.ownership,
            message="implement resume fixture",
            approved_paths=("feature.txt",),
        )
        run = Reconciler(self.repository).reconcile(self.run_id)
        self.assertEqual(run.state.phase, Phase.CODE_REVIEW)
        self.assertIsNotNone(run.subject)
        return run.subject

    def prepare_verifying(self):
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

    def test_ordinary_resume_only_reports_one_next_action(self) -> None:
        state_before = self.store.state_path.read_bytes()
        events_before = self.store.events_path.read_bytes()

        payload = self.resume()

        self.assertNotIn("recovered", payload)
        self.assertEqual(payload["state"]["phase"], "PLAN_REVIEW")  # type: ignore[index]
        self.assertEqual(
            payload["next_action"],
            {  # type: ignore[index]
                "phase": "PLAN_REVIEW",
                "kind": "automatic",
                "action": "review_plan",
            },
        )
        self.assertNotIn("actions", payload)
        self.assertEqual(self.store.state_path.read_bytes(), state_before)
        self.assertEqual(self.store.events_path.read_bytes(), events_before)

    def test_fresh_resume_finishes_sealed_plan_review_without_review_rerun(
        self,
    ) -> None:
        assert self.plan_subject is not None
        nonce = issue_handoff(
            self.store,
            subject=self.plan_subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        with mock.patch.object(
            self.store,
            "transition",
            side_effect=OSError("simulated crash before review transition"),
        ):
            with self.assertRaisesRegex(OSError, "review transition"):
                record_plan_review(
                    self.store,
                    current_subject=self.plan_subject,
                    reviewer_actor="critic-context",
                    handoff_nonce=nonce,
                    verdict="pass",
                    findings=(),
                )
        del nonce
        before = Reconciler(self.repository).reconcile(self.run_id)
        self.assertEqual(before.reason, "plan-review-publication-recoverable")

        payload = self.resume()

        self.assertEqual(payload["recovered"]["kind"], "review_publication")  # type: ignore[index]
        self.assertEqual(payload["state"]["phase"], "AWAITING_PLAN_APPROVAL")  # type: ignore[index]
        self.assertEqual(payload["next_action"]["action"], "approve_plan")  # type: ignore[index]
        self.assertNotIn("actions", payload)
        self.assertFalse((self.store.run_directory / "review-operation.json").exists())
        self.assertFalse(self.command_sentinel.exists())

    def test_fresh_resume_finishes_sealed_code_review_without_verification(
        self,
    ) -> None:
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
            side_effect=OSError("simulated crash before code review transition"),
        ):
            with self.assertRaisesRegex(OSError, "code review transition"):
                record_code_review(
                    self.store,
                    current_subject=subject,
                    reviewer_actor="reviewer-context",
                    handoff_nonce=nonce,
                    verdict="pass",
                    findings=(),
                )
        del nonce
        before = Reconciler(self.repository).reconcile(self.run_id)
        self.assertEqual(before.reason, "code-review-publication-recoverable")

        payload = self.resume()

        self.assertEqual(payload["recovered"]["review_type"], "code")  # type: ignore[index]
        self.assertEqual(payload["state"]["phase"], "VERIFYING")  # type: ignore[index]
        self.assertEqual(payload["next_action"]["action"], "verify")  # type: ignore[index]
        self.assertNotIn("actions", payload)
        self.assertFalse(self.command_sentinel.exists())

    def test_fresh_resume_finishes_sealed_verification_without_command_rerun(
        self,
    ) -> None:
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
                raise OSError("simulated crash before verification transition")
            return original_transition(
                store,
                target,
                expected_revision=expected_revision,
            )

        verifier = Verifier(
            repo=self.ownership.worktree_path,
            run_directory=self.store.run_directory,
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
            with self.assertRaisesRegex(OSError, "verification transition"):
                verifier.verify(
                    self.run_id,
                    verifier_actor="verifier-context",
                    handoff_nonce=nonce,
                    sensitive_values=(),
                )
        del nonce
        sentinel_before = self.command_sentinel.read_bytes()
        self.assertEqual(sentinel_before, b"run\n")
        before = Reconciler(self.repository).reconcile(self.run_id)
        self.assertEqual(before.reason, "verification-publication-recoverable")

        payload = self.resume()

        self.assertEqual(payload["recovered"]["kind"], "verification_publication")  # type: ignore[index]
        self.assertEqual(payload["state"]["phase"], "SYNCING")  # type: ignore[index]
        self.assertEqual(payload["next_action"]["action"], "sync_project")  # type: ignore[index]
        self.assertNotIn("actions", payload)
        self.assertEqual(self.command_sentinel.read_bytes(), sentinel_before)
        self.assertFalse(
            (self.store.run_directory / "verification-operation.json").exists()
        )


class ApprovalAwareStatusCliTests(unittest.TestCase):
    run_id = "run-approval-status-cli"

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.primary = self.root / "approval status repo"
        initialize_repository(self.primary)
        self.release_sentinel = self.root / "release-must-not-run"
        self.rollback_sentinel = self.root / "rollback-must-not-run"
        self.manifest = Manifest(
            project_name="approval-status-fixture",
            base_branch="main",
            remote="origin",
            verification_steps=(
                CommandSpec("unit", (sys.executable, "-c", "pass"), "unit"),
            ),
            release_required=True,
            release_steps=(
                OperationSpec(
                    name="release-sentinel",
                    kind="push",
                    target="production",
                    argv=(
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                        str(self.release_sentinel),
                    ),
                    effect="external_write",
                    idempotency="safe",
                ),
            ),
            release_healthchecks=(
                CommandSpec(
                    "unhealthy-release",
                    (
                        sys.executable,
                        "-c",
                        (
                            "import json; print(json.dumps({"
                            "'schema_version':1,'kind':'health',"
                            "'status':'unhealthy','target':'production',"
                            "'version':'wrong-release'},sort_keys=True,"
                            "separators=(',',':')))"
                        ),
                    ),
                    "health",
                ),
            ),
            rollback_steps=(
                OperationSpec(
                    name="rollback-sentinel",
                    target="production",
                    argv=(
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                        str(self.rollback_sentinel),
                    ),
                    effect="external_write",
                    idempotency="safe",
                    data_impact="none",
                ),
            ),
        )
        write_manifest(self.primary / ".ship" / "manifest.toml", self.manifest)
        git(self.primary, "add", ".ship/manifest.toml")
        git(self.primary, "commit", "-m", "confirm approval status manifest")
        self.repository = GitRepository.discover(self.primary)
        started = start_run(
            self.repository,
            run_id=self.run_id,
            branch="ship/approval-status-cli",
            worktree_path=self.root / "approval status worktree",
        )
        planned = set_plan(
            self.repository,
            self.run_id,
            "# Plan\n\nImplement, review, verify, and wait for release approval.\n",
            expected_revision=started.state.revision,
        )
        self.ownership = planned.ownership
        self.store = planned.store
        plan_subject = planned.subject
        assert plan_subject is not None
        nonce = issue_handoff(
            self.store,
            subject=plan_subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        record_plan_review(
            self.store,
            current_subject=plan_subject,
            reviewer_actor="critic-context",
            handoff_nonce=nonce,
            verdict="pass",
            findings=(),
        )
        record_plan_approval(
            self.store,
            current_subject=plan_subject,
            approver_actor="human-owner",
        )
        (self.ownership.worktree_path / "feature.txt").write_text(
            "implemented\n",
            encoding="utf-8",
        )
        commit_candidate(
            self.ownership,
            message="implement approval status fixture",
            approved_paths=("feature.txt",),
        )
        reviewing = Reconciler(self.repository).reconcile(self.run_id)
        self.assertEqual(reviewing.state.phase, Phase.CODE_REVIEW)
        subject = reviewing.subject
        assert subject is not None
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
        nonce = issue_handoff(
            self.store,
            subject=subject,
            source_actor="reviewer-context",
            role=ReviewRole.VERIFIER,
        )
        self.variables = {
            "repo": str(self.ownership.primary_checkout),
            "worktree": str(self.ownership.worktree_path),
            "branch": self.ownership.branch,
            "base_branch": self.manifest.base_branch,
            "remote": self.manifest.remote,
        }
        Verifier(
            repo=self.ownership.worktree_path,
            run_directory=self.store.run_directory,
            manifest=self.manifest,
            current_subject=subject,
            variables=self.variables,
        ).verify(
            self.run_id,
            verifier_actor="verifier-context",
            handoff_nonce=nonce,
            sensitive_values=(),
        )
        self.assertEqual(self.store.load().phase, Phase.AWAITING_RELEASE_APPROVAL)
        current = Reconciler(self.repository).reconcile(self.run_id)
        assert current.subject is not None
        self.engine = ReleaseEngine(
            repo=self.ownership.worktree_path,
            run_directory=self.store.run_directory,
            manifest=self.manifest,
            current_subject=current.subject,
            variables=self.variables,
        )

    def cli(self, command: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        source_root = Path(__file__).resolve().parents[2] / "src"
        environment["PYTHONPATH"] = str(source_root)
        return subprocess.run(
            (
                sys.executable,
                "-m",
                "ship_flow",
                command,
                "--repo",
                str(self.primary),
                "--run-id",
                self.run_id,
                "--json",
            ),
            cwd=self.primary,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def run_files(self) -> dict[Path, bytes]:
        return {
            path.relative_to(self.store.run_directory): path.read_bytes()
            for path in self.store.run_directory.rglob("*")
            if path.is_file()
        }

    def select_mode(self, mode: ExecutionMode) -> None:
        AuthorizationStore(self.store).create_initial(
            mode=mode,
            goal="ship approval-aware fixture",
            repository=self.primary,
            worktree=self.ownership.worktree_path,
            branch=self.ownership.branch,
            manifest_sha256=manifest_digest(self.manifest),
            release_target="production",
            previous_release="release-v1",
            state_revision=self.store.load().revision,
        )

    def rollback_preapproval(self, mode: ExecutionMode) -> dict[str, object]:
        self.select_mode(mode)
        release_approval = self.engine.record_approval(
            gate="release",
            target="production",
            approver_actor="release-owner",
            expires_at="2999-01-01T00:00:00Z",
        )
        revision = self.store.load().revision
        completed = subprocess.run(
            (
                sys.executable,
                "-m",
                "ship_flow",
                "approve",
                "--repo",
                str(self.primary),
                "--run-id",
                self.run_id,
                "--expected-revision",
                str(revision),
                "--gate",
                "rollback",
                "--actor",
                "rollback-owner",
                "--target",
                "production",
                "--expires-at",
                "2999-01-01T00:00:00Z",
                "--failed-release-id",
                release_approval.approval_id,
                "--previous-release",
                "release-v1",
                "--json",
            ),
            cwd=self.primary,
            env={
                **os.environ,
                "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src"),
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}",
        )
        payload = json.loads(completed.stdout)
        payload["release_approval_id"] = release_approval.approval_id
        return payload

    def test_autonomous_safe_rollback_preapproval_keeps_release_action_identity(
        self,
    ) -> None:
        payload = self.rollback_preapproval(ExecutionMode.AUTONOMOUS)
        release_approval_id = payload.pop("release_approval_id")
        rollback_approval_id = payload["approval_id"]

        self.assertNotEqual(rollback_approval_id, release_approval_id)
        self.assertEqual(
            payload["next_action"],
            {
                "phase": "AWAITING_RELEASE_APPROVAL",
                "kind": "automatic",
                "action": "release",
                "approval_id": release_approval_id,
                "target": "production",
            },
        )
        self.assertEqual(
            payload["approval"],
            {
                "gate": "rollback",
                "approval_id": rollback_approval_id,
                "target": "production",
                "failed_release_id": release_approval_id,
                "previous_release": "release-v1",
            },
        )

    def test_strict_safe_rollback_preapproval_keeps_release_human_gate(
        self,
    ) -> None:
        payload = self.rollback_preapproval(ExecutionMode.STRICT)
        release_approval_id = payload.pop("release_approval_id")
        rollback_approval_id = payload["approval_id"]

        self.assertEqual(
            payload["next_action"],
            {
                "phase": "AWAITING_RELEASE_APPROVAL",
                "kind": "human",
                "action": "approve_release",
            },
        )
        self.assertEqual(
            payload["approval"],
            {
                "gate": "rollback",
                "approval_id": rollback_approval_id,
                "target": "production",
                "failed_release_id": release_approval_id,
                "previous_release": "release-v1",
            },
        )

    def test_default_expiry_approve_recovers_orphan_and_response_lost_retry(
        self,
    ) -> None:
        revision = self.store.load().revision
        arguments = (
            "approve",
            "--repo",
            str(self.primary),
            "--run-id",
            self.run_id,
            "--expected-revision",
            str(revision),
            "--gate",
            "release",
            "--actor",
            "human-owner",
            "--target",
            "production",
            "--json",
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
                raise OSError("simulated response power loss")
            original_write(path, payload, trusted_root=trusted_root)

        expiry_values = iter(
            (
                "2998-01-01T00:00:00Z",
                "2997-01-01T00:00:00Z",
                "2996-01-01T00:00:00Z",
                "2995-01-01T00:00:00Z",
            )
        )
        with mock.patch("ship_flow.cli._utc_after", side_effect=expiry_values):
            output = io.StringIO()
            with (
                redirect_stdout(output),
                mock.patch(
                    "ship_flow.release._write_canonical_json",
                    side_effect=crash_before_pointer,
                ),
            ):
                first_code = cli_main(arguments)
            self.assertEqual(first_code, 6)

            approval_ids: list[str] = []
            for _ in range(2):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(cli_main(arguments), 0)
                approval_ids.append(json.loads(output.getvalue())["approval_id"])
            self.assertEqual(approval_ids[0], approval_ids[1])
            self.assertEqual(
                len(
                    tuple(
                        (self.store.run_directory / "approvals" / "sealed").glob(
                            "*.json"
                        )
                    )
                ),
                1,
            )

            output = io.StringIO()
            different_actor = tuple(
                "another-owner" if token == "human-owner" else token
                for token in arguments
            )
            with redirect_stdout(output):
                self.assertEqual(cli_main(different_actor), 0)
            self.assertNotEqual(
                json.loads(output.getvalue())["approval_id"],
                approval_ids[0],
            )

    def test_status_and_resume_recover_one_approval_without_executing_release(
        self,
    ) -> None:
        approval = self.engine.record_approval(
            gate="release",
            target="production",
            approver_actor="human-owner",
            expires_at="2999-01-01T00:00:00Z",
        )
        before = self.run_files()

        for command in ("status", "resume"):
            with self.subTest(command=command):
                completed = self.cli(command)
                self.assertEqual(
                    completed.returncode,
                    0,
                    msg=f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}",
                )
                payload = json.loads(completed.stdout)
                self.assertEqual(
                    payload["next_action"],
                    {
                        "phase": "AWAITING_RELEASE_APPROVAL",
                        "kind": "automatic",
                        "action": "release",
                        "approval_id": approval.approval_id,
                        "target": "production",
                    },
                )
                self.assertEqual(self.run_files(), before)
                self.assertFalse(self.release_sentinel.exists())

    def test_status_and_resume_recover_consumed_commitment_before_pointer_update(
        self,
    ) -> None:
        approval = self.engine.record_approval(
            gate="release",
            target="production",
            approver_actor="human-owner",
            expires_at="2999-01-01T00:00:00Z",
        )
        approval_path = (
            self.store.run_directory / "approvals" / f"{approval.approval_id}.json"
        )
        original_write = release_module._write_canonical_json
        crashed = False

        def crash_before_consumed_pointer(
            path: Path,
            payload: dict[str, object],
            *,
            trusted_root: object,
        ) -> None:
            nonlocal crashed
            if (
                path == approval_path
                and payload.get("consumed_at") is not None
                and not crashed
            ):
                crashed = True
                raise OSError("simulated power loss before consumed pointer")
            original_write(path, payload, trusted_root=trusted_root)

        with mock.patch(
            "ship_flow.release._write_canonical_json",
            side_effect=crash_before_consumed_pointer,
        ):
            with self.assertRaisesRegex(OSError, "consumed pointer"):
                self.engine.release(
                    target="production",
                    approval_id=approval.approval_id,
                )

        self.assertEqual(self.store.load().phase, Phase.AWAITING_RELEASE_APPROVAL)
        active = json.loads(
            (
                self.store.run_directory / "release-cycles" / "active-release.json"
            ).read_text(encoding="utf-8")
        )
        before = self.run_files()

        for command in ("status", "resume"):
            with self.subTest(command=command):
                completed = self.cli(command)
                self.assertEqual(
                    completed.returncode,
                    0,
                    msg=f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}",
                )
                payload = json.loads(completed.stdout)
                self.assertEqual(
                    payload["next_action"],
                    {
                        "phase": "AWAITING_RELEASE_APPROVAL",
                        "kind": "automatic",
                        "action": "release",
                        "cycle_id": active["cycle_id"],
                        "approval_id": approval.approval_id,
                        "target": "production",
                    },
                )
                self.assertEqual(self.run_files(), before)
                self.assertFalse(self.release_sentinel.exists())

    def test_status_and_resume_keep_approval_prompt_when_none_exists(self) -> None:
        before = self.run_files()

        for command in ("status", "resume"):
            with self.subTest(command=command):
                completed = self.cli(command)
                self.assertEqual(
                    completed.returncode,
                    0,
                    msg=f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}",
                )
                payload = json.loads(completed.stdout)
                self.assertEqual(
                    payload["next_action"],
                    {
                        "phase": "AWAITING_RELEASE_APPROVAL",
                        "kind": "human",
                        "action": "approve_release",
                    },
                )
                self.assertEqual(self.run_files(), before)
                self.assertFalse(self.release_sentinel.exists())

    def test_status_and_resume_refuse_to_guess_between_current_approvals(
        self,
    ) -> None:
        for actor in ("human-one", "human-two"):
            self.engine.record_approval(
                gate="release",
                target="production",
                approver_actor=actor,
                expires_at="2999-01-01T00:00:00Z",
            )
        before = self.run_files()

        for command in ("status", "resume"):
            with self.subTest(command=command):
                completed = self.cli(command)
                self.assertEqual(completed.returncode, 6)
                payload = json.loads(completed.stdout)
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["error"]["code"], "evidence_invalid")
                self.assertEqual(self.run_files(), before)
                self.assertFalse(self.release_sentinel.exists())

    def test_status_and_resume_recover_one_rollback_approval_without_execution(
        self,
    ) -> None:
        previous_release = "release-v1"
        release_approval = self.engine.record_approval(
            gate="release",
            target="production",
            approver_actor="human-owner",
            expires_at="2999-01-01T00:00:00Z",
        )
        self.engine.release(
            target="production",
            approval_id=release_approval.approval_id,
            previous_release=previous_release,
        )
        self.assertEqual(self.store.load().phase, Phase.ROLLBACK_PENDING)
        rollback_approval = self.engine.record_approval(
            gate="rollback",
            target="production",
            approver_actor="human-owner",
            expires_at="2999-01-01T00:00:00Z",
            failed_release_id=release_approval.approval_id,
            previous_release=previous_release,
        )
        before = self.run_files()

        for command in ("status", "resume"):
            with self.subTest(command=command):
                completed = self.cli(command)
                self.assertEqual(
                    completed.returncode,
                    0,
                    msg=f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}",
                )
                payload = json.loads(completed.stdout)
                self.assertEqual(
                    payload["next_action"],
                    {
                        "phase": "ROLLBACK_PENDING",
                        "kind": "automatic",
                        "action": "rollback",
                        "approval_id": rollback_approval.approval_id,
                        "target": "production",
                        "failed_release_id": release_approval.approval_id,
                        "previous_release": previous_release,
                    },
                )
                self.assertEqual(self.run_files(), before)
                self.assertFalse(self.rollback_sentinel.exists())


class ExternalContextNextActionTests(unittest.TestCase):
    def test_external_phases_return_exact_cli_context_without_execution(self) -> None:
        cases = (
            (Phase.RELEASING, "release", None, None),
            (Phase.POST_RELEASE_VERIFYING, "release", None, None),
            (Phase.ROLLING_BACK, "rollback", "f" * 64, "release-v1"),
            (Phase.ROLLBACK_VERIFYING, "rollback", "f" * 64, "release-v1"),
        )
        for phase, command, failed_release_id, previous_release in cases:
            with self.subTest(phase=phase.value):
                state = RunState(
                    run_id="run-context",
                    phase=phase,
                    revision=12,
                    created_at="2026-07-16T00:00:00.000000Z",
                    updated_at="2026-07-16T00:00:00.000000Z",
                )
                run = SimpleNamespace(
                    state=state,
                    ownership=object(),
                    manifest=object(),
                    subject=object(),
                )
                context = SimpleNamespace(
                    cycle_id="c" * 64,
                    mode=command,
                    approval_id="a" * 64,
                    target="production",
                    failed_release_id=failed_release_id,
                    previous_release=previous_release,
                )
                engine = mock.Mock()
                engine.inspect_active_external_context.return_value = context
                with (
                    mock.patch(
                        "ship_flow.cli._next_action_payload",
                        return_value={
                            "phase": phase.value,
                            "kind": "automatic",
                            "action": "legacy-action",
                        },
                    ),
                    mock.patch("ship_flow.cli._release_engine", return_value=engine),
                ):
                    payload = _approval_aware_next_action(run)

                expected = {
                    "phase": phase.value,
                    "kind": "automatic",
                    "action": command,
                    "cycle_id": "c" * 64,
                    "approval_id": "a" * 64,
                    "target": "production",
                }
                if command == "rollback":
                    expected.update(
                        {
                            "failed_release_id": "f" * 64,
                            "previous_release": "release-v1",
                        }
                    )
                self.assertEqual(payload, expected)
                engine.inspect_active_external_context.assert_called_once_with(
                    phase=phase
                )
                engine.resume_external_cycle.assert_not_called()
                engine.release.assert_not_called()
                engine.rollback.assert_not_called()

    def test_status_and_resume_report_six_sealed_external_states_byte_stably(
        self,
    ) -> None:
        cases = (
            (Phase.RELEASING, "state-current", "release", False),
            (
                Phase.POST_RELEASE_VERIFYING,
                "external-health-publication-recoverable",
                "release",
                False,
            ),
            (Phase.ROLLING_BACK, "state-current", "rollback", False),
            (
                Phase.ROLLBACK_VERIFYING,
                "external-health-publication-recoverable",
                "rollback",
                False,
            ),
            (
                Phase.AWAITING_RELEASE_APPROVAL,
                "external-cycle-publication-recoverable",
                "release",
                True,
            ),
            (
                Phase.ROLLBACK_PENDING,
                "external-cycle-publication-recoverable",
                "rollback",
                True,
            ),
        )
        for phase, reason, command, _human_gate in cases:
            with self.subTest(phase=phase.value), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                evidence = root / "evidence.bin"
                sentinel = root / "external-effect-must-not-run"
                evidence.write_bytes(b"sealed-evidence\n")
                state = RunState(
                    run_id="run-context",
                    phase=phase,
                    revision=12,
                    created_at="2026-07-16T00:00:00.000000Z",
                    updated_at="2026-07-16T00:00:00.000000Z",
                )
                ownership = SimpleNamespace(
                    worktree_path=root / "worktree",
                    branch="ship/context",
                )
                subject = SimpleNamespace(
                    digest=lambda: "d" * 64,
                    candidate_oid="1" * 40,
                    tree_oid="2" * 40,
                )
                run = ReconciledRun(
                    state=state,
                    ownership=ownership,
                    manifest=object(),
                    subject=subject,
                    plan_approval=None,
                    dirty=False,
                    reason=reason,
                    evidence=EvidenceInventory.not_applicable(),
                )
                engine = mock.Mock()
                approval = SimpleNamespace(
                    approval_id="a" * 64,
                    gate=command,
                    target="production",
                    failed_release_id=("f" * 64 if command == "rollback" else None),
                    previous_release=("release-v1" if command == "rollback" else None),
                )
                context = SimpleNamespace(
                    cycle_id="c" * 64,
                    mode=command,
                    approval_id=approval.approval_id,
                    target=approval.target,
                    failed_release_id=approval.failed_release_id,
                    previous_release=approval.previous_release,
                )
                engine.inspect_current_unconsumed_approval.return_value = approval
                engine.inspect_active_external_context.return_value = context
                before = evidence.read_bytes()

                for cli_command in ("status", "resume"):
                    with self.subTest(command=cli_command):
                        output = io.StringIO()
                        reconciler = mock.Mock()
                        reconciler.reconcile.return_value = run
                        with (
                            redirect_stdout(output),
                            mock.patch(
                                "ship_flow.cli._repository", return_value=object()
                            ),
                            mock.patch(
                                "ship_flow.cli.Reconciler",
                                return_value=reconciler,
                            ),
                            mock.patch(
                                "ship_flow.cli._release_engine",
                                return_value=engine,
                            ),
                        ):
                            return_code = cli_main(
                                (
                                    cli_command,
                                    "--repo",
                                    ".",
                                    "--run-id",
                                    "run-context",
                                    "--json",
                                )
                            )
                        payload = json.loads(output.getvalue())
                        expected = {
                            "phase": phase.value,
                            "kind": "automatic",
                            "action": command,
                            "cycle_id": "c" * 64,
                            "approval_id": "a" * 64,
                            "target": "production",
                        }
                        if command == "rollback":
                            expected.update(
                                {
                                    "failed_release_id": "f" * 64,
                                    "previous_release": "release-v1",
                                }
                            )
                        self.assertEqual(return_code, 0)
                        self.assertEqual(payload["next_action"], expected)
                        self.assertEqual(evidence.read_bytes(), before)
                        self.assertFalse(sentinel.exists())
                engine.resume_external_cycle.assert_not_called()
                engine.release.assert_not_called()
                engine.rollback.assert_not_called()
                engine.verify_rollback.assert_not_called()


class UnknownOperationCliTests(unittest.TestCase):
    run_id = "run-unknown-cli"
    timestamp = "2026-07-16T00:00:00.000000Z"

    def invoke(self, *arguments: str) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with redirect_stdout(output):
            return_code = cli_main((*arguments, "--json"))
        payload = json.loads(output.getvalue())
        return return_code, payload

    def state(self, phase: Phase, revision: int) -> RunState:
        return RunState(
            run_id=self.run_id,
            phase=phase,
            revision=revision,
            created_at=self.timestamp,
            updated_at=self.timestamp,
        )

    def test_unknown_inspection_returns_exact_single_human_decision(self) -> None:
        blocked = self.state(Phase.BLOCKED, 17)
        store = SimpleNamespace(
            run_directory=Path("/private/runtime/run-unknown-cli"),
            load=mock.Mock(return_value=blocked),
        )
        decision = SimpleNamespace(
            run_id=self.run_id,
            cycle_id="a" * 64,
            mode="release",
            index=1,
            attempt=1,
            operation_name="deploy production",
            target="production",
            argv=("deploy-tool", "--candidate", "abc123"),
            reason="probe-inconclusive",
            unknown_receipt_sha256="b" * 64,
            operation_start_marker_id="c" * 64,
            blocked_revision=17,
            confirmation_token="d" * 64,
        )
        engine = mock.Mock()
        engine.inspect_unknown_operation.return_value = decision

        with (
            mock.patch("ship_flow.cli._repository", return_value=object()),
            mock.patch(
                "ship_flow.cli._live_release_context",
                return_value=(engine, store, blocked),
            ),
        ):
            return_code, payload = self.invoke(
                "reconcile-operation",
                "--repo",
                ".",
                "--run-id",
                self.run_id,
                "--expected-revision",
                "17",
                "--target",
                "production",
            )

        self.assertEqual(return_code, 0)
        self.assertEqual(
            payload["next_action"]["action"], "confirm_external_operation_outcome"
        )  # type: ignore[index]
        self.assertEqual(
            payload["decision"],
            {
                "run_id": self.run_id,
                "cycle_id": "a" * 64,
                "mode": "release",
                "index": 1,
                "attempt": 1,
                "operation_name": "deploy production",
                "target": "production",
                "argv": ["deploy-tool", "--candidate", "abc123"],
                "reason": "probe-inconclusive",
                "unknown_receipt_sha256": "b" * 64,
                "operation_start_marker_id": "c" * 64,
                "blocked_revision": 17,
                "confirmation_token": "d" * 64,
            },
        )
        engine.inspect_unknown_operation.assert_called_once_with(target="production")
        engine.record_operation_outcome.assert_not_called()

    def test_unknown_outcome_is_sealed_without_resuming_external_effect(self) -> None:
        blocked = self.state(Phase.BLOCKED, 17)
        restored = self.state(Phase.RELEASING, 18)
        store = SimpleNamespace(
            run_directory=Path("/private/runtime/run-unknown-cli"),
            load=mock.Mock(return_value=restored),
        )
        adjudication = SimpleNamespace(
            adjudication_id="e" * 64,
            mode="release",
            index=1,
            attempt=1,
            target="production",
            command_sha256="f" * 64,
            unknown_receipt_sha256="b" * 64,
            actor="human-owner",
            outcome="applied",
            reason="probe-inconclusive",
            recorded_at=self.timestamp,
        )
        engine = mock.Mock()
        engine.record_operation_outcome.return_value = adjudication

        with (
            mock.patch("ship_flow.cli._repository", return_value=object()),
            mock.patch(
                "ship_flow.cli._live_release_context",
                return_value=(engine, store, blocked),
            ),
        ):
            return_code, payload = self.invoke(
                "reconcile-operation",
                "--repo",
                ".",
                "--run-id",
                self.run_id,
                "--expected-revision",
                "17",
                "--target",
                "production",
                "--unknown-receipt-sha256",
                "b" * 64,
                "--confirmation-token",
                "d" * 64,
                "--actor",
                "human-owner",
                "--outcome",
                "applied",
            )

        self.assertEqual(return_code, 0)
        self.assertEqual(payload["state"]["phase"], "RELEASING")  # type: ignore[index]
        self.assertEqual(payload["adjudication"]["outcome"], "applied")  # type: ignore[index]
        engine.record_operation_outcome.assert_called_once_with(
            target="production",
            unknown_receipt_sha256="b" * 64,
            confirmation_token="d" * 64,
            expected_revision=17,
            actor="human-owner",
            outcome="applied",
        )
        engine.resume_external_cycle.assert_not_called()

    def test_release_without_approval_id_resumes_adjudicated_cycle(self) -> None:
        releasing = self.state(Phase.RELEASING, 18)
        syncing = self.state(Phase.SYNCING, 19)
        run = SimpleNamespace(state=releasing)
        ownership = object()
        store = SimpleNamespace(
            load=mock.Mock(return_value=syncing),
            run_directory=Path("/private/runtime/run-unknown-cli"),
        )
        gate_store = SimpleNamespace(load=mock.Mock(return_value=releasing))
        engine = mock.Mock()
        engine.resume_external_cycle.return_value = ()

        with (
            mock.patch("ship_flow.cli._repository", return_value=object()),
            mock.patch(
                "ship_flow.cli._load_run",
                return_value=(ownership, gate_store),
            ),
            mock.patch(
                "ship_flow.cli._preflight",
                return_value=(run, ownership, store),
            ),
            mock.patch("ship_flow.cli._release_engine", return_value=engine),
        ):
            return_code, payload = self.invoke(
                "release",
                "--repo",
                ".",
                "--run-id",
                self.run_id,
                "--expected-revision",
                "18",
                "--target",
                "production",
            )

        self.assertEqual(return_code, 0)
        self.assertTrue(payload["resumed"])
        self.assertEqual(payload["state"]["phase"], "SYNCING")  # type: ignore[index]
        engine.resume_external_cycle.assert_called_once_with(target="production")
        engine.release.assert_not_called()

    def test_fresh_external_gates_require_durable_approval_without_wal_change(
        self,
    ) -> None:
        cases = (
            (
                "release",
                (
                    Phase.PLANNING,
                    Phase.PLAN_REVIEW,
                    Phase.AWAITING_PLAN_APPROVAL,
                    Phase.DEVELOPING,
                    Phase.CODE_REVIEW,
                    Phase.VERIFYING,
                    Phase.AWAITING_RELEASE_APPROVAL,
                ),
                (),
            ),
            (
                "rollback",
                (
                    Phase.PLANNING,
                    Phase.PLAN_REVIEW,
                    Phase.AWAITING_PLAN_APPROVAL,
                    Phase.DEVELOPING,
                    Phase.CODE_REVIEW,
                    Phase.VERIFYING,
                    Phase.AWAITING_RELEASE_APPROVAL,
                    Phase.RELEASING,
                    Phase.POST_RELEASE_VERIFYING,
                    Phase.ROLLBACK_PENDING,
                ),
                (
                    "--failed-release-id",
                    "a" * 64,
                    "--previous-release",
                    "previous-v1",
                ),
            ),
        )
        for command, phases, extra_arguments in cases:
            with self.subTest(command=command):
                with tempfile.TemporaryDirectory() as temporary:
                    store = StateStore(Path(temporary) / "runs" / self.run_id)
                    state = store.create(self.run_id)
                    for phase in phases:
                        state = store.transition(
                            phase,
                            expected_revision=state.revision,
                        )
                    state_before = store.state_path.read_bytes()
                    events_before = store.events_path.read_bytes()
                    ownership = object()
                    preflight = mock.Mock(
                        side_effect=AssertionError(
                            "gate rejection must precede reconciliation"
                        )
                    )
                    with (
                        mock.patch("ship_flow.cli._repository", return_value=object()),
                        mock.patch(
                            "ship_flow.cli._load_run",
                            return_value=(ownership, store),
                        ),
                        mock.patch("ship_flow.cli._preflight", preflight),
                        mock.patch("ship_flow.cli._release_engine") as release_engine,
                    ):
                        return_code, payload = self.invoke(
                            command,
                            "--repo",
                            ".",
                            "--run-id",
                            self.run_id,
                            "--expected-revision",
                            str(state.revision),
                            "--target",
                            "production",
                            *extra_arguments,
                        )

                    self.assertEqual(return_code, 4)
                    self.assertEqual(payload["error"]["code"], "approval_required")  # type: ignore[index]
                    self.assertEqual(store.state_path.read_bytes(), state_before)
                    self.assertEqual(store.events_path.read_bytes(), events_before)
                    preflight.assert_not_called()
                    release_engine.assert_not_called()


if __name__ == "__main__":
    unittest.main()
