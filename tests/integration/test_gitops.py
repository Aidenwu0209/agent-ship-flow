from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ship_flow import gitops as gitops_module
from ship_flow import store as store_module
from ship_flow.gitops import (
    BareRepositoryError,
    CandidateCommitPartialError,
    CandidateRecoveryBlockedError,
    CandidateSafetyError,
    CleanupPartialError,
    CleanupRecoveryBlockedError,
    CleanupRefusedError,
    DirtyBaseError,
    GitCommandError,
    GitRepository,
    InvalidBranchError,
    OwnershipError,
    ResourceCollisionError,
    candidate_identity,
    cleanup_owned_worktree,
    commit_candidate,
    create_run_worktree,
)
from ship_flow.store import FileLock, LockUnavailableError
from tests.support import git, git_output, initialize_repository


class GitRepositoryIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.primary = self.root / "中文 仓库"
        self.base_oid = initialize_repository(self.primary)

    def test_git_output_line_only_removes_one_line_feed(self) -> None:
        self.assertEqual(gitops_module._git_output_line("value\r\n"), "value\r")
        self.assertEqual(gitops_module._git_output_line("value\n\n"), "value\n")

    def test_discover_finds_primary_checkout_from_primary_and_linked_worktrees(
        self,
    ) -> None:
        linked = self.root / "已链接 工作树"
        git(self.primary, "worktree", "add", "-b", "linked-test", str(linked))
        (self.primary / "nested").mkdir()
        (linked / "nested").mkdir()

        from_primary = GitRepository.discover(self.primary / "nested")
        from_linked = GitRepository.discover(linked / "nested")

        self.assertEqual(from_primary, from_linked)
        self.assertEqual(from_primary.primary_checkout, self.primary.resolve())
        self.assertEqual(
            from_primary.git_common_directory, (self.primary / ".git").resolve()
        )

    def test_discover_rejects_a_bare_repository(self) -> None:
        bare = self.root / "bare repository.git"
        bare.mkdir()
        git(bare, "init", "--bare", "--initial-branch=main")

        with self.assertRaises(BareRepositoryError):
            GitRepository.discover(bare)

    def test_create_run_worktree_records_canonical_run_ownership(self) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "运行 工作树"

        ownership = create_run_worktree(
            repository,
            run_id="run-zh-001",
            branch="ship/中文-goal-001",
            worktree_path=worktree,
            base_ref="main",
            require_clean_base=True,
        )

        self.assertEqual(ownership.primary_checkout, self.primary.resolve())
        self.assertEqual(ownership.worktree_path, worktree.resolve())
        self.assertEqual(ownership.base_oid, self.base_oid)
        self.assertEqual(ownership.branch, "ship/中文-goal-001")
        self.assertEqual(git_output(worktree, "rev-parse", "HEAD"), self.base_oid)
        self.assertEqual(
            git_output(worktree, "branch", "--show-current"),
            "ship/中文-goal-001",
        )
        record = json.loads(ownership.record_path.read_text(encoding="utf-8"))
        self.assertEqual(record["run_id"], "run-zh-001")
        self.assertEqual(record["base_oid"], self.base_oid)
        self.assertEqual(record["last_known_oid"], self.base_oid)
        self.assertEqual(record["worktree_path"], str(worktree.resolve()))
        self.assertEqual(record["git_backlink"], str(ownership.git_backlink))

    def test_candidate_identity_rejects_unrecorded_or_non_base_branch_movement(
        self,
    ) -> None:
        for suffix, parent_arguments in (
            ("descendant", ("-p", self.base_oid)),
            ("unrelated", ()),
        ):
            with self.subTest(movement=suffix):
                repository = GitRepository.discover(self.primary)
                worktree = self.root / f"moved {suffix}"
                branch = f"ship/moved-{suffix}"
                ownership = create_run_worktree(
                    repository,
                    run_id=f"run-moved-{suffix}",
                    branch=branch,
                    worktree_path=worktree,
                )
                tree_oid = git_output(self.primary, "rev-parse", "HEAD^{tree}")
                moved_oid = git_output(
                    self.primary,
                    "commit-tree",
                    tree_oid,
                    *parent_arguments,
                    "-m",
                    f"unrecorded {suffix}",
                )
                git(
                    self.primary,
                    "update-ref",
                    f"refs/heads/{branch}",
                    moved_oid,
                    self.base_oid,
                )

                with self.assertRaises(OwnershipError):
                    candidate_identity(ownership)

    def test_ownership_runtime_directories_and_record_are_private(self) -> None:
        repository = GitRepository.discover(self.primary)
        ownership = create_run_worktree(
            repository,
            run_id="run-private-record",
            branch="ship/private-record",
            worktree_path=self.root / "private record worktree",
        )
        runtime_root = repository.git_common_directory / "ship-flow"

        for directory in (
            runtime_root,
            runtime_root / "runs",
            ownership.record_path.parent,
        ):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(ownership.record_path.stat().st_mode), 0o600)

    def test_ownership_replace_keeps_stable_parent_fd_during_directory_swap(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        ownership = create_run_worktree(
            repository,
            run_id="run-ownership-parent-swap",
            branch="ship/ownership-parent-swap",
            worktree_path=self.root / "ownership parent swap",
        )
        run_directory = ownership.record_path.parent
        displaced = self.root / "displaced-ownership"
        outside = self.root / "outside-ownership"
        outside.mkdir()
        outside_record = outside / ownership.record_path.name
        outside_record.write_text("foreign\n", encoding="utf-8")
        outside_record.chmod(0o644)
        outside_before = {
            entry.name: (entry.read_bytes(), stat.S_IMODE(entry.stat().st_mode))
            for entry in outside.iterdir()
        }
        real_open = store_module._open_private_directory
        swapped = False

        def open_then_swap(path: Path, *, private_root: Path | None = None) -> int:
            nonlocal swapped
            descriptor = real_open(path, private_root=private_root)
            if not swapped and Path(path) == run_directory:
                run_directory.rename(displaced)
                run_directory.symlink_to(outside, target_is_directory=True)
                swapped = True
            return descriptor

        changed = replace(ownership, last_known_oid=ownership.base_oid)
        with mock.patch.object(
            store_module,
            "_open_private_directory",
            side_effect=open_then_swap,
        ):
            gitops_module._replace_ownership_record(changed)

        self.assertTrue(swapped)
        self.assertEqual(
            {
                entry.name: (entry.read_bytes(), stat.S_IMODE(entry.stat().st_mode))
                for entry in outside.iterdir()
            },
            outside_before,
        )
        self.assertEqual(
            json.loads(
                (displaced / ownership.record_path.name).read_text(encoding="utf-8")
            ),
            gitops_module._ownership_payload(changed),
        )

    def test_create_rejects_an_invalid_or_existing_branch_without_creating_a_path(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        git(self.primary, "branch", "ship/existing")

        invalid_path = self.root / "invalid-branch-worktree"
        with self.assertRaises(InvalidBranchError):
            create_run_worktree(
                repository,
                run_id="run-invalid",
                branch="-unsafe",
                worktree_path=invalid_path,
            )
        self.assertFalse(os.path.lexists(invalid_path))

        collision_path = self.root / "existing-branch-worktree"
        with self.assertRaises(ResourceCollisionError):
            create_run_worktree(
                repository,
                run_id="run-branch-collision",
                branch="ship/existing",
                worktree_path=collision_path,
            )
        self.assertFalse(os.path.lexists(collision_path))

    def test_create_rejects_existing_and_symbolic_link_paths_before_branch_creation(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        existing = self.root / "existing path"
        existing.mkdir()
        symlink_target = self.root / "missing symlink target"
        symlink_path = self.root / "symbolic worktree"
        symlink_path.symlink_to(symlink_target, target_is_directory=True)

        for run_id, branch, path in (
            ("run-existing-path", "ship/existing-path", existing),
            ("run-symlink-path", "ship/symlink-path", symlink_path),
        ):
            with self.subTest(path=path):
                with self.assertRaises(ResourceCollisionError):
                    create_run_worktree(
                        repository,
                        run_id=run_id,
                        branch=branch,
                        worktree_path=path,
                    )
                self.assertNotEqual(
                    git(
                        self.primary,
                        "show-ref",
                        "--verify",
                        "--quiet",
                        f"refs/heads/{branch}",
                        check=False,
                    ).returncode,
                    0,
                )

    def test_dirty_base_policy_refuses_or_preserves_primary_changes(self) -> None:
        repository = GitRepository.discover(self.primary)
        (self.primary / "README.md").write_text("user change\n", encoding="utf-8")
        refused_path = self.root / "dirty-refused"

        with self.assertRaises(DirtyBaseError):
            create_run_worktree(
                repository,
                run_id="run-dirty-refused",
                branch="ship/dirty-refused",
                worktree_path=refused_path,
                require_clean_base=True,
            )

        allowed_path = self.root / "dirty allowed"
        ownership = create_run_worktree(
            repository,
            run_id="run-dirty-allowed",
            branch="ship/dirty-allowed",
            worktree_path=allowed_path,
            require_clean_base=False,
        )
        self.assertEqual(ownership.base_oid, self.base_oid)
        self.assertEqual(
            (self.primary / "README.md").read_text(encoding="utf-8"),
            "user change\n",
        )
        self.assertEqual(
            (allowed_path / "README.md").read_text(encoding="utf-8"),
            "initial\n",
        )
        self.assertFalse(os.path.lexists(refused_path))

    def test_created_worktree_remains_bound_to_recorded_oid_when_base_ref_moves(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "base movement"
        ownership = create_run_worktree(
            repository,
            run_id="run-base-movement",
            branch="ship/base-movement",
            worktree_path=worktree,
            base_ref="main",
        )

        (self.primary / "after.txt").write_text("later\n", encoding="utf-8")
        git(self.primary, "add", "after.txt")
        git(self.primary, "commit", "-m", "move base")
        moved_oid = git_output(self.primary, "rev-parse", "main")

        self.assertNotEqual(moved_oid, ownership.base_oid)
        self.assertEqual(ownership.base_oid, self.base_oid)
        self.assertEqual(git_output(worktree, "rev-parse", "HEAD"), self.base_oid)

    def test_partial_worktree_creation_compensates_only_resources_from_this_run(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        foreign_branch = "ship/foreign"
        git(self.primary, "branch", foreign_branch)
        foreign_path = self.root / "foreign path"
        foreign_path.mkdir()
        (foreign_path / "keep.txt").write_text("keep\n", encoding="utf-8")
        hook = self.primary / ".git" / "hooks" / "post-checkout"
        hook.write_text("#!/bin/sh\nexit 23\n", encoding="utf-8")
        hook.chmod(0o755)
        failed_path = self.root / "half-created worktree"

        with self.assertRaises(GitCommandError):
            create_run_worktree(
                repository,
                run_id="run-half-created",
                branch="ship/half-created",
                worktree_path=failed_path,
            )

        self.assertFalse(os.path.lexists(failed_path))
        self.assertNotEqual(
            git(
                self.primary,
                "show-ref",
                "--verify",
                "--quiet",
                "refs/heads/ship/half-created",
                check=False,
            ).returncode,
            0,
        )
        self.assertEqual(
            git_output(self.primary, "rev-parse", foreign_branch), self.base_oid
        )
        self.assertEqual(
            (foreign_path / "keep.txt").read_text(encoding="utf-8"), "keep\n"
        )
        self.assertFalse(
            (
                repository.git_common_directory
                / "ship-flow"
                / "runs"
                / "run-half-created"
            ).exists()
        )

    def test_creation_intent_preserves_a_branch_that_wins_the_update_ref_race(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        branch = "ship/external-race"
        branch_ref = f"refs/heads/{branch}"
        worktree = self.root / "external race worktree"
        real_git = gitops_module._git
        raced = False

        def create_foreign_branch_before_compare_and_swap(
            cwd: Path,
            *arguments: str,
            **kwargs: object,
        ) -> object:
            nonlocal raced
            if (
                not raced
                and arguments[:2] == ("update-ref", branch_ref)
                and len(arguments) == 4
            ):
                raced = True
                real_git(cwd, "update-ref", branch_ref, self.base_oid)
            return real_git(cwd, *arguments, **kwargs)

        with mock.patch.object(
            gitops_module,
            "_git",
            side_effect=create_foreign_branch_before_compare_and_swap,
        ):
            with self.assertRaises(GitCommandError):
                create_run_worktree(
                    repository,
                    run_id="run-external-race",
                    branch=branch,
                    worktree_path=worktree,
                )

        self.assertTrue(raced)
        branch_result = git(self.primary, "rev-parse", branch, check=False)
        self.assertEqual(branch_result.returncode, 0)
        self.assertEqual(branch_result.stdout.strip(), self.base_oid)
        self.assertFalse(os.path.lexists(worktree))
        self.assertTrue(
            (
                repository.git_common_directory
                / "ship-flow"
                / "creation-intents"
                / "run-external-race.json"
            ).is_file()
        )

    def test_repository_lock_serializes_worktree_creation(self) -> None:
        repository = GitRepository.discover(self.primary)
        path = self.root / "locked worktree"

        with FileLock.repository(repository.git_common_directory):
            with self.assertRaises(LockUnavailableError):
                create_run_worktree(
                    repository,
                    run_id="run-locked",
                    branch="ship/locked",
                    worktree_path=path,
                )

        self.assertFalse(os.path.lexists(path))

    def test_repository_lock_serializes_candidate_identity_and_commit(self) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "locked candidate"
        ownership = create_run_worktree(
            repository,
            run_id="run-locked-candidate",
            branch="ship/locked-candidate",
            worktree_path=worktree,
        )
        (worktree / "README.md").write_text("candidate\n", encoding="utf-8")

        with FileLock.repository(repository.git_common_directory):
            with self.assertRaises(LockUnavailableError):
                candidate_identity(ownership)
            with self.assertRaises(LockUnavailableError):
                commit_candidate(
                    ownership,
                    message="feat: locked candidate",
                    approved_paths=("README.md",),
                )

        self.assertEqual(git_output(worktree, "rev-parse", "HEAD"), self.base_oid)

    def test_index_sync_failure_returns_candidate_receipt_and_retry_reconciles(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "partial candidate"
        ownership = create_run_worktree(
            repository,
            run_id="run-partial-candidate",
            branch="ship/partial-candidate",
            worktree_path=worktree,
        )
        (worktree / "README.md").write_text("candidate\n", encoding="utf-8")
        index_path = Path(git_output(worktree, "rev-parse", "--git-path", "index"))
        if not index_path.is_absolute():
            index_path = worktree / index_path
        index_lock = index_path.with_name("index.lock")
        index_lock.write_text("inject sync failure\n", encoding="utf-8")

        with self.assertRaises(CandidateCommitPartialError) as raised:
            commit_candidate(
                ownership,
                message="feat: partial candidate",
                approved_paths=("README.md",),
            )

        identity = raised.exception.identity
        self.assertEqual(raised.exception.stage, "index-sync")
        self.assertEqual(git_output(worktree, "rev-parse", "HEAD"), identity.commit_oid)
        record = json.loads(ownership.record_path.read_text(encoding="utf-8"))
        self.assertEqual(record["last_known_oid"], identity.commit_oid)
        self.assertEqual(git_output(worktree, "rev-list", "--count", "HEAD"), "2")

        index_lock.unlink()
        reconciled = commit_candidate(
            ownership,
            message="feat: partial candidate",
            approved_paths=("README.md",),
        )

        self.assertEqual(reconciled, identity)
        self.assertEqual(git_output(worktree, "rev-list", "--count", "HEAD"), "2")
        self.assertEqual(git_output(worktree, "status", "--porcelain"), "")

    def test_pending_candidate_recovers_after_restart_before_new_changes_commit(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "durable pending candidate"
        ownership = create_run_worktree(
            repository,
            run_id="run-durable-pending-candidate",
            branch="ship/durable-pending-candidate",
            worktree_path=worktree,
        )
        (worktree / "README.md").write_text("candidate\n", encoding="utf-8")
        receipt_path = ownership.record_path.parent / "candidate-operation.json"

        with mock.patch(
            "ship_flow.gitops._replace_ownership_record",
            side_effect=OSError("injected ownership write failure"),
        ):
            with self.assertRaises(CandidateCommitPartialError) as raised:
                commit_candidate(
                    ownership,
                    message="feat: durable pending candidate",
                    approved_paths=("README.md",),
                )

        identity = raised.exception.identity
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
        self.assertEqual(receipt["run_id"], ownership.run_id)
        self.assertEqual(receipt["branch"], ownership.branch)
        self.assertEqual(receipt["old_oid"], self.base_oid)
        self.assertEqual(receipt["new_oid"], identity.commit_oid)
        self.assertEqual(receipt["tree_oid"], identity.tree_oid)
        self.assertEqual(receipt["stage"], "ref-updated")
        self.assertEqual(receipt["subject"], "feat: durable pending candidate")
        self.assertEqual(git_output(worktree, "rev-list", "--count", "HEAD"), "2")

        restarted = replace(ownership, last_known_oid=self.base_oid)
        (worktree / "new-after-restart.txt").write_text("later\n", encoding="utf-8")
        recovered = commit_candidate(
            restarted,
            message="feat: a different next candidate",
            approved_paths=("new-after-restart.txt",),
        )

        self.assertEqual(recovered, identity)
        self.assertEqual(git_output(worktree, "rev-list", "--count", "HEAD"), "2")
        self.assertFalse(receipt_path.exists())
        record = json.loads(restarted.record_path.read_text(encoding="utf-8"))
        self.assertEqual(record["last_known_oid"], identity.commit_oid)
        self.assertEqual(
            (worktree / "new-after-restart.txt").read_text(encoding="utf-8"),
            "later\n",
        )

    def test_pending_candidate_continues_when_branch_is_still_at_old_oid(self) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "pending before ref update"
        ownership = create_run_worktree(
            repository,
            run_id="run-pending-before-ref-update",
            branch="ship/pending-before-ref-update",
            worktree_path=worktree,
        )
        (worktree / "README.md").write_text("candidate\n", encoding="utf-8")
        hook = self.primary / ".git" / "hooks" / "reference-transaction"
        marker = self.root / "reject-update-once"
        hook.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "prepared" ] && [ ! -e "$SHIP_REJECT_MARKER" ]; then\n'
            '  : > "$SHIP_REJECT_MARKER"\n'
            "  exit 1\n"
            "fi\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)

        with mock.patch.dict(os.environ, {"SHIP_REJECT_MARKER": str(marker)}):
            with self.assertRaises(CandidateCommitPartialError) as raised:
                commit_candidate(
                    ownership,
                    message="feat: pending before ref update",
                    approved_paths=("README.md",),
                )

            self.assertEqual(raised.exception.stage, "ref-update")
            receipt_path = ownership.record_path.parent / "candidate-operation.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["stage"], "prepared")
            self.assertEqual(git_output(worktree, "rev-parse", "HEAD"), self.base_oid)

            recovered = commit_candidate(
                replace(ownership, last_known_oid=self.base_oid),
                message="ignored during recovery",
                approved_paths=("README.md",),
            )

        self.assertEqual(recovered, raised.exception.identity)
        self.assertEqual(git_output(worktree, "rev-list", "--count", "HEAD"), "2")
        self.assertFalse(receipt_path.exists())

    def test_pending_candidate_blocks_when_branch_is_neither_old_nor_new(self) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "blocked pending candidate"
        ownership = create_run_worktree(
            repository,
            run_id="run-blocked-pending-candidate",
            branch="ship/blocked-pending-candidate",
            worktree_path=worktree,
        )
        (worktree / "README.md").write_text("candidate\n", encoding="utf-8")
        hook = self.primary / ".git" / "hooks" / "reference-transaction"
        hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        hook.chmod(0o755)
        with self.assertRaises(CandidateCommitPartialError):
            commit_candidate(
                ownership,
                message="feat: blocked pending candidate",
                approved_paths=("README.md",),
            )
        hook.unlink()
        tree_oid = git_output(self.primary, "rev-parse", "HEAD^{tree}")
        foreign_oid = git_output(
            self.primary,
            "commit-tree",
            tree_oid,
            "-m",
            "foreign branch movement",
        )
        git(
            self.primary,
            "update-ref",
            f"refs/heads/{ownership.branch}",
            foreign_oid,
            self.base_oid,
        )

        with self.assertRaises(CandidateRecoveryBlockedError) as raised:
            commit_candidate(
                replace(ownership, last_known_oid=self.base_oid),
                message="must not proceed",
                approved_paths=("README.md",),
            )

        self.assertEqual(raised.exception.observed_oid, foreign_oid)
        self.assertTrue(
            (ownership.record_path.parent / "candidate-operation.json").exists()
        )
        self.assertEqual(git_output(worktree, "rev-parse", "HEAD"), foreign_oid)

    def test_engine_stages_and_creates_an_immutable_candidate_commit(self) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "candidate worktree"
        ownership = create_run_worktree(
            repository,
            run_id="run-candidate",
            branch="ship/candidate",
            worktree_path=worktree,
        )
        (worktree / "README.md").write_text("candidate\n", encoding="utf-8")
        source = worktree / "src" / "中文 文件.py"
        source.parent.mkdir()
        source.write_text("VALUE = 1\n", encoding="utf-8")

        identity = commit_candidate(
            ownership,
            message="feat: create candidate",
            approved_paths=("README.md", "src"),
        )

        self.assertNotEqual(identity.commit_oid, self.base_oid)
        self.assertEqual(identity.commit_oid, git_output(worktree, "rev-parse", "HEAD"))
        self.assertEqual(
            identity.tree_oid, git_output(worktree, "rev-parse", "HEAD^{tree}")
        )
        self.assertEqual(
            git_output(worktree, "log", "-1", "--pretty=%s"),
            "feat: create candidate",
        )
        self.assertEqual(
            set(
                git_output(
                    worktree,
                    "diff-tree",
                    "--no-commit-id",
                    "--name-only",
                    "-r",
                    "HEAD",
                ).splitlines()
            ),
            {"README.md", "src/中文 文件.py"},
        )
        self.assertEqual(git_output(worktree, "status", "--porcelain"), "")
        self.assertEqual(candidate_identity(ownership), identity)

    def test_candidate_commit_intercepts_secret_unplanned_and_oversized_staged_files(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "unsafe candidate"
        ownership = create_run_worktree(
            repository,
            run_id="run-unsafe-candidate",
            branch="ship/unsafe-candidate",
            worktree_path=worktree,
        )
        (worktree / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
        private_key = worktree / "keys" / "deploy.pem"
        private_key.parent.mkdir()
        private_key.write_text(
            "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
            encoding="utf-8",
        )
        large = worktree / "approved" / "large.bin"
        large.parent.mkdir()
        large.write_bytes(b"x" * 129)
        (worktree / "unplanned.txt").write_text("outside plan\n", encoding="utf-8")
        git(worktree, "add", "--all")
        staged_before = git_output(
            worktree, "diff", "--cached", "--name-only", "--diff-filter=ACMR"
        )

        with self.assertRaises(CandidateSafetyError) as raised:
            commit_candidate(
                ownership,
                message="feat: unsafe candidate",
                approved_paths=(".env", "keys", "approved"),
                max_file_bytes=64,
            )

        reasons_by_path = {
            finding.path: set(finding.reasons) for finding in raised.exception.findings
        }
        self.assertIn("environment-file", reasons_by_path[".env"])
        self.assertIn("private-key", reasons_by_path["keys/deploy.pem"])
        self.assertIn("oversized", reasons_by_path["approved/large.bin"])
        self.assertIn("outside-approved-plan", reasons_by_path["unplanned.txt"])
        self.assertEqual(git_output(worktree, "rev-parse", "HEAD"), self.base_oid)
        self.assertEqual(
            git_output(
                worktree, "diff", "--cached", "--name-only", "--diff-filter=ACMR"
            ),
            staged_before,
        )

    def test_candidate_commit_refuses_a_forged_or_missing_ownership_record(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "owned candidate"
        ownership = create_run_worktree(
            repository,
            run_id="run-owned-candidate",
            branch="ship/owned-candidate",
            worktree_path=worktree,
        )
        (self.primary / "README.md").write_text(
            "user primary change\n", encoding="utf-8"
        )
        forged = replace(ownership, worktree_path=self.primary.resolve())

        with self.assertRaises(OwnershipError):
            commit_candidate(
                forged,
                message="feat: must not commit primary",
                approved_paths=("README.md",),
            )

        ownership.record_path.unlink()
        (worktree / "README.md").write_text("candidate\n", encoding="utf-8")
        with self.assertRaises(OwnershipError):
            commit_candidate(
                ownership,
                message="feat: must remain owned",
                approved_paths=("README.md",),
            )
        self.assertEqual(git_output(self.primary, "rev-parse", "HEAD"), self.base_oid)
        self.assertEqual(git_output(worktree, "rev-parse", "HEAD"), self.base_oid)

    def test_cleanup_requires_action_time_approval_even_for_a_clean_merged_branch(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "cleanup approval"
        ownership = create_run_worktree(
            repository,
            run_id="run-cleanup-approval",
            branch="ship/cleanup-approval",
            worktree_path=worktree,
        )

        with self.assertRaises(CleanupRefusedError) as raised:
            cleanup_owned_worktree(ownership, approved=False)

        self.assertIn("approval", raised.exception.conditions)
        self.assertTrue(worktree.is_dir())

    def test_cleanup_refuses_dirty_or_unowned_worktrees(self) -> None:
        repository = GitRepository.discover(self.primary)
        dirty_path = self.root / "dirty cleanup"
        dirty = create_run_worktree(
            repository,
            run_id="run-dirty-cleanup",
            branch="ship/dirty-cleanup",
            worktree_path=dirty_path,
        )
        (dirty_path / "README.md").write_text("dirty\n", encoding="utf-8")

        with self.assertRaises(CleanupRefusedError) as dirty_error:
            cleanup_owned_worktree(dirty, approved=True)
        self.assertIn("dirty", dirty_error.exception.conditions)
        self.assertTrue(dirty_path.is_dir())

        unowned_path = self.root / "unowned cleanup"
        unowned = create_run_worktree(
            repository,
            run_id="run-unowned-cleanup",
            branch="ship/unowned-cleanup",
            worktree_path=unowned_path,
        )
        unowned.record_path.unlink()

        with self.assertRaises(CleanupRefusedError) as unowned_error:
            cleanup_owned_worktree(unowned, approved=True)
        self.assertIn("unowned", unowned_error.exception.conditions)
        self.assertTrue(unowned_path.is_dir())

    def test_cleanup_rejects_a_symbolic_link_substituted_for_the_git_backlink(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "backlink substitution"
        ownership = create_run_worktree(
            repository,
            run_id="run-backlink-substitution",
            branch="ship/backlink-substitution",
            worktree_path=worktree,
        )
        marker = worktree / ".git"
        copied_marker = self.root / "copied git backlink"
        copied_marker.write_bytes(marker.read_bytes())
        marker.unlink()
        marker.symlink_to(copied_marker)

        with self.assertRaises(CleanupRefusedError) as raised:
            cleanup_owned_worktree(ownership, approved=True)

        self.assertIn("unowned", raised.exception.conditions)
        self.assertTrue(worktree.is_dir())

    def test_cleanup_refuses_unmerged_without_exact_approval_then_preserves_branch(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "unmerged cleanup"
        ownership = create_run_worktree(
            repository,
            run_id="run-unmerged-cleanup",
            branch="ship/unmerged-cleanup",
            worktree_path=worktree,
        )
        (worktree / "candidate.txt").write_text("candidate\n", encoding="utf-8")
        identity = commit_candidate(
            ownership,
            message="feat: unmerged candidate",
            approved_paths=("candidate.txt",),
        )

        with self.assertRaises(CleanupRefusedError) as raised:
            cleanup_owned_worktree(ownership, approved=True)
        self.assertIn("unmerged", raised.exception.conditions)
        self.assertTrue(worktree.is_dir())

        cleanup_owned_worktree(
            ownership,
            approved=True,
            approved_conditions=("unmerged",),
        )
        self.assertFalse(os.path.lexists(worktree))
        self.assertEqual(
            git_output(self.primary, "rev-parse", "ship/unmerged-cleanup"),
            identity.commit_oid,
        )
        self.assertFalse(ownership.record_path.exists())

    def test_cleanup_removes_an_owned_clean_merged_worktree_and_branch(self) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "merged cleanup"
        ownership = create_run_worktree(
            repository,
            run_id="run-merged-cleanup",
            branch="ship/merged-cleanup",
            worktree_path=worktree,
        )

        cleanup_owned_worktree(ownership, approved=True)

        self.assertFalse(os.path.lexists(worktree))
        self.assertNotEqual(
            git(
                self.primary,
                "show-ref",
                "--verify",
                "--quiet",
                "refs/heads/ship/merged-cleanup",
                check=False,
            ).returncode,
            0,
        )
        self.assertFalse(ownership.record_path.exists())

    def test_cleanup_recovers_after_worktree_removal_progress_write_is_interrupted(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "interrupted cleanup worktree"
        ownership = create_run_worktree(
            repository,
            run_id="run-interrupted-cleanup-worktree",
            branch="ship/interrupted-cleanup-worktree",
            worktree_path=worktree,
        )
        receipt_path = ownership.record_path.parent / "cleanup-operation.json"
        real_write_receipt = gitops_module._write_cleanup_receipt

        def interrupt_progress_write(
            owned: object,
            receipt: dict[str, object],
            *,
            stage: str,
        ) -> dict[str, object]:
            if stage == "worktree-removed":
                raise OSError("simulated interruption after worktree removal")
            return real_write_receipt(owned, receipt, stage=stage)

        with mock.patch.object(
            gitops_module,
            "_write_cleanup_receipt",
            side_effect=interrupt_progress_write,
        ):
            with self.assertRaises(CleanupPartialError) as raised:
                cleanup_owned_worktree(ownership, approved=True)

        self.assertEqual(raised.exception.stage, "receipt-worktree-removed")
        self.assertFalse(os.path.lexists(worktree))
        self.assertTrue(ownership.record_path.is_file())
        self.assertTrue(receipt_path.is_file())
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["stage"], "prepared")
        self.assertEqual(receipt["run_id"], ownership.run_id)
        self.assertEqual(receipt["branch"], ownership.branch)
        self.assertEqual(receipt["branch_oid"], ownership.last_known_oid)
        self.assertEqual(receipt["worktree_path"], str(ownership.worktree_path))
        self.assertEqual(receipt["target_oid"], self.base_oid)

        cleanup_owned_worktree(ownership, approved=True)

        self.assertFalse(receipt_path.exists())
        self.assertFalse(ownership.record_path.exists())
        self.assertNotEqual(
            git(
                self.primary,
                "show-ref",
                "--verify",
                "--quiet",
                "refs/heads/ship/interrupted-cleanup-worktree",
                check=False,
            ).returncode,
            0,
        )

    def test_cleanup_recovers_after_branch_removal_progress_write_is_interrupted(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "interrupted cleanup branch"
        ownership = create_run_worktree(
            repository,
            run_id="run-interrupted-cleanup-branch",
            branch="ship/interrupted-cleanup-branch",
            worktree_path=worktree,
        )
        receipt_path = ownership.record_path.parent / "cleanup-operation.json"
        real_write_receipt = gitops_module._write_cleanup_receipt

        def interrupt_progress_write(
            owned: object,
            receipt: dict[str, object],
            *,
            stage: str,
        ) -> dict[str, object]:
            if stage == "branch-handled":
                raise OSError("simulated interruption after branch removal")
            return real_write_receipt(owned, receipt, stage=stage)

        with mock.patch.object(
            gitops_module,
            "_write_cleanup_receipt",
            side_effect=interrupt_progress_write,
        ):
            with self.assertRaises(CleanupPartialError) as raised:
                cleanup_owned_worktree(ownership, approved=True)

        self.assertEqual(raised.exception.stage, "receipt-branch-handled")
        self.assertFalse(os.path.lexists(worktree))
        self.assertIsNone(
            gitops_module._branch_oid_or_none(repository, ownership.branch)
        )
        self.assertTrue(ownership.record_path.is_file())
        self.assertEqual(
            json.loads(receipt_path.read_text(encoding="utf-8"))["stage"],
            "worktree-removed",
        )

        cleanup_owned_worktree(ownership, approved=True)

        self.assertFalse(receipt_path.exists())
        self.assertFalse(ownership.record_path.exists())

    def test_cleanup_recovers_after_ownership_removal_progress_write_is_interrupted(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "interrupted cleanup ownership"
        ownership = create_run_worktree(
            repository,
            run_id="run-interrupted-cleanup-ownership",
            branch="ship/interrupted-cleanup-ownership",
            worktree_path=worktree,
        )
        receipt_path = ownership.record_path.parent / "cleanup-operation.json"
        real_write_receipt = gitops_module._write_cleanup_receipt

        def interrupt_progress_write(
            owned: object,
            receipt: dict[str, object],
            *,
            stage: str,
        ) -> dict[str, object]:
            if stage == "ownership-removed":
                raise OSError("simulated interruption after ownership removal")
            return real_write_receipt(owned, receipt, stage=stage)

        with mock.patch.object(
            gitops_module,
            "_write_cleanup_receipt",
            side_effect=interrupt_progress_write,
        ):
            with self.assertRaises(CleanupPartialError) as raised:
                cleanup_owned_worktree(ownership, approved=True)

        self.assertEqual(raised.exception.stage, "receipt-ownership-removed")
        self.assertFalse(os.path.lexists(worktree))
        self.assertIsNone(
            gitops_module._branch_oid_or_none(repository, ownership.branch)
        )
        self.assertFalse(ownership.record_path.exists())
        self.assertEqual(
            json.loads(receipt_path.read_text(encoding="utf-8"))["stage"],
            "branch-handled",
        )

        cleanup_owned_worktree(ownership, approved=True)

        self.assertFalse(receipt_path.exists())
        self.assertFalse(ownership.record_path.parent.exists())

    def test_cleanup_recovery_preserves_an_atomically_replaced_ownership_record(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "replaced cleanup ownership"
        ownership = create_run_worktree(
            repository,
            run_id="run-replaced-cleanup-ownership",
            branch="ship/replaced-cleanup-ownership",
            worktree_path=worktree,
        )
        real_remove_durable_file = gitops_module._remove_durable_file

        def interrupt_ownership_removal(path: Path) -> None:
            if path == ownership.record_path:
                raise OSError("simulated interruption before ownership removal")
            real_remove_durable_file(path)

        with mock.patch.object(
            gitops_module,
            "_remove_durable_file",
            side_effect=interrupt_ownership_removal,
        ):
            with self.assertRaises(CleanupPartialError) as raised:
                cleanup_owned_worktree(ownership, approved=True)

        self.assertEqual(raised.exception.stage, "ownership-remove")
        replacement_payload = json.loads(
            ownership.record_path.read_text(encoding="utf-8")
        )
        replacement_payload["run_id"] = "foreign-run"
        replacement = ownership.record_path.with_name("replacement.json")
        replacement.write_text(
            json.dumps(replacement_payload, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(replacement, ownership.record_path)
        replacement_bytes = ownership.record_path.read_bytes()

        with self.assertRaises(OwnershipError):
            cleanup_owned_worktree(ownership, approved=True)

        self.assertEqual(ownership.record_path.read_bytes(), replacement_bytes)
        self.assertTrue(
            (ownership.record_path.parent / "cleanup-operation.json").is_file()
        )

    def test_cleanup_recovery_preserves_a_replaced_branch_and_foreign_path(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)

        for suffix, replacement in (("branch", "branch"), ("path", "path")):
            with self.subTest(replacement=replacement):
                worktree = self.root / f"foreign cleanup {suffix}"
                ownership = create_run_worktree(
                    repository,
                    run_id=f"run-foreign-cleanup-{suffix}",
                    branch=f"ship/foreign-cleanup-{suffix}",
                    worktree_path=worktree,
                )
                real_write_receipt = gitops_module._write_cleanup_receipt

                def interrupt_progress_write(
                    owned: object,
                    receipt: dict[str, object],
                    *,
                    stage: str,
                ) -> dict[str, object]:
                    if stage == "worktree-removed":
                        raise OSError("simulated interruption after worktree removal")
                    return real_write_receipt(owned, receipt, stage=stage)

                with mock.patch.object(
                    gitops_module,
                    "_write_cleanup_receipt",
                    side_effect=interrupt_progress_write,
                ):
                    with self.assertRaises(CleanupPartialError):
                        cleanup_owned_worktree(ownership, approved=True)

                if replacement == "branch":
                    tree_oid = git_output(self.primary, "rev-parse", "HEAD^{tree}")
                    foreign_oid = git_output(
                        self.primary,
                        "commit-tree",
                        tree_oid,
                        "-p",
                        self.base_oid,
                        "-m",
                        "foreign branch replacement",
                    )
                    git(
                        self.primary,
                        "update-ref",
                        f"refs/heads/{ownership.branch}",
                        foreign_oid,
                        ownership.last_known_oid,
                    )
                    with self.assertRaises(CleanupRecoveryBlockedError):
                        cleanup_owned_worktree(ownership, approved=True)
                    self.assertEqual(
                        git_output(self.primary, "rev-parse", ownership.branch),
                        foreign_oid,
                    )
                else:
                    worktree.mkdir()
                    sentinel = worktree / "foreign.txt"
                    sentinel.write_text("foreign\n", encoding="utf-8")
                    with self.assertRaises(CleanupRecoveryBlockedError):
                        cleanup_owned_worktree(ownership, approved=True)
                    self.assertEqual(
                        sentinel.read_text(encoding="utf-8"),
                        "foreign\n",
                    )

    def test_cleanup_preserves_a_corrupted_record_after_removal_starts(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "cleanup record race"
        ownership = create_run_worktree(
            repository,
            run_id="run-cleanup-record-race",
            branch="ship/cleanup-record-race",
            worktree_path=worktree,
        )
        hook = self.primary / ".git" / "hooks" / "reference-transaction"
        hook.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "committed" ]; then\n'
            "  printf '{' > \"$SHIP_TEST_OWNERSHIP_RECORD\"\n"
            "fi\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)

        with mock.patch.dict(
            os.environ,
            {"SHIP_TEST_OWNERSHIP_RECORD": str(ownership.record_path)},
        ):
            with self.assertRaises(OwnershipError):
                cleanup_owned_worktree(ownership, approved=True)

        self.assertFalse(os.path.lexists(worktree))
        self.assertEqual(ownership.record_path.read_text(encoding="utf-8"), "{")

    def test_cleanup_pins_the_merge_target_oid_before_the_target_ref_moves(
        self,
    ) -> None:
        repository = GitRepository.discover(self.primary)
        worktree = self.root / "pinned cleanup target"
        ownership = create_run_worktree(
            repository,
            run_id="run-pinned-cleanup-target",
            branch="ship/pinned-cleanup-target",
            worktree_path=worktree,
        )
        (worktree / "candidate.txt").write_text("candidate\n", encoding="utf-8")
        identity = commit_candidate(
            ownership,
            message="feat: cleanup target candidate",
            approved_paths=("candidate.txt",),
        )
        target_ref = "refs/heads/integration-target"
        git(self.primary, "update-ref", target_ref, identity.commit_oid)
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        wrapper_directory = self.root / "git wrapper"
        wrapper_directory.mkdir()
        wrapper = wrapper_directory / "git"
        wrapper.write_text(
            "#!/bin/sh\n"
            "move_target() {\n"
            '  "$SHIP_REAL_GIT" -C "$SHIP_TEST_REPO" update-ref '
            '"$SHIP_TARGET_REF" "$SHIP_BASE_OID" "$SHIP_CANDIDATE_OID" '
            ">/dev/null 2>&1 || true\n"
            "}\n"
            'for argument in "$@"; do\n'
            '  case "$argument" in\n'
            "    *integration-target*{commit}*)\n"
            '      output=$("$SHIP_REAL_GIT" "$@")\n'
            "      status=$?\n"
            "      move_target\n"
            "      printf '%s\\n' \"$output\"\n"
            "      exit $status\n"
            "      ;;\n"
            "  esac\n"
            "done\n"
            'if [ "$1" = "merge-base" ]; then\n'
            '  for argument in "$@"; do\n'
            '    if [ "$argument" = "integration-target" ]; then\n'
            "      move_target\n"
            "    fi\n"
            "  done\n"
            "fi\n"
            'exec "$SHIP_REAL_GIT" "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        environment = {
            "PATH": f"{wrapper_directory}{os.pathsep}{os.environ['PATH']}",
            "SHIP_REAL_GIT": real_git or "git",
            "SHIP_TEST_REPO": str(self.primary),
            "SHIP_TARGET_REF": target_ref,
            "SHIP_BASE_OID": self.base_oid,
            "SHIP_CANDIDATE_OID": identity.commit_oid,
        }

        with mock.patch.dict(os.environ, environment):
            cleanup_owned_worktree(
                ownership,
                approved=True,
                merged_into="integration-target",
            )

        self.assertFalse(os.path.lexists(worktree))
        self.assertEqual(
            git_output(self.primary, "rev-parse", "integration-target"),
            self.base_oid,
        )


if __name__ == "__main__":
    unittest.main()
