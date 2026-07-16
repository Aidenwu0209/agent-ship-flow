from __future__ import annotations

import hashlib
import inspect
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import ship_flow.workflow as workflow_module
import ship_flow.gitops as gitops_module
from ship_flow.gitops import (
    CleanupRefusedError,
    OwnershipError,
    ResourceCollisionError,
    WorktreeOwnership,
    cleanup_owned_worktree,
    commit_candidate,
)
from ship_flow.manifest import CommandSpec, Manifest, manifest_digest, write_manifest
from ship_flow.model import Phase
from ship_flow.store import PrivateRootAnchor, StateStore
from ship_flow.verify import verification_commands_digest
from ship_flow.workflow import (
    WorkflowRecoveryError,
    WorkflowRun,
    cleanup_run,
    discover_repository,
    load_run,
    observe_subject,
    run_directory,
    set_plan,
    start_run,
)
from tests.support import git, git_output, initialize_repository


class SimulatedCrash(BaseException):
    pass


class WorkflowIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.primary = self.root / "repo"
        initialize_repository(self.primary)
        self.manifest = Manifest(
            project_name="workflow-fixture",
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
        git(self.primary, "commit", "-m", "add workflow manifest")
        self.repository = discover_repository(self.primary)

    def start(self, suffix: str = "001") -> WorkflowRun:
        return start_run(
            self.repository,
            run_id=f"run-{suffix}",
            branch=f"ship/run-{suffix}",
            worktree_path=self.root / f"worktree-{suffix}",
        )

    def plan(
        self, run: WorkflowRun, text: str = "# Plan\n\nShip safely.\n"
    ) -> WorkflowRun:
        return set_plan(
            self.repository,
            run.state.run_id,
            text,
            expected_revision=run.state.revision,
        )

    def advance_to_cleanup(self, run: WorkflowRun) -> object:
        state = run.store.load()
        for phase in (
            Phase.AWAITING_PLAN_APPROVAL,
            Phase.DEVELOPING,
            Phase.CODE_REVIEW,
            Phase.VERIFYING,
            Phase.AWAITING_RELEASE_APPROVAL,
        ):
            state = run.store.transition(phase, expected_revision=state.revision)
        state = run.store.reconcile_transition(
            Phase.SYNCING,
            expected_revision=state.revision,
            reason="release-not-required",
        )
        return run.store.transition(
            Phase.AWAITING_CLEANUP_APPROVAL,
            expected_revision=state.revision,
        )

    def test_safe_discovery_and_start_return_a_validated_planning_run(self) -> None:
        run = self.start()

        self.assertIsInstance(run, WorkflowRun)
        self.assertEqual(run.repository, self.repository)
        self.assertEqual(run.state.phase, Phase.PLANNING)
        self.assertEqual(run.state.revision, 1)
        self.assertEqual(run.run_directory, run.ownership.record_path.parent)
        self.assertEqual(run_directory(self.repository, "run-001"), run.run_directory)
        self.assertEqual(load_run(self.repository, "run-001").state, run.state)
        self.assertEqual(
            git_output(run.ownership.worktree_path, "rev-parse", "HEAD"),
            git_output(self.primary, "rev-parse", "main"),
        )
        with self.assertRaises(ValueError):
            run_directory(self.repository, "../foreign")

    def test_start_recovers_when_state_creation_was_interrupted(self) -> None:
        with mock.patch.object(
            workflow_module,
            "_create_state_anchored",
            side_effect=SimulatedCrash("after worktree creation"),
        ):
            with self.assertRaisesRegex(SimulatedCrash, "worktree"):
                self.start("start-crash")

        ownership = workflow_module.load_run_worktree(
            self.repository,
            "run-start-crash",
        )
        self.assertTrue(ownership.worktree_path.is_dir())
        recovered = self.start("start-crash")

        self.assertEqual(recovered.state.phase, Phase.PLANNING)
        self.assertEqual(recovered.ownership.worktree_path, ownership.worktree_path)
        self.assertEqual(self.start("start-crash").state, recovered.state)

    def test_start_recovers_power_loss_after_worktree_add_before_ownership_write(
        self,
    ) -> None:
        real_write_ownership = gitops_module._write_ownership
        crashed = False

        def lose_power_once(ownership: object) -> None:
            nonlocal crashed
            if not crashed:
                crashed = True
                raise SimulatedCrash("after worktree add")
            real_write_ownership(ownership)

        with mock.patch.object(
            gitops_module,
            "_write_ownership",
            autospec=True,
            side_effect=lose_power_once,
        ):
            with self.assertRaisesRegex(SimulatedCrash, "worktree add"):
                self.start("creation-intent")

        worktree = self.root / "worktree-creation-intent"
        self.assertTrue(worktree.is_dir())
        self.assertEqual(
            git_output(worktree, "rev-parse", "--abbrev-ref", "HEAD"),
            "ship/run-creation-intent",
        )

        try:
            recovered = self.start("creation-intent")
        except WorkflowRecoveryError as error:
            self.fail(f"exact interrupted creation was not recovered: {error}")

        self.assertEqual(recovered.state.phase, Phase.PLANNING)
        self.assertEqual(recovered.ownership.worktree_path, worktree.resolve())
        self.assertTrue(recovered.ownership.record_path.is_file())

    def test_start_recovers_power_loss_after_run_directory_before_ownership_record(
        self,
    ) -> None:
        real_atomic_write = gitops_module._atomic_write_private_json
        crashed = False

        def lose_power_before_ownership_record(
            path: Path,
            payload: dict[str, object],
            *,
            trusted_root: object,
        ) -> None:
            nonlocal crashed
            if path.name == "worktree.json" and not crashed:
                crashed = True
                self.assertTrue(path.parent.is_dir())
                raise SimulatedCrash("before ownership record")
            real_atomic_write(
                path,
                payload,
                trusted_root=trusted_root,
            )

        with mock.patch.object(
            gitops_module,
            "_atomic_write_private_json",
            side_effect=lose_power_before_ownership_record,
        ):
            with self.assertRaisesRegex(SimulatedCrash, "ownership record"):
                self.start("ownership-record-crash")

        directory = run_directory(self.repository, "run-ownership-record-crash")
        self.assertFalse(os.path.lexists(directory))
        abandoned = tuple(directory.parent.glob(f".{directory.name}.creating-*"))
        self.assertEqual(len(abandoned), 1)
        self.assertEqual(tuple(abandoned[0].iterdir()), ())
        self.assertTrue(
            (
                self.repository.git_common_directory
                / "ship-flow"
                / "creation-intents"
                / "run-ownership-record-crash.json"
            ).is_file()
        )

        try:
            recovered = self.start("ownership-record-crash")
        except (OwnershipError, WorkflowRecoveryError) as error:
            self.fail(f"private partial ownership was not recovered: {error}")

        self.assertEqual(recovered.state.phase, Phase.PLANNING)
        self.assertTrue(recovered.ownership.record_path.is_file())
        self.assertTrue(abandoned[0].is_dir())
        self.assertEqual(tuple(abandoned[0].iterdir()), ())

    def test_start_recovers_power_loss_after_run_directory_before_intent_binding(
        self,
    ) -> None:
        crashed = False
        unbound_directory: Path | None = None
        unbound_identity: tuple[int, int] | None = None

        def lose_power_before_intent_binding(
            ownership: object,
            anchor: PrivateRootAnchor,
        ) -> None:
            nonlocal crashed, unbound_directory, unbound_identity
            if not crashed:
                crashed = True
                directory = run_directory(
                    self.repository,
                    "run-directory-binding-crash",
                )
                self.assertFalse(os.path.lexists(directory))
                unbound_directory = anchor.path
                metadata = os.fstat(anchor.descriptor)
                unbound_identity = (metadata.st_dev, metadata.st_ino)
                self.assertTrue(unbound_directory.is_dir())
                self.assertTrue((unbound_directory / "worktree.json").is_file())
                raise SimulatedCrash("before run directory intent binding")

        with mock.patch.object(
            gitops_module,
            "_record_creation_run_directory_locked",
            autospec=True,
            side_effect=lose_power_before_intent_binding,
        ):
            with self.assertRaisesRegex(SimulatedCrash, "intent binding"):
                self.start("directory-binding-crash")

        directory = run_directory(
            self.repository,
            "run-directory-binding-crash",
        )
        self.assertFalse(os.path.lexists(directory))
        self.assertIsNotNone(unbound_directory)
        self.assertIsNotNone(unbound_identity)
        intent_path = (
            self.repository.git_common_directory
            / "ship-flow"
            / "creation-intents"
            / "run-directory-binding-crash.json"
        )
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        self.assertEqual(intent["stage"], "worktree-added")
        self.assertIsNone(intent["run_directory_device"])
        self.assertIsNone(intent["run_directory_inode"])

        recovered = self.start("directory-binding-crash")

        current = os.stat(directory, follow_symlinks=False)
        self.assertNotEqual((current.st_dev, current.st_ino), unbound_identity)
        assert unbound_directory is not None
        abandoned = os.stat(unbound_directory, follow_symlinks=False)
        self.assertEqual((abandoned.st_dev, abandoned.st_ino), unbound_identity)
        self.assertTrue((unbound_directory / "worktree.json").is_file())
        self.assertEqual(recovered.state.phase, Phase.PLANNING)
        self.assertTrue(recovered.ownership.record_path.is_file())

    def test_start_recovers_power_loss_after_staging_intent_before_publication(
        self,
    ) -> None:
        with mock.patch.object(
            gitops_module,
            "_publish_staged_ownership_directory_locked",
            autospec=True,
            side_effect=SimulatedCrash("after staging intent"),
        ):
            with self.assertRaisesRegex(SimulatedCrash, "staging intent"):
                self.start("staging-intent-crash")

        intent_path = (
            self.repository.git_common_directory
            / "ship-flow"
            / "creation-intents"
            / "run-staging-intent-crash.json"
        )
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        self.assertEqual(intent["stage"], "run-directory-staged")
        staged_directory = Path(intent["staging_directory"])
        self.assertTrue(staged_directory.is_dir())
        self.assertTrue((staged_directory / "worktree.json").is_file())
        staged_identity = (
            intent["run_directory_device"],
            intent["run_directory_inode"],
        )

        recovered = self.start("staging-intent-crash")

        published = os.stat(recovered.run_directory, follow_symlinks=False)
        self.assertEqual((published.st_dev, published.st_ino), staged_identity)
        self.assertFalse(os.path.lexists(staged_directory))
        self.assertEqual(recovered.state.phase, Phase.PLANNING)

    def test_start_recovers_power_loss_after_staged_directory_publication(
        self,
    ) -> None:
        real_publish = gitops_module._publish_staged_ownership_directory_locked
        crashed = False

        def publish_then_lose_power(
            ownership: WorktreeOwnership,
            anchor: PrivateRootAnchor,
        ) -> None:
            nonlocal crashed
            real_publish(ownership, anchor)
            if not crashed:
                crashed = True
                raise SimulatedCrash("after staged directory publication")

        with mock.patch.object(
            gitops_module,
            "_publish_staged_ownership_directory_locked",
            autospec=True,
            side_effect=publish_then_lose_power,
        ):
            with self.assertRaisesRegex(SimulatedCrash, "publication"):
                self.start("staged-publication-crash")

        directory = run_directory(
            self.repository,
            "run-staged-publication-crash",
        )
        published = os.stat(directory, follow_symlinks=False)
        intent_path = (
            self.repository.git_common_directory
            / "ship-flow"
            / "creation-intents"
            / "run-staged-publication-crash.json"
        )
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        self.assertEqual(intent["stage"], "run-directory-staged")
        self.assertEqual(
            (published.st_dev, published.st_ino),
            (
                intent["run_directory_device"],
                intent["run_directory_inode"],
            ),
        )

        recovered = self.start("staged-publication-crash")

        current = os.stat(directory, follow_symlinks=False)
        self.assertEqual(
            (current.st_dev, current.st_ino),
            (published.st_dev, published.st_ino),
        )
        self.assertEqual(recovered.state.phase, Phase.PLANNING)
        self.assertFalse(intent_path.exists())

    def test_published_creation_rejects_a_copied_record_in_a_replaced_inode(
        self,
    ) -> None:
        real_publish = gitops_module._publish_staged_ownership_directory_locked

        def publish_then_lose_power(
            ownership: WorktreeOwnership,
            anchor: PrivateRootAnchor,
        ) -> None:
            real_publish(ownership, anchor)
            raise SimulatedCrash("after bound publication")

        with mock.patch.object(
            gitops_module,
            "_publish_staged_ownership_directory_locked",
            autospec=True,
            side_effect=publish_then_lose_power,
        ):
            with self.assertRaisesRegex(SimulatedCrash, "bound publication"):
                self.start("replaced-published-inode")

        directory = run_directory(
            self.repository,
            "run-replaced-published-inode",
        )
        record_bytes = (directory / "worktree.json").read_bytes()
        displaced = directory.with_name(f"{directory.name}.displaced")
        directory.rename(displaced)
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
        (directory / "worktree.json").write_bytes(record_bytes)
        (directory / "worktree.json").chmod(0o600)
        replacement = os.stat(directory, follow_symlinks=False)

        with self.assertRaises((OwnershipError, WorkflowRecoveryError)):
            self.start("replaced-published-inode")

        current = os.stat(directory, follow_symlinks=False)
        self.assertEqual(
            (current.st_dev, current.st_ino),
            (replacement.st_dev, replacement.st_ino),
        )
        self.assertEqual((directory / "worktree.json").read_bytes(), record_bytes)
        self.assertTrue((displaced / "worktree.json").is_file())

    def test_unbound_creation_never_claims_foreign_run_directories(self) -> None:
        for kind in ("empty", "nonempty", "symlink"):
            with self.subTest(kind=kind):
                suffix = f"foreign-run-directory-{kind}"
                with mock.patch.object(
                    gitops_module,
                    "_record_creation_run_directory_locked",
                    autospec=True,
                    side_effect=SimulatedCrash("before intent binding"),
                ):
                    with self.assertRaisesRegex(SimulatedCrash, "intent binding"):
                        self.start(suffix)

                directory = run_directory(self.repository, f"run-{suffix}")
                self.assertFalse(os.path.lexists(directory))
                target = self.root / f"foreign-target-{kind}"
                if kind == "symlink":
                    target.mkdir()
                    (target / "keep.txt").write_text("foreign\n", encoding="utf-8")
                    directory.symlink_to(target, target_is_directory=True)
                else:
                    directory.mkdir(mode=0o700)
                    directory.chmod(0o700)
                    if kind == "nonempty":
                        (directory / "keep.txt").write_text(
                            "foreign\n",
                            encoding="utf-8",
                        )
                foreign = os.lstat(directory)

                with self.assertRaises(WorkflowRecoveryError):
                    self.start(suffix)

                current = os.lstat(directory)
                self.assertEqual(
                    (current.st_dev, current.st_ino),
                    (foreign.st_dev, foreign.st_ino),
                )
                if kind == "empty":
                    self.assertEqual(tuple(directory.iterdir()), ())
                elif kind == "nonempty":
                    self.assertEqual(
                        (directory / "keep.txt").read_text(encoding="utf-8"),
                        "foreign\n",
                    )
                else:
                    self.assertTrue(directory.is_symlink())
                    self.assertEqual(
                        (target / "keep.txt").read_text(encoding="utf-8"),
                        "foreign\n",
                    )

    def test_staged_creation_rejects_replaced_staging_inode(self) -> None:
        with mock.patch.object(
            gitops_module,
            "_publish_staged_ownership_directory_locked",
            autospec=True,
            side_effect=SimulatedCrash("before staged publication"),
        ):
            with self.assertRaisesRegex(SimulatedCrash, "staged publication"):
                self.start("replaced-staging-inode")

        intent_path = (
            self.repository.git_common_directory
            / "ship-flow"
            / "creation-intents"
            / "run-replaced-staging-inode.json"
        )
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        staged_directory = Path(intent["staging_directory"])
        original_identity = (
            intent["run_directory_device"],
            intent["run_directory_inode"],
        )
        (staged_directory / "worktree.json").unlink()
        staged_directory.rmdir()
        staged_directory.mkdir(mode=0o700)
        staged_directory.chmod(0o700)
        replacement = os.stat(staged_directory, follow_symlinks=False)
        self.assertNotEqual(
            (replacement.st_dev, replacement.st_ino),
            original_identity,
        )

        with self.assertRaises(WorkflowRecoveryError):
            self.start("replaced-staging-inode")

        current = os.stat(staged_directory, follow_symlinks=False)
        self.assertEqual(
            (current.st_dev, current.st_ino),
            (replacement.st_dev, replacement.st_ino),
        )
        self.assertEqual(tuple(staged_directory.iterdir()), ())

    def test_publication_collision_preserves_foreign_ownership_files(self) -> None:
        real_publish = gitops_module._publish_staged_ownership_directory_locked

        def insert_foreign_directory_before_publication(
            ownership: WorktreeOwnership,
            anchor: PrivateRootAnchor,
        ) -> None:
            directory = ownership.record_path.parent
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
            (directory / "worktree.json").write_text(
                "foreign ownership\n",
                encoding="utf-8",
            )
            (directory / "keep.txt").write_text("keep\n", encoding="utf-8")
            real_publish(ownership, anchor)

        with mock.patch.object(
            gitops_module,
            "_publish_staged_ownership_directory_locked",
            autospec=True,
            side_effect=insert_foreign_directory_before_publication,
        ):
            with self.assertRaises(WorkflowRecoveryError):
                self.start("publication-collision")

        directory = run_directory(self.repository, "run-publication-collision")
        self.assertEqual(
            (directory / "worktree.json").read_text(encoding="utf-8"),
            "foreign ownership\n",
        )
        self.assertEqual(
            (directory / "keep.txt").read_text(encoding="utf-8"),
            "keep\n",
        )

    def test_normal_publication_rejects_tampered_staged_ownership(self) -> None:
        for kind in ("foreign-entry", "symlink", "rewrite"):
            with self.subTest(kind=kind):
                suffix = f"tampered-staging-{kind}"
                real_write_intent = gitops_module._write_creation_intent_locked
                injected_path: Path | None = None
                injected_bytes: bytes | None = None
                staged_path: Path | None = None

                def write_intent_then_tamper_staging(
                    repository: object,
                    payload: dict[str, object],
                    *,
                    stage: str,
                    git_backlink: Path | None,
                    staging_directory: Path | None = None,
                    run_directory_identity: tuple[int, int] | None = None,
                ) -> dict[str, object]:
                    nonlocal injected_path, injected_bytes, staged_path
                    changed = real_write_intent(
                        repository,
                        payload,
                        stage=stage,
                        git_backlink=git_backlink,
                        staging_directory=staging_directory,
                        run_directory_identity=run_directory_identity,
                    )
                    if stage != "run-directory-staged":
                        return changed
                    staged = Path(str(changed["staging_directory"]))
                    staged_path = staged
                    record = staged / "worktree.json"
                    if kind == "foreign-entry":
                        injected_path = staged / "foreign.txt"
                        injected_bytes = b"foreign entry\n"
                        injected_path.write_bytes(injected_bytes)
                    elif kind == "symlink":
                        target = self.root / f"foreign-record-target-{suffix}"
                        injected_bytes = b"foreign symlink target\n"
                        target.write_bytes(injected_bytes)
                        record.unlink()
                        record.symlink_to(target)
                        injected_path = target
                    else:
                        foreign = json.loads(record.read_text(encoding="utf-8"))
                        foreign["run_id"] = "foreign-run"
                        injected_bytes = (
                            json.dumps(
                                foreign,
                                ensure_ascii=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                            + b"\n"
                        )
                        record.write_bytes(injected_bytes)
                        record.chmod(0o600)
                        injected_path = record
                    return changed

                with mock.patch.object(
                    gitops_module,
                    "_write_creation_intent_locked",
                    autospec=True,
                    side_effect=write_intent_then_tamper_staging,
                ):
                    with self.assertRaises((OwnershipError, WorkflowRecoveryError)):
                        self.start(suffix)

                directory = run_directory(self.repository, f"run-{suffix}")
                self.assertFalse(os.path.lexists(directory))
                self.assertIsNotNone(injected_path)
                self.assertIsNotNone(injected_bytes)
                assert injected_path is not None
                assert injected_bytes is not None
                self.assertEqual(injected_path.read_bytes(), injected_bytes)
                if kind == "symlink":
                    assert staged_path is not None
                    self.assertTrue((staged_path / "worktree.json").is_symlink())

    def test_recovery_publication_rejects_foreign_staging_entries(self) -> None:
        with mock.patch.object(
            gitops_module,
            "_publish_staged_ownership_directory_locked",
            autospec=True,
            side_effect=SimulatedCrash("before recovery publication"),
        ):
            with self.assertRaisesRegex(SimulatedCrash, "recovery publication"):
                self.start("recovery-staging-foreign-entry")

        intent_path = (
            self.repository.git_common_directory
            / "ship-flow"
            / "creation-intents"
            / "run-recovery-staging-foreign-entry.json"
        )
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        staged_directory = Path(intent["staging_directory"])
        foreign = staged_directory / "foreign.txt"
        foreign.write_text("foreign\n", encoding="utf-8")

        with self.assertRaises(WorkflowRecoveryError):
            self.start("recovery-staging-foreign-entry")

        self.assertEqual(foreign.read_text(encoding="utf-8"), "foreign\n")
        self.assertFalse(
            os.path.lexists(
                run_directory(
                    self.repository,
                    "run-recovery-staging-foreign-entry",
                )
            )
        )

    def test_publication_boundary_revalidates_exact_staging_contents(self) -> None:
        suffix = "publication-boundary-foreign-entry"
        run_id = f"run-{suffix}"
        worktree = self.root / f"worktree-{suffix}"
        real_publish = gitops_module._publish_staged_ownership_directory_locked
        staged_path: Path | None = None

        def add_foreign_entry_then_publish(
            ownership: WorktreeOwnership,
            anchor: PrivateRootAnchor,
        ) -> None:
            nonlocal staged_path
            staged_path = anchor.path
            foreign = anchor.path / "foreign.txt"
            foreign.write_text("foreign\n", encoding="utf-8")
            foreign.chmod(0o600)
            real_publish(ownership, anchor)

        with mock.patch.object(
            gitops_module,
            "_publish_staged_ownership_directory_locked",
            autospec=True,
            side_effect=add_foreign_entry_then_publish,
        ):
            with self.assertRaises((OwnershipError, WorkflowRecoveryError)):
                self.start(suffix)

        directory = run_directory(self.repository, run_id)
        intent_path = (
            self.repository.git_common_directory
            / "ship-flow"
            / "creation-intents"
            / f"{run_id}.json"
        )
        self.assertFalse(os.path.lexists(directory))
        self.assertTrue(intent_path.is_file())
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        self.assertEqual(intent["stage"], "run-directory-staged")
        self.assertIsNotNone(staged_path)
        assert staged_path is not None
        self.assertEqual(Path(str(intent["staging_directory"])), staged_path)
        self.assertEqual(
            (staged_path / "foreign.txt").read_text(encoding="utf-8"),
            "foreign\n",
        )
        self.assertTrue(worktree.is_dir())
        self.assertEqual(
            git_output(worktree, "branch", "--show-current"),
            f"ship/{run_id}",
        )

        with self.assertRaises((OwnershipError, WorkflowRecoveryError)):
            self.start(suffix)

        self.assertFalse(os.path.lexists(directory))
        self.assertTrue(intent_path.is_file())
        self.assertTrue(worktree.is_dir())

    def test_publication_rejects_replaced_visible_runs_root(self) -> None:
        suffix = "publication-runs-root-replaced"
        run_id = f"run-{suffix}"
        worktree = self.root / f"worktree-{suffix}"
        branch = f"ship/{run_id}"
        runs = self.repository.git_common_directory / "ship-flow" / "runs"
        displaced_runs = runs.with_name("runs-displaced-during-publication")
        real_rename = gitops_module._rename_directory_noreplace_at
        swapped = False

        def replace_runs_then_rename(
            parent_descriptor: int,
            source_name: str,
            destination_name: str,
        ) -> None:
            nonlocal swapped
            self.assertFalse(swapped)
            runs.rename(displaced_runs)
            runs.mkdir(mode=0o700)
            runs.chmod(0o700)
            swapped = True
            real_rename(parent_descriptor, source_name, destination_name)

        with mock.patch.object(
            gitops_module,
            "_rename_directory_noreplace_at",
            autospec=True,
            side_effect=replace_runs_then_rename,
        ):
            with self.assertRaises(ResourceCollisionError):
                gitops_module.create_run_worktree(
                    self.repository,
                    run_id=run_id,
                    branch=branch,
                    worktree_path=worktree,
                    base_ref="main",
                )

        directory = run_directory(self.repository, run_id)
        displaced_directory = displaced_runs / run_id
        intent_path = (
            self.repository.git_common_directory
            / "ship-flow"
            / "creation-intents"
            / f"{run_id}.json"
        )
        self.assertTrue(swapped)
        self.assertFalse(os.path.lexists(directory))
        self.assertTrue((displaced_directory / "worktree.json").is_file())
        self.assertTrue(intent_path.is_file())
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        self.assertEqual(intent["stage"], "run-directory-staged")
        displaced_metadata = os.stat(displaced_directory, follow_symlinks=False)
        self.assertEqual(
            (displaced_metadata.st_dev, displaced_metadata.st_ino),
            (intent["run_directory_device"], intent["run_directory_inode"]),
        )
        self.assertTrue(worktree.is_dir())
        self.assertEqual(git_output(worktree, "branch", "--show-current"), branch)

        with self.assertRaises(ResourceCollisionError):
            gitops_module.create_run_worktree(
                self.repository,
                run_id=run_id,
                branch=branch,
                worktree_path=worktree,
                base_ref="main",
            )

        self.assertFalse(os.path.lexists(directory))
        self.assertTrue(intent_path.is_file())
        self.assertTrue(worktree.is_dir())

    def test_restart_revalidates_published_directory_before_removing_intent(
        self,
    ) -> None:
        suffix = "published-final-foreign-entry"
        run_id = f"run-{suffix}"
        worktree = self.root / f"worktree-{suffix}"
        branch = f"ship/{run_id}"
        directory = run_directory(self.repository, run_id)
        real_rename = gitops_module._rename_directory_noreplace_at

        def rename_then_add_foreign_entry(
            parent_descriptor: int,
            source_name: str,
            destination_name: str,
        ) -> None:
            real_rename(parent_descriptor, source_name, destination_name)
            foreign = directory / "foreign.txt"
            foreign.write_text("foreign\n", encoding="utf-8")
            foreign.chmod(0o600)

        with mock.patch.object(
            gitops_module,
            "_rename_directory_noreplace_at",
            autospec=True,
            side_effect=rename_then_add_foreign_entry,
        ):
            with self.assertRaises(ResourceCollisionError):
                gitops_module.create_run_worktree(
                    self.repository,
                    run_id=run_id,
                    branch=branch,
                    worktree_path=worktree,
                    base_ref="main",
                )

        intent_path = (
            self.repository.git_common_directory
            / "ship-flow"
            / "creation-intents"
            / f"{run_id}.json"
        )
        self.assertTrue((directory / "worktree.json").is_file())
        self.assertEqual(
            (directory / "foreign.txt").read_text(encoding="utf-8"),
            "foreign\n",
        )
        self.assertTrue(intent_path.is_file())
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        self.assertEqual(intent["stage"], "run-directory-staged")
        published = os.stat(directory, follow_symlinks=False)
        self.assertEqual(
            (published.st_dev, published.st_ino),
            (intent["run_directory_device"], intent["run_directory_inode"]),
        )
        self.assertTrue(worktree.is_dir())
        self.assertEqual(git_output(worktree, "branch", "--show-current"), branch)

        with self.assertRaises(ResourceCollisionError):
            gitops_module.create_run_worktree(
                self.repository,
                run_id=run_id,
                branch=branch,
                worktree_path=worktree,
                base_ref="main",
            )

        self.assertTrue(intent_path.is_file())
        self.assertTrue((directory / "worktree.json").is_file())
        self.assertEqual(
            (directory / "foreign.txt").read_text(encoding="utf-8"),
            "foreign\n",
        )
        self.assertTrue(worktree.is_dir())

    def test_ordinary_exception_after_publication_preserves_git_for_restart(
        self,
    ) -> None:
        real_publish = gitops_module._publish_staged_ownership_directory_locked
        failed = False

        def publish_then_fail_checkpoint(
            ownership: WorktreeOwnership,
            anchor: PrivateRootAnchor,
        ) -> None:
            nonlocal failed
            real_publish(ownership, anchor)
            if not failed:
                failed = True
                raise OSError("post-publication checkpoint failed")

        with mock.patch.object(
            gitops_module,
            "_publish_staged_ownership_directory_locked",
            autospec=True,
            side_effect=publish_then_fail_checkpoint,
        ):
            with self.assertRaisesRegex(OSError, "checkpoint"):
                self.start("ordinary-post-publication-error")

        directory = run_directory(
            self.repository,
            "run-ordinary-post-publication-error",
        )
        intent_path = (
            self.repository.git_common_directory
            / "ship-flow"
            / "creation-intents"
            / "run-ordinary-post-publication-error.json"
        )
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        self.assertEqual(intent["stage"], "run-directory-staged")
        worktree = self.root / "worktree-ordinary-post-publication-error"
        self.assertTrue(directory.is_dir())
        self.assertTrue((directory / "worktree.json").is_file())
        self.assertTrue(worktree.is_dir())
        self.assertEqual(
            git_output(worktree, "branch", "--show-current"),
            "ship/run-ordinary-post-publication-error",
        )

        real_git = gitops_module._git

        def reject_recreated_git_resources(
            cwd: Path,
            *arguments: str,
            **kwargs: object,
        ) -> object:
            if arguments[:2] == ("worktree", "add") or (
                arguments and arguments[0] == "update-ref"
            ):
                raise AssertionError("restart attempted to recreate Git resources")
            return real_git(cwd, *arguments, **kwargs)

        with mock.patch.object(
            gitops_module,
            "_git",
            side_effect=reject_recreated_git_resources,
        ):
            recovered = self.start("ordinary-post-publication-error")

        self.assertEqual(recovered.state.phase, Phase.PLANNING)
        self.assertTrue(recovered.ownership.worktree_path.is_dir())
        self.assertFalse(intent_path.exists())

    def test_set_plan_publishes_private_plan_then_observes_live_subject(self) -> None:
        started = self.start("plan")
        text = "# Plan\n\nReview, verify, then ship.\n"

        planned = self.plan(started, text)

        plan_path = planned.run_directory / "plan.md"
        variables = {
            "repo": str(planned.ownership.primary_checkout),
            "worktree": str(planned.ownership.worktree_path),
            "branch": planned.ownership.branch,
            "base_branch": self.manifest.base_branch,
            "remote": self.manifest.remote,
        }
        self.assertEqual(planned.state.phase, Phase.PLAN_REVIEW)
        self.assertEqual(plan_path.read_text(encoding="utf-8"), text)
        self.assertEqual(stat.S_IMODE(plan_path.stat().st_mode), 0o600)
        self.assertIsNotNone(planned.subject)
        assert planned.subject is not None
        self.assertEqual(
            planned.subject.plan_sha256,
            hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(
            planned.subject.manifest_sha256, manifest_digest(self.manifest)
        )
        self.assertEqual(
            planned.subject.commands_sha256,
            verification_commands_digest(self.manifest, variables),
        )
        self.assertEqual(
            observe_subject(self.repository, planned.state.run_id),
            planned.subject,
        )

    def test_set_plan_recovers_after_plan_write_before_state_transition(self) -> None:
        started = self.start("plan-crash")
        text = "# Plan\n\nResume this exact publication.\n"
        real_transition = StateStore.transition
        crashed = False

        def crash_before_plan_review(
            store: StateStore,
            target: Phase | str,
            *,
            expected_revision: int,
        ) -> object:
            nonlocal crashed
            if Phase(target) is Phase.PLAN_REVIEW and not crashed:
                crashed = True
                raise SimulatedCrash("before PLAN_REVIEW")
            return real_transition(
                store,
                target,
                expected_revision=expected_revision,
            )

        with mock.patch.object(
            StateStore,
            "transition",
            autospec=True,
            side_effect=crash_before_plan_review,
        ):
            with self.assertRaisesRegex(SimulatedCrash, "PLAN_REVIEW"):
                self.plan(started, text)

        operation_path = started.run_directory / "set-plan-operation.json"
        self.assertTrue(operation_path.is_file())
        self.assertEqual(started.store.load().phase, Phase.PLANNING)
        self.assertEqual(
            (started.run_directory / "plan.md").read_text(encoding="utf-8"),
            text,
        )

        recovered = self.plan(started, text)

        self.assertEqual(recovered.state.phase, Phase.PLAN_REVIEW)
        self.assertFalse(operation_path.exists())

    def test_pending_plan_rejects_a_different_retry(self) -> None:
        started = self.start("plan-conflict")
        original = "# Plan\n\nOriginal request.\n"
        with mock.patch.object(
            StateStore,
            "transition",
            side_effect=SimulatedCrash("before PLAN_REVIEW"),
        ):
            with self.assertRaises(SimulatedCrash):
                self.plan(started, original)

        with self.assertRaises(WorkflowRecoveryError):
            self.plan(started, "# Plan\n\nForeign retry.\n")

        self.assertEqual(
            (started.run_directory / "plan.md").read_text(encoding="utf-8"),
            original,
        )
        self.assertEqual(started.store.load().phase, Phase.PLANNING)

    def test_set_plan_rejects_replacement_before_plan_review_transition(
        self,
    ) -> None:
        started = self.start("plan-replaced")
        text = "# Plan\n\nAccept this exact plan.\n"
        replacement = text.replace("Accept", "Reject", 1)
        self.assertEqual(len(replacement.encode()), len(text.encode()))
        plan_path = started.run_directory / "plan.md"
        real_write_operation = workflow_module._write_plan_operation
        replaced = False

        def replace_after_plan_write(
            path: Path,
            operation: dict[str, object],
            *,
            trusted_root: object,
            stage: str,
        ) -> dict[str, object]:
            nonlocal replaced
            result = real_write_operation(
                path,
                operation,
                trusted_root=trusted_root,
                stage=stage,
            )
            if stage == "plan-written" and not replaced:
                replaced = True
                plan_path.write_text(replacement, encoding="utf-8")
                plan_path.chmod(0o600)
            return result

        with mock.patch.object(
            workflow_module,
            "_write_plan_operation",
            side_effect=replace_after_plan_write,
        ):
            with self.assertRaises(WorkflowRecoveryError):
                self.plan(started, text)

        self.assertEqual(started.store.load().phase, Phase.PLANNING)
        self.assertEqual(plan_path.read_text(encoding="utf-8"), replacement)
        self.assertTrue((started.run_directory / "set-plan-operation.json").is_file())

    def test_set_plan_compensates_replacement_inside_plan_review_transition(
        self,
    ) -> None:
        started = self.start("plan-cas-replaced")
        text = "# Plan\n\nExact CAS subject.\n"
        replacement = "# Plan\n\nOther CAS subject.\n"
        plan_path = started.run_directory / "plan.md"
        real_transition = StateStore.transition

        def replace_inside_transition(
            store: StateStore,
            target: Phase | str,
            *,
            expected_revision: int,
        ) -> object:
            if Phase(target) is Phase.PLAN_REVIEW:
                plan_path.write_text(replacement, encoding="utf-8")
                plan_path.chmod(0o600)
            return real_transition(
                store,
                target,
                expected_revision=expected_revision,
            )

        with mock.patch.object(
            StateStore,
            "transition",
            autospec=True,
            side_effect=replace_inside_transition,
        ):
            with self.assertRaises(WorkflowRecoveryError):
                self.plan(started, text)

        state = started.store.load()
        self.assertEqual(state.phase, Phase.PLANNING)
        self.assertEqual(state.revision, started.state.revision + 2)
        self.assertFalse((started.run_directory / "set-plan-operation.json").exists())
        self.assertEqual(plan_path.read_text(encoding="utf-8"), replacement)

    def test_set_plan_restart_compensates_replacement_after_plan_review_transition(
        self,
    ) -> None:
        started = self.start("plan-cas-crash")
        text = "# Plan\n\nCrash-safe CAS subject.\n"
        replacement = "# Plan\n\nTampered after CAS.\n"
        plan_path = started.run_directory / "plan.md"
        real_transition = StateStore.transition
        crashed = False

        def transition_then_lose_power(
            store: StateStore,
            target: Phase | str,
            *,
            expected_revision: int,
        ) -> object:
            nonlocal crashed
            changed = real_transition(
                store,
                target,
                expected_revision=expected_revision,
            )
            if Phase(target) is Phase.PLAN_REVIEW and not crashed:
                crashed = True
                plan_path.write_text(replacement, encoding="utf-8")
                plan_path.chmod(0o600)
                raise SimulatedCrash("after PLAN_REVIEW CAS")
            return changed

        with mock.patch.object(
            StateStore,
            "transition",
            autospec=True,
            side_effect=transition_then_lose_power,
        ):
            with self.assertRaisesRegex(SimulatedCrash, "PLAN_REVIEW CAS"):
                self.plan(started, text)

        self.assertEqual(started.store.load().phase, Phase.PLAN_REVIEW)
        self.assertTrue((started.run_directory / "set-plan-operation.json").is_file())

        with self.assertRaises(WorkflowRecoveryError):
            self.plan(started, text)

        state = started.store.load()
        self.assertEqual(state.phase, Phase.PLANNING)
        self.assertEqual(state.revision, started.state.revision + 2)
        self.assertFalse((started.run_directory / "set-plan-operation.json").exists())

    def test_cleanup_refusal_leaves_cleanup_approval_gate(self) -> None:
        planned = self.plan(self.start("cleanup-refusal"))
        candidate_path = planned.ownership.worktree_path / "candidate.txt"
        candidate_path.write_text("candidate\n", encoding="utf-8")
        commit_candidate(
            planned.ownership,
            message="candidate",
            approved_paths=("candidate.txt",),
        )
        gate = self.advance_to_cleanup(planned)

        with self.assertRaises(CleanupRefusedError) as refused:
            cleanup_run(
                self.repository,
                planned.state.run_id,
                expected_revision=gate.revision,
                approved=True,
            )

        self.assertIn("unmerged", refused.exception.conditions)
        self.assertEqual(planned.store.load(), gate)
        self.assertFalse(
            (planned.run_directory / "cleanup-workflow-operation.json").exists()
        )

        completed = cleanup_run(
            self.repository,
            planned.state.run_id,
            expected_revision=gate.revision,
            approved=True,
            approved_conditions=("unmerged",),
        )

        self.assertEqual(completed.state.phase, Phase.COMPLETED)
        self.assertEqual(
            git_output(self.primary, "rev-parse", planned.ownership.branch),
            planned.ownership.last_known_oid,
        )

    def test_cleanup_recovery_rejects_ownership_drift_before_completed(
        self,
    ) -> None:
        planned = self.plan(self.start("cleanup-drift"))
        gate = self.advance_to_cleanup(planned)
        real_transition = StateStore.transition
        crashed = False

        def crash_before_completed(
            store: StateStore,
            target: Phase | str,
            *,
            expected_revision: int,
        ) -> object:
            nonlocal crashed
            if Phase(target) is Phase.COMPLETED and not crashed:
                crashed = True
                raise SimulatedCrash("before COMPLETED")
            return real_transition(
                store,
                target,
                expected_revision=expected_revision,
            )

        with mock.patch.object(
            StateStore,
            "transition",
            autospec=True,
            side_effect=crash_before_completed,
        ):
            with self.assertRaisesRegex(SimulatedCrash, "COMPLETED"):
                cleanup_run(
                    self.repository,
                    planned.state.run_id,
                    expected_revision=gate.revision,
                    approved=True,
                )

        record = json.loads(planned.ownership.record_path.read_text(encoding="utf-8"))
        record["last_known_oid"] = "0" * len(planned.ownership.last_known_oid)
        planned.ownership.record_path.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        planned.ownership.record_path.chmod(0o600)

        with self.assertRaises(WorkflowRecoveryError):
            cleanup_run(
                self.repository,
                planned.state.run_id,
                expected_revision=gate.revision,
                approved=True,
            )

        self.assertEqual(planned.store.load(), gate)
        self.assertTrue(planned.ownership.record_path.is_file())

    def test_cleanup_recovers_after_completed_state_before_worktree_removal(
        self,
    ) -> None:
        planned = self.plan(self.start("cleanup"))
        gate = self.advance_to_cleanup(planned)

        with mock.patch.object(
            workflow_module,
            "cleanup_owned_worktree",
            side_effect=SimulatedCrash("before worktree removal"),
        ):
            with self.assertRaisesRegex(SimulatedCrash, "worktree"):
                cleanup_run(
                    self.repository,
                    planned.state.run_id,
                    expected_revision=gate.revision,
                    approved=True,
                )

        operation_path = planned.run_directory / "cleanup-workflow-operation.json"
        self.assertEqual(planned.store.load().phase, Phase.COMPLETED)
        self.assertTrue(planned.ownership.worktree_path.is_dir())
        self.assertTrue(planned.ownership.record_path.is_file())
        self.assertTrue(operation_path.is_file())

        recovered = cleanup_run(
            self.repository,
            planned.state.run_id,
            expected_revision=gate.revision,
            approved=True,
        )

        self.assertEqual(recovered.state.phase, Phase.COMPLETED)
        self.assertFalse(os.path.lexists(planned.ownership.worktree_path))
        self.assertFalse(planned.ownership.record_path.exists())
        self.assertFalse(operation_path.exists())

    def test_cleanup_restart_preserves_a_foreign_recreated_path(self) -> None:
        planned = self.plan(self.start("cleanup-foreign"))
        gate = self.advance_to_cleanup(planned)
        with mock.patch.object(
            workflow_module,
            "cleanup_owned_worktree",
            side_effect=SimulatedCrash("pause workflow cleanup"),
        ):
            with self.assertRaises(SimulatedCrash):
                cleanup_run(
                    self.repository,
                    planned.state.run_id,
                    expected_revision=gate.revision,
                    approved=True,
                )

        cleanup_owned_worktree(planned.ownership, approved=True)
        planned.ownership.worktree_path.mkdir()
        sentinel = planned.ownership.worktree_path / "foreign.txt"
        sentinel.write_text("do not delete\n", encoding="utf-8")

        recovered = cleanup_run(
            self.repository,
            planned.state.run_id,
            expected_revision=gate.revision,
            approved=True,
        )

        self.assertEqual(recovered.state.phase, Phase.COMPLETED)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "do not delete\n")
        self.assertFalse(
            (planned.run_directory / "cleanup-workflow-operation.json").exists()
        )

    def test_cleanup_missing_record_does_not_complete_registered_worktree(
        self,
    ) -> None:
        planned = self.plan(self.start("cleanup-missing-record"))
        gate = self.advance_to_cleanup(planned)
        with mock.patch.object(
            workflow_module,
            "cleanup_owned_worktree",
            side_effect=SimulatedCrash("before owned cleanup"),
        ):
            with self.assertRaises(SimulatedCrash):
                cleanup_run(
                    self.repository,
                    planned.state.run_id,
                    expected_revision=gate.revision,
                    approved=True,
                )

        planned.ownership.record_path.unlink()

        with self.assertRaises(WorkflowRecoveryError):
            cleanup_run(
                self.repository,
                planned.state.run_id,
                expected_revision=gate.revision,
                approved=True,
            )

        listing = git_output(self.primary, "worktree", "list", "--porcelain")
        self.assertIn(f"worktree {planned.ownership.worktree_path}", listing)
        self.assertTrue(
            (planned.run_directory / "cleanup-workflow-operation.json").is_file()
        )

    def test_start_rejects_run_directory_swap_during_state_creation(self) -> None:
        run_id = "run-directory-swap"
        directory = run_directory(self.repository, run_id)
        displaced = directory.with_name(f"{run_id}-displaced")
        sentinel = directory / "foreign.txt"
        real_write_snapshot = StateStore._write_snapshot
        swapped = False

        def write_snapshot_then_swap(
            store: StateStore,
            state: object,
            *,
            run_descriptor: int,
        ) -> None:
            nonlocal swapped
            real_write_snapshot(
                store,
                state,
                run_descriptor=run_descriptor,
            )
            if not swapped and state.phase is Phase.INITIALIZED:
                directory.rename(displaced)
                directory.mkdir(mode=0o700)
                sentinel.write_text("foreign\n", encoding="utf-8")
                swapped = True

        with mock.patch.object(
            StateStore,
            "_write_snapshot",
            autospec=True,
            side_effect=write_snapshot_then_swap,
        ):
            with self.assertRaises(WorkflowRecoveryError):
                self.start("directory-swap")

        self.assertTrue(swapped)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "foreign\n")
        self.assertEqual(StateStore(displaced).load().phase, Phase.INITIALIZED)

    def test_observe_subject_has_no_public_repository_lock_bypass(self) -> None:
        self.assertNotIn(
            "repository_lock_held",
            inspect.signature(observe_subject).parameters,
        )
