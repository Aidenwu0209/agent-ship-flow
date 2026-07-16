from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ship_flow import store as store_module
from ship_flow.model import LEGAL_TRANSITIONS, OperationStatus, Phase
from ship_flow.store import (
    FileLock,
    InvalidTransitionError,
    LockUnavailableError,
    StateCorruptionError,
    StateStore,
    StaleRevisionError,
    UnsafeLockPathError,
    _atomic_write_private_json,
    _read_bounded_private_file,
    _remove_private_file,
)


class StateModelTests(unittest.TestCase):
    def test_transition_graph_matches_the_approved_workflow(self) -> None:
        expected = {
            Phase.INITIALIZED: {Phase.PLANNING, Phase.BLOCKED},
            Phase.PLANNING: {Phase.PLAN_REVIEW, Phase.BLOCKED},
            Phase.PLAN_REVIEW: {
                Phase.AWAITING_PLAN_APPROVAL,
                Phase.PLANNING,
                Phase.BLOCKED,
            },
            Phase.AWAITING_PLAN_APPROVAL: {Phase.DEVELOPING, Phase.CANCELLED},
            Phase.DEVELOPING: {Phase.CODE_REVIEW, Phase.BLOCKED},
            Phase.CODE_REVIEW: {
                Phase.VERIFYING,
                Phase.DEVELOPING,
                Phase.BLOCKED,
            },
            Phase.VERIFYING: {
                Phase.AWAITING_RELEASE_APPROVAL,
                Phase.DEVELOPING,
                Phase.BLOCKED,
            },
            Phase.AWAITING_RELEASE_APPROVAL: {
                Phase.RELEASING,
                Phase.BLOCKED,
                Phase.CANCELLED,
            },
            Phase.RELEASING: {
                Phase.POST_RELEASE_VERIFYING,
                Phase.ROLLBACK_PENDING,
                Phase.BLOCKED,
            },
            Phase.POST_RELEASE_VERIFYING: {
                Phase.SYNCING,
                Phase.ROLLBACK_PENDING,
                Phase.ROLLING_BACK,
                Phase.BLOCKED,
            },
            Phase.ROLLBACK_PENDING: {Phase.ROLLING_BACK, Phase.BLOCKED},
            Phase.ROLLING_BACK: {Phase.ROLLBACK_VERIFYING, Phase.BLOCKED},
            Phase.ROLLBACK_VERIFYING: {Phase.ROLLED_BACK, Phase.BLOCKED},
            Phase.ROLLED_BACK: set(),
            Phase.SYNCING: {
                Phase.AWAITING_CLEANUP_APPROVAL,
                Phase.DEVELOPING,
                Phase.BLOCKED,
            },
            Phase.AWAITING_CLEANUP_APPROVAL: {Phase.COMPLETED, Phase.BLOCKED},
            Phase.COMPLETED: set(),
            # Leaving BLOCKED is a later, explicit corrective-action operation,
            # not an ordinary state transition.
            Phase.BLOCKED: set(),
            Phase.CANCELLED: set(),
        }

        self.assertEqual(
            {phase: set(targets) for phase, targets in LEGAL_TRANSITIONS.items()},
            expected,
        )

    def test_operation_status_has_durable_receipt_states(self) -> None:
        self.assertEqual(
            {status.value for status in OperationStatus},
            {"PREPARED", "RUNNING", "SUCCEEDED", "FAILED", "UNKNOWN"},
        )


class StateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.run_directory = Path(self.temporary_directory.name) / "runs" / "run-123"
        self.store = StateStore(self.run_directory)

    def test_create_and_legal_transition_increment_revision(self) -> None:
        initial = self.store.create("run-123")

        changed = self.store.transition(Phase.PLANNING, expected_revision=0)

        self.assertEqual(initial.revision, 0)
        self.assertEqual(initial.phase, Phase.INITIALIZED)
        self.assertEqual(changed.revision, 1)
        self.assertEqual(changed.phase, Phase.PLANNING)
        self.assertEqual(self.store.load(), changed)
        self.assertEqual([event.revision for event in self.store.events()], [0, 1])

    def test_run_lock_and_state_io_share_one_run_directory_inode(self) -> None:
        initial = self.store.create("run-123")
        displaced = Path(self.temporary_directory.name) / "detached-run"
        real_acquire = FileLock.acquire
        swapped = False

        def acquire_then_replace(lock: FileLock) -> FileLock:
            nonlocal swapped
            acquired = real_acquire(lock)
            if not swapped and lock.path == Path(os.path.abspath(self.store.lock_path)):
                self.run_directory.rename(displaced)
                shutil.copytree(displaced, self.run_directory)
                swapped = True
            return acquired

        with mock.patch.object(
            FileLock,
            "acquire",
            autospec=True,
            side_effect=acquire_then_replace,
        ):
            changed = self.store.transition(
                Phase.PLANNING,
                expected_revision=initial.revision,
            )

        replacement = StateStore(self.run_directory).load()
        detached = StateStore(displaced).load()
        self.assertTrue(swapped)
        self.assertEqual(
            (replacement.phase, replacement.revision), (Phase.INITIALIZED, 0)
        )
        self.assertEqual((detached.phase, detached.revision), (Phase.PLANNING, 1))
        self.assertEqual(changed, detached)

    def test_legacy_state_events_without_reconciliation_reason_remain_valid(
        self,
    ) -> None:
        initial = self.store.create("run-123")
        payload = json.loads(self.store.events_path.read_text(encoding="utf-8"))
        payload.pop("reconciliation_reason")
        payload.pop("operation_adjudication")
        self.store.events_path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

        self.assertEqual(StateStore(self.run_directory).load(), initial)
        changed = StateStore(self.run_directory).transition(
            Phase.PLANNING,
            expected_revision=0,
        )

        self.assertEqual(changed.phase, Phase.PLANNING)
        self.assertEqual(len(StateStore(self.run_directory).events()), 2)

    def test_symlinked_event_wal_cannot_read_or_write_outside_the_run(self) -> None:
        self.store.create("run-123")
        snapshot_before = self.store.state_path.read_bytes()
        event_before = self.store.events_path.read_bytes()
        outside = Path(self.temporary_directory.name) / "outside-events.jsonl"
        outside.write_bytes(event_before)
        outside_before = outside.read_bytes()
        self.store.events_path.unlink()
        self.store.events_path.symlink_to(outside)

        with self.assertRaises(StateCorruptionError):
            self.store.transition(Phase.PLANNING, expected_revision=0)

        self.assertTrue(self.store.events_path.is_symlink())
        self.assertEqual(outside.read_bytes(), outside_before)
        self.assertEqual(self.store.state_path.read_bytes(), snapshot_before)

    def test_symlinked_snapshot_cannot_be_read_or_replaced(self) -> None:
        self.store.create("run-123")
        event_before = self.store.events_path.read_bytes()
        outside = Path(self.temporary_directory.name) / "outside-state.json"
        outside.write_bytes(self.store.state_path.read_bytes())
        outside_before = outside.read_bytes()
        self.store.state_path.unlink()
        self.store.state_path.symlink_to(outside)

        with self.assertRaises(StateCorruptionError):
            self.store.transition(Phase.PLANNING, expected_revision=0)

        self.assertTrue(self.store.state_path.is_symlink())
        self.assertEqual(outside.read_bytes(), outside_before)
        self.assertEqual(self.store.events_path.read_bytes(), event_before)

    def test_operation_start_markers_are_append_only_verified_and_idempotent(
        self,
    ) -> None:
        self.store.create("run-123")
        arguments = {
            "cycle_id": "a" * 64,
            "mode": "release",
            "index": 1,
            "attempt": 1,
            "running_receipt_sha256": "b" * 64,
            "idempotency_key": "c" * 64,
        }

        first = self.store.record_operation_start(**arguments)
        repeated = self.store.record_operation_start(**arguments)
        second = self.store.record_operation_start(
            **{
                **arguments,
                "index": 2,
                "running_receipt_sha256": "d" * 64,
                "idempotency_key": "e" * 64,
            }
        )

        self.assertEqual(first, repeated)
        self.assertEqual(first.sequence, 1)
        self.assertEqual(first.revision, 1)
        self.assertIsNotNone(first.previous_event_sha256)
        self.assertEqual(second.sequence, 2)
        self.assertEqual(second.revision, 2)
        self.assertIsNotNone(second.previous_event_sha256)
        self.assertEqual(
            self.store.operation_start_markers(),
            (first, second),
        )
        self.assertEqual(stat.S_IMODE(self.store.events_path.stat().st_mode), 0o600)

        tail_store = StateStore(self.run_directory.parent / "tail-run")
        tail_store.create("tail-run")
        tail_store.record_operation_start(**arguments)
        tail_lines = tail_store.events_path.read_bytes().splitlines(keepends=True)
        tail_store.events_path.write_bytes(b"".join(tail_lines[:-1]))
        with self.assertRaises(StateCorruptionError):
            tail_store.events()

        lines = self.store.events_path.read_bytes().splitlines(keepends=True)
        self.store.transition(Phase.PLANNING, expected_revision=2)
        transitioned = self.store.events_path.read_bytes().splitlines(keepends=True)[-1]
        self.store.events_path.write_bytes(lines[0] + transitioned)
        with self.assertRaises(StateCorruptionError):
            self.store.events()

    def test_illegal_transition_does_not_mutate_state_or_events(self) -> None:
        self.store.create("run-123")
        state_before = self.store.state_path.read_bytes()
        events_before = self.store.events_path.read_bytes()

        with self.assertRaises(InvalidTransitionError):
            self.store.transition(Phase.DEVELOPING, expected_revision=0)

        self.assertEqual(self.store.state_path.read_bytes(), state_before)
        self.assertEqual(self.store.events_path.read_bytes(), events_before)
        self.assertEqual(self.store.load().revision, 0)

    def test_adjudicated_operation_has_a_dedicated_idempotent_restore_event(
        self,
    ) -> None:
        state = self.store.create("run-123")
        for phase in (
            Phase.PLANNING,
            Phase.PLAN_REVIEW,
            Phase.AWAITING_PLAN_APPROVAL,
            Phase.DEVELOPING,
            Phase.CODE_REVIEW,
            Phase.VERIFYING,
            Phase.AWAITING_RELEASE_APPROVAL,
            Phase.RELEASING,
        ):
            state = self.store.transition(phase, expected_revision=state.revision)
        blocked = self.store.reconcile_transition(
            Phase.BLOCKED,
            expected_revision=state.revision,
            reason="external-operation-unknown",
        )

        with self.assertRaises(InvalidTransitionError):
            self.store.transition(
                Phase.RELEASING,
                expected_revision=blocked.revision,
            )

        restored = self.store.restore_adjudicated_operation(
            mode="release",
            adjudication_id="a" * 64,
            expected_revision=blocked.revision,
        )
        repeated = self.store.restore_adjudicated_operation(
            mode="release",
            adjudication_id="a" * 64,
            expected_revision=blocked.revision,
        )

        self.assertEqual(restored, repeated)
        self.assertEqual(restored.phase, Phase.RELEASING)
        self.assertEqual(restored.revision, blocked.revision + 1)
        event = self.store.events()[-1]
        self.assertEqual(event.event_type, "operation.adjudicated")
        self.assertEqual(
            event.operation_adjudication,
            {
                "schema_version": 1,
                "run_id": "run-123",
                "mode": "release",
                "adjudication_id": "a" * 64,
            },
        )
        invalid = event.to_dict()
        invalid["operation_adjudication"]["schema_version"] = True
        with self.assertRaises(ValueError):
            type(event).from_dict(invalid)

    def test_adjudicated_operation_rejects_unrelated_block_without_mutation(
        self,
    ) -> None:
        initial = self.store.create("run-123")
        blocked = self.store.transition(
            Phase.BLOCKED,
            expected_revision=initial.revision,
        )
        state_before = self.store.state_path.read_bytes()
        events_before = self.store.events_path.read_bytes()

        with self.assertRaises(InvalidTransitionError):
            self.store.restore_adjudicated_operation(
                mode="release",
                adjudication_id="a" * 64,
                expected_revision=blocked.revision,
            )

        self.assertEqual(self.store.state_path.read_bytes(), state_before)
        self.assertEqual(self.store.events_path.read_bytes(), events_before)
        self.assertEqual(self.store.load(), blocked)

    def test_stale_revision_does_not_mutate_state_or_events(self) -> None:
        self.store.create("run-123")
        self.store.transition(Phase.PLANNING, expected_revision=0)
        state_before = self.store.state_path.read_bytes()
        events_before = self.store.events_path.read_bytes()

        with self.assertRaises(StaleRevisionError):
            self.store.transition(Phase.PLAN_REVIEW, expected_revision=0)

        self.assertEqual(self.store.state_path.read_bytes(), state_before)
        self.assertEqual(self.store.events_path.read_bytes(), events_before)
        self.assertEqual(self.store.load().revision, 1)

    def test_wal_event_recovers_when_snapshot_write_fails(self) -> None:
        self.store.create("run-123")

        with mock.patch.object(
            self.store,
            "_write_snapshot",
            side_effect=OSError("simulated crash before snapshot replace"),
        ):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                self.store.transition(Phase.PLANNING, expected_revision=0)

        recovered = StateStore(self.run_directory).load()
        self.assertEqual(recovered.phase, Phase.PLANNING)
        self.assertEqual(recovered.revision, 1)
        self.assertEqual(len(StateStore(self.run_directory).events()), 2)

    def test_torn_final_jsonl_line_is_ignored_and_removed_before_append(self) -> None:
        self.store.create("run-123")
        with self.store.events_path.open("ab") as stream:
            stream.write(b'{"revision":')
            stream.flush()
            os.fsync(stream.fileno())

        self.assertEqual(len(self.store.events()), 1)
        self.assertEqual(self.store.load().revision, 0)

        changed = self.store.transition(Phase.PLANNING, expected_revision=0)

        self.assertEqual(changed.revision, 1)
        self.assertEqual(len(self.store.events()), 2)
        self.assertNotIn(b'{"revision":\n', self.store.events_path.read_bytes())

    def test_unterminated_final_event_is_treated_as_torn(self) -> None:
        self.store.create("run-123")
        pre_transition_snapshot = self.store.state_path.read_bytes()
        self.store.transition(Phase.PLANNING, expected_revision=0)
        with self.store.events_path.open("r+b") as stream:
            stream.seek(-1, os.SEEK_END)
            self.assertEqual(stream.read(1), b"\n")
            stream.truncate(stream.tell() - 1)
            stream.flush()
            os.fsync(stream.fileno())
        self.store.state_path.write_bytes(pre_transition_snapshot)

        recovered = self.store.load()

        self.assertEqual(recovered.phase, Phase.INITIALIZED)
        self.assertEqual(recovered.revision, 0)
        changed = self.store.transition(Phase.PLANNING, expected_revision=0)
        self.assertEqual(changed.revision, 1)
        self.assertEqual(len(self.store.events()), 2)

    def test_torn_tail_cannot_hide_wal_truncation_proven_by_snapshot(self) -> None:
        self.store.create("run-123")
        expected = self.store.transition(Phase.PLANNING, expected_revision=0)
        event_lines = self.store.events_path.read_bytes().splitlines(keepends=True)
        self.assertEqual(expected.revision, 1)

        self.store.events_path.write_bytes(event_lines[0] + b'{"torn"')

        with self.assertRaises(StateCorruptionError):
            self.store.load()

    def test_interior_corrupt_event_is_fatal(self) -> None:
        self.store.create("run-123")
        valid_event = self.store.events_path.read_bytes()
        with self.store.events_path.open("ab") as stream:
            stream.write(b"not-json\n")
            stream.write(valid_event)
            stream.flush()
            os.fsync(stream.fileno())

        with self.assertRaises(StateCorruptionError):
            self.store.events()
        with self.assertRaises(StateCorruptionError):
            self.store.load()

    def test_rebuild_restores_a_missing_snapshot_from_events(self) -> None:
        expected = self.store.create("run-123")
        expected = self.store.transition(Phase.PLANNING, expected_revision=0)
        self.store.state_path.unlink()

        rebuilt = self.store.rebuild()

        self.assertEqual(rebuilt, expected)
        self.assertEqual(self.store.load(), expected)

    def test_runtime_directory_and_files_are_private(self) -> None:
        self.store.create("run-123")

        self.assertEqual(stat.S_IMODE(self.run_directory.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.run_directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.store.state_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.store.events_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.store.lock_path.stat().st_mode), 0o600)

    def test_new_runtime_directories_fsync_their_parent_entries(self) -> None:
        with mock.patch("ship_flow.store._fsync_directory") as fsync_directory:
            self.store.create("run-123")

        synced_directories = {call.args[0] for call in fsync_directory.call_args_list}
        self.assertIn(Path(self.temporary_directory.name), synced_directories)
        self.assertIn(self.run_directory.parent, synced_directories)

    def test_existing_runtime_ancestors_are_made_private(self) -> None:
        runtime_root = Path(self.temporary_directory.name) / "ship-flow"
        runs_directory = runtime_root / "runs"
        run_directory = runs_directory / "run-456"
        run_directory.mkdir(parents=True)
        for directory in (runtime_root, runs_directory, run_directory):
            directory.chmod(0o755)

        StateStore(run_directory).create("run-456")

        for directory in (runtime_root, runs_directory, run_directory):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)


class PrivateEvidenceFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.run_directory = self.root / "runs" / "run-123"
        self.evidence_directory = self.run_directory / "evidence"
        self.evidence_directory.mkdir(parents=True)
        self.run_directory.chmod(0o700)
        self.evidence_directory.chmod(0o700)
        self.displaced_directory = self.root / "displaced-evidence"
        self.outside_directory = self.root / "outside"
        self.outside_directory.mkdir()
        self.sentinel = self.outside_directory / "sentinel"
        self.sentinel.write_text("unchanged\n", encoding="utf-8")
        self.sentinel.chmod(0o644)

    def _swap_after_parent_open(self) -> mock._patch:
        real_open = store_module._open_private_directory
        swapped = False

        def open_then_swap(path: Path, *, private_root: Path | None = None) -> int:
            nonlocal swapped
            descriptor = real_open(path, private_root=private_root)
            if not swapped and Path(path) == self.evidence_directory:
                self.evidence_directory.rename(self.displaced_directory)
                self.evidence_directory.symlink_to(
                    self.outside_directory,
                    target_is_directory=True,
                )
                swapped = True
            return descriptor

        return mock.patch.object(
            store_module,
            "_open_private_directory",
            side_effect=open_then_swap,
        )

    def _swap_after_existing_parent_open(self) -> mock._patch:
        real_open = store_module._open_existing_private_directory_from_anchor
        swapped = False

        def open_then_swap(
            path: Path,
            *,
            trusted_root: Path | store_module.PrivateRootAnchor,
        ) -> int:
            nonlocal swapped
            descriptor = real_open(path, trusted_root=trusted_root)
            if not swapped and Path(path) == self.evidence_directory:
                self.evidence_directory.rename(self.displaced_directory)
                self.evidence_directory.symlink_to(
                    self.outside_directory,
                    target_is_directory=True,
                )
                swapped = True
            return descriptor

        return mock.patch.object(
            store_module,
            "_open_existing_private_directory_from_anchor",
            side_effect=open_then_swap,
        )

    def test_mutable_replace_keeps_stable_parent_fd_during_directory_swap(
        self,
    ) -> None:
        outside_target = self.outside_directory / "receipt.json"
        outside_target.write_text("foreign\n", encoding="utf-8")
        outside_target.chmod(0o644)
        outside_before = {
            entry.name: (entry.read_bytes(), stat.S_IMODE(entry.stat().st_mode))
            for entry in self.outside_directory.iterdir()
        }

        with self._swap_after_parent_open():
            _atomic_write_private_json(
                self.evidence_directory / "receipt.json",
                {"status": "safe"},
                trusted_root=self.run_directory,
            )

        self.assertEqual(
            {
                entry.name: (entry.read_bytes(), stat.S_IMODE(entry.stat().st_mode))
                for entry in self.outside_directory.iterdir()
            },
            outside_before,
        )
        self.assertEqual(
            json.loads(
                (self.displaced_directory / "receipt.json").read_text(encoding="utf-8")
            ),
            {"status": "safe"},
        )

    def test_immutable_link_keeps_stable_parent_fd_during_directory_swap(
        self,
    ) -> None:
        outside_before = tuple(
            sorted(entry.name for entry in self.outside_directory.iterdir())
        )

        with self._swap_after_parent_open():
            _atomic_write_private_json(
                self.evidence_directory / "seal.json",
                {"status": "sealed"},
                trusted_root=self.run_directory,
                immutable=True,
            )

        self.assertEqual(
            tuple(sorted(entry.name for entry in self.outside_directory.iterdir())),
            outside_before,
        )
        self.assertEqual(self.sentinel.read_text(encoding="utf-8"), "unchanged\n")
        self.assertEqual(
            json.loads(
                (self.displaced_directory / "seal.json").read_text(encoding="utf-8")
            ),
            {"status": "sealed"},
        )

    def test_unlink_keeps_stable_parent_fd_during_directory_swap(self) -> None:
        receipt = self.evidence_directory / "receipt.json"
        receipt.write_text("owned\n", encoding="utf-8")
        receipt.chmod(0o600)
        outside_target = self.outside_directory / receipt.name
        outside_target.write_text("foreign\n", encoding="utf-8")
        outside_target.chmod(0o644)
        outside_before = {
            entry.name: (entry.read_bytes(), stat.S_IMODE(entry.stat().st_mode))
            for entry in self.outside_directory.iterdir()
        }

        with self._swap_after_parent_open():
            _remove_private_file(
                receipt,
                trusted_root=self.run_directory,
            )

        self.assertFalse((self.displaced_directory / receipt.name).exists())
        self.assertEqual(
            {
                entry.name: (entry.read_bytes(), stat.S_IMODE(entry.stat().st_mode))
                for entry in self.outside_directory.iterdir()
            },
            outside_before,
        )

    def test_read_keeps_stable_parent_fd_during_directory_swap(self) -> None:
        evidence = self.evidence_directory / "receipt.json"
        evidence.write_text("owned\n", encoding="utf-8")
        evidence.chmod(0o600)
        outside_target = self.outside_directory / evidence.name
        outside_target.write_text("foreign\n", encoding="utf-8")
        outside_target.chmod(0o600)

        with self._swap_after_existing_parent_open():
            raw = _read_bounded_private_file(
                evidence,
                trusted_root=self.run_directory,
                label="receipt",
                max_bytes=1024,
            )

        self.assertEqual(raw, b"owned\n")
        self.assertEqual(outside_target.read_bytes(), b"foreign\n")


class FileLockTests(unittest.TestCase):
    def test_publication_anchor_binds_state_and_evidence_to_locked_run_inode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            run_directory = root / "runs" / "run-123"
            detached = root / "detached-run"
            store = StateStore(run_directory)
            store.create("run-123")
            publication_lock = FileLock(
                run_directory / "review-publication.lock",
                private_root=run_directory,
            )

            with publication_lock as acquired_lock:
                run_directory.rename(detached)
                shutil.copytree(detached, run_directory)
                with store.anchored(acquired_lock.trusted_parent):
                    store.transition(Phase.PLANNING, expected_revision=0)
                    _atomic_write_private_json(
                        run_directory / "reviews" / "plan-review.json",
                        {"verdict": "pass"},
                        trusted_root=store.trusted_root,
                    )

            replacement = StateStore(run_directory).load()
            anchored = StateStore(detached).load()
            self.assertEqual(
                (replacement.phase, replacement.revision),
                (Phase.INITIALIZED, 0),
            )
            self.assertEqual(
                (anchored.phase, anchored.revision),
                (Phase.PLANNING, 1),
            )
            self.assertFalse((run_directory / "reviews" / "plan-review.json").exists())
            self.assertEqual(
                json.loads(
                    (detached / "reviews" / "plan-review.json").read_text(
                        encoding="utf-8"
                    )
                ),
                {"verdict": "pass"},
            )

    def test_repository_lock_keeps_parent_fd_during_ancestor_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            common_directory = root / ".git"
            locks_directory = common_directory / "ship-flow" / "locks"
            locks_directory.mkdir(parents=True)
            displaced_locks = root / "original-locks"
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "repository.lock"
            sentinel.write_text("foreign\n", encoding="utf-8")
            sentinel.chmod(0o644)
            real_open = os.open
            swapped = False

            def replace_ancestor_before_lock_open(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                if not swapped and Path(path).name == "repository.lock":
                    locks_directory.rename(displaced_locks)
                    locks_directory.symlink_to(outside, target_is_directory=True)
                    swapped = True
                if dir_fd is None:
                    return real_open(path, flags, mode)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch(
                "ship_flow.store.os.open",
                side_effect=replace_ancestor_before_lock_open,
            ):
                lock = FileLock.repository(common_directory)
                lock.acquire()
                lock.release()

            self.assertTrue(swapped)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "foreign\n")
            self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o644)

    def test_repository_lock_rejects_symlinked_private_components(self) -> None:
        for component in ("ship-flow", "locks", "repository.lock"):
            with (
                self.subTest(component=component),
                tempfile.TemporaryDirectory() as temporary_directory,
            ):
                root = Path(temporary_directory)
                common_directory = root / ".git"
                common_directory.mkdir()
                outside = root / "outside"
                outside.mkdir()
                sentinel = outside / "sentinel"
                sentinel.write_text("unchanged\n", encoding="utf-8")
                sentinel.chmod(0o644)

                runtime_root = common_directory / "ship-flow"
                locks_directory = runtime_root / "locks"
                lock_path = locks_directory / "repository.lock"
                if component == "ship-flow":
                    runtime_root.symlink_to(outside, target_is_directory=True)
                elif component == "locks":
                    runtime_root.mkdir()
                    locks_directory.symlink_to(outside, target_is_directory=True)
                else:
                    locks_directory.mkdir(parents=True)
                    lock_path.symlink_to(sentinel)

                with self.assertRaises(UnsafeLockPathError):
                    FileLock.repository(common_directory).acquire()

                self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged\n")
                self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o644)

    def test_second_lock_acquisition_fails_without_waiting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            lock_path = Path(temporary_directory) / "locks" / "repository.lock"
            first = FileLock(lock_path)
            second = FileLock(lock_path)
            first.acquire()
            self.addCleanup(first.release)

            with self.assertRaises(LockUnavailableError):
                second.acquire()

            first.release()
            second.acquire()
            second.release()

    def test_scope_factories_use_distinct_private_lock_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            common_directory = Path(temporary_directory) / ".git"
            run_directory = common_directory / "ship-flow" / "runs" / "run-123"
            common_directory.mkdir()

            locks = (
                FileLock.repository(common_directory),
                FileLock.run(run_directory),
                FileLock.release_target(common_directory, "production/us-east"),
            )
            self.assertEqual(len({lock.path for lock in locks}), 3)

            for lock in locks:
                lock.acquire()
                lock.release()
                self.assertEqual(stat.S_IMODE(lock.path.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(lock.path.stat().st_mode), 0o600)

    def test_release_lock_tightens_existing_runtime_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            common_directory = Path(temporary_directory) / ".git"
            runtime_root = common_directory / "ship-flow"
            locks_directory = runtime_root / "locks"
            locks_directory.mkdir(parents=True)
            for directory in (runtime_root, locks_directory):
                directory.chmod(0o755)

            lock = FileLock.release_target(common_directory, "production/us-east")
            lock.acquire()
            lock.release()

            for directory in (runtime_root, locks_directory, lock.path.parent):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
