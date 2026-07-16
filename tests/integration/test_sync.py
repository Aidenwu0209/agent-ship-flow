from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Callable
from unittest import mock

import ship_flow.sync as sync_module
from ship_flow.model import Phase
from ship_flow.store import FileLock, LockUnavailableError, StateStore
from ship_flow.subject import EvidenceSubject
from ship_flow.sync import (
    SyncError,
    SyncItem,
    SyncRecoveryError,
    SyncRecorder,
    SyncReport,
    SyncReportDraft,
    _load_current_sync_report_locked,
    load_current_sync_report,
)
from tests.support import git, git_output, initialize_repository


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SimulatedCrash(BaseException):
    pass


@contextmanager
def _reject_external_io(
    external_root: Path,
) -> Iterator[tuple[list[tuple[int, int]], list[tuple[int, int]]]]:
    external_identities = {
        (path.lstat().st_dev, path.lstat().st_ino)
        for path in (external_root, *external_root.rglob("*"))
    }
    original_open = os.open
    original_read = os.read
    external_opens: list[tuple[int, int]] = []
    external_reads: list[tuple[int, int]] = []

    def guarded_open(
        path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in external_identities:
            external_opens.append(identity)
            os.close(descriptor)
            raise AssertionError("external runtime evidence was opened")
        return descriptor

    def guarded_read(descriptor: int, length: int) -> bytes:
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in external_identities:
            external_reads.append(identity)
            raise AssertionError("external runtime evidence was read")
        return original_read(descriptor, length)

    with (
        mock.patch.object(os, "open", new=guarded_open),
        mock.patch.object(os, "read", new=guarded_read),
    ):
        yield external_opens, external_reads


class SymlinkRaceRecorder(SyncRecorder):
    def __init__(self, *, race: Callable[[], None], **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._race = race
        self._live_calls = 0

    def _live_subject(self) -> EvidenceSubject:
        self._live_calls += 1
        if self._live_calls == 2:
            self._race()
        return self._subject_provider()


class SyncReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repo = self.root / "repo"
        initialize_repository(self.repo)
        (self.repo / "src").mkdir()
        (self.repo / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
        git(self.repo, "add", "src/app.py")
        git(self.repo, "commit", "-m", "add app")
        self.run_directory = self.repo / ".git" / "ship-flow" / "runs" / "run-sync"
        self.store = StateStore(self.run_directory)
        state = self.store.create("run-sync")
        for phase in (
            Phase.PLANNING,
            Phase.PLAN_REVIEW,
            Phase.AWAITING_PLAN_APPROVAL,
            Phase.DEVELOPING,
            Phase.CODE_REVIEW,
            Phase.VERIFYING,
            Phase.AWAITING_RELEASE_APPROVAL,
            Phase.RELEASING,
            Phase.POST_RELEASE_VERIFYING,
            Phase.SYNCING,
        ):
            state = self.store.transition(phase, expected_revision=state.revision)
        self.subject = EvidenceSubject(
            run_id="run-sync",
            base_oid=git_output(self.repo, "rev-parse", "HEAD^"),
            candidate_oid=git_output(self.repo, "rev-parse", "HEAD"),
            tree_oid=git_output(self.repo, "rev-parse", "HEAD^{tree}"),
            plan_sha256=_sha("plan"),
            manifest_sha256=_sha("manifest"),
            commands_sha256=_sha("commands"),
            engine_version="test-engine",
            schema_version=1,
        )
        self.recorder = SyncRecorder(
            store=self.store,
            worktree=self.repo,
            current_subject=lambda: self.subject,
        )

    def _passing_draft(self) -> SyncReportDraft:
        return SyncReportDraft(
            reporter="sync-agent",
            items=(
                SyncItem("code", "current", ("src/app.py",)),
                SyncItem("docs", "current", ("README.md",)),
                SyncItem("rules", "not_applicable", ()),
                SyncItem("project_knowledge", "not_applicable", ()),
            ),
        )

    def _changes_required_draft(self) -> SyncReportDraft:
        return SyncReportDraft(
            reporter="sync-agent",
            items=(
                SyncItem("code", "current", ("src/app.py",)),
                SyncItem("docs", "changes_required", ("docs/needed.md",)),
                SyncItem("rules", "not_applicable", ()),
                SyncItem("project_knowledge", "not_applicable", ()),
            ),
        )

    def _subject_at_head(self) -> EvidenceSubject:
        return EvidenceSubject(
            **{
                **self.subject.to_dict(),
                "candidate_oid": git_output(self.repo, "rev-parse", "HEAD"),
                "tree_oid": git_output(self.repo, "rev-parse", "HEAD^{tree}"),
            }
        )

    def _load_current(
        self,
        subject: EvidenceSubject | None = None,
        *,
        current_subject: Callable[[], EvidenceSubject] | None = None,
        worktree: Path | None = None,
    ) -> SyncReport:
        expected = self.subject if subject is None else subject
        if current_subject is None:

            def provider() -> EvidenceSubject:
                return expected

        else:
            provider = current_subject
        return load_current_sync_report(
            self.store,
            expected,
            worktree=self.repo if worktree is None else worktree,
            current_subject=provider,
        )

    def test_models_are_frozen(self) -> None:
        item = SyncItem("code", "current", ("src/app.py",))
        draft = self._passing_draft()

        with self.assertRaises(FrozenInstanceError):
            item.status = "changes_required"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            draft.reporter = "other"  # type: ignore[misc]
        self.assertTrue(SyncReport.__dataclass_params__.frozen)

    def test_recorder_requires_a_live_subject_provider(self) -> None:
        with self.assertRaises(TypeError):
            SyncRecorder(
                store=self.store,
                worktree=self.repo,
                current_subject=self.subject,
            )

    def test_items_are_normalized_to_the_fixed_category_order(self) -> None:
        draft = SyncReportDraft(
            reporter="sync-agent",
            items=tuple(reversed(self._passing_draft().items)),
        )

        self.assertEqual(
            tuple(item.category for item in draft.items),
            ("code", "docs", "rules", "project_knowledge"),
        )

    def test_live_provider_drift_rejects_before_writing_any_publication(self) -> None:
        drifted = EvidenceSubject(
            **{
                **self.subject.to_dict(),
                "plan_sha256": _sha("changed-plan"),
            }
        )
        recorder = SyncRecorder(
            store=self.store,
            worktree=self.repo,
            current_subject=lambda: drifted,
        )

        with self.assertRaises(SyncError):
            recorder.record_sync_report(self._passing_draft(), self.subject)

        self.assertEqual(self.store.load().phase, Phase.SYNCING)
        self.assertFalse((self.run_directory / "sync-operation.json").exists())
        self.assertFalse((self.run_directory / "sync-report.json").exists())
        self.assertFalse((self.run_directory / "sync-publications").exists())

    def test_live_subject_rejects_an_unknown_base_commit_before_writing(self) -> None:
        invalid = EvidenceSubject(
            **{
                **self.subject.to_dict(),
                "base_oid": "0" * 40,
            }
        )
        recorder = SyncRecorder(
            store=self.store,
            worktree=self.repo,
            current_subject=lambda: invalid,
        )

        with self.assertRaises(SyncError):
            recorder.record_sync_report(self._passing_draft(), invalid)

        self.assertEqual(self.store.load().phase, Phase.SYNCING)
        self.assertFalse((self.run_directory / "sync-operation.json").exists())
        self.assertFalse((self.run_directory / "sync-report.json").exists())

    def test_candidate_change_after_first_observation_never_reaches_cleanup(
        self,
    ) -> None:
        calls = 0

        def moving_subject() -> EvidenceSubject:
            nonlocal calls
            calls += 1
            if calls == 2:
                (self.repo / "src" / "app.py").write_text(
                    "print('changed')\n",
                    encoding="utf-8",
                )
                git(self.repo, "add", "src/app.py")
                git(self.repo, "commit", "-m", "racing candidate")
            return self.subject

        recorder = SyncRecorder(
            store=self.store,
            worktree=self.repo,
            current_subject=moving_subject,
        )

        with self.assertRaises(SyncError):
            recorder.record_sync_report(self._passing_draft(), self.subject)

        self.assertEqual(self.store.load().phase, Phase.SYNCING)
        with self.assertRaises((SyncError, SyncRecoveryError)):
            self._load_current()

    def test_repository_lock_spans_live_check_publication_and_transition(self) -> None:
        calls = 0
        contention: list[str] = []
        common = (
            self.repo / git_output(self.repo, "rev-parse", "--git-common-dir")
        ).resolve()

        def contending_subject() -> EvidenceSubject:
            nonlocal calls
            calls += 1
            if calls == 2:
                contender = FileLock.repository(common)
                try:
                    contender.acquire()
                except LockUnavailableError:
                    contention.append("blocked")
                else:
                    contender.release()
                    raise SimulatedCrash("candidate publisher acquired repository lock")
            return self.subject

        recorder = SyncRecorder(
            store=self.store,
            worktree=self.repo,
            current_subject=contending_subject,
        )

        recorder.record_sync_report(self._passing_draft(), self.subject)

        self.assertEqual(contention, ["blocked"])
        self.assertEqual(self.store.load().phase, Phase.AWAITING_CLEANUP_APPROVAL)

    def test_strict_schema_rejects_missing_unknown_and_duplicate_categories(
        self,
    ) -> None:
        valid = {
            "reporter": "sync-agent",
            "items": [
                {"category": "code", "status": "current", "paths": ["src/app.py"]},
                {"category": "docs", "status": "current", "paths": ["README.md"]},
                {"category": "rules", "status": "not_applicable", "paths": []},
                {
                    "category": "project_knowledge",
                    "status": "not_applicable",
                    "paths": [],
                },
            ],
        }
        malformed = (
            {"items": valid["items"]},
            {**valid, "unknown": True},
            {**valid, "items": [*valid["items"], valid["items"][0]]},
            {
                **valid,
                "items": [
                    {**valid["items"][0], "status": "looks_good"},
                    *valid["items"][1:],
                ],
            },
            {
                **valid,
                "items": [
                    {**valid["items"][0], "unknown": "field"},
                    *valid["items"][1:],
                ],
            },
        )

        for payload in malformed:
            with self.subTest(payload=payload):
                with self.assertRaises((SyncError, TypeError, ValueError)):
                    SyncReportDraft.from_dict(payload)

    def test_rejects_paths_outside_the_canonical_worktree(self) -> None:
        escaped = self.root / "outside.txt"
        escaped.write_text("outside\n", encoding="utf-8")
        (self.repo / "escape").symlink_to(self.root, target_is_directory=True)
        unsafe_paths = (
            str(escaped),
            "../outside.txt",
            ".git/config",
            "escape/outside.txt",
            "~/.codex/rules/default.rules",
        )

        for unsafe_path in unsafe_paths:
            with self.subTest(path=unsafe_path):
                draft = SyncReportDraft(
                    reporter="sync-agent",
                    items=(
                        SyncItem("code", "current", (unsafe_path,)),
                        SyncItem("docs", "current", ("README.md",)),
                        SyncItem("rules", "not_applicable", ()),
                        SyncItem("project_knowledge", "not_applicable", ()),
                    ),
                )
                with self.assertRaises(SyncError):
                    self.recorder.record_sync_report(draft, self.subject)
                self.assertEqual(self.store.load().phase, Phase.SYNCING)

    def test_current_path_must_be_a_regular_tracked_blob_not_an_ignored_file(
        self,
    ) -> None:
        exclude = self.repo / ".git" / "info" / "exclude"
        exclude.write_text("ignored-current.txt\n", encoding="utf-8")
        (self.repo / "ignored-current.txt").write_text("ignored\n", encoding="utf-8")
        draft = SyncReportDraft(
            reporter="sync-agent",
            items=(
                SyncItem("code", "current", ("src/app.py",)),
                SyncItem("docs", "current", ("ignored-current.txt",)),
                SyncItem("rules", "not_applicable", ()),
                SyncItem("project_knowledge", "not_applicable", ()),
            ),
        )

        with self.assertRaises(SyncError):
            self.recorder.record_sync_report(draft, self.subject)

        self.assertEqual(self.store.load().phase, Phase.SYNCING)
        self.assertFalse((self.run_directory / "sync-operation.json").exists())

    def test_current_path_is_revalidated_after_a_raced_ignored_symlink(self) -> None:
        target = self.repo / "ignored-target.txt"
        target.write_text("ignored\n", encoding="utf-8")
        (self.repo / ".git" / "info" / "exclude").write_text(
            "ignored-target.txt\n",
            encoding="utf-8",
        )

        def replace_tracked_file() -> None:
            readme = self.repo / "README.md"
            readme.unlink()
            readme.symlink_to(target)

        recorder = SymlinkRaceRecorder(
            store=self.store,
            worktree=self.repo,
            current_subject=lambda: self.subject,
            race=replace_tracked_file,
        )

        with self.assertRaises(SyncError):
            recorder.record_sync_report(self._passing_draft(), self.subject)

        self.assertEqual(self.store.load().phase, Phase.SYNCING)

    def test_current_path_rejects_assume_unchanged_content_drift(self) -> None:
        git(self.repo, "update-index", "--assume-unchanged", "README.md")
        (self.repo / "README.md").write_text(
            "hidden working-tree drift\n",
            encoding="utf-8",
        )

        with self.assertRaises(SyncError):
            self.recorder.record_sync_report(
                self._passing_draft(),
                self.subject,
            )

        self.assertEqual(self.store.load().phase, Phase.SYNCING)
        self.assertFalse((self.run_directory / "sync-operation.json").exists())

    def test_same_subject_can_publish_a_second_sync_gate_generation(self) -> None:
        self.recorder.record_sync_report(
            self._changes_required_draft(),
            self.subject,
        )
        state = self.store.load()
        for phase in (
            Phase.CODE_REVIEW,
            Phase.VERIFYING,
            Phase.AWAITING_RELEASE_APPROVAL,
            Phase.RELEASING,
            Phase.POST_RELEASE_VERIFYING,
            Phase.SYNCING,
        ):
            state = self.store.transition(phase, expected_revision=state.revision)

        current = self.recorder.record_sync_report(
            self._passing_draft(),
            self.subject,
        )

        self.assertEqual(self.store.load().phase, Phase.AWAITING_CLEANUP_APPROVAL)
        self.assertEqual(current.subject, self.subject)
        self.assertEqual(
            len(tuple((self.run_directory / "sync-publications").glob("*.json"))),
            2,
        )
        self.assertEqual(self._load_current(), current)

    def test_a_sync_gate_rejects_an_orphan_seal_for_a_different_subject(self) -> None:
        state = self.store.load()
        publications = self.run_directory / "sync-publications"
        publications.mkdir(mode=0o700)
        orphan = (
            publications / f"sync-{'f' * 64}-gate-{state.revision:08d}-{'e' * 64}.json"
        )
        orphan.write_text("{}\n", encoding="utf-8")
        orphan.chmod(0o600)

        with self.assertRaises(SyncRecoveryError):
            self.recorder.record_sync_report(
                self._passing_draft(),
                self.subject,
            )

        self.assertEqual(self.store.load().phase, Phase.SYNCING)
        self.assertFalse((self.run_directory / "sync-operation.json").exists())

    def test_current_report_is_canonical_private_and_reaches_cleanup_gate(self) -> None:
        report = self.recorder.record_sync_report(
            self._passing_draft(),
            self.subject,
        )

        self.assertEqual(report.subject, self.subject)
        self.assertEqual(self.store.load().phase, Phase.AWAITING_CLEANUP_APPROVAL)
        path = self.run_directory / "sync-report.json"
        raw = path.read_bytes()
        self.assertEqual(
            raw,
            json.dumps(
                json.loads(raw.decode("utf-8")),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n",
        )
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        seals = tuple((self.run_directory / "sync-publications").glob("*.json"))
        self.assertEqual(len(seals), 1)
        self.assertEqual(stat.S_IMODE(seals[0].stat().st_mode), 0o600)
        self.assertFalse((self.run_directory / "sync-operation.json").exists())
        self.assertEqual(
            self._load_current(),
            report,
        )

    def test_cleanup_loader_rejects_dirty_or_changed_head_with_an_old_subject(
        self,
    ) -> None:
        self.recorder.record_sync_report(self._passing_draft(), self.subject)
        (self.repo / "README.md").write_text("dirty\n", encoding="utf-8")

        with self.assertRaises(SyncError):
            self._load_current()

        git(self.repo, "restore", "README.md")
        (self.repo / "README.md").write_text("new head\n", encoding="utf-8")
        git(self.repo, "add", "README.md")
        git(self.repo, "commit", "-m", "move cleanup head")
        with self.assertRaises(SyncError):
            self._load_current()

    def test_cleanup_loader_is_strictly_read_only(self) -> None:
        expected = self.recorder.record_sync_report(
            self._passing_draft(),
            self.subject,
        )

        with mock.patch.object(
            sync_module,
            "_ensure_publication_seal",
            side_effect=AssertionError("write-capable publication helper was called"),
        ):
            actual = self._load_current()

        self.assertEqual(actual, expected)

    def test_lock_held_loader_does_not_reacquire_the_repository_lock(self) -> None:
        expected = self.recorder.record_sync_report(
            self._passing_draft(),
            self.subject,
        )

        with FileLock.repository(self.recorder.git_common_directory):
            actual = _load_current_sync_report_locked(
                self.store,
                self.subject,
                worktree=self.repo,
                current_subject=lambda: self.subject,
            )

        self.assertEqual(actual, expected)

    def test_completed_loader_is_opt_in_and_needs_no_live_worktree(self) -> None:
        expected = self.recorder.record_sync_report(
            self._passing_draft(),
            self.subject,
        )
        awaiting_cleanup = self.store.load()
        self.store.transition(
            Phase.COMPLETED,
            expected_revision=awaiting_cleanup.revision,
        )

        with self.assertRaises(SyncRecoveryError):
            self._load_current()

        def deleted_worktree_provider() -> EvidenceSubject:
            raise AssertionError("completed audit consulted the deleted worktree")

        missing_worktree = self.root / "deleted-run-worktree"
        actual = load_current_sync_report(
            self.store,
            None,
            worktree=missing_worktree,
            current_subject=deleted_worktree_provider,
            allow_completed=True,
        )
        with (
            FileLock.repository(self.recorder.git_common_directory),
            FileLock(
                self.run_directory / "sync-publication.lock",
                private_root=self.run_directory,
            ),
        ):
            locked = _load_current_sync_report_locked(
                self.store,
                None,
                worktree=missing_worktree,
                current_subject=deleted_worktree_provider,
                allow_completed=True,
            )

        self.assertEqual(actual, expected)
        self.assertEqual(locked, expected)

    def test_completed_loader_requires_one_immediate_cleanup_transition(self) -> None:
        self.recorder.record_sync_report(self._passing_draft(), self.subject)
        awaiting_cleanup = self.store.load()
        self.store.transition(
            Phase.COMPLETED,
            expected_revision=awaiting_cleanup.revision,
        )
        events = self.store.events()

        with mock.patch.object(
            self.store,
            "events",
            return_value=events + (events[-1],),
        ):
            with self.assertRaises(SyncRecoveryError):
                load_current_sync_report(
                    self.store,
                    None,
                    worktree=self.root / "deleted-run-worktree",
                    current_subject=lambda: self.subject,
                    allow_completed=True,
                )

    def test_completed_loader_rejects_a_non_cleanup_sync_publication(self) -> None:
        self.recorder.record_sync_report(
            self._changes_required_draft(),
            self.subject,
        )
        state = self.store.load()
        for phase in (
            Phase.CODE_REVIEW,
            Phase.VERIFYING,
            Phase.AWAITING_RELEASE_APPROVAL,
            Phase.RELEASING,
            Phase.POST_RELEASE_VERIFYING,
            Phase.SYNCING,
            Phase.AWAITING_CLEANUP_APPROVAL,
            Phase.COMPLETED,
        ):
            state = self.store.transition(phase, expected_revision=state.revision)

        with self.assertRaises(SyncRecoveryError):
            load_current_sync_report(
                self.store,
                None,
                worktree=self.root / "deleted-run-worktree",
                current_subject=lambda: self.subject,
                allow_completed=True,
            )

    def test_loader_binds_the_store_directory_to_the_subject_run_id(self) -> None:
        self.recorder.record_sync_report(
            self._passing_draft(),
            self.subject,
        )
        copied_run = self.run_directory.parent / "different-run"
        shutil.copytree(self.run_directory, copied_run)

        with self.assertRaises(SyncRecoveryError):
            load_current_sync_report(
                StateStore(copied_run),
                self.subject,
                worktree=self.repo,
                current_subject=lambda: self.subject,
            )

    def test_report_requires_exact_integer_schema_and_canonical_utc_timestamp(
        self,
    ) -> None:
        report = self.recorder.record_sync_report(
            self._passing_draft(),
            self.subject,
        )
        payload = report.to_dict()

        for invalid_schema in (True, 1.0, "1"):
            with self.subTest(schema_version=invalid_schema):
                with self.assertRaises(SyncError):
                    SyncReport.from_dict({**payload, "schema_version": invalid_schema})
        for invalid_time in (
            "2026-07-15T12:34:56Z",
            "2026-07-15T12:34:56.123456+00:00",
            "2026-7-15T12:34:56.123456Z",
            "not-a-time",
        ):
            with self.subTest(recorded_at=invalid_time):
                with self.assertRaises(SyncError):
                    SyncReport.from_dict({**payload, "recorded_at": invalid_time})
        with self.assertRaises(SyncError):
            SyncReport.from_dict({**payload, "items": list(reversed(payload["items"]))})

    def test_changes_required_report_is_persisted_before_returning_to_development(
        self,
    ) -> None:
        report = self.recorder.record_sync_report(
            self._changes_required_draft(),
            self.subject,
        )

        self.assertEqual(self.store.load().phase, Phase.DEVELOPING)
        self.assertIn(
            "changes_required",
            {item.status for item in report.items},
        )
        self.assertEqual(
            json.loads((self.run_directory / "sync-report.json").read_text()),
            report.to_dict(),
        )

    def test_a_new_subject_can_replace_the_pointer_but_preserves_both_seals(
        self,
    ) -> None:
        holder = [self.subject]
        recorder = SyncRecorder(
            store=self.store,
            worktree=self.repo,
            current_subject=lambda: holder[0],
        )
        recorder.record_sync_report(self._changes_required_draft(), self.subject)
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "needed.md").write_text("current\n", encoding="utf-8")
        git(self.repo, "add", "docs/needed.md")
        git(self.repo, "commit", "-m", "sync docs")
        holder[0] = self._subject_at_head()
        state = self.store.load()
        for phase in (
            Phase.CODE_REVIEW,
            Phase.VERIFYING,
            Phase.AWAITING_RELEASE_APPROVAL,
            Phase.RELEASING,
            Phase.POST_RELEASE_VERIFYING,
            Phase.SYNCING,
        ):
            state = self.store.transition(phase, expected_revision=state.revision)

        current = recorder.record_sync_report(self._passing_draft(), holder[0])

        self.assertEqual(current.subject, holder[0])
        self.assertEqual(self.store.load().phase, Phase.AWAITING_CLEANUP_APPROVAL)
        self.assertEqual(
            len(tuple((self.run_directory / "sync-publications").glob("*.json"))),
            2,
        )
        self.assertEqual(
            self._load_current(holder[0]),
            current,
        )

    def test_cleanup_loader_rejects_report_tampering_and_deletion(self) -> None:
        self.recorder.record_sync_report(self._passing_draft(), self.subject)
        report_path = self.run_directory / "sync-report.json"
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        payload["reporter"] = "attacker"
        report_path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        report_path.chmod(0o600)

        with self.assertRaises(SyncRecoveryError):
            self._load_current()

        report_path.unlink()
        with self.assertRaises(SyncRecoveryError):
            self._load_current()

    def test_cleanup_loader_rejects_noncanonical_nan_as_recovery_error(self) -> None:
        self.recorder.record_sync_report(self._passing_draft(), self.subject)
        report_path = self.run_directory / "sync-report.json"
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        payload["recorded_at"] = float("nan")
        report_path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        report_path.chmod(0o600)

        with self.assertRaises(SyncRecoveryError):
            self._load_current()

    def test_cleanup_loader_rejects_seal_tampering_and_deletion(self) -> None:
        self.recorder.record_sync_report(self._passing_draft(), self.subject)
        seal = next((self.run_directory / "sync-publications").glob("*.json"))
        original = seal.read_bytes()
        payload = json.loads(original.decode("utf-8"))
        payload["target_phase"] = Phase.DEVELOPING.value
        seal.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        seal.chmod(0o600)

        with self.assertRaises(SyncRecoveryError):
            self._load_current()

        seal.write_bytes(original)
        seal.chmod(0o600)
        seal.unlink()
        with self.assertRaises(SyncRecoveryError):
            self._load_current()

    def test_report_loader_rejects_symlinked_run_ancestor_without_external_read(
        self,
    ) -> None:
        self.recorder.record_sync_report(self._passing_draft(), self.subject)
        external = self.root / "external-report-run"
        self.run_directory.rename(external)
        self.run_directory.symlink_to(external, target_is_directory=True)
        with _reject_external_io(external) as (external_opens, external_reads):
            with self.assertRaises(SyncRecoveryError):
                self._load_current()

        self.assertEqual(external_opens, [])
        self.assertEqual(external_reads, [])

    def test_pending_loader_rejects_symlinked_run_ancestor_without_external_read(
        self,
    ) -> None:
        with mock.patch.object(
            self.store,
            "transition",
            side_effect=SimulatedCrash("after report publication"),
        ):
            with self.assertRaises(SimulatedCrash):
                self.recorder.record_sync_report(
                    self._passing_draft(),
                    self.subject,
                )
        external = self.root / "external-operation-run"
        self.run_directory.rename(external)
        self.run_directory.symlink_to(external, target_is_directory=True)
        with _reject_external_io(external) as (external_opens, external_reads):
            with self.assertRaises(SyncRecoveryError):
                sync_module._load_operation(
                    StateStore(self.run_directory),
                    trusted_boundary=self.recorder.git_common_directory,
                )

        self.assertEqual(external_opens, [])
        self.assertEqual(external_reads, [])

    def test_loader_rejects_symlinked_publication_directory_without_external_read(
        self,
    ) -> None:
        self.recorder.record_sync_report(self._passing_draft(), self.subject)
        publications = self.run_directory / "sync-publications"
        external = self.root / "external-publications"
        publications.rename(external)
        publications.symlink_to(external, target_is_directory=True)
        with _reject_external_io(external) as (external_opens, external_reads):
            with self.assertRaises(SyncRecoveryError):
                self._load_current()

        self.assertEqual(external_opens, [])
        self.assertEqual(external_reads, [])

    def test_trusted_boundary_rejects_external_runtime_without_opening_it(self) -> None:
        with mock.patch.object(
            self.store,
            "transition",
            side_effect=SimulatedCrash("after report publication"),
        ):
            with self.assertRaises(SimulatedCrash):
                self.recorder.record_sync_report(
                    self._passing_draft(),
                    self.subject,
                )
        external_common = self.root / "external-common"
        shutil.copytree(self.repo / ".git" / "ship-flow", external_common / "ship-flow")
        forged_common = self.root / "forged-common"
        forged_common.symlink_to(external_common, target_is_directory=True)
        forged_store = StateStore(
            forged_common / "ship-flow" / "runs" / self.subject.run_id
        )
        with _reject_external_io(external_common) as (
            external_opens,
            external_reads,
        ):
            with self.assertRaises(SyncRecoveryError):
                sync_module._load_operation(
                    forged_store,
                    trusted_boundary=self.recorder.git_common_directory,
                )

        self.assertEqual(external_opens, [])
        self.assertEqual(external_reads, [])

    def test_recording_never_edits_reported_files_or_global_codex_state(self) -> None:
        global_rule = self.root / "home" / ".codex" / "rules" / "default.rules"
        global_rule.parent.mkdir(parents=True)
        global_rule.write_text("user-owned\n", encoding="utf-8")
        before = {
            "readme": (self.repo / "README.md").read_bytes(),
            "code": (self.repo / "src" / "app.py").read_bytes(),
            "global": global_rule.read_bytes(),
        }

        self.recorder.record_sync_report(self._passing_draft(), self.subject)

        self.assertEqual((self.repo / "README.md").read_bytes(), before["readme"])
        self.assertEqual((self.repo / "src" / "app.py").read_bytes(), before["code"])
        self.assertEqual(global_rule.read_bytes(), before["global"])

    def test_run_directory_swap_during_write_never_writes_external_target(self) -> None:
        external = self.root / "external-write-target"
        external.mkdir(mode=0o700)
        detached = self.root / "detached-run"
        original_open = os.open
        raced = False

        def racing_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal raced
            name = os.path.basename(os.fsdecode(os.fspath(path)))
            if (
                not raced
                and flags & os.O_CREAT
                and name.startswith(".sync-operation.json.")
            ):
                self.run_directory.rename(detached)
                self.run_directory.symlink_to(external, target_is_directory=True)
                raced = True
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(os, "open", new=racing_open):
            with self.assertRaises(SyncError):
                self.recorder.record_sync_report(
                    self._passing_draft(),
                    self.subject,
                )

        self.assertTrue(raced)
        self.assertEqual(tuple(external.iterdir()), ())

    def test_report_written_crash_same_request_converges_without_rewriting_report(
        self,
    ) -> None:
        draft = self._passing_draft()
        with mock.patch.object(
            self.store,
            "transition",
            side_effect=SimulatedCrash("after report publication"),
        ):
            with self.assertRaises(SimulatedCrash):
                self.recorder.record_sync_report(draft, self.subject)

        report_path = self.run_directory / "sync-report.json"
        published = report_path.read_bytes()
        self.assertEqual(self.store.load().phase, Phase.SYNCING)
        self.assertTrue((self.run_directory / "sync-operation.json").is_file())

        recovered = self.recorder.record_sync_report(draft, self.subject)

        self.assertEqual(self.store.load().phase, Phase.AWAITING_CLEANUP_APPROVAL)
        self.assertEqual(report_path.read_bytes(), published)
        self.assertEqual(
            recovered.recorded_at,
            json.loads(published.decode("utf-8"))["recorded_at"],
        )
        self.assertFalse((self.run_directory / "sync-operation.json").exists())

    def test_report_written_crash_blocks_a_different_request(self) -> None:
        draft = self._passing_draft()
        with mock.patch.object(
            self.store,
            "transition",
            side_effect=SimulatedCrash("after report publication"),
        ):
            with self.assertRaises(SimulatedCrash):
                self.recorder.record_sync_report(draft, self.subject)
        report_path = self.run_directory / "sync-report.json"
        published = report_path.read_bytes()
        different = SyncReportDraft(reporter="another-agent", items=draft.items)

        with self.assertRaises(SyncRecoveryError):
            self.recorder.record_sync_report(different, self.subject)

        self.assertEqual(self.store.load().phase, Phase.SYNCING)
        self.assertEqual(report_path.read_bytes(), published)

    def test_a_forward_operation_stage_cannot_cause_an_unproven_transition(
        self,
    ) -> None:
        with mock.patch.object(
            self.store,
            "transition",
            side_effect=SimulatedCrash("before transition"),
        ):
            with self.assertRaises(SimulatedCrash):
                self.recorder.record_sync_report(
                    self._passing_draft(),
                    self.subject,
                )
        operation_path = self.run_directory / "sync-operation.json"
        operation = json.loads(operation_path.read_text(encoding="utf-8"))
        self.assertEqual(operation["stage"], "report-written")
        operation["stage"] = "state-transitioned"
        operation_path.write_text(
            json.dumps(operation, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        operation_path.chmod(0o600)

        with self.assertRaises(SyncRecoveryError):
            self.recorder.record_sync_report(
                self._passing_draft(),
                self.subject,
            )

        self.assertEqual(self.store.load().phase, Phase.SYNCING)

    def test_transition_crash_before_operation_stage_update_converges(self) -> None:
        original = sync_module._write_operation_stage

        def crash_before_transitioned_stage(
            store: StateStore,
            operation: dict[str, object],
            stage: str,
            *,
            trusted_boundary: Path,
        ) -> dict[str, object]:
            if stage == "state-transitioned":
                raise SimulatedCrash("after transition before stage update")
            return original(
                store,
                operation,
                stage,
                trusted_boundary=trusted_boundary,
            )

        with mock.patch.object(
            sync_module,
            "_write_operation_stage",
            new=crash_before_transitioned_stage,
        ):
            with self.assertRaises(SimulatedCrash):
                self.recorder.record_sync_report(
                    self._passing_draft(),
                    self.subject,
                )

        self.assertEqual(self.store.load().phase, Phase.AWAITING_CLEANUP_APPROVAL)
        self.assertTrue((self.run_directory / "sync-operation.json").is_file())
        recovered = self.recorder.record_sync_report(
            self._passing_draft(),
            self.subject,
        )
        self.assertEqual(recovered, self._load_current())
        self.assertFalse((self.run_directory / "sync-operation.json").exists())

    def test_transition_crash_before_operation_unlink_converges(self) -> None:
        operation_path = self.run_directory / "sync-operation.json"
        original_unlink = sync_module._unlink_run_file
        crashed = False

        def crash_before_operation_unlink(
            store: StateStore,
            name: str,
            *,
            trusted_boundary: Path,
        ) -> None:
            nonlocal crashed
            if store is self.store and name == operation_path.name and not crashed:
                crashed = True
                raise SimulatedCrash("after transitioned stage before unlink")
            original_unlink(
                store,
                name,
                trusted_boundary=trusted_boundary,
            )

        with mock.patch.object(
            sync_module,
            "_unlink_run_file",
            new=crash_before_operation_unlink,
        ):
            with self.assertRaises(SimulatedCrash):
                self.recorder.record_sync_report(
                    self._passing_draft(),
                    self.subject,
                )

        self.assertEqual(self.store.load().phase, Phase.AWAITING_CLEANUP_APPROVAL)
        operation = json.loads(operation_path.read_text(encoding="utf-8"))
        self.assertEqual(operation["stage"], "state-transitioned")
        recovered = self.recorder.record_sync_report(
            self._passing_draft(),
            self.subject,
        )
        self.assertEqual(recovered, self._load_current())
        self.assertFalse(operation_path.exists())

    def test_old_transitioned_journal_is_finalized_before_a_new_sync_gate(self) -> None:
        holder = [self.subject]
        recorder = SyncRecorder(
            store=self.store,
            worktree=self.repo,
            current_subject=lambda: holder[0],
        )
        operation_path = self.run_directory / "sync-operation.json"
        original_unlink = sync_module._unlink_run_file
        crashed = False

        def crash_before_old_operation_unlink(
            store: StateStore,
            name: str,
            *,
            trusted_boundary: Path,
        ) -> None:
            nonlocal crashed
            if store is self.store and name == operation_path.name and not crashed:
                crashed = True
                raise SimulatedCrash("old gate transitioned before journal unlink")
            original_unlink(
                store,
                name,
                trusted_boundary=trusted_boundary,
            )

        with mock.patch.object(
            sync_module,
            "_unlink_run_file",
            new=crash_before_old_operation_unlink,
        ):
            with self.assertRaises(SimulatedCrash):
                recorder.record_sync_report(
                    self._changes_required_draft(),
                    holder[0],
                )

        (self.repo / "README.md").write_text("new candidate\n", encoding="utf-8")
        git(self.repo, "add", "README.md")
        git(self.repo, "commit", "-m", "new sync candidate")
        holder[0] = self._subject_at_head()
        state = self.store.load()
        for phase in (
            Phase.CODE_REVIEW,
            Phase.VERIFYING,
            Phase.AWAITING_RELEASE_APPROVAL,
            Phase.RELEASING,
            Phase.POST_RELEASE_VERIFYING,
            Phase.SYNCING,
        ):
            state = self.store.transition(phase, expected_revision=state.revision)

        current = recorder.record_sync_report(
            self._passing_draft(),
            holder[0],
        )

        self.assertEqual(self.store.load().phase, Phase.AWAITING_CLEANUP_APPROVAL)
        self.assertEqual(current.subject, holder[0])
        self.assertFalse(operation_path.exists())
        self.assertEqual(
            len(tuple((self.run_directory / "sync-publications").glob("*.json"))),
            2,
        )

    def test_crash_before_seal_write_converges_from_the_operation_receipt(self) -> None:
        with mock.patch.object(
            sync_module,
            "_ensure_publication_seal",
            side_effect=SimulatedCrash("before seal write"),
        ):
            with self.assertRaises(SimulatedCrash):
                self.recorder.record_sync_report(
                    self._passing_draft(),
                    self.subject,
                )

        self.assertTrue((self.run_directory / "sync-operation.json").is_file())
        self.assertFalse((self.run_directory / "sync-report.json").exists())
        recovered = self.recorder.record_sync_report(
            self._passing_draft(),
            self.subject,
        )
        self.assertEqual(recovered, self._load_current())

    def test_crash_after_seal_before_report_pointer_converges(self) -> None:
        original = sync_module._ensure_publication_seal
        crashed = False

        def crash_after_seal(
            store: StateStore,
            operation: dict[str, object],
            *,
            trusted_boundary: Path,
        ) -> None:
            nonlocal crashed
            original(
                store,
                operation,
                trusted_boundary=trusted_boundary,
            )
            if not crashed:
                crashed = True
                raise SimulatedCrash("after seal before report pointer")

        with mock.patch.object(
            sync_module,
            "_ensure_publication_seal",
            new=crash_after_seal,
        ):
            with self.assertRaises(SimulatedCrash):
                self.recorder.record_sync_report(
                    self._passing_draft(),
                    self.subject,
                )

        self.assertEqual(
            len(tuple((self.run_directory / "sync-publications").glob("*.json"))),
            1,
        )
        self.assertFalse((self.run_directory / "sync-report.json").exists())
        recovered = self.recorder.record_sync_report(
            self._passing_draft(),
            self.subject,
        )
        self.assertEqual(recovered, self._load_current())


if __name__ == "__main__":
    unittest.main()
