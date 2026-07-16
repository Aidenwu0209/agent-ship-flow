from __future__ import annotations

import hashlib
import json
import shutil
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ship_flow import authorization as authorization_module
from ship_flow.authorization import (
    AuthorizationContract,
    AuthorizationStore,
    ExecutionMode,
    ScopeChangeRequest,
    ScopeChangeResolution,
)
from ship_flow.model import Phase
from ship_flow.store import (
    InvalidTransitionError,
    StateCorruptionError,
    StateStore,
    StaleRevisionError,
)


class AuthorizationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.run_directory = self.root / "runs" / "run-123"
        self.repository = self.root / "repository"
        self.worktree = self.root / "worktree"
        self.repository.mkdir()
        self.worktree.mkdir()
        self.store = StateStore(self.run_directory)
        self.state = self.store.create("run-123")
        self.authorizations = AuthorizationStore(self.store)

    def _create_initial(self, **overrides: object) -> AuthorizationContract:
        arguments: dict[str, object] = {
            "mode": ExecutionMode.AUTONOMOUS,
            "goal": "ship the requested repository change",
            "repository": self.repository.resolve(),
            "worktree": self.worktree.resolve(),
            "branch": "feat/example",
            "manifest_sha256": "a" * 64,
            "release_target": "production",
            "previous_release": "v1",
            "state_revision": self.state.revision,
        }
        arguments.update(overrides)
        return self.authorizations.create_initial(**arguments)  # type: ignore[arg-type]

    def _request_change(self, **overrides: object) -> ScopeChangeRequest:
        contract = self.authorizations.current()
        assert contract is not None
        arguments: dict[str, object] = {
            "reason": "manifest_drift",
            "summary": "verification command changed",
            "proposed_goal": contract.goal,
            "proposed_manifest_sha256": "b" * 64,
            "proposed_release_target": contract.release_target,
            "proposed_previous_release": contract.previous_release,
            "expected_revision": self.store.load().revision,
        }
        arguments.update(overrides)
        return self.authorizations.request_change(**arguments)  # type: ignore[arg-type]

    def _contract_files(self, generation: int) -> list[Path]:
        return sorted(
            (self.run_directory / "authorization" / "contracts").glob(
                f"{generation:04d}-*.json"
            )
        )

    @staticmethod
    def _contract_from_path(path: Path) -> AuthorizationContract:
        return AuthorizationContract.from_dict(
            json.loads(path.read_text(encoding="utf-8"))
        )

    def _request_archive_path(self, request: ScopeChangeRequest) -> Path:
        return (
            self.run_directory
            / "authorization"
            / "requests"
            / f"{request.request_id}.json"
        )

    def _request_archive_files(self) -> list[Path]:
        return sorted(
            (self.run_directory / "authorization" / "requests").glob("*.json")
        )

    def _leave_orphan_pending_after_interrupted_stale_cas(
        self,
    ) -> ScopeChangeRequest:
        self._create_initial()
        real_transition = self.store.transition

        def supersede_gate_before_scope_transition(
            next_phase: Phase | str,
            *,
            expected_revision: int,
        ) -> object:
            real_transition(Phase.PLANNING, expected_revision=expected_revision)
            return real_transition(next_phase, expected_revision=expected_revision)

        with (
            mock.patch.object(
                self.store,
                "transition",
                side_effect=supersede_gate_before_scope_transition,
            ),
            mock.patch.object(
                self.authorizations,
                "_remove_pending_if_matches_locked",
                side_effect=SystemExit("simulated interruption before cleanup"),
            ),
        ):
            with self.assertRaisesRegex(SystemExit, "simulated interruption"):
                self._request_change(expected_revision=self.state.revision)

        orphan = self.authorizations.pending()
        assert orphan is not None
        self.assertEqual(self.store.load().phase, Phase.PLANNING)
        self.assertGreater(self.store.load().revision, orphan.gate_revision)
        return orphan

    @staticmethod
    def _request_with_identity(
        request: ScopeChangeRequest,
        **changes: object,
    ) -> ScopeChangeRequest:
        changed = replace(request, **changes)
        identity = changed.to_dict()
        identity.pop("request_id")
        request_id = hashlib.sha256(
            json.dumps(
                identity,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return replace(changed, request_id=request_id)

    def test_missing_contract_uses_strict_compatibility_mode(self) -> None:
        self.assertIsNone(self.authorizations.current())
        self.assertEqual(self.authorizations.mode(), ExecutionMode.STRICT)

    def test_create_initial_persists_private_immutable_generation(self) -> None:
        contract = self._create_initial()

        self.assertEqual(contract.generation, 1)
        self.assertEqual(AuthorizationStore(self.store).current(), contract)
        self.assertEqual(
            AuthorizationStore(self.store).mode(), ExecutionMode.AUTONOMOUS
        )
        self.assertRegex(contract.digest(), r"^[0-9a-f]{64}$")
        self.assertEqual(
            AuthorizationContract.from_dict(contract.to_dict()),
            contract,
        )
        contract_path = (
            self.run_directory
            / "authorization"
            / "contracts"
            / f"0001-{contract.digest()}.json"
        )
        self.assertTrue(contract_path.is_file())
        self.assertEqual(stat.S_IMODE(contract_path.stat().st_mode), 0o600)
        self.assertEqual(
            json.loads(
                (self.run_directory / "authorization" / "current.json").read_text(
                    encoding="utf-8"
                )
            ),
            {
                "schema_version": 1,
                "generation": 1,
                "digest": contract.digest(),
            },
        )

    def test_create_initial_is_idempotent_only_for_identical_input(self) -> None:
        first = self._create_initial()

        self.assertEqual(self._create_initial(), first)
        with self.assertRaises(ValueError):
            self._create_initial(goal="ship a broader repository change")

        self.assertEqual(self.authorizations.current(), first)

    def test_create_initial_recovers_prepared_generation_before_pointer(self) -> None:
        with mock.patch.object(
            self.authorizations,
            "_write_current",
            side_effect=OSError("simulated crash before current pointer"),
        ):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                self._create_initial()

        prepared_files = self._contract_files(1)
        self.assertEqual(len(prepared_files), 1)
        prepared = self._contract_from_path(prepared_files[0])

        recovered = self._create_initial()

        self.assertEqual(recovered, prepared)
        self.assertEqual(self._contract_files(1), prepared_files)
        self.assertEqual(self.authorizations.current(), prepared)

    def test_create_initial_rejects_conflicting_prepared_generation(self) -> None:
        with mock.patch.object(
            self.authorizations,
            "_write_current",
            side_effect=OSError("simulated crash before current pointer"),
        ):
            with self.assertRaises(OSError):
                self._create_initial()
        prepared = self._contract_from_path(self._contract_files(1)[0])
        conflicting = replace(prepared, created_at="2099-01-01T00:00:00.000000Z")
        conflict_path = (
            self.run_directory
            / "authorization"
            / "contracts"
            / f"0001-{conflicting.digest()}.json"
        )
        conflict_path.write_text(
            json.dumps(
                conflicting.to_dict(),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        conflict_path.chmod(0o600)

        with self.assertRaises(StateCorruptionError):
            self._create_initial()

    def test_symlinked_authorization_directory_is_rejected(self) -> None:
        outside = self.root / "outside-authorization"
        outside.mkdir(mode=0o700)
        (self.run_directory / "authorization").symlink_to(
            outside,
            target_is_directory=True,
        )

        with self.assertRaises(StateCorruptionError):
            self.authorizations.current()

    def test_request_and_approve_scope_change_create_generation_and_resolution(
        self,
    ) -> None:
        contract = self._create_initial()

        request = self._request_change()

        self.assertEqual(self.store.load().phase, Phase.AWAITING_SCOPE_APPROVAL)
        self.assertEqual(self.authorizations.pending(), request)
        self.assertEqual(ScopeChangeRequest.from_dict(request.to_dict()), request)
        self.assertRegex(request.request_id, r"^[0-9a-f]{64}$")
        self.assertRegex(request.digest(), r"^[0-9a-f]{64}$")

        expanded = self.authorizations.resolve_change(
            decision="approve",
            actor="human-owner",
            expected_revision=self.store.load().revision,
        )

        self.assertEqual(expanded.generation, 2)
        self.assertEqual(expanded.manifest_sha256, "b" * 64)
        self.assertEqual(self.store.load().phase, Phase.PLANNING)
        self.assertIsNone(self.authorizations.pending())
        resolution = self.authorizations.latest_resolution()
        assert resolution is not None
        self.assertEqual(resolution.decision, "approve")
        self.assertEqual(resolution.actor, "human-owner")
        self.assertEqual(
            ScopeChangeResolution.from_dict(resolution.to_dict()),
            resolution,
        )
        self.assertEqual(resolution.previous_contract_digest, contract.digest())
        self.assertEqual(resolution.resulting_contract_digest, expanded.digest())
        resolution_path = (
            self.run_directory
            / "authorization"
            / "resolutions"
            / f"{request.request_id}-{resolution.resolution_id}.json"
        )
        self.assertTrue(resolution_path.is_file())
        self.assertEqual(stat.S_IMODE(resolution_path.stat().st_mode), 0o600)

    def test_approval_recovers_prepared_generation_before_pointer(self) -> None:
        initial = self._create_initial()
        self._request_change()
        awaiting_revision = self.store.load().revision
        with mock.patch.object(
            self.authorizations,
            "_write_current",
            side_effect=OSError("simulated crash before current pointer"),
        ):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                self.authorizations.resolve_change(
                    decision="approve",
                    actor="human-owner",
                    expected_revision=awaiting_revision,
                )

        prepared_files = self._contract_files(2)
        self.assertEqual(len(prepared_files), 1)
        prepared = self._contract_from_path(prepared_files[0])
        self.assertEqual(self.authorizations.current(), initial)

        recovered = self.authorizations.resolve_change(
            decision="approve",
            actor="human-owner",
            expected_revision=awaiting_revision,
        )

        self.assertEqual(recovered, prepared)
        self.assertEqual(self._contract_files(2), prepared_files)
        self.assertEqual(self.authorizations.current(), prepared)

    def test_reject_scope_change_retains_initial_generation(self) -> None:
        contract = self._create_initial()
        self._request_change(proposed_goal="ship an expanded goal")

        retained = self.authorizations.resolve_change(
            decision="reject",
            actor="human-owner",
            expected_revision=self.store.load().revision,
        )

        self.assertEqual(retained, contract)
        self.assertEqual(retained.generation, 1)
        self.assertEqual(self.authorizations.current(), contract)
        self.assertIsNone(self.authorizations.pending())
        self.assertEqual(self.store.load().phase, Phase.PLANNING)
        resolution = self.authorizations.latest_resolution()
        assert resolution is not None
        self.assertEqual(resolution.decision, "reject")
        self.assertEqual(
            resolution.resulting_contract_digest,
            contract.digest(),
        )

    def test_resolved_request_is_retained_in_private_immutable_archive(self) -> None:
        self._create_initial()
        request = self._request_change(proposed_goal="ship an expanded goal")
        archive_path = self._request_archive_path(request)

        self.assertTrue(archive_path.is_file())
        self.assertEqual(stat.S_IMODE(archive_path.stat().st_mode), 0o600)
        self.authorizations.resolve_change(
            decision="reject",
            actor="human-owner",
            expected_revision=self.store.load().revision,
        )

        self.assertTrue(archive_path.is_file())
        self.assertEqual(
            ScopeChangeRequest.from_dict(
                json.loads(archive_path.read_text(encoding="utf-8"))
            ),
            request,
        )

    def test_resolution_rejects_request_archive_changed_after_pending_write(
        self,
    ) -> None:
        self._create_initial()
        request = self._request_change()
        archive_path = self._request_archive_path(request)
        archive_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        changed = request.to_dict()
        changed["summary"] = "changed after pending publication"
        archive_path.write_text(
            json.dumps(changed, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        archive_path.chmod(0o600)

        with self.assertRaises(StateCorruptionError):
            self.authorizations.resolve_change(
                decision="approve",
                actor="human-owner",
                expected_revision=self.store.load().revision,
            )

    def test_request_rejects_stale_revision_without_creating_pending_state(
        self,
    ) -> None:
        self._create_initial()

        with self.assertRaises(StaleRevisionError):
            self._request_change(expected_revision=self.state.revision + 1)

        self.assertIsNone(self.authorizations.pending())
        self.assertEqual(self.store.load(), self.state)

    def test_request_removes_its_pending_pointer_when_final_cas_is_stale(
        self,
    ) -> None:
        self._create_initial()
        real_transition = self.store.transition

        def advance_revision_before_scope_transition(
            next_phase: Phase | str,
            *,
            expected_revision: int,
        ) -> object:
            real_transition(Phase.BLOCKED, expected_revision=expected_revision)
            return real_transition(next_phase, expected_revision=expected_revision)

        with mock.patch.object(
            self.store,
            "transition",
            side_effect=advance_revision_before_scope_transition,
        ):
            with self.assertRaises(StaleRevisionError):
                self._request_change(expected_revision=self.state.revision)

        self.assertEqual(len(self._request_archive_files()), 1)
        self.assertFalse(self.authorizations.pending_path.exists())
        self.assertIsNone(self.authorizations.pending())
        self.assertEqual(self.store.load().phase, Phase.BLOCKED)

    def test_stale_cas_cleanup_does_not_remove_another_pending_request(
        self,
    ) -> None:
        self._create_initial()
        real_transition = self.store.transition
        replacement: ScopeChangeRequest | None = None

        def replace_pending_and_advance_revision(
            next_phase: Phase | str,
            *,
            expected_revision: int,
        ) -> object:
            nonlocal replacement
            published = ScopeChangeRequest.from_dict(
                json.loads(self.authorizations.pending_path.read_text(encoding="utf-8"))
            )
            replacement = self._request_with_identity(
                published,
                summary="another request replaced the pending pointer",
            )
            authorization_module._atomic_write_private_json(
                self._request_archive_path(replacement),
                replacement.to_dict(),
                trusted_root=self.store.trusted_root,
                immutable=True,
            )
            authorization_module._atomic_write_private_json(
                self.authorizations.pending_path,
                replacement.to_dict(),
                trusted_root=self.store.trusted_root,
            )
            real_transition(Phase.BLOCKED, expected_revision=expected_revision)
            return real_transition(next_phase, expected_revision=expected_revision)

        with mock.patch.object(
            self.store,
            "transition",
            side_effect=replace_pending_and_advance_revision,
        ):
            with self.assertRaises(StaleRevisionError):
                self._request_change(expected_revision=self.state.revision)

        assert replacement is not None
        self.assertEqual(self.authorizations.pending(), replacement)

    def test_restart_reconciles_orphan_pending_and_allows_new_request(
        self,
    ) -> None:
        orphan = self._leave_orphan_pending_after_interrupted_stale_cas()
        orphan_archive = self._request_archive_path(orphan)
        restarted_store = StateStore(self.run_directory)
        restarted = AuthorizationStore(restarted_store)
        contract = restarted.current()
        assert contract is not None

        request = restarted.request_change(
            reason="goal_expansion",
            summary="publish a valid request after restart",
            proposed_goal="ship the requested repository change safely",
            proposed_manifest_sha256="c" * 64,
            proposed_release_target=contract.release_target,
            proposed_previous_release=contract.previous_release,
            expected_revision=restarted_store.load().revision,
        )

        self.assertNotEqual(request.request_id, orphan.request_id)
        self.assertTrue(orphan_archive.is_file())
        self.assertEqual(restarted.pending(), request)
        self.assertEqual(
            restarted_store.load().phase,
            Phase.AWAITING_SCOPE_APPROVAL,
        )

    def test_restart_preserves_current_legitimate_scope_approval(self) -> None:
        self._create_initial()
        request = self._request_change()
        awaiting = self.store.load()
        restarted_store = StateStore(self.run_directory)
        restarted = AuthorizationStore(restarted_store)
        contract = restarted.current()
        assert contract is not None

        with self.assertRaises(ValueError):
            restarted.request_change(
                reason="goal_expansion",
                summary="do not replace the current approval",
                proposed_goal="ship a different scope",
                proposed_manifest_sha256="c" * 64,
                proposed_release_target=contract.release_target,
                proposed_previous_release=contract.previous_release,
                expected_revision=awaiting.revision,
            )

        self.assertEqual(restarted.pending(), request)
        self.assertEqual(restarted_store.load(), awaiting)

    def test_restart_does_not_clear_orphan_with_missing_contract(self) -> None:
        orphan = self._leave_orphan_pending_after_interrupted_stale_cas()
        invalid = self._request_with_identity(
            orphan,
            contract_digest="d" * 64,
        )
        authorization_module._atomic_write_private_json(
            self._request_archive_path(invalid),
            invalid.to_dict(),
            trusted_root=self.store.trusted_root,
            immutable=True,
        )
        authorization_module._atomic_write_private_json(
            self.authorizations.pending_path,
            invalid.to_dict(),
            trusted_root=self.store.trusted_root,
        )
        restarted_store = StateStore(self.run_directory)
        restarted = AuthorizationStore(restarted_store)
        contract = restarted.current()
        assert contract is not None

        with self.assertRaises(StateCorruptionError):
            restarted.request_change(
                reason="goal_expansion",
                summary="do not hide the invalid contract reference",
                proposed_goal=contract.goal,
                proposed_manifest_sha256="c" * 64,
                proposed_release_target=contract.release_target,
                proposed_previous_release=contract.previous_release,
                expected_revision=restarted_store.load().revision,
            )

        self.assertEqual(restarted.pending(), invalid)

    def test_restart_orphan_cleanup_preserves_a_replacement_pending_request(
        self,
    ) -> None:
        orphan = self._leave_orphan_pending_after_interrupted_stale_cas()
        restarted_store = StateStore(self.run_directory)
        restarted = AuthorizationStore(restarted_store)
        state = restarted_store.load()
        contract = restarted.current()
        assert contract is not None
        real_remove = restarted._remove_pending_if_matches_locked
        replacement: ScopeChangeRequest | None = None

        def replace_before_removing(request: ScopeChangeRequest) -> None:
            nonlocal replacement
            replacement = self._request_with_identity(
                request,
                summary="a valid replacement pending request",
                proposed_manifest_sha256="c" * 64,
                gate_revision=state.revision,
            )
            authorization_module._atomic_write_private_json(
                self._request_archive_path(replacement),
                replacement.to_dict(),
                trusted_root=restarted_store.trusted_root,
                immutable=True,
            )
            authorization_module._atomic_write_private_json(
                restarted.pending_path,
                replacement.to_dict(),
                trusted_root=restarted_store.trusted_root,
            )
            real_remove(request)

        with mock.patch.object(
            restarted,
            "_remove_pending_if_matches_locked",
            side_effect=replace_before_removing,
        ):
            recovered = restarted.request_change(
                reason=orphan.reason,
                summary="a valid replacement pending request",
                proposed_goal=orphan.proposed_goal,
                proposed_manifest_sha256="c" * 64,
                proposed_release_target=orphan.proposed_release_target,
                proposed_previous_release=orphan.proposed_previous_release,
                expected_revision=state.revision,
            )

        assert replacement is not None
        self.assertEqual(recovered, replacement)
        self.assertEqual(restarted.pending(), replacement)
        self.assertTrue(self._request_archive_path(orphan).is_file())
        self.assertTrue(self._request_archive_path(replacement).is_file())

    def test_request_rejects_multiple_pending_changes(self) -> None:
        self._create_initial()
        request = self._request_change()

        with self.assertRaises(ValueError):
            self._request_change(
                reason="goal_expansion",
                summary="add a deployment dashboard",
                proposed_goal="ship the requested change and dashboard",
            )

        self.assertEqual(self.authorizations.pending(), request)

    def test_request_recovers_archive_written_before_pending_pointer(self) -> None:
        self._create_initial()
        real_write = authorization_module._atomic_write_private_json

        def fail_pending_write(
            path: Path,
            payload: object,
            **kwargs: object,
        ) -> None:
            if path == self.authorizations.pending_path:
                raise OSError("simulated crash before pending pointer")
            real_write(path, payload, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(
            authorization_module,
            "_atomic_write_private_json",
            side_effect=fail_pending_write,
        ):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                self._request_change()

        prepared_files = self._request_archive_files()
        self.assertEqual(len(prepared_files), 1)
        prepared = ScopeChangeRequest.from_dict(
            json.loads(prepared_files[0].read_text(encoding="utf-8"))
        )
        self.assertFalse(self.authorizations.pending_path.exists())
        self.assertEqual(self.store.load(), self.state)

        recovered = self._request_change()

        self.assertEqual(recovered, prepared)
        self.assertEqual(self._request_archive_files(), prepared_files)
        self.assertEqual(self.authorizations.pending(), prepared)

    def test_request_rejects_conflicting_prepared_archives(self) -> None:
        self._create_initial()
        real_write = authorization_module._atomic_write_private_json

        def fail_pending_write(
            path: Path,
            payload: object,
            **kwargs: object,
        ) -> None:
            if path == self.authorizations.pending_path:
                raise OSError("simulated crash before pending pointer")
            real_write(path, payload, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(
            authorization_module,
            "_atomic_write_private_json",
            side_effect=fail_pending_write,
        ):
            with self.assertRaises(OSError):
                self._request_change()
        prepared = ScopeChangeRequest.from_dict(
            json.loads(self._request_archive_files()[0].read_text(encoding="utf-8"))
        )
        conflicting = self._request_with_identity(
            prepared,
            summary="a conflicting proposal for the same gate",
        )
        conflict_path = self._request_archive_path(conflicting)
        conflict_path.write_text(
            json.dumps(
                conflicting.to_dict(),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        conflict_path.chmod(0o600)

        with self.assertRaises(StateCorruptionError):
            self._request_change()

        self.assertFalse(self.authorizations.pending_path.exists())
        self.assertEqual(self.store.load(), self.state)

    def test_blocked_request_writes_no_request_artifacts(self) -> None:
        self._create_initial()
        blocked = self.store.transition(
            Phase.BLOCKED,
            expected_revision=self.state.revision,
        )

        with self.assertRaises(InvalidTransitionError):
            self._request_change()

        self.assertEqual(self._request_archive_files(), [])
        self.assertFalse(self.authorizations.pending_path.exists())
        self.assertEqual(self.store.load(), blocked)

    def test_request_rejects_invalid_digest_and_empty_reason(self) -> None:
        self._create_initial()

        with self.assertRaises(ValueError):
            self._request_change(proposed_manifest_sha256="not-a-sha256")
        with self.assertRaises(ValueError):
            self._request_change(reason="   ")

        self.assertIsNone(self.authorizations.pending())
        self.assertEqual(self.store.load(), self.state)

    def test_changed_pending_request_digest_is_rejected(self) -> None:
        self._create_initial()
        self._request_change()
        pending_path = (
            self.run_directory / "authorization" / "pending-scope-change.json"
        )
        payload = json.loads(pending_path.read_text(encoding="utf-8"))
        payload["summary"] = "silently changed summary"
        pending_path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(StateCorruptionError):
            self.authorizations.pending()

    def test_resolution_rejects_stale_revision_and_invalid_decision(self) -> None:
        self._create_initial()
        request = self._request_change()
        awaiting = self.store.load()

        with self.assertRaises(StaleRevisionError):
            self.authorizations.resolve_change(
                decision="approve",
                actor="human-owner",
                expected_revision=awaiting.revision - 1,
            )
        with self.assertRaises(ValueError):
            self.authorizations.resolve_change(
                decision="maybe",
                actor="human-owner",
                expected_revision=awaiting.revision,
            )

        self.assertEqual(self.authorizations.pending(), request)
        self.assertEqual(self.store.load(), awaiting)

    def test_latest_resolution_rejects_a_foreign_run_record(self) -> None:
        self._create_initial()
        other_run_directory = self.root / "runs" / "run-other"
        other_repository = self.root / "repository-other"
        other_worktree = self.root / "worktree-other"
        other_repository.mkdir()
        other_worktree.mkdir()
        other_store = StateStore(other_run_directory)
        other_state = other_store.create("run-other")
        other_authorizations = AuthorizationStore(other_store)
        other_authorizations.create_initial(
            mode=ExecutionMode.AUTONOMOUS,
            goal="ship another run",
            repository=other_repository,
            worktree=other_worktree,
            branch="feat/other",
            manifest_sha256="c" * 64,
            release_target=None,
            previous_release=None,
            state_revision=other_state.revision,
        )
        other_contract = other_authorizations.current()
        assert other_contract is not None
        other_request = other_authorizations.request_change(
            reason="goal_expansion",
            summary="expand another run",
            proposed_goal="ship another expanded run",
            proposed_manifest_sha256=other_contract.manifest_sha256,
            proposed_release_target=None,
            proposed_previous_release=None,
            expected_revision=other_store.load().revision,
        )
        other_authorizations.resolve_change(
            decision="reject",
            actor="other-owner",
            expected_revision=other_store.load().revision,
        )
        other_resolution = other_authorizations.latest_resolution()
        assert other_resolution is not None
        source = (
            other_run_directory
            / "authorization"
            / "resolutions"
            / f"{other_request.request_id}-{other_resolution.resolution_id}.json"
        )
        target_directory = self.run_directory / "authorization" / "resolutions"
        target_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(source, target_directory / source.name)

        with self.assertRaises(StateCorruptionError):
            self.authorizations.latest_resolution()

    def test_latest_resolution_requires_its_archived_request(self) -> None:
        self._create_initial()
        request = self._request_change()
        self.authorizations.resolve_change(
            decision="reject",
            actor="human-owner",
            expected_revision=self.store.load().revision,
        )
        self._request_archive_path(request).unlink()

        with self.assertRaises(StateCorruptionError):
            self.authorizations.latest_resolution()

    def test_latest_resolution_requires_its_referenced_contract(self) -> None:
        contract = self._create_initial()
        self._request_change()
        self.authorizations.resolve_change(
            decision="reject",
            actor="human-owner",
            expected_revision=self.store.load().revision,
        )
        contract_path = self._contract_files(contract.generation)[0]
        contract_path.unlink()

        with self.assertRaises(StateCorruptionError):
            self.authorizations.latest_resolution()


if __name__ == "__main__":
    unittest.main()
