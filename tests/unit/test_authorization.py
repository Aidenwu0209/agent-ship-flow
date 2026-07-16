from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from ship_flow.authorization import (
    AuthorizationContract,
    AuthorizationStore,
    ExecutionMode,
    ScopeChangeRequest,
    ScopeChangeResolution,
)
from ship_flow.model import Phase
from ship_flow.store import StateCorruptionError, StateStore, StaleRevisionError


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

    def test_request_rejects_stale_revision_without_creating_pending_state(
        self,
    ) -> None:
        self._create_initial()

        with self.assertRaises(StaleRevisionError):
            self._request_change(expected_revision=self.state.revision + 1)

        self.assertIsNone(self.authorizations.pending())
        self.assertEqual(self.store.load(), self.state)

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


if __name__ == "__main__":
    unittest.main()
