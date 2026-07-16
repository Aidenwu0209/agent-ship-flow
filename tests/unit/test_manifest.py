from __future__ import annotations

import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from ship_flow.manifest import (
    CommandSpec,
    Manifest,
    OperationSpec,
    detect_manifest,
    load_manifest,
    manifest_digest,
    write_manifest,
)


def _verification_command() -> CommandSpec:
    return CommandSpec(
        name="unit",
        category="unit",
        argv=("python3", "-m", "unittest"),
        timeout_seconds=120,
    )


def _valid_manifest(**changes: object) -> Manifest:
    values: dict[str, object] = {
        "project_name": "example",
        "base_branch": "main",
        "remote": "origin",
        "verification_steps": (_verification_command(),),
        "release_required": False,
    }
    values.update(changes)
    return Manifest(**values)


class ProjectDetectionTests(unittest.TestCase):
    def test_detects_node_python_go_rust_and_unknown_projects(self) -> None:
        cases = (
            (
                "node",
                "package.json",
                '{"scripts":{"test":"node --test"}}',
                ("npm", "test"),
            ),
            (
                "python",
                "pyproject.toml",
                "[project]\nname='sample'\n",
                ("python3", "-m", "unittest", "discover", "-s", "tests", "-v"),
            ),
            (
                "go",
                "go.mod",
                "module example.invalid/sample\n",
                ("go", "test", "./..."),
            ),
            ("rust", "Cargo.toml", "[package]\nname='sample'\n", ("cargo", "test")),
            ("unknown", None, None, ("git", "diff", "--check")),
        )
        for label, marker, contents, expected_argv in cases:
            with (
                self.subTest(project=label),
                tempfile.TemporaryDirectory() as directory,
            ):
                repository = Path(directory) / label
                repository.mkdir()
                if marker is not None:
                    (repository / marker).write_text(contents or "", encoding="utf-8")

                manifest = detect_manifest(repository)

                self.assertEqual(manifest.project_name, label)
                self.assertEqual(manifest.verification_steps[0].argv, expected_argv)
                self.assertFalse(manifest.release_required)


class ManifestModelTests(unittest.TestCase):
    def test_models_are_immutable(self) -> None:
        command = _verification_command()
        manifest = _valid_manifest()

        with self.assertRaises(FrozenInstanceError):
            command.name = "changed"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            manifest.remote = "upstream"  # type: ignore[misc]

    def test_release_required_false_is_valid(self) -> None:
        manifest = _valid_manifest(release_required=False)

        self.assertFalse(manifest.release_required)
        self.assertEqual(manifest.release_steps, ())

    def test_release_required_true_requires_a_release_step(self) -> None:
        with self.assertRaisesRegex(ValueError, "release.*step"):
            _valid_manifest(release_required=True, release_steps=())

    def test_manifest_version_rejects_bool_and_float(self) -> None:
        for version in (True, 1.0):
            with (
                self.subTest(version=version),
                self.assertRaisesRegex(ValueError, "version"),
            ):
                _valid_manifest(version=version)

    def test_release_readiness_requires_a_verification_command(self) -> None:
        with self.assertRaisesRegex(ValueError, "verification"):
            _valid_manifest(verification_steps=())

    def test_command_runner_fields_have_safe_defaults(self) -> None:
        command = CommandSpec(name="unit", argv=("python3", "-m", "unittest"))

        self.assertEqual(command.cwd, ".")
        self.assertEqual(command.env_allowlist, ())
        self.assertEqual(command.max_log_bytes, 1_048_576)
        self.assertFalse(command.shell_approved)

    def test_command_runner_fields_reject_wrong_types_and_values(self) -> None:
        invalid_fields = (
            ("cwd", "", "cwd"),
            ("cwd", 7, "cwd"),
            ("cwd", "bad\x00path", "cwd"),
            ("env_allowlist", "PATH", "env_allowlist"),
            ("env_allowlist", ("PATH", 7), "env_allowlist"),
            ("env_allowlist", ("",), "env_allowlist"),
            ("max_log_bytes", True, "max_log_bytes"),
            ("max_log_bytes", 0, "max_log_bytes"),
            ("max_log_bytes", 1.5, "max_log_bytes"),
            ("shell_approved", 1, "shell_approved"),
            ("shell_approved", "true", "shell_approved"),
        )

        for field, value, message in invalid_fields:
            with (
                self.subTest(field=field, value=value),
                self.assertRaisesRegex(ValueError, message),
            ):
                CommandSpec(
                    name="unit",
                    argv=("python3", "-m", "unittest"),
                    **{field: value},
                )

    def test_rejects_unknown_placeholder_in_any_argv_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "placeholder"):
            CommandSpec(name="bad", argv=("tool", "${unknown}"))

        with self.assertRaisesRegex(ValueError, "placeholder"):
            OperationSpec(
                name="push",
                kind="push",
                target="${remote}",
                argv=("git", "push", "${remote}", "${candidate}"),
                effect="external_write",
                idempotency="safe",
            )

    def test_allows_only_documented_placeholders(self) -> None:
        operation = OperationSpec(
            name="push",
            kind="push",
            target="${remote}",
            argv=(
                "tool",
                "${repo}",
                "${worktree}",
                "${branch}",
                "${base_branch}",
                "${remote}",
            ),
            effect="external_write",
            idempotency="probe",
            probe_argv=("tool", "probe", "${remote}", "${branch}"),
        )

        self.assertEqual(operation.target, "${remote}")

    def test_external_write_and_destructive_operations_require_idempotency(
        self,
    ) -> None:
        for effect in ("external_write", "destructive"):
            with (
                self.subTest(effect=effect),
                self.assertRaisesRegex(ValueError, "idempotency"),
            ):
                OperationSpec(
                    name="mutate",
                    kind="deploy",
                    target="production",
                    argv=("deploy",),
                    effect=effect,
                )

    def test_rejects_misspelled_or_unknown_effects(self) -> None:
        for effect in ("externl_write", "mystery"):
            with (
                self.subTest(effect=effect),
                self.assertRaisesRegex(ValueError, "effect"),
            ):
                OperationSpec(
                    name="mutate",
                    kind="deploy",
                    target="production",
                    argv=("deploy",),
                    effect=effect,
                )

    def test_probe_idempotency_requires_probe_argv(self) -> None:
        with self.assertRaisesRegex(ValueError, "probe_argv"):
            OperationSpec(
                name="push",
                kind="push",
                target="${remote}",
                argv=("git", "push", "${remote}", "${branch}"),
                effect="external_write",
                idempotency="probe",
            )

    def test_manual_reconcile_is_explicitly_recoverable_without_a_probe(self) -> None:
        operation = OperationSpec(
            name="deploy",
            kind="deploy",
            target="production",
            argv=("deploy-command",),
            effect="external_write",
            idempotency="manual_reconcile",
        )

        self.assertEqual(operation.idempotency, "manual_reconcile")
        self.assertEqual(operation.probe_argv, ())

    def test_deploy_requires_at_least_one_release_healthcheck(self) -> None:
        deploy = OperationSpec(
            name="deploy",
            kind="deploy",
            target="production",
            argv=("deploy-command",),
            effect="external_write",
            idempotency="manual_reconcile",
        )

        with self.assertRaisesRegex(ValueError, "healthcheck"):
            _valid_manifest(release_required=True, release_steps=(deploy,))

    def test_rejects_noncanonical_rollback_kind(self) -> None:
        rollback = OperationSpec(
            name="rollback-release",
            kind="rollback",
            target="production",
            argv=("rollback-command",),
            effect="external_write",
            idempotency="manual_reconcile",
            data_impact="possible",
        )

        with self.assertRaisesRegex(ValueError, "rollback.*kind"):
            _valid_manifest(rollback_steps=(rollback,))


class ManifestTomlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.path = Path(self.temporary_directory.name) / ".ship" / "manifest.toml"

    def test_toml_round_trip_preserves_the_immutable_manifest(self) -> None:
        deploy = OperationSpec(
            name="deploy",
            kind="deploy",
            target="production",
            argv=("deploy-command", "${branch}"),
            effect="external_write",
            idempotency="manual_reconcile",
            timeout_seconds=1800,
        )
        healthcheck = CommandSpec(
            name="production-smoke",
            argv=("curl", "-fsS", "https://example.invalid/health"),
            timeout_seconds=60,
        )
        manifest = _valid_manifest(
            development_setup=(
                CommandSpec(name="install", argv=("npm", "ci"), timeout_seconds=900),
            ),
            release_required=True,
            release_steps=(deploy,),
            release_healthchecks=(healthcheck,),
        )

        write_manifest(self.path, manifest)

        self.assertEqual(load_manifest(self.path), manifest)

    def test_command_runner_fields_round_trip_and_change_digest(self) -> None:
        command = CommandSpec(
            name="unit",
            category="unit",
            argv=("python3", "-m", "unittest"),
            timeout_seconds=120,
            cwd="packages/service",
            env_allowlist=("PATH", "HOME"),
            max_log_bytes=65_536,
            shell_approved=True,
        )
        manifest = _valid_manifest(verification_steps=(command,))
        default_manifest = _valid_manifest()

        write_manifest(self.path, manifest)

        loaded = load_manifest(self.path)
        self.assertEqual(loaded, manifest)
        self.assertNotEqual(manifest_digest(loaded), manifest_digest(default_manifest))

    def test_writer_rejects_a_corrupted_boolean_version(self) -> None:
        manifest = _valid_manifest()
        object.__setattr__(manifest, "version", True)

        with self.assertRaisesRegex(ValueError, "version"):
            write_manifest(self.path, manifest)

        self.assertFalse(self.path.exists())

    def test_default_rollback_kind_round_trips_canonically(self) -> None:
        rollback = OperationSpec(
            name="rollback-release",
            target="production",
            argv=("rollback-command",),
            effect="external_write",
            idempotency="manual_reconcile",
            data_impact="possible",
        )
        manifest = _valid_manifest(rollback_steps=(rollback,))

        write_manifest(self.path, manifest)

        self.assertEqual(load_manifest(self.path), manifest)

    def test_non_verification_category_round_trips(self) -> None:
        setup = CommandSpec(
            name="install",
            category="setup",
            argv=("npm", "ci"),
        )
        manifest = _valid_manifest(development_setup=(setup,))

        write_manifest(self.path, manifest)

        self.assertEqual(load_manifest(self.path), manifest)

    def test_non_verification_category_changes_digest(self) -> None:
        categorized = _valid_manifest(
            development_setup=(
                CommandSpec(
                    name="install",
                    category="setup",
                    argv=("npm", "ci"),
                ),
            )
        )
        uncategorized = _valid_manifest(
            development_setup=(CommandSpec(name="install", argv=("npm", "ci")),)
        )

        self.assertNotEqual(
            manifest_digest(categorized), manifest_digest(uncategorized)
        )

    def test_rejects_a_string_command_instead_of_an_argv_array(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_text(
            """
version = 1
[project]
name = "example"
base_branch = "main"
remote = "origin"
[release]
required = false
[[verification.steps]]
name = "unit"
category = "unit"
argv = "python3 -m unittest"
timeout_seconds = 120
""".strip()
            + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "argv.*array"):
            load_manifest(self.path)

    def test_strict_parser_rejects_unknown_fields(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_text(
            """
version = 1
surprise = true
[project]
name = "example"
base_branch = "main"
remote = "origin"
[release]
required = false
[[verification.steps]]
name = "unit"
category = "unit"
argv = ["python3", "-m", "unittest"]
timeout_seconds = 120
""".strip()
            + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "unexpected"):
            load_manifest(self.path)

    def test_digest_is_normalized_and_deterministic(self) -> None:
        manifest = _valid_manifest()
        first = manifest_digest(manifest)
        second = manifest_digest(manifest)
        other = _valid_manifest(remote="upstream")

        write_manifest(self.path, manifest)

        self.assertEqual(first, second)
        self.assertEqual(first, manifest_digest(load_manifest(self.path)))
        self.assertNotEqual(first, manifest_digest(other))
        self.assertEqual(len(first), 64)


if __name__ == "__main__":
    unittest.main()
