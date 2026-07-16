from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scripts.install_codex_skill as installer_module
from scripts.install_codex_skill import (
    InstallError,
    Installer,
    canonical_tree_digest,
    validate_pressure_receipt,
)


SCENARIO_IDS = (
    "SF-01-vague-request",
    "SF-02-self-verification",
    "SF-03-stale-review",
    "SF-04-verifier-repair",
    "SF-05-no-healthcheck",
    "SF-06-release-no-current-evidence",
    "SF-07-interrupted-external-write",
)


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_sha256(root: Path) -> str:
    entries: list[bytes] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or not path.is_file():
            if path.is_dir() and not path.is_symlink():
                continue
            raise AssertionError(f"unexpected fixture path: {path}")
        payload = path.read_bytes()
        entries.append(
            relative.encode("utf-8")
            + b"\0"
            + str(len(payload)).encode("ascii")
            + b"\0"
            + hashlib.sha256(payload).hexdigest().encode("ascii")
            + b"\n"
        )
    return hashlib.sha256(b"".join(entries)).hexdigest()


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.codex_home = root / "codex-home"
        self.skill = root / "skills" / "ship-flow"
        self.engine = root / "src" / "ship_flow"
        self.pressure = root / "tests" / "skill" / "pressure-scenarios.md"
        self.receipt = root / "tests" / "skill" / "validation-receipt.json"
        (self.skill / "agents").mkdir(parents=True)
        (self.skill / "references").mkdir()
        self.engine.mkdir(parents=True)
        self.pressure.parent.mkdir(parents=True)
        (self.skill / "SKILL.md").write_text(
            '---\nname: "ship-flow"\n'
            'description: "Use when shipping safely."\n---\n# Ship Flow\n',
            encoding="utf-8",
        )
        (self.skill / "agents" / "openai.yaml").write_text(
            'interface:\n  display_name: "Ship Flow"\n', encoding="utf-8"
        )
        (self.skill / "references" / "workflow.md").write_text(
            "# Workflow\n", encoding="utf-8"
        )
        (self.engine / "__init__.py").write_text("", encoding="utf-8")
        (self.engine / "__main__.py").write_text(
            "def main():\n    print('fixture ship help')\n    return 0\n",
            encoding="utf-8",
        )
        self.pressure.write_text("# pressure v1\n", encoding="utf-8")
        self.write_receipt()

    def write_receipt(
        self,
        *,
        skill_sha256: str | None = None,
        pressure_sha256: str | None = None,
        fail_with_skill: str | None = None,
    ) -> None:
        transcript_root = self.receipt.parent / "transcripts"
        scenarios = []
        for index, scenario_id in enumerate(SCENARIO_IDS):
            row: dict[str, object] = {"scenario_id": scenario_id}
            for variant in ("baseline", "with_skill"):
                directory = transcript_root / variant
                directory.mkdir(parents=True, exist_ok=True)
                transcript = directory / f"{scenario_id}.json"
                response = (
                    "unsafe direct deploy"
                    if variant == "baseline" and index == 4
                    else f"safe response {scenario_id} {variant}"
                )
                runner_id = f"runner-{variant}-{index}"
                transcript.write_text(
                    json.dumps(
                        {
                            "scenario_id": scenario_id,
                            "runner_id": runner_id,
                            "prompt": f"prompt {scenario_id} {variant}",
                            "response": response,
                        },
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
                passed = not (variant == "baseline" and index == 4)
                if variant == "with_skill" and scenario_id == fail_with_skill:
                    passed = False
                result: dict[str, object] = {
                    "runner_id": runner_id,
                    "transcript": transcript.relative_to(
                        self.receipt.parent
                    ).as_posix(),
                    "transcript_sha256": _file_sha256(transcript),
                    "passed": passed,
                }
                if not passed:
                    result["unsafe_rationalization"] = (
                        "unsafe direct deploy"
                        if "unsafe direct deploy" in response
                        else "safe response"
                    )
                row[variant] = result
            scenarios.append(row)
        payload = {
            "schema_version": 1,
            "generated_at": "2026-07-16T00:00:00Z",
            "skill_sha256": skill_sha256 or _tree_sha256(self.skill),
            "pressure_spec_sha256": pressure_sha256 or _file_sha256(self.pressure),
            "scenarios": scenarios,
        }
        self.receipt.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def installer(self, **kwargs: object) -> Installer:
        return Installer(
            project_root=self.root,
            codex_home=self.codex_home,
            preflight=lambda: None,
            **kwargs,
        )


class ReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_canonical_tree_digest_matches_independent_manifest(self) -> None:
        self.assertEqual(
            _tree_sha256(self.fixture.skill), canonical_tree_digest(self.fixture.skill)
        )

    def test_missing_receipt_is_rejected(self) -> None:
        self.fixture.receipt.unlink()
        with self.assertRaises(InstallError):
            self.fixture.installer().install()
        self.assertFalse(self.fixture.codex_home.exists())

    def test_wrong_skill_or_pressure_hash_is_rejected(self) -> None:
        for field in ("skill", "pressure"):
            with self.subTest(field=field):
                self.fixture.write_receipt(
                    skill_sha256="0" * 64 if field == "skill" else None,
                    pressure_sha256="0" * 64 if field == "pressure" else None,
                )
                with self.assertRaises(InstallError):
                    validate_pressure_receipt(
                        self.fixture.receipt,
                        skill_source=self.fixture.skill,
                        pressure_spec=self.fixture.pressure,
                    )
        self.assertFalse(self.fixture.codex_home.exists())

    def test_failed_with_skill_result_is_rejected(self) -> None:
        self.fixture.write_receipt(fail_with_skill=SCENARIO_IDS[0])
        with self.assertRaises(InstallError):
            self.fixture.installer().install()
        self.assertFalse(self.fixture.codex_home.exists())

    def test_duplicate_runner_or_non_substring_rationalization_is_rejected(
        self,
    ) -> None:
        payload = json.loads(self.fixture.receipt.read_text(encoding="utf-8"))
        payload["scenarios"][1]["baseline"]["runner_id"] = payload["scenarios"][0][
            "baseline"
        ]["runner_id"]
        self.fixture.receipt.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(InstallError):
            self.fixture.installer().install()

    def test_canonical_agent_runner_ids_are_accepted(self) -> None:
        payload = json.loads(self.fixture.receipt.read_text(encoding="utf-8"))
        for index, row in enumerate(payload["scenarios"]):
            for variant in ("baseline", "with_skill"):
                result = row[variant]
                runner_id = f"/root/sf{index + 1:02d}_{variant}"
                result["runner_id"] = runner_id
                transcript = self.fixture.receipt.parent / result["transcript"]
                transcript_payload = json.loads(transcript.read_text(encoding="utf-8"))
                transcript_payload["runner_id"] = runner_id
                transcript.write_text(
                    json.dumps(transcript_payload),
                    encoding="utf-8",
                )
                result["transcript_sha256"] = _file_sha256(transcript)
        self.fixture.receipt.write_text(json.dumps(payload), encoding="utf-8")
        validated = validate_pressure_receipt(
            self.fixture.receipt,
            skill_source=self.fixture.skill,
            pressure_spec=self.fixture.pressure,
        )
        self.assertEqual(_tree_sha256(self.fixture.skill), validated.skill_sha256)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        raw = self.fixture.receipt.read_text(encoding="utf-8")
        self.fixture.receipt.write_text(
            raw.replace(
                '"schema_version": 1,',
                '"schema_version": 1, "schema_version": 1,',
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaises(InstallError):
            validate_pressure_receipt(
                self.fixture.receipt,
                skill_source=self.fixture.skill,
                pressure_spec=self.fixture.pressure,
            )

    def test_transcripts_are_unique(self) -> None:
        payload = json.loads(self.fixture.receipt.read_text(encoding="utf-8"))
        source = payload["scenarios"][0]["baseline"]
        reused = payload["scenarios"][0]["with_skill"]
        reused["transcript"] = source["transcript"]
        reused["transcript_sha256"] = source["transcript_sha256"]
        self.fixture.receipt.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(InstallError, "transcripts must be distinct"):
            validate_pressure_receipt(
                self.fixture.receipt,
                skill_source=self.fixture.skill,
                pressure_spec=self.fixture.pressure,
            )

    def test_transcript_identity_is_bound_to_its_receipt_row(self) -> None:
        payload = json.loads(self.fixture.receipt.read_text(encoding="utf-8"))
        result = payload["scenarios"][0]["baseline"]
        transcript = self.fixture.receipt.parent / result["transcript"]
        transcript_payload = json.loads(transcript.read_text(encoding="utf-8"))
        transcript_payload["runner_id"] = "runner-someone-else"
        transcript.write_text(json.dumps(transcript_payload), encoding="utf-8")
        result["transcript_sha256"] = _file_sha256(transcript)
        self.fixture.receipt.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(InstallError, "runner identity does not match"):
            validate_pressure_receipt(
                self.fixture.receipt,
                skill_source=self.fixture.skill,
                pressure_spec=self.fixture.pressure,
            )

    def test_tree_digest_rejects_root_replacement_during_read(self) -> None:
        replacement = self.fixture.root / "replacement-skill"
        displaced = self.fixture.root / "displaced-skill"
        shutil.copytree(self.fixture.skill, replacement)
        original = installer_module._read_regular_file
        swapped = False

        def replace_root(path: Path, **kwargs: object) -> bytes:
            nonlocal swapped
            if not swapped and self.fixture.skill in path.parents:
                self.fixture.skill.rename(displaced)
                replacement.rename(self.fixture.skill)
                swapped = True
            return original(path, **kwargs)

        with mock.patch.object(
            installer_module,
            "_read_regular_file",
            side_effect=replace_root,
        ):
            with self.assertRaises(InstallError):
                canonical_tree_digest(self.fixture.skill)
        self.fixture.write_receipt()
        payload = json.loads(self.fixture.receipt.read_text(encoding="utf-8"))
        payload["scenarios"][4]["baseline"]["unsafe_rationalization"] = "not present"
        self.fixture.receipt.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(InstallError):
            self.fixture.installer().install()


class InstallationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_preflight_failure_has_zero_target_writes(self) -> None:
        def fail() -> None:
            raise InstallError("tests failed")

        installer = Installer(
            project_root=self.fixture.root,
            codex_home=self.fixture.codex_home,
            preflight=fail,
        )
        with self.assertRaises(InstallError):
            installer.install()
        self.assertFalse(self.fixture.codex_home.exists())

    def test_default_preflight_discovers_unit_and_integration_suites(self) -> None:
        installer = Installer(
            project_root=self.fixture.root,
            codex_home=self.fixture.codex_home,
        )
        completed = subprocess.CompletedProcess((), 0, stdout="tests passed")
        with mock.patch.object(
            installer_module.subprocess,
            "run",
            return_value=completed,
        ) as run:
            installer._default_preflight()
        commands = [call.args[0] for call in run.call_args_list]
        starts = [
            command[command.index("-s") + 1]
            for command in commands
            if "unittest" in command
        ]
        self.assertEqual(["tests/unit", "tests/integration"], starts)

    def test_launcher_accepts_an_interpreter_path_with_spaces(self) -> None:
        launcher = installer_module._launcher_bytes(
            Path("/private/tmp/agent ship/python"),
            codex_home=self.fixture.codex_home,
            skill_target=self.fixture.codex_home / "skills" / "ship-flow",
            engine_target=self.fixture.codex_home / "tools" / "ship-flow",
        )
        self.assertTrue(launcher.startswith(b"#!/bin/sh\n"))
        self.assertIn(b"'/private/tmp/agent ship/python'", launcher)
        self.assertIn(b' "$0" "$@"', launcher)

    def test_first_install_and_idempotent_reinstall(self) -> None:
        first = self.fixture.installer().install()
        self.assertTrue(first.changed)
        self.assertEqual(_tree_sha256(self.fixture.skill), first.skill_sha256)
        self.assertEqual(_tree_sha256(self.fixture.engine), first.engine_sha256)
        self.assertEqual(
            first.skill_sha256,
            canonical_tree_digest(self.fixture.codex_home / "skills" / "ship-flow"),
        )
        self.assertEqual(
            first.engine_sha256,
            canonical_tree_digest(
                self.fixture.codex_home / "tools" / "ship-flow" / "src" / "ship_flow"
            ),
        )
        launcher = self.fixture.codex_home / "tools" / "ship-flow" / "bin" / "ship"
        completed = subprocess.run(
            [str(launcher), "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("fixture ship help", completed.stdout)
        second = self.fixture.installer().install()
        self.assertFalse(second.changed)

    def test_unknown_or_modified_target_is_never_overwritten(self) -> None:
        unknown = self.fixture.codex_home / "skills" / "ship-flow"
        unknown.mkdir(parents=True)
        sentinel = unknown / "mine.txt"
        sentinel.write_text("keep", encoding="utf-8")
        with self.assertRaises(InstallError):
            self.fixture.installer().install()
        self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))

        self.temporary.cleanup()
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name))
        self.fixture.installer().install()
        installed = self.fixture.codex_home / "skills" / "ship-flow" / "SKILL.md"
        installed.write_text("locally modified", encoding="utf-8")
        with self.assertRaises(InstallError):
            self.fixture.installer().install()
        self.assertEqual("locally modified", installed.read_text(encoding="utf-8"))

    def test_known_update_replaces_both_bound_targets(self) -> None:
        before = self.fixture.installer().install()
        (self.fixture.skill / "SKILL.md").write_text(
            "updated skill\n", encoding="utf-8"
        )
        (self.fixture.engine / "__init__.py").write_text(
            "VERSION = 2\n", encoding="utf-8"
        )
        self.fixture.write_receipt()
        after = self.fixture.installer().install()
        self.assertTrue(after.changed)
        self.assertNotEqual(before.skill_sha256, after.skill_sha256)
        self.assertNotEqual(before.engine_sha256, after.engine_sha256)

    def test_custom_targets_are_bound_into_the_launcher(self) -> None:
        skill_target = self.fixture.codex_home / "custom-skills" / "ship-flow"
        engine_target = self.fixture.codex_home / "custom-tools" / "ship-flow"
        installer = Installer(
            project_root=self.fixture.root,
            codex_home=self.fixture.codex_home,
            skill_target=skill_target,
            engine_target=engine_target,
            preflight=lambda: None,
        )
        result = installer.install()
        completed = subprocess.run(
            [str(result.engine_target / "bin" / "ship"), "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_symlink_and_special_source_are_rejected(self) -> None:
        link = self.fixture.skill / "references" / "link"
        link.symlink_to(self.fixture.skill / "SKILL.md")
        with self.assertRaises(InstallError):
            self.fixture.installer().install()
        link.unlink()
        fifo = self.fixture.engine / "pipe"
        os.mkfifo(fifo)
        try:
            with self.assertRaises(InstallError):
                self.fixture.installer().install()
        finally:
            fifo.unlink()

    def test_pending_transaction_or_integrity_mismatch_blocks_launcher(self) -> None:
        self.fixture.installer().install()
        launcher = self.fixture.codex_home / "tools" / "ship-flow" / "bin" / "ship"
        journal = self.fixture.codex_home / ".ship-flow-install-journal.json"
        journal.write_text("{}\n", encoding="utf-8")
        blocked = subprocess.run(
            [str(launcher)], text=True, capture_output=True, check=False
        )
        self.assertNotEqual(0, blocked.returncode)
        self.assertIn("installation", blocked.stderr.lower())
        journal.unlink()
        (self.fixture.codex_home / "skills" / "ship-flow" / "SKILL.md").write_text(
            "tampered", encoding="utf-8"
        )
        blocked = subprocess.run(
            [str(launcher)], text=True, capture_output=True, check=False
        )
        self.assertNotEqual(0, blocked.returncode)
        self.assertIn("integrity", blocked.stderr.lower())

    def test_launcher_rejects_duplicate_bundle_keys(self) -> None:
        self.fixture.installer().install()
        engine = self.fixture.codex_home / "tools" / "ship-flow"
        bundle = engine / "bundle.json"
        raw = bundle.read_text(encoding="utf-8")
        bundle.write_text(
            raw.replace(
                '"installed_at":',
                '"installed_at":"2026-07-16T00:00:00Z","installed_at":',
                1,
            ),
            encoding="utf-8",
        )
        completed = subprocess.run(
            [str(engine / "bin" / "ship"), "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("metadata is invalid", completed.stderr)

    def test_launcher_rejects_malformed_bundle_schema(self) -> None:
        self.fixture.installer().install()
        engine = self.fixture.codex_home / "tools" / "ship-flow"
        bundle_path = engine / "bundle.json"
        original = json.loads(bundle_path.read_text(encoding="utf-8"))
        cases = (
            ("boolean version", "schema_version", True),
            ("non-string receipt digest", "receipt_sha256", 7),
            ("non-string Python", "python_executable", 7),
            ("invalid timestamp", "installed_at", "not-a-timestamp"),
        )
        for label, key, value in cases:
            with self.subTest(label=label):
                payload = dict(original)
                payload[key] = value
                bundle_path.write_text(json.dumps(payload), encoding="utf-8")
                completed = subprocess.run(
                    [str(engine / "bin" / "ship"), "--help"],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(0, completed.returncode)
                self.assertIn("metadata schema is invalid", completed.stderr)

    def test_crash_checkpoints_are_recovered_on_rerun(self) -> None:
        for checkpoint in (
            "STAGED",
            "ENGINE_PUBLISHED",
            "SKILL_PUBLISHED",
            "ACTIVATED",
        ):
            with self.subTest(checkpoint=checkpoint):
                self.temporary.cleanup()
                self.temporary = tempfile.TemporaryDirectory()
                self.fixture = Fixture(Path(self.temporary.name))

                def crash(value: str) -> None:
                    if value == checkpoint:
                        raise RuntimeError("injected crash")

                with self.assertRaises(RuntimeError):
                    self.fixture.installer(checkpoint=crash).install()
                recovered = self.fixture.installer().install()
                self.assertEqual(
                    recovered.skill_sha256,
                    canonical_tree_digest(
                        self.fixture.codex_home / "skills" / "ship-flow"
                    ),
                )
                self.assertFalse(
                    (
                        self.fixture.codex_home / ".ship-flow-install-journal.json"
                    ).exists()
                )

    def test_activated_recovery_revalidates_targets_before_cleanup(self) -> None:
        self.fixture.installer().install()
        (self.fixture.skill / "SKILL.md").write_text(
            "updated skill\n", encoding="utf-8"
        )
        (self.fixture.engine / "__init__.py").write_text(
            "VERSION = 2\n", encoding="utf-8"
        )
        self.fixture.write_receipt()

        def crash(status: str) -> None:
            if status == "ACTIVATED":
                raise RuntimeError("injected crash")

        with self.assertRaises(RuntimeError):
            self.fixture.installer(checkpoint=crash).install()
        journal = self.fixture.codex_home / ".ship-flow-install-journal.json"
        backups = list(self.fixture.codex_home.glob(".ship-flow-backup-*"))
        self.assertTrue(journal.exists())
        self.assertTrue(backups)
        engine = self.fixture.codex_home / "tools" / "ship-flow"
        shutil.rmtree(engine)

        with self.assertRaises(InstallError):
            self.fixture.installer().install()
        self.assertTrue(journal.exists())
        self.assertEqual(
            backups, list(self.fixture.codex_home.glob(".ship-flow-backup-*"))
        )

    def test_activated_recovery_preserves_a_replaced_install_backup(self) -> None:
        self.fixture.installer().install()
        (self.fixture.skill / "SKILL.md").write_text(
            "updated skill\n", encoding="utf-8"
        )
        self.fixture.write_receipt()

        def crash(status: str) -> None:
            if status == "ACTIVATED":
                raise RuntimeError("injected crash")

        with self.assertRaises(RuntimeError):
            self.fixture.installer(checkpoint=crash).install()
        journal = self.fixture.codex_home / ".ship-flow-install-journal.json"
        skill_backup = next(self.fixture.codex_home.glob(".ship-flow-backup-*-skill"))
        shutil.rmtree(skill_backup)
        skill_backup.mkdir()
        sentinel = skill_backup / "foreign.txt"
        sentinel.write_text("keep", encoding="utf-8")

        with self.assertRaisesRegex(InstallError, "backup changed before cleanup"):
            self.fixture.installer().install()
        self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))
        self.assertTrue(journal.exists())

    def test_activated_recovery_preserves_a_reappeared_stage_path(self) -> None:
        self.fixture.installer().install()
        (self.fixture.skill / "SKILL.md").write_text(
            "updated skill\n", encoding="utf-8"
        )
        self.fixture.write_receipt()

        def crash(status: str) -> None:
            if status == "ACTIVATED":
                raise RuntimeError("injected crash")

        with self.assertRaises(RuntimeError):
            self.fixture.installer(checkpoint=crash).install()
        journal_path = self.fixture.codex_home / ".ship-flow-install-journal.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        stage = Path(journal["stage_skill"])
        stage.mkdir()
        sentinel = stage / "foreign.txt"
        sentinel.write_text("keep", encoding="utf-8")

        with self.assertRaisesRegex(InstallError, "stage path reappeared"):
            self.fixture.installer().install()
        self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))
        self.assertTrue(journal_path.exists())

    def test_journal_versions_reject_booleans(self) -> None:
        for operation, checkpoint in (
            ("install", "STAGED"),
            ("uninstall", "UNINSTALL_STAGED"),
        ):
            with self.subTest(operation=operation):
                self.temporary.cleanup()
                self.temporary = tempfile.TemporaryDirectory()
                self.fixture = Fixture(Path(self.temporary.name))
                if operation == "uninstall":
                    self.fixture.installer().install()

                def crash(status: str) -> None:
                    if status == checkpoint:
                        raise RuntimeError("injected crash")

                installer = self.fixture.installer(checkpoint=crash)
                with self.assertRaises(RuntimeError):
                    (
                        installer.install()
                        if operation == "install"
                        else installer.uninstall()
                    )
                journal_path = (
                    self.fixture.codex_home / ".ship-flow-install-journal.json"
                )
                journal = json.loads(journal_path.read_text(encoding="utf-8"))
                journal["schema_version"] = True
                journal_path.write_text(json.dumps(journal), encoding="utf-8")
                with self.assertRaisesRegex(InstallError, "journal is unsupported"):
                    (
                        self.fixture.installer().install()
                        if operation == "install"
                        else self.fixture.installer().uninstall()
                    )
                self.assertTrue(journal_path.exists())

    def test_uninstall_removes_only_unchanged_owned_targets(self) -> None:
        installer = self.fixture.installer()
        installer.install()
        result = installer.uninstall()
        self.assertTrue(result.changed)
        self.assertFalse((self.fixture.codex_home / "skills" / "ship-flow").exists())

        installer.install()
        skill = self.fixture.codex_home / "skills" / "ship-flow" / "SKILL.md"
        skill.write_text("mine", encoding="utf-8")
        with self.assertRaises(InstallError):
            installer.uninstall()
        self.assertEqual("mine", skill.read_text(encoding="utf-8"))

    def test_uninstall_crash_checkpoints_are_recovered(self) -> None:
        for checkpoint in (
            "UNINSTALL_STAGED",
            "UNINSTALL_ENGINE_PUBLISHED",
            "UNINSTALL_SKILL_PUBLISHED",
        ):
            with self.subTest(checkpoint=checkpoint):
                self.temporary.cleanup()
                self.temporary = tempfile.TemporaryDirectory()
                self.fixture = Fixture(Path(self.temporary.name))
                self.fixture.installer().install()

                def crash(value: str) -> None:
                    if value == checkpoint:
                        raise RuntimeError("injected uninstall crash")

                with self.assertRaises(RuntimeError):
                    self.fixture.installer(checkpoint=crash).uninstall()
                recovered = self.fixture.installer().uninstall()
                self.assertTrue(recovered.changed)
                self.assertFalse(
                    (
                        self.fixture.codex_home / ".ship-flow-install-journal.json"
                    ).exists()
                )
                self.assertFalse(
                    (self.fixture.codex_home / "skills" / "ship-flow").exists()
                )
                self.assertFalse(
                    (self.fixture.codex_home / "tools" / "ship-flow").exists()
                )

    def test_uninstall_cleanup_preserves_a_replaced_foreign_backup(self) -> None:
        self.fixture.installer().install()

        def crash(status: str) -> None:
            if status == "UNINSTALL_SKILL_PUBLISHED":
                raise RuntimeError("injected uninstall crash")

        with self.assertRaises(RuntimeError):
            self.fixture.installer(checkpoint=crash).uninstall()
        skill_backup = next(
            self.fixture.codex_home.glob(".ship-flow-uninstall-*-skill")
        )
        journal = self.fixture.codex_home / ".ship-flow-install-journal.json"
        original_digest = installer_module.canonical_tree_digest
        foreign_backup = self.fixture.root / "foreign-skill-backup"
        foreign_backup.mkdir()
        (foreign_backup / "foreign.txt").write_text("keep", encoding="utf-8")
        swapped = False

        def replace_after_digest(path: Path) -> str:
            nonlocal swapped
            digest = original_digest(path)
            if Path(path) == skill_backup and not swapped:
                shutil.rmtree(skill_backup)
                foreign_backup.rename(skill_backup)
                swapped = True
            return digest

        with mock.patch.object(
            installer_module,
            "canonical_tree_digest",
            side_effect=replace_after_digest,
        ):
            with self.assertRaisesRegex(InstallError, "cleanup path was replaced"):
                self.fixture.installer().uninstall()
        self.assertEqual(
            "keep", (skill_backup / "foreign.txt").read_text(encoding="utf-8")
        )
        self.assertTrue(journal.exists())

    def test_codex_home_lock_cannot_manage_targets_from_another_home(self) -> None:
        other_home = self.fixture.root / "other-codex-home"
        with self.assertRaisesRegex(InstallError, "inside CODEX_HOME"):
            Installer(
                project_root=self.fixture.root,
                codex_home=other_home,
                skill_target=self.fixture.codex_home / "skills" / "ship-flow",
                engine_target=self.fixture.codex_home / "tools" / "ship-flow",
                preflight=lambda: None,
            )

    def test_target_permissions_are_private(self) -> None:
        self.fixture.installer().install()
        for path in (
            self.fixture.codex_home,
            self.fixture.codex_home / "skills" / "ship-flow",
            self.fixture.codex_home / "tools" / "ship-flow",
        ):
            self.assertEqual(0o700, stat.S_IMODE(path.stat().st_mode))


if __name__ == "__main__":
    unittest.main()
