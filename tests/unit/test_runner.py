from __future__ import annotations

import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import ship_flow.runner as runner_module
from ship_flow.manifest import CommandSpec
from ship_flow.runner import CommandResult, CommandRunner, RunnerError


class RunnerImportTests(unittest.TestCase):
    def test_runner_interfaces_import(self) -> None:
        self.assertTrue(CommandRunner)
        self.assertTrue(CommandResult)


class CommandRunnerValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        root = Path(self.temporary_directory.name).resolve()
        self.worktree = root / "worktree"
        self.worktree.mkdir()
        self.log_dir = root / "runtime" / "logs"
        self.runner = CommandRunner()

    def run_spec(
        self,
        spec: CommandSpec,
        *,
        variables: dict[str, str] | None = None,
        sensitive_values: tuple[str, ...] = (),
    ) -> CommandResult:
        return self.runner.run(
            spec,
            variables=variables or {},
            worktree=self.worktree,
            log_dir=self.log_dir,
            sensitive_values=sensitive_values,
        )

    def test_expands_each_argv_token_without_interpreting_shell_metacharacters(
        self,
    ) -> None:
        self.log_dir.parent.mkdir(mode=0o750)
        os.chmod(self.log_dir.parent, 0o750)
        command_directory = self.worktree / "packages" / "service"
        command_directory.mkdir(parents=True)
        marker = self.worktree / "shell-was-used"
        script = (
            "import json, os, sys; "
            "print(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(), "
            "'allowed': os.environ.get('RUNNER_ALLOWED'), "
            "'hidden': os.environ.get('RUNNER_HIDDEN')}))"
        )
        spec = CommandSpec(
            name="literal-argv",
            argv=(
                sys.executable,
                "-c",
                script,
                "${branch}",
                "; touch ${worktree}/shell-was-used",
            ),
            cwd="packages/service",
            env_allowlist=("RUNNER_ALLOWED",),
        )

        with mock.patch.dict(
            os.environ,
            {"RUNNER_ALLOWED": "visible", "RUNNER_HIDDEN": "must-not-leak"},
        ):
            result = self.run_spec(
                spec,
                variables={"branch": "feat/safe", "worktree": str(self.worktree)},
            )

        payload = json.loads(result.log_path.read_text(encoding="utf-8"))
        self.assertEqual(
            payload["argv"],
            ["feat/safe", f"; touch {marker}"],
        )
        self.assertEqual(Path(payload["cwd"]), command_directory.resolve())
        self.assertEqual(payload["allowed"], "visible")
        self.assertIsNone(payload["hidden"])
        self.assertFalse(marker.exists())
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.truncated)
        persisted = result.log_path.read_bytes()
        self.assertEqual(result.log_size, len(persisted))
        self.assertEqual(result.log_sha256, hashlib.sha256(persisted).hexdigest())
        self.assertEqual(stat.S_IMODE(self.log_dir.parent.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE(self.log_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(result.log_path.stat().st_mode), 0o600)

    def test_rejects_cwd_escape_including_a_symlink(self) -> None:
        outside = Path(self.temporary_directory.name).resolve() / "outside"
        outside.mkdir()
        (self.worktree / "linked-outside").symlink_to(outside, target_is_directory=True)

        for cwd in ("../outside", "linked-outside"):
            with (
                self.subTest(cwd=cwd),
                self.assertRaisesRegex(RunnerError, "cwd.*worktree"),
            ):
                self.run_spec(
                    CommandSpec(name="escape", argv=(sys.executable, "-V"), cwd=cwd)
                )

    def test_rejects_empty_or_nul_argv_tokens(self) -> None:
        for argv in (("",), (sys.executable, "bad\x00token")):
            with self.subTest(argv=argv), self.assertRaisesRegex(RunnerError, "argv"):
                self.run_spec(CommandSpec(name="invalid-argv", argv=argv))

    def test_rejects_unapproved_shell_wrappers_and_allows_explicit_approval(
        self,
    ) -> None:
        shell_alias = self.worktree / "renamed-shell"
        shell_alias.symlink_to("/bin/sh")
        wrappers = (
            ("sh", "-c", "printf blocked"),
            ("/bin/bash", "-lc", "printf blocked"),
            ("zsh", "-c", "printf blocked"),
            ("/usr/bin/env", "sh", "-c", "printf blocked"),
            ("/usr/bin/env", "-u", "IGNORED", "sh", "-c", "printf blocked"),
            (
                "/usr/bin/env",
                "--unset",
                "IGNORED",
                "--",
                "sh",
                "-c",
                "printf blocked",
            ),
            (
                "/usr/bin/env",
                "-C",
                str(self.worktree),
                "sh",
                "-c",
                "printf blocked",
            ),
            (
                "/usr/bin/env",
                "--chdir",
                str(self.worktree),
                "sh",
                "-lc",
                "printf blocked",
            ),
            ("/usr/bin/env", "-S", "sh -c 'printf blocked'"),
            ("/usr/bin/env", "--split-string=sh -c 'printf blocked'"),
            ("/usr/bin/env", "--", "sh", "-c", "printf blocked"),
            ("/usr/bin/env", str(shell_alias), "-c", "printf blocked"),
            (
                "/usr/bin/env",
                "env",
                str(shell_alias),
                "-c",
                "printf blocked",
            ),
            (
                "/usr/bin/env",
                *("env",) * 9,
                sys.executable,
                "-V",
            ),
            (
                "/usr/bin/env",
                str(self.worktree / "missing-env-command"),
                "-c",
                "printf blocked",
            ),
            ("/bin/bash", "-O", "extglob", "-c", "printf blocked"),
            (str(shell_alias), "-c", "printf blocked"),
        )
        for argv in wrappers:
            with (
                self.subTest(argv=argv),
                self.assertRaisesRegex(RunnerError, "shell.*approval"),
            ):
                self.run_spec(CommandSpec(name="shell", argv=argv))

        result = self.run_spec(
            CommandSpec(
                name="approved-shell",
                argv=("/bin/sh", "-c", "printf approved"),
                shell_approved=True,
            )
        )
        self.assertEqual(result.log_path.read_bytes(), b"approved")

    def test_repeated_commands_do_not_overwrite_prior_evidence_logs(self) -> None:
        script = "import os; print(os.environ['RUN_VALUE'])"
        spec = CommandSpec(
            name="repeatable",
            argv=(sys.executable, "-c", script),
            env_allowlist=("RUN_VALUE",),
        )

        with mock.patch.dict(os.environ, {"RUN_VALUE": "first"}):
            first = self.run_spec(spec)
        with mock.patch.dict(os.environ, {"RUN_VALUE": "second"}):
            second = self.run_spec(spec)

        self.assertNotEqual(first.log_path, second.log_path)
        self.assertEqual(first.log_path.read_bytes(), b"first\n")
        self.assertEqual(second.log_path.read_bytes(), b"second\n")
        self.assertEqual(
            first.log_sha256,
            hashlib.sha256(first.log_path.read_bytes()).hexdigest(),
        )

    def test_rejects_symlinked_log_directory_ancestors_and_leaf(self) -> None:
        root = Path(self.temporary_directory.name).resolve()
        spec = CommandSpec(name="symlink-log", argv=(sys.executable, "-V"))

        for placement in ("ancestor", "leaf"):
            external = root / f"external-{placement}"
            external.mkdir()
            sentinel = external / "sentinel"
            sentinel.write_text("do not change", encoding="utf-8")
            if placement == "ancestor":
                link = root / "linked-runtime"
                link.symlink_to(external, target_is_directory=True)
                log_dir = link / "logs"
            else:
                log_dir = root / "linked-logs"
                log_dir.symlink_to(external, target_is_directory=True)

            with (
                self.subTest(placement=placement),
                self.assertRaisesRegex(RunnerError, "log directory"),
            ):
                self.runner.run(
                    spec,
                    variables={},
                    worktree=self.worktree,
                    log_dir=log_dir,
                    sensitive_values=(),
                )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "do not change")
            self.assertEqual(
                sorted(path.name for path in external.iterdir()), ["sentinel"]
            )

    def test_rejects_displaced_log_path_without_using_foreign_evidence(self) -> None:
        root = Path(self.temporary_directory.name).resolve()
        runtime = root / "race-runtime"
        log_dir = runtime / "logs"
        log_dir.mkdir(parents=True)
        pinned_log_dir = runtime / "opened-logs"
        external = root / "external-log-target"
        external.mkdir()
        sentinel = external / "sentinel"
        sentinel.write_text("do not change", encoding="utf-8")
        real_open = os.open
        swapped = False
        created_filename: str | None = None

        def replace_before_file_creation(
            path: str | bytes,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal created_filename, swapped
            if (
                not swapped
                and flags & os.O_CREAT
                and os.fsdecode(path).endswith(".log")
            ):
                created_filename = os.fsdecode(path)
                log_dir.rename(pinned_log_dir)
                log_dir.symlink_to(external, target_is_directory=True)
                swapped = True
                (external / created_filename).write_bytes(b"foreign evidence")
            if dir_fd is None:
                return real_open(path, flags, mode)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with (
            mock.patch.object(runner_module.os, "open", replace_before_file_creation),
            self.assertRaisesRegex(RunnerError, "evidence.*path"),
        ):
            self.runner.run(
                CommandSpec(
                    name="replace-log-dir",
                    argv=(sys.executable, "-c", "print('pinned log')"),
                ),
                variables={},
                worktree=self.worktree,
                log_dir=log_dir,
                sensitive_values=(),
            )

        self.assertTrue(swapped)
        self.assertIsNotNone(created_filename)
        assert created_filename is not None
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "do not change")
        self.assertEqual(
            (external / created_filename).read_bytes(),
            b"foreign evidence",
        )
        self.assertEqual(
            (pinned_log_dir / created_filename).read_bytes(),
            b"pinned log\n",
        )

    def test_cwd_fd_survives_replacement_before_process_launch(self) -> None:
        service = self.worktree / "service"
        service.mkdir()
        (service / "sentinel").write_text("original", encoding="utf-8")
        opened_service = self.worktree / "opened-service"
        external = Path(self.temporary_directory.name).resolve() / "external-cwd"
        external.mkdir()
        external_sentinel = external / "sentinel"
        external_sentinel.write_text("external", encoding="utf-8")
        real_popen = subprocess.Popen
        swapped = False

        def replace_before_spawn(*args, **kwargs):
            nonlocal swapped
            if not swapped:
                service.rename(opened_service)
                service.symlink_to(external, target_is_directory=True)
                swapped = True
            return real_popen(*args, **kwargs)

        script = (
            "from pathlib import Path; "
            "print(Path('sentinel').read_text()); "
            "Path('created-by-command').write_text('original only')"
        )
        with mock.patch.object(runner_module.subprocess, "Popen", replace_before_spawn):
            result = self.run_spec(
                CommandSpec(
                    name="pinned-cwd",
                    argv=(sys.executable, "-c", script),
                    cwd="service",
                )
            )

        self.assertTrue(swapped)
        self.assertEqual(result.log_path.read_bytes(), b"original\n")
        self.assertEqual(
            (opened_service / "created-by-command").read_text(encoding="utf-8"),
            "original only",
        )
        self.assertEqual(external_sentinel.read_text(encoding="utf-8"), "external")
        self.assertFalse((external / "created-by-command").exists())

    def test_rejects_a_duck_typed_command_spec(self) -> None:
        class FakeSpec:
            name = "fake"
            argv = (sys.executable, "-V")
            timeout_seconds = 1
            cwd = "."
            env_allowlist = ()
            max_log_bytes = 1024
            shell_approved = False

        with self.assertRaisesRegex(RunnerError, "CommandSpec"):
            self.runner.run(
                FakeSpec(),  # type: ignore[arg-type]
                variables={},
                worktree=self.worktree,
                log_dir=self.log_dir,
                sensitive_values=(),
            )

    def test_redacts_a_secret_split_across_merged_output_chunks_before_disk(
        self,
    ) -> None:
        secret = "TOKEN-cross-stream-secret"
        script = (
            "import os, time; "
            "os.write(1, b'prefix TOKEN-cross-'); "
            "time.sleep(0.05); "
            "os.write(2, b'stream-secret suffix\\n')"
        )
        result = self.run_spec(
            CommandSpec(name="redact", argv=(sys.executable, "-c", script)),
            sensitive_values=(secret,),
        )

        persisted = result.log_path.read_bytes()
        self.assertEqual(persisted, b"prefix \xff suffix\n")
        self.assertNotIn(secret.encode("utf-8"), persisted)
        self.assertEqual(list(self.log_dir.iterdir()), [result.log_path])
        self.assertEqual(result.log_size, len(persisted))
        self.assertEqual(result.log_sha256, hashlib.sha256(persisted).hexdigest())

    def test_binary_redaction_sentinel_cannot_recreate_utf8_secrets(self) -> None:
        secrets = (
            "foo",
            "[REDACTED]",
            "REDACTED",
            "X[REDACTED]Y",
            "aba",
            "bab",
            "TOKEN",
            "TOKEN-LONG",
        )
        payload = "[REDACTED]|XfooY|ababa|TOKEN-LONG|TOKEN|REDACTED"
        script = "import os, sys; os.write(1, sys.argv[1].encode('utf-8'))"

        result = self.run_spec(
            CommandSpec(
                name="marker-safe-redaction",
                argv=(sys.executable, "-c", script, payload),
            ),
            sensitive_values=secrets,
        )

        persisted = result.log_path.read_bytes()
        self.assertIn(b"\xff", persisted)
        for secret in secrets:
            with self.subTest(secret=secret):
                self.assertNotIn(secret.encode("utf-8"), persisted)

    def test_infinite_output_is_capped_while_the_process_is_drained(self) -> None:
        limit = 4096
        script = (
            "import os, time; "
            "chunk = b'x' * 1024; "
            "\nwhile True:\n os.write(1, chunk); time.sleep(0.001)"
        )
        result = self.run_spec(
            CommandSpec(
                name="bounded-output",
                argv=(sys.executable, "-c", script),
                timeout_seconds=1,
                max_log_bytes=limit,
            )
        )

        persisted = result.log_path.read_bytes()
        self.assertTrue(result.timed_out)
        self.assertTrue(result.truncated)
        self.assertEqual(len(persisted), limit)
        self.assertEqual(result.log_size, limit)
        self.assertEqual(result.log_sha256, hashlib.sha256(persisted).hexdigest())

    def test_timeout_terminates_and_kills_the_spawned_process_group(self) -> None:
        child_pid_path = self.worktree / "child.pid"
        child_script = (
            "import os, pathlib, signal, sys, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
            "time.sleep(60)"
        )
        parent_script = (
            "import signal, subprocess, sys, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]); "
            "time.sleep(60)"
        )

        result = self.run_spec(
            CommandSpec(
                name="timeout-group",
                argv=(
                    sys.executable,
                    "-c",
                    parent_script,
                    child_script,
                    str(child_pid_path),
                ),
                timeout_seconds=1,
            )
        )

        self.assertTrue(result.timed_out)
        self.assertEqual(result.exit_code, -signal.SIGKILL)
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            self.fail("timeout left a descendant process alive")

    def test_log_write_failure_reaps_the_entire_process_group(self) -> None:
        parent_pid_path = self.worktree / "failing-parent.pid"
        child_pid_path = self.worktree / "failing-child.pid"
        child_script = (
            "import os, pathlib, signal, sys, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
            "time.sleep(60)"
        )
        parent_script = (
            "import os, pathlib, signal, subprocess, sys, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
            "subprocess.Popen([sys.executable, '-c', sys.argv[3], sys.argv[2]]); "
            "child = pathlib.Path(sys.argv[2]); "
            "\nwhile not child.exists(): time.sleep(0.01)\n"
            "print('trigger log failure', flush=True); "
            "time.sleep(60)"
        )
        real_write = runner_module._BoundedLog.write
        injected = False

        def fail_first_log_write(log, contents: bytes) -> None:
            nonlocal injected
            if contents and not injected:
                injected = True
                raise OSError("injected log write failure")
            real_write(log, contents)

        parent_pid: int | None = None
        try:
            with (
                mock.patch.object(
                    runner_module._BoundedLog,
                    "write",
                    fail_first_log_write,
                ),
                self.assertRaisesRegex(OSError, "injected log write failure"),
            ):
                self.run_spec(
                    CommandSpec(
                        name="log-write-failure",
                        argv=(
                            sys.executable,
                            "-c",
                            parent_script,
                            str(parent_pid_path),
                            str(child_pid_path),
                            child_script,
                        ),
                    )
                )

            self.assertTrue(injected)
            parent_pid = int(parent_pid_path.read_text(encoding="utf-8"))
            child_pid = int(child_pid_path.read_text(encoding="utf-8"))
            for label, pid in (("parent", parent_pid), ("child", child_pid)):
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.02)
                else:
                    self.fail(f"log failure left the {label} process alive")
        finally:
            if parent_pid is None and parent_pid_path.exists():
                parent_pid = int(parent_pid_path.read_text(encoding="utf-8"))
            if parent_pid is not None:
                try:
                    os.killpg(parent_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_log_failure_after_target_exit_kills_only_owned_descendants(self) -> None:
        descendant_identity_path = self.worktree / "orphan-descendant.identity"
        child_script = (
            "import os, pathlib, signal, sys, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "pathlib.Path(sys.argv[1]).write_text("
            "f'{os.getpid()} {os.getpgrp()}'); "
            "time.sleep(0.2); "
            "os.write(1, b'trigger after target exit'); "
            "time.sleep(60)"
        )
        target_script = (
            "import pathlib, subprocess, sys, time; "
            "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]); "
            "identity = pathlib.Path(sys.argv[2]); "
            "\nwhile not identity.exists(): time.sleep(0.01)\n"
        )
        external = subprocess.Popen(
            (sys.executable, "-c", "import time; time.sleep(60)"),
            start_new_session=True,
        )
        real_write = runner_module._BoundedLog.write
        injected = False
        owned_pgid: int | None = None

        def fail_first_log_write(log, contents: bytes) -> None:
            nonlocal injected
            if contents and not injected:
                injected = True
                raise OSError("injected orphan log failure")
            real_write(log, contents)

        try:
            with (
                mock.patch.object(
                    runner_module._BoundedLog,
                    "write",
                    fail_first_log_write,
                ),
                self.assertRaisesRegex(OSError, "injected orphan log failure"),
            ):
                self.run_spec(
                    CommandSpec(
                        name="orphan-log-write-failure",
                        argv=(
                            sys.executable,
                            "-c",
                            target_script,
                            child_script,
                            str(descendant_identity_path),
                        ),
                    )
                )

            self.assertTrue(injected)
            descendant_pid, owned_pgid = map(
                int,
                descendant_identity_path.read_text(encoding="utf-8").split(),
            )
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline:
                try:
                    os.kill(descendant_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail("log failure left an exited target's descendant alive")
            self.assertIsNone(external.poll())
        finally:
            if owned_pgid is None and descendant_identity_path.exists():
                _, owned_pgid = map(
                    int,
                    descendant_identity_path.read_text(encoding="utf-8").split(),
                )
            if owned_pgid is not None:
                try:
                    os.killpg(owned_pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            external.kill()
            external.wait()

    def test_eof_does_not_shorten_the_configured_process_timeout(self) -> None:
        script = "import os, time; os.close(1); os.close(2); time.sleep(60)"

        started = time.monotonic()
        result = self.run_spec(
            CommandSpec(
                name="closed-output-timeout",
                argv=(sys.executable, "-c", script),
                timeout_seconds=2,
            )
        )
        elapsed = time.monotonic() - started

        self.assertTrue(result.timed_out)
        self.assertGreaterEqual(elapsed, 1.8)
        self.assertLess(elapsed, 3.5)


if __name__ == "__main__":
    unittest.main()
