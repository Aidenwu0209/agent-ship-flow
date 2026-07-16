from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .manifest import CommandSpec


class RunnerError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    exit_code: int | None
    timed_out: bool
    truncated: bool
    log_sha256: str
    log_size: int
    log_path: Path


@dataclass(frozen=True)
class _StreamOutcome:
    timed_out: bool
    target_exit_code: int | None
    kill_sent: bool


_PLACEHOLDER = re.compile(r"\$\{([^}]*)\}")
_ENV_ASSIGNMENT = re.compile(r"^[^=]+=")
_SHELL_EXECUTABLES = frozenset({"bash", "dash", "ksh", "sh", "zsh"})
_REDACTION_SENTINEL = b"\xff"
_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
)
_LOG_OPEN_FLAGS = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
)
_LOG_VERIFY_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_EVIDENCE_PATH_ERROR = "evidence path changed during command execution"
_MAX_ENV_WRAPPERS = 8
_FD_SUPERVISOR = """
import os
import select
import signal
import sys
import time

cwd_fd = int(sys.argv[1])
status_fd = int(sys.argv[2])
control_fd = int(sys.argv[3])
argv = sys.argv[4:]
os.fchdir(cwd_fd)
os.close(cwd_fd)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
target_pid = os.fork()
if target_pid == 0:
    os.close(status_fd)
    os.close(control_fd)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    try:
        os.execvpe(argv[0], argv, os.environ)
    except BaseException:
        os.write(2, b"command exec failed\\n")
        os._exit(127)

os.close(0)
os.close(1)
os.close(2)
wait_status = None
status_open = True
cleanup_deadline = None
while True:
    if wait_status is None:
        waited_pid, candidate_status = os.waitpid(target_pid, os.WNOHANG)
        if waited_pid:
            wait_status = candidate_status
            try:
                payload = (str(wait_status) + "\\n").encode("ascii")
                while payload:
                    payload = payload[os.write(status_fd, payload):]
            except OSError:
                pass
            os.close(status_fd)
            status_open = False
    if cleanup_deadline is not None and time.monotonic() >= cleanup_deadline:
        os.kill(0, signal.SIGKILL)
    timeout = 0.01
    if cleanup_deadline is not None:
        timeout = max(0.0, min(timeout, cleanup_deadline - time.monotonic()))
    readable, _, _ = select.select((control_fd,), (), (), timeout)
    if not readable:
        continue
    try:
        control = os.read(control_fd, 1)
    except OSError:
        control = b""
    if control == b"R" and wait_status is not None and cleanup_deadline is None:
        if status_open:
            os.close(status_fd)
        os.close(control_fd)
        os._exit(0)
    if cleanup_deadline is None:
        os.kill(0, signal.SIGTERM)
        cleanup_deadline = time.monotonic() + 0.2
"""


def _resolved_argv(
    argv: tuple[str, ...], variables: Mapping[str, str]
) -> tuple[str, ...]:
    if not isinstance(variables, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str) or "\x00" in value
        for key, value in variables.items()
    ):
        raise RunnerError("variables must map strings to NUL-free strings")

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in variables:
            raise RunnerError(f"argv placeholder is unresolved: {name}")
        return variables[name]

    resolved: list[str] = []
    for token in argv:
        if not isinstance(token, str) or not token or "\x00" in token:
            raise RunnerError("argv tokens must be non-empty NUL-free strings")
        expanded = _PLACEHOLDER.sub(replace, token)
        if not expanded or "\x00" in expanded or "${" in _PLACEHOLDER.sub("", expanded):
            raise RunnerError("argv token expansion is invalid")
        resolved.append(expanded)
    return tuple(resolved)


def _uses_shell_command_string(
    argv: tuple[str, ...],
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> bool:
    effective_environment = dict(environment or {})
    effective_argv = argv
    for depth in range(_MAX_ENV_WRAPPERS + 1):
        executable = Path(effective_argv[0]).name.lower()
        arguments = effective_argv[1:]
        if executable != "env":
            break
        if depth == _MAX_ENV_WRAPPERS:
            return True
        cwd_changed = False
        command_index = 0
        while command_index < len(arguments):
            token = arguments[command_index]
            if token == "--":
                command_index += 1
                break
            if token in {"-S", "--split-string"} or token.startswith(
                ("-S", "--split-string=")
            ):
                return True
            if token in {"-u", "--unset", "-C", "--chdir"}:
                if command_index + 1 >= len(arguments):
                    return True
                value = arguments[command_index + 1]
                if token in {"-u", "--unset"}:
                    effective_environment.pop(value, None)
                else:
                    cwd_changed = True
                command_index += 2
                continue
            if token.startswith("--unset=") or (
                token.startswith("-u") and len(token) > 2
            ):
                name = token.split("=", 1)[1] if token.startswith("--") else token[2:]
                effective_environment.pop(name, None)
                command_index += 1
                continue
            if token.startswith("--chdir=") or (
                token.startswith("-C") and len(token) > 2
            ):
                cwd_changed = True
                command_index += 1
                continue
            if token in {
                "-i",
                "--ignore-environment",
                "-0",
                "--null",
                "-v",
                "--debug",
            }:
                if token in {"-i", "--ignore-environment"}:
                    effective_environment.clear()
                command_index += 1
                continue
            if token.startswith("-"):
                return True
            if _ENV_ASSIGNMENT.match(token) is not None:
                name, value = token.split("=", 1)
                effective_environment[name] = value
                command_index += 1
                continue
            break
        if command_index >= len(arguments):
            return False
        effective_executable = arguments[command_index]
        executable = Path(effective_executable).name.lower()
        arguments = arguments[command_index + 1 :]
        if executable not in _SHELL_EXECUTABLES:
            if cwd is None or environment is None or cwd_changed:
                return True
            try:
                canonical = _resolve_executable(
                    effective_executable,
                    cwd=cwd,
                    environment=effective_environment,
                )
            except RunnerError:
                return True
            executable = Path(canonical).name.lower()
            effective_executable = canonical
        effective_argv = (effective_executable, *arguments)
    else:
        return True
    if executable not in _SHELL_EXECUTABLES:
        return False
    for option in arguments:
        if option == "--command" or (
            option.startswith("-") and not option.startswith("--") and "c" in option[1:]
        ):
            return True
    return False


def _child_environment(allowlist: tuple[str, ...]) -> dict[str, str]:
    return {name: os.environ[name] for name in allowlist if name in os.environ}


def _resolve_executable(
    executable: str,
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> str:
    if os.sep in executable:
        path = Path(executable)
        candidate = path if path.is_absolute() else cwd / path
        try:
            resolved_path = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise RunnerError("command executable was not found") from error
        if not resolved_path.is_file() or not os.access(resolved_path, os.X_OK):
            raise RunnerError("command executable is not executable")
        return str(resolved_path)
    search_path = environment.get("PATH", os.defpath)
    located = shutil.which(executable, path=search_path)
    if located is None:
        raise RunnerError("command executable was not found in the approved PATH")
    return str(Path(located).resolve())


class _DirectoryChain:
    def __init__(self, descriptors: list[int]) -> None:
        self._descriptors = descriptors

    @property
    def fd(self) -> int:
        return self._descriptors[-1]

    def close(self) -> None:
        while self._descriptors:
            os.close(self._descriptors.pop())


def _append_directory(
    chain: _DirectoryChain,
    component: str,
    *,
    create: bool,
) -> None:
    if component in {"", ".", ".."} or os.sep in component:
        raise RunnerError("directory path contains an unsafe component")
    created = False
    try:
        descriptor = os.open(component, _DIRECTORY_OPEN_FLAGS, dir_fd=chain.fd)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(component, mode=0o700, dir_fd=chain.fd)
            created = True
        except FileExistsError:
            pass
        descriptor = os.open(component, _DIRECTORY_OPEN_FLAGS, dir_fd=chain.fd)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise RunnerError("directory path component is not a directory")
        if created:
            os.fchmod(descriptor, 0o700)
    except Exception:
        os.close(descriptor)
        raise
    chain._descriptors.append(descriptor)


def _open_absolute_directory(
    value: Path | str,
    *,
    create: bool,
    error_message: str,
) -> tuple[Path, _DirectoryChain]:
    try:
        absolute = Path(os.path.abspath(os.fspath(value)))
        if "\x00" in os.fspath(absolute):
            raise ValueError("directory path contains NUL")
        chain = _DirectoryChain([os.open(os.sep, _DIRECTORY_OPEN_FLAGS)])
    except (OSError, TypeError, ValueError) as error:
        raise RunnerError(error_message) from error
    try:
        for component in absolute.relative_to(os.sep).parts:
            _append_directory(chain, component, create=create)
    except (OSError, RunnerError, ValueError) as error:
        chain.close()
        raise RunnerError(error_message) from error
    return absolute, chain


def _open_worktree_cwd(
    worktree: Path | str,
    configured_cwd: str,
) -> tuple[Path, Path, _DirectoryChain]:
    try:
        root = Path(os.path.abspath(os.fspath(worktree)))
        raw_cwd = os.fspath(configured_cwd)
        if "\x00" in os.fspath(root) or "\x00" in raw_cwd:
            raise ValueError("cwd path contains NUL")
        candidate = Path(
            os.path.abspath(
                raw_cwd
                if os.path.isabs(raw_cwd)
                else os.path.join(os.fspath(root), raw_cwd)
            )
        )
        relative_cwd = candidate.relative_to(root)
    except (OSError, TypeError, ValueError) as error:
        raise RunnerError("cwd must resolve inside the worktree") from error

    root, chain = _open_absolute_directory(
        root,
        create=False,
        error_message="worktree cannot be opened safely",
    )
    try:
        for component in relative_cwd.parts:
            _append_directory(chain, component, create=False)
    except (OSError, RunnerError, ValueError) as error:
        chain.close()
        raise RunnerError("cwd must resolve inside the worktree") from error
    return root, candidate, chain


def _open_unique_log(directory_fd: int, prefix: str) -> tuple[int, str]:
    for _ in range(128):
        filename = f"{prefix}{secrets.token_hex(16)}.log"
        try:
            descriptor = os.open(
                filename,
                _LOG_OPEN_FLAGS,
                0o600,
                dir_fd=directory_fd,
            )
        except FileExistsError:
            continue
        try:
            os.fchmod(descriptor, 0o600)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise RunnerError("command log is not a regular file")
        except Exception:
            os.close(descriptor)
            raise
        return descriptor, filename
    raise RunnerError("a unique command log could not be created")


def _new_private_log(
    log_dir: Path | str,
    *,
    name: str,
    argv: tuple[str, ...],
):
    directory, chain = _open_absolute_directory(
        log_dir,
        create=True,
        error_message="log directory cannot be opened safely",
    )
    identity = json.dumps(
        {"name": name, "argv": argv},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    prefix = f"command-{hashlib.sha256(identity).hexdigest()}-"
    descriptor: int | None = None
    retained_directory_fd: int | None = None
    try:
        os.fchmod(chain.fd, 0o700)
        descriptor, filename = _open_unique_log(chain.fd, prefix)
        retained_directory_fd = os.dup(chain.fd)
    except (OSError, RunnerError) as error:
        if descriptor is not None:
            os.close(descriptor)
        raise RunnerError("command log cannot be created safely") from error
    finally:
        chain.close()
    try:
        stream = os.fdopen(descriptor, "wb")
    except Exception:
        os.close(descriptor)
        os.close(retained_directory_fd)
        raise
    return directory / filename, stream, retained_directory_fd


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _validate_evidence_path(log_path: Path, directory_fd: int, log_fd: int) -> None:
    try:
        _, current_chain = _open_absolute_directory(
            log_path.parent,
            create=False,
            error_message=_EVIDENCE_PATH_ERROR,
        )
    except RunnerError as error:
        raise RunnerError(_EVIDENCE_PATH_ERROR) from error
    try:
        if not _same_file_identity(os.fstat(directory_fd), os.fstat(current_chain.fd)):
            raise RunnerError(_EVIDENCE_PATH_ERROR)
        try:
            current_log_fd = os.open(
                log_path.name,
                _LOG_VERIFY_FLAGS,
                dir_fd=current_chain.fd,
            )
        except OSError as error:
            raise RunnerError(_EVIDENCE_PATH_ERROR) from error
        try:
            if not _same_file_identity(os.fstat(log_fd), os.fstat(current_log_fd)):
                raise RunnerError(_EVIDENCE_PATH_ERROR)
        finally:
            os.close(current_log_fd)
    finally:
        current_chain.close()


class _StreamingRedactor:
    def __init__(self, sensitive_values: Sequence[str]) -> None:
        if isinstance(sensitive_values, (str, bytes)) or not isinstance(
            sensitive_values, Sequence
        ):
            raise RunnerError("sensitive_values must be a sequence of strings")
        if any(not isinstance(value, str) for value in sensitive_values):
            raise RunnerError("sensitive_values must contain only strings")
        self._secrets = tuple(
            sorted(
                {value.encode("utf-8") for value in sensitive_values if value},
                key=lambda value: (-len(value), value),
            )
        )
        self._maximum_length = max((len(value) for value in self._secrets), default=0)
        self._pending = b""

    def feed(self, chunk: bytes, *, final: bool = False) -> bytes:
        self._pending += chunk
        if not self._secrets:
            emitted, self._pending = self._pending, b""
            return emitted

        emitted = bytearray()
        while self._pending:
            safe_start_limit = (
                len(self._pending)
                if final
                else max(0, len(self._pending) - (self._maximum_length - 1))
            )
            matches = []
            for secret in self._secrets:
                index = self._pending.find(secret)
                if index >= 0 and (final or index < safe_start_limit):
                    matches.append((index, -len(secret), secret))
            if matches:
                index, _, secret = min(matches)
                emitted.extend(self._pending[:index])
                emitted.extend(_REDACTION_SENTINEL)
                self._pending = self._pending[index + len(secret) :]
                continue
            if final:
                emitted.extend(self._pending)
                self._pending = b""
            elif safe_start_limit:
                emitted.extend(self._pending[:safe_start_limit])
                self._pending = self._pending[safe_start_limit:]
            break
        return bytes(emitted)


class _BoundedLog:
    def __init__(self, stream, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self._digest = hashlib.sha256()
        self.size = 0
        self.truncated = False

    def write(self, contents: bytes) -> None:
        remaining = self._limit - self.size
        persisted = contents[:remaining]
        if len(contents) > remaining:
            self.truncated = True
        if persisted:
            self._stream.write(persisted)
            self._digest.update(persisted)
            self.size += len(persisted)

    def finish(self) -> str:
        self._stream.flush()
        os.fsync(self._stream.fileno())
        return self._digest.hexdigest()


def _signal_process_group(process: subprocess.Popen[bytes], action: int) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, action)
    except ProcessLookupError:
        pass


def _terminate_and_reap_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        process.wait()
        return
    _signal_process_group(process, signal.SIGTERM)
    grace_deadline = time.monotonic() + 0.2
    try:
        process.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        pass
    remaining_grace = grace_deadline - time.monotonic()
    if remaining_grace > 0:
        time.sleep(remaining_grace)
    _signal_process_group(process, signal.SIGKILL)
    if process.poll() is None:
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def _stream_process(
    process: subprocess.Popen[bytes],
    *,
    status_fd: int,
    timeout_seconds: int,
    redactor: _StreamingRedactor,
    log: _BoundedLog,
) -> _StreamOutcome:
    if process.stdout is None:
        raise RunnerError("command output pipe was not created")
    output_fd = process.stdout.fileno()
    os.set_blocking(output_fd, False)
    os.set_blocking(status_fd, False)
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout_seconds
    term_sent_at: float | None = None
    kill_sent_at: float | None = None
    timed_out = False
    output_eof = False
    status_eof = False
    status_buffer = bytearray()
    target_exit_code: int | None = None
    primary_error: BaseException | None = None
    try:
        selector.register(output_fd, selectors.EVENT_READ, "output")
        selector.register(status_fd, selectors.EVENT_READ, "status")
        while True:
            supervisor_exited = process.poll() is not None
            if output_eof and (
                target_exit_code is not None or (status_eof and supervisor_exited)
            ):
                break
            now = time.monotonic()
            if not timed_out and now >= deadline:
                timed_out = True
                term_sent_at = now
                _signal_process_group(process, signal.SIGTERM)
            if (
                timed_out
                and kill_sent_at is None
                and term_sent_at is not None
                and now >= term_sent_at + 0.2
            ):
                _signal_process_group(process, signal.SIGKILL)
                kill_sent_at = now
            if kill_sent_at is not None and now >= kill_sent_at + 1.0:
                break

            wake_at = deadline
            if term_sent_at is not None and kill_sent_at is None:
                wake_at = term_sent_at + 0.2
            wait = max(0.0, min(0.1, wake_at - now))
            if output_eof and (status_eof or target_exit_code is not None):
                time.sleep(wait)
                continue
            for key, _ in selector.select(wait):
                if key.data == "output":
                    while True:
                        try:
                            chunk = os.read(output_fd, 65_536)
                        except BlockingIOError:
                            break
                        if not chunk:
                            output_eof = True
                            selector.unregister(output_fd)
                            break
                        log.write(redactor.feed(chunk))
                    continue
                while True:
                    try:
                        chunk = os.read(status_fd, 64)
                    except BlockingIOError:
                        break
                    if not chunk:
                        status_eof = True
                        selector.unregister(status_fd)
                        break
                    status_buffer.extend(chunk)
                    if len(status_buffer) > 32:
                        raise RunnerError("command supervisor returned invalid status")
                    if b"\n" not in status_buffer:
                        continue
                    status_line, _, remainder = status_buffer.partition(b"\n")
                    if remainder:
                        raise RunnerError("command supervisor returned invalid status")
                    try:
                        target_exit_code = os.waitstatus_to_exitcode(int(status_line))
                    except (TypeError, ValueError) as error:
                        raise RunnerError(
                            "command supervisor returned invalid status"
                        ) from error
                    selector.unregister(status_fd)
                    break
    except BaseException as error:
        primary_error = error
    try:
        selector.close()
    except BaseException as error:
        if primary_error is None:
            primary_error = error
    try:
        log.write(redactor.feed(b"", final=True))
    except BaseException as error:
        if primary_error is None:
            primary_error = error
    try:
        process.stdout.close()
    except BaseException as error:
        if primary_error is None:
            primary_error = error
    if primary_error is not None:
        raise primary_error.with_traceback(primary_error.__traceback__)
    return _StreamOutcome(
        timed_out=timed_out,
        target_exit_code=target_exit_code,
        kill_sent=kill_sent_at is not None,
    )


class CommandRunner:
    """Run one argv command with stderr merged into its bounded evidence log."""

    def run(
        self,
        spec: CommandSpec,
        variables: Mapping[str, str],
        worktree: Path | str,
        log_dir: Path | str,
        sensitive_values: Sequence[str],
    ) -> CommandResult:
        if type(spec) is not CommandSpec:
            raise RunnerError("spec must be a validated CommandSpec")
        process: subprocess.Popen[bytes] | None = None
        stream = None
        log_directory_fd: int | None = None
        status_read_fd: int | None = None
        status_write_fd: int | None = None
        control_read_fd: int | None = None
        control_write_fd: int | None = None
        _, cwd, cwd_chain = _open_worktree_cwd(worktree, spec.cwd)
        try:
            try:
                argv = _resolved_argv(spec.argv, variables)
                environment = _child_environment(spec.env_allowlist)
                policy_argv = (
                    _resolve_executable(argv[0], cwd=cwd, environment=environment),
                    *argv[1:],
                )
                if (
                    _uses_shell_command_string(
                        policy_argv,
                        cwd=cwd,
                        environment=environment,
                    )
                    and not spec.shell_approved
                ):
                    raise RunnerError(
                        "shell command strings require explicit manifest approval"
                    )
                redactor = _StreamingRedactor(sensitive_values)
                log_path, stream, log_directory_fd = _new_private_log(
                    log_dir,
                    name=spec.name,
                    argv=argv,
                )
                log = _BoundedLog(stream, spec.max_log_bytes)
                status_read_fd, status_write_fd = os.pipe()
                control_read_fd, control_write_fd = os.pipe()
                try:
                    process = subprocess.Popen(
                        (
                            sys.executable,
                            "-I",
                            "-c",
                            _FD_SUPERVISOR,
                            str(cwd_chain.fd),
                            str(status_write_fd),
                            str(control_read_fd),
                            *argv,
                        ),
                        env=environment,
                        pass_fds=(
                            cwd_chain.fd,
                            status_write_fd,
                            control_read_fd,
                        ),
                        close_fds=True,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        shell=False,
                        start_new_session=True,
                        bufsize=0,
                    )
                except OSError as error:
                    raise RunnerError("command could not be started") from error
                os.close(status_write_fd)
                status_write_fd = None
                os.close(control_read_fd)
                control_read_fd = None
            finally:
                cwd_chain.close()

            outcome = _stream_process(
                process,
                status_fd=status_read_fd,
                timeout_seconds=spec.timeout_seconds,
                redactor=redactor,
                log=log,
            )
            timed_out = outcome.timed_out
            os.close(status_read_fd)
            status_read_fd = None
            if outcome.target_exit_code is not None and process.poll() is None:
                os.write(control_write_fd, b"R")
            os.close(control_write_fd)
            control_write_fd = None
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired as error:
                raise RunnerError("command supervisor did not exit") from error
            if outcome.target_exit_code is not None:
                exit_code: int | None = outcome.target_exit_code
            elif outcome.timed_out and outcome.kill_sent:
                exit_code = -signal.SIGKILL
            else:
                raise RunnerError("command supervisor exited without target status")
            digest = log.finish()
            _validate_evidence_path(log_path, log_directory_fd, stream.fileno())
            stream.close()
            stream = None
            os.close(log_directory_fd)
            log_directory_fd = None
        except BaseException:
            if process is not None:
                try:
                    _terminate_and_reap_process_group(process)
                except BaseException:
                    pass
            if process is not None and process.stdout is not None:
                try:
                    process.stdout.close()
                except BaseException:
                    pass
            if stream is not None:
                try:
                    stream.close()
                except BaseException:
                    pass
            if log_directory_fd is not None:
                try:
                    os.close(log_directory_fd)
                except BaseException:
                    pass
            for descriptor in (
                status_read_fd,
                status_write_fd,
                control_read_fd,
                control_write_fd,
            ):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except BaseException:
                        pass
            raise
        return CommandResult(
            exit_code=exit_code,
            timed_out=timed_out,
            truncated=log.truncated,
            log_sha256=digest,
            log_size=log.size,
            log_path=log_path,
        )
