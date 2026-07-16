from __future__ import annotations

import os
import subprocess
from pathlib import Path


def git(
    cwd: Path,
    *arguments: str,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    process_environment = os.environ.copy()
    if env:
        process_environment.update(env)
    return subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        env=process_environment,
        check=check,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def git_output(cwd: Path, *arguments: str) -> str:
    return git(cwd, *arguments).stdout.strip()


def initialize_repository(path: Path) -> str:
    path.mkdir(parents=True)
    git(path, "init", "--initial-branch=main")
    git(path, "config", "user.name", "Ship Flow Tests")
    git(path, "config", "user.email", "ship-flow@example.invalid")
    git(path, "config", "core.quotepath", "false")
    (path / "README.md").write_text("initial\n", encoding="utf-8")
    git(path, "add", "README.md")
    git(path, "commit", "-m", "initial")
    return git_output(path, "rev-parse", "HEAD")
