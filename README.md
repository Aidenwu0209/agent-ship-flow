# Agent Ship Flow

[![CI](https://github.com/Aidenwu0209/agent-ship-flow/actions/workflows/ci.yml/badge.svg)](https://github.com/Aidenwu0209/agent-ship-flow/actions/workflows/ci.yml)

Agent Ship Flow is a durable, reviewable end-to-end Git shipping workflow for
AI agents. It turns “plan → develop → independent review → deterministic
verification → release → health check → rollback → cleanup” into a recoverable
state machine.

中文：这是一个面向多种 AI Agent 的安全交付引擎。它不会因为 Agent
中断、上下文丢失或外部操作结果未知，就跳过 Review、Verification、人工
上线确认或回滚证据。

## Agent-neutral core

The core is the standard-library `ship` CLI and its JSON contract. Any agent
that can execute local commands, retain a repository path and `run-id`, and
present human gates to a user can integrate with it.

- **Codex**: the included `skills/ship-flow/` directory is an optional Codex
  adapter.
- **Claude, Cursor, OpenCode, or custom agents**: follow the same command and
  state contract in [the integration guide](docs/agent-integration.md).
- The engine never assumes that a conversational Agent is the source of truth:
  it reloads durable state and gives one typed `next_action` at a time.

## Safety model

- Every run uses an isolated Git branch and worktree.
- Planner, Plan Critic, Developer, Reviewer, and Verifier are separate roles.
- Review and Verification evidence is bound to exact Git and manifest state;
  changed code makes stale evidence unusable.
- External operations use durable receipts. `UNKNOWN` outcomes are probed or
  sent to a human gate, never blindly replayed.
- Deploy requires a health check that asserts the released candidate/version.
- Push, merge, release, deploy, data-impacting rollback, and cleanup remain
  explicit human or engine-authorized actions.

## Quick start

Requirements: Python 3.11+, Git, and an existing Git repository to ship.

```bash
git clone <your-agent-ship-flow-repository>
cd agent-ship-flow
python3 -m pip install -e ".[dev]"
ship --help
```

For a first run, your Agent calls `ship init --repo <absolute-repo-path> --json`.
It must show the detected manifest and wait for the user to confirm it before
using `--accept-detected`.

For an existing run, every Agent turn starts with:

```bash
ship status --repo <absolute-repo-path> --run-id <run-id> --json
```

Then it follows the returned `next_action`. Do not reconstruct phase from chat
history or Git alone.

## Codex integration

Codex users can install the included optional adapter from this repository:

```bash
python3 scripts/install-codex-skill.py
```

The installer validates the Skill, pressure-test receipt, unit tests, and
integration tests before installing the Skill and a self-contained engine under
`~/.codex/`.

For the portable CLI workflow, see [the Chinese quick start](docs/quickstart-zh.md).
For Codex installation, recovery, release, rollback, and uninstall, see the
[Codex adapter quick start](docs/ship-flow-quickstart-zh.md).

## Development and tests

```bash
python3 -m pip install -e ".[dev]"
python3 -m unittest discover -s tests/unit -v
python3 -m unittest discover -s tests/integration -v
ruff format --check src/ship_flow tests scripts/install_codex_skill.py scripts/install-codex-skill.py
ruff check src/ship_flow tests scripts/install_codex_skill.py scripts/install-codex-skill.py
ship --help
```

GitHub Actions runs this matrix on Python 3.11 and 3.12.

## Project layout

- `src/ship_flow/`: agent-neutral engine and `ship` CLI.
- `docs/agent-integration.md`: integration contract for any Agent.
- `skills/ship-flow/`: optional Codex adapter.
- `tests/`: unit, integration, installer, and Skill pressure tests.
- `AGENTS.md`: concise operating rules for AI contributors.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
and [SECURITY.md](SECURITY.md) before opening a contribution or reporting a
vulnerability.

## License

MIT. See [LICENSE](LICENSE).
