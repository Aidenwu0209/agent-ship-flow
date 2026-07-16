# Contributing to Agent Ship Flow

Thanks for contributing. This project treats delivery safety as a product
feature, so every change needs reproducible evidence.

## Before you start

1. Open an issue or discussion for a behavior change that affects workflow
   gates, external operations, recovery, or the public JSON contract.
2. Do not add credentials, real deployment targets, customer data, or private
   evidence to the repository.
3. Keep the core agent-neutral. Provider-specific behavior belongs in an
   adapter or documented integration layer.

## Local checks

```bash
python3 -m pip install -e ".[dev]"
python3 -m unittest discover -s tests/unit -v
python3 -m unittest discover -s tests/integration -v
ruff format --check src/ship_flow tests scripts/install_codex_skill.py scripts/install-codex-skill.py
ruff check src/ship_flow tests scripts/install_codex_skill.py scripts/install-codex-skill.py
git diff --check
```

Add a focused regression test for every bug. For a workflow change, include a
case that proves stale evidence, a missing human approval, or an interrupted
operation cannot be treated as success.

## Pull requests

Keep pull requests small and explain:

- the user-visible workflow change;
- the evidence, state, and approval boundary it affects;
- tests run and their output summary;
- any migration, compatibility, or security consequence.

Never use a pull request to perform a real push, merge, release, deploy,
rollback, or cleanup against someone else's repository.
