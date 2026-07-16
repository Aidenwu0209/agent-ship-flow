# Repository Entry, Documentation, and CI Design

## Status

Proposed and approved for implementation. This document records the agreed
scope before implementation starts.

## Goals

1. Make the GitHub landing experience explain Agent Ship Flow in one scan:
   what it protects, why its state machine is trustworthy, and how to begin.
2. Give English and Simplified Chinese readers equivalent entry points without
   mixing two full languages in one long page.
3. Turn the documentation directory into a clear map for the portable CLI,
   agent integration, Codex adapter, contribution, and security paths.
4. Make CI faster to read and less wasteful while preserving Python 3.11 and
   3.12 compatibility coverage.
5. Repair the first-run experience so accepting a detected manifest produces a
   precise next action instead of leaving users to discover the clean-base rule
   through a generic Git error.

## Non-goals

- No release, deployment, rollback, automatic merge, or automatic push.
- No change to the state-machine gates, durable-evidence model, or public
  command semantics beyond adding a typed post-initialization next action.
- No fabricated metrics, user logos, screenshots, coverage badges, or claims
  that are not supported by the repository.
- No automatic commit of a generated manifest. Versioning project policy must
  remain an explicit human Git action.

## Repository Entry

### GitHub About

Set the repository description to:

> Durable, reviewable Git shipping workflows for AI agents.

Set the homepage to the repository README and add focused topics:
`ai-agents`, `automation`, `git`, `release-management`, `code-review`,
`verification`, `developer-tools`, and `python`.

### English README

Rewrite `README.md` as the canonical English landing page. Its order is:

1. Project name, CI/Python/license badges, and an English/Chinese switch.
2. A concise value statement: the engine turns a risky conversational shipping
   process into durable, independently reviewed state transitions.
3. A compact table of guarantees: isolated worktrees, independent roles,
   evidence freshness, unknown-outcome recovery, and human gates.
4. A GitHub-renderable Mermaid flow that shows the journey from planning to
   cleanup and makes human gates visible.
5. Two short paths: portable CLI and optional Codex adapter. Each path leads to
   the correct detailed guide rather than reproducing long instructions.
6. A task-oriented documentation directory, development checks, contribution,
   security, and license links.

The voice is direct and evidence-based. It will describe capabilities rather
than imitate large-project marketing or release-note volume.

### Chinese README

Add `README.zh-CN.md` with the same information architecture and command
meaning as the English README. It uses natural Simplified Chinese terminology
for state, evidence, review, verification, and human approval, while retaining
literal command names and flags. Each README links to the other at the top.

### Documentation Navigation

Add `docs/README.md` and `docs/README.zh-CN.md` as concise documentation
directories. They classify content by reader goal:

- ship a repository with any compatible agent;
- integrate an agent with the JSON contract;
- install and use the Codex adapter;
- contribute safely; and
- report a security issue.

Existing guides retain their detailed material. Their opening copy and links
will be aligned so users can return to the documentation directory or switch
to the relevant equivalent language path.

## First-run Manifest Guidance

The engine intentionally requires a clean base before it creates an isolated
worktree. A confirmed `.ship/manifest.toml` is project policy and must be
versioned before a run starts; silently committing it would bypass normal Git
review and can fail when user identity is absent.

`ship init --accept-detected --json` will therefore return a typed human
`next_action` instructing the caller to review, add, and commit the manifest.
The README and quick starts will place this step directly after initialization.
The CLI and integration tests will cover the response contract and the
documented init-to-commit-to-start sequence.

## CI Design

Replace the monolithic duplicated workflow with these jobs:

| Job | Runtime | Checks |
| --- | --- | --- |
| `lint` | Python 3.12 | Ruff formatting and lint rules |
| `test` | Python 3.11 and 3.12 | unit tests, integration tests, and `ship --help` |

The workflow will:

- run on pull requests, pushes to `main`, and manual dispatch;
- cancel superseded runs for the same workflow/ref pair;
- keep `contents: read` as the only default permission;
- use current supported `actions/checkout` and `actions/setup-python` majors;
- enable setup-python's pip cache; and
- keep the project documentation's local checks consistent with the CI jobs.

This removes redundant lint work on both Python versions and avoids the
duplicate branch-push plus pull-request runs currently produced for a PR.

## Verification

Implementation will add or update focused tests before behavior changes.
Acceptance requires:

1. The new first-run CLI test demonstrates the typed manifest-commit action.
2. All unit and integration tests pass on the supported Python versions.
3. Ruff format and lint checks pass.
4. The GitHub workflow YAML parses and its job/trigger structure is inspected.
5. Markdown links and language/doc navigation are checked locally.
6. The final diff is reviewed for accidental credentials, generated files, and
   unplanned scope.

GitHub About metadata is a separate repository-setting write. It will be
applied only after the exact target and values are restated and the local
content changes have been verified.
