# Security Policy

Agent Ship Flow handles local repositories, workflow evidence, and optional
external-operation adapters. Do not report a suspected vulnerability in a
public issue before a fix is available.

Use GitHub's private security advisory flow for the repository once it is
published. Include a minimal reproduction, affected version or commit, impact,
and any safe mitigation. Do not include live credentials, customer data, or a
real production target in the report.

The project treats the following as security-sensitive: bypassed human gates,
stale-evidence acceptance, replay of unknown external effects, path traversal,
unsafe worktree cleanup, log redaction failures, and secret disclosure.
