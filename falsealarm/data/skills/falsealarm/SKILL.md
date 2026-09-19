---
name: falsealarm
description: Operate, extend, troubleshoot, or test the FalseAlarm Python/Go async web-reconnaissance framework. Use for scoped FalseAlarm scans, result interpretation, custom modules or vulnerability templates, CLI/pipeline changes, and the Go dirfuzz engine; not for generic security testing unrelated to FalseAlarm.
---

# FalseAlarm

Use the repository and installed CLI as the source of truth. FalseAlarm is a
Python 3.10+ asyncio orchestrator with an optional Go dirfuzz worker, a
discovered-module system, a DAG scheduler, SQLite scan history, and streamed
machine-readable output.

## Route the task

- For installation, scan planning/execution, output, resume/diff/notification,
  or operational troubleshooting, read [references/operations.md](references/operations.md).
- For changes to Python modules, the scheduler/pipeline, vulnerability
  templates, or the Go engine, read
  [references/development.md](references/development.md).
- For a mixed task, read both. Do not load either reference for a simple
  conceptual answer that the entrypoint already covers.

## Safety and scope

Before sending traffic, establish that the user owns the target or has explicit
authorization and identify the permitted targets, time window, request rate,
and excluded techniques. Public reachability is not authorization. When scope
is unclear, help prepare or validate commands without executing them against a
live target.

Treat `portscan`, `dirfuzz`, `vulnscan`, GraphQL probing, WebSocket probing,
open-redirect probing, subdomain brute force, `--depth deep|insane`, and `-A`
as active testing. Start with the least intrusive profile that answers the
question and expand only within scope. Do not claim that a clean scan proves
the target is secure; authenticated, session, authorization, and business-logic
testing remain manual work.

Keep secrets out of prompts, logs, reports, commits, and shell history. Redact
credentials and sensitive response data before sharing results. Do not enable
`--include-third-party-js` unless third-party assets are explicitly in scope.

## Working rules

- Confirm behavior with `python -m falsealarm scan --help` and
  `python -m falsealarm modules` when options or modules may have changed.
- Preserve the engine path for HTTP requests so rate limits, delay, proxy,
  fingerprinting, retries, and adaptive backoff continue to apply.
- In pipe mode, keep stdout machine-readable; diagnostics belong on stderr.
- Prefer focused tests for the changed behavior, then run the repository's
  validation commands before calling a code change complete.
- Report the target scope, selected modules/profile, rate/concurrency, output
  artifacts, errors/fallbacks, and residual coverage gaps. Never turn a scanner
  hit into a confirmed vulnerability without evidence and manual validation.

