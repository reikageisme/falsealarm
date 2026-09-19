# Operating FalseAlarm

Read this reference for installation, authorized scan execution, output,
history, diffing, notifications, AI triage, or runtime troubleshooting.

## Establish the runtime

From PyPI, install the requested version and optionally install the bundled
agent skill:

```powershell
python -m pip install --upgrade falsealarm
falsealarm install-skill --target codex
```

Other supported destinations are `--target claude` and `--target project`.
Use `--destination <path>` for a custom final skill directory and `--force` to
update an existing installation. Installing the Python package alone does not
write into an agent's home directory.

From a source checkout:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m falsealarm modules
```

On Unix-like systems, activate with `source .venv/bin/activate`. For a packaged
install, use `pipx install falsealarm` where available. The CLI entrypoints
`falsealarm` and `python -m falsealarm` are equivalent.

The Go dirfuzz worker is optional. `python -m falsealarm build-engine` builds it
when Go is available or attempts to download a matching release binary. If it
cannot run, `dirfuzz` falls back to the Python async engine. Record that fallback
because the Go worker exposes URL/status/length, while Python can also use body
signatures for catch-all filtering.

## Choose the smallest useful scan

Inspect current capabilities before composing a command:

```powershell
python -m falsealarm modules
python -m falsealarm scan --help
```

Current depth profiles are:

| Selection | Modules | Operational character |
| --- | --- | --- |
| `-q` / `--depth quick` | `httpprobe`, `ssl` | Small HTTP/TLS baseline |
| default / `--depth normal` | quick plus `tech`, `vulnscan`, `cors`, `favicon` | Active web assessment |
| `--depth deep` | normal plus `dirfuzz`, `websocket`, `js_analysis`, `wayback`, `graphql`, `openredirect` | Broad application mapping |
| `-A` / `--depth insane` | deep plus `dns`, `subdomain`, `portscan` | Full active reconnaissance |

Use `-m name1,name2` when the user needs an exact module set. FalseAlarm
auto-discovers installed modules, so prefer `modules` output over a memorized
list.

Examples to adapt only after authorization and scope are established:

```powershell
# Low-volume baseline
python -m falsealarm scan -u https://app.example.test -q -r 5 -t 5 --report baseline.md

# Exact modules with machine-readable output
python -m falsealarm scan -u https://app.example.test -m httpprobe,tech -o results.json -f json

# Directory fuzzing with an approved wordlist and bounded recursion
python -m falsealarm scan -u https://app.example.test -m dirfuzz -w .\wordlist.txt -r 10 -t 10 --recursion-depth 1
```

For target files use `-iL`; for CIDR input, confirm every expanded host is in
scope. Proxy, `--random-agent`, and adaptive rate control do not make an
unauthorized scan acceptable.

## Preserve machine-readable output

`--pipe` reads newline-delimited targets from stdin when no target is supplied
and streams NDJSON on stdout; logs are routed to stderr. `-o -` also enables
pipe behavior. Do not add banners, status text, or ad-hoc prints to stdout.

Supported file formats are `table`, `json`, `jsonl`, `csv`, `txt`, and `sarif`.
Use `--report <path>` for the Markdown pentest handoff. Treat output as evidence
to validate: note WAF/catch-all behavior, network errors, fallbacks, and modules
that did not run.

## State, diffs, and notifications

Scan history is stored in `falsealarm.db` by default. Useful commands/options:

```powershell
python -m falsealarm list-scans
python -m falsealarm scan --resume <scan-id>
python -m falsealarm scan -u https://app.example.test -q --diff
```

Notifications require a concrete platform; there is no standalone `--notify`
flag in the current CLI:

```powershell
python -m falsealarm scan -u https://app.example.test -q --diff --notify-type discord --notify-webhook <url>
```

Slack also uses `--notify-webhook`; Telegram uses `--telegram-token` and
`--telegram-chat-id`. Prefer a protected profile outside version control for
notification credentials, redact them from output, and never invent delivery
success: report the CLI result.

## AI triage

The current implementation uses Gemini only, via `GEMINI_API_KEY` and optional
`GEMINI_MODEL`, even though some prose documentation mentions other providers.
Run `--ai-triage` only when the user has approved sending scan data to that
external model. Explain what data leaves the environment and redact sensitive
content where required.

## Troubleshooting order

1. Reproduce with a single target, exact module, low rate, and `--verbose`.
2. Confirm the module appears in `python -m falsealarm modules`.
3. Check target normalization, proxy health, WAF/rate-limit messages, and the
   structured response's `error` field.
4. For dirfuzz, distinguish Go-worker failure from the Python fallback and
   verify the wordlist path.
5. For profile issues, inspect the selected YAML profile and then compare it
   with `scan --help`; current source behavior wins over documentation examples.
6. Re-run a focused test or a localhost fixture before using any live target.
