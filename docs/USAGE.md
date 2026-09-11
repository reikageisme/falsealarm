# FalseAlarm — Usage & Workflow Guide

This guide shows how to fold FalseAlarm into a real reconnaissance workflow:
from a first low-intrusion baseline, through full authorized enumeration, to
continuous monitoring. For installation see the
[README](../README.md#installation).

> **Authorized use only.** Every command below assumes you have explicit,
> written permission to test the target. Layer-7 recon and fuzzing against
> infrastructure you do not own is illegal.

---

## The mental model

FalseAlarm runs recon as a **pipeline (DAG)**, not a pile of unrelated scans.
A discovery in one stage feeds the next:

```
subdomain ─► httpprobe ─► tech ─► [ js_analysis · cors · vulnscan · dirfuzz · … ]
   dns                 portscan ─► (web ports promoted back into httpprobe)
```

Run a single module in isolation with `-m`, the full chain with `-A`, and
control intrusiveness with `--depth` / `-q`.

```bash
falsealarm modules          # list every installed module
falsealarm scan --help      # all flags
```

---

## Workflow 1 — Fast baseline (least intrusive)

Start here. Live services and TLS/security-header posture, no heavy fuzzing.

```bash
falsealarm scan -u example.com -q --report quick-baseline.md
```

- `-q` quick mode (skips aggressive fuzzing)
- `--report` writes a readable Markdown summary

---

## Workflow 2 — Full authorized recon → pentest handoff

The repeatable attack-surface baseline you build *before* manual testing.

```bash
falsealarm scan -u example.com -A --adaptive-rate --diff \
  -o falsealarm.sarif -f sarif \
  --report pentest-handoff.md
```

- `-A` every module
- `--adaptive-rate` backs off automatically on 429/503/timeouts
- `-f sarif` output for GitHub Code Scanning / security CI
- `--report` a handoff that separates automated evidence from a prioritized
  **manual testing queue**

JavaScript analysis is same-origin by default to keep findings in scope. Add
`--include-third-party-js` only when the rules of engagement cover external
assets.

> A clean automated scan is **not** proof an app is secure — authentication,
> session, and business-logic testing still need a human and an intercepting
> proxy.

---

## Workflow 3 — Pipe chaining (compose with your toolkit)

With `--pipe`, FalseAlarm reads targets from stdin and streams NDJSON to
stdout (logs go to stderr), so it drops into any recon chain:

```bash
# Chain FalseAlarm stages
echo example.com | falsealarm --pipe -m httpprobe | jq -r .url \
  | falsealarm --pipe -m tech,vulnscan

# Feed it from other recon tools
subfinder -d example.com | falsealarm --pipe -m httpprobe -o live.jsonl -f jsonl
```

---

## Workflow 4 — Continuous monitoring

FalseAlarm can alert only on **what changed** since the last scan — new
subdomains, new open ports, new findings. Pair `--diff` with `--notify`:

```bash
falsealarm scan -u example.com -A --diff --notify
```

Configure the webhook (Discord / Slack / Telegram) via environment or profile,
then schedule it with cron or a systemd timer:

```cron
# Every night at 02:00 — only pings you when the attack surface changes
0 2 * * *  falsealarm scan -u example.com -A --diff --notify >> ~/falsealarm.log 2>&1
```

This is the "set it and forget it" habit: the tool watches an asset and stays
quiet until something moves.

---

## Stealth & rate control

```bash
# Route through Tor / a SOCKS5 proxy, randomize headers, cap the rate
falsealarm scan -u example.com -A -r 15 -t 20 \
  --proxy socks5://127.0.0.1:9050 --random-agent
```

- `-r` requests/second (token-bucket, per-host aware)
- `-t` concurrency
- `--proxy` HTTP or SOCKS5 (the Go fuzzing engine honours the same proxy)
- `--random-agent` rotate User-Agent / headers

---

## Profiles

Save and reuse scan presets in YAML:

```bash
falsealarm scan -c profile.yaml -p stealth
```

---

## AI triage

Hook an LLM to parse results, cut noise, and highlight chained exploit paths.
Set `GEMINI_API_KEY` / `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` in `.env`, then:

```bash
falsealarm scan -u example.com -A --ai-triage
```

---

## Output formats

| Flag | Format | Use for |
|------|--------|---------|
| `-f json`  | JSON            | scripting / storage |
| `-f jsonl` | JSONL / NDJSON  | streaming, piping |
| `-f sarif` | SARIF           | GitHub Code Scanning, security CI |
| `--report` | Markdown        | human-readable pentest handoff |

```bash
falsealarm list-scans                 # history
falsealarm scan --resume <scan-id>    # continue an interrupted scan
```

---

See the [README](../README.md) for the full flag reference and the
[Python API](../README.md#python-api-integration) for embedding the async core
in your own tooling.
