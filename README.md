# siem-detect

A small, dependency-light **Sigma detection engine** for logs — for SOC
analysts and detection engineers who want to *run* Sigma rules directly against
log data without standing up a full SIEM.

Point it at a log file (JSON, syslog, nginx/Apache, Linux auth, or Windows
EVTX-as-JSON), and it will:

1. **Parse** the log into structured events and auto-detect its `logsource`.
2. **Match** every event against a bundled (or your own) set of **Sigma rules**,
   honoring field modifiers (`contains`, `cidr`, `endswith`, `re`, `base64`,
   `gt/lt`, …) and the full `condition` mini-language
   (`and`/`or`/`not`, parentheses, `1 of selection*`, `all of them`).
3. **Report** an analyst-ready verdict with every detection mapped to
   **MITRE ATT&CK** techniques and tactics — as markdown, JSON, or JSONL.

> ⚙️  The only runtime dependency is **PyYAML** (the Sigma-standard YAML parser).
> Rules are *executed* against events in-process — this is **not** a
> rule-to-query converter like `sigma-cli`/pySigma; it is the lightweight,
> host-side matching engine those tools don't give you.

## Why this exists

Tools like [Hayabusa](https://github.com/Yamato-Security/hayabusa) and
[Chainsaw](https://github.com/WithSecureLabs/chainsaw) run Sigma over **Windows
EVTX** and are fantastic — but they're Rust binaries scoped to Windows forensics.
`sigma-cli`/pySigma convert rules into *backend queries* but never actually match
anything themselves. `siem-detect` fills the gap in the middle: a tiny,
readable, cross-format Python engine you can drop into a pipeline, a CI check,
or a triage notebook.

## Architecture

```
              ┌───────────────────────────────┐
   log file ─►│ logsource.py — parsers        │──► events[] + {product,service}
   (any of    │  jsonl · json · syslog ·      │
   5 formats) │  auth · nginx · evtx-json     │
              └───────────────┬───────────────┘
                              │
              ┌───────────────▼───────────────┐
   Sigma  ───►│ sigma.py — rule model +       │
   rules      │  field matchers + condition   │
   (YAML)     │  evaluator (AND/OR/NOT/1 of)  │
              └───────────────┬───────────────┘
                              │
              ┌───────────────▼───────────────┐
              │ engine.py — scan + Report     │──► markdown / JSON / JSONL
              │  verdict + MITRE ATT&CK roll-up│    + CI exit code
              └───────────────────────────────┘
```

## Quickstart

```bash
# install (editable) into a venv
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e .

# scan a Linux auth log with the bundled ruleset
siem-detect /var/log/auth.log

# scan an nginx access log, JSON output
siem-detect access.log -f nginx -o json

# pipe Windows Sysmon (EVTX exported to JSON) from stdin
cat sysmon.jsonl | siem-detect - -f evtx-json

# use your own rules, only report high+ severity
siem-detect app.log -r ./my-rules --min-level high

# CI gate: exit non-zero if anything critical fires
siem-detect audit.jsonl --fail-on critical
```

### Example output

```
# siem-detect report — verdict: 🔴 CRITICAL

- events scanned: 6
- rules loaded: 14 · matched: 4
- total detections: 5
- by level: 🔴 critical: 1  🟠 high: 2  🟡 medium: 2
- MITRE ATT&CK: `T1190`×2, `T1110.004`×2, `T1505.003`×1

| # | level | rule | ATT&CK | event # | key fields |
|---|-------|------|--------|---------|------------|
| 1 | 🔴 critical | Web Shell Upload Or Access | T1505.003 | 2 | uri=/uploads/shell.php?cmd=id; status=200 |
| 2 | 🟠 high | Web SQL Injection Attempt In URI | T1190 | 0 | src_ip=203.0.113.9; uri=…union+select… |
| … |
```

## Supported log formats

| `--format`  | Source                                   | logsource targeting          |
|-------------|------------------------------------------|------------------------------|
| `auto`      | sniffs the first ~50 lines               | derived from detected format |
| `jsonl`     | one JSON object per line                 | none (matches any rule)      |
| `json`      | a single JSON array/object               | none                         |
| `syslog`    | RFC3164-ish `time host prog[pid]: msg`   | `product: linux`             |
| `auth`      | Linux `/var/log/auth.log` (sshd/sudo)    | `product: linux, service: auth` |
| `nginx`     | nginx/Apache combined access log         | `category: webserver`        |
| `evtx-json` | Windows EVTX exported to JSON            | `product: windows`           |

The Windows parser flattens the common
`{"Event": {"System": {...}, "EventData": {...}}}` shape produced by
`evtx_dump`, EvtxECmd, and winlogbeat into flat Sigma fields.

## Bundled ruleset (14 rules)

| Platform | Rules |
|----------|-------|
| **linux**   | SSH brute force (external), SSH invalid user, reverse-shell one-liners, sudo→root escalation |
| **web**     | SQL injection, path traversal / LFI, web-shell access, HTTP auth brute force |
| **windows** | encoded/hidden PowerShell, LSASS credential dump, privileged-group add |
| **cloud**   | AWS CloudTrail disabled, AWS root console login, AWS IAM access-key created |

Every rule carries a MITRE ATT&CK tag (`attack.tNNNN[.NNN]`) and a `level`.
Drop your own `*.yml` Sigma rules into any directory and pass `-r`.

## Sigma coverage

Implemented subset of the [Sigma specification](https://sigmahq.io/docs):

- **logsource** targeting (`category` / `product` / `service`)
- **selections** as dicts (implicit AND) and lists (OR), field-lists (OR), and
  `keywords` blocks (substring OR over the whole event)
- **field modifiers**: `contains`, `startswith`, `endswith`, `all`, `re`,
  `cidr`, `base64`, `base64offset`, `windash`, `lt`/`lte`/`gt`/`gte`, `cased`,
  `exists`
- **condition**: `and` / `or` / `not`, parentheses, `1 of pattern*`,
  `all of pattern*`, `1 of them`, `all of them`
- dotted field paths (`userIdentity.type`) into nested JSON

Not implemented (out of scope for a host-side matcher): rule correlation,
backend query conversion, and field-mapping pipelines — use pySigma for those.

## Development

```bash
pip install -e ".[dev]"
pytest -q          # 30 tests: engine, parsers, end-to-end
```

## License

MIT — see [LICENSE](LICENSE).
