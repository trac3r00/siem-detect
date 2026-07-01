# Detection rules

Sigma rules bundled with `siem-detect`, organised by platform. Each rule is a
standard [Sigma](https://sigmahq.io/docs) YAML file and is executed directly by
the engine (no backend conversion).

```
rules/
├── linux/    SSH brute force, invalid user, reverse shell, sudo escalation
├── web/      SQLi, path traversal, web shell, HTTP auth brute force
├── windows/  encoded PowerShell, LSASS dump, privileged group add
└── cloud/    AWS CloudTrail disabled, root console login, IAM key created
```

## Writing your own

Drop any `*.yml` Sigma rule into a directory and point the CLI at it:

```bash
siem-detect app.log -r ./my-rules
```

Minimum viable rule:

```yaml
title: My Detection
id: unique-id
level: high
tags:
  - attack.execution
  - attack.t1059
logsource:
  product: linux          # optional; scopes which logs the rule runs on
detection:
  selection:
    message|contains: "something bad"
  condition: selection
```

The `logsource` block is matched against the parser's descriptor
(`product` / `service` / `category`). Leave it empty to run the rule against
every event regardless of source.

See [`../docs/engine-walkthrough.md`](../docs/engine-walkthrough.md) for the full
list of supported field modifiers and condition operators.
