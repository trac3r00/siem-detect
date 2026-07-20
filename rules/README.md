# Detection rules

This directory contains the 14 Sigma YAML rules bundled with `siem-detect`. The CLI loads these rules by default when it is run from an editable source installation.

```text
rules/
├── cloud/    AWS CloudTrail, root console, and IAM access key events
├── linux/    SSH, reverse-shell command, and sudo events
├── web/      SQL injection, path traversal, web shell, and authentication events
└── windows/  PowerShell, LSASS access, and privileged group events
```

All bundled rules currently declare `status: experimental`. Review their field names, severity, false-positive guidance, and match conditions before using them with production data.

The engine evaluates one event at a time. Rules with names such as “brute force” or “high rate” identify individual events associated with that activity; the engine does not aggregate counts over a time window.

## Use custom rules

Pass either one YAML file or a directory. Directories are searched recursively for `*.yml` and `*.yaml` files.

```bash
siem-detect app.log --rules ./my-rules
```

A minimal supported rule is:

```yaml
title: Example detection
id: example-detection
level: high
tags:
  - attack.execution
  - attack.t1059
logsource:
  product: linux
detection:
  selection:
    message|contains: "example command"
  condition: selection
```

The `logsource` mapping is optional. When the parser identifies an input source, the engine compares the rule's `category`, `product`, and `service` values with that descriptor. A rule without these constraints can be evaluated against any source.

Only a subset of Sigma syntax is supported. Unsupported rule documents without a `detection` block, including correlation-only documents, are skipped. Malformed rules and unsupported selection shapes stop rule loading with an error. See the [engine walkthrough](../docs/engine-walkthrough.md) and [Sigma support](../README.md#sigma-support) for the implemented behavior.
