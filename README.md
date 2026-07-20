# siem-detect

Run Sigma detection rules directly against common log formats and produce MITRE ATT&CK-mapped reports.

[![Tests](https://github.com/trac3r00/siem-detect/actions/workflows/tests.yml/badge.svg)](https://github.com/trac3r00/siem-detect/actions/workflows/tests.yml)
[![Security](https://github.com/trac3r00/siem-detect/actions/workflows/security.yml/badge.svg)](https://github.com/trac3r00/siem-detect/actions/workflows/security.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Overview

`siem-detect` is a dependency-light Python detection engine for evaluating Sigma rules against local log data. It parses supported text and JSON formats into structured events, limits rules by Sigma `logsource` where possible, evaluates a practical subset of Sigma matching semantics, and emits Markdown, JSON, or JSON Lines reports.

The engine executes rules in-process. It does not convert rules into queries for SIEM backends and does not implement multi-event correlation.

## Features

- Reads JSON, JSON Lines, syslog, Linux authentication logs, nginx/Apache combined access logs, and Windows EVTX exported as JSON.
- Auto-detects the input format from the first 50 lines, or accepts an explicit format.
- Evaluates field selections, keyword selections, common field modifiers, dotted JSON paths, and boolean conditions.
- Filters rules by `category`, `product`, and `service` logsource fields when the parser identifies them.
- Produces Markdown, JSON, or JSON Lines output with severity and MITRE ATT&CK metadata.
- Supports severity filtering and a non-zero exit status for CI gates.
- Includes 14 experimental rules for Linux, web server, Windows, and AWS CloudTrail events.

## Architecture

```text
log file or stdin                     Sigma YAML file or directory
        |                                         |
        v                                         v
  logsource.py                               sigma.py
  parse + normalize                 load rules + compile matchers
        |                                         |
        +-------------------+---------------------+
                            v
                         engine.py
                 logsource filter + event scan
                            |
                            v
               Markdown, JSON, or JSON Lines
```

The command-line interface in `cli.py` coordinates parsing, rule loading, scanning, output formatting, and exit status. See [Engine walkthrough](docs/engine-walkthrough.md) for the matching flow in detail.

## Installation

Python 3.11 or later is required. The only runtime dependency is [PyYAML](https://pyyaml.org/).

Install from a local clone:

```bash
git clone https://github.com/trac3r00/siem-detect.git
cd siem-detect
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

On Windows PowerShell, activate the environment with `.venv\Scripts\Activate.ps1`.

## Usage

Scan a log with the bundled rules and Markdown output:

```bash
siem-detect tests/fixtures/nginx_attack.log
```

Choose the input and output formats explicitly:

```bash
siem-detect access.log --format nginx --output json
```

Read JSON Lines from standard input:

```bash
siem-detect - --format jsonl < events.jsonl
```

Use a custom rule file or recursively load rules from a directory:

```bash
siem-detect app.log --rules ./my-rules
```

Report only high and critical detections:

```bash
siem-detect app.log --min-level high
```

Fail with exit status `1` when a high or critical detection is reported:

```bash
siem-detect audit.jsonl --fail-on high
```

Run `siem-detect --help` for the complete command reference.

### Supported input formats

| Value | Input | Assigned logsource |
| --- | --- | --- |
| `auto` | Detect from the first 50 lines | Determined by the detected format |
| `jsonl` | One JSON object per line | None |
| `json` | One JSON object or an array of objects | None |
| `syslog` | RFC 3164-style syslog lines | `product: linux` |
| `auth` | Linux authentication log lines, including `sshd` fields | `product: linux`, `service: auth` |
| `nginx` | nginx/Apache combined access log lines | `category: webserver` |
| `evtx-json` | Windows event records represented as JSON | `product: windows` |

Generic JSON inputs do not receive a logsource descriptor, so logsource filtering does not exclude rules for those inputs. Use `--format evtx-json` when generic JSON auto-detection cannot identify Windows event data.

## Configuration

`siem-detect` does not read environment variables or a standalone configuration file. Runtime behavior is controlled through command-line options:

| Option | Purpose | Default |
| --- | --- | --- |
| `-f`, `--format` | Select an input parser | `auto` |
| `-r`, `--rules` | Load one Sigma YAML file or a directory recursively | Repository `rules/` directory |
| `-o`, `--output` | Select `markdown`, `json`, or `jsonl` output | `markdown` |
| `--no-logsource-filter` | Evaluate every rule against every event | Disabled |
| `--min-level` | Keep detections at or above a severity | No minimum |
| `--fail-on` | Exit `1` for detections at or above a severity | Disabled |

Severity values are `informational`, `low`, `medium`, `high`, and `critical`. When both `--min-level` and `--fail-on` are set, the exit check applies to the detections that remain after filtering.

## Sigma support

The implemented Sigma subset includes:

- `logsource` targeting by `category`, `product`, and `service`;
- mapping selections with implicit AND, list selections with OR, field value lists with OR, and keyword lists;
- `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`, `base64`, `base64offset`, `windash`, `lt`, `lte`, `gt`, `gte`, `cased`, and `exists` modifiers;
- exact values, `*` and `?` wildcards, list-valued event fields, and dotted paths into nested JSON;
- `and`, `or`, `not`, parentheses, `1 of`, and `all of` conditions.

Rule correlation, backend query conversion, and field-mapping pipelines are not implemented. See [Detection rules](rules/README.md) before adding custom rules.

## Bundled rules

| Platform | Coverage |
| --- | --- |
| Linux | External SSH authentication failures, invalid SSH users, reverse-shell command patterns, and sudo privilege escalation |
| Web | SQL injection, path traversal/local file inclusion, web shell access, and authentication failure responses |
| Windows | Suspicious PowerShell commands, LSASS access, and privileged group membership changes |
| AWS | CloudTrail logging changes, root console use, and IAM access key creation |

All 14 bundled rules have `status: experimental`. Review and tune them for the fields and expected activity in your environment before operational use. Despite names that refer to brute force or high rates, the engine evaluates one event at a time and does not aggregate events over a time window.

## Development

Install development dependencies and run the 30-test suite:

```bash
python -m pip install -e ".[dev]"
pytest -q
```

The test workflow runs on Python 3.11 and 3.12 for pushes to `main` and for pull requests. A separate workflow scans resolved dependencies with OSV-Scanner on pushes to `main`, pull requests, and a weekly schedule.

## Project structure

```text
src/siem_detect/   CLI, parsers, Sigma evaluator, and reporting engine
rules/             Bundled Sigma YAML rules grouped by platform
tests/             Unit, parser, and end-to-end tests with log fixtures
docs/              Design rationale, engine walkthrough, and release guidance
```

## License

Licensed under the [MIT License](LICENSE).
