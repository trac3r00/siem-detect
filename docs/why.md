# Design rationale

Sigma provides a portable YAML format for describing detections, but using a rule commonly involves translating it into a query for a separate analytics backend. `siem-detect` addresses a narrower use case: evaluate supported Sigma rules directly against a local log file without deploying a SIEM or generating backend-specific queries.

## Design goals

### Execute rules directly

The engine compiles supported Sigma selections and conditions into in-process Python matchers. This makes it suitable for local investigation, repeatable fixture checks, and command-line pipelines where the input is already available as a file or standard input.

### Preserve logsource scope

Each parser supplies a Sigma-compatible logsource descriptor when it can identify the source. Before scanning, the engine compares the parser's `category`, `product`, and `service` values with each rule. This prevents clearly incompatible rules from being evaluated against a recognized source.

Generic JSON and JSON Lines inputs do not have a logsource descriptor. In that case, the engine does not exclude rules by logsource.

### Keep runtime dependencies small

The project requires Python 3.11 or later and one runtime dependency, PyYAML. Parsing, matching, reporting, and MITRE ATT&CK tag extraction are implemented in the package.

### Produce pipeline-friendly results

Markdown output provides a readable summary and detection table. JSON contains the complete report and matching events, while JSON Lines emits one detection per line. The `--fail-on` option allows a scan to act as a CI or automation gate at a selected severity.

## Scope boundaries

`siem-detect` evaluates one event at a time. It does not aggregate repeated events, evaluate Sigma correlation rules, convert rules into backend queries, ship logs, or provide storage and alert management. Rule names that mention rates or brute force describe suspicious event types; they do not imply time-window aggregation by the engine.

The supported Sigma syntax is intentionally a subset. See the [README](../README.md#sigma-support) and [engine walkthrough](engine-walkthrough.md) for the implemented matching behavior.
