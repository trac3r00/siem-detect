# Project health report

_Reviewed on 2026-07-19 by Codex._

## Executive summary

The project is a small Python package with clear module boundaries, a single runtime dependency, automated tests, and CI coverage for Python 3.11 and 3.12. Its implementation and test surface are appropriate for the current command-line scope.

The main operational risks are the intentionally limited Sigma implementation, experimental bundled rules, and the absence of a published release workflow or version history. These constraints should remain explicit in user-facing documentation. An architectural rebuild is not warranted.

## Project map

| Area | Current implementation |
| --- | --- |
| Runtime | Python 3.11 or later |
| Packaging | `pyproject.toml` with setuptools |
| Runtime dependency | PyYAML |
| Entry point | `siem-detect = siem_detect.cli:main` |
| Parsing | `src/siem_detect/logsource.py` |
| Rule evaluation | `src/siem_detect/sigma.py` |
| Scanning and reports | `src/siem_detect/engine.py` |
| Bundled content | 14 Sigma YAML rules under `rules/` |
| Tests | 30 pytest tests across unit, parser, and end-to-end coverage |
| CI | Test matrix and OSV dependency scanning under `.github/workflows/` |
| External services | None at runtime |
| Data storage | None |

## Current strengths

- The CLI flags, parser formats, package entry point, and dependency metadata are declared in source and `pyproject.toml`.
- Parser, matcher, report serialization, bundled-rule loading, and fixture-based scans have automated coverage.
- The test workflow runs the complete pytest suite and a CLI smoke test on Python 3.11 and 3.12.
- The security workflow resolves dependencies and scans them with OSV-Scanner on pull requests, pushes to `main`, and weekly.
- The package has no runtime network, database, authentication, or secret-management requirements.
- Rule loading accepts individual YAML files and recursively searches directories.

## Risks and gaps

| Area | Risk | Evidence | Recommended action |
| --- | --- | --- | --- |
| Sigma compatibility | Users may assume complete Sigma support. | `sigma.py` implements a documented subset and skips documents without `detection`. | Keep the support matrix and exclusions visible in the README. |
| Detection interpretation | Rule names can imply aggregation that the engine does not perform. | `Engine.scan()` evaluates each rule against each event independently. | State the event-by-event behavior in rule documentation and validate rules against local telemetry. |
| Bundled rules | Untuned rules may produce false positives or miss environment-specific fields. | All 14 bundled rules declare `status: experimental`. | Review and tune rules before operational use. |
| Packaging | The default rule path depends on the source-tree layout. | `cli.py` resolves the default to the repository-level `rules/` directory, while package data is empty. | Validate wheel installation behavior before publishing a package release. |
| Release process | Releases are manual and there is no established version history. | The repository has no tags or release workflow; the package version is `0.1.0`. | Add release automation only when the project is ready to publish artifacts. |
| Static analysis | No formatter, linter, or type checker is configured. | `pyproject.toml` defines pytest settings but no static-analysis tools. | Add checks when code changes justify the maintenance cost. |

## Verification commands

From an activated development environment:

```bash
python -m pip install -e ".[dev]"
pytest -q
siem-detect tests/fixtures/nginx_attack.log --output json
```

CI definitions are in [`.github/workflows/tests.yml`](../.github/workflows/tests.yml) and [`.github/workflows/security.yml`](../.github/workflows/security.yml).

## Recommendation

Continue with incremental maintenance. Preserve the current module boundaries, add regression tests for subtle matcher or parser changes, and treat broader Sigma compatibility or distributable package data as explicit design work rather than incidental extensions.
