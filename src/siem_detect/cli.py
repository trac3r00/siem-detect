"""Command-line interface for siem-detect."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .sigma import load_rules, SigmaParseError
from .engine import Engine
from .logsource import parse_log, LOG_FORMATS

_DEFAULT_RULES = Path(__file__).resolve().parent.parent.parent / "rules"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="siem-detect",
        description="Run Sigma detection rules over logs and report ATT&CK-mapped hits.",
    )
    p.add_argument("logfile", help="path to a log file, or '-' to read stdin")
    p.add_argument(
        "-f", "--format", default="auto", choices=LOG_FORMATS,
        help="log format (default: auto-detect)",
    )
    p.add_argument(
        "-r", "--rules", default=str(_DEFAULT_RULES),
        help="Sigma rule file or directory (default: bundled ruleset)",
    )
    p.add_argument(
        "-o", "--output", choices=("markdown", "json", "jsonl"), default="markdown",
        help="report format (default: markdown)",
    )
    p.add_argument(
        "--no-logsource-filter", action="store_true",
        help="run every rule against every event (skip logsource targeting)",
    )
    p.add_argument(
        "--min-level",
        choices=("informational", "low", "medium", "high", "critical"),
        help="only report detections at or above this severity",
    )
    p.add_argument(
        "--fail-on",
        choices=("informational", "low", "medium", "high", "critical"),
        help="exit non-zero if any detection at/above this level fires (for CI)",
    )
    p.add_argument("--version", action="version", version=f"siem-detect {__version__}")
    return p


_ORDER = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    # Load rules
    try:
        rules = load_rules(args.rules)
    except SigmaParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not rules:
        print(f"error: no Sigma rules found under {args.rules!r}", file=sys.stderr)
        return 2

    # Read log
    if args.logfile == "-":
        text = sys.stdin.read()
        parsed = parse_log(text, fmt=args.format)
    else:
        if not Path(args.logfile).exists():
            print(f"error: log file not found: {args.logfile}", file=sys.stderr)
            return 2
        parsed = parse_log(args.logfile, fmt=args.format)

    engine = Engine(rules, match_logsource=not args.no_logsource_filter)
    report = engine.scan(parsed.events, logsource=parsed.logsource)

    # Optional min-level filtering
    if args.min_level:
        floor = _ORDER[args.min_level]
        report.detections = [d for d in report.detections if d.weight >= floor]

    # Emit
    if args.output == "json":
        print(report.to_json())
    elif args.output == "jsonl":
        for d in report.detections:
            print(_json_line(d))
    else:
        print(report.to_markdown())

    # CI gate
    if args.fail_on:
        floor = _ORDER[args.fail_on]
        if any(d.weight >= floor for d in report.detections):
            return 1
    return 0


def _json_line(detection) -> str:
    import json
    from dataclasses import asdict
    return json.dumps(asdict(detection), default=str)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
