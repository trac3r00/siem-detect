"""siem-detect — a small, dependency-light Sigma detection engine for logs.

Feed it JSON/JSONL, syslog, nginx/Apache access logs, Linux auth logs, or
Windows EVTX-as-JSON; match them against Sigma rules; get analyst-ready
detections mapped to MITRE ATT&CK.

Public API:
    from siem_detect import Engine, load_rules, parse_log
"""
from __future__ import annotations

__version__ = "0.1.0"

from .sigma import SigmaRule, SigmaParseError, load_rules, load_rule_file
from .engine import Engine, Detection
from .logsource import parse_log, iter_events, LOG_FORMATS

__all__ = [
    "__version__",
    "SigmaRule",
    "SigmaParseError",
    "load_rules",
    "load_rule_file",
    "Engine",
    "Detection",
    "parse_log",
    "iter_events",
    "LOG_FORMATS",
]
