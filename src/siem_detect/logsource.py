"""Log source parsers — normalise raw logs into flat event dicts.

Each parser turns a line (or record) of a given log format into a Python dict
whose keys are the field names Sigma rules reference. Every parser also reports
a ``logsource`` descriptor (product/service/category) so the engine can target
only the rules relevant to that log type — mirroring Sigma's own logsource model.

Supported formats:

    jsonl        one JSON object per line (generic / already-structured)
    json         a single JSON array or object
    syslog       RFC3164-ish ``<time> <host> <program>[pid]: <message>``
    auth         Linux /var/log/auth.log (syslog + sshd field extraction)
    nginx        nginx/Apache combined access log
    evtx-json    Windows EVTX exported to JSON (``EventID``, ``Channel``, ...)

Autodetection (``format="auto"``) sniffs the first non-empty lines.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator


@dataclass
class ParsedLog:
    """A parsed log stream: its logsource descriptor + iterable of events."""

    logsource: dict
    events: list[dict]
    fmt: str


LOG_FORMATS = ("auto", "jsonl", "json", "syslog", "auth", "nginx", "evtx-json")


# --------------------------------------------------------------------------- #
# Individual line parsers
# --------------------------------------------------------------------------- #

_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s[\d:]+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>[\w.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# nginx/Apache "combined" log format.
_NGINX_RE = re.compile(
    r"^(?P<src_ip>\S+)\s+\S+\s+(?P<remote_user>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r"(?P<status>\d{3})\s+(?P<bytes>\d+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# sshd auth messages worth structuring into fields.
_SSHD_FAIL_RE = re.compile(
    r"(?P<result>Failed|Accepted)\s+(?P<method>\S+)\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<src_ip>[\d.:a-fA-F]+)\s+port\s+(?P<src_port>\d+)"
)
_SSHD_INVALID_RE = re.compile(r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>[\d.:a-fA-F]+)")


def parse_syslog_line(line: str) -> dict | None:
    m = _SYSLOG_RE.match(line.rstrip("\n"))
    if not m:
        return None
    return {k: v for k, v in m.groupdict().items() if v is not None}


def parse_auth_line(line: str) -> dict | None:
    ev = parse_syslog_line(line)
    if ev is None:
        # Some auth lines are bare; keep the raw text searchable.
        stripped = line.rstrip("\n")
        return {"message": stripped} if stripped else None
    msg = ev.get("message", "")
    m = _SSHD_FAIL_RE.search(msg)
    if m:
        ev.update({k: v for k, v in m.groupdict().items() if v is not None})
        ev["outcome"] = "failure" if ev.get("result") == "Failed" else "success"
    else:
        m2 = _SSHD_INVALID_RE.search(msg)
        if m2:
            ev.update(m2.groupdict())
            ev["outcome"] = "failure"
            ev["invalid_user"] = True
    return ev


def parse_nginx_line(line: str) -> dict | None:
    m = _NGINX_RE.match(line.rstrip("\n"))
    if not m:
        return None
    ev = m.groupdict()
    # Coerce numeric fields so Sigma numeric modifiers (gt/lt) work.
    if ev.get("status"):
        ev["status"] = int(ev["status"])
    if ev.get("bytes") and ev["bytes"] != "-":
        ev["bytes"] = int(ev["bytes"])
    return {k: v for k, v in ev.items() if v is not None}


def parse_json_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if isinstance(obj, dict):
        return _flatten_evtx(obj)
    return None


def _flatten_evtx(obj: dict) -> dict:
    """Flatten common Windows EVTX-as-JSON shapes into flat Sigma fields.

    Handles the widely-used ``{"Event": {"System": {...}, "EventData": {...}}}``
    layout (evtx_dump / EvtxECmd / winlogbeat) by hoisting System + EventData
    keys to the top level, while leaving already-flat records untouched.
    """
    event = obj.get("Event") if isinstance(obj.get("Event"), dict) else None
    if not event:
        return obj
    flat: dict = {}
    system = event.get("System", {})
    if isinstance(system, dict):
        for k, v in system.items():
            if isinstance(v, dict):
                # e.g. {"EventID": {"#text": "4688"}} or {"Provider": {"Name": ...}}
                if "#text" in v:
                    flat[k] = v["#text"]
                elif "Name" in v:
                    flat[k] = v["Name"]
                else:
                    flat[k] = v
            else:
                flat[k] = v
    data = event.get("EventData", {})
    if isinstance(data, dict):
        # winlogbeat style: {"Data": [{"Name": "X", "#text": "Y"}, ...]}
        inner = data.get("Data")
        if isinstance(inner, list):
            for item in inner:
                if isinstance(item, dict) and "Name" in item:
                    flat[item["Name"]] = item.get("#text", item.get("Value"))
        else:
            flat.update(data)
    # Coerce EventID to int when possible for numeric comparisons.
    if "EventID" in flat:
        try:
            flat["EventID"] = int(flat["EventID"])
        except (TypeError, ValueError):
            pass
    return flat


# --------------------------------------------------------------------------- #
# Format autodetection
# --------------------------------------------------------------------------- #

def _detect_format(sample_lines: list[str]) -> str:
    for line in sample_lines:
        s = line.strip()
        if not s:
            continue
        if s.startswith("{") or s.startswith("["):
            try:
                obj = json.loads(s)
                if isinstance(obj, dict) and (
                    "EventID" in obj or "Event" in obj or "Channel" in obj
                ):
                    return "evtx-json"
                return "jsonl"
            except json.JSONDecodeError:
                pass
        if _NGINX_RE.match(s):
            return "nginx"
        if _SSHD_FAIL_RE.search(s) or "sshd" in s:
            return "auth"
        if _SYSLOG_RE.match(s):
            return "syslog"
    return "jsonl"


_LINE_PARSERS = {
    "jsonl": parse_json_line,
    "evtx-json": parse_json_line,
    "syslog": parse_syslog_line,
    "auth": parse_auth_line,
    "nginx": parse_nginx_line,
}

_LOGSOURCE = {
    "jsonl": {},
    "json": {},
    "evtx-json": {"product": "windows"},
    "syslog": {"product": "linux"},
    "auth": {"product": "linux", "service": "auth"},
    "nginx": {"category": "webserver"},
}


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def iter_events(text: str, fmt: str = "auto") -> Iterator[dict]:
    """Yield parsed events from raw log ``text`` in the given format."""
    if fmt == "json":
        obj = json.loads(text)
        records = obj if isinstance(obj, list) else [obj]
        for rec in records:
            if isinstance(rec, dict):
                yield _flatten_evtx(rec)
        return

    lines = text.splitlines()
    if fmt == "auto":
        fmt = _detect_format(lines[:50])
    parser = _LINE_PARSERS.get(fmt)
    if parser is None:
        raise ValueError(f"unsupported log format: {fmt!r} (choose from {LOG_FORMATS})")
    for line in lines:
        ev = parser(line)
        if ev is not None:
            # Keep raw line for keyword rules & analyst context.
            ev.setdefault("_raw", line.rstrip("\n"))
            yield ev


def _safe_exists(p: Path) -> bool:
    """Path.exists() that never raises on odd/oversized names."""
    try:
        return p.exists()
    except (OSError, ValueError):
        return False


def parse_log(path_or_text: str | Path, fmt: str = "auto") -> ParsedLog:
    """Parse a log file (or raw string) into a :class:`ParsedLog`.

    If ``path_or_text`` is an existing file path it is read; otherwise it is
    treated as the raw log text directly.
    """
    text: str
    raw = str(path_or_text)
    # Treat as a path only for short, single-line, newline-free strings.
    looks_like_path = (
        isinstance(path_or_text, Path)
        or (len(raw) < 4096 and "\n" not in raw and "\x00" not in raw)
    )
    p = Path(path_or_text) if looks_like_path else None
    if p is not None and _safe_exists(p):
        text = p.read_text(encoding="utf-8", errors="replace")
    else:
        text = raw

    if fmt == "auto":
        fmt = _detect_format(text.splitlines()[:50])
    events = list(iter_events(text, fmt))
    return ParsedLog(logsource=dict(_LOGSOURCE.get(fmt, {})), events=events, fmt=fmt)
