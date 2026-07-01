"""Tests for log parsers (logsource)."""
from pathlib import Path

from siem_detect.logsource import parse_log, iter_events

FIX = Path(__file__).parent / "fixtures"


def test_auth_log_parses_sshd_fields():
    parsed = parse_log(FIX / "auth_attack.log")
    assert parsed.fmt == "auth"
    assert parsed.logsource == {"product": "linux", "service": "auth"}
    fails = [e for e in parsed.events if e.get("outcome") == "failure"]
    assert fails, "expected at least one failed auth event"
    assert any(e.get("src_ip") == "203.0.113.9" for e in fails)


def test_nginx_log_parses_status_and_uri():
    parsed = parse_log(FIX / "nginx_attack.log")
    assert parsed.fmt == "nginx"
    assert parsed.logsource == {"category": "webserver"}
    assert all(isinstance(e["status"], int) for e in parsed.events)
    assert any("union" in e["uri"] for e in parsed.events)


def test_evtx_json_flattens_system_and_eventdata():
    parsed = parse_log(FIX / "windows_sysmon.jsonl")
    assert parsed.fmt in ("evtx-json", "jsonl")
    evids = [e.get("EventID") for e in parsed.events]
    assert 1 in evids and 4728 in evids
    ps = [e for e in parsed.events if e.get("EventID") == 1]
    assert any("powershell" in str(e.get("Image", "")).lower() for e in ps)


def test_cloudtrail_jsonl():
    parsed = parse_log(FIX / "cloudtrail.jsonl")
    names = [e.get("eventName") for e in parsed.events]
    assert "StopLogging" in names
    assert "ConsoleLogin" in names


def test_raw_text_input():
    text = '203.0.113.1 - - [01/Jul/2026:00:00:00 +0000] "GET /a HTTP/1.1" 200 10 "-" "x"'
    events = list(iter_events(text, fmt="nginx"))
    assert events and events[0]["status"] == 200
