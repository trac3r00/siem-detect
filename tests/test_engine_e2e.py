"""End-to-end tests: bundled rules over fixtures produce expected verdicts."""
from pathlib import Path

from siem_detect.sigma import load_rules
from siem_detect.engine import Engine
from siem_detect.logsource import parse_log

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
FIX = ROOT / "tests" / "fixtures"


def scan(fixture, fmt="auto"):
    rules = load_rules(RULES)
    parsed = parse_log(FIX / fixture, fmt=fmt)
    return Engine(rules).scan(parsed.events, logsource=parsed.logsource)


def test_bundled_rules_all_load():
    rules = load_rules(RULES)
    assert len(rules) >= 12
    # every rule has an id, level and at least one selection compiled
    for r in rules:
        assert r.id and r.level
        assert r._condition is not None


def test_auth_attack_flags_bruteforce_and_revshell():
    rep = scan("auth_attack.log")
    assert rep.verdict in ("high", "critical", "suspicious")
    titles = {d.rule_title for d in rep.detections}
    assert any("SSH" in t for t in titles)
    assert any("Reverse Shell" in t for t in titles)
    # ATT&CK mapping surfaced
    techniques = rep.technique_counts()
    assert any(t.startswith("T1110") for t in techniques)


def test_auth_benign_is_clean():
    rep = scan("auth_benign.log")
    # benign log: no brute force, no revshell. Allow at most low-noise only.
    high = [d for d in rep.detections if d.weight >= 4]
    assert not high, f"benign log raised high severity: {[d.rule_title for d in high]}"


def test_nginx_attack_flags_web_exploits():
    rep = scan("nginx_attack.log")
    titles = {d.rule_title for d in rep.detections}
    assert any("SQL Injection" in t for t in titles)
    assert any("Traversal" in t for t in titles)
    assert any("Web Shell" in t for t in titles)


def test_windows_sysmon_flags_ps_and_lsass():
    rep = scan("windows_sysmon.jsonl")
    titles = {d.rule_title for d in rep.detections}
    assert any("PowerShell" in t for t in titles)
    assert any("LSASS" in t for t in titles)
    assert rep.verdict == "critical"


def test_cloudtrail_flags_defense_evasion():
    rep = scan("cloudtrail.jsonl")
    titles = {d.rule_title for d in rep.detections}
    assert any("CloudTrail" in t for t in titles)
    assert any("Root" in t for t in titles)


def test_logsource_filtering_scopes_rules():
    # nginx events should not trip windows/linux-auth rules
    rep = scan("nginx_attack.log")
    for d in rep.detections:
        assert "webserver" in d.source_path or "web" in d.source_path


def test_report_serialization_roundtrip():
    rep = scan("windows_sysmon.jsonl")
    d = rep.to_dict()
    assert d["verdict"] == "critical"
    assert d["events_scanned"] >= 3
    md = rep.to_markdown()
    assert "verdict" in md.lower()
    assert "MITRE ATT&CK" in md
    js = rep.to_json()
    assert '"verdict"' in js
