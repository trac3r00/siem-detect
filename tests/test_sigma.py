"""Unit tests for the Sigma matching engine (field modifiers + conditions)."""
import pytest

from siem_detect.sigma import _build_rule, SigmaParseError


def rule(detection, **meta):
    doc = {"title": meta.get("title", "t"), "id": meta.get("id", "t"),
           "detection": detection}
    doc.update({k: v for k, v in meta.items() if k not in ("title", "id")})
    return _build_rule(doc, "test")


def test_exact_field_and_logic():
    r = rule({"sel": {"a": 1, "b": 2}, "condition": "sel"})
    assert r.matches({"a": 1, "b": 2})
    assert not r.matches({"a": 1, "b": 99})  # AND: both must match


def test_field_list_is_or():
    r = rule({"sel": {"EventID": [4728, 4732, 4756]}, "condition": "sel"})
    assert r.matches({"EventID": 4732})
    assert not r.matches({"EventID": 4}) 


def test_contains_modifier():
    r = rule({"sel": {"msg|contains": "Failed password"}, "condition": "sel"})
    assert r.matches({"msg": "sshd: Failed password for root"})
    assert not r.matches({"msg": "Accepted password"})


def test_contains_all_modifier():
    r = rule({"sel": {"uri|contains|all": ["?dwn=", "&fn="]}, "condition": "sel"})
    assert r.matches({"uri": "/a?dwn=1&fn=x"})
    assert not r.matches({"uri": "/a?dwn=1"})  # missing &fn=


def test_startswith_endswith():
    r = rule({"sel": {"Image|endswith": "\\powershell.exe"}, "condition": "sel"})
    assert r.matches({"Image": "C:\\x\\powershell.exe"})
    assert not r.matches({"Image": "C:\\x\\cmd.exe"})


def test_wildcard_value():
    r = rule({"sel": {"path": "C:\\Users\\*\\evil.exe"}, "condition": "sel"})
    assert r.matches({"path": "C:\\Users\\bob\\evil.exe"})
    assert not r.matches({"path": "C:\\Windows\\evil.exe"})


def test_cidr_modifier():
    r = rule({"sel": {"ip|cidr": ["10.0.0.0/8", "192.168.0.0/16"]}, "condition": "sel"})
    assert r.matches({"ip": "10.5.6.7"})
    assert not r.matches({"ip": "203.0.113.9"})


def test_numeric_modifiers():
    r = rule({"sel": {"bytes|gt": 1000}, "condition": "sel"})
    assert r.matches({"bytes": 5000})
    assert not r.matches({"bytes": 10})


def test_keyword_search():
    r = rule({"keywords": ["history -c", "/dev/tcp/"], "condition": "keywords"})
    assert r.matches({"cmd": "ran history -c"})
    assert r.matches({"blob": {"nested": "bash /dev/tcp/1.2.3.4/4444"}})
    assert not r.matches({"cmd": "ls -la"})


def test_condition_and_not_filter():
    r = rule({
        "selection": {"program": "sshd"},
        "filter": {"ip|cidr": "10.0.0.0/8"},
        "condition": "selection and not filter",
    })
    assert r.matches({"program": "sshd", "ip": "203.0.113.9"})
    assert not r.matches({"program": "sshd", "ip": "10.1.1.1"})


def test_condition_1_of_pattern():
    r = rule({
        "sel_a": {"EventID": 1},
        "sel_b": {"EventID": 4688},
        "condition": "1 of sel_*",
    })
    assert r.matches({"EventID": 1})
    assert r.matches({"EventID": 4688})
    assert not r.matches({"EventID": 9})


def test_condition_all_of_pattern():
    r = rule({
        "sel_a": {"a": 1},
        "sel_b": {"b": 2},
        "condition": "all of sel_*",
    })
    assert r.matches({"a": 1, "b": 2})
    assert not r.matches({"a": 1})


def test_condition_grouping_precedence():
    r = rule({
        "s1": {"a": 1},
        "s2": {"b": 2},
        "f": {"c": 3},
        "condition": "(s1 or s2) and not f",
    })
    assert r.matches({"a": 1})
    assert r.matches({"b": 2})
    assert not r.matches({"a": 1, "c": 3})


def test_dotted_field_path():
    r = rule({"sel": {"userIdentity.type": "Root"}, "condition": "sel"})
    assert r.matches({"userIdentity": {"type": "Root"}})
    assert not r.matches({"userIdentity": {"type": "IAMUser"}})


def test_mitre_extraction():
    r = rule({"sel": {"a": 1}, "condition": "sel"},
             tags=["attack.credential_access", "attack.t1110.001"])
    assert r.mitre_techniques == ["T1110.001"]
    assert r.mitre_tactics == ["credential_access"]


def test_missing_condition_raises():
    with pytest.raises(SigmaParseError):
        _build_rule({"title": "x", "id": "x", "detection": {"sel": {"a": 1}}}, "t")


def test_unknown_selection_in_condition_raises():
    with pytest.raises(SigmaParseError):
        rule({"sel": {"a": 1}, "condition": "nope"}).matches({"a": 1})
