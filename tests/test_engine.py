"""Tests for detector/engine.py - loading rules and matching single events."""

import pytest

from detector.engine import (RuleError, detect_event, field_matches, get_field,
                             load_rules, matches, run_detection)
from tests.conftest import RULES_DIR


# ---------------------------------------------------------------------------
# Field operators
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("op, value, expected, result", [
    ("equals",     "Security",           "security",   True),   # case-insensitive
    ("equals",     "Security",           "Secur",      False),
    ("contains",   "C:\\Users\\Public\\x", "\\users\\public\\", True),
    ("contains",   "notepad.exe",        "powershell", False),
    ("startswith", "powershell -enc",    "POWERSHELL", True),
    ("startswith", "cmd /c powershell",  "powershell", False),
    ("endswith",   "evil.ps1",           ".ps1",       True),
    ("endswith",   "evil.ps1.txt",       ".ps1",       False),
])
def test_each_operator(op, value, expected, result):
    assert field_matches(value, op, expected) is result


def test_list_of_values_means_or():
    assert field_matches("10", "equals", [10, 12])          # ints compared as text
    assert field_matches("12", "equals", [10, 12])
    assert not field_matches("3", "equals", [10, 12])


def test_missing_value_never_matches():
    assert not field_matches(None, "contains", "")


def test_get_field_reads_data_and_top_level(make_event):
    event = make_event(4624, computer="HOST1", IpAddress="1.2.3.4")
    assert get_field(event, "IpAddress") == "1.2.3.4"
    assert get_field(event, "computer") == "HOST1"
    assert get_field(event, "DoesNotExist") is None


# ---------------------------------------------------------------------------
# Selections (the 'detection' block)
# ---------------------------------------------------------------------------

def test_matches_event_id_and_channel(make_event):
    selection = {"event_id": [1102], "channel": "Security"}
    assert matches(selection, make_event(1102))
    assert not matches(selection, make_event(4624))
    assert not matches(selection, make_event(1102, channel="System"))


def test_all_fields_must_match(make_event):
    selection = {"event_id": [4624], "fields": {"LogonType|equals": [10],
                                                "IpAddress|startswith": "10."}}
    assert matches(selection, make_event(4624, LogonType="10", IpAddress="10.1.1.1"))
    assert not matches(selection, make_event(4624, LogonType="3", IpAddress="10.1.1.1"))
    assert not matches(selection, make_event(4624, LogonType="10", IpAddress="8.8.8.8"))


def test_exclude_drops_event(make_event):
    selection = {"event_id": [4624], "exclude": {"IpAddress|equals": ["-", "127.0.0.1"]}}
    assert matches(selection, make_event(4624, IpAddress="10.0.0.1"))
    assert not matches(selection, make_event(4624, IpAddress="127.0.0.1"))
    # A missing field cannot match an exclude condition, so the event stays.
    assert matches(selection, make_event(4624))


# ---------------------------------------------------------------------------
# Rules and alerts
# ---------------------------------------------------------------------------

SERVICE_RULE = {
    "title": "Suspicious Service", "id": "t-1", "level": "high", "mitre": "T1543.003",
    "detection": {"event_id": [7045], "fields": {"ImagePath|contains": ["\\temp\\"]}},
    "show": ["ServiceName", "ImagePath"],
}


def test_detect_event_builds_alert(make_event):
    event = make_event(7045, channel="System", ServiceName="x",
                       ImagePath="C:\\Windows\\Temp\\x.exe")
    [alert] = detect_event(event, [SERVICE_RULE])
    assert alert["rule"] == "Suspicious Service"
    assert alert["rule_id"] == "t-1"
    assert alert["level"] == "high"
    assert alert["mitre"] == "T1543.003"
    assert alert["computer"] == "PC01"
    assert alert["details"] == {"ServiceName": "x", "ImagePath": "C:\\Windows\\Temp\\x.exe"}


def test_correlation_rules_are_skipped_by_run_detection(make_event):
    rule = dict(SERVICE_RULE, correlation={"type": "threshold", "threshold": 1})
    event = make_event(7045, ImagePath="C:\\temp\\x.exe")
    assert run_detection([event], [rule]) == []


def test_project_rules_load_and_are_valid():
    rules = load_rules(RULES_DIR)
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids)) >= 10
    mitre = {r["mitre"] for r in rules}
    assert {"T1110", "T1070.001", "T1543.003", "T1053.005", "T1021.001"} <= mitre


def test_project_rules_detect_known_attacks(make_event):
    rules = load_rules(RULES_DIR)
    attacks = [
        make_event(1102),
        make_event(7045, channel="System", ImagePath="powershell -enc AAAA"),
        make_event(4698, TaskContent="<Command>C:\\Users\\Public\\a.exe</Command>"),
        make_event(4624, LogonType="10", IpAddress="10.0.0.9", TargetUserName="bob"),
    ]
    found = {a["mitre"] for a in run_detection(attacks, rules)}
    assert found == {"T1070.001", "T1543.003", "T1053.005", "T1021.001"}

    # Benign events must not raise alerts.
    benign = [make_event(7045, channel="System", ImagePath="C:\\Program Files\\App\\svc.exe"),
              make_event(4624, LogonType="10", IpAddress="127.0.0.1"),
              make_event(4624, LogonType="3", IpAddress="10.0.0.9")]
    assert run_detection(benign, rules) == []


def write_rule(tmp_path, text):
    (tmp_path / "r.yml").write_text(text, encoding="utf-8")
    return str(tmp_path)


def test_load_rules_multiple_documents(tmp_path):
    folder = write_rule(tmp_path, """
title: A
id: a
level: low
mitre: T1
detection: {event_id: [1]}
---
title: B
id: b
level: high
mitre: T2
detection: {event_id: [2]}
""")
    assert [r["id"] for r in load_rules(folder)] == ["a", "b"]


@pytest.mark.parametrize("text, message", [
    ("title: A\nid: a\nlevel: low\nmitre: T1\n", "missing 'detection'"),
    ("title: A\nid: a\nlevel: extreme\nmitre: T1\ndetection: {}\n", "unknown level"),
    ("title: A\nid: a\nlevel: low\nmitre: T1\ndetection: {fields: {X|regex: a}}\n",
     "unknown operator"),
    ("title: A\nid: a\nlevel: low\nmitre: T1\ndetection: {}\ncorrelation: {type: sequence}\n",
     "followed_by"),
    ("title: [unclosed\n", "invalid YAML"),
])
def test_invalid_rules_raise(tmp_path, text, message):
    with pytest.raises(RuleError, match=message):
        load_rules(write_rule(tmp_path, text))


def test_missing_rules_dir():
    with pytest.raises(RuleError):
        load_rules("this/folder/does/not/exist")


# ---------------------------------------------------------------------------
# Optional 'recommendation' text
# ---------------------------------------------------------------------------

def test_alert_carries_recommendation(make_event):
    rule = dict(SERVICE_RULE, recommendation="Stop and delete the service.")
    event = make_event(7045, ImagePath="C:\\temp\\x.exe")
    [alert] = detect_event(event, [rule])
    assert alert["recommendation"] == "Stop and delete the service."


def test_missing_recommendation_is_empty_text(make_event):
    assert "recommendation" not in SERVICE_RULE
    [alert] = detect_event(make_event(7045, ImagePath="C:\\temp\\x.exe"), [SERVICE_RULE])
    assert alert["recommendation"] == ""


def test_recommendation_must_be_text(tmp_path):
    folder = write_rule(tmp_path, "title: A\nid: a\nlevel: low\nmitre: T1\n"
                                  "detection: {}\nrecommendation: [not, text]\n")
    with pytest.raises(RuleError, match="recommendation"):
        load_rules(folder)


def test_every_project_rule_has_a_recommendation():
    for rule in load_rules(RULES_DIR):
        assert rule.get("recommendation", "").strip(), rule["id"]
