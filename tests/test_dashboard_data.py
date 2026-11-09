"""Tests for detector/dashboard_data.py (no Streamlit or pandas needed)."""

from datetime import datetime, timezone

import pytest

from detector import dashboard_data as dd
from detector.correlation import get_settings
from detector.engine import load_rules
from tests.conftest import RULES_DIR


def alert(level="high", minute=0, day=1, rule="Rule A", mitre="T1110",
          computer="PC01", **details):
    return {"time": f"2024-01-{day:02d}T10:{minute:02d}:00+00:00", "level": level,
            "rule": rule, "rule_id": rule.lower().replace(" ", "-"), "mitre": mitre,
            "computer": computer, "description": "", "details": details}


ALERTS = [
    alert("high", 5, rule="Log Cleared", mitre="T1070.001", SubjectUserName="eve"),
    alert("critical", 1, rule="Brute Force Succeeded", computer="DC01", IpAddress="10.0.0.9"),
    alert("low", 3, rule="RDP Logon", mitre="T1021.001", computer="PC02"),
]


# --- thresholds -------------------------------------------------------------

def test_default_thresholds_come_from_rules_and_config():
    rules = load_rules(RULES_DIR)
    assert dd.default_thresholds(rules, {}) == {
        "bf_count": 5, "bf_minutes": 10, "rdp_hosts": 3, "rdp_minutes": 60}
    config = {"correlation": {"rule-007": {"threshold": 9, "timeframe": "2h"}}}
    defaults = dd.default_thresholds(rules, config)
    assert (defaults["bf_count"], defaults["bf_minutes"]) == (9, 120)


def test_build_config_applies_to_every_rule_in_group():
    base = {"correlation": {"rule-007": {"threshold": 5}}, "other": 1}
    config = dd.build_config(base, 7, 15, 4, 30)
    assert base["correlation"]["rule-007"] == {"threshold": 5}       # input not modified
    assert config["other"] == 1
    for rule_id in dd.BRUTE_FORCE_RULES:
        assert config["correlation"][rule_id] == {"threshold": 7, "timeframe": "15m"}
    for rule_id in dd.RDP_RULES:
        assert config["correlation"][rule_id] == {"threshold": 4, "timeframe": "30m"}


def test_built_config_is_understood_by_correlation():
    rules = {r["id"]: r for r in load_rules(RULES_DIR)}
    config = dd.build_config({}, 7, 90, 4, 30)
    s = get_settings(rules["rule-008"], config)
    assert s["threshold"] == 7 and s["timeframe"].total_seconds() == 90 * 60


# --- uploads ----------------------------------------------------------------

def test_check_upload():
    good = dd.EVTX_MAGIC + b"rest of file"
    assert dd.check_upload("a.evtx", good) is None
    assert dd.check_upload("A.EVTX", good) is None
    assert "only .evtx" in dd.check_upload("a.exe", good)
    assert "not a valid EVTX" in dd.check_upload("a.evtx", b"MZ\x90\x00")


@pytest.mark.parametrize("name, expected", [
    ("Security.evtx", "Security.evtx"),
    ("../../evil.evtx", "evil.evtx"),
    ("C:\\Windows\\x.evtx", "x.evtx"),
    ("my log (1).evtx", "my_log__1_.evtx"),
    ("...", "upload.evtx"),
])
def test_safe_filename(name, expected):
    assert dd.safe_filename(name) == expected


# --- rows, filters, counts --------------------------------------------------

def test_alert_rows_are_chronological_and_flat():
    rows = dd.alert_rows(ALERTS)
    assert [r["severity"] for r in rows] == ["critical", "low", "high"]
    assert [r["index"] for r in rows] == [0, 1, 2]
    assert rows[0]["details"] == "IpAddress=10.0.0.9"


def test_filter_options():
    options = dd.filter_options(ALERTS)
    assert options["severity"] == ["critical", "high", "low"]
    assert options["computer"] == ["DC01", "PC01", "PC02"]


def test_filters_combine_with_and():
    assert len(dd.filter_alerts(ALERTS)) == 3                              # no filter
    assert [a["rule"] for a in dd.filter_alerts(ALERTS, severities=["low"])] == ["RDP Logon"]
    assert len(dd.filter_alerts(ALERTS, techniques=["T1110"], computers=["PC01"])) == 0
    assert len(dd.filter_alerts(ALERTS, rules=["Log Cleared", "RDP Logon"])) == 2


def test_search_is_case_insensitive_and_covers_details():
    assert [a["rule"] for a in dd.filter_alerts(ALERTS, search="EVE")] == ["Log Cleared"]
    assert len(dd.filter_alerts(ALERTS, search="10.0.0.9")) == 1
    assert dd.filter_alerts(ALERTS, search="nothing-matches") == []


def test_level_and_technique_counts():
    assert dd.level_counts(ALERTS) == {"critical": 1, "high": 1, "medium": 0, "low": 1}
    assert dd.technique_counts(ALERTS)[0] == {"mitre": "T1021.001", "count": 1}
    assert dd.technique_counts(ALERTS + [alert()])[0] == {"mitre": "T1110", "count": 2}
    assert sum(r["count"] for r in dd.technique_counts(ALERTS)) == 3


# --- timeline ---------------------------------------------------------------

def test_timeline_by_minute_for_short_logs():
    unit, rows = dd.timeline_counts(ALERTS + [alert("high", 5)])
    assert unit == "minute"
    high = [r for r in rows if r["severity"] == "high"]
    assert high == [{"time": datetime(2024, 1, 1, 10, 5, tzinfo=timezone.utc),
                     "severity": "high", "count": 2}]


def test_timeline_by_day_for_long_logs():
    unit, rows = dd.timeline_counts([alert(day=1), alert(day=1, minute=30), alert(day=9)])
    assert unit == "day"
    assert [r["count"] for r in rows] == [2, 1]


def test_timeline_empty():
    assert dd.timeline_counts([]) == ("minute", [])


def test_mitre_link():
    assert dd.mitre_link("T1053.005") == "https://attack.mitre.org/techniques/T1053/005/"
    assert dd.mitre_link("T1110") == "https://attack.mitre.org/techniques/T1110/"
    assert dd.mitre_link("javascript:alert(1)") is None
