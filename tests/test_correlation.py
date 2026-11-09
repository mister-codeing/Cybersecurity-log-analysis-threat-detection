"""Tests for detector/correlation.py - threshold and sequence detection."""

from datetime import timedelta

import pytest

from detector.correlation import (get_settings, parse_timeframe, run_correlation)
from detector.engine import load_rules
from tests.conftest import RULES_DIR

FAILED_RULE = {
    "title": "Many failed logons", "id": "bf", "level": "medium", "mitre": "T1110",
    "detection": {"event_id": [4625]},
    "correlation": {"type": "threshold", "group_by": ["IpAddress"],
                    "threshold": 5, "timeframe": "10m"},
    "show": ["TargetUserName"],
}

SUCCESS_RULE = {
    "title": "Brute force succeeded", "id": "bf-ok", "level": "critical", "mitre": "T1110",
    "detection": {"event_id": [4625]},
    "correlation": {"type": "sequence", "group_by": ["IpAddress"],
                    "threshold": 5, "timeframe": "10m",
                    "followed_by": {"event_id": [4624]}},
    "show": ["TargetUserName"],
}


def failures(make_event, minutes, ip="10.0.0.9", user="bob"):
    return [make_event(4625, minute=m, IpAddress=ip, TargetUserName=user) for m in minutes]


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("30s", timedelta(seconds=30)), ("10m", timedelta(minutes=10)),
    ("2h", timedelta(hours=2)), ("15", timedelta(minutes=15)), (5, timedelta(minutes=5)),
])
def test_parse_timeframe(text, expected):
    assert parse_timeframe(text) == expected


@pytest.mark.parametrize("bad", ["abc", "0m", "-5m", "10x", 0])
def test_parse_timeframe_rejects_bad_values(bad):
    with pytest.raises(ValueError):
        parse_timeframe(bad)


def test_settings_priority_rule_then_config_then_cli():
    assert get_settings(FAILED_RULE)["threshold"] == 5
    config = {"correlation": {"bf": {"threshold": 8, "timeframe": "20m"}}}
    s = get_settings(FAILED_RULE, config)
    assert (s["threshold"], s["timeframe"]) == (8, timedelta(minutes=20))
    s = get_settings(FAILED_RULE, config, {"threshold": 3, "timeframe": None})
    assert (s["threshold"], s["timeframe"]) == (3, timedelta(minutes=20))


# ---------------------------------------------------------------------------
# Threshold
# ---------------------------------------------------------------------------

def test_threshold_reached(make_event):
    [alert] = run_correlation(failures(make_event, range(5)), [FAILED_RULE])
    assert alert["level"] == "medium"
    assert alert["details"]["IpAddress"] == "10.0.0.9"
    assert alert["details"]["event_count"] == 5
    assert alert["time"] == "2024-01-01T10:00:00+00:00"       # first event


def test_threshold_not_reached(make_event):
    assert run_correlation(failures(make_event, range(4)), [FAILED_RULE]) == []


def test_events_outside_window_do_not_count(make_event):
    # 5 failures, but spread over 40 minutes (window is 10 minutes).
    assert run_correlation(failures(make_event, [0, 10, 20, 30, 40]), [FAILED_RULE]) == []


def test_long_attack_gives_one_alert(make_event):
    alerts = run_correlation(failures(make_event, range(30)), [FAILED_RULE])
    assert len(alerts) == 1
    assert alerts[0]["details"]["event_count"] == 30


def test_groups_are_separate(make_event):
    events = failures(make_event, range(3), ip="1.1.1.1") + \
             failures(make_event, range(3), ip="2.2.2.2")
    assert run_correlation(events, [FAILED_RULE]) == []      # 3 + 3, not 6


def test_show_fields_list_distinct_values(make_event):
    events = [make_event(4625, minute=m, IpAddress="1.1.1.1", TargetUserName=f"user{m % 2}")
              for m in range(5)]
    [alert] = run_correlation(events, [FAILED_RULE])
    assert alert["details"]["TargetUserName"] == "user0, user1"


def test_distinct_counts_different_values(make_event):
    rule = {**FAILED_RULE, "id": "hosts",
            "detection": {"event_id": [4624]},
            "correlation": {"type": "threshold", "group_by": ["TargetUserName"],
                            "distinct": "computer", "threshold": 3, "timeframe": "60m"}}
    same_host = [make_event(4624, minute=m, computer="H1", TargetUserName="adm") for m in range(5)]
    assert run_correlation(same_host, [rule]) == []
    many_hosts = [make_event(4624, minute=m, computer=f"H{m}", TargetUserName="adm")
                  for m in range(3)]
    [alert] = run_correlation(many_hosts, [rule])
    assert alert["details"]["distinct_computer"].startswith("3:")


# ---------------------------------------------------------------------------
# Sequence
# ---------------------------------------------------------------------------

def test_sequence_failures_then_success(make_event):
    events = failures(make_event, range(5)) + \
        [make_event(4624, minute=6, IpAddress="10.0.0.9", TargetUserName="bob")]
    [alert] = run_correlation(events, [SUCCESS_RULE])
    assert alert["level"] == "critical"
    assert alert["details"]["failed_attempts"] == 5
    assert alert["time"] == "2024-01-01T10:06:00+00:00"       # time of the success


def test_sequence_needs_enough_failures(make_event):
    events = failures(make_event, range(2)) + [make_event(4624, minute=3, IpAddress="10.0.0.9")]
    assert run_correlation(events, [SUCCESS_RULE]) == []


def test_sequence_success_from_other_source_is_ignored(make_event):
    events = failures(make_event, range(5)) + [make_event(4624, minute=6, IpAddress="8.8.8.8")]
    assert run_correlation(events, [SUCCESS_RULE]) == []


def test_sequence_success_too_late(make_event):
    events = failures(make_event, range(5)) + [make_event(4624, minute=30, IpAddress="10.0.0.9")]
    assert run_correlation(events, [SUCCESS_RULE]) == []


def test_sequence_success_before_failures_is_ignored(make_event):
    events = [make_event(4624, minute=0, IpAddress="10.0.0.9")] + failures(make_event, range(1, 6))
    assert run_correlation(events, [SUCCESS_RULE]) == []


def test_project_brute_force_rules(make_event):
    """The real rules/brute_force.yml raises medium + critical alerts."""
    rules = load_rules(RULES_DIR)
    events = failures(make_event, range(6)) + \
        [make_event(4624, minute=7, IpAddress="10.0.0.9", TargetUserName="bob", LogonType="3")]
    levels = sorted(a["level"] for a in run_correlation(events, rules))
    assert levels == ["critical", "medium"]
