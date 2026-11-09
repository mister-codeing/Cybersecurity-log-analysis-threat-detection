"""
correlation.py - Detections that need MORE than one event.

Some attacks are invisible in a single event: one failed logon is a typo,
fifty failed logons in five minutes is a brute force attack. Rules with a
"correlation:" section are evaluated here. Two generic types exist:

1. threshold - "at least N matching events (or N different values of a field)
                for the same group within T minutes"
   Example: >= 5 failed logons (4625) from the same IpAddress within 10m.

        correlation:
          type: threshold
          group_by: [IpAddress]   # events are grouped by these fields
          threshold: 5            # N
          timeframe: 10m          # T  (s / m / h)
          distinct: computer      # optional: count different values instead

2. sequence  - "at least N events of step 1, then one event of step 2,
                for the same group, all within T minutes"
   Example: >= 5 failed logons, then a successful logon (4624) from that IP.

        correlation:
          type: sequence
          group_by: [IpAddress]
          threshold: 5
          timeframe: 10m
          followed_by:            # step 2, same syntax as 'detection'
            event_id: [4624]

Thresholds can be changed without editing rules:
    rule YAML  <  config.yml (per rule id)  <  CLI --threshold / --timeframe
"""

from __future__ import annotations

import os
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any

import yaml

from detector.engine import get_field, is_correlation_rule, make_alert, matches
from detector.parser import parse_time

MAX_LISTED_VALUES = 10     # how many distinct values to show in an alert


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def parse_timeframe(value: Any) -> timedelta:
    """'30s' -> 30 seconds, '10m' -> 10 minutes, '2h' -> 2 hours, 15 -> 15 minutes."""
    if isinstance(value, (int, float)):
        minutes = float(value)
        if minutes <= 0:
            raise ValueError(f"timeframe must be positive: {value}")
        return timedelta(minutes=minutes)

    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smh]?)\s*", str(value).lower())
    if not match or float(match.group(1)) <= 0:
        raise ValueError(f"invalid timeframe '{value}' (use e.g. 30s, 10m, 1h)")
    number, unit = float(match.group(1)), match.group(2) or "m"
    return {"s": timedelta(seconds=number),
            "m": timedelta(minutes=number),
            "h": timedelta(hours=number)}[unit]


def format_timeframe(delta: timedelta) -> str:
    """timedelta(minutes=10) -> '10m' (for readable alert details)."""
    seconds = int(delta.total_seconds())
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def load_config(path: str | None) -> dict:
    """Read config.yml. A missing file simply means 'no overrides'."""
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def get_settings(rule: dict, config: dict | None = None,
                 cli: dict | None = None) -> dict:
    """Combine the rule's own settings with config.yml and CLI overrides."""
    settings = dict(rule["correlation"])

    per_rule = ((config or {}).get("correlation") or {}).get(rule["id"]) or {}
    for key in ("threshold", "timeframe"):
        if per_rule.get(key) is not None:
            settings[key] = per_rule[key]
        if cli and cli.get(key) is not None:
            settings[key] = cli[key]

    settings["threshold"] = int(settings.get("threshold", 1))
    if settings["threshold"] < 1:
        raise ValueError(f"{rule['id']}: threshold must be at least 1")
    settings["timeframe"] = parse_timeframe(settings.get("timeframe", "10m"))
    settings["group_by"] = settings.get("group_by") or []
    return settings


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def is_relevant(rule: dict, event: dict) -> bool:
    """Is this event needed by a correlation rule? (used to save memory)"""
    if matches(rule["detection"], event):
        return True
    follow = rule["correlation"].get("followed_by")
    return bool(follow) and matches(follow, event)


def group_key(event: dict, fields: list[str]) -> tuple:
    """The values that decide which group an event belongs to."""
    return tuple(str(get_field(event, f) or "-") for f in fields)


def distinct_values(events: list[dict], field: str) -> list[str]:
    """Different values of a field, in order of first appearance."""
    seen: list[str] = []
    for event in events:
        value = get_field(event, field)
        if value not in (None, "", "-") and str(value) not in seen:
            seen.append(str(value))
    return seen


def join_values(values: list[str]) -> str:
    """'a, b, c' - shortened when there are too many values."""
    if len(values) > MAX_LISTED_VALUES:
        extra = len(values) - MAX_LISTED_VALUES
        return ", ".join(values[:MAX_LISTED_VALUES]) + f" (+{extra} more)"
    return ", ".join(values)


def _timed(events: list[dict]) -> list[tuple[datetime, dict]]:
    """Attach a datetime to each event, drop events without time, sort."""
    pairs = [(parse_time(e.get("time")), e) for e in events]
    pairs = [(t, e) for t, e in pairs if t is not None]
    pairs.sort(key=lambda pair: pair[0])
    return pairs


# ---------------------------------------------------------------------------
# Threshold correlation
# ---------------------------------------------------------------------------

def threshold_alerts(rule: dict, events: list[dict], s: dict) -> list[dict]:
    """N events (or N distinct values) per group inside a sliding time window."""
    groups: dict[tuple, list] = defaultdict(list)
    for event in events:
        if matches(rule["detection"], event):
            groups[group_key(event, s["group_by"])].append(event)

    def count(window: list[tuple[datetime, dict]]) -> int:
        evs = [e for _, e in window]
        return len(distinct_values(evs, s["distinct"])) if s.get("distinct") else len(evs)

    alerts = []
    for key, group_events in groups.items():
        items = _timed(group_events)
        start, end = 0, 0
        while end < len(items):
            # Move the window start forward until the window fits in timeframe.
            while items[end][0] - items[start][0] > s["timeframe"]:
                start += 1
            window = items[start:end + 1]

            if count(window) >= s["threshold"]:
                # Threshold reached. Keep adding events that continue the same
                # burst (each one within 'timeframe' of the previous one), so a
                # long attack produces ONE alert instead of many.
                while (end + 1 < len(items) and
                       items[end + 1][0] - items[end][0] <= s["timeframe"]):
                    end += 1
                burst = [e for _, e in items[start:end + 1]]
                alerts.append(_summary_alert(rule, s, key, burst))
                start = end + 1          # start looking for a new burst
            end += 1
    return alerts


def _summary_alert(rule: dict, s: dict, key: tuple, burst: list[dict]) -> dict:
    """Build one alert that describes a whole group of events."""
    details: dict[str, Any] = dict(zip(s["group_by"], key))
    details["event_count"] = len(burst)
    if s.get("distinct"):
        values = distinct_values(burst, s["distinct"])
        details[f"distinct_{s['distinct']}"] = f"{len(values)}: {join_values(values)}"
    details["first_seen"] = burst[0]["time"]
    details["last_seen"] = burst[-1]["time"]
    details["rule_window"] = f"{s['threshold']} within {format_timeframe(s['timeframe'])}"
    for field in rule.get("show", []):
        values = distinct_values(burst, field)
        if values:                                 # skip empty fields
            details[field] = join_values(values)

    computers = join_values(distinct_values(burst, "computer"))
    return make_alert(rule, burst[0]["time"], computers, details)


# ---------------------------------------------------------------------------
# Sequence correlation
# ---------------------------------------------------------------------------

def sequence_alerts(rule: dict, events: list[dict], s: dict) -> list[dict]:
    """>= N 'detection' events followed by one 'followed_by' event (same group)."""
    follow = s["followed_by"]
    groups: dict[tuple, list] = defaultdict(list)
    for event in events:
        if matches(rule["detection"], event):
            groups[group_key(event, s["group_by"])].append(("step1", event))
        elif matches(follow, event):
            groups[group_key(event, s["group_by"])].append(("step2", event))

    alerts = []
    for key, tagged in groups.items():
        steps = {id(e): step for step, e in tagged}
        recent: deque = deque()            # step-1 events inside the window
        for time, event in _timed([e for _, e in tagged]):
            if steps[id(event)] == "step1":
                recent.append((time, event))
                continue
            # A step-2 event: forget step-1 events that are too old.
            while recent and time - recent[0][0] > s["timeframe"]:
                recent.popleft()
            if len(recent) >= s["threshold"]:
                alerts.append(_sequence_alert(rule, s, key, recent, event))
                recent.clear()             # one alert per attack
    return alerts


def _sequence_alert(rule: dict, s: dict, key: tuple, recent: deque,
                    final_event: dict) -> dict:
    details: dict[str, Any] = dict(zip(s["group_by"], key))
    details["failed_attempts"] = len(recent)
    details["first_attempt"] = recent[0][1]["time"]
    details["success_time"] = final_event["time"]
    details["rule_window"] = f"{s['threshold']} within {format_timeframe(s['timeframe'])}"
    for field in rule.get("show", []):     # values from the final event
        details[field] = get_field(final_event, field)
    return make_alert(rule, final_event["time"], final_event.get("computer"), details)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_correlation(events: list[dict], rules: list[dict],
                    config: dict | None = None, cli: dict | None = None) -> list[dict]:
    """Run every correlation rule over the (already collected) events."""
    alerts: list[dict] = []
    for rule in rules:
        if not is_correlation_rule(rule):
            continue
        settings = get_settings(rule, config, cli)
        if settings.get("type") == "sequence":
            alerts.extend(sequence_alerts(rule, events, settings))
        else:
            alerts.extend(threshold_alerts(rule, events, settings))
    return alerts
