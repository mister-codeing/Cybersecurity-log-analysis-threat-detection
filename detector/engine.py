"""
engine.py - Load YAML rules and match them against normalized events.

A rule is a YAML document like this:

    title: Suspicious Service Installed
    id: rule-003
    level: high                 # low | medium | high | critical
    mitre: T1543.003
    description: ...
    detection:
      event_id: [7045]          # event must have one of these IDs
      channel: System           # optional, one value or a list
      fields:                   # optional, ALL fields must match
        ImagePath|contains: ['\\temp\\', 'powershell']   # ANY value may match
      exclude:                  # optional, drop the event if ANY of these match
        IpAddress|equals: ['-', '127.0.0.1']
    show: [ServiceName, ImagePath]   # fields copied into the alert

Rules that also contain a "correlation:" section look at *groups* of events
and are handled by correlation.py instead of run_detection() below.
"""

from __future__ import annotations

import glob
import os
from typing import Any, Iterable

import yaml

# Severity levels from lowest to highest (used for sorting and filtering).
LEVELS = ["low", "medium", "high", "critical"]

# Supported field operators, written as "FieldName|operator".
OPERATORS = {"equals", "contains", "startswith", "endswith"}

REQUIRED_KEYS = ["title", "id", "level", "mitre", "detection"]

# Top-level event keys that rules may also use as "fields".
EVENT_KEYS = {"event_id", "channel", "computer", "provider", "time", "record_id"}


class RuleError(ValueError):
    """Raised when a rule file is not valid."""


# ---------------------------------------------------------------------------
# Loading rules
# ---------------------------------------------------------------------------

def load_rules(rules_dir: str = "rules") -> list[dict]:
    """Read every *.yml / *.yaml file in rules_dir.

    One file may contain several rules separated by '---'.
    Invalid rules raise RuleError with the file name, so mistakes are found
    immediately instead of silently producing no alerts.
    """
    if not os.path.isdir(rules_dir):
        raise RuleError(f"rules directory not found: {rules_dir}")

    paths = sorted(glob.glob(os.path.join(rules_dir, "*.yml")) +
                   glob.glob(os.path.join(rules_dir, "*.yaml")))
    rules: list[dict] = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            try:
                documents = list(yaml.safe_load_all(f))
            except yaml.YAMLError as exc:
                raise RuleError(f"{path}: invalid YAML: {exc}") from exc
        for rule in documents:
            if rule:                      # skip empty documents
                validate_rule(rule, path)
                rules.append(rule)

    ids = [r["id"] for r in rules]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise RuleError(f"duplicate rule id(s): {', '.join(sorted(duplicates))}")
    return rules


def validate_rule(rule: dict, source: str = "") -> None:
    """Check that a rule has the required keys and known operators/levels."""
    name = f"{source}: rule '{rule.get('title', '?')}'"
    for key in REQUIRED_KEYS:
        if key not in rule:
            raise RuleError(f"{name} is missing '{key}'")
    if str(rule["level"]).lower() not in LEVELS:
        raise RuleError(f"{name} has unknown level '{rule['level']}'")

    selections = [rule["detection"]]
    if "followed_by" in rule.get("correlation", {}):
        selections.append(rule["correlation"]["followed_by"])
    for selection in selections:
        for section in ("fields", "exclude"):
            for key in (selection.get(section) or {}):
                op = key.partition("|")[2] or "equals"
                if op not in OPERATORS:
                    raise RuleError(f"{name} uses unknown operator '{op}'")


def is_correlation_rule(rule: dict) -> bool:
    return "correlation" in rule


# ---------------------------------------------------------------------------
# Matching one event
# ---------------------------------------------------------------------------

def get_field(event: dict, name: str) -> Any:
    """Return a field from event["data"], or a top-level key like 'computer'."""
    data = event.get("data") or {}
    if name in data:
        return data[name]
    if name in EVENT_KEYS:
        return event.get(name)
    return None


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def field_matches(value: Any, op: str, expected: Any) -> bool:
    """Compare one field value with one or more expected values.

    The comparison ignores upper/lower case. If 'expected' is a list,
    the field matches when ANY value in the list matches (logical OR).
    """
    if value is None:
        return False
    value = str(value).lower()
    candidates = [str(e).lower() for e in _as_list(expected)]

    if op == "contains":
        return any(e in value for e in candidates)
    if op == "startswith":
        return any(value.startswith(e) for e in candidates)
    if op == "endswith":
        return any(value.endswith(e) for e in candidates)
    return any(value == e for e in candidates)          # "equals" (default)


def _check(event: dict, key: str, expected: Any) -> bool:
    """Evaluate one 'FieldName|operator: values' condition."""
    name, _, op = key.partition("|")
    return field_matches(get_field(event, name), op or "equals", expected)


def matches(selection: dict, event: dict) -> bool:
    """Does the event satisfy a selection (a rule's 'detection' block)?

    1. event_id must be in the list (if given)
    2. channel must be one of the values (if given, case-insensitive)
    3. every condition under 'fields' must be true      (AND)
    4. no condition under 'exclude' may be true          (NOT ... OR ...)
    """
    if "event_id" in selection:
        allowed = [int(i) for i in _as_list(selection["event_id"])]
        if event.get("event_id") not in allowed:
            return False

    if "channel" in selection:
        if not field_matches(event.get("channel"), "equals", selection["channel"]):
            return False

    for key, expected in (selection.get("fields") or {}).items():
        if not _check(event, key, expected):
            return False

    for key, expected in (selection.get("exclude") or {}).items():
        if _check(event, key, expected):
            return False

    return True


# ---------------------------------------------------------------------------
# Building alerts
# ---------------------------------------------------------------------------

def make_alert(rule: dict, time: str | None, computer: str | None,
               details: dict, level: str | None = None) -> dict:
    """Create an alert dict. All alerts (simple and correlated) use this shape."""
    return {
        "time": time,
        "computer": computer,
        "rule": rule["title"],
        "rule_id": rule["id"],
        "level": str(level or rule["level"]).lower(),
        "mitre": rule["mitre"],
        "description": rule.get("description", ""),
        "details": details,
    }


def detect_event(event: dict, rules: Iterable[dict]) -> list[dict]:
    """Return the alerts produced by ONE event (single-event rules only)."""
    alerts = []
    for rule in rules:
        if is_correlation_rule(rule):
            continue                       # handled in correlation.py
        if matches(rule["detection"], event):
            details = {k: get_field(event, k) for k in rule.get("show", [])}
            alerts.append(make_alert(rule, event.get("time"),
                                     event.get("computer"), details))
    return alerts


def run_detection(events: Iterable[dict], rules: list[dict]) -> list[dict]:
    """Apply every single-event rule to every event and return all alerts."""
    alerts: list[dict] = []
    for event in events:
        alerts.extend(detect_event(event, rules))
    return alerts
