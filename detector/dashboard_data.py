"""
dashboard_data.py - Data preparation for the optional Streamlit dashboard.

Everything here is plain Python (no Streamlit, no pandas), so it can be unit
tested and the CLI never depends on dashboard libraries. dashboard.py only
draws what these functions return.
"""

from __future__ import annotations

import copy
import re
from collections import Counter
from datetime import timedelta

from detector.correlation import format_timeframe, get_settings
from detector.engine import LEVELS
from detector.parser import parse_time
from detector.report import details_text, mitre_url, sort_alerts

# The dashboard shows two groups of correlation settings.
# Changing a group changes every rule in it (they share the same defaults).
BRUTE_FORCE_RULES = ["rule-007", "rule-008", "rule-009", "rule-010"]
RDP_RULES = ["rule-015", "rule-016"]

EVTX_MAGIC = b"ElfFile\x00"          # every EVTX file starts with these 8 bytes
MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


# ---------------------------------------------------------------------------
# Threshold settings
# ---------------------------------------------------------------------------

def _rule_settings(rules: list[dict], rule_id: str, config: dict) -> tuple[int, int]:
    """(threshold, timeframe in minutes) of one rule: rule YAML + config.yml."""
    for rule in rules:
        if rule["id"] == rule_id and "correlation" in rule:
            s = get_settings(rule, config)
            return s["threshold"], max(1, int(s["timeframe"].total_seconds() // 60))
    raise KeyError(f"correlation rule {rule_id} not found")


def default_thresholds(rules: list[dict], config: dict) -> dict:
    """Starting values for the sidebar inputs (taken from rules + config.yml)."""
    bf_count, bf_minutes = _rule_settings(rules, BRUTE_FORCE_RULES[0], config)
    rdp_hosts, rdp_minutes = _rule_settings(rules, RDP_RULES[0], config)
    return {"bf_count": bf_count, "bf_minutes": bf_minutes,
            "rdp_hosts": rdp_hosts, "rdp_minutes": rdp_minutes}


def build_config(base: dict, bf_count: int, bf_minutes: int,
                 rdp_hosts: int, rdp_minutes: int) -> dict:
    """Return a copy of config.yml's content with the dashboard's values applied.

    The result has the normal config.yml format, so correlation.py needs no
    dashboard-specific code.
    """
    config = copy.deepcopy(base or {})
    per_rule = config.setdefault("correlation", {})
    groups = [(BRUTE_FORCE_RULES, bf_count, bf_minutes), (RDP_RULES, rdp_hosts, rdp_minutes)]
    for rule_ids, threshold, minutes in groups:
        for rule_id in rule_ids:
            per_rule[rule_id] = {"threshold": int(threshold),
                                 "timeframe": format_timeframe(timedelta(minutes=minutes))}
    return config


# ---------------------------------------------------------------------------
# Upload safety
# ---------------------------------------------------------------------------

def check_upload(name: str, data: bytes) -> str | None:
    """Return an error message if an uploaded file must be rejected, else None."""
    if not name.lower().endswith(".evtx"):
        return f"{name}: only .evtx files are accepted"
    if not data.startswith(EVTX_MAGIC):
        return f"{name}: this is not a valid EVTX file (wrong file header)"
    return None


def safe_filename(name: str) -> str:
    """Keep only a harmless base name (no folders, no special characters).

    An upload called '../../evil.evtx' must not be written outside the
    temporary folder, so path parts are dropped and odd characters replaced.
    """
    base = re.split(r"[\\/]", name)[-1]
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")
    return base or "upload.evtx"


# ---------------------------------------------------------------------------
# Table rows, filters and counts
# ---------------------------------------------------------------------------

def alert_rows(alerts: list[dict]) -> list[dict]:
    """Flat rows for the alerts table, in chronological order.

    Each row keeps 'index' = position in sort_alerts(alerts), so a selected
    row can be traced back to the full alert.
    """
    return [{
        "index": i,
        "time": a["time"],
        "severity": a["level"],
        "rule": a["rule"],
        "rule_id": a["rule_id"],
        "mitre": a["mitre"],
        "computer": a["computer"],
        "details": details_text(a["details"]),
    } for i, a in enumerate(sort_alerts(alerts))]


def filter_options(alerts: list[dict]) -> dict:
    """Possible values for each filter (severity in severity order)."""
    present = {a["level"] for a in alerts}
    return {
        "severity": [lvl for lvl in reversed(LEVELS) if lvl in present],
        "mitre": sorted({a["mitre"] for a in alerts}),
        "rule": sorted({a["rule"] for a in alerts}),
        "computer": sorted({str(a["computer"]) for a in alerts}),
    }


def matches_search(alert: dict, search: str) -> bool:
    """Case-insensitive text search over all visible fields and details."""
    if not search:
        return True
    text = " ".join(str(v) for v in (
        alert["time"], alert["level"], alert["rule"], alert["rule_id"],
        alert["mitre"], alert["computer"], details_text(alert["details"])))
    return search.lower() in text.lower()


def filter_alerts(alerts: list[dict], severities=None, techniques=None,
                  rules=None, computers=None, search: str = "") -> list[dict]:
    """Keep alerts matching ALL chosen filters. An empty/None filter = no filter."""
    def allowed(value, chosen) -> bool:
        return not chosen or value in chosen

    return [a for a in alerts
            if allowed(a["level"], severities)
            and allowed(a["mitre"], techniques)
            and allowed(a["rule"], rules)
            and allowed(str(a["computer"]), computers)
            and matches_search(a, search.strip())]


def level_counts(alerts: list[dict]) -> dict:
    """{'critical': n, 'high': n, 'medium': n, 'low': n}"""
    counts = Counter(a["level"] for a in alerts)
    return {lvl: counts.get(lvl, 0) for lvl in reversed(LEVELS)}


def technique_counts(alerts: list[dict]) -> list[dict]:
    """[{'mitre': 'T1110', 'count': 3}, ...] - most frequent first, ties by id."""
    counts = Counter(a["mitre"] for a in alerts)
    return [{"mitre": t, "count": n}
            for t, n in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]


def timeline_counts(alerts: list[dict]) -> tuple[str, list[dict]]:
    """Count alerts per time bucket and severity, for the timeline chart.

    The bucket size depends on how long the logs cover:
    up to 2 hours -> minute, up to 3 days -> hour, otherwise -> day.
    Returns (bucket name, [{'time': datetime, 'severity': 'high', 'count': 2}, ...]).
    """
    timed = [(parse_time(a["time"]), a["level"]) for a in alerts]
    timed = [(t, lvl) for t, lvl in timed if t is not None]
    if not timed:
        return "minute", []

    span = max(t for t, _ in timed) - min(t for t, _ in timed)
    if span <= timedelta(hours=2):
        unit, cut = "minute", {"second": 0, "microsecond": 0}
    elif span <= timedelta(days=3):
        unit, cut = "hour", {"minute": 0, "second": 0, "microsecond": 0}
    else:
        unit, cut = "day", {"hour": 0, "minute": 0, "second": 0, "microsecond": 0}

    counts = Counter((t.replace(**cut), lvl) for t, lvl in timed)
    rows = [{"time": t, "severity": lvl, "count": n}
            for (t, lvl), n in sorted(counts.items())]
    return unit, rows


# ---------------------------------------------------------------------------
# Alert details
# ---------------------------------------------------------------------------

def mitre_link(technique: str) -> str | None:
    """Link to attack.mitre.org, or None if the id does not look like Txxxx(.yyy)."""
    return mitre_url(technique) if MITRE_ID.match(str(technique)) else None
