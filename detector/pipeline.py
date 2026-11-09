"""
pipeline.py - Run the whole detection pipeline with one function call.

    EVTX file(s) -> parser -> rules engine -> correlation -> alerts

Both user interfaces use this module, so the detection steps exist only once:
  - main.py       (command line)
  - dashboard.py  (optional Streamlit web dashboard)

This module never prints anything: problems are returned in stats["warnings"]
and each interface decides how to show them.
"""

from __future__ import annotations

import os
from typing import Callable, Optional

from detector.correlation import is_relevant, load_config, run_correlation
from detector.engine import LEVELS, detect_event, is_correlation_rule, load_rules
from detector.parser import parse_evtx

# progress(file_number, total_files, path, events_read_in_this_file)
ProgressCallback = Callable[[int, int, str, int], None]

PROGRESS_EVERY = 2000      # report progress every N events inside a big file


def find_evtx_files(paths: list[str]) -> tuple[list[str], list[str]]:
    """Expand folders into .evtx files (recursive). Returns (files, error messages)."""
    files, errors = [], []
    for path in paths:
        if os.path.isfile(path):
            files.append(path)
        elif os.path.isdir(path):
            found = sorted(os.path.join(root, name)
                           for root, _, names in os.walk(path)
                           for name in names if name.lower().endswith(".evtx"))
            if not found:
                errors.append(f"no .evtx files found in folder: {path}")
            files.extend(found)
        else:
            errors.append(f"path not found: {path}")
    return files, errors


def analyze(files: list[str], rules: list[dict], config: dict | None = None,
            cli_overrides: dict | None = None,
            progress: Optional[ProgressCallback] = None) -> tuple[list[dict], dict]:
    """Read all files once, run single-event rules, then correlation rules.

    Returns (alerts, stats). A file that cannot be read is recorded in
    stats["failed_files"] / stats["warnings"] and the next file is processed.
    """
    correlation_rules = [r for r in rules if is_correlation_rule(r)]
    alerts: list[dict] = []
    kept_for_correlation: list[dict] = []
    stats = {"files": [], "failed_files": [], "events": 0,
             "rules": len(rules), "warnings": []}

    for number, path in enumerate(files, start=1):
        count = 0
        if progress:
            progress(number, len(files), path, 0)
        try:
            for event in parse_evtx(path):
                count += 1
                alerts.extend(detect_event(event, rules))
                # Only keep events that a correlation rule needs (saves memory).
                if any(is_relevant(r, event) for r in correlation_rules):
                    kept_for_correlation.append(event)
                if progress and count % PROGRESS_EVERY == 0:
                    progress(number, len(files), path, count)
            stats["files"].append(path)
        except Exception as exc:          # corrupt / not an EVTX file / no access
            stats["warnings"].append(f"could not read {path}: {type(exc).__name__}: {exc}")
            stats["failed_files"].append(path)
        stats["events"] += count

    # Correlation runs over ALL files together (e.g. RDP across many hosts).
    alerts.extend(run_correlation(kept_for_correlation, rules, config, cli_overrides))
    return alerts, stats


def filter_by_level(alerts: list[dict], min_level: str = "low") -> list[dict]:
    """Keep alerts whose severity is at least min_level."""
    minimum = LEVELS.index(min_level)
    return [a for a in alerts if LEVELS.index(a["level"]) >= minimum]


def run_pipeline(paths: list[str], rules_dir: str = "rules",
                 config: dict | str | None = "config.yml",
                 cli_overrides: dict | None = None, min_level: str = "low",
                 progress: Optional[ProgressCallback] = None) -> tuple[list[dict], dict]:
    """Complete pipeline: paths -> (alerts, stats).

    'config' may be a path to config.yml or an already loaded dict.
    Raises RuleError / ValueError for invalid rules or settings; file problems
    are reported in stats["warnings"] instead of raising.
    """
    rules = load_rules(rules_dir)
    if isinstance(config, str) or config is None:
        config = load_config(config)

    files, errors = find_evtx_files(paths)
    alerts, stats = analyze(files, rules, config, cli_overrides, progress)
    stats["warnings"] = errors + stats["warnings"]
    return filter_by_level(alerts, min_level), stats
