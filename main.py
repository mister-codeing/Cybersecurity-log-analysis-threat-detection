"""
main.py - Command line interface of the EVTX threat detector.

Pipeline:  EVTX file(s) -> parser -> rules engine -> correlation -> report

Examples:
    python main.py samples/DE_1102_security_log_cleared.evtx
    python main.py samples/ --format console,html,csv,json --output output
    python main.py logs/ --threshold 10 --timeframe 5m --min-level medium
"""

from __future__ import annotations

import argparse
import os
import sys

from detector.correlation import (is_relevant, load_config, parse_timeframe,
                                  run_correlation)
from detector.engine import LEVELS, RuleError, detect_event, is_correlation_rule, load_rules
from detector.parser import parse_evtx
from detector.report import FILE_FORMATS, write_reports

FORMATS = ["console"] + list(FILE_FORMATS)      # console, csv, json, html
EXIT_OK, EXIT_ERROR = 0, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Detect attacks in Windows EVTX logs using YAML rules "
                    "(MITRE ATT&CK mapped).")
    p.add_argument("paths", nargs="+",
                   help="EVTX file(s) and/or folder(s) (folders are searched recursively)")
    p.add_argument("-r", "--rules", default="rules",
                   help="folder with YAML rules (default: rules)")
    p.add_argument("-o", "--output", default="output",
                   help="folder for csv/json/html reports (default: output)")
    p.add_argument("-f", "--format", default="console",
                   help="comma-separated list of: " + ", ".join(FORMATS)
                        + " (default: console)")
    p.add_argument("-c", "--config", default="config.yml",
                   help="correlation settings file (default: config.yml, optional)")
    p.add_argument("--threshold", type=int,
                   help="override the threshold of ALL correlation rules")
    p.add_argument("--timeframe",
                   help="override the time window of ALL correlation rules (e.g. 30s, 10m, 1h)")
    p.add_argument("--min-level", choices=LEVELS, default="low",
                   help="only report alerts with at least this severity (default: low)")
    return p


def parse_formats(text: str) -> list[str]:
    """'console, html' -> ['console', 'html'] (raises ValueError if unknown)."""
    formats = [f.strip().lower() for f in text.split(",") if f.strip()]
    unknown = [f for f in formats if f not in FORMATS]
    if unknown or not formats:
        raise ValueError(f"unknown format(s): {', '.join(unknown) or '(empty)'}; "
                         f"choose from {', '.join(FORMATS)}")
    return formats


def find_evtx_files(paths: list[str]) -> tuple[list[str], list[str]]:
    """Expand folders into .evtx files. Returns (files, error messages)."""
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


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr)


def analyze(files: list[str], rules: list[dict], config: dict,
            cli_overrides: dict) -> tuple[list[dict], dict]:
    """Read all files once, run single-event rules, then correlation rules."""
    correlation_rules = [r for r in rules if is_correlation_rule(r)]
    alerts: list[dict] = []
    kept_for_correlation: list[dict] = []
    stats = {"files": [], "failed_files": [], "events": 0, "rules": len(rules)}

    for path in files:
        count = 0
        try:
            for event in parse_evtx(path):
                count += 1
                alerts.extend(detect_event(event, rules))
                # Only keep events that a correlation rule needs (saves memory).
                if any(is_relevant(r, event) for r in correlation_rules):
                    kept_for_correlation.append(event)
            stats["files"].append(path)
        except Exception as exc:          # corrupt / not an EVTX file / no access
            warn(f"could not read {path}: {type(exc).__name__}: {exc}")
            stats["failed_files"].append(path)
        stats["events"] += count

    # Correlation runs over ALL files together (e.g. RDP across many hosts).
    alerts.extend(run_correlation(kept_for_correlation, rules, config, cli_overrides))
    return alerts, stats


def main(argv: list[str] | None = None) -> int:
    # Avoid crashes when event data contains characters the console can't show.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    args = build_parser().parse_args(argv)

    # --- validate options ---
    try:
        formats = parse_formats(args.format)
        if args.timeframe:
            parse_timeframe(args.timeframe)
        if args.threshold is not None and args.threshold < 1:
            raise ValueError("--threshold must be at least 1")
        rules = load_rules(args.rules)
        config = load_config(args.config)
    except (ValueError, RuleError, OSError) as exc:
        warn(str(exc))
        return EXIT_ERROR
    if not rules:
        warn(f"no rules found in {args.rules}")
        return EXIT_ERROR

    files, errors = find_evtx_files(args.paths)
    for message in errors:
        warn(message)
    if not files:
        warn("nothing to analyse")
        return EXIT_ERROR

    print(f"[*] Loaded {len(rules)} rule(s), analysing {len(files)} file(s)...")

    # --- detection ---
    cli_overrides = {"threshold": args.threshold, "timeframe": args.timeframe}
    try:
        alerts, stats = analyze(files, rules, config, cli_overrides)
    except ValueError as exc:            # e.g. bad threshold value in config.yml
        warn(str(exc))
        return EXIT_ERROR

    minimum = LEVELS.index(args.min_level)
    alerts = [a for a in alerts if LEVELS.index(a["level"]) >= minimum]

    # --- reports ---
    try:
        written = write_reports(alerts, formats, args.output, stats)
    except OSError as exc:
        warn(f"could not write report: {exc}")
        return EXIT_ERROR
    for path in written:
        print(f"[+] Report written: {path}")

    print(f"[*] Total alerts: {len(alerts)}")
    return EXIT_ERROR if not stats["files"] else EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        warn("interrupted by user")
        sys.exit(130)
