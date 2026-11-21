"""
evaluate.py - Measure how well the detector works on known attack samples.

    python evaluate.py                      # samples/ + tests/expected_results.yml
    python evaluate.py --samples other_dir --no-docs

What it does
  1. REAL samples: runs the normal pipeline (detector/pipeline.py) on every file
     listed in tests/expected_results.yml and compares the rules that fired with
     the rules that SHOULD fire (ground truth written from the sample names,
     not from this tool's output).
  2. SYNTHETIC scenarios: made-up events for situations the public samples do
     not contain (long brute-force bursts, RDP to many hosts). Always labelled
     SYNTHETIC so they are never confused with real data.
  3. Writes output/evaluation.csv, output/evaluation.json and
     docs/evaluation_results.md (with the date and Python version used).

Words used
  TP (true positive)   an expected rule fired
  FN (false negative)  an expected rule did NOT fire           -> "missing"
  FP (false positive)  a rule fired that was not expected      -> "unexpected"
  PASS                 no missing and no unexpected rules
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import sys
import time
from datetime import datetime, timedelta, timezone

import yaml

from detector.correlation import load_config, run_correlation
from detector.engine import load_rules, run_detection
from detector.pipeline import analyze

REAL, SYNTHETIC = "REAL", "SYNTHETIC"


# ---------------------------------------------------------------------------
# Pure logic (unit tested in tests/test_evaluate.py)
# ---------------------------------------------------------------------------

def compare(expected, actual, allowed=(), should_not=()) -> dict:
    """Compare the rule ids that fired with the ground truth.

    expected    rules that should fire
    actual      rules that really fired (duplicates are fine)
    allowed     rules that may fire without being an error
    should_not  rules that must not fire - stronger than 'allowed'
    """
    expected, actual = set(expected), set(actual)
    allowed = set(allowed) - set(should_not)
    missing = expected - actual
    unexpected = actual - expected - allowed
    return {
        "matched": sorted(expected & actual),
        "missing": sorted(missing),
        "unexpected": sorted(unexpected),
        "allowed_hits": sorted((actual & allowed) - expected),
        "passed": not missing and not unexpected,
    }


def allowed_rules(entry: dict, rule_mitre: dict, global_allowed=()) -> set:
    """Allowed = global list + the sample's own list + rules of the same technique."""
    techniques = techniques_of(entry)
    same_technique = {rid for rid, mitre in rule_mitre.items() if mitre in techniques}
    return set(global_allowed) | set(entry.get("allowed_rules") or []) | same_technique


def technique_table(rows: list[dict], rule_mitre: dict) -> list[dict]:
    """Per MITRE technique: samples, samples detected, TP, FN, FP (raw counts)."""
    table: dict[str, dict] = {}

    def line(technique):
        return table.setdefault(technique, {"technique": technique, "samples": 0,
                                            "detected": 0, "tp": 0, "fn": 0, "fp": 0})

    for row in rows:
        for technique in row["technique"]:
            line(technique)["samples"] += 1
            if any(rule_mitre.get(r) == technique for r in row["matched"]):
                line(technique)["detected"] += 1
        for rule in row["matched"]:
            line(rule_mitre.get(rule, "?"))["tp"] += 1
        for rule in row["missing"]:
            line(rule_mitre.get(rule, "?"))["fn"] += 1
        for rule in row["unexpected"]:
            line(rule_mitre.get(rule, "?"))["fp"] += 1
    return [table[t] for t in sorted(table)]


def summarize(rows: list[dict]) -> dict:
    """Totals over evaluated rows (events, time, pass count, TP/FN/FP)."""
    seconds = sum(r["seconds"] for r in rows)
    events = sum(r["events"] for r in rows)
    return {
        "evaluated": len(rows),
        "passed": sum(1 for r in rows if r["passed"]),
        "events": events,
        "seconds": round(seconds, 3),
        "events_per_second": round(events / seconds) if seconds > 0 else None,
        "tp": sum(len(r["matched"]) for r in rows),
        "fn": sum(len(r["missing"]) for r in rows),
        "fp": sum(len(r["unexpected"]) for r in rows),
    }


def load_expected(path: str) -> dict:
    """Read and check tests/expected_results.yml."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    for entry in data.get("samples") or []:
        for key in ("file", "technique", "expected_rules", "label", "justification"):
            if key not in entry:
                raise ValueError(f"{path}: sample {entry.get('file', '?')} is missing '{key}'")
        if entry["label"] not in ("certain", "uncertain"):
            raise ValueError(f"{path}: {entry['file']}: label must be certain or uncertain")
    return data


def techniques_of(entry: dict) -> list[str]:
    value = entry.get("technique") or []
    if isinstance(value, str):
        return [] if value == "none" else [value]
    return list(value)


# ---------------------------------------------------------------------------
# Real samples
# ---------------------------------------------------------------------------

def evaluate_sample(entry: dict, path: str, rules: list[dict], config: dict,
                    rule_mitre: dict, global_allowed=(), threshold=None) -> dict:
    """Run the normal pipeline on one file and compare with the ground truth."""
    overrides = {"threshold": threshold, "timeframe": None} if threshold else None
    start = time.perf_counter()
    alerts, stats = analyze([path], rules, config, overrides)
    seconds = time.perf_counter() - start

    actual = sorted({a["rule_id"] for a in alerts})
    result = compare(entry.get("expected_rules") or [], actual,
                     allowed_rules(entry, rule_mitre, global_allowed),
                     entry.get("should_not_fire") or [])
    return {
        "data": REAL,
        "name": entry["file"],
        "settings": f"threshold={threshold}" if threshold else "default",
        "technique": techniques_of(entry),
        "label": entry["label"],
        "events": stats["events"],
        "alerts": len(alerts),
        "expected": sorted(entry.get("expected_rules") or []),
        "actual": actual,
        **result,
        "seconds": round(seconds, 3),
        "warnings": stats["warnings"],
    }


# ---------------------------------------------------------------------------
# Synthetic scenarios (made-up events - NOT real logs)
# ---------------------------------------------------------------------------

BASE_TIME = datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc)


def fake_event(event_id: int, minute: float, computer: str = "PC01", **data) -> dict:
    """A normalized event exactly like parser.normalize() would return."""
    return {"event_id": event_id,
            "time": (BASE_TIME + timedelta(minutes=minute)).isoformat(),
            "channel": "Security", "computer": computer, "provider": "SYNTHETIC",
            "record_id": None, "data": data}


def synthetic_scenarios() -> list[dict]:
    fail = lambda m, ip="10.0.0.9", user="bob": fake_event(  # noqa: E731
        4625, m, IpAddress=ip, TargetUserName=user, LogonType="3")
    rdp = lambda m, host, ip, user="admin": fake_event(      # noqa: E731
        4624, m, computer=host, IpAddress=ip, TargetUserName=user, LogonType="10")
    return [
        {"name": "Brute force: 8 failures in 8 min, then success",
         "technique": ["T1110"],
         "events": [fail(m) for m in range(8)] +
                   [fake_event(4624, 9, IpAddress="10.0.0.9", TargetUserName="bob",
                               LogonType="3")],
         "expected": ["rule-007", "rule-008"]},
        {"name": "Password spray: 6 users from one IP in 3 min",
         "technique": ["T1110"],
         "events": [fail(m / 2, user=f"user{m}") for m in range(6)],
         "expected": ["rule-007"]},
        {"name": "NEGATIVE: 5 failures spread over 50 min (typos)",
         "technique": [],
         "events": [fail(m) for m in (0, 12, 24, 36, 48)],
         "expected": [], "should_not": ["rule-007", "rule-008"]},
        {"name": "NEGATIVE: 4 failures then success (below threshold)",
         "technique": [],
         "events": [fail(m) for m in range(4)] +
                   [fake_event(4624, 5, IpAddress="10.0.0.9", TargetUserName="bob",
                               LogonType="3")],
         "expected": [], "should_not": ["rule-007", "rule-008"]},
        {"name": "RDP lateral movement: 1 account -> 3 hosts in 30 min",
         "technique": ["T1021.001"],
         "events": [rdp(0, "HOST1", "10.0.0.5"), rdp(15, "HOST2", "10.0.0.5"),
                    rdp(30, "HOST3", "10.0.0.5")],
         "expected": ["rule-011", "rule-015"], "should_not": ["rule-016"]},
        {"name": "RDP from 3 source IPs to one host in 40 min",
         "technique": ["T1021.001"],
         "events": [rdp(0, "HOST1", "10.0.0.5"), rdp(20, "HOST1", "10.0.0.6"),
                    rdp(40, "HOST1", "10.0.0.7")],
         "expected": ["rule-011", "rule-016"], "should_not": ["rule-015"]},
        {"name": "NEGATIVE: normal RDP use (same host, same IP, 3 logons)",
         "technique": ["T1021.001"],
         "events": [rdp(m, "HOST1", "10.0.0.5") for m in (0, 20, 40)],
         "expected": ["rule-011"], "should_not": ["rule-015", "rule-016"]},
        {"name": "NEGATIVE: 3 hosts but spread over 3 hours",
         "technique": ["T1021.001"],
         "events": [rdp(0, "HOST1", "10.0.0.5"), rdp(90, "HOST2", "10.0.0.5"),
                    rdp(180, "HOST3", "10.0.0.5")],
         "expected": ["rule-011"], "should_not": ["rule-015", "rule-016"]},
    ]


def evaluate_synthetic(scenario: dict, rules: list[dict], config: dict) -> dict:
    """Run single-event rules and correlation on made-up events."""
    start = time.perf_counter()
    events = scenario["events"]
    alerts = run_detection(events, rules) + run_correlation(events, rules, config)
    seconds = time.perf_counter() - start
    actual = sorted({a["rule_id"] for a in alerts})
    result = compare(scenario["expected"], actual, (), scenario.get("should_not", ()))
    return {"data": SYNTHETIC, "name": scenario["name"], "settings": "default",
            "technique": scenario["technique"], "label": "certain",
            "events": len(events), "alerts": len(alerts),
            "expected": sorted(scenario["expected"]), "actual": actual,
            **result, "seconds": round(seconds, 4), "warnings": []}


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _ids(values) -> str:
    return ", ".join(values) if values else "-"


def print_rows(title: str, rows: list[dict]) -> None:
    print("\n" + "=" * 78)
    print(f" {title}")
    print("=" * 78)
    for r in rows:
        status = "PASS" if r["passed"] else "FAIL"
        extra = "" if r["settings"] == "default" else f"  [{r['settings']}]"
        print(f"[{status}] [{r['data']}] {r['name']}{extra}")
        print(f"        events={r['events']}  alerts={r['alerts']}  time={r['seconds']:.3f}s"
              f"  label={r['label']}")
        print(f"        expected  : {_ids(r['expected'])}")
        print(f"        actual    : {_ids(r['actual'])}")
        print(f"        missing   : {_ids(r['missing'])}   (false negatives)")
        print(f"        unexpected: {_ids(r['unexpected'])}   (false positives)")
        if r["allowed_hits"]:
            print(f"        allowed   : {_ids(r['allowed_hits'])}   (not counted)")
        for w in r["warnings"]:
            print(f"        [!] {w}")


def print_summary(summary: dict, table: list[dict], synth: dict) -> None:
    print("\n" + "=" * 78)
    print(" SUMMARY (real samples, default settings)")
    print("=" * 78)
    print(f" Samples passed : {summary['passed']}/{summary['evaluated']}")
    print(f" Rule checks    : TP={summary['tp']}  FN={summary['fn']}  FP={summary['fp']}")
    print(f" Events parsed  : {summary['events']}")
    print(f" Total time     : {summary['seconds']:.3f} s"
          f"  ({summary['events_per_second']} events/s)")
    print(f"\n {'Technique':<11}{'Samples':>8}{'Detected':>10}{'TP':>5}{'FN':>5}{'FP':>5}")
    for t in table:
        print(f" {t['technique']:<11}{t['samples']:>8}{t['detected']:>10}"
              f"{t['tp']:>5}{t['fn']:>5}{t['fp']:>5}")
    print(f"\n SYNTHETIC scenarios passed: {synth['passed']}/{synth['evaluated']}"
          "  (made-up events, not real logs)")
    print("\n Note: very small sample set - these are raw counts, not a general accuracy.")


ROW_FIELDS = ["data", "name", "settings", "technique", "label", "events", "alerts",
              "expected", "actual", "missing", "unexpected", "allowed_hits",
              "passed", "seconds"]


def write_csv(rows: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(ROW_FIELDS)
        for r in rows:
            writer.writerow(["; ".join(v) if isinstance(v, list) else v
                             for v in (r[k] for k in ROW_FIELDS)])


def environment() -> dict:
    try:
        from importlib.metadata import version
        evtx_version = version("python-evtx")
    except Exception:
        evtx_version = "unknown"
    return {"date_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "python_evtx": evtx_version}


def markdown(report: dict) -> str:
    env, s = report["environment"], report["summary"]

    def table(rows):
        out = ["| Result | File / scenario | Events | Time (s) | Expected | Actual | "
               "Missing (FN) | Unexpected (FP) | Allowed | Label |",
               "|---|---|---:|---:|---|---|---|---|---|---|"]
        for r in rows:
            name = r["name"] + ("" if r["settings"] == "default" else f" `[{r['settings']}]`")
            out.append(f"| {'PASS' if r['passed'] else '**FAIL**'} | {name} | {r['events']} | "
                       f"{r['seconds']:.3f} | {_ids(r['expected'])} | {_ids(r['actual'])} | "
                       f"{_ids(r['missing'])} | {_ids(r['unexpected'])} | "
                       f"{_ids(r['allowed_hits'])} | {r['label']} |")
        return "\n".join(out)

    tech = ["| Technique | Samples | Samples detected | TP | FN | FP |",
            "|---|---:|---:|---:|---:|---:|"]
    tech += [f"| {t['technique']} | {t['samples']} | {t['detected']} | {t['tp']} | "
             f"{t['fn']} | {t['fp']} |" for t in report["techniques"]]

    skipped = "\n".join(f"- `{name}`" for name in report["skipped"]) or "- none"
    synth = report["synthetic_summary"]
    return f"""# Evaluation results

> **Generated automatically** by `python evaluate.py` - do not edit by hand.
> Date: **{env['date_utc']}** · Python **{env['python']}** · python-evtx {env['python_evtx']}
> · {env['platform']}

Ground truth: [`tests/expected_results.yml`](../tests/expected_results.yml) - written
from each sample's name and the EVTX-ATTACK-SAMPLES technique, **not** from this
tool's output. Processing times depend on the computer and change between runs.

## 1. Real samples (EVTX-ATTACK-SAMPLES), default settings

**Samples passed: {s['passed']}/{s['evaluated']}** · Rule checks: TP = {s['tp']},
FN = {s['fn']}, FP = {s['fp']} · {s['events']} events in {s['seconds']:.3f} s
({s['events_per_second']} events/s)

{table(report['real'])}

### Per technique (real samples, default settings)

{chr(10).join(tech)}

TP = expected rule fired, FN = expected rule did not fire, FP = a rule fired that was
neither expected nor allowed. "Allowed" alerts (log clearing and rules of the same
technique, see the policy in `expected_results.yml`) are shown but not counted.

## 2. Real samples, tuned threshold (informational, not counted above)

{table(report['tuned']) if report['tuned'] else 'No sample has a threshold override.'}

## 3. SYNTHETIC scenarios (made-up events, not real logs)

**Passed: {synth['passed']}/{synth['evaluated']}**. These events were written by hand in
`evaluate.py` to test the correlation logic on situations the public samples do not
contain. They prove the logic works as designed, not that it works on real attacks.

{table(report['synthetic'])}

## Samples skipped (not found locally)

{skipped}

## Limitations of this evaluation

- **Very small sample set** ({s['evaluated']} real files, mostly one technique each). The
  counts above are not a general detection rate or accuracy and must not be read as one.
- Ground truth is based on file names and technique descriptions; labels marked
  `uncertain` could be wrong (see the justification in `expected_results.yml`).
- Every sample is evaluated **on its own**, so correlation across several files
  (e.g. RDP to many hosts) is only tested with SYNTHETIC events.
- The samples are short lab recordings with no normal background activity, so the
  false-positive rate on a busy real network is **not** measured here.
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    p = argparse.ArgumentParser(description="Evaluate the detector on labelled samples.")
    p.add_argument("--samples", default="samples", help="folder with the .evtx samples")
    p.add_argument("--expected", default=os.path.join("tests", "expected_results.yml"))
    p.add_argument("--rules", default="rules")
    p.add_argument("--config", default="config.yml")
    p.add_argument("--output", default="output", help="folder for evaluation.csv/.json")
    p.add_argument("--docs", default=os.path.join("docs", "evaluation_results.md"))
    p.add_argument("--no-docs", action="store_true", help="do not write the Markdown file")
    args = p.parse_args(argv)

    truth = load_expected(args.expected)
    rules = load_rules(args.rules)
    config = load_config(args.config)
    rule_mitre = {r["id"]: r["mitre"] for r in rules}
    global_allowed = (truth.get("allowed_on_all_samples") or {}).get("rules") or []

    real, tuned, skipped = [], [], []
    for entry in truth.get("samples") or []:
        path = os.path.join(args.samples, entry["file"])
        if not os.path.isfile(path):
            skipped.append(entry["file"])
            continue
        real.append(evaluate_sample(entry, path, rules, config, rule_mitre, global_allowed))
        if entry.get("threshold_override"):
            tuned.append(evaluate_sample(entry, path, rules, config, rule_mitre,
                                         global_allowed, int(entry["threshold_override"])))

    synthetic = [evaluate_synthetic(s, rules, config) for s in synthetic_scenarios()]

    report = {
        "environment": environment(),
        "summary": summarize(real),
        "techniques": technique_table(real, rule_mitre),
        "real": real, "tuned": tuned, "skipped": skipped,
        "synthetic": synthetic, "synthetic_summary": summarize(synthetic),
    }

    print_rows("REAL SAMPLES (default settings)", real)
    if tuned:
        print_rows("REAL SAMPLES - TUNED THRESHOLD (informational, not in summary)", tuned)
    print_rows("SYNTHETIC SCENARIOS (made-up events)", synthetic)
    for name in skipped:
        print(f"[SKIP] {name} - not found in {args.samples}/ (download it, see README)")
    print_summary(report["summary"], report["techniques"], report["synthetic_summary"])

    os.makedirs(args.output, exist_ok=True)
    write_csv(real + tuned + synthetic, os.path.join(args.output, "evaluation.csv"))
    with open(os.path.join(args.output, "evaluation.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    written = [os.path.join(args.output, n) for n in ("evaluation.csv", "evaluation.json")]
    if not args.no_docs:
        with open(args.docs, "w", encoding="utf-8") as f:
            f.write(markdown(report))
        written.append(args.docs)
    print("\n" + "\n".join(f"[+] Written: {path}" for path in written))
    return 0


if __name__ == "__main__":
    sys.exit(main())
