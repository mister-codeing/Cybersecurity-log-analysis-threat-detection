"""
compare_tools.py - Put this tool's alert counts next to Chainsaw / Hayabusa counts.

Nothing is invented: other tools' numbers come either from a CSV that YOU fill in
after running them, or from really running `chainsaw` (only if it is on PATH).

    python compare_tools.py --init output/comparison.csv     # 1. create the template
    # 2. run Chainsaw / Hayabusa yourself (see docs/comparison_template.md)
    #    and type their alert counts into the CSV
    python compare_tools.py output/comparison.csv            # 3. show the comparison

    # optional: let this script run chainsaw (needs Sigma rules + a mapping file)
    python compare_tools.py output/comparison.csv --run-chainsaw \\
        --sigma path/to/sigma/rules --mapping path/to/chainsaw/mappings/sigma-event-logs-all.yml

CSV columns: sample, tool, alerts, notes   (alerts empty = not filled in yet)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile

import yaml

from detector.correlation import load_config
from detector.engine import load_rules
from detector.pipeline import analyze

THIS_TOOL = "evtx-detector"
MANUAL_TOOLS = ["chainsaw", "hayabusa"]
COLUMNS = ["sample", "tool", "alerts", "notes"]


# ---------------------------------------------------------------------------
# CSV handling (pure, unit tested)
# ---------------------------------------------------------------------------

def template_rows(samples: list[str], tools=MANUAL_TOOLS) -> list[dict]:
    """One empty row per sample and tool, ready to be filled in."""
    return [{"sample": s, "tool": t, "alerts": "", "notes": ""} for s in samples for t in tools]


def read_rows(path: str) -> list[dict]:
    """Read the filled-in CSV. Empty 'alerts' = not filled in (kept as None)."""
    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        missing = [c for c in COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"{path}: missing column(s): {', '.join(missing)}")
        rows = []
        for number, row in enumerate(reader, start=2):
            text = (row["alerts"] or "").strip()
            if text and not text.isdigit():
                raise ValueError(f"{path} line {number}: alerts must be a whole number, "
                                 f"got '{text}'")
            rows.append({"sample": row["sample"].strip(), "tool": row["tool"].strip().lower(),
                         "alerts": int(text) if text else None,
                         "notes": (row["notes"] or "").strip()})
    return rows


def write_rows(rows: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows({**r, "alerts": "" if r["alerts"] is None else r["alerts"]}
                         for r in rows)


def pivot(rows: list[dict]) -> tuple[list[str], dict]:
    """-> (tool names, {sample: {tool: alerts or None}})."""
    tools: list[str] = []
    table: dict[str, dict] = {}
    for r in rows:
        if r["tool"] not in tools:
            tools.append(r["tool"])
        table.setdefault(r["sample"], {})[r["tool"]] = r["alerts"]
    return tools, table


def markdown_table(tools: list[str], table: dict) -> str:
    lines = ["| Sample | " + " | ".join(tools) + " |",
             "|---|" + "---:|" * len(tools)]
    for sample, counts in table.items():
        cells = ["not filled" if counts.get(t) is None else str(counts[t]) for t in tools]
        lines.append(f"| {sample} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Real runs
# ---------------------------------------------------------------------------

def own_counts(samples_dir: str, names: list[str]) -> list[dict]:
    """Run THIS tool (default settings) on each sample that exists locally."""
    rules, config = load_rules("rules"), load_config("config.yml")
    rows = []
    for name in names:
        path = os.path.join(samples_dir, name)
        if os.path.isfile(path):
            alerts, _ = analyze([path], rules, config)
            rows.append({"sample": name, "tool": THIS_TOOL, "alerts": len(alerts),
                         "notes": "run by compare_tools.py (default settings)"})
    return rows


def chainsaw_count(path: str, sigma: str, mapping: str) -> int:
    """Run chainsaw hunt on one file and return ONLY the number of detections."""
    with tempfile.TemporaryDirectory() as folder:
        out = os.path.join(folder, "chainsaw.json")
        subprocess.run(["chainsaw", "hunt", path, "-s", sigma, "--mapping", mapping,
                        "--json", "--output", out],
                       check=True, capture_output=True, timeout=600)
        with open(out, encoding="utf-8") as f:
            return len(json.load(f) or [])


def chainsaw_rows(samples_dir: str, names: list[str], sigma: str, mapping: str) -> list[dict]:
    rows = []
    for name in names:
        path = os.path.join(samples_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            count, note = chainsaw_count(path, sigma, mapping), "run by compare_tools.py"
        except Exception as exc:              # never guess a number
            count, note = None, f"chainsaw failed: {type(exc).__name__}"
        rows.append({"sample": name, "tool": "chainsaw", "alerts": count, "notes": note})
    return rows


HOW_TO = """\
chainsaw was not found on PATH, so it was NOT run. To run it yourself:
  1. Download a release from https://github.com/WithSecureLabs/chainsaw/releases
     and the Sigma rules from https://github.com/SigmaHQ/sigma
  2. chainsaw hunt samples/<file>.evtx -s sigma/rules --mapping mappings/sigma-event-logs-all.yml --json --output out.json
  3. Count the detections in out.json and type the number into the CSV.
Hayabusa (https://github.com/Yamato-Security/hayabusa/releases):
  hayabusa csv-timeline -f samples/<file>.evtx -o out.csv   (count the rows, minus the header)
"""


def sample_names(expected_path: str) -> list[str]:
    with open(expected_path, encoding="utf-8") as f:
        return [s["file"] for s in (yaml.safe_load(f) or {}).get("samples") or []]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Compare alert counts with Chainsaw / Hayabusa.")
    p.add_argument("csv", help="comparison CSV (sample, tool, alerts, notes)")
    p.add_argument("--init", action="store_true", help="create an empty template CSV")
    p.add_argument("--samples", default="samples")
    p.add_argument("--expected", default=os.path.join("tests", "expected_results.yml"))
    p.add_argument("--run-chainsaw", action="store_true",
                   help="run chainsaw if it is on PATH (needs --sigma and --mapping)")
    p.add_argument("--sigma", help="folder with Sigma rules (for chainsaw)")
    p.add_argument("--mapping", help="chainsaw mapping file (sigma-event-logs-all.yml)")
    p.add_argument("--markdown", default=os.path.join("output", "comparison.md"))
    args = p.parse_args(argv)

    names = sample_names(args.expected)
    if args.init:
        if os.path.exists(args.csv):
            print(f"[!] {args.csv} already exists - not overwritten", file=sys.stderr)
            return 2
        write_rows(template_rows(names), args.csv)
        print(f"[+] Template written: {args.csv} - fill in the 'alerts' column")
        return 0

    try:
        rows = [r for r in read_rows(args.csv) if r["tool"] != THIS_TOOL]
    except (OSError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if args.run_chainsaw:
        if shutil.which("chainsaw") is None:
            print(HOW_TO)
        elif not (args.sigma and args.mapping):
            print("[!] --run-chainsaw needs --sigma and --mapping", file=sys.stderr)
            return 2
        else:
            auto = chainsaw_rows(args.samples, names, args.sigma, args.mapping)
            done = {r["sample"] for r in auto}
            rows = [r for r in rows if not (r["tool"] == "chainsaw" and r["sample"] in done)]
            rows += auto
    elif shutil.which("chainsaw") is None:
        print("[i] chainsaw is not on PATH - only manually entered numbers are shown.")

    rows = own_counts(args.samples, names) + rows
    tools, table = pivot(rows)
    text = markdown_table(tools, table)
    print(text)
    os.makedirs(os.path.dirname(args.markdown) or ".", exist_ok=True)
    with open(args.markdown, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    print(f"\n[+] Written: {args.markdown}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
