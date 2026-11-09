"""
report.py - Present the alerts: console summary, CSV, JSON and HTML.

All functions receive the same list of alert dicts (see engine.make_alert)
plus an optional 'stats' dict with information about the scan:

    stats = {"files": [...], "failed_files": [...], "events": 1234, "rules": 16}
"""

from __future__ import annotations

import csv
import html
import io
import json
import os
from collections import Counter
from datetime import datetime, timezone

from detector.engine import LEVELS

# Human-readable names for the techniques this project detects.
MITRE_NAMES = {
    "T1110": "Brute Force",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
}

# Colors used in the HTML report for each severity.
LEVEL_COLORS = {"low": "#2b7bb9", "medium": "#d89614",
                "high": "#e0561b", "critical": "#b3123a"}


# ---------------------------------------------------------------------------
# Helpers shared by all formats
# ---------------------------------------------------------------------------

def level_rank(level: str) -> int:
    """low=0, medium=1, high=2, critical=3 (unknown levels sort first)."""
    return LEVELS.index(level) if level in LEVELS else -1


def sort_alerts(alerts: list[dict]) -> list[dict]:
    """Chronological order (alerts without a time go last)."""
    return sorted(alerts, key=lambda a: (a.get("time") is None, a.get("time") or ""))


def mitre_url(technique: str) -> str:
    """T1070.001 -> https://attack.mitre.org/techniques/T1070/001/"""
    return f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"


def details_text(details: dict, sep: str = "; ") -> str:
    """{'a': 1, 'b': None} -> 'a=1; b=None'"""
    return sep.join(f"{k}={v}" for k, v in details.items())


def summarize(alerts: list[dict]) -> dict:
    """Count alerts per level, per MITRE technique and per rule."""
    by_level = Counter(a["level"] for a in alerts)
    return {
        "total": len(alerts),
        "by_level": {lvl: by_level.get(lvl, 0) for lvl in reversed(LEVELS)},
        "by_technique": dict(Counter(a["mitre"] for a in alerts).most_common()),
        "by_rule": dict(Counter(a["rule"] for a in alerts).most_common()),
    }


# ---------------------------------------------------------------------------
# (a) Console
# ---------------------------------------------------------------------------

def print_console(alerts: list[dict], stats: dict | None = None) -> None:
    """Print a summary followed by every alert in chronological order."""
    stats = stats or {}
    summary = summarize(alerts)
    levels = ", ".join(f"{lvl} {n}" for lvl, n in summary["by_level"].items() if n)

    print("=" * 70)
    print(" DETECTION SUMMARY")
    print("=" * 70)
    if "files" in stats:
        failed = len(stats.get("failed_files", []))
        print(f" Files analysed : {len(stats['files'])}"
              + (f"  ({failed} could not be read)" if failed else ""))
    if "events" in stats:
        print(f" Events parsed  : {stats['events']}")
    if "rules" in stats:
        print(f" Rules loaded   : {stats['rules']}")
    print(f" Alerts         : {summary['total']}" + (f"  ({levels})" if levels else ""))

    if summary["by_technique"]:
        print("\n Alerts per MITRE ATT&CK technique:")
        for technique, count in summary["by_technique"].items():
            name = MITRE_NAMES.get(technique, "")
            print(f"   {technique:<10} {name:<50} {count:>4}")

    if alerts:
        print("\n" + "=" * 70)
        print(" ALERTS (chronological)")
        print("=" * 70)
    for a in sort_alerts(alerts):
        print(f"[{a['level'].upper()}] {a['time']} | {a['computer']} | "
              f"{a['rule']} ({a['mitre']})")
        for key, value in a["details"].items():
            print(f"        {key}: {value}")


# ---------------------------------------------------------------------------
# (b) CSV
# ---------------------------------------------------------------------------

CSV_COLUMNS = ["time", "level", "rule_id", "rule", "mitre", "computer", "details"]


def safe_cell(value) -> str:
    """Protect against CSV/formula injection.

    Log data is attacker-controlled. A username like '=HYPERLINK(...)' would be
    executed as a formula when the CSV is opened in Excel, so cells starting
    with = + - @ get a leading apostrophe (Excel then shows them as text).
    """
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def csv_text(alerts: list[dict]) -> str:
    """Return the CSV report as a string (used for files and downloads)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)          # rows end with \r\n (CSV standard)
    writer.writerow(CSV_COLUMNS)
    for a in sort_alerts(alerts):
        writer.writerow([safe_cell(v) for v in (
            a["time"], a["level"], a["rule_id"], a["rule"],
            a["mitre"], a["computer"], details_text(a["details"]))])
    return buffer.getvalue()


def write_csv(alerts: list[dict], path: str) -> str:
    """One row per alert. 'utf-8-sig' lets Excel open the file correctly."""
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        f.write(csv_text(alerts))
    return path


# ---------------------------------------------------------------------------
# (c) JSON
# ---------------------------------------------------------------------------

def json_text(alerts: list[dict], stats: dict | None = None) -> str:
    """Machine-readable report as a string: scan info + summary + all alerts."""
    report = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scan": stats or {},
        "summary": summarize(alerts),
        "alerts": sort_alerts(alerts),
    }
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def write_json(alerts: list[dict], path: str, stats: dict | None = None) -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(json_text(alerts, stats))
    return path


# ---------------------------------------------------------------------------
# (d) HTML - one self-contained file (no internet needed to open it)
# ---------------------------------------------------------------------------

HTML_STYLE = """
:root { --bg:#f6f7f9; --card:#fff; --text:#1d2330; --muted:#5d6675; --line:#dfe3ea; }
* { box-sizing:border-box; }
body { margin:0; padding:24px; background:var(--bg); color:var(--text);
       font:14px/1.5 -apple-system, "Segoe UI", Roboto, Arial, sans-serif; }
h1 { margin:0 0 4px; font-size:22px; }
h2 { margin:32px 0 12px; font-size:17px; }
.muted { color:var(--muted); }
.cards { display:flex; flex-wrap:wrap; gap:12px; margin-top:16px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px;
        padding:12px 16px; min-width:120px; }
.card b { display:block; font-size:24px; }
.wrap { overflow-x:auto; background:var(--card); border:1px solid var(--line); border-radius:8px; }
table { border-collapse:collapse; width:100%; }
th, td { padding:8px 10px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
th { background:#eef1f5; cursor:pointer; user-select:none; white-space:nowrap; }
th:hover { background:#e2e7ee; }
th.asc::after { content:" \\25B2"; } th.desc::after { content:" \\25BC"; }
td.time { white-space:nowrap; font-family:Consolas, monospace; font-size:12px; }
td.details { font-family:Consolas, monospace; font-size:12px; word-break:break-all; }
.badge { display:inline-block; padding:2px 8px; border-radius:10px; color:#fff;
         font-size:12px; font-weight:600; text-transform:uppercase; }
a { color:#1a5fb4; }
.timeline { list-style:none; margin:0; padding:0 0 0 18px; border-left:3px solid var(--line); }
.timeline li { position:relative; margin:0 0 14px; padding-left:12px; }
.timeline li::before { content:""; position:absolute; left:-27px; top:5px; width:12px; height:12px;
                       border-radius:50%; background:var(--dot); border:2px solid var(--bg); }
.empty { padding:16px; }
"""

# Click a column header to sort. Severity is sorted by rank, not alphabetically.
HTML_SCRIPT = """
document.querySelectorAll("#alerts th").forEach(function (th, col) {
  th.addEventListener("click", function () {
    var tbody = document.querySelector("#alerts tbody");
    var rows = Array.from(tbody.rows);
    var asc = !th.classList.contains("asc");
    document.querySelectorAll("#alerts th").forEach(function (h) { h.className = ""; });
    th.className = asc ? "asc" : "desc";
    rows.sort(function (a, b) {
      var x = a.cells[col].dataset.sort || a.cells[col].textContent;
      var y = b.cells[col].dataset.sort || b.cells[col].textContent;
      return (asc ? 1 : -1) * x.localeCompare(y, undefined, {numeric: true});
    });
    rows.forEach(function (r) { tbody.appendChild(r); });
  });
});
"""


def _badge(level: str) -> str:
    color = LEVEL_COLORS.get(level, "#666")
    return f'<span class="badge" style="background:{color}">{html.escape(level)}</span>'


def _mitre_link(technique: str) -> str:
    name = MITRE_NAMES.get(technique, "")
    return (f'<a href="{html.escape(mitre_url(technique))}" target="_blank" '
            f'title="{html.escape(name)}">{html.escape(technique)}</a>')


def build_html(alerts: list[dict], stats: dict | None = None) -> str:
    """Return the full HTML report as a string."""
    esc = html.escape
    stats = stats or {}
    summary = summarize(alerts)
    ordered = sort_alerts(alerts)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # --- summary cards ---
    cards = [f'<div class="card">Total alerts<b>{summary["total"]}</b></div>']
    for lvl, n in summary["by_level"].items():
        cards.append(f'<div class="card" style="border-top:4px solid {LEVEL_COLORS[lvl]}">'
                     f'{lvl.capitalize()}<b>{n}</b></div>')
    scan_info = (f'{len(stats.get("files", []))} file(s), {stats.get("events", "?")} events, '
                 f'{stats.get("rules", "?")} rules' if stats else "")

    # --- technique table ---
    tech_rows = "".join(
        f"<tr><td>{_mitre_link(t)}</td><td>{esc(MITRE_NAMES.get(t, ''))}</td><td>{n}</td></tr>"
        for t, n in summary["by_technique"].items())

    # --- alerts table ---
    alert_rows = []
    for a in ordered:
        details = "<br>".join(f"<b>{esc(str(k))}</b>: {esc(str(v))}"
                              for k, v in a["details"].items())
        alert_rows.append(
            "<tr>"
            f'<td class="time">{esc(str(a["time"]))}</td>'
            f'<td data-sort="{level_rank(a["level"])}">{_badge(a["level"])}</td>'
            f'<td>{esc(a["rule"])}<br><span class="muted">{esc(str(a["rule_id"]))}</span></td>'
            f'<td data-sort="{esc(a["mitre"])}">{_mitre_link(a["mitre"])}</td>'
            f'<td>{esc(str(a["computer"]))}</td>'
            f'<td class="details">{details}</td>'
            "</tr>")

    # --- timeline ---
    timeline = "".join(
        f'<li style="--dot:{LEVEL_COLORS.get(a["level"], "#666")}">'
        f'<span class="muted">{esc(str(a["time"]))}</span> {_badge(a["level"])}<br>'
        f'<b>{esc(a["rule"])}</b> on {esc(str(a["computer"]))} ({esc(a["mitre"])})</li>'
        for a in ordered)

    if not alerts:
        alerts_html = '<div class="wrap empty">No alerts - nothing suspicious was found.</div>'
        timeline_html = ""
    else:
        alerts_html = (
            '<div class="wrap"><table id="alerts"><thead><tr>'
            "<th>Time (UTC)</th><th>Severity</th><th>Rule</th><th>MITRE</th>"
            "<th>Computer</th><th>Details</th></tr></thead><tbody>"
            + "".join(alert_rows) + "</tbody></table></div>")
        timeline_html = f'<h2>Timeline</h2><ul class="timeline">{timeline}</ul>'

    tech_html = ("" if not tech_rows else
                 '<h2>MITRE ATT&amp;CK techniques</h2><div class="wrap"><table>'
                 "<thead><tr><th>ID</th><th>Technique</th><th>Alerts</th></tr></thead>"
                 f"<tbody>{tech_rows}</tbody></table></div>")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Threat Detection Report</title>
<style>{HTML_STYLE}</style>
</head>
<body>
<h1>Threat Detection Report</h1>
<div class="muted">Generated {generated}{" &middot; " + esc(scan_info) if scan_info else ""}</div>
<div class="cards">{"".join(cards)}</div>
{tech_html}
<h2>Alerts <span class="muted">(click a column header to sort)</span></h2>
{alerts_html}
{timeline_html}
<script>{HTML_SCRIPT}</script>
</body>
</html>
"""


def write_html(alerts: list[dict], path: str, stats: dict | None = None) -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_html(alerts, stats))
    return path


# ---------------------------------------------------------------------------
# Write several formats at once
# ---------------------------------------------------------------------------

FILE_FORMATS = {"csv": "alerts.csv", "json": "alerts.json", "html": "report.html"}


def write_reports(alerts: list[dict], formats: list[str], output_dir: str,
                  stats: dict | None = None) -> list[str]:
    """Create the requested report files and return their paths."""
    written = []
    if "console" in formats:
        print_console(alerts, stats)

    file_formats = [f for f in formats if f in FILE_FORMATS]
    if file_formats:
        os.makedirs(output_dir, exist_ok=True)
    for fmt in file_formats:
        path = os.path.join(output_dir, FILE_FORMATS[fmt])
        if fmt == "csv":
            written.append(write_csv(alerts, path))
        elif fmt == "json":
            written.append(write_json(alerts, path, stats))
        else:
            written.append(write_html(alerts, path, stats))
    return written
