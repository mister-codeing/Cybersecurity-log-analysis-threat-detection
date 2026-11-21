"""
dashboard.py - OPTIONAL web dashboard for the EVTX threat detector.

    pip install -r requirements-dashboard.txt
    streamlit run dashboard.py

This file only builds the user interface. All detection work is done by the
same code the command line uses (detector/pipeline.py), and all data
preparation lives in detector/dashboard_data.py (unit tested).

Security notes
  - Log content is attacker-controlled. It is only displayed with elements that
    show plain text (st.dataframe, st.code, charts) - never as Markdown/HTML,
    and unsafe_allow_html is not used anywhere.
  - Uploaded files are checked (extension + EVTX header), written to a private
    temporary folder under a sanitized name, analysed, and deleted.
  - The dashboard is meant to run locally (the "folder" option reads folders on
    the machine that runs Streamlit).
"""

from __future__ import annotations

import os
import tempfile

import altair as alt
import pandas as pd
import streamlit as st

from detector import dashboard_data as dd
from detector.correlation import load_config
from detector.engine import RuleError, load_rules
from detector.pipeline import find_evtx_files, run_pipeline
from detector.report import LEVEL_COLORS, MITRE_NAMES, build_html, csv_text, json_text, sort_alerts

RULES_DIR = "rules"
CONFIG_PATH = "config.yml"
SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_SCALE = alt.Scale(domain=SEVERITIES, range=[LEVEL_COLORS[s] for s in SEVERITIES])


# ---------------------------------------------------------------------------
# Cached analysis: changing a filter re-runs the whole script, but these
# functions then return the stored result instead of parsing the files again.
# The cache key is made of ALL arguments (files, thresholds, rule files), so
# changing any of them triggers a new analysis.
#
# The progress bar is created INSIDE the cached function and removed at its
# end: Streamlit records element calls made inside a cached function and
# replays them on a cache hit, which only works for elements created there.
# ---------------------------------------------------------------------------

def files_fingerprint(paths: list[str]) -> tuple:
    """(path, size, modification time) of each file - changes when a file changes."""
    result = []
    for path in paths:
        try:
            info = os.stat(path)
            result.append((path, info.st_size, info.st_mtime))
        except OSError:
            result.append((path, None, None))
    return tuple(result)


def rules_fingerprint() -> tuple:
    """Editing a rule file must invalidate the cache too."""
    names = sorted(n for n in os.listdir(RULES_DIR) if n.endswith((".yml", ".yaml")))
    return files_fingerprint([os.path.join(RULES_DIR, n) for n in names])


@st.cache_data(show_spinner=False, max_entries=10)
def analyze_uploads(uploads: tuple, config: dict, rules_key: tuple):
    """uploads = ((original name, file bytes), ...) -> (alerts, stats)."""
    bar = st.progress(0.0, text="Starting analysis...")
    with tempfile.TemporaryDirectory(prefix="evtx_upload_",
                                     ignore_cleanup_errors=True) as folder:
        display_names = {}
        paths = []
        for number, (name, data) in enumerate(uploads):
            path = os.path.join(folder, f"{number:03d}_{dd.safe_filename(name)}")
            with open(path, "wb") as f:
                f.write(data)
            paths.append(path)
            display_names[path] = dd.safe_filename(name)

        alerts, stats = run_pipeline(paths, RULES_DIR, config, progress=progress_callback(bar))
    # The temporary folder and files are deleted here.
    bar.empty()

    # Show the uploaded names instead of temporary paths.
    stats["files"] = [display_names.get(p, p) for p in stats["files"]]
    stats["failed_files"] = [display_names.get(p, p) for p in stats["failed_files"]]
    warnings = []
    for message in stats["warnings"]:
        for path, name in display_names.items():
            message = message.replace(path, name)
        warnings.append(message)
    stats["warnings"] = warnings
    return alerts, stats


@st.cache_data(show_spinner=False, max_entries=10)
def analyze_folder(folder: str, files_key: tuple, config: dict, rules_key: tuple):
    """Analyse every .evtx file in a folder -> (alerts, stats)."""
    bar = st.progress(0.0, text="Starting analysis...")
    result = run_pipeline([folder], RULES_DIR, config, progress=progress_callback(bar))
    bar.empty()
    return result


def progress_callback(bar):
    """Return a function that the pipeline calls to report progress."""
    def update(number: int, total: int, path: str, events: int) -> None:
        name = dd.safe_filename(os.path.basename(path))
        bar.progress((number - 1) / total,
                     text=f"File {number}/{total}: {name} - {events:,} events read")
    return update


def show_messages(title: str, messages: list[str]) -> None:
    """Show untrusted messages (they contain file names) as plain text."""
    if messages:
        st.warning(title)
        st.code("\n".join(messages), language=None)


# ---------------------------------------------------------------------------
# Page setup and sidebar
# ---------------------------------------------------------------------------

st.set_page_config(page_title="EVTX Threat Detection", page_icon="🛡️", layout="wide")
st.title("EVTX Threat Detection Dashboard")
st.caption("Windows Event Log analysis with YAML rules, correlation and MITRE ATT&CK mapping")

try:
    rules = load_rules(RULES_DIR)
    base_config = load_config(CONFIG_PATH)
    defaults = dd.default_thresholds(rules, base_config)
except (RuleError, ValueError, KeyError, OSError) as exc:
    st.error("Could not load the detection rules or config.yml.")
    st.code(str(exc), language=None)
    st.stop()

with st.sidebar:
    st.header("Logs")
    source = st.radio("Source", ["Upload .evtx files", "Folder on this computer"])
    if source == "Upload .evtx files":
        uploaded = st.file_uploader("EVTX files", type=["evtx"], accept_multiple_files=True)
    else:
        folder = st.text_input("Folder path", value="samples",
                               help="Searched recursively for .evtx files")

    st.header("Correlation thresholds")
    st.caption("Defaults come from config.yml")
    bf_count = st.number_input("Brute force: failed logons", 1, 10_000, defaults["bf_count"])
    bf_minutes = st.number_input("Brute force: window (minutes)", 1, 10_080,
                                 defaults["bf_minutes"])
    rdp_hosts = st.number_input("RDP: different hosts / sources", 1, 1_000,
                                defaults["rdp_hosts"])
    rdp_minutes = st.number_input("RDP: window (minutes)", 1, 10_080, defaults["rdp_minutes"])
    st.caption(f"{len(rules)} rules loaded from `{RULES_DIR}/`")

config = dd.build_config(base_config, bf_count, bf_minutes, rdp_hosts, rdp_minutes)


# ---------------------------------------------------------------------------
# Run the analysis (cached)
# ---------------------------------------------------------------------------

try:
    if source == "Upload .evtx files":
        if not uploaded:
            st.info("Upload one or more .evtx files in the sidebar, "
                    "or choose a folder (for example `samples`).")
            st.stop()
        accepted, rejected = [], []
        for file in uploaded:
            data = file.getvalue()
            error = dd.check_upload(dd.safe_filename(file.name), data)
            if error:
                rejected.append(error)
            else:
                accepted.append((file.name, data))
        show_messages(f"{len(rejected)} file(s) rejected", rejected)
        if not accepted:
            st.stop()
        alerts, stats = analyze_uploads(tuple(accepted), config, rules_fingerprint())
    else:
        if not os.path.isdir(folder):
            st.error("Folder not found. Enter a folder that contains .evtx files.")
            st.stop()
        files, _ = find_evtx_files([folder])
        alerts, stats = analyze_folder(folder, files_fingerprint(files), config,
                                       rules_fingerprint())
except (RuleError, ValueError) as exc:
    st.error("Analysis failed because of an invalid rule or setting.")
    st.code(str(exc), language=None)
    st.stop()

show_messages(f"{len(stats['failed_files'])} file(s) could not be read (corrupt or not EVTX)"
              if stats["failed_files"] else "Warnings", stats["warnings"])
if not stats["files"]:
    st.error("No file could be analysed.")
    st.stop()


# ---------------------------------------------------------------------------
# Metric cards (all alerts)
# ---------------------------------------------------------------------------

counts = dd.level_counts(alerts)
columns = st.columns(6)
columns[0].metric("Events parsed", f"{stats['events']:,}")
columns[1].metric("Alerts", len(alerts))
for column, level in zip(columns[2:], SEVERITIES):
    column.metric(level.capitalize(), counts[level])
st.caption(f"{len(stats['files'])} file(s) analysed")

if not alerts:
    st.success("No alerts - nothing suspicious was found with the current rules and thresholds.")
    st.stop()


# ---------------------------------------------------------------------------
# Filters (charts, table and downloads below follow them)
# ---------------------------------------------------------------------------

st.subheader("Filters")
options = dd.filter_options(alerts)
f1, f2, f3, f4 = st.columns(4)
chosen_severity = f1.multiselect("Severity", options["severity"])
chosen_mitre = f2.multiselect("MITRE technique", options["mitre"])
chosen_rule = f3.multiselect("Rule", options["rule"])
chosen_computer = f4.multiselect("Computer", options["computer"])
search = st.text_input("Search (any field, e.g. a user name or IP address)")

filtered = dd.filter_alerts(alerts, chosen_severity, chosen_mitre, chosen_rule,
                            chosen_computer, search)
st.caption(f"Showing {len(filtered)} of {len(alerts)} alerts (no filter selected = all)")


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------

c1, c2 = st.columns(2)
with c1:
    st.markdown("**Alerts by severity**")
    df_level = pd.DataFrame([{"severity": k, "count": v}
                             for k, v in dd.level_counts(filtered).items()])
    st.altair_chart(
        alt.Chart(df_level).mark_bar().encode(
            x=alt.X("severity:N", sort=SEVERITIES, title=None),
            y=alt.Y("count:Q", title="Alerts"),
            color=alt.Color("severity:N", scale=SEVERITY_SCALE, legend=None),
            tooltip=["severity", "count"]),
        width="stretch")
with c2:
    st.markdown("**Alerts by MITRE ATT&CK technique**")
    df_mitre = pd.DataFrame(dd.technique_counts(filtered), columns=["mitre", "count"])
    df_mitre["name"] = df_mitre["mitre"].map(lambda t: MITRE_NAMES.get(t, ""))
    st.altair_chart(
        alt.Chart(df_mitre).mark_bar(color="#1a5fb4").encode(
            y=alt.Y("mitre:N", sort="-x", title=None),
            x=alt.X("count:Q", title="Alerts"),
            tooltip=["mitre", "name", "count"]),
        width="stretch")

unit, timeline = dd.timeline_counts(filtered)
st.markdown(f"**Alerts over time** (per {unit}, UTC)")
if timeline:
    df_time = pd.DataFrame(timeline)
    st.altair_chart(
        alt.Chart(df_time).mark_bar(size=8).encode(
            x=alt.X("time:T", title=None),
            y=alt.Y("count:Q", stack=True, title="Alerts"),
            color=alt.Color("severity:N", scale=SEVERITY_SCALE),
            tooltip=[alt.Tooltip("time:T", format="%Y-%m-%d %H:%M"), "severity", "count"]),
        width="stretch")


# ---------------------------------------------------------------------------
# Alerts table + details of the selected row
# ---------------------------------------------------------------------------

st.subheader("Alerts")
st.caption("Click a column header to sort. Select a row to see its details.")
rows = dd.alert_rows(filtered)
table = st.dataframe(
    pd.DataFrame(rows),
    hide_index=True,
    width="stretch",
    column_order=["time", "severity", "rule", "mitre", "computer", "details"],
    on_select="rerun",
    selection_mode="single-row",
    key="alerts_table",
)

selected = table.selection.rows if table and table.selection else []
if selected and selected[0] < len(rows):
    alert = sort_alerts(filtered)[rows[selected[0]]["index"]]
    st.subheader("Alert details")
    # Shown as a table of plain-text values - never as Markdown/HTML.
    fields = [("Rule", alert["rule"]), ("Rule id", alert["rule_id"]),
              ("Severity", alert["level"]), ("Time (UTC)", alert["time"]),
              ("Computer", alert["computer"]),
              ("MITRE ATT&CK", f"{alert['mitre']} {MITRE_NAMES.get(alert['mitre'], '')}"),
              ("Description", alert.get("description", "")),
              ("Recommendation", alert.get("recommendation") or "(none in this rule)")]
    fields += [(str(k), v) for k, v in alert["details"].items()]
    st.dataframe(pd.DataFrame([{"field": k, "value": "" if v is None else str(v)}
                               for k, v in fields]),
                 hide_index=True, width="stretch")
    link = dd.mitre_link(alert["mitre"])
    if link:
        st.link_button(f"Open {alert['mitre']} on attack.mitre.org", link)
else:
    st.caption("No row selected.")


# ---------------------------------------------------------------------------
# Downloads (reuse the existing report generator)
# ---------------------------------------------------------------------------

st.subheader("Export")
d1, d2, d3 = st.columns(3)
d1.download_button("Filtered alerts (CSV)", csv_text(filtered).encode("utf-8-sig"),
                   file_name="alerts_filtered.csv", mime="text/csv")
d2.download_button("Filtered alerts (JSON)", json_text(filtered, stats).encode("utf-8"),
                   file_name="alerts_filtered.json", mime="application/json")
d3.download_button("Full HTML report", build_html(alerts, stats).encode("utf-8"),
                   file_name="report.html", mime="text/html")
