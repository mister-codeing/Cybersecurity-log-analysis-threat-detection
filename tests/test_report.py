"""Tests for detector/report.py - console, CSV, JSON and HTML output."""

import csv
import json

from detector.report import (build_html, mitre_url, print_console, sort_alerts,
                             summarize, write_reports)

ALERTS = [
    {"time": "2024-01-01T10:05:00+00:00", "computer": "PC01", "rule": "Security Log Cleared",
     "rule_id": "rule-001", "level": "high", "mitre": "T1070.001", "description": "",
     "details": {"SubjectUserName": "eve"}},
    {"time": "2024-01-01T10:00:00+00:00", "computer": "PC02", "rule": "<script>alert(1)</script>",
     "rule_id": "rule-x", "level": "critical", "mitre": "T1110", "description": "",
     "details": {"IpAddress": "10.0.0.9", "event_count": 7}},
]


def test_sort_alerts_is_chronological():
    assert [a["rule_id"] for a in sort_alerts(ALERTS)] == ["rule-x", "rule-001"]


def test_summarize_counts():
    summary = summarize(ALERTS)
    assert summary["total"] == 2
    assert summary["by_level"] == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert summary["by_technique"] == {"T1070.001": 1, "T1110": 1}


def test_mitre_url_for_sub_technique():
    assert mitre_url("T1070.001") == "https://attack.mitre.org/techniques/T1070/001/"
    assert mitre_url("T1110") == "https://attack.mitre.org/techniques/T1110/"


def test_console_output(capsys):
    print_console(ALERTS, {"files": ["a.evtx"], "events": 10, "rules": 3})
    out = capsys.readouterr().out
    assert "Alerts         : 2" in out
    assert "[CRITICAL]" in out and "[HIGH]" in out
    assert "SubjectUserName: eve" in out


def test_write_all_file_formats(tmp_path):
    paths = write_reports(ALERTS, ["csv", "json", "html"], str(tmp_path / "out"))
    assert len(paths) == 3

    with open(tmp_path / "out" / "alerts.csv", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    assert [r["rule_id"] for r in rows] == ["rule-x", "rule-001"]
    assert rows[0]["details"] == "IpAddress=10.0.0.9; event_count=7"

    with open(tmp_path / "out" / "alerts.json", encoding="utf-8") as f:
        report = json.load(f)
    assert report["summary"]["total"] == 2
    assert report["alerts"][0]["mitre"] == "T1110"

    html = (tmp_path / "out" / "report.html").read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>")


def test_html_content_and_escaping():
    page = build_html(ALERTS, {"files": ["a"], "events": 1, "rules": 1})
    assert '<table id="alerts">' in page                       # sortable table
    assert 'class="timeline"' in page                          # timeline
    assert "attack.mitre.org/techniques/T1070/001/" in page    # MITRE links
    assert "#b3123a" in page                                   # critical color
    # Event data must never be able to inject HTML/JavaScript.
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_html_without_alerts():
    page = build_html([])
    assert "No alerts" in page
    assert '<table id="alerts">' not in page


def test_csv_and_json_text_match_files(tmp_path):
    from detector.report import csv_text, json_text
    text = csv_text(ALERTS)
    assert text.splitlines()[0] == "time,level,rule_id,rule,mitre,computer,details"
    assert len(text.splitlines()) == 3
    assert json.loads(json_text(ALERTS))["summary"]["total"] == 2


def test_csv_formula_injection_is_neutralized():
    from detector.report import csv_text, safe_cell
    assert safe_cell("=1+1") == "'=1+1"
    assert safe_cell("@SUM(A1)") == "'@SUM(A1)"
    assert safe_cell("normal") == "normal"
    alert = dict(ALERTS[0], computer='=HYPERLINK("http://evil")')
    row = list(csv.reader(csv_text([alert]).splitlines()))[1]
    assert row[5] == '\'=HYPERLINK("http://evil")'
