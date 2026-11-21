"""Tests for evaluate.py - the pure comparison / counting logic.

These tests use hand-made values and the SYNTHETIC scenarios only; they never
need the real sample files.
"""

import os

import pytest

import evaluate
from detector.correlation import load_config
from detector.engine import load_rules
from tests.conftest import PROJECT_ROOT, RULES_DIR

EXPECTED_FILE = os.path.join(PROJECT_ROOT, "tests", "expected_results.yml")
RULE_MITRE = {"rule-001": "T1070.001", "rule-005": "T1053.005", "rule-006": "T1053.005",
              "rule-007": "T1110", "rule-009": "T1110"}


# ---------------------------------------------------------------------------
# compare()
# ---------------------------------------------------------------------------

def test_compare_exact_match_passes():
    r = evaluate.compare(["rule-005"], ["rule-005", "rule-005"])
    assert r == {"matched": ["rule-005"], "missing": [], "unexpected": [],
                 "allowed_hits": [], "passed": True}


def test_compare_missing_rule_is_false_negative():
    r = evaluate.compare(["rule-009"], [])
    assert r["missing"] == ["rule-009"] and not r["passed"]


def test_compare_extra_rule_is_false_positive():
    r = evaluate.compare([], ["rule-007"])
    assert r["unexpected"] == ["rule-007"] and not r["passed"]


def test_compare_allowed_rule_is_not_counted():
    r = evaluate.compare(["rule-005"], ["rule-001", "rule-005"], allowed=["rule-001"])
    assert r["passed"] and r["allowed_hits"] == ["rule-001"] and r["unexpected"] == []


def test_should_not_fire_wins_over_allowed():
    r = evaluate.compare([], ["rule-001"], allowed=["rule-001"], should_not=["rule-001"])
    assert r["unexpected"] == ["rule-001"] and not r["passed"]


def test_negative_sample_with_no_alerts_passes():
    assert evaluate.compare([], [])["passed"]


def test_allowed_rules_include_same_technique_and_global():
    entry = {"technique": ["T1053.005"], "allowed_rules": ["rule-009"]}
    assert evaluate.allowed_rules(entry, RULE_MITRE, ["rule-001"]) == \
        {"rule-001", "rule-005", "rule-006", "rule-009"}
    negative = {"technique": "none"}
    assert evaluate.allowed_rules(negative, RULE_MITRE) == set()


# ---------------------------------------------------------------------------
# Counting
# ---------------------------------------------------------------------------

def row(technique, matched=(), missing=(), unexpected=(), events=10, seconds=0.5):
    return {"technique": technique, "matched": list(matched), "missing": list(missing),
            "unexpected": list(unexpected), "events": events, "seconds": seconds,
            "passed": not missing and not unexpected}


ROWS = [
    row(["T1053.005"], matched=["rule-005"]),                       # pass
    row(["T1110"], missing=["rule-009"]),                           # FN
    row([], unexpected=["rule-007"], events=30, seconds=1.0),       # FP on negative
]


def test_summarize_counts():
    s = evaluate.summarize(ROWS)
    assert (s["evaluated"], s["passed"]) == (3, 1)
    assert (s["tp"], s["fn"], s["fp"]) == (1, 1, 1)
    assert s["events"] == 50 and s["seconds"] == 2.0 and s["events_per_second"] == 25


def test_summarize_empty():
    s = evaluate.summarize([])
    assert s["evaluated"] == 0 and s["events_per_second"] is None


def test_technique_table():
    table = {t["technique"]: t for t in evaluate.technique_table(ROWS, RULE_MITRE)}
    assert table["T1053.005"] == {"technique": "T1053.005", "samples": 1, "detected": 1,
                                  "tp": 1, "fn": 0, "fp": 0}
    assert table["T1110"]["samples"] == 1
    assert table["T1110"]["detected"] == 0
    assert table["T1110"]["fn"] == 1
    assert table["T1110"]["fp"] == 1          # the FP on the negative sample is T1110


# ---------------------------------------------------------------------------
# Ground truth file
# ---------------------------------------------------------------------------

def test_expected_results_file_is_valid():
    truth = evaluate.load_expected(EXPECTED_FILE)
    rule_ids = {r["id"] for r in load_rules(RULES_DIR)}
    samples = truth["samples"]
    assert len(samples) >= 10
    assert any(not s["expected_rules"] for s in samples)        # has a negative sample
    for s in samples:
        referenced = set(s["expected_rules"]) | set(s.get("should_not_fire") or [])
        assert referenced <= rule_ids, s["file"]
        assert s["justification"].strip()


def test_load_expected_rejects_bad_label(tmp_path):
    bad = tmp_path / "e.yml"
    bad.write_text("samples:\n  - {file: a.evtx, technique: none, expected_rules: [],"
                   " label: maybe, justification: x}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="label"):
        evaluate.load_expected(str(bad))


# ---------------------------------------------------------------------------
# SYNTHETIC scenarios run against the real rules
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scenario", evaluate.synthetic_scenarios(), ids=lambda s: s["name"])
def test_synthetic_scenarios_pass(scenario):
    rules = load_rules(RULES_DIR)
    config = load_config(os.path.join(PROJECT_ROOT, "config.yml"))
    result = evaluate.evaluate_synthetic(scenario, rules, config)
    assert result["data"] == "SYNTHETIC"
    assert result["passed"], result


def test_main_skips_missing_samples(tmp_path, capsys):
    code = evaluate.main(["--samples", str(tmp_path / "empty"), "--output",
                          str(tmp_path / "out"), "--no-docs",
                          "--rules", RULES_DIR,
                          "--config", os.path.join(PROJECT_ROOT, "config.yml"),
                          "--expected", EXPECTED_FILE])
    assert code == 0
    out = capsys.readouterr().out
    assert "[SKIP]" in out and "SYNTHETIC" in out
    assert (tmp_path / "out" / "evaluation.json").is_file()
    assert (tmp_path / "out" / "evaluation.csv").is_file()
