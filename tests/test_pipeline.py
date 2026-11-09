"""Tests for detector/pipeline.py - the shared 'run everything' functions."""

import os

import pytest

from detector.engine import RuleError
from detector.pipeline import filter_by_level, run_pipeline
from tests.conftest import RULES_DIR, SAMPLES_DIR

SAMPLE_1102 = os.path.join(SAMPLES_DIR, "DE_1102_security_log_cleared.evtx")


def test_filter_by_level():
    alerts = [{"level": lvl} for lvl in ("low", "medium", "high", "critical")]
    assert [a["level"] for a in filter_by_level(alerts, "high")] == ["high", "critical"]
    assert len(filter_by_level(alerts)) == 4


def test_missing_path_is_a_warning_not_a_crash():
    alerts, stats = run_pipeline(["no/such/file.evtx"], rules_dir=RULES_DIR, config=None)
    assert alerts == []
    assert stats["files"] == []
    assert any("path not found" in w for w in stats["warnings"])


def test_corrupt_file_is_reported(tmp_path):
    bad = tmp_path / "bad.evtx"
    bad.write_bytes(b"not an evtx file")
    alerts, stats = run_pipeline([str(bad)], rules_dir=RULES_DIR, config={})
    assert stats["failed_files"] == [str(bad)]
    assert any("could not read" in w for w in stats["warnings"])


def test_invalid_rules_dir_raises():
    with pytest.raises(RuleError):
        run_pipeline([], rules_dir="no_such_rules_dir")


@pytest.mark.skipif(not os.path.isfile(SAMPLE_1102), reason="sample EVTX not present")
def test_run_pipeline_on_sample_reports_progress():
    calls = []
    alerts, stats = run_pipeline([SAMPLE_1102], rules_dir=RULES_DIR, config={},
                                 progress=lambda *args: calls.append(args))
    assert [a["rule_id"] for a in alerts] == ["rule-001"]
    assert stats["events"] > 0 and stats["files"] == [SAMPLE_1102]
    assert calls[0] == (1, 1, SAMPLE_1102, 0)          # called when the file starts
    # min_level filters the result
    alerts, _ = run_pipeline([SAMPLE_1102], rules_dir=RULES_DIR, config={},
                             min_level="critical")
    assert alerts == []
