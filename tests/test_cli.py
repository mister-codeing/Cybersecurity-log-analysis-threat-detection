"""Tests for main.py (the command line interface) + one real-file integration test."""

import json
import os

import pytest

import main
from tests.conftest import RULES_DIR, SAMPLES_DIR

SAMPLE_1102 = os.path.join(SAMPLES_DIR, "DE_1102_security_log_cleared.evtx")


def test_parse_formats():
    assert main.parse_formats("console, HTML") == ["console", "html"]
    with pytest.raises(ValueError):
        main.parse_formats("pdf")


def test_missing_path_returns_error(capsys):
    assert main.main(["does_not_exist.evtx", "--rules", RULES_DIR]) == main.EXIT_ERROR
    assert "path not found" in capsys.readouterr().err


def test_bad_options_return_error():
    assert main.main(["x.evtx", "--format", "pdf"]) == main.EXIT_ERROR
    assert main.main(["x.evtx", "--timeframe", "soon", "--rules", RULES_DIR]) == main.EXIT_ERROR
    assert main.main(["x.evtx", "--rules", "no_such_rules_dir"]) == main.EXIT_ERROR


def test_corrupt_file_is_reported_not_crashing(tmp_path, capsys):
    bad = tmp_path / "broken.evtx"
    bad.write_bytes(b"this is not an evtx file")
    code = main.main([str(bad), "--rules", RULES_DIR, "--config", ""])
    assert code == main.EXIT_ERROR              # no file could be read
    assert "could not read" in capsys.readouterr().err


def test_find_evtx_files_in_folder(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.evtx").write_bytes(b"")
    (tmp_path / "sub" / "b.EVTX").write_bytes(b"")
    (tmp_path / "notes.txt").write_text("x")
    files, errors = main.find_evtx_files([str(tmp_path)])
    assert [os.path.basename(f) for f in files] == ["a.evtx", "b.EVTX"]
    assert errors == []


@pytest.mark.skipif(not os.path.isfile(SAMPLE_1102),
                    reason="sample EVTX not present (see README 'Sample data')")
def test_integration_security_log_cleared(tmp_path):
    """Real EVTX file: exactly one HIGH 'Security Log Cleared' alert."""
    out = tmp_path / "out"
    code = main.main([SAMPLE_1102, "--rules", RULES_DIR, "--format", "json,html",
                      "--output", str(out)])
    assert code == main.EXIT_OK

    report = json.loads((out / "alerts.json").read_text(encoding="utf-8"))
    assert report["summary"]["total"] == 1
    [alert] = report["alerts"]
    assert alert["level"] == "high"
    assert alert["rule_id"] == "rule-001"
    assert alert["mitre"] == "T1070.001"
    assert (out / "report.html").is_file()
