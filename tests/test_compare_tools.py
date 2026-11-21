"""Tests for compare_tools.py - reading the manual CSV and building the table.

No external tool is run: only hand-written CSV content (made-up numbers).
"""

import pytest

import compare_tools as ct


def write(tmp_path, text):
    path = tmp_path / "c.csv"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_template_has_one_empty_row_per_sample_and_tool(tmp_path):
    rows = ct.template_rows(["a.evtx", "b.evtx"])
    assert len(rows) == 4 and all(r["alerts"] == "" for r in rows)
    path = str(tmp_path / "t.csv")
    ct.write_rows([{**r, "alerts": None} for r in rows], path)
    assert [r["alerts"] for r in ct.read_rows(path)] == [None] * 4


def test_read_rows_and_pivot(tmp_path):
    path = write(tmp_path, "sample,tool,alerts,notes\n"
                           "a.evtx,Chainsaw,3,manual\n"
                           "a.evtx,hayabusa,,\n"
                           "b.evtx,chainsaw,0,\n")
    rows = ct.read_rows(path)
    assert rows[0] == {"sample": "a.evtx", "tool": "chainsaw", "alerts": 3, "notes": "manual"}
    tools, table = ct.pivot(rows)
    assert tools == ["chainsaw", "hayabusa"]
    assert table == {"a.evtx": {"chainsaw": 3, "hayabusa": None}, "b.evtx": {"chainsaw": 0}}
    md = ct.markdown_table(tools, table)
    assert "| a.evtx | 3 | not filled |" in md
    assert "| b.evtx | 0 | not filled |" in md


@pytest.mark.parametrize("text, message", [
    ("sample,tool,notes\n", "missing column"),
    ("sample,tool,alerts,notes\na.evtx,chainsaw,many,\n", "whole number"),
])
def test_bad_csv_is_rejected(tmp_path, text, message):
    with pytest.raises(ValueError, match=message):
        ct.read_rows(write(tmp_path, text))
