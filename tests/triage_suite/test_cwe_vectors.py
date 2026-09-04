"""The CWE to CVSS vector table that scores Semgrep findings."""

import json
from pathlib import Path

import pytest

from triage.cvss import base_score
from triage.cwe_vectors import TABLE_PATH, load_table, score_for_cwe

REPO_TABLE = Path(__file__).resolve().parents[2] / ".cra" / "cwe-vectors.json"


def test_default_table_path_is_the_repo_file():
    assert TABLE_PATH == REPO_TABLE


def test_every_row_in_the_repo_table_states_the_score_its_vector_computes_to():
    rows = json.loads(REPO_TABLE.read_text())
    assert rows, "table must not be empty"
    for cwe, row in rows.items():
        assert cwe.startswith("CWE-")
        for field in ("name", "vector", "score", "rationale"):
            assert row.get(field), f"{cwe} is missing {field}"
        assert base_score(row["vector"]) == row["score"], cwe


def test_repo_table_covers_the_classes_used_in_gate_fixtures():
    rows = json.loads(REPO_TABLE.read_text())
    for cwe in ("CWE-295", "CWE-502", "CWE-78", "CWE-22", "CWE-327", "CWE-489", "CWE-89"):
        assert cwe in rows


def test_score_for_known_cwe(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"CWE-295": {"name": "x", "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", "score": 7.4, "rationale": "r"}}))
    table = load_table(p)
    assert score_for_cwe(table, "CWE-295") == (7.4, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N")


def test_unknown_cwe_is_none_not_a_guess(tmp_path):
    p = tmp_path / "t.json"
    p.write_text("{}")
    assert score_for_cwe(load_table(p), "CWE-999") is None


def test_table_row_with_wrong_score_is_rejected_on_load(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"CWE-1": {"name": "x", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 5.0, "rationale": "r"}}))
    with pytest.raises(ValueError):
        load_table(p)
