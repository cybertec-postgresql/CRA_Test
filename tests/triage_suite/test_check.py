"""The configuration check the workflows run before triage: labels and the vector table."""

import json

import pytest

from triage import __main__ as cli
from triage.check import LABEL_DESCRIPTION_LIMIT, LABEL_NAME_LIMIT, problems


def test_github_limits_are_the_documented_ones():
    assert LABEL_DESCRIPTION_LIMIT == 100
    assert LABEL_NAME_LIMIT == 50


def test_shipped_configuration_has_no_problems():
    assert problems() == []


def test_over_long_description_is_reported_with_its_length():
    labels = {"P9": {"color": "000000", "description": "x" * 101}}
    (msg,) = problems(labels=labels)
    assert "P9" in msg and "101" in msg and "100" in msg


def test_over_long_name_and_bad_colour_are_reported():
    labels = {"n" * 51: {"color": "zzz", "description": "ok"}}
    msgs = problems(labels=labels)
    assert any("51" in m for m in msgs) and any("colour" in m for m in msgs)


def test_inconsistent_vector_table_is_reported(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"CWE-1": {"name": "x", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 1.0, "rationale": "r"}}))
    (msg,) = problems(table_path=p)
    assert "CWE-1" in msg


def test_check_command_exit_codes(monkeypatch, capsys):
    assert cli.main(["check"]) == 0
    monkeypatch.setattr("triage.check.LABELS", {"P9": {"color": "000000", "description": "x" * 101}})
    assert cli.main(["check"]) == 1
    assert "P9" in capsys.readouterr().out
