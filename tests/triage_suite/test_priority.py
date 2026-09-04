"""The P1 to P4 chart, applied to a CVSS base score."""

import pytest

from triage.priority import LABELS, priority


@pytest.mark.parametrize(
    "score, expected",
    [(10.0, "P1"), (9.0, "P1"), (8.9, "P2"), (7.0, "P2"), (6.9, "P3"),
     (4.0, "P3"), (3.9, "P4"), (0.1, "P4"), (0.0, "P4")],
)
def test_chart_boundaries(score, expected):
    assert priority(score) == expected


def test_no_score_means_needs_scoring():
    assert priority(None) == "needs-scoring"


def test_every_priority_has_a_label_definition():
    for name in ("P1", "P2", "P3", "P4", "needs-scoring", "cra-triage"):
        assert name in LABELS
        assert LABELS[name]["description"]
        assert len(LABELS[name]["color"]) == 6
