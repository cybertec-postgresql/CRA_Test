"""CVSS 3.1 base score, computed the way NVD computes it: from the vector."""

import pytest

from triage.cvss import base_score, qualitative


@pytest.mark.parametrize(
    "vector, expected",
    [
        # CVE-2020-14343, PyYAML: published NVD score 9.8
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        # Disabled certificate validation, CWE-295 vector from the table
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4),
        # Classic reflected XSS, scope changed
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        # Local info disclosure needing low privileges
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        # Weak hash
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
        # Privileged, scope changed: PR weight switches to the changed-scope value
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
        # No impact at all
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        # 3.0 vectors score identically
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ],
)
def test_base_score_matches_published_values(vector, expected):
    assert base_score(vector) == expected


def test_rejects_vectors_that_are_not_3x():
    with pytest.raises(ValueError):
        base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    with pytest.raises(ValueError):
        base_score("AV:N/AC:L")


def test_rejects_missing_metric():
    with pytest.raises(ValueError):
        base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")


@pytest.mark.parametrize(
    "score, label",
    [(0.0, "None"), (0.1, "Low"), (3.9, "Low"), (4.0, "Medium"), (6.9, "Medium"),
     (7.0, "High"), (8.9, "High"), (9.0, "Critical"), (10.0, "Critical")],
)
def test_qualitative_rating(score, label):
    assert qualitative(score) == label
