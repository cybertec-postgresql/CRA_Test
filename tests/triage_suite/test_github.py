"""The thin API client, exercised through a fake transport."""

import json

import pytest

from triage.github import GitHub, WriteForbidden


class Transport:
    def __init__(self, routes):
        self.routes = routes
        self.log = []

    def __call__(self, method, url, body):
        self.log.append((method, url, body))
        for (m, u), resp in self.routes.items():
            if m == method and u in url:
                return resp
        return (404, {"message": f"no route {method} {url}"})


def make(routes):
    t = Transport(routes)
    return GitHub("tok", "o/r", transport=t), t


def test_pypi_name_canonicalises_case():
    gh, t = make({("GET", "pypi.org/pypi/pyyaml/json"): (200, {"info": {"name": "PyYAML"}})})
    assert gh.pypi_name("pyyaml") == "PyYAML"


def test_pypi_name_falls_back_to_input_when_unknown():
    gh, t = make({})
    assert gh.pypi_name("nonesuch") == "nonesuch"


def test_advisories_query_uses_canonical_name_and_ecosystem():
    gh, t = make({
        ("GET", "pypi.org/pypi/pyyaml/json"): (200, {"info": {"name": "PyYAML"}}),
        ("GET", "/advisories?ecosystem=pip&affects=PyYAML%405.3.1"): (200, [{"ghsa_id": "GHSA-1"}]),
    })
    assert gh.advisories("pyyaml", "5.3.1") == [{"ghsa_id": "GHSA-1"}]


def test_ensure_labels_creates_only_missing_ones():
    gh, t = make({
        ("GET", "/repos/o/r/labels"): (200, [{"name": "P1"}, {"name": "cra-triage"}]),
        ("POST", "/repos/o/r/labels"): (201, {}),
    })
    created = gh.ensure_labels()
    assert "P1" not in created and "P2" in created and "needs-scoring" in created
    posted = [json.loads(b)["name"] for m, u, b in t.log if m == "POST"]
    assert set(posted) == set(created)


def test_write_on_read_only_token_raises_a_named_error():
    gh, t = make({("POST", "/repos/o/r/issues"): (403, {"message": "Resource not accessible by integration"})})
    with pytest.raises(WriteForbidden):
        gh.create_issue("t", "b", [], [])


def test_find_issue_scans_triage_labelled_issues_of_all_states():
    body = "<!-- cra-triage: key=dep:pyyaml:GHSA-1 -->\nx"
    gh, t = make({("GET", "/repos/o/r/issues?"): (200, [{"number": 1, "body": body, "state": "closed"}])})
    assert gh.find_issue("dep:pyyaml:GHSA-1")["number"] == 1
    assert gh.find_issue("dep:other") is None
    url = t.log[0][1]
    assert "labels=cra-triage" in url and "state=all" in url


def test_upsert_pr_comment_edits_the_existing_marker_comment():
    marker = "<!-- cra-triage: pr-summary -->"
    gh, t = make({
        ("GET", "/repos/o/r/issues/12/comments"): (200, [{"id": 5, "body": marker + " old"}]),
        ("PATCH", "/repos/o/r/issues/comments/5"): (200, {}),
    })
    gh.upsert_pr_comment(12, marker + " new")
    assert [m for m, u, b in t.log] == ["GET", "PATCH"]


def test_upsert_pr_comment_creates_when_absent():
    marker = "<!-- cra-triage: pr-summary -->"
    gh, t = make({
        ("GET", "/repos/o/r/issues/12/comments"): (200, []),
        ("POST", "/repos/o/r/issues/12/comments"): (201, {}),
    })
    gh.upsert_pr_comment(12, marker + " new")
    assert [m for m, u, b in t.log] == ["GET", "POST"]


def test_api_error_carries_the_validation_detail():
    gh, t = make({("POST", "/repos/o/r/labels"): (422, {"message": "Validation Failed", "errors": [{"resource": "Label", "field": "description", "code": "invalid"}]})})
    from triage.github import ApiError
    with pytest.raises(ApiError) as exc:
        gh.post("/repos/o/r/labels", {"name": "x"})
    assert "description" in str(exc.value) and "invalid" in str(exc.value)


def test_ensure_labels_tolerates_a_label_created_meanwhile():
    gh, t = make({
        ("GET", "/repos/o/r/labels"): (200, []),
        ("POST", "/repos/o/r/labels"): (422, {"message": "Validation Failed", "errors": [{"resource": "Label", "code": "already_exists", "field": "name"}]}),
    })
    assert gh.ensure_labels() == []
