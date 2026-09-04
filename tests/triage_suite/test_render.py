"""Issue and comment text. This is the documentation record, so it is tested word by word."""

from triage import findings as F
from triage import render as R
from triage.cwe_vectors import load_table

from .fixtures import PYYAML_ADVISORY, SARIF_CERT_VALIDATION

ORIGIN = {"kind": "pr", "number": 12, "url": "https://github.com/o/r/pull/12", "sha": "abc1234"}


def dep():
    (f,) = F.findings_from_advisories("PyYAML", "5.3.1", "requirements.txt", [PYYAML_ADVISORY], ORIGIN)
    return f


def code():
    known, unknown = F.findings_from_sarif(SARIF_CERT_VALIDATION, load_table(), ORIGIN)
    return known, unknown


def test_marker_round_trips_through_a_body():
    body = R.issue_body(dep())
    assert R.key_from_body(body) == "dep:pyyaml:GHSA-8q59-q68h-6hv4"
    assert R.key_from_body("no marker here") is None


def test_dependency_issue_title_leads_with_priority_and_cve():
    assert R.issue_title(dep()) == "[P1] CVE-2020-14343: PyYAML 5.3.1, Improper Input Validation in PyYAML"


def test_dependency_issue_body_has_every_documentation_field():
    body = R.issue_body(dep())
    for needle in (
        "CVE-2020-14343",
        "GHSA-8q59-q68h-6hv4",
        "https://github.com/advisories/GHSA-8q59-q68h-6hv4",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-14343",
        "**CVSS 3.1 base score:** 9.8 (Critical)",
        "`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`",
        "**CVSS 4.0 base score:** 9.3",
        "**Priority:** P1",
        "**Package:** PyYAML 5.3.1",
        "`requirements.txt`",
        "**Fixed in:** 5.4",
        "https://github.com/o/r/pull/12",
        "GitHub Advisory Database",
        "Article 14",
    ):
        assert needle in body, needle


def test_code_issue_says_the_score_is_assessed_from_the_cwe_vector():
    known, _ = code()
    body = R.issue_body(known)
    assert R.issue_title(known) == "[P2] CWE-295: app/upstream.py:17, Improper Certificate Validation"
    assert "**CVSS 3.1 base score:** 7.4 (High)" in body
    assert "assessed" in body and "CWE-295" in body and "not a published NVD score" in body
    assert "https://semgrep.dev/r/python.requests.security.disabled-cert-validation.disabled-cert-validation" in body
    assert "app/upstream.py" in body and "line 17" in body


def test_unscored_code_issue_asks_for_a_vector():
    _, unknown = code()
    body = R.issue_body(unknown)
    assert R.issue_title(unknown).startswith("[needs-scoring] CWE-999:")
    assert "no CVSS vector" in body and ".cra/cwe-vectors.json" in body


def test_pr_comment_lists_findings_with_score_priority_and_issue_link():
    known, unknown = code()
    text = R.pr_comment([dep(), known, unknown], {"dep:pyyaml:GHSA-8q59-q68h-6hv4": "https://github.com/o/r/issues/20", known.key: "https://github.com/o/r/issues/21"})
    assert R.PR_COMMENT_MARKER in text
    assert "| CVE-2020-14343 | PyYAML 5.3.1 | 9.8 | P1 | [#20](https://github.com/o/r/issues/20) |" in text
    assert "| CWE-295 | app/upstream.py:17 | 7.4 (assessed) | P2 | [#21](https://github.com/o/r/issues/21) |" in text
    assert "| CWE-999 | app/x.py:3 | no vector | needs-scoring |" in text


def test_pr_comment_when_clean_says_so():
    text = R.pr_comment([], {})
    assert R.PR_COMMENT_MARKER in text and "No findings" in text


def test_close_and_reopen_comments_carry_action_markers():
    f = dep()
    f.state = "fixed"
    c = R.close_comment(f)
    assert R.action_from_comment(c) == "close" and "fixed" in c
    f.state = "dismissed"; f.dismissed_reason = "not_used"; f.dismissed_by = "alice"
    c = R.close_comment(f)
    assert "not_used" in c and "alice" in c
    r = R.reopen_comment(f)
    assert R.action_from_comment(r) == "reopen"
    assert R.action_from_comment("hello") is None
