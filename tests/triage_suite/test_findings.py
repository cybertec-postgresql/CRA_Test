"""Turning scanner output into Findings with a score, a vector and a stable key."""

from triage import findings as F
from triage.cwe_vectors import load_table

from .fixtures import (CODE_SCANNING_ALERT_OPEN, DEPENDABOT_ALERT_OPEN, PYYAML_ADVISORY,
                       REQUESTS_ADVISORY_NO_CVE, SARIF_CERT_VALIDATION)

ORIGIN = {"kind": "pr", "number": 12, "url": "https://github.com/o/r/pull/12", "sha": "abc"}


def test_parse_requirements_reads_exact_pins_only():
    text = "flask==3.1.3\n# comment\npsycopg[binary]==3.2.3\nrequests>=2\n\nPyYAML == 5.3.1\n-r other.txt\n"
    assert F.parse_requirements(text) == {"flask": "3.1.3", "psycopg": "3.2.3", "pyyaml": "5.3.1"}


def test_added_pins_are_new_or_changed_versions():
    base = "flask==3.1.3\nrequests==2.32.0\n"
    head = "flask==3.1.3\nrequests==2.31.0\nPyYAML==5.3.1\n"
    assert F.added_pins(base, head) == [("pyyaml", "5.3.1"), ("requests", "2.31.0")]


def test_dependency_finding_carries_published_scores_and_links():
    (f,) = F.findings_from_advisories("PyYAML", "5.3.1", "requirements.txt", [PYYAML_ADVISORY], ORIGIN)
    assert f.key == "dep:pyyaml:GHSA-8q59-q68h-6hv4"
    assert f.kind == "dependency"
    assert f.cve_id == "CVE-2020-14343"
    assert f.cvss31_score == 9.8
    assert f.cvss31_vector.endswith("C:H/I:H/A:H")
    assert f.cvss4_score == 9.3
    assert f.score_source == "advisory"
    assert f.priority == "P1"
    assert f.fixed_in == "5.4"
    assert f.advisory_url == "https://github.com/advisories/GHSA-8q59-q68h-6hv4"
    assert f.nvd_url == "https://nvd.nist.gov/vuln/detail/CVE-2020-14343"
    assert f.cwes == ["CWE-20"]
    assert f.state == "open"


def test_advisory_without_cve_still_gets_an_issue_keyed_by_ghsa():
    (f,) = F.findings_from_advisories("requests", "2.31.0", "requirements.txt", [REQUESTS_ADVISORY_NO_CVE], ORIGIN)
    assert f.cve_id is None
    assert f.nvd_url is None
    assert f.key == "dep:requests:GHSA-9wx4-h78v-vm56"
    assert f.priority == "P3"


def test_one_finding_per_advisory():
    out = F.findings_from_advisories("x", "1", "requirements.txt", [PYYAML_ADVISORY, REQUESTS_ADVISORY_NO_CVE], ORIGIN)
    assert len(out) == 2


def test_sarif_finding_is_scored_from_the_cwe_table(tmp_path):
    table = load_table()
    known, unknown = F.findings_from_sarif(SARIF_CERT_VALIDATION, table, ORIGIN)
    assert known.kind == "code"
    assert known.key == "code:python.requests.security.disabled-cert-validation.disabled-cert-validation:app/upstream.py"
    assert known.cwes == ["CWE-295"]
    assert known.cvss31_score == 7.4
    assert known.score_source == "cwe-table"
    assert known.priority == "P2"
    assert known.location == ("app/upstream.py", 17)
    assert known.rule_url.startswith("https://semgrep.dev/r/")
    assert known.nvd_url is None and known.cve_id is None


def test_sarif_finding_with_unmapped_cwe_needs_scoring():
    table = load_table()
    _, unknown = F.findings_from_sarif(SARIF_CERT_VALIDATION, table, ORIGIN)
    assert unknown.cvss31_score is None
    assert unknown.score_source is None
    assert unknown.priority == "needs-scoring"


def test_dependabot_alert_becomes_the_same_key_as_the_pr_finding():
    f = F.finding_from_dependabot_alert(DEPENDABOT_ALERT_OPEN)
    assert f.key == "dep:pyyaml:GHSA-8q59-q68h-6hv4"
    assert f.cvss31_score == 9.8 and f.priority == "P1"
    assert f.fixed_in == "5.4"
    assert f.origin == {"kind": "dependabot", "number": 12, "url": "https://github.com/o/r/security/dependabot/12"}
    assert f.state == "open"


def test_dismissed_dependabot_alert_carries_reason_and_who():
    alert = dict(DEPENDABOT_ALERT_OPEN, state="dismissed", dismissed_reason="not_used", dismissed_by={"login": "alice"}, dismissed_comment="dev only")
    f = F.finding_from_dependabot_alert(alert)
    assert f.state == "dismissed"
    assert f.dismissed_reason == "not_used" and f.dismissed_by == "alice"


def test_code_scanning_alert_becomes_the_same_key_as_the_pr_finding():
    f = F.finding_from_code_scanning_alert(CODE_SCANNING_ALERT_OPEN, load_table())
    assert f.key == "code:python.requests.security.disabled-cert-validation.disabled-cert-validation:app/upstream.py"
    assert f.cvss31_score == 7.4 and f.priority == "P2"
    assert f.origin["kind"] == "code-scanning" and f.origin["number"] == 3


def test_cwe_ids_are_pulled_from_semgrep_tags():
    assert F.cwes_from_tags(["CWE-295: Improper Certificate Validation", "security", "CWE-20: x"]) == ["CWE-295", "CWE-20"]
