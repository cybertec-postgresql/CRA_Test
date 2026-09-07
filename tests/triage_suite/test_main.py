"""Command line shape. The pull request step feeds more than one SARIF file."""

from triage.__main__ import parse_args


def test_pr_accepts_several_sarif_files_in_order():
    args = parse_args(["pr", "--event", "e.json", "--sarif", "semgrep.sarif", "--sarif", "gitleaks.sarif"])
    assert args.sarif == ["semgrep.sarif", "gitleaks.sarif"]


def test_pr_defaults_to_the_semgrep_sarif():
    assert parse_args(["pr", "--event", "e.json"]).sarif == ["semgrep.sarif"]
