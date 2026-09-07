"""Who gets the issue when there is no PR author."""

from triage import assign as A

CODEOWNERS = """
# comment
*                 @default-owner
requirements.txt  @dep-owner @security-team
/app/             @app-owner
docs/             @org/docs-team
"""


def test_codeowners_last_match_wins_and_teams_are_skipped():
    assert A.codeowner_for("requirements.txt", CODEOWNERS) == "dep-owner"
    assert A.codeowner_for("app/api.py", CODEOWNERS) == "app-owner"
    assert A.codeowner_for("README.md", CODEOWNERS) == "default-owner"
    assert A.codeowner_for("docs/x.md", CODEOWNERS) == "default-owner"


def test_codeowners_missing_means_none():
    assert A.codeowner_for("x", "") is None


def test_sha_from_blame_porcelain():
    out = "3784280abcdef0123456789abcdef0123456789a 5 5 1\nauthor X\nfilename requirements.txt\n\tPyYAML==5.3.1\n"
    assert A.sha_from_blame(out) == "3784280abcdef0123456789abcdef0123456789a"
    assert A.sha_from_blame("") is None


def test_choose_first_present():
    assert A.choose([None, "", "bob", "alice"]) == "bob"
    assert A.choose([None]) is None
