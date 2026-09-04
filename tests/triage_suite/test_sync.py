"""Mirroring findings into issues: create once, close when fixed, reopen when the alert flips."""

import pytest

from triage import findings as F
from triage import render as R
from triage.sync import sync_finding

from .fixtures import DEPENDABOT_ALERT_OPEN


class FakeGitHub:
    def __init__(self, issues=None, comments=None):
        self.issues = issues or []
        self.comments = comments or {}
        self.calls = []

    def find_issue(self, key):
        for i in self.issues:
            if R.key_from_body(i["body"]) == key:
                return i
        return None

    def create_issue(self, title, body, labels, assignees):
        self.calls.append(("create", title, labels, assignees))
        issue = {"number": 100, "state": "open", "title": title, "body": body, "html_url": "https://github.com/o/r/issues/100", "labels": [{"name": l} for l in labels]}
        self.issues.append(issue)
        return issue

    def close_issue(self, number, comment):
        self.calls.append(("close", number, comment))

    def reopen_issue(self, number, comment):
        self.calls.append(("reopen", number, comment))

    def issue_comments(self, number):
        return self.comments.get(number, [])


def finding(state="open"):
    f = F.finding_from_dependabot_alert(dict(DEPENDABOT_ALERT_OPEN, state=state))
    return f


def existing(state, body_key="dep:pyyaml:GHSA-8q59-q68h-6hv4"):
    return {"number": 7, "state": state, "body": R.marker(body_key) + "\nold", "html_url": "https://github.com/o/r/issues/7", "labels": [{"name": "P1"}]}


def test_new_open_finding_creates_labelled_assigned_issue():
    gh = FakeGitHub()
    result = sync_finding(gh, finding(), assignee="dev")
    assert result["action"] == "created"
    (call,) = gh.calls
    assert call[0] == "create"
    assert call[1].startswith("[P1] CVE-2020-14343")
    assert set(call[2]) == {"cra-triage", "P1"}
    assert call[3] == ["dev"]


def test_unassignable_finding_is_still_created():
    gh = FakeGitHub()
    sync_finding(gh, finding(), assignee=None)
    assert gh.calls[0][3] == []


def test_open_finding_with_open_issue_is_a_no_op():
    gh = FakeGitHub(issues=[existing("open")])
    assert sync_finding(gh, finding(), assignee="dev")["action"] == "unchanged"
    assert gh.calls == []


def test_fixed_finding_closes_open_issue_with_reason():
    gh = FakeGitHub(issues=[existing("open")])
    assert sync_finding(gh, finding("fixed"), assignee="dev")["action"] == "closed"
    action, number, comment = gh.calls[0]
    assert (action, number) == ("close", 7)
    assert R.action_from_comment(comment) == "close"


def test_fixed_finding_with_no_issue_creates_nothing():
    gh = FakeGitHub()
    assert sync_finding(gh, finding("fixed"), assignee="dev")["action"] == "skipped"
    assert gh.calls == []


def test_open_finding_reopens_issue_the_script_closed():
    gh = FakeGitHub(issues=[existing("closed")], comments={7: [{"body": "human chatter"}, {"body": R.close_comment(finding("fixed"))}]})
    assert sync_finding(gh, finding(), assignee="dev")["action"] == "reopened"
    assert gh.calls[0][:2] == ("reopen", 7)


def test_open_finding_leaves_alone_an_issue_a_human_closed():
    gh = FakeGitHub(issues=[existing("closed")], comments={7: [{"body": "closing, accepted risk"}]})
    assert sync_finding(gh, finding(), assignee="dev")["action"] == "left-closed"
    assert gh.calls == []


def test_open_finding_leaves_alone_when_script_reopened_and_human_closed_again():
    gh = FakeGitHub(issues=[existing("closed")], comments={7: [{"body": R.close_comment(finding("fixed"))}, {"body": R.reopen_comment(finding())}, {"body": "no, closing"}]})
    assert sync_finding(gh, finding(), assignee="dev")["action"] == "left-closed"
