"""Mirror a Finding into exactly one issue, and keep the issue's state honest."""

from triage import render as R
from triage.findings import Finding


def _last_action(comments: list) -> str | None:
    last = None
    for c in comments:
        action = R.action_from_comment(c.get("body"))
        if action:
            last = action
        elif last is not None:
            # a human wrote after the script's last action; that comment wins
            last = "human"
    return last


def sync_finding(gh, f: Finding, assignee: str | None) -> dict:
    issue = gh.find_issue(f.key)
    if issue is None:
        if f.state != "open":
            return {"action": "skipped", "key": f.key}
        labels = ["cra-triage", f.priority]
        issue = gh.create_issue(R.issue_title(f), R.issue_body(f), labels, [assignee] if assignee else [])
        return {"action": "created", "key": f.key, "issue": issue}

    if f.state == "open":
        if issue["state"] == "open":
            return {"action": "unchanged", "key": f.key, "issue": issue}
        if _last_action(gh.issue_comments(issue["number"])) == "close":
            gh.reopen_issue(issue["number"], R.reopen_comment(f))
            return {"action": "reopened", "key": f.key, "issue": issue}
        return {"action": "left-closed", "key": f.key, "issue": issue}

    if issue["state"] == "open":
        gh.close_issue(issue["number"], R.close_comment(f))
        return {"action": "closed", "key": f.key, "issue": issue}
    return {"action": "unchanged", "key": f.key, "issue": issue}
