"""Entry points.

  python -m triage pr   --event $GITHUB_EVENT_PATH --sarif semgrep.sarif
  python -m triage main --repo-dir . [--default-assignee login]

Both need GITHUB_TOKEN and GITHUB_REPOSITORY in the environment.
"""

import argparse
import json
import os
import sys

from triage import assign as A
from triage import findings as F
from triage import render as R
from triage.cwe_vectors import load_table
from triage.github import GitHub, WriteForbidden
from triage.sync import sync_finding

MANIFEST = "requirements.txt"


def _log(msg):
    print(msg, flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(msg + "\n\n")


def _client():
    return GitHub(os.environ.get("GITHUB_TOKEN"), os.environ["GITHUB_REPOSITORY"])


def run_pr(args) -> int:
    gh = _client()
    table = load_table()
    event = json.load(open(args.event, encoding="utf-8"))
    pr = event["pull_request"]
    number, author = pr["number"], pr["user"]["login"]
    origin = {"kind": "pr", "number": number, "url": pr["html_url"], "sha": pr["head"]["sha"]}

    if not author.endswith("[bot]"):
        gh.assign_pr(number, author)

    findings = []
    head_text = open(MANIFEST, encoding="utf-8").read() if os.path.exists(MANIFEST) else ""
    base_text = gh.file_at(MANIFEST, pr["base"]["sha"])
    for name, version in F.added_pins(base_text, head_text):
        findings.extend(F.findings_from_advisories(name, version, MANIFEST, gh.advisories(name, version), origin))
    if args.sarif and os.path.exists(args.sarif):
        findings.extend(F.findings_from_sarif(json.load(open(args.sarif, encoding="utf-8")), table, origin))

    gh.ensure_labels()
    previous = set(R.keys_from_pr_comment(gh.existing_pr_comment(number)))
    urls = {}
    for f in findings:
        result = sync_finding(gh, f, assignee=None if author.endswith("[bot]") else author)
        if result.get("issue"):
            urls[f.key] = result["issue"]["html_url"]
        _log(f"{result['action']}: {f.key} -> {urls.get(f.key, '')}")
    for key in previous - {f.key for f in findings}:
        issue = gh.find_issue(key)
        if issue and issue["state"] == "open":
            gh.close_issue(issue["number"], f"<!-- cra-triage: action=close -->\nClosed automatically: no longer present at head `{origin['sha'][:7]}` of pull request #{number}.")
            _log(f"closed: {key} (gone from PR head)")
    gh.upsert_pr_comment(number, R.pr_comment(findings, urls))
    _log(f"{len(findings)} finding(s) on PR #{number}")
    return 0


def _assignee_for(gh, repo_dir, path, line, default):
    login = None
    if line:
        sha = A.blame_sha(repo_dir, path, line)
        if sha:
            login = gh.commit_author_login(sha)
    if login and login.endswith("[bot]"):
        login = None
    codeowners = ""
    for candidate in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
        try:
            with open(os.path.join(repo_dir, candidate), encoding="utf-8") as fh:
                codeowners = fh.read()
                break
        except OSError:
            continue
    return A.choose([login, A.codeowner_for(path, codeowners), default])


def run_main(args) -> int:
    gh = _client()
    table = load_table()
    gh.ensure_labels()
    findings = [F.finding_from_dependabot_alert(a) for a in gh.dependabot_alerts()]
    findings += [F.finding_from_code_scanning_alert(a, table) for a in gh.code_scanning_alerts()]
    counts = {}
    for f in findings:
        if f.kind == "dependency":
            path, line = f.manifest or MANIFEST, A.line_of(args.repo_dir, f.manifest or MANIFEST, f.package or "")
        else:
            path, line = f.location
        assignee = _assignee_for(gh, args.repo_dir, path, line, args.default_assignee)
        result = sync_finding(gh, f, assignee)
        counts[result["action"]] = counts.get(result["action"], 0) + 1
        _log(f"{result['action']}: {f.key} [{f.state}] -> {result.get('issue', {}).get('html_url', '')}")
    _log(f"{len(findings)} alert(s) reconciled: {counts}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="triage")
    sub = p.add_subparsers(dest="mode", required=True)
    pr = sub.add_parser("pr")
    pr.add_argument("--event", default=os.environ.get("GITHUB_EVENT_PATH"))
    pr.add_argument("--sarif", default="semgrep.sarif")
    mn = sub.add_parser("main")
    mn.add_argument("--repo-dir", default=".")
    mn.add_argument("--default-assignee", default=os.environ.get("TRIAGE_DEFAULT_ASSIGNEE") or None)
    args = p.parse_args(argv)
    try:
        return run_pr(args) if args.mode == "pr" else run_main(args)
    except WriteForbidden as exc:
        _log(f"::warning::triage could not write: {exc}. This happens on fork and Dependabot pull requests; the scheduled run on main will pick the findings up.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
