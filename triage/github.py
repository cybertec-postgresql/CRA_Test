"""A thin GitHub REST client. Standard library only, transport injectable for tests."""

import base64
import json
import urllib.error
import urllib.parse
import urllib.request

from triage.priority import LABELS
from triage.render import PR_COMMENT_MARKER, key_from_body

API = "https://api.github.com"


class ApiError(RuntimeError):
    pass


class WriteForbidden(ApiError):
    """The token cannot write. Typical on pull requests from forks or Dependabot."""


def _urllib_transport(token: str | None):
    def call(method, url, body):
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "cra-triage"}
        if token and url.startswith(API):
            headers["Authorization"] = f"Bearer {token}"
        data = body.encode() if body is not None else None
        if data is not None:
            headers["Content-Type"] = "application/json"
        if not url.startswith("https://"):
            raise ApiError(f"refusing non-https URL {url!r}")
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            # 2026-09-04: URLs are built from API constants and repository paths, never from
            # caller input, and the https guard above rejects file:// and friends. See SUPPRESSIONS.md.
            with urllib.request.urlopen(req, timeout=30) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw) if raw else {}
            except ValueError:
                payload = {"message": raw.decode(errors="replace")}
            return exc.code, payload
    return call


class GitHub:
    def __init__(self, token: str | None, repo: str, transport=None, api: str = API):
        self.token, self.repo, self.api = token, repo, api
        self.transport = transport or _urllib_transport(token)
        self._triage_issues = None

    # transport helpers

    def _call(self, method, url, body=None):
        status, data = self.transport(method, url, json.dumps(body) if body is not None else None)
        if status == 403 and method in ("POST", "PATCH", "PUT", "DELETE"):
            raise WriteForbidden(f"{method} {url}: {data.get('message') if isinstance(data, dict) else data}")
        if status >= 400:
            raise ApiError(f"{method} {url} -> {status}: {data.get('message') if isinstance(data, dict) else data}")
        return data

    def _url(self, path, params=None):
        url = path if path.startswith("http") else self.api + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        return url

    def get(self, path, params=None):
        return self._call("GET", self._url(path, params))

    def post(self, path, body):
        return self._call("POST", self._url(path), body)

    def patch(self, path, body):
        return self._call("PATCH", self._url(path), body)

    def paginate(self, path, params=None):
        params = dict(params or {}, per_page=100)
        out, page = [], 1
        while True:
            chunk = self.get(path, dict(params, page=page))
            if not isinstance(chunk, list):
                return chunk
            out.extend(chunk)
            if len(chunk) < 100:
                return out
            page += 1

    # advisories

    def pypi_name(self, name: str) -> str:
        status, data = self.transport("GET", f"https://pypi.org/pypi/{name}/json", None)
        if status == 200 and isinstance(data, dict):
            return data.get("info", {}).get("name") or name
        return name

    def advisories(self, name: str, version: str, ecosystem: str = "pip") -> list:
        canonical = self.pypi_name(name) if ecosystem == "pip" else name
        affects = urllib.parse.quote(f"{canonical}@{version}", safe="")
        return self.paginate(f"/advisories?ecosystem={ecosystem}&affects={affects}")

    # labels and issues

    def ensure_labels(self) -> list:
        existing = {l["name"] for l in self.paginate(f"/repos/{self.repo}/labels")}
        created = []
        for name, spec in LABELS.items():
            if name not in existing:
                self.post(f"/repos/{self.repo}/labels", {"name": name, "color": spec["color"], "description": spec["description"]})
                created.append(name)
        return created

    def list_triage_issues(self) -> list:
        if self._triage_issues is None:
            items = self.paginate(f"/repos/{self.repo}/issues", {"labels": "cra-triage", "state": "all"})
            self._triage_issues = [i for i in items if "pull_request" not in i]
        return self._triage_issues

    def find_issue(self, key: str):
        for issue in self.list_triage_issues():
            if key_from_body(issue.get("body")) == key:
                return issue
        return None

    def create_issue(self, title, body, labels, assignees):
        issue = self.post(f"/repos/{self.repo}/issues", {"title": title, "body": body, "labels": labels, "assignees": assignees})
        if self._triage_issues is not None:
            self._triage_issues.append(issue)
        return issue

    def issue_comments(self, number: int) -> list:
        return self.paginate(f"/repos/{self.repo}/issues/{number}/comments")

    def comment(self, number: int, body: str):
        return self.post(f"/repos/{self.repo}/issues/{number}/comments", {"body": body})

    def close_issue(self, number: int, comment: str):
        self.comment(number, comment)
        return self.patch(f"/repos/{self.repo}/issues/{number}", {"state": "closed", "state_reason": "completed"})

    def reopen_issue(self, number: int, comment: str):
        out = self.patch(f"/repos/{self.repo}/issues/{number}", {"state": "open"})
        self.comment(number, comment)
        return out

    def set_labels(self, number: int, labels: list):
        return self.patch(f"/repos/{self.repo}/issues/{number}", {"labels": labels})

    def upsert_pr_comment(self, pr: int, body: str):
        for c in self.issue_comments(pr):
            if PR_COMMENT_MARKER in (c.get("body") or ""):
                return self.patch(f"/repos/{self.repo}/issues/comments/{c['id']}", {"body": body})
        return self.comment(pr, body)

    def existing_pr_comment(self, pr: int) -> str | None:
        for c in self.issue_comments(pr):
            if PR_COMMENT_MARKER in (c.get("body") or ""):
                return c.get("body")
        return None

    def assign_pr(self, pr: int, login: str):
        return self.post(f"/repos/{self.repo}/issues/{pr}/assignees", {"assignees": [login]})

    # repository content and alerts

    def file_at(self, path: str, ref: str) -> str:
        try:
            data = self.get(f"/repos/{self.repo}/contents/{path}", {"ref": ref})
        except ApiError:
            return ""
        if isinstance(data, dict) and data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return ""

    def dependabot_alerts(self) -> list:
        return self.paginate(f"/repos/{self.repo}/dependabot/alerts", {"state": "open,fixed,dismissed,auto_dismissed"})

    def code_scanning_alerts(self) -> list:
        out = []
        for state in ("open", "dismissed", "fixed"):
            try:
                out.extend(self.paginate(f"/repos/{self.repo}/code-scanning/alerts", {"state": state}))
            except ApiError as exc:
                if "no analysis found" in str(exc).lower() or "-> 404" in str(exc):
                    continue
                raise
        return out

    def commit_author_login(self, sha: str) -> str | None:
        try:
            data = self.get(f"/repos/{self.repo}/commits/{sha}")
        except ApiError:
            return None
        return (data.get("author") or {}).get("login")
