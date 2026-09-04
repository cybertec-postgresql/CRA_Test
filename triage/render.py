"""Issue and comment text. This is the record the CRA file keeps, so it is explicit."""

import re

from triage.cvss import qualitative
from triage.findings import Finding
from triage.priority import band

PR_COMMENT_MARKER = "<!-- cra-triage: pr-summary -->"
_KEY = re.compile(r"<!-- cra-triage: key=([^\s>]+) -->")
_ACTION = re.compile(r"<!-- cra-triage: action=(close|reopen) -->")
_ROW_KEY = re.compile(r"<!-- row=([^\s>]+) -->")

CRA_NOTE = (
    "Priority is internal triage under the P1 to P4 chart. It is not the Cyber Resilience Act "
    "Article 14 reporting trigger, which starts on evidence that the vulnerability is being "
    "actively exploited, not on this score."
)


def marker(key: str) -> str:
    return f"<!-- cra-triage: key={key} -->"


def key_from_body(body: str | None) -> str | None:
    m = _KEY.search(body or "")
    return m.group(1) if m else None


def action_from_comment(body: str | None) -> str | None:
    m = _ACTION.search(body or "")
    return m.group(1) if m else None


def _loc(f: Finding) -> str:
    path, line = f.location or ("?", None)
    return f"{path}:{line}" if line else path


def _ident(f: Finding) -> str:
    if f.kind == "dependency":
        return f.cve_id or f.ghsa_id
    return f.primary_cwe or f.rule_id


def issue_title(f: Finding) -> str:
    if f.kind == "dependency":
        return f"[{f.priority}] {_ident(f)}: {f.package} {f.version or ''}".rstrip() + f", {f.summary}"
    what = f.summary or f.message or f.rule_id
    return f"[{f.priority}] {_ident(f)}: {_loc(f)}, {what}"


def _origin_line(o: dict) -> str:
    kind = o.get("kind")
    if kind == "pr":
        sha = o.get("sha")
        return f"pull request [#{o['number']}]({o['url']})" + (f", head `{sha[:7]}`" if sha else "")
    if kind == "dependabot":
        return f"Dependabot alert [#{o['number']}]({o['url']}) on the default branch"
    if kind == "code-scanning":
        return f"code scanning alert [#{o['number']}]({o['url']}) on the default branch"
    return str(o)


def _score_lines(f: Finding) -> list:
    lines = []
    if f.cvss31_score is not None:
        lines.append(f"**CVSS 3.1 base score:** {f.cvss31_score} ({qualitative(f.cvss31_score)}), vector `{f.cvss31_vector}`")
    if f.cvss4_score is not None:
        lines.append(f"**CVSS 4.0 base score:** {f.cvss4_score}, vector `{f.cvss4_vector}`")
    if f.score_source == "advisory":
        lines.append("**Score source:** GitHub Advisory Database, which mirrors the NVD record.")
    elif f.score_source == "cwe-table":
        lines.append(
            f"**Score source:** assessed from the {f.primary_cwe} vector in `.cra/cwe-vectors.json`, "
            "the way an NVD analyst scores a new CVE. This is not a published NVD score; the vector is "
            "the reviewed judgement for this weakness class and the score is computed from it."
        )
    else:
        cwe = f.primary_cwe or "this weakness"
        lines.append(
            f"**CVSS 3.1 base score:** none. There is no CVSS vector on file for {cwe}. "
            "Security must add one to `.cra/cwe-vectors.json`; the next run will rescore and relabel this issue."
        )
    lines.append(f"**Priority:** {f.priority} ({band(f.priority)})")
    return lines


def issue_body(f: Finding) -> str:
    lines = [marker(f.key), ""]
    if f.kind == "dependency":
        lines.append(f"**Package:** {f.package} {f.version or ''}".rstrip() + (f" in `{f.manifest}`" if f.manifest else ""))
        adv = f"[{f.ghsa_id}]({f.advisory_url})"
        if f.cve_id:
            adv += f", [{f.cve_id}]({f.nvd_url})"
        lines.append(f"**Advisory:** {adv}")
        lines.append(f"**Summary:** {f.summary}")
        lines.extend(_score_lines(f))
        if f.vulnerable_range:
            lines.append(f"**Vulnerable range:** {f.vulnerable_range}")
        lines.append(f"**Fixed in:** {f.fixed_in or 'no fixed version published'}")
    else:
        path, line = f.location or ("?", None)
        lines.append(f"**Location:** `{path}`" + (f", line {line}" if line else ""))
        rule = f"[{f.rule_id}]({f.rule_url})" if f.rule_url else f"`{f.rule_id}`"
        lines.append(f"**Rule:** {rule}, Semgrep level {f.rule_level or 'unknown'}")
        if f.message:
            lines.append(f"**Message:** {f.message}")
        lines.extend(_score_lines(f))
    if f.cwes:
        lines.append("**Weakness:** " + ", ".join(f"{c} {f.cwe_names.get(c, '')}".strip() for c in f.cwes))
    lines.append(f"**Found on:** {_origin_line(f.origin)}")
    lines.extend(["", CRA_NOTE])
    return "\n".join(lines)


def _issue_link(url: str | None) -> str:
    if not url:
        return "not created"
    return f"[#{url.rstrip('/').rsplit('/', 1)[-1]}]({url})"


def pr_comment(findings: list, issue_urls: dict) -> str:
    lines = [PR_COMMENT_MARKER, "## CRA triage", ""]
    if not findings:
        lines.append("No findings on this pull request head.")
        return "\n".join(lines)
    lines += ["| Finding | Where | CVSS 3.1 | Priority | Issue |", "|---|---|---|---|---|"]
    for f in findings:
        if f.kind == "dependency":
            where = f"{f.package} {f.version or ''}".strip()
        else:
            where = _loc(f)
        if f.cvss31_score is None:
            score = "no vector"
        elif f.score_source == "cwe-table":
            score = f"{f.cvss31_score} (assessed)"
        else:
            score = f"{f.cvss31_score}"
        lines.append(f"| {_ident(f)} | {where} | {score} | {f.priority} | {_issue_link(issue_urls.get(f.key))} | <!-- row={f.key} -->")
    lines += ["", "Each row has an issue carrying the CVE link, the CVSS vector and the fix version. " + CRA_NOTE]
    return "\n".join(lines)


def keys_from_pr_comment(body: str | None) -> list:
    return _ROW_KEY.findall(body or "")


def close_comment(f: Finding, reason: str | None = None) -> str:
    if reason:
        why = reason
    elif f.state == "dismissed":
        why = f"the alert was dismissed by {f.dismissed_by or 'unknown'} with reason `{f.dismissed_reason or 'none given'}`"
        if f.dismissed_comment:
            why += f': "{f.dismissed_comment}"'
    else:
        why = f"the alert is now `{f.state}` on GitHub"
    return f"<!-- cra-triage: action=close -->\nClosed automatically: {why}. Source: {_origin_line(f.origin)}."


def reopen_comment(f: Finding) -> str:
    return f"<!-- cra-triage: action=reopen -->\nReopened automatically: the finding is open again. Source: {_origin_line(f.origin)}."
