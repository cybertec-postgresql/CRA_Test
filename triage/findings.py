"""Scanner output, normalised into Findings that carry a score and a stable key.

Keys are identity, not origin. The same CVE on the same package has one key
whether it surfaced on a pull request or as a Dependabot alert on main, so it
gets one issue.
"""

import re
from dataclasses import dataclass, field

from triage.priority import priority as _priority

_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)")
_CWE = re.compile(r"^(CWE-\d+)(?::\s*(.*))?$")


@dataclass
class Finding:
    key: str
    kind: str  # "dependency" or "code"
    summary: str
    origin: dict
    state: str = "open"  # open, fixed, dismissed
    package: str | None = None
    version: str | None = None
    manifest: str | None = None
    cve_id: str | None = None
    ghsa_id: str | None = None
    advisory_url: str | None = None
    nvd_url: str | None = None
    cvss31_score: float | None = None
    cvss31_vector: str | None = None
    cvss4_score: float | None = None
    cvss4_vector: str | None = None
    score_source: str | None = None  # "advisory" or "cwe-table"
    cwes: list = field(default_factory=list)
    cwe_names: dict = field(default_factory=dict)
    vulnerable_range: str | None = None
    fixed_in: str | None = None
    location: tuple | None = None  # (path, line)
    rule_id: str | None = None
    rule_url: str | None = None
    rule_level: str | None = None
    message: str | None = None
    reported_severity: str | None = None
    dismissed_reason: str | None = None
    dismissed_by: str | None = None
    dismissed_comment: str | None = None

    @property
    def priority(self) -> str:
        return _priority(self.cvss31_score)

    @property
    def primary_cwe(self) -> str | None:
        return self.cwes[0] if self.cwes else None


def normalise(name: str) -> str:
    """PEP 503 name normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str) -> dict:
    pins = {}
    for line in text.splitlines():
        m = _PIN.match(line)
        if m:
            pins[normalise(m.group(1))] = m.group(2)
    return pins


def added_pins(base_text: str, head_text: str) -> list:
    base, head = parse_requirements(base_text), parse_requirements(head_text)
    return sorted((n, v) for n, v in head.items() if base.get(n) != v)


def cwes_from_tags(tags: list) -> list:
    out = []
    for tag in tags or []:
        m = _CWE.match(tag)
        if m:
            out.append(m.group(1))
    return out


def cwe_names_from_tags(tags: list) -> dict:
    out = {}
    for tag in tags or []:
        m = _CWE.match(tag)
        if m and m.group(2):
            out[m.group(1)] = m.group(2).strip()
    return out


def _scores(advisory: dict) -> tuple:
    sev = advisory.get("cvss_severities") or {}
    v3 = sev.get("cvss_v3") or advisory.get("cvss") or {}
    v4 = sev.get("cvss_v4") or {}
    return v3.get("score"), v3.get("vector_string"), v4.get("score"), v4.get("vector_string")


def _nvd(cve_id):
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None


def findings_from_advisories(name: str, version: str, manifest: str, advisories: list, origin: dict) -> list:
    out = []
    for adv in advisories:
        vulns = adv.get("vulnerabilities") or []
        match = next((v for v in vulns if normalise((v.get("package") or {}).get("name", "")) == normalise(name)), vulns[0] if vulns else {})
        s31, v31, s4, v4 = _scores(adv)
        out.append(Finding(
            key=f"dep:{normalise(name)}:{adv['ghsa_id']}",
            kind="dependency",
            summary=adv.get("summary") or adv["ghsa_id"],
            origin=origin,
            package=name,
            version=version,
            manifest=manifest,
            cve_id=adv.get("cve_id"),
            ghsa_id=adv["ghsa_id"],
            advisory_url=adv.get("html_url") or f"https://github.com/advisories/{adv['ghsa_id']}",
            nvd_url=_nvd(adv.get("cve_id")),
            cvss31_score=s31, cvss31_vector=v31, cvss4_score=s4, cvss4_vector=v4,
            score_source="advisory" if s31 is not None else None,
            cwes=[c["cwe_id"] for c in adv.get("cwes") or []],
            cwe_names={c["cwe_id"]: c.get("name", "") for c in adv.get("cwes") or []},
            vulnerable_range=match.get("vulnerable_version_range"),
            fixed_in=match.get("first_patched_version"),
            reported_severity=adv.get("severity"),
        ))
    return out


def _code_finding(rule_id, rule_url, level, tags, path, line, message, table, origin, state="open") -> Finding:
    from triage.cwe_vectors import score_for_cwe

    cwes = cwes_from_tags(tags)
    names = cwe_names_from_tags(tags)
    score = vector = None
    scored_cwe = None
    for cwe in cwes:
        hit = score_for_cwe(table, cwe)
        if hit:
            score, vector = hit
            scored_cwe = cwe
            break
    if scored_cwe:
        cwes = [scored_cwe] + [c for c in cwes if c != scored_cwe]
    return Finding(
        key=f"code:{rule_id}:{path}",
        kind="code",
        summary=names.get(cwes[0], "") if cwes else "",
        origin=origin,
        state=state,
        cwes=cwes,
        cwe_names=names,
        cvss31_score=score, cvss31_vector=vector,
        score_source="cwe-table" if score is not None else None,
        location=(path, line),
        rule_id=rule_id, rule_url=rule_url, rule_level=level,
        message=message,
        reported_severity=level,
    )


def findings_from_sarif(sarif: dict, table: dict, origin: dict) -> list:
    out = []
    for run in sarif.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            if res.get("suppressions"):
                # nosemgrep with a documented reason: an accepted decision, not a finding
                continue
            rule = rules.get(res.get("ruleId"), {})
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            path = loc.get("artifactLocation", {}).get("uri", "?")
            line = loc.get("region", {}).get("startLine")
            out.append(_code_finding(
                rule_id=res.get("ruleId"),
                rule_url=rule.get("helpUri"),
                level=res.get("level") or rule.get("defaultConfiguration", {}).get("level"),
                tags=rule.get("properties", {}).get("tags", []),
                path=path, line=line,
                message=res.get("message", {}).get("text"),
                table=table, origin=origin,
            ))
    return out


def _alert_state(state: str) -> str:
    return {"open": "open", "fixed": "fixed", "dismissed": "dismissed", "auto_dismissed": "dismissed", "closed": "fixed"}.get(state, state)


def finding_from_dependabot_alert(alert: dict) -> Finding:
    adv = alert["security_advisory"]
    vuln = alert.get("security_vulnerability") or {}
    dep = alert.get("dependency") or {}
    name = (dep.get("package") or {}).get("name", "?")
    origin = {"kind": "dependabot", "number": alert["number"], "url": alert.get("html_url")}
    (f,) = findings_from_advisories(name, None, dep.get("manifest_path"), [dict(adv, vulnerabilities=[])], origin)
    f.state = _alert_state(alert.get("state", "open"))
    f.vulnerable_range = vuln.get("vulnerable_version_range")
    f.fixed_in = (vuln.get("first_patched_version") or {}).get("identifier")
    f.dismissed_reason = alert.get("dismissed_reason")
    f.dismissed_by = (alert.get("dismissed_by") or {}).get("login")
    f.dismissed_comment = alert.get("dismissed_comment")
    return f


def finding_from_code_scanning_alert(alert: dict, table: dict) -> Finding:
    rule = alert.get("rule") or {}
    inst = alert.get("most_recent_instance") or {}
    loc = inst.get("location") or {}
    origin = {"kind": "code-scanning", "number": alert["number"], "url": alert.get("html_url")}
    rule_id = rule.get("id")
    f = _code_finding(
        rule_id=rule_id,
        rule_url=f"https://semgrep.dev/r/{rule_id}" if rule_id else None,
        level=rule.get("severity"),
        tags=rule.get("tags", []),
        path=loc.get("path", "?"), line=loc.get("start_line"),
        message=(inst.get("message") or {}).get("text") or rule.get("description"),
        table=table, origin=origin,
        state=_alert_state(alert.get("state", "open")),
    )
    f.dismissed_reason = alert.get("dismissed_reason")
    f.dismissed_by = (alert.get("dismissed_by") or {}).get("login")
    f.dismissed_comment = alert.get("dismissed_comment")
    return f
