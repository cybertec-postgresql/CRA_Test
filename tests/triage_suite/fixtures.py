"""Shapes copied from real API responses, trimmed to the fields the code reads."""

PYYAML_ADVISORY = {
    "ghsa_id": "GHSA-8q59-q68h-6hv4",
    "cve_id": "CVE-2020-14343",
    "summary": "Improper Input Validation in PyYAML",
    "severity": "critical",
    "html_url": "https://github.com/advisories/GHSA-8q59-q68h-6hv4",
    "cvss": {"score": 9.8, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "cvss_severities": {
        "cvss_v3": {"score": 9.8, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "cvss_v4": {"score": 9.3, "vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
    },
    "cwes": [{"cwe_id": "CWE-20", "name": "Improper Input Validation"}],
    "vulnerabilities": [
        {"package": {"ecosystem": "pip", "name": "PyYAML"}, "vulnerable_version_range": "< 5.4", "first_patched_version": "5.4"}
    ],
}

REQUESTS_ADVISORY_NO_CVE = {
    "ghsa_id": "GHSA-9wx4-h78v-vm56",
    "cve_id": None,
    "summary": "Requests Session does not verify requests after making first request with verify=False",
    "severity": "medium",
    "html_url": "https://github.com/advisories/GHSA-9wx4-h78v-vm56",
    "cvss": {"score": 5.6, "vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"},
    "cvss_severities": {"cvss_v3": {"score": 5.6, "vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"}, "cvss_v4": {"score": None, "vector_string": None}},
    "cwes": [{"cwe_id": "CWE-670", "name": "Always-Incorrect Control Flow Implementation"}],
    "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "requests"}, "vulnerable_version_range": ">= 2.3.0, < 2.32.0", "first_patched_version": "2.32.0"}],
}

SARIF_CERT_VALIDATION = {
    "runs": [
        {
            "tool": {"driver": {"rules": [
                {
                    "id": "python.requests.security.disabled-cert-validation.disabled-cert-validation",
                    "helpUri": "https://semgrep.dev/r/python.requests.security.disabled-cert-validation.disabled-cert-validation",
                    "defaultConfiguration": {"level": "error"},
                    "properties": {"tags": ["CWE-295: Improper Certificate Validation", "LOW CONFIDENCE", "security"]},
                },
                {
                    "id": "python.lang.best-practice.unknown-thing",
                    "helpUri": "https://semgrep.dev/r/x",
                    "defaultConfiguration": {"level": "warning"},
                    "properties": {"tags": ["CWE-999: Made Up", "security"]},
                },
            ]}},
            "results": [
                {
                    "ruleId": "python.requests.security.disabled-cert-validation.disabled-cert-validation",
                    "level": "error",
                    "message": {"text": "Certificate verification has been explicitly disabled."},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/upstream.py"}, "region": {"startLine": 17, "snippet": {"text": "requests.get(url, verify=False)"}}}}],
                },
                {
                    "ruleId": "python.lang.best-practice.unknown-thing",
                    "level": "warning",
                    "message": {"text": "Something"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/x.py"}, "region": {"startLine": 3}}}],
                },
            ],
        }
    ]
}

DEPENDABOT_ALERT_OPEN = {
    "number": 12,
    "state": "open",
    "html_url": "https://github.com/o/r/security/dependabot/12",
    "dependency": {"package": {"ecosystem": "pip", "name": "pyyaml"}, "manifest_path": "requirements.txt", "scope": "runtime"},
    "security_advisory": {
        "ghsa_id": "GHSA-8q59-q68h-6hv4", "cve_id": "CVE-2020-14343", "summary": "Improper Input Validation in PyYAML", "severity": "critical",
        "cvss": {"score": 9.8, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "cvss_severities": {"cvss_v3": {"score": 9.8, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, "cvss_v4": {"score": 9.3, "vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}},
        "cwes": [{"cwe_id": "CWE-20", "name": "Improper Input Validation"}],
    },
    "security_vulnerability": {"vulnerable_version_range": "< 5.4", "first_patched_version": {"identifier": "5.4"}},
    "dismissed_reason": None, "dismissed_by": None, "dismissed_comment": None, "fixed_at": None,
}

CODE_SCANNING_ALERT_OPEN = {
    "number": 3,
    "state": "open",
    "html_url": "https://github.com/o/r/security/code-scanning/3",
    "rule": {"id": "python.requests.security.disabled-cert-validation.disabled-cert-validation", "severity": "error", "tags": ["CWE-295: Improper Certificate Validation", "security"], "description": "Certificate verification disabled"},
    "tool": {"name": "Semgrep OSS"},
    "most_recent_instance": {"location": {"path": "app/upstream.py", "start_line": 17}, "message": {"text": "Certificate verification has been explicitly disabled."}},
    "dismissed_reason": None, "dismissed_by": None,
}
