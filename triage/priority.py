"""The P1 to P4 chart, and the labels that carry it."""

LABELS = {
    "P1": {"color": "b60205", "description": "Critical, CVSS 9.0 to 10.0. Full compromise of confidentiality, integrity or availability."},
    "P2": {"color": "d93f0b", "description": "High, CVSS 7.0 to 8.9. Compromise possible but needs interaction or privileged access."},
    "P3": {"color": "fbca04", "description": "Medium, CVSS 4.0 to 6.9. Limited access or partial degradation of service."},
    "P4": {"color": "0e8a16", "description": "Low, CVSS 0.1 to 3.9. Little immediate risk, still to be patched."},
    "needs-scoring": {"color": "5319e7", "description": "No CVSS vector on file for this weakness class. Security must add one to .cra/cwe-vectors.json."},
    "cra-triage": {"color": "0052cc", "description": "Opened automatically from a scanner finding. Keep the label: the triage script tracks issues by it."},
}


def priority(score: float | None) -> str:
    if score is None:
        return "needs-scoring"
    if score >= 9.0:
        return "P1"
    if score >= 7.0:
        return "P2"
    if score >= 4.0:
        return "P3"
    return "P4"


def band(name: str) -> str:
    return {"P1": "CVSS 9.0 to 10.0", "P2": "CVSS 7.0 to 8.9", "P3": "CVSS 4.0 to 6.9", "P4": "CVSS 0.1 to 3.9"}.get(name, "no score")
