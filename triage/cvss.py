"""CVSS 3.1 base score, computed from a vector string.

Formula and constants are from the CVSS v3.1 specification, section 7.
"""

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    """Round up to one decimal, using the integer method the spec mandates."""
    whole = round(value * 100000)
    if whole % 10000 == 0:
        return whole / 100000.0
    return (math.floor(whole / 10000) + 1) / 10.0


def parse(vector: str) -> dict:
    if not vector.startswith("CVSS:3.0/") and not vector.startswith("CVSS:3.1/"):
        raise ValueError(f"not a CVSS 3.x vector: {vector!r}")
    metrics = {}
    for part in vector.split("/")[1:]:
        if ":" not in part:
            raise ValueError(f"malformed metric {part!r} in {vector!r}")
        name, value = part.split(":", 1)
        metrics[name] = value
    for name in _REQUIRED:
        if name not in metrics:
            raise ValueError(f"missing metric {name} in {vector!r}")
    return metrics


def base_score(vector: str) -> float:
    m = parse(vector)
    scope = m["S"]
    try:
        av, ac, pr, ui = _AV[m["AV"]], _AC[m["AC"]], _PR[scope][m["PR"]], _UI[m["UI"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError as exc:
        raise ValueError(f"unknown metric value {exc} in {vector!r}") from exc

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def qualitative(score: float) -> str:
    """The CVSS qualitative severity rating scale."""
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"
