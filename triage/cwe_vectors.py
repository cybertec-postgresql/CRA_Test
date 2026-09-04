"""The reviewed CWE to CVSS vector table that scores code findings."""

import json
from pathlib import Path

from triage.cvss import base_score

TABLE_PATH = Path(__file__).resolve().parents[1] / ".cra" / "cwe-vectors.json"


def load_table(path: Path = TABLE_PATH) -> dict:
    rows = json.loads(Path(path).read_text())
    for cwe, row in rows.items():
        computed = base_score(row["vector"])
        if computed != row["score"]:
            raise ValueError(f"{cwe}: table says {row['score']} but vector computes to {computed}")
    return rows


def score_for_cwe(table: dict, cwe_id: str) -> tuple[float, str] | None:
    row = table.get(cwe_id)
    if row is None:
        return None
    return row["score"], row["vector"]
