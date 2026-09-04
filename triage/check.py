"""Configuration rules the workflows verify before running triage.

GitHub rejects a label whose description is over 100 characters or whose
name is over 50 with a 422, and the first pull request run died exactly
that way. The vector table must state the score its vector computes to.
Both are checked here, and in the unit tests, so a bad edit fails the
workflow at the check step with a clear message instead of mid-triage.
"""

import re
from pathlib import Path

from triage.cwe_vectors import TABLE_PATH, load_table
from triage.priority import LABELS

LABEL_DESCRIPTION_LIMIT = 100
LABEL_NAME_LIMIT = 50
_COLOUR = re.compile(r"^[0-9a-fA-F]{6}$")


def problems(labels: dict | None = None, table_path: Path = TABLE_PATH) -> list:
    labels = LABELS if labels is None else labels
    out = []
    for name, spec in labels.items():
        if len(name) > LABEL_NAME_LIMIT:
            out.append(f"label name {name!r} is {len(name)} characters, GitHub allows {LABEL_NAME_LIMIT}")
        desc = spec.get("description", "")
        if len(desc) > LABEL_DESCRIPTION_LIMIT:
            out.append(f"label {name}: description is {len(desc)} characters, GitHub allows {LABEL_DESCRIPTION_LIMIT}")
        if not _COLOUR.match(spec.get("color", "")):
            out.append(f"label {name}: colour {spec.get('color')!r} is not six hex digits")
    try:
        load_table(table_path)
    except (ValueError, OSError, KeyError) as exc:
        out.append(f"vector table {table_path}: {exc}")
    return out
