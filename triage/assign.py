"""Who gets the issue when there is no pull request author."""

import fnmatch
import re
import subprocess

_SHA = re.compile(r"^([0-9a-f]{40}) ")


def _matches(pattern: str, path: str) -> bool:
    if pattern == "*":
        return True
    anchored = pattern.startswith("/")
    pat = pattern.lstrip("/")
    if pat.endswith("/"):
        pat = pat.rstrip("/")
        return path == pat or path.startswith(pat + "/") if anchored else (path.startswith(pat + "/") or f"/{pat}/" in f"/{path}")
    if anchored or "/" in pat:
        return fnmatch.fnmatch(path, pat) or path.startswith(pat + "/")
    return fnmatch.fnmatch(path.rsplit("/", 1)[-1], pat)


def codeowner_for(path: str, codeowners: str) -> str | None:
    """Last matching CODEOWNERS line that names an individual wins. Teams are skipped."""
    winner = None
    for line in codeowners.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        pattern, *owners = line.split()
        if not _matches(pattern, path):
            continue
        people = [o[1:] for o in owners if o.startswith("@") and "/" not in o]
        if people:
            winner = people[0]
    return winner


def sha_from_blame(porcelain: str) -> str | None:
    m = _SHA.match(porcelain or "")
    return m.group(1) if m else None


def choose(candidates: list) -> str | None:
    return next((c for c in candidates if c), None)


def blame_sha(repo_dir: str, path: str, line: int) -> str | None:
    try:
        out = subprocess.run(
            ["git", "blame", "--porcelain", "-L", f"{line},{line}", "--", path],
            cwd=repo_dir, capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return sha_from_blame(out)


def line_of(repo_dir: str, path: str, needle: str) -> int | None:
    try:
        with open(f"{repo_dir}/{path}", encoding="utf-8") as fh:
            for n, text in enumerate(fh, 1):
                if needle.lower() in text.lower():
                    return n
    except OSError:
        return None
    return None
