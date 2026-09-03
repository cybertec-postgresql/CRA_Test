# Incident record

## 2026-09-03: SQL injection reached the default branch

**Severity:** high. **Status:** closed by revert. **Exposure:** test repository
only, never deployed.

### What happened

Pull request #3 (`feat/asset-search`) added a search endpoint that built its
query by interpolating caller supplied values into the SQL text:

```python
query = (
    "SELECT id, name, criticality, updated_at FROM assets "
    f"WHERE name ILIKE '%{term}%' ORDER BY {sort}"
)
cur.execute(query)
```

`term` and `sort` came straight from the URL, so a visitor controlled the SQL
rather than only the values in it. CWE-89, OWASP A03:2021.

The Semgrep check **failed on the pull request as designed**. The pull request
was merged anyway, and `main` then failed its own scan.

### Why it was possible

No branch ruleset existed on the default branch. A failing required check only
blocks a merge when a ruleset makes it required. Without one the red check is
advisory and the merge button stays clickable.

The detection control worked. The **enforcement** control was absent.

### Timeline

| When | What |
|---|---|
| 2026-09-03 | PR #3 opened, Semgrep check fails, finding filed to code scanning |
| 2026-09-03 | PR #3 merged despite the failing check |
| 2026-09-03 | `main` scan fails, run 33749431344 |
| 2026-09-03 | Detected while writing the branch ruleset |
| 2026-09-03 | Reverted, `main` returns to 0 findings |

### Corrective actions

| Action | Status |
|---|---|
| Revert the merge, restoring `main` to a clean scan | done, this pull request |
| Add a branch ruleset requiring the `scan` check to pass | written, see [`MERGE_GATES.md`](MERGE_GATES.md), **not yet applied** |
| Require an approving review from another team member | in the same ruleset, not yet applied |
| Pin the required check to the GitHub Actions app id | in the same ruleset, not yet applied |
| Run the four bypass tests in `MERGE_GATES.md` | outstanding |

### What this cost, and what it bought

Nothing, because it is a test repository. That is the point of having one. The
same sequence in a production repository is a shipped vulnerability, and the
evidence that it can happen is now on the record rather than hypothetical.

### Note for whoever re-lands this feature

This reverts a **merge commit**. Git records that the branch has been merged, so
re-merging `feat/asset-search` will not restore the code. A corrected version
must come from a fresh branch, or by reverting this revert and fixing forward on
top. Either way the fix is bound parameters:

```python
cur.execute(
    "SELECT id, name FROM assets WHERE name ILIKE %s ORDER BY updated_at",
    (f"%{term}%",),
)
```

with the sort column resolved through the `SORTABLE` allow list, as `_page`
already does.
