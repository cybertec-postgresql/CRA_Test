# Local rules

Rules that cover gaps in the public rulesets. Each one exists because a real
miss was demonstrated, not on suspicion.

## `formatted-sql-into-execute`

The public rule `python.lang.security.audit.formatted-sql-query` matches an
f-string that reaches `execute()` as a single literal. It does **not** match
SQL assembled from adjacent string literals across lines:

```python
query = (
    "SELECT id, name FROM assets "
    f"WHERE name ILIKE '%{term}%' ORDER BY name"   # missed by the public rule
)
cur.execute(query)
```

That is the normal way to write SQL longer than one line, so the gap matters
here. This rule uses taint mode instead of literal matching, so the formatting
is caught wherever it happens before the sink.
