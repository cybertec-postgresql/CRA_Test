"""Cache keys for generated asset reports.

Reports are expensive to build, so a rendered report is cached under a key
derived from the query that produced it.
"""

import hashlib


def report_cache_key(query: str, tenant: str) -> str:
    """Return a stable cache key for a report request."""
    digest = hashlib.md5(f"{tenant}:{query}".encode()).hexdigest()
    return f"report:{tenant}:{digest}"
