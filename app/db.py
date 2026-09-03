"""PostgreSQL connection handling for the asset inventory."""

from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from app import config

_pool: ConnectionPool | None = None


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            conninfo=config.database_url(),
            min_size=1,
            max_size=config.pool_size(),
            open=True,
        )
    return _pool


@contextmanager
def cursor() -> psycopg.Cursor:
    """Yield a dict cursor inside a transaction that commits on clean exit."""
    with get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            yield cur
