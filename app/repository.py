"""Queries against the asset inventory.

Every query passes user input as a bound parameter. Identifiers that cannot be
bound, such as a sort column, are resolved through an allow list rather than
interpolated.
"""

from psycopg import sql

from app.db import cursor

SORTABLE = {
    "name": "name",
    "criticality": "criticality",
    "updated": "updated_at",
}


def list_assets(limit: int = 50, offset: int = 0, sort: str = "updated") -> list[dict]:
    """Return a page of assets.

    ``sort`` is a caller supplied key, so it is resolved through SORTABLE rather
    than interpolated. An unknown key is a programming error, not a query.
    """
    column = SORTABLE.get(sort)
    if column is None:
        raise ValueError(f"unsortable column: {sort}")
    return _page(column, limit, offset)


def _page(column: str, limit: int, offset: int) -> list[dict]:
    """Compose the ORDER BY through psycopg rather than string formatting.

    ``column`` is already known safe, it came out of SORTABLE, but composing it
    as an Identifier means the query is never assembled by hand and the quoting
    is psycopg's problem rather than ours.
    """
    query = sql.SQL(
        "SELECT id, name, criticality, updated_at FROM assets "
        "ORDER BY {column} DESC LIMIT %s OFFSET %s"
    ).format(column=sql.Identifier(column))
    with cursor() as cur:
        # Accepted 2026-09-03. The rule targets SQLAlchemy text() queries; this
        # is psycopg, and the only dynamic element is an Identifier composed by
        # psycopg from the SORTABLE allow list. Values stay bound. Revisit if
        # this module ever adopts SQLAlchemy. See SUPPRESSIONS.md.
        # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
        cur.execute(query, (limit, offset))
        return cur.fetchall()


def count_assets() -> int:
    with cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM assets")
        return cur.fetchone()["n"]


def get_asset(asset_id: int) -> dict | None:
    with cursor() as cur:
        cur.execute(
            "SELECT id, name, criticality, updated_at FROM assets WHERE id = %s",
            (asset_id,),
        )
        return cur.fetchone()


def assets_by_criticality(level: str) -> list[dict]:
    with cursor() as cur:
        cur.execute(
            "SELECT id, name, criticality FROM assets WHERE criticality = %s "
            "ORDER BY name",
            (level,),
        )
        return cur.fetchall()


def create_asset(name: str, criticality: str) -> int:
    with cursor() as cur:
        cur.execute(
            "INSERT INTO assets (name, criticality) VALUES (%s, %s) RETURNING id",
            (name, criticality),
        )
        return cur.fetchone()["id"]
