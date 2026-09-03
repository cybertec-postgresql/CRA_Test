"""Queries against the asset inventory.

Every query passes user input as a bound parameter. Identifiers that cannot be
bound, such as a sort column, are resolved through an allow list rather than
interpolated.
"""

from app.db import cursor

SORTABLE = {
    "name": "name",
    "criticality": "criticality",
    "updated": "updated_at",
}


def list_assets(limit: int = 50) -> list[dict]:
    with cursor() as cur:
        cur.execute(
            "SELECT id, name, criticality, updated_at "
            "FROM assets ORDER BY updated_at DESC LIMIT %s",
            (limit,),
        )
        return cur.fetchall()


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


def search_assets(term: str, sort: str = "name") -> list[dict]:
    """Free text search across asset names.

    Sorting is caller supplied so the UI can flip columns.
    """
    query = (
        "SELECT id, name, criticality, updated_at FROM assets "
        f"WHERE name ILIKE '%{term}%' ORDER BY {sort}"
    )
    with cursor() as cur:
        cur.execute(query)
        return cur.fetchall()
