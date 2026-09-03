"""HTTP interface for the asset inventory."""

from flask import Flask, jsonify, request

from app import repository

VALID_CRITICALITY = {"low", "medium", "high", "critical"}

app = Flask(__name__)


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")


@app.get("/assets")
def list_assets():
    limit = min(max(request.args.get("limit", default=50, type=int), 1), 200)
    offset = max(request.args.get("offset", default=0, type=int), 0)
    sort = request.args.get("sort", "updated")
    if sort not in repository.SORTABLE:
        return jsonify(error="unsortable column"), 400
    return jsonify(
        assets=repository.list_assets(limit=limit, offset=offset, sort=sort),
        total=repository.count_assets(),
    )


@app.get("/assets/<int:asset_id>")
def get_asset(asset_id: int):
    asset = repository.get_asset(asset_id)
    if asset is None:
        return jsonify(error="asset not found"), 404
    return jsonify(asset=asset)


@app.get("/assets/criticality/<level>")
def by_criticality(level: str):
    if level not in VALID_CRITICALITY:
        return jsonify(error="unknown criticality level"), 400
    return jsonify(assets=repository.assets_by_criticality(level))


@app.post("/assets")
def create_asset():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    criticality = payload.get("criticality")
    if not name:
        return jsonify(error="name is required"), 400
    if criticality not in VALID_CRITICALITY:
        return jsonify(error="unknown criticality level"), 400
    asset_id = repository.create_asset(name, criticality)
    return jsonify(id=asset_id), 201
