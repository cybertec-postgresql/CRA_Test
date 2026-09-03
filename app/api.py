"""HTTP interface for the asset inventory."""

from flask import Flask, jsonify, request

from app import reports, repository

VALID_CRITICALITY = {"low", "medium", "high", "critical"}

app = Flask(__name__)


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")


@app.get("/assets")
def list_assets():
    limit = min(request.args.get("limit", default=50, type=int), 200)
    return jsonify(assets=repository.list_assets(limit=limit))


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


@app.get("/reports/<name>")
def get_report(name: str):
    return jsonify(report=reports.load_report(name))


@app.post("/reports/archive")
def archive():
    target = request.get_json(silent=True).get("target")
    reports.archive_reports(target)
    return jsonify(status="archived")
