"""Contract tests for the asset inventory API."""

import pytest

from app.api import app


@pytest.fixture
def client():
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def test_healthz(client):
    assert client.get("/healthz").get_json() == {"status": "ok"}


def test_unknown_criticality_is_rejected(client):
    response = client.get("/assets/criticality/banana")
    assert response.status_code == 400


def test_create_requires_a_name(client):
    response = client.post("/assets", json={"criticality": "high"})
    assert response.status_code == 400


def test_unsortable_column_is_rejected(client):
    assert client.get("/assets?sort=; DROP TABLE assets").status_code == 400
