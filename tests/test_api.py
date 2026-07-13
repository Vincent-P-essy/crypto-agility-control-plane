from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from crypto_agility.api import APISettings, create_app


def test_api_enforces_root_and_persists_redacted_cbom(fixture_root: Path, tmp_path: Path) -> None:
    app = create_app(
        APISettings(state_directory=tmp_path / "state", allowed_roots=(fixture_root.parent,))
    )
    with TestClient(app) as client:
        health = client.get("/healthz")
        assert health.status_code == 200
        assert health.headers["x-content-type-options"] == "nosniff"
        assert "default-src 'self'" in health.headers["content-security-policy"]
        assert client.get("/").status_code == 200
        assert client.get("/static/app.js").status_code == 200
        assert "crypto_agility_scans_total 0" in client.get("/metrics").text
        algorithms = client.get("/api/v1/algorithms").json()
        assert algorithms["algorithms"]["ML-KEM-768"]["standard"] == "FIPS 203"
        assert client.get("/api/v1/benchmarks").json() == []
        outside = client.post(
            "/api/v1/scans",
            json={"local_path": str(tmp_path), "source_label": "outside"},
        )
        assert outside.status_code == 403
        created = client.post(
            "/api/v1/scans",
            json={
                "local_path": str(fixture_root),
                "source_label": "api-fixture",
                "confidentiality_years": 12,
            },
        )
        assert created.status_code == 201
        payload = created.json()
        assert payload["summary"]["finding_count"] > 10
        assert "fixture-user" not in created.text
        listed = client.get("/api/v1/cboms").json()
        assert listed[0]["id"] == payload["document_id"]
        fetched = client.get(f"/api/v1/cboms/{payload['document_id']}")
        assert fetched.status_code == 200
        assert fetched.json()["document_id"] == payload["document_id"]
        assert "crypto_agility_scans_total 1" in client.get("/metrics").text
        assert client.get("/api/v1/cboms/not$valid").status_code == 400
        missing = "urn:cbom:sha256:" + "0" * 64
        assert client.get(f"/api/v1/cboms/{missing}").status_code == 404


def test_api_rejects_relative_scan_path(fixture_root: Path, tmp_path: Path) -> None:
    app = create_app(
        APISettings(state_directory=tmp_path / "state", allowed_roots=(fixture_root.parent,))
    )
    with TestClient(app) as client:
        response = client.post("/api/v1/scans", json={"local_path": "fixtures/inventory"})
    assert response.status_code == 400
