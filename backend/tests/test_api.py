"""
Unit and integration tests for FastAPI backend.
Tests /api/alerts, /api/alerts/{message_id}, schema validation, and 404 behavior.
"""
import pytest
from fastapi.testclient import TestClient

try:
    from backend.main import app
except ModuleNotFoundError:
    import sys
    import os
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data.get("status") == "ok"


def test_get_alerts_list_status_and_schema():
    response = client.get("/api/alerts")
    assert response.status_code == 200
    alerts = response.json()
    assert isinstance(alerts, list)
    assert len(alerts) >= 15

    for alert in alerts:
        assert "message_id" in alert
        assert "subject" in alert
        assert "from" in alert
        assert "date" in alert
        assert "risk_score" in alert
        assert "risk_tier" in alert
        assert "contributing_factors" in alert
        assert "geolocation" in alert

        assert isinstance(alert["risk_score"], (int, float))
        assert 0.0 <= alert["risk_score"] <= 100.0
        assert alert["risk_tier"] in ["low", "medium", "high", "critical"]
        assert isinstance(alert["contributing_factors"], list)

        if alert["geolocation"] is not None:
            geo = alert["geolocation"]
            assert "country" in geo
            assert "city" in geo
            assert "lat" in geo
            assert "long" in geo
            assert isinstance(geo["lat"], (int, float))
            assert isinstance(geo["long"], (int, float))


def test_get_alerts_sorted_descending():
    response = client.get("/api/alerts")
    assert response.status_code == 200
    alerts = response.json()
    scores = [a["risk_score"] for a in alerts]
    assert scores == sorted(scores, reverse=True)


def test_get_alerts_filter_by_risk_tier():
    for tier in ["low", "medium", "high", "critical"]:
        response = client.get(f"/api/alerts?risk_tier={tier}")
        assert response.status_code == 200
        filtered = response.json()
        assert len(filtered) > 0
        for alert in filtered:
            assert alert["risk_tier"] == tier


def test_get_alert_by_id_success():
    # First fetch list to obtain a valid message_id
    list_resp = client.get("/api/alerts")
    assert list_resp.status_code == 200
    sample_alert = list_resp.json()[0]
    mid = sample_alert["message_id"]

    response = client.get(f"/api/alerts/{mid}")
    assert response.status_code == 200
    data = response.json()
    assert data["message_id"] == mid
    assert data["subject"] == sample_alert["subject"]
    assert data["from"] == sample_alert["from"]
    assert data["risk_score"] == sample_alert["risk_score"]
    assert data["risk_tier"] == sample_alert["risk_tier"]
    assert data["contributing_factors"] == sample_alert["contributing_factors"]
    assert data["geolocation"] == sample_alert["geolocation"]


def test_get_alert_by_id_not_found():
    response = client.get("/api/alerts/nonexistent-msg-id-99999")
    assert response.status_code == 404
    error_data = response.json()
    assert "detail" in error_data
    assert "nonexistent-msg-id-99999" in error_data["detail"]


def test_null_geolocation_handled_gracefully():
    response = client.get("/api/alerts")
    assert response.status_code == 200
    alerts = response.json()
    null_geo_alerts = [a for a in alerts if a["geolocation"] is None]
    assert len(null_geo_alerts) >= 1
    # Verify the null geo entry is still fully accessible by message_id
    mid = null_geo_alerts[0]["message_id"]
    detail_resp = client.get(f"/api/alerts/{mid}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["geolocation"] is None
