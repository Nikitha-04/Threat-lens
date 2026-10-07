"""
tests/test_orchestrator.py — Tests for run_pipeline orchestrator logic.
Tests per-email failure handling, multi-module field merging into dashboard JSON,
and backend handling of dashboard data.
"""
from __future__ import annotations

import json
import os
import pytest
from unittest.mock import patch, MagicMock

from run_pipeline import (
    process_single_email,
    ensure_directories,
    to_iso_date,
    format_sender,
)
from geo.maxmind_client import MaxMindClient
from geolocate import MockMaxMind
from geo.sender_history import Database
from reputation.cache import ReputationCache
from risk.scoring import load_weights
from backend.main import load_alerts, app
from fastapi.testclient import TestClient


SAMPLE_RAW_EMAIL_1 = b"""From: "Alice Security" <alice@security-team.org>
To: target@company.com
Subject: Notice: Security Review Required
Date: Wed, 07 Oct 2026 10:00:00 +0000
Message-ID: <test-email-001@security-team.org>
Content-Type: text/plain

Hello team, please review the security guidelines attached.
Visit https://example.com/guide for details.
"""

SAMPLE_RAW_EMAIL_2 = b"""From: "Billing Department" <invoices@vendor-corp.net>
To: target@company.com
Subject: Monthly Invoice #10294
Date: Wed, 07 Oct 2026 10:15:00 +0000
Message-ID: <test-email-002@vendor-corp.net>
Content-Type: text/plain

Here is your monthly invoice. Please pay by the end of the week.
Visit https://vendor-corp.net/pay
"""


@pytest.fixture
def test_env(tmp_path):
    """Set up temporary directory structure and test database."""
    base_dir = str(tmp_path / "data")
    dirs = ensure_directories(base_dir)
    db_path = str(tmp_path / "test.db")
    db = Database(db_path)
    maxmind = MockMaxMind()
    rep_cache = ReputationCache(db_path)
    weights = load_weights()
    return {
        "dirs": dirs,
        "db": db,
        "maxmind": maxmind,
        "rep_cache": rep_cache,
        "weights": weights,
        "tmp_path": tmp_path,
    }


def test_per_email_failure_handling_continues_gracefully(test_env):
    """
    Simulate one module (e.g., reputation) failing with an exception on the first email.
    Confirm the pipeline handles the error gracefully, marks data_completeness.reputation
    as False for that email, and continues processing the second email successfully.
    """
    call_count = 0

    def mock_rep_fail_first(data, cache):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("VirusTotal API quota hit (HTTP 429 Too Many Requests)")
        return {
            "message_id": data.get("message_id", "test"),
            "url_checks": [],
            "attachment_checks": [],
            "overall_reputation_flag": "clean",
        }

    with patch("run_pipeline.reputation_process_email", side_effect=mock_rep_fail_first):
        # Process Email 1 (reputation will fail)
        res1 = process_single_email(
            raw_bytes=SAMPLE_RAW_EMAIL_1,
            dirs=test_env["dirs"],
            db=test_env["db"],
            maxmind=test_env["maxmind"],
            rep_cache=test_env["rep_cache"],
            weights=test_env["weights"],
            generate_pdfs=False,
        )

        # Process Email 2 (reputation will succeed)
        res2 = process_single_email(
            raw_bytes=SAMPLE_RAW_EMAIL_2,
            dirs=test_env["dirs"],
            db=test_env["db"],
            maxmind=test_env["maxmind"],
            rep_cache=test_env["rep_cache"],
            weights=test_env["weights"],
            generate_pdfs=False,
        )

    # Email 1 completed despite module failure
    assert res1 is not None
    assert res1["message_id"] == "test-email-001_security-team.org"

    # Verify Email 1 risk file noted missing module
    risk_file_1 = os.path.join(test_env["dirs"]["risk"], "test-email-001_security-team.org.json")
    assert os.path.exists(risk_file_1)
    with open(risk_file_1, "r", encoding="utf-8") as f:
        risk_data_1 = json.load(f)

    assert risk_data_1["data_completeness"]["reputation"] is False
    assert any("reputation module data unavailable" in f for f in risk_data_1["contributing_factors"])

    # Email 2 completed cleanly with full reputation data
    assert res2 is not None
    assert res2["message_id"] == "test-email-002_vendor-corp.net"
    risk_file_2 = os.path.join(test_env["dirs"]["risk"], "test-email-002_vendor-corp.net.json")
    with open(risk_file_2, "r", encoding="utf-8") as f:
        risk_data_2 = json.load(f)
    assert risk_data_2["data_completeness"]["reputation"] is True


def test_dashboard_json_merges_all_module_fields(test_env):
    """
    Test that dashboard JSON correctly merges fields from Task 1 (subject, from, date),
    Task 6 (risk_score, risk_tier, contributing_factors), and Task 3 (geolocation).
    """
    res = process_single_email(
        raw_bytes=SAMPLE_RAW_EMAIL_1,
        dirs=test_env["dirs"],
        db=test_env["db"],
        maxmind=test_env["maxmind"],
        rep_cache=test_env["rep_cache"],
        weights=test_env["weights"],
        generate_pdfs=False,
    )

    dash_file = os.path.join(test_env["dirs"]["dashboard"], f"{res['message_id']}.json")
    assert os.path.exists(dash_file)

    with open(dash_file, "r", encoding="utf-8") as f:
        dash_data = json.load(f)

    # Verify all expected keys exist
    expected_keys = {
        "message_id",
        "subject",
        "from",
        "date",
        "risk_score",
        "risk_tier",
        "contributing_factors",
        "geolocation",
    }
    assert expected_keys.issubset(set(dash_data.keys()))

    # Verify field values match real source data
    assert dash_data["subject"] == "Notice: Security Review Required"
    assert dash_data["from"] == "alice@security-team.org"
    assert "2026-10-07" in dash_data["date"]
    assert isinstance(dash_data["risk_score"], float)
    assert dash_data["risk_tier"] in ["low", "medium", "high", "critical"]
    assert isinstance(dash_data["contributing_factors"], list)


def test_backend_loads_dashboard_and_handles_empty_dir(tmp_path):
    """
    Test backend/main.py load_alerts():
    1. Returns [] without crashing when the dashboard directory is empty.
    2. Correctly loads alerts when files exist in the directory.
    """
    empty_dash_dir = str(tmp_path / "empty_dashboard")
    os.makedirs(empty_dash_dir, exist_ok=True)

    # 1. Empty directory
    alerts = load_alerts(dashboard_dir=empty_dash_dir)
    assert alerts == []

    # FastApi endpoint with empty dir
    client = TestClient(app)
    with patch("backend.main.DASHBOARD_DATA_DIR", empty_dash_dir):
        response = client.get("/api/alerts")
        assert response.status_code == 200
        assert response.json() == []

    # 2. Populated directory
    sample_alert = {
        "message_id": "test-live-001",
        "subject": "System Alert",
        "from": "alerts@internal.corp",
        "date": "2026-10-07T10:00:00Z",
        "risk_score": 15.5,
        "risk_tier": "low",
        "contributing_factors": ["SPF PASS"],
        "geolocation": {
            "country": "US",
            "city": "New York",
            "lat": 40.7128,
            "long": -74.0060,
        },
    }
    alert_path = os.path.join(empty_dash_dir, "test-live-001.json")
    with open(alert_path, "w", encoding="utf-8") as f:
        json.dump(sample_alert, f)

    loaded = load_alerts(dashboard_dir=empty_dash_dir)
    assert len(loaded) == 1
    assert loaded[0]["message_id"] == "test-live-001"

    with patch("backend.main.DASHBOARD_DATA_DIR", empty_dash_dir):
        api_resp = client.get("/api/alerts")
        assert api_resp.status_code == 200
        data = api_resp.json()
        assert len(data) == 1
        assert data[0]["message_id"] == "test-live-001"
        assert data[0]["risk_score"] == 15.5
