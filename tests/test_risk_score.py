import json
import os
import pytest

from risk.scoring import compute_risk, score_auth, score_geo, score_nlp, score_reputation


# ─── Fixtures ─────────────────────────────────────────────────────────────────

CLEAN_FORENSICS = {
    "spf": "pass", "dkim": "pass", "dmarc": "pass",
    "dmarc_policy": "reject",
    "alignment": {"spf_aligned": True, "dkim_aligned": True},
    "red_flags": []
}

FAIL_FORENSICS = {
    "spf": "fail", "dkim": "fail", "dmarc": "fail",
    "dmarc_policy": "none",
    "alignment": {"spf_aligned": False, "dkim_aligned": False},
    "red_flags": ["reply-to mismatch", "display-name spoofing"]
}

CLEAN_GEO = {
    "originating_ip": "1.1.1.1",
    "geolocation": {"country": "US", "city": "New York", "lat": 40.71, "long": -74.0},
    "anomaly": {"flagged": False, "reason": None, "implied_speed_kmh": None}
}

ANOMALY_GEO = {
    "originating_ip": "2.2.2.2",
    "geolocation": {"country": "GB", "city": "London", "lat": 51.5, "long": -0.12},
    "anomaly": {"flagged": True, "reason": "NYC to London in 2 hours", "implied_speed_kmh": 2785.0}
}

CLEAN_CLASSIFIED = {
    "phishing_probability": 0.08,
    "predicted_label": "legitimate",
    "top_indicative_terms": ["hello", "team"]
}

HIGH_CLASSIFIED = {
    "phishing_probability": 0.97,
    "predicted_label": "phishing",
    "top_indicative_terms": ["click", "verify", "account", "immediately", "password"]
}

CLEAN_REPUTATION = {
    "url_checks": [{
        "url": "https://example.com",
        "safe_browsing_flagged": False,
        "safe_browsing_threat_types": [],
        "virustotal_malicious_count": 0,
        "virustotal_suspicious_count": 0,
        "virustotal_total_vendors": 72
    }],
    "attachment_checks": [],
    "overall_reputation_flag": "clean"
}

MALICIOUS_REPUTATION = {
    "url_checks": [{
        "url": "https://evil.example.com/steal",
        "safe_browsing_flagged": True,
        "safe_browsing_threat_types": ["MALWARE"],
        "virustotal_malicious_count": 5,
        "virustotal_suspicious_count": 2,
        "virustotal_total_vendors": 72
    }],
    "attachment_checks": [{
        "filename": "payload.exe",
        "sha256": "a" * 64,
        "virustotal_malicious_count": 10,
        "virustotal_total_vendors": 72,
        "known_to_virustotal": True
    }],
    "overall_reputation_flag": "malicious"
}


# ─── 1. All inputs clean → low risk, no PDF ───────────────────────────────────

def test_all_clean_is_low(tmp_path):
    result = compute_risk(CLEAN_FORENSICS, CLEAN_GEO, CLEAN_CLASSIFIED, CLEAN_REPUTATION)
    assert result["risk_tier"] == "low"
    assert result["risk_score"] < 30


# ─── 2. High phishing + malicious reputation → critical, PDF generated ────────

def test_high_phishing_malicious_reputation(tmp_path):
    result = compute_risk(FAIL_FORENSICS, ANOMALY_GEO, HIGH_CLASSIFIED, MALICIOUS_REPUTATION)
    result["message_id"] = "phish_test"
    result["data_completeness"] = {"forensics": True, "geolocation": True, "classification": True, "reputation": True}

    assert result["risk_tier"] in ("high", "critical")
    assert result["risk_score"] >= 60

    # Verify PDF is generated
    from risk.pdf_report import generate_pdf
    pdf_path = str(tmp_path / "phish_test.pdf")
    generate_pdf(result, FAIL_FORENSICS, ANOMALY_GEO, HIGH_CLASSIFIED, MALICIOUS_REPUTATION, None, pdf_path)

    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 1000   # non-trivial PDF


# ─── 3. Missing geo/reputation → no crash, treated as neutral ─────────────────

def test_missing_modules_no_crash():
    # Neither geo nor reputation available
    result = compute_risk(CLEAN_FORENSICS, None, HIGH_CLASSIFIED, None)
    assert isinstance(result["risk_score"], float)
    assert result["risk_tier"] in ("low", "medium", "high", "critical")
    # geo_score and reputation_score should both be 0 (neutral) when data absent
    assert result["component_scores"]["geo_score"] == 0.0
    assert result["component_scores"]["reputation_score"] == 0.0


# ─── 4. Weighted score math verification ──────────────────────────────────────

def test_weighted_score_math():
    """
    With exact inputs:
      auth_score=0, geo_score=100, nlp_score=50, rep_score=0
      weights: 0.20, 0.20, 0.30, 0.30
      expected = 0*0.20 + 100*0.20 + 50*0.30 + 0*0.30 = 0 + 20 + 15 + 0 = 35.0
    """
    pure_geo = {
        "originating_ip": "1.1.1.1",
        "geolocation": {"country": "GB", "city": "London", "lat": 51.5, "long": -0.12},
        "anomaly": {"flagged": True, "reason": "test", "implied_speed_kmh": 3000}
    }
    mid_nlp = {"phishing_probability": 0.50, "predicted_label": "phishing", "top_indicative_terms": []}

    result = compute_risk(CLEAN_FORENSICS, pure_geo, mid_nlp, None)
    expected = 0 * 0.20 + 100 * 0.20 + 50 * 0.30 + 0 * 0.30
    assert abs(result["risk_score"] - expected) < 1.0, (
        f"Expected ~{expected}, got {result['risk_score']}"
    )


# ─── 5. PDF file actually created and non-empty ───────────────────────────────

def test_pdf_file_created_and_nonempty(tmp_path):
    from risk.pdf_report import generate_pdf

    result = compute_risk(FAIL_FORENSICS, ANOMALY_GEO, HIGH_CLASSIFIED, MALICIOUS_REPUTATION)
    result["message_id"] = "pdf_test"
    result["data_completeness"] = {"forensics": True, "geolocation": True, "classification": True, "reputation": True}

    pdf_path = str(tmp_path / "pdf_test.pdf")
    generate_pdf(result, FAIL_FORENSICS, ANOMALY_GEO, HIGH_CLASSIFIED, MALICIOUS_REPUTATION, None, pdf_path)

    assert os.path.exists(pdf_path), "PDF file was not created"
    size = os.path.getsize(pdf_path)
    assert size > 2000, f"PDF suspiciously small: {size} bytes"
    # Verify it starts with %PDF magic bytes
    with open(pdf_path, "rb") as f:
        header = f.read(5)
    assert header == b"%PDF-", f"File doesn't look like a PDF: {header}"
