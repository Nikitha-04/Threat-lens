import json
import os
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest

from reputation.cache import ReputationCache
from reputation.rate_limiter import RateLimiter
from reputation.engine import process_email


# ─── Helpers / Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path):
    return ReputationCache(db_path=str(tmp_path / "test.db"))


PHISHING_EMAIL = {
    "message_id": "phish001",
    "links": ["https://evil.example.com/steal"],
    "attachments": [
        {"filename": "payload.exe", "sha256": "a" * 64}
    ],
}

CLEAN_EMAIL = {
    "message_id": "clean001",
    "links": ["https://example.com"],
    "attachments": [],
}

EMPTY_EMAIL = {
    "message_id": "empty001",
    "links": [],
    "attachments": [],
}

MOCK_GSB_FLAGGED = {"https://evil.example.com/steal": ["MALWARE"]}
MOCK_GSB_CLEAN   = {"https://example.com": []}

MOCK_VT_URL   = (3, 2, 72)   # malicious=3, suspicious=2, total=72
MOCK_VT_CLEAN = (0, 0, 72)
MOCK_VT_HASH  = (5, 72, True)


# ─── 1. Uncached URL triggers API call ───────────────────────────────────────

def test_uncached_url_calls_apis(db):
    with patch("reputation.safe_browsing_client.check_urls", return_value=MOCK_GSB_FLAGGED) as mock_gsb, \
         patch("reputation.virustotal_client.check_url",     return_value=MOCK_VT_URL)     as mock_vt, \
         patch("reputation.virustotal_client.check_hash",    return_value=MOCK_VT_HASH)    as mock_hash:

        result = process_email(PHISHING_EMAIL, db)

    mock_gsb.assert_called_once()
    mock_vt.assert_called_once_with("https://evil.example.com/steal")
    mock_hash.assert_called_once_with("a" * 64)

    uc = result["url_checks"][0]
    assert uc["safe_browsing_flagged"] is True
    assert "MALWARE" in uc["safe_browsing_threat_types"]
    assert uc["virustotal_malicious_count"] == 3
    assert uc["from_cache"] is False
    assert result["overall_reputation_flag"] == "malicious"


# ─── 2. Cached URL (<24 h) does NOT trigger API ──────────────────────────────

def test_cached_fresh_url_skips_api(db):
    # Pre-populate cache
    db.set_url("https://example.com", False, [], 0, 0, 72)

    with patch("reputation.safe_browsing_client.check_urls") as mock_gsb, \
         patch("reputation.virustotal_client.check_url")     as mock_vt:

        result = process_email(CLEAN_EMAIL, db)

    mock_gsb.assert_not_called()
    mock_vt.assert_not_called()
    assert result["url_checks"][0]["from_cache"] is True


# ─── 3. Stale cached URL (>24 h) triggers re-check ───────────────────────────

def test_stale_cache_triggers_recheck(db):
    # Write an entry with timestamp 25 hours ago
    db.set_url("https://example.com", False, [], 0, 0, 72)

    # Manually age the row
    from sqlalchemy.orm import sessionmaker
    from reputation.cache import UrlReputation
    session = db.Session()
    row = session.query(UrlReputation).first()
    row.checked_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=25)
    session.commit()
    session.close()

    with patch("reputation.safe_browsing_client.check_urls", return_value=MOCK_GSB_CLEAN) as mock_gsb, \
         patch("reputation.virustotal_client.check_url",     return_value=MOCK_VT_CLEAN) as mock_vt:

        result = process_email(CLEAN_EMAIL, db)

    mock_gsb.assert_called_once()
    mock_vt.assert_called_once()
    assert result["url_checks"][0]["from_cache"] is False


# ─── 4. Rate limiter delays the 5th rapid call ───────────────────────────────

def test_rate_limiter_delays_fifth_call():
    limiter = RateLimiter(max_calls=4, period_seconds=2)

    t_start = time.monotonic()
    for _ in range(4):
        limiter.acquire()   # slots 1-4 — instant

    # 5th should block until window slides
    limiter.acquire()
    elapsed = time.monotonic() - t_start

    assert elapsed >= 2.0, f"Expected >=2s delay for 5th call, got {elapsed:.2f}s"


# ─── 5. Missing API key handled gracefully ───────────────────────────────────

def test_missing_vt_key_no_crash(db, monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    with patch("reputation.safe_browsing_client.check_urls", return_value=MOCK_GSB_CLEAN):
        result = process_email(CLEAN_EMAIL, db)

    uc = result["url_checks"][0]
    # VT counts will be None, but no crash
    assert uc["virustotal_malicious_count"] is None
    assert uc["virustotal_total_vendors"] is None


def test_missing_gsb_key_no_crash(db, monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)

    with patch("reputation.virustotal_client.check_url", return_value=MOCK_VT_CLEAN), \
         patch("reputation.virustotal_client.check_hash", return_value=(0, 72, True)):
        result = process_email(PHISHING_EMAIL, db)

    # No crash; GSB fields default to not-flagged
    uc = result["url_checks"][0]
    assert isinstance(uc["safe_browsing_flagged"], bool)


# ─── 6. Email with zero links/attachments produces well-formed output ─────────

def test_empty_email_output(db):
    result = process_email(EMPTY_EMAIL, db)

    assert result["message_id"] == "empty001"
    assert result["url_checks"] == []
    assert result["attachment_checks"] == []
    assert result["overall_reputation_flag"] == "unknown"


# ─── 7. Non-200 / failed VirusTotal response produces 'unknown', not 'clean' ─

def test_virustotal_non_200_failure_results_in_unknown(db, monkeypatch):
    """
    Assert that when VirusTotal returns a non-200 status code (e.g. 500, 400, or 429),
    the URL check records virustotal_malicious_count as None and the overall
    reputation flag evaluates to 'unknown', NEVER falsely marking the email 'clean'.
    """
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy_key")
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"

    email_data = {
        "message_id": "vt_fail_001",
        "links": ["https://suspicious-site.example.com"],
        "attachments": [],
    }

    with patch("requests.get", return_value=mock_resp), \
         patch("requests.post", return_value=mock_resp), \
         patch("reputation.safe_browsing_client.check_urls", return_value={"https://suspicious-site.example.com": []}):
        result = process_email(email_data, db)

    assert len(result["url_checks"]) == 1
    uc = result["url_checks"][0]
    assert uc["virustotal_malicious_count"] is None
    assert uc["virustotal_total_vendors"] is None
    # Must NOT be clean — failed verification must be unknown
    assert result["overall_reputation_flag"] == "unknown"


# ─── 8. Fast mode caps unflagged VT checks and sets virustotal_checked=False ──

def test_fast_mode_caps_unflagged_links_and_marks_checked_false(db):
    """
    In fast mode:
    - Safe Browsing runs on all links.
    - At most 3 unflagged links are sent to VirusTotal based on suspicion.
    - Skipped links have virustotal_checked = False and VT counts as None.
    - Contributing factors receives 'VirusTotal not checked (fast mode)'.
    """
    from risk.scoring import score_reputation

    email_data = {
        "message_id": "fast_mode_001",
        "from": "alerts@google.com",
        "links": [
            "https://bit.ly/suspicious-shortener",       # Shortener -> suspicion 100
            "http://192.168.1.100/login",                # IP host -> suspicion 100
            "https://attacker-domain.com/long/random/path/abcdef0123456789", # diff domain + random -> suspicion 95
            "https://google.com/help",                   # same domain, clean -> low suspicion
            "https://google.com/about",                  # same domain, clean -> low suspicion
        ],
        "attachments": [],
    }

    mock_gsb_clean = {u: [] for u in email_data["links"]}
    with patch("reputation.safe_browsing_client.check_urls", return_value=mock_gsb_clean), \
         patch("reputation.virustotal_client.check_url", return_value=(0, 0, 72)) as mock_vt:
        result = process_email(email_data, db, fast_mode=True)

    # All 5 links must have records
    assert len(result["url_checks"]) == 5

    # Top 3 suspicious links were checked on VT
    checked_urls = [uc["url"] for uc in result["url_checks"] if uc["virustotal_checked"] is True]
    skipped_urls = [uc["url"] for uc in result["url_checks"] if uc["virustotal_checked"] is False]

    assert len(checked_urls) == 3
    assert len(skipped_urls) == 2
    assert "https://bit.ly/suspicious-shortener" in checked_urls
    assert "http://192.168.1.100/login" in checked_urls
    assert "https://attacker-domain.com/long/random/path/abcdef0123456789" in checked_urls

    # Skipped links have null VT fields and virustotal_checked: False
    for uc in result["url_checks"]:
        if uc["url"] in skipped_urls:
            assert uc["virustotal_checked"] is False
            assert uc["virustotal_malicious_count"] is None
            assert uc["virustotal_suspicious_count"] is None
            assert uc["virustotal_total_vendors"] is None

    # Check contributing factor
    _, factors = score_reputation(result)
    assert "VirusTotal not checked (fast mode)" in factors

