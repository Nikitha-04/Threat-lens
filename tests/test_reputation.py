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
