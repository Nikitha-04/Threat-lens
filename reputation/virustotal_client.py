import base64
import logging
import os
import time

import requests

from reputation.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
_limiter = RateLimiter(max_calls=4, period_seconds=60)
_DAILY_QUOTA_EXCEEDED = False


def _headers() -> dict:
    key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not key:
        raise EnvironmentError(
            "VIRUSTOTAL_API_KEY is not set. Add it to your .env file."
        )
    return {"x-apikey": key}


def _get(url: str, params: dict | None = None, retries: int = 2) -> dict | None:
    global _DAILY_QUOTA_EXCEEDED
    if _DAILY_QUOTA_EXCEEDED:
        logger.warning("VirusTotal daily quota already hit — skipping request.")
        return None

    _limiter.acquire()
    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, headers=_headers(), params=params, timeout=15)
        except requests.RequestException as exc:
            logger.error("VirusTotal network error: %s", exc)
            return None

        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            return None          # Hash / URL not known to VT
        if resp.status_code == 429:
            body = resp.json().get("error", {})
            if body.get("code") == "DailyQuotaExceeded":
                logger.warning("VirusTotal daily quota exceeded. Remaining checks will be skipped.")
                _DAILY_QUOTA_EXCEEDED = True
                return None
            # Minute-rate exceeded — back off and retry
            wait = 15 * (attempt + 1)
            logger.warning("VirusTotal 429 — backing off %ds (attempt %d).", wait, attempt + 1)
            time.sleep(wait)
            continue
        logger.error("VirusTotal unexpected status %s for %s", resp.status_code, url)
        return None
    return None


def _post(url: str, json_body: dict) -> dict | None:
    global _DAILY_QUOTA_EXCEEDED
    if _DAILY_QUOTA_EXCEEDED:
        return None

    _limiter.acquire()
    try:
        resp = requests.post(url, headers=_headers(), json=json_body, timeout=15)
    except requests.RequestException as exc:
        logger.error("VirusTotal POST error: %s", exc)
        return None

    if resp.status_code in (200, 201):
        return resp.json()
    if resp.status_code == 429:
        logger.warning("VirusTotal 429 on POST.")
        return None
    logger.error("VirusTotal POST status %s", resp.status_code)
    return None


def _extract_stats(data: dict) -> tuple[int | None, int | None, int | None]:
    """Returns (malicious, suspicious, total_vendors) from a VT analysis attributes dict."""
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        return malicious, suspicious, total
    except (KeyError, TypeError):
        return None, None, None


def check_url(url: str) -> tuple[int | None, int | None, int | None]:
    """
    Check a URL against VirusTotal.
    Returns (malicious_count, suspicious_count, total_vendors).
    """
    # Encode URL as base64url (no padding) per VT v3 spec
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    data = _get(f"{VT_BASE}/urls/{url_id}")

    if data is None:
        # Not known — submit for scanning
        submitted = _post(f"{VT_BASE}/urls", {"url": url})
        if submitted is None:
            return None, None, None
        # Fetch the analysis result (may still be queued — return zeros)
        analysis_id = submitted.get("data", {}).get("id", "")
        if not analysis_id:
            return None, None, None
        result = _get(f"{VT_BASE}/analyses/{analysis_id}")
        if result is None:
            return None, None, None
        return _extract_stats(result)

    return _extract_stats(data)


def check_hash(sha256: str) -> tuple[int | None, int | None, bool]:
    """
    Look up a file hash on VirusTotal.
    Returns (malicious_count, total_vendors, known_to_virustotal).
    """
    data = _get(f"{VT_BASE}/files/{sha256}")
    if data is None:
        return None, None, False
    malicious, _, total = _extract_stats(data)
    return malicious, total, True
