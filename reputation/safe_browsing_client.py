import logging
import os

import requests

logger = logging.getLogger(__name__)

GSB_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def _api_key() -> str:
    key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if not key:
        raise EnvironmentError(
            "GOOGLE_SAFE_BROWSING_API_KEY is not set. Add it to your .env file."
        )
    return key


def check_urls(urls: list[str]) -> dict[str, list[str]]:
    """
    Batch-check a list of URLs against Google Safe Browsing.
    Returns a dict mapping url -> list of threat types found (empty = safe).
    """
    if not urls:
        return {}

    results: dict[str, list[str]] = {u: [] for u in urls}

    try:
        key = _api_key()
    except EnvironmentError as exc:
        logger.error(str(exc))
        return results   # all treated as unknown / unchecked

    body = {
        "client": {"clientId": "threat-lens", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }

    try:
        resp = requests.post(GSB_API, params={"key": key}, json=body, timeout=15)
    except requests.RequestException as exc:
        logger.error("Safe Browsing network error: %s", exc)
        return results

    if resp.status_code != 200:
        logger.error("Safe Browsing returned HTTP %s: %s", resp.status_code, resp.text[:200])
        return results

    data = resp.json()
    for match in data.get("matches", []):
        url = match.get("threat", {}).get("url", "")
        threat_type = match.get("threatType", "UNKNOWN")
        if url in results:
            results[url].append(threat_type)

    return results
