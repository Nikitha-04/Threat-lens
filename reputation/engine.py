"""
reputation/engine.py — core processing logic, importable by tests and CLI.
"""
import json as _json
import logging
from datetime import datetime, timezone

from reputation.cache import ReputationCache
from reputation import virustotal_client as vt
from reputation import safe_browsing_client as gsb

logger = logging.getLogger(__name__)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _overall_flag(url_checks: list, attachment_checks: list) -> str:
    for uc in url_checks:
        if uc["safe_browsing_flagged"]:
            return "malicious"
        mal = uc.get("virustotal_malicious_count") or 0
        sus = uc.get("virustotal_suspicious_count") or 0
        if mal >= 3:
            return "malicious"
        if mal >= 1 or sus >= 3:
            return "suspicious"

    for ac in attachment_checks:
        mal = ac.get("virustotal_malicious_count") or 0
        if mal >= 3:
            return "malicious"
        if mal >= 1:
            return "suspicious"

    if not url_checks and not attachment_checks:
        return "unknown"
    return "clean"


def _url_check_record(url: str, sb_flagged: bool, sb_threats: list,
                      vt_mal: int | None, vt_sus: int | None,
                      vt_total: int | None, checked_at: datetime,
                      from_cache: bool) -> dict:
    """
    Always returns a url_check dict with an identical, complete set of keys —
    guaranteed no missing fields regardless of which code path populated it.
    """
    return {
        "url": url,
        "safe_browsing_flagged": sb_flagged,
        "safe_browsing_threat_types": sb_threats,
        "virustotal_malicious_count": vt_mal,
        "virustotal_suspicious_count": vt_sus,
        "virustotal_total_vendors": vt_total,
        "checked_at": _iso(checked_at),
        "from_cache": from_cache,
    }


def _attachment_check_record(filename: str, sha256: str,
                             vt_mal: int | None, vt_total: int | None,
                             known: bool, checked_at: datetime,
                             from_cache: bool) -> dict:
    """Always returns an attachment_check dict with the complete set of keys."""
    return {
        "filename": filename,
        "sha256": sha256,
        "virustotal_malicious_count": vt_mal,
        "virustotal_total_vendors": vt_total,
        "known_to_virustotal": known,
        "checked_at": _iso(checked_at),
        "from_cache": from_cache,
    }


def process_email(data: dict, cache: ReputationCache) -> dict:
    message_id = data.get("message_id", "unknown")
    links = data.get("links", [])
    attachments = data.get("attachments", [])

    url_checks: list[dict] = []
    attachment_checks: list[dict] = []

    # ── Google Safe Browsing: batch all uncached URLs ─────────────────────────
    urls_needing_gsb: list[str] = []
    gsb_cache_hits: dict[str, object] = {}

    for url in links:
        cached = cache.get_url(url)
        if cached:
            gsb_cache_hits[url] = cached
        else:
            urls_needing_gsb.append(url)

    gsb_results: dict[str, list[str]] = {}
    if urls_needing_gsb:
        try:
            gsb_results = gsb.check_urls(urls_needing_gsb)
        except Exception as exc:
            logger.error("Safe Browsing failed: %s", exc)
            gsb_results = {u: [] for u in urls_needing_gsb}

    # ── Per-URL VirusTotal ────────────────────────────────────────────────────
    for url in links:
        cached = gsb_cache_hits.get(url)
        if cached:
            try:
                threats = _json.loads(cached.safe_browsing_threat_types or "[]")
            except Exception:
                threats = []
            url_checks.append(_url_check_record(
                url=url,
                sb_flagged=cached.safe_browsing_flagged,
                sb_threats=threats,
                vt_mal=cached.virustotal_malicious_count,
                vt_sus=cached.virustotal_suspicious_count,
                vt_total=cached.virustotal_total_vendors,
                checked_at=cached.checked_at,
                from_cache=True,
            ))
            continue

        sb_threats = gsb_results.get(url, [])
        sb_flagged = len(sb_threats) > 0

        # Always initialise to None so the schema key is always present
        vt_mal: int | None = None
        vt_sus: int | None = None
        vt_total: int | None = None
        try:
            vt_mal, vt_sus, vt_total = vt.check_url(url)
        except EnvironmentError as exc:
            logger.error(str(exc))
        except Exception as exc:
            logger.error("VirusTotal URL check failed for %s: %s", url, exc)

        now = datetime.now(timezone.utc)
        cache.set_url(url, sb_flagged, sb_threats, vt_mal, vt_sus, vt_total)

        url_checks.append(_url_check_record(
            url=url,
            sb_flagged=sb_flagged,
            sb_threats=sb_threats,
            vt_mal=vt_mal,
            vt_sus=vt_sus,
            vt_total=vt_total,
            checked_at=now,
            from_cache=False,
        ))

    # ── Attachment hash lookups ───────────────────────────────────────────────
    for att in attachments:
        sha256 = att.get("sha256", "")
        filename = att.get("filename", "")
        if not sha256:
            continue

        cached = cache.get_file(sha256)
        if cached:
            attachment_checks.append(_attachment_check_record(
                filename=filename,
                sha256=sha256,
                vt_mal=cached.virustotal_malicious_count,
                vt_total=cached.virustotal_total_vendors,
                known=cached.known_to_virustotal,
                checked_at=cached.checked_at,
                from_cache=True,
            ))
            continue

        # Always initialise to None / False — only overwrite on successful lookup
        vt_mal: int | None = None
        vt_total: int | None = None
        known: bool = False  # False = not found in VT (404 → not_known)
        try:
            vt_mal, vt_total, known = vt.check_hash(sha256)
        except EnvironmentError as exc:
            logger.error(str(exc))
        except Exception as exc:
            logger.error("VirusTotal hash check failed for %s: %s", sha256, exc)

        now = datetime.now(timezone.utc)
        cache.set_file(sha256, vt_mal, vt_total, known)

        attachment_checks.append(_attachment_check_record(
            filename=filename,
            sha256=sha256,
            vt_mal=vt_mal,
            vt_total=vt_total,
            known=known,
            checked_at=now,
            from_cache=False,
        ))

    return {
        "message_id": message_id,
        "url_checks": url_checks,
        "attachment_checks": attachment_checks,
        "overall_reputation_flag": _overall_flag(url_checks, attachment_checks),
    }
