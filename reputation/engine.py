"""
reputation/engine.py — core processing logic, importable by tests and CLI.
"""
import ipaddress
import json as _json
import logging
import re
import urllib.parse
from datetime import datetime, timezone
from email.utils import parseaddr

from reputation.cache import ReputationCache
from reputation import virustotal_client as vt
from reputation import safe_browsing_client as gsb
from parsers.email_parser import deduplicate_links

logger = logging.getLogger(__name__)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "rebrand.ly", "cutt.ly",
    "shorturl.at", "tiny.cc", "lnkd.in", "t.ly", "rb.gy", "qr.ae",
    "v.gd", "clck.ru", "s.id", "soo.gd", "trib.al"
}


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def is_ip_host(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_sender_domain(from_val) -> str | None:
    email_addr = ""
    if isinstance(from_val, dict):
        email_addr = from_val.get("email", "") or ""
    elif isinstance(from_val, str):
        email_addr = parseaddr(from_val)[1]
    if "@" in email_addr:
        return email_addr.split("@")[-1].strip().lower()
    return None


def compute_url_suspicion(url: str, sender_domain: str | None) -> float:
    score = 0.0
    try:
        p = urllib.parse.urlparse(url)
        host = (p.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]

        # 1. URL shorteners
        if host in URL_SHORTENERS or any(host.endswith("." + s) for s in URL_SHORTENERS):
            score += 100.0

        # 2. Raw IP hosts
        if is_ip_host(host):
            score += 100.0

        # 3. Domain different from sender's domain
        if sender_domain:
            s_dom = sender_domain.lower()
            if s_dom.startswith("www."):
                s_dom = s_dom[4:]
            if host and s_dom:
                if host != s_dom and not host.endswith("." + s_dom):
                    score += 50.0

        # 4. Long random paths
        path = p.path or ""
        if len(path) > 30:
            score += 20.0 + min(len(path) - 30, 30)
        if re.search(r'[a-f0-9]{16,}|[A-Za-z0-9_-]{24,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}', path):
            score += 25.0
    except Exception:
        pass
    return score


def _overall_flag(url_checks: list, attachment_checks: list) -> str:
    if not url_checks and not attachment_checks:
        return "unknown"

    has_suspicious = False
    has_unverified = False

    for uc in url_checks:
        if uc.get("safe_browsing_flagged"):
            return "malicious"
        if uc.get("virustotal_checked", True):
            mal = uc.get("virustotal_malicious_count")
            sus = uc.get("virustotal_suspicious_count")
            if mal is not None:
                if mal >= 3:
                    return "malicious"
                elif mal >= 1 or (sus is not None and sus >= 3):
                    has_suspicious = True
            else:
                has_unverified = True
        else:
            # Not sent to VirusTotal in fast mode
            pass

    for ac in attachment_checks:
        mal = ac.get("virustotal_malicious_count")
        if mal is not None:
            if mal >= 3:
                return "malicious"
            elif mal >= 1:
                has_suspicious = True
        else:
            has_unverified = True

    if has_suspicious:
        return "suspicious"
    if has_unverified:
        # A check genuinely failed or could not be verified — never mark clean!
        return "unknown"
    return "clean"


def _url_check_record(url: str, sb_flagged: bool, sb_threats: list,
                      vt_mal: int | None, vt_sus: int | None,
                      vt_total: int | None, checked_at: datetime,
                      from_cache: bool, vt_checked: bool = True) -> dict:
    """
    Always returns a url_check dict with an identical, complete set of keys —
    guaranteed no missing fields regardless of which code path populated it.
    """
    return {
        "url": url,
        "safe_browsing_flagged": sb_flagged,
        "safe_browsing_threat_types": sb_threats,
        "virustotal_checked": vt_checked,
        "virustotal_malicious_count": vt_mal if vt_checked else None,
        "virustotal_suspicious_count": vt_sus if vt_checked else None,
        "virustotal_total_vendors": vt_total if vt_checked else None,
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


def process_email(data: dict, cache: ReputationCache, fast_mode: bool = False) -> dict:
    message_id = data.get("message_id", "unknown")
    raw_links = data.get("links", [])
    # Strictly filter to valid web URLs (http:// and https://) — ignores mailto: and non-web links
    valid_links = [
        u.strip() for u in raw_links
        if isinstance(u, str) and u.strip().lower().startswith(("http://", "https://"))
    ]
    links = deduplicate_links(valid_links)
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

    # ── Determine VirusTotal allowed URLs in fast mode ────────────────────────
    sender_domain = extract_sender_domain(data.get("from"))
    vt_allowed_urls = set()

    if not fast_mode:
        vt_allowed_urls = set(links)
    else:
        sb_flagged_links = []
        unflagged_links = []
        for url in links:
            cached = gsb_cache_hits.get(url)
            if cached:
                flagged = cached.safe_browsing_flagged
            else:
                flagged = len(gsb_results.get(url, [])) > 0
            if flagged:
                sb_flagged_links.append(url)
            else:
                unflagged_links.append(url)

        vt_allowed_urls.update(sb_flagged_links)
        scored_unflagged = [
            (compute_url_suspicion(u, sender_domain), u)
            for u in unflagged_links
        ]
        scored_unflagged.sort(key=lambda x: (x[0], -len(x[1])), reverse=True)
        top_3_unflagged = [u for _, u in scored_unflagged[:3]]
        vt_allowed_urls.update(top_3_unflagged)

    # ── Per-URL VirusTotal ────────────────────────────────────────────────────
    for url in links:
        should_check_vt = (url in vt_allowed_urls)
        cached = gsb_cache_hits.get(url)

        if cached:
            try:
                threats = _json.loads(cached.safe_browsing_threat_types or "[]")
            except Exception:
                threats = []

            cached_vt_available = (
                cached.virustotal_malicious_count is not None
                or cached.virustotal_total_vendors is not None
            )

            if should_check_vt and not cached_vt_available:
                vt_mal, vt_sus, vt_total = None, None, None
                try:
                    vt_mal, vt_sus, vt_total = vt.check_url(url)
                except EnvironmentError as exc:
                    logger.error(str(exc))
                except Exception as exc:
                    logger.error("VirusTotal URL check failed for %s: %s", url, exc)

                now = datetime.now(timezone.utc)
                cache.set_url(url, cached.safe_browsing_flagged, threats, vt_mal, vt_sus, vt_total)
                url_checks.append(_url_check_record(
                    url=url,
                    sb_flagged=cached.safe_browsing_flagged,
                    sb_threats=threats,
                    vt_mal=vt_mal,
                    vt_sus=vt_sus,
                    vt_total=vt_total,
                    checked_at=now,
                    from_cache=False,
                    vt_checked=True,
                ))
            elif should_check_vt and cached_vt_available:
                url_checks.append(_url_check_record(
                    url=url,
                    sb_flagged=cached.safe_browsing_flagged,
                    sb_threats=threats,
                    vt_mal=cached.virustotal_malicious_count,
                    vt_sus=cached.virustotal_suspicious_count,
                    vt_total=cached.virustotal_total_vendors,
                    checked_at=cached.checked_at,
                    from_cache=True,
                    vt_checked=True,
                ))
            else:
                url_checks.append(_url_check_record(
                    url=url,
                    sb_flagged=cached.safe_browsing_flagged,
                    sb_threats=threats,
                    vt_mal=None,
                    vt_sus=None,
                    vt_total=None,
                    checked_at=cached.checked_at,
                    from_cache=True,
                    vt_checked=False,
                ))
            continue

        sb_threats = gsb_results.get(url, [])
        sb_flagged = len(sb_threats) > 0

        if should_check_vt:
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
                vt_checked=True,
            ))
        else:
            now = datetime.now(timezone.utc)
            url_checks.append(_url_check_record(
                url=url,
                sb_flagged=sb_flagged,
                sb_threats=sb_threats,
                vt_mal=None,
                vt_sus=None,
                vt_total=None,
                checked_at=now,
                from_cache=False,
                vt_checked=False,
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
