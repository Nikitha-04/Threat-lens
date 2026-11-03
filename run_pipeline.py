"""
run_pipeline.py — Master orchestrator for Email Threat Detection Platform.
Fetches real emails via IMAP/Gmail, runs every analytical module in sequence:
ingest -> forensics -> geo -> classify -> reputation -> risk_score -> dashboard
"""
from __future__ import annotations

import argparse
import email
import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from dateutil import parser as date_parser
from dotenv import load_dotenv

# Pipeline module imports
from parsers.email_parser import parse_email, sanitize_filename
from forensics import analyze_forensics
from geolocate import process_email as geolocate_process_email, MockMaxMind
from geo.maxmind_client import MaxMindClient
from geo.sender_history import Database
from classifier.scorer import score_email
from reputation.cache import ReputationCache
from reputation.engine import process_email as reputation_process_email
from risk.scoring import compute_risk, load_weights
from risk.pdf_report import generate_pdf

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("run_pipeline")


def to_iso_date(date_str: str | None) -> str:
    """Convert email Date header string to ISO 8601 string."""
    if not date_str:
        return datetime.now(timezone.utc).isoformat()
    try:
        dt = date_parser.parse(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def format_sender(from_val) -> str:
    """Format email sender into a standard email address string."""
    if isinstance(from_val, dict):
        email_addr = from_val.get("email", "").strip()
        name = from_val.get("name", "").strip()
        return email_addr or name or "unknown"
    elif isinstance(from_val, str):
        from email.utils import parseaddr
        name, addr = parseaddr(from_val)
        return addr or from_val.strip() or "unknown"
    return "unknown"


def decode_subject(subject_val: str | None) -> str:
    """Decode RFC 2047 encoded subject to clean unicode text."""
    if not subject_val:
        return "(No Subject)"
    try:
        from email.header import decode_header, make_header
        decoded = str(make_header(decode_header(str(subject_val)))).strip()
        return decoded or "(No Subject)"
    except Exception:
        return str(subject_val).strip() or "(No Subject)"


def extract_safe_message_id(raw_bytes: bytes) -> str:
    """Quickly extract sanitized message_id from raw email bytes without full parsing."""
    try:
        msg = email.message_from_bytes(raw_bytes)
        mid = msg.get("Message-ID", "")
        if mid:
            safe = sanitize_filename(mid.strip("<>"))
            if safe and safe != "unnamed":
                return safe
    except Exception:
        pass
    return hashlib.sha256(raw_bytes).hexdigest()


def ensure_directories(base_dir: str = "./data") -> dict[str, str]:
    """Ensure all required pipeline directories exist and return their paths."""
    dirs = {
        "raw": os.path.join(base_dir, "raw"),
        "parsed": os.path.join(base_dir, "parsed"),
        "attachments": os.path.join(base_dir, "attachments"),
        "forensics": os.path.join(base_dir, "forensics"),
        "geo": os.path.join(base_dir, "geo"),
        "classified": os.path.join(base_dir, "classified"),
        "reputation": os.path.join(base_dir, "reputation"),
        "risk": os.path.join(base_dir, "risk"),
        "reports": os.path.join(base_dir, "reports"),
        "dashboard": os.path.join(base_dir, "dashboard"),
    }
    for p in dirs.values():
        os.makedirs(p, exist_ok=True)
    return dirs


def process_single_email(
    raw_bytes: bytes,
    dirs: dict[str, str],
    db: Database,
    maxmind: MaxMindClient | MockMaxMind,
    rep_cache: ReputationCache,
    weights: dict,
    generate_pdfs: bool = True,
    force: bool = False,
    fast_mode: bool = False,
) -> dict | None:
    """
    Execute all analytical stages for a single raw email with graceful error handling.
    Returns the combined dashboard-ready dictionary, or None if ingestion parsing fails.
    If force is False and dashboard output already exists, skips analytical modules.
    """
    # ── Fast Skip Check if Already Processed ─────────────────────────────────
    if not force:
        quick_id = extract_safe_message_id(raw_bytes)
        quick_dash_path = os.path.join(dirs["dashboard"], f"{quick_id}.json")
        if os.path.exists(quick_dash_path):
            try:
                with open(quick_dash_path, "r", encoding="utf-8") as f:
                    existing_data = json.load(f)
                logger.info("[%s] Already processed in dashboard. Skipping (use --force to reprocess).", quick_id)
                return existing_data
            except Exception:
                pass

    # ── 1. Ingestion & Email Parsing ──────────────────────────────────────────
    try:
        parsed_data = parse_email(raw_bytes, attachments_dir=dirs["attachments"])
    except Exception as exc:
        logger.error("Failed to parse raw email: %s", exc)
        return None

    safe_id = sanitize_filename(parsed_data.get("message_id"))
    if not safe_id or safe_id == "unnamed":
        safe_id = hashlib.sha256(raw_bytes).hexdigest()

    dash_path = os.path.join(dirs["dashboard"], f"{safe_id}.json")
    if not force and os.path.exists(dash_path):
        try:
            with open(dash_path, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
            logger.info("[%s] Already processed in dashboard. Skipping (use --force to reprocess).", safe_id)
            return existing_data
        except Exception:
            pass

    parsed_path = os.path.join(dirs["parsed"], f"{safe_id}.json")
    with open(parsed_path, "w", encoding="utf-8") as f:
        json.dump(parsed_data, f, indent=2, ensure_ascii=False)

    logger.info("[%s] Ingestion complete: '%s'", safe_id, parsed_data.get("subject", "")[:50])

    # ── 2. Header Forensics ───────────────────────────────────────────────────
    forensics = None
    try:
        forensics = analyze_forensics(parsed_data)
        forensics_path = os.path.join(dirs["forensics"], f"{safe_id}.json")
        with open(forensics_path, "w", encoding="utf-8") as f:
            json.dump(forensics, f, indent=2, ensure_ascii=False)
        logger.info("[%s] Forensics: SPF=%s, DKIM=%s, IP=%s", safe_id, forensics.get("spf"), forensics.get("dkim"), forensics.get("originating_ip"))
    except Exception as exc:
        logger.error("[%s] Forensics module failed: %s", safe_id, exc)

    # ── 3. Geolocation & Anomaly Detection ────────────────────────────────────
    geo = None
    try:
        geo_input = forensics if forensics else parsed_data
        geo = geolocate_process_email(geo_input, db, maxmind)
        geo_path = os.path.join(dirs["geo"], f"{safe_id}.json")
        with open(geo_path, "w", encoding="utf-8") as f:
            json.dump(geo, f, indent=2, ensure_ascii=False)
        anomaly_flag = geo.get("anomaly", {}).get("flagged", False)
        logger.info("[%s] Geolocation: Flagged=%s, City=%s", safe_id, anomaly_flag, (geo.get("geolocation") or {}).get("city"))
    except Exception as exc:
        logger.error("[%s] Geolocation module failed: %s", safe_id, exc)

    # ── 4. NLP Phishing Classification ─────────────────────────────────────────
    classified = None
    try:
        subject = parsed_data.get("subject", "") or ""
        body_text = parsed_data.get("body_text", "") or ""
        score_res = score_email(subject, body_text)
        classified = {
            "message_id": safe_id,
            "phishing_probability": score_res["phishing_probability"],
            "predicted_label": score_res["predicted_label"],
            "model_version": score_res.get("model_version", "baseline_v1.0"),
            "top_indicative_terms": score_res.get("top_indicative_terms", []),
        }
        classified_path = os.path.join(dirs["classified"], f"{safe_id}.json")
        with open(classified_path, "w", encoding="utf-8") as f:
            json.dump(classified, f, indent=2, ensure_ascii=False)
        logger.info("[%s] Classifier: Label=%s, Prob=%.4f", safe_id, classified["predicted_label"], classified["phishing_probability"])
    except Exception as exc:
        logger.error("[%s] Classification module failed: %s", safe_id, exc)

    # ── 5. Reputation Analysis (VirusTotal & Safe Browsing) ────────────────────
    reputation = None
    try:
        try:
            reputation = reputation_process_email(parsed_data, rep_cache, fast_mode=fast_mode)
        except TypeError:
            reputation = reputation_process_email(parsed_data, rep_cache)
        rep_path = os.path.join(dirs["reputation"], f"{safe_id}.json")
        with open(rep_path, "w", encoding="utf-8") as f:
            json.dump(reputation, f, indent=2, ensure_ascii=False)
        for uc in reputation.get("url_checks", []):
            url_str = uc.get("url", "")
            sb_flag = "FLAGGED" if uc.get("safe_browsing_flagged") else "clean"
            if not uc.get("virustotal_checked", True):
                vt_status = "not checked (fast mode)"
            else:
                vt_mal = uc.get("virustotal_malicious_count")
                vt_tot = uc.get("virustotal_total_vendors")
                vt_status = f"{vt_mal}/{vt_tot} malicious" if vt_mal is not None else "unverified/failed"
            from_c = " (cached)" if uc.get("from_cache") else ""
            logger.info("[%s] Reputation URL: %s | SafeBrowsing: %s | VirusTotal: %s%s", safe_id, url_str, sb_flag, vt_status, from_c)
        for ac in reputation.get("attachment_checks", []):
            att_name = ac.get("filename", "")
            vt_mal = ac.get("virustotal_malicious_count")
            vt_tot = ac.get("virustotal_total_vendors")
            vt_status = f"{vt_mal}/{vt_tot} malicious" if vt_mal is not None else "unverified/failed"
            from_c = " (cached)" if ac.get("from_cache") else ""
            logger.info("[%s] Reputation Attachment: %s | VirusTotal: %s%s", safe_id, att_name, vt_status, from_c)
        logger.info("[%s] Reputation: Flag=%s (URLs: %d, Attachments: %d)", safe_id, reputation.get("overall_reputation_flag"), len(reputation.get("url_checks", [])), len(reputation.get("attachment_checks", [])))
    except Exception as exc:
        logger.error("[%s] Reputation module failed: %s", safe_id, exc)

    # ── 6. Risk Scoring & Reporting ───────────────────────────────────────────
    completeness = {
        "forensics": forensics is not None,
        "geolocation": geo is not None,
        "classification": classified is not None,
        "reputation": reputation is not None,
    }

    try:
        risk_result = compute_risk(forensics, geo, classified, reputation)
        risk_result["message_id"] = safe_id
        risk_result["data_completeness"] = completeness
        # Note missing module factors if any module failed
        if not completeness["reputation"]:
            risk_result["contributing_factors"].append("reputation module data unavailable")
        if not completeness["forensics"]:
            risk_result["contributing_factors"].append("forensics module data unavailable")
        if not completeness["geolocation"]:
            risk_result["contributing_factors"].append("geolocation module data unavailable")
        if not completeness["classification"]:
            risk_result["contributing_factors"].append("classification module data unavailable")
    except Exception as exc:
        logger.error("[%s] Risk scoring engine failed: %s", safe_id, exc)
        risk_result = {
            "message_id": safe_id,
            "risk_score": 0.0,
            "risk_tier": "low",
            "contributing_factors": [f"Risk scoring failure: {exc}"],
            "component_scores": {},
            "data_completeness": completeness,
        }

    risk_path = os.path.join(dirs["risk"], f"{safe_id}.json")
    with open(risk_path, "w", encoding="utf-8") as f:
        json.dump(risk_result, f, indent=2, ensure_ascii=False)

    tier = risk_result.get("risk_tier", "low")
    logger.info("[%s] Risk Score: %.1f [%s]", safe_id, risk_result.get("risk_score", 0.0), tier.upper())

    # Generate PDF forensics report for medium, high, or critical risks
    if generate_pdfs and tier in ("medium", "high", "critical"):
        pdf_path = os.path.join(dirs["reports"], f"{safe_id}.pdf")
        try:
            generate_pdf(risk_result, forensics, geo, classified, reputation, parsed_data, pdf_path)
            size = os.path.getsize(pdf_path)
            logger.info("[%s] PDF Report generated: %s (%d bytes)", safe_id, pdf_path, size)
        except Exception as exc:
            logger.error("[%s] PDF report generation failed: %s", safe_id, exc)

    # ── 7. Combined Dashboard Output ──────────────────────────────────────────
    geolocation_data = None
    if geo and isinstance(geo.get("geolocation"), dict):
        g = geo["geolocation"]
        if (
            g.get("country") is not None
            and g.get("lat") is not None
            and g.get("long") is not None
        ):
            try:
                city_name = g.get("city")
                if city_name is not None:
                    city_name = str(city_name).strip() or None
                geolocation_data = {
                    "country": str(g["country"]),
                    "city": city_name,
                    "lat": float(g["lat"]),
                    "long": float(g["long"]),
                }
            except (ValueError, TypeError):
                geolocation_data = None

    dashboard_item = {
        "message_id": safe_id,
        "subject": decode_subject(parsed_data.get("subject")),
        "from": format_sender(parsed_data.get("from")),
        "date": to_iso_date(parsed_data.get("date")),
        "risk_score": float(risk_result["risk_score"]),
        "risk_tier": str(risk_result["risk_tier"]),
        "contributing_factors": list(risk_result["contributing_factors"]),
        "geolocation": geolocation_data,
    }

    with open(dash_path, "w", encoding="utf-8") as f:
        json.dump(dashboard_item, f, indent=2, ensure_ascii=False)

    return dashboard_item


def run_pipeline(
    source: str = "imap",
    limit: int = 50,
    since: str | None = None,
    file_path: str | None = None,
    data_dir: str = "./data",
    folders: str = "inbox,spam",
    force: bool = False,
    fast: bool | None = None,
    full: bool = False,
) -> list[dict]:
    """
    Main pipeline entry point.
    1. Downloads raw emails first into ./data/raw/{message_id}.eml and closes connection.
    2. Runs analytical modules from saved messages.
    3. Handles fast vs full reputation checks.
    4. Logs rolling ETA and prints a comprehensive run summary.
    """
    load_dotenv()
    dirs = ensure_directories(data_dir)
    weights = load_weights()

    db_path = os.environ.get("DATABASE_URL", "sqlite:///./data/db/threat_platform.db").replace("sqlite:///", "")
    db = Database(db_path)

    maxmind_path = os.environ.get("MAXMIND_DB_PATH", "./data/geoip/GeoLite2-City.mmdb")
    maxmind = MaxMindClient(maxmind_path)
    if not maxmind.reader:
        raise FileNotFoundError(
            f"Required MaxMind GeoLite2 database missing at '{maxmind_path}'. "
            "Mock fallbacks are disabled. Ensure GeoLite2-City.mmdb exists in ./data/geoip/ "
            "or configure MAXMIND_DB_PATH in your .env file."
        )

    rep_cache = ReputationCache(db_path)

    # ── Phase 1: Download First ──────────────────────────────────────────────
    if source == "imap":
        from parsers.imap_client import IMAPClient
        client = IMAPClient()
        folder_counts = client.log_folder_status()
        saved_emails, folder_status = client.download_emails(
            raw_dir=dirs["raw"],
            limit=limit,
            since_date=since,
            folders=folders,
        )
    elif source == "gmail":
        from parsers.gmail_client import GmailClient
        client = GmailClient()
        saved_emails = []
        for raw_bytes in client.fetch_emails(limit=limit, since_date=since):
            safe_id = extract_safe_message_id(raw_bytes)
            eml_path = os.path.join(dirs["raw"], f"{safe_id}.eml")
            with open(eml_path, "wb") as f:
                f.write(raw_bytes)
            saved_emails.append({
                "message_id": safe_id,
                "folder": "GMAIL",
                "eml_path": eml_path,
                "raw_bytes": raw_bytes,
            })
        folder_status = {"GMAIL": {"fully_read": True, "read": len(saved_emails), "expected": len(saved_emails), "error": None}}
    elif source == "file":
        if not file_path:
            raise ValueError("--file path is required when source is 'file'")
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
        safe_id = extract_safe_message_id(raw_bytes)
        eml_path = os.path.join(dirs["raw"], f"{safe_id}.eml")
        with open(eml_path, "wb") as f:
            f.write(raw_bytes)
        saved_emails = [{
            "message_id": safe_id,
            "folder": "FILE",
            "eml_path": eml_path,
            "raw_bytes": raw_bytes,
        }]
        folder_status = {"FILE": {"fully_read": True, "read": 1, "expected": 1, "error": None}}
    else:
        raise ValueError(f"Unknown source: {source}")

    total_emails = len(saved_emails)

    # ── Determine Fast Mode vs Full Mode ─────────────────────────────────────
    if full:
        fast_mode = False
    elif fast is True:
        fast_mode = True
    else:
        # Default for runs over 20 emails
        fast_mode = (total_emails > 20) or (limit == 0) or (limit > 20)

    mode_label = "FAST MODE (Safe Browsing on all, VT capped at 3 suspicious unflagged links)" if fast_mode else "FULL MODE (all links checked on VT)"
    limit_desc = "no limit (all)" if limit == 0 else str(limit)
    logger.info("Starting ThreatLens Pipeline (source=%s, folders=%s, limit=%s, force=%s, mode=%s)", source, folders, limit_desc, force, mode_label)

    # Log any folder read failures
    for f_name, f_stat in folder_status.items():
        if not f_stat.get("fully_read", False):
            logger.error(
                "Folder '%s' could not be fully read: read %d of %d expected messages. Error: %s",
                f_name, f_stat.get("read", 0), f_stat.get("expected", 0), f_stat.get("error")
            )

    # ── Phase 2: Analysis Loop ────────────────────────────────────────────────
    processed_items = []
    skipped_count = 0
    newly_processed_count = 0
    failed_items = []

    loop_start = time.monotonic()

    for idx, item in enumerate(saved_emails, 1):
        safe_id = item["message_id"]
        folder = item["folder"]
        raw_bytes = item["raw_bytes"]

        # Calculate rolling estimated time remaining
        elapsed = time.monotonic() - loop_start
        if idx > 1 and elapsed > 0:
            avg_sec = elapsed / (idx - 1)
            remaining_sec = (total_emails - (idx - 1)) * avg_sec
            if remaining_sec < 60:
                est_str = f"~{int(remaining_sec)}s remaining"
            elif remaining_sec < 3600:
                est_str = f"~{int(remaining_sec // 60)}m {int(remaining_sec % 60)}s remaining"
            else:
                est_str = f"~{remaining_sec / 3600:.1f}h remaining"
        else:
            est_str = "estimating time remaining..."

        logger.info("==================== Email %d/%d (%s) [%s] ====================", idx, total_emails, folder, est_str)

        dash_path = os.path.join(dirs["dashboard"], f"{safe_id}.json")
        is_already_done = (not force) and os.path.exists(dash_path)

        try:
            result = process_single_email(
                raw_bytes=raw_bytes,
                dirs=dirs,
                db=db,
                maxmind=maxmind,
                rep_cache=rep_cache,
                weights=weights,
                generate_pdfs=True,
                force=force,
                fast_mode=fast_mode,
            )
            if result:
                processed_items.append(result)
                if is_already_done:
                    skipped_count += 1
                else:
                    newly_processed_count += 1
            else:
                failed_items.append({"message_id": safe_id, "reason": "Failed to parse email"})
        except Exception as exc:
            logger.exception("[%s] Unexpected error processing email: %s", safe_id, exc)
            failed_items.append({"message_id": safe_id, "reason": str(exc)})

    if hasattr(maxmind, "close"):
        maxmind.close()

    # ── Final Summary ─────────────────────────────────────────────────────────
    summary_lines = [
        "",
        "=" * 80,
        "                           PIPELINE EXECUTION SUMMARY",
        "=" * 80,
        f"Fetched:                      {total_emails}",
        f"Already processed (skipped):  {skipped_count}",
        f"Newly processed:              {newly_processed_count}",
        f"Failed:                       {len(failed_items)}",
        "-" * 80,
        "Folder Status:",
    ]
    for f_name, f_stat in folder_status.items():
        r_cnt = f_stat.get("read", 0)
        e_cnt = f_stat.get("expected", 0)
        is_full = f_stat.get("fully_read", False)
        status_label = "Fully read" if is_full else f"PARTIALLY READ (Error: {f_stat.get('error')})"
        summary_lines.append(f"  - {f_name}: {status_label} ({r_cnt}/{e_cnt} messages)")

    summary_lines.append("-" * 80)
    if failed_items:
        summary_lines.append("Failed Emails Details:")
        for item in failed_items:
            summary_lines.append(f"  - ID: {item['message_id']} | Reason: {item['reason']}")
    else:
        summary_lines.append("Failed Emails Details:\n  None (all emails processed successfully)")
    summary_lines.append("=" * 80)

    summary_text = "\n".join(summary_lines)
    print(summary_text, flush=True)
    logger.info("Pipeline completed. Fetched %d, skipped %d, newly processed %d, failed %d.", total_emails, skipped_count, newly_processed_count, len(failed_items))

    return processed_items


def main():
    parser = argparse.ArgumentParser(description="ThreatLens end-to-end pipeline orchestrator.")
    parser.add_argument("--limit", type=int, default=50, help="Max emails to fetch and process (default: 50, 0 = no limit)")
    parser.add_argument("--folders", type=str, default="inbox,spam", help="Comma-separated IMAP folders to scan: inbox, spam, all (default: inbox,spam)")
    parser.add_argument("--force", action="store_true", help="Force reprocessing of emails already present in data/dashboard")
    parser.add_argument("--fast", action="store_true", default=None, help="Enable fast reputation mode (Safe Browsing on all, VirusTotal capped at 3 suspicious unflagged links)")
    parser.add_argument("--full", action="store_true", default=False, help="Force full reputation mode (check all links on VirusTotal)")
    parser.add_argument("--source", choices=["imap", "gmail", "file"], default="imap", help="Email source (default: imap)")
    parser.add_argument("--file", type=str, help="File path if source is file")
    parser.add_argument("--since", type=str, help="Fetch emails since date")
    parser.add_argument("--data-dir", default="./data", help="Root data directory (default: ./data)")
    args = parser.parse_args()

    run_pipeline(
        source=args.source,
        limit=args.limit,
        since=args.since,
        file_path=args.file,
        data_dir=args.data_dir,
        folders=args.folders,
        force=args.force,
        fast=args.fast,
        full=args.full,
    )


if __name__ == "__main__":
    main()
