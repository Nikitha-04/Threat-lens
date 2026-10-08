"""
run_pipeline.py — Master orchestrator for Email Threat Detection Platform.
Fetches real emails via IMAP/Gmail, runs every analytical module in sequence:
ingest -> forensics -> geo -> classify -> reputation -> risk_score -> dashboard
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
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


def ensure_directories(base_dir: str = "./data") -> dict[str, str]:
    """Ensure all required pipeline directories exist and return their paths."""
    dirs = {
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
) -> dict | None:
    """
    Execute all analytical stages for a single raw email with graceful error handling.
    Returns the combined dashboard-ready dictionary, or None if ingestion parsing fails.
    """
    # ── 1. Ingestion & Email Parsing ──────────────────────────────────────────
    try:
        parsed_data = parse_email(raw_bytes, attachments_dir=dirs["attachments"])
    except Exception as exc:
        logger.error("Failed to parse raw email: %s", exc)
        return None

    safe_id = sanitize_filename(parsed_data.get("message_id"))
    if not safe_id or safe_id == "unnamed":
        safe_id = hashlib.sha256(raw_bytes).hexdigest()

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
        reputation = reputation_process_email(parsed_data, rep_cache)
        rep_path = os.path.join(dirs["reputation"], f"{safe_id}.json")
        with open(rep_path, "w", encoding="utf-8") as f:
            json.dump(reputation, f, indent=2, ensure_ascii=False)
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

    risk_result = compute_risk(forensics, geo, classified, reputation)
    risk_result["message_id"] = safe_id
    risk_result["data_completeness"] = completeness

    # Append transparent notes for any module that failed
    for mod_name, present in completeness.items():
        if not present:
            risk_result["contributing_factors"].append(
                f"Best-effort assessment: {mod_name} module data unavailable"
            )

    risk_path = os.path.join(dirs["risk"], f"{safe_id}.json")
    with open(risk_path, "w", encoding="utf-8") as f:
        json.dump(risk_result, f, indent=2, ensure_ascii=False)

    tier = risk_result["risk_tier"]
    score = risk_result["risk_score"]
    logger.info("[%s] Risk Score: %.1f [%s]", safe_id, score, tier.upper())

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
                if not city_name or str(city_name).strip() == "":
                    city_name = str(g.get("country") or "Unknown")
                geolocation_data = {
                    "country": str(g["country"]),
                    "city": str(city_name),
                    "lat": float(g["lat"]),
                    "long": float(g["long"]),
                }
            except (ValueError, TypeError):
                geolocation_data = None

    dashboard_item = {
        "message_id": safe_id,
        "subject": parsed_data.get("subject", "") or "(No Subject)",
        "from": format_sender(parsed_data.get("from")),
        "date": to_iso_date(parsed_data.get("date")),
        "risk_score": float(risk_result["risk_score"]),
        "risk_tier": str(risk_result["risk_tier"]),
        "contributing_factors": list(risk_result["contributing_factors"]),
        "geolocation": geolocation_data,
    }

    dash_path = os.path.join(dirs["dashboard"], f"{safe_id}.json")
    with open(dash_path, "w", encoding="utf-8") as f:
        json.dump(dashboard_item, f, indent=2, ensure_ascii=False)

    return dashboard_item


def run_pipeline(
    source: str = "imap",
    limit: int = 20,
    since: str | None = None,
    file_path: str | None = None,
    data_dir: str = "./data",
) -> list[dict]:
    """
    Main pipeline entry point. Fetches emails from source and runs them through
    all threat detection stages, saving dashboard-ready JSONs.
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

    # Email generator selection
    if source == "imap":
        from parsers.imap_client import IMAPClient
        client = IMAPClient()
        email_generator = client.fetch_emails(limit=limit, since_date=since)
    elif source == "gmail":
        from parsers.gmail_client import GmailClient
        client = GmailClient()
        email_generator = client.fetch_emails(limit=limit, since_date=since)
    elif source == "file":
        if not file_path:
            raise ValueError("--file path is required when source is 'file'")
        def _file_gen():
            with open(file_path, "rb") as f:
                yield f.read()
        email_generator = _file_gen()
    else:
        raise ValueError(f"Unknown source: {source}")

    logger.info("Starting ThreatLens Pipeline (source=%s, limit=%d)", source, limit)
    processed_items = []
    count = 0

    for raw_bytes in email_generator:
        count += 1
        logger.info("==================== Processing Email #%d ====================", count)
        result = process_single_email(
            raw_bytes=raw_bytes,
            dirs=dirs,
            db=db,
            maxmind=maxmind,
            rep_cache=rep_cache,
            weights=weights,
            generate_pdfs=True,
        )
        if result:
            processed_items.append(result)

    if hasattr(maxmind, "close"):
        maxmind.close()

    logger.info("Pipeline completed. Processed %d email(s) into %s", len(processed_items), dirs["dashboard"])
    return processed_items


def main():
    parser = argparse.ArgumentParser(description="ThreatLens end-to-end pipeline orchestrator.")
    parser.add_argument("--limit", type=int, default=20, help="Max emails to fetch and process (default: 20)")
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
    )


if __name__ == "__main__":
    main()
