"""
risk/aggregator.py — reads per-module JSON files and builds the combined risk output.
"""
from __future__ import annotations
import glob
import json
import logging
import os

logger = logging.getLogger(__name__)


def _load(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("Could not parse %s: %s", path, exc)
        return None


def collect_message_ids(
    forensics_dir: str,
    geo_dir: str,
    classified_dir: str,
    reputation_dir: str,
) -> set[str]:
    """Union of all message_ids found across every input directory."""
    ids: set[str] = set()
    for d in (forensics_dir, geo_dir, classified_dir, reputation_dir):
        for f in glob.glob(os.path.join(d, "*.json")):
            ids.add(os.path.splitext(os.path.basename(f))[0])
    return ids


def load_all(
    message_id: str,
    forensics_dir: str,
    geo_dir: str,
    classified_dir: str,
    reputation_dir: str,
) -> tuple[dict | None, dict | None, dict | None, dict | None, dict]:
    """
    Returns (forensics, geo, classified, reputation, completeness).
    completeness is a dict of {module: bool} indicating whether data was available.
    """
    forensics = _load(os.path.join(forensics_dir, f"{message_id}.json"))
    geo = _load(os.path.join(geo_dir, f"{message_id}.json"))
    classified = _load(os.path.join(classified_dir, f"{message_id}.json"))
    reputation = _load(os.path.join(reputation_dir, f"{message_id}.json"))

    completeness = {
        "forensics": forensics is not None,
        "geolocation": geo is not None,
        "classification": classified is not None,
        "reputation": reputation is not None,
    }
    return forensics, geo, classified, reputation, completeness
