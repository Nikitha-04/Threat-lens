"""
risk/scoring.py — weighted risk score calculation.
All component scores are 0-100 before weighting.
"""
from __future__ import annotations
import json
import os


DEFAULT_WEIGHTS_PATH = os.path.join(os.path.dirname(__file__), "..", "risk_weights.json")

_WEIGHTS: dict | None = None


def load_weights(path: str = DEFAULT_WEIGHTS_PATH) -> dict:
    global _WEIGHTS
    if _WEIGHTS is not None:
        return _WEIGHTS
    if os.path.exists(path):
        with open(path, "r") as f:
            _WEIGHTS = json.load(f)
    else:
        _WEIGHTS = {
            "auth_weight": 0.20,
            "geo_weight": 0.20,
            "nlp_weight": 0.30,
            "reputation_weight": 0.30,
            "thresholds": {"low_max": 29, "medium_max": 59, "high_max": 84},
        }
    return _WEIGHTS


def risk_tier(score: float, weights: dict) -> str:
    t = weights.get("thresholds", {})
    if score <= t.get("low_max", 29):
        return "low"
    if score <= t.get("medium_max", 59):
        return "medium"
    if score <= t.get("high_max", 84):
        return "high"
    return "critical"


# ─── Component scorers (each returns 0-100 and list of factor strings) ────────

def score_auth(forensics: dict | None) -> tuple[float, list[str]]:
    """Score email authentication (SPF/DKIM/DMARC). Returns (0-100, factors)."""
    if not forensics:
        return 0.0, []

    factors: list[str] = []
    raw = 0.0

    spf = str(forensics.get("spf", "")).lower()
    dkim = str(forensics.get("dkim", "")).lower()
    dmarc = str(forensics.get("dmarc", "")).lower()
    alignment = forensics.get("alignment", {}) or {}
    red_flags = forensics.get("red_flags", []) or []

    # SPF
    if spf in ("fail", "softfail", "none", "permerror", "temperror"):
        raw += 35
        factors.append(f"SPF {spf.upper()}")
    elif spf == "pass":
        pass
    else:
        raw += 10
        factors.append(f"SPF result unknown ({spf})")

    # DKIM
    if dkim in ("fail", "none", "permerror", "temperror"):
        raw += 35
        factors.append(f"DKIM {dkim.upper()}")
    elif dkim == "pass":
        pass
    else:
        raw += 10
        factors.append(f"DKIM result unknown ({dkim})")

    # DMARC
    if dmarc in ("fail", "none"):
        raw += 20
        policy = forensics.get("dmarc_policy", "none")
        factors.append(f"DMARC {dmarc.upper()} (policy: {policy})")
    elif dmarc == "pass":
        pass
    else:
        raw += 5

    # Alignment failures
    spf_aligned = alignment.get("spf_aligned", True)
    dkim_aligned = alignment.get("dkim_aligned", True)
    if not spf_aligned:
        raw += 5
        factors.append("SPF domain misalignment")
    if not dkim_aligned:
        raw += 5
        factors.append("DKIM domain misalignment")

    # Header red flags
    for flag in red_flags:
        raw += 5
        factors.append(f"Header red flag: {flag}")

    return min(raw, 100.0), factors


def score_geo(geo: dict | None) -> tuple[float, list[str]]:
    """Score geolocation anomaly. Returns (0-100, factors)."""
    if not geo:
        return 0.0, []

    factors: list[str] = []
    anomaly = geo.get("anomaly") or {}
    if anomaly.get("flagged"):
        reason = anomaly.get("reason", "Impossible travel detected")
        speed = anomaly.get("implied_speed_kmh")
        speed_str = f" ({speed:.0f} km/h)" if speed else ""
        factors.append(f"Geolocation anomaly: {reason}{speed_str}")
        return 100.0, factors
    return 0.0, factors


def score_nlp(classified: dict | None) -> tuple[float, list[str]]:
    """Score NLP phishing probability. Returns (0-100, factors)."""
    if not classified:
        return 0.0, []

    prob = classified.get("phishing_probability", 0.0) or 0.0
    score = float(prob) * 100.0
    factors: list[str] = []
    if prob >= 0.5:
        pct = int(prob * 100)
        terms = classified.get("top_indicative_terms", [])
        term_str = f" (terms: {', '.join(terms[:3])})" if terms else ""
        factors.append(f"NLP phishing probability {pct}%{term_str}")
    return score, factors


def score_reputation(reputation: dict | None) -> tuple[float, list[str]]:
    """Score URL/attachment reputation. Returns (0-100, factors)."""
    if not reputation:
        return 0.0, []

    factors: list[str] = []
    raw = 0.0

    for uc in reputation.get("url_checks", []) or []:
        url = uc.get("url", "")
        if uc.get("safe_browsing_flagged"):
            threats = ", ".join(uc.get("safe_browsing_threat_types", []))
            factors.append(f"URL flagged by Safe Browsing ({threats}): {url}")
            raw += 60
        mal = uc.get("virustotal_malicious_count") or 0
        total = uc.get("virustotal_total_vendors") or 1
        if mal >= 3:
            factors.append(f"URL flagged malicious by VirusTotal ({mal}/{total} vendors): {url}")
            raw += 50
        elif mal >= 1:
            factors.append(f"URL suspicious on VirusTotal ({mal}/{total} vendors): {url}")
            raw += 25

    for ac in reputation.get("attachment_checks", []) or []:
        mal = ac.get("virustotal_malicious_count") or 0
        total = ac.get("virustotal_total_vendors") or 1
        filename = ac.get("filename", "")
        if mal >= 3:
            factors.append(f"Attachment '{filename}' flagged malicious ({mal}/{total} vendors)")
            raw += 70
        elif mal >= 1:
            factors.append(f"Attachment '{filename}' suspicious ({mal}/{total} vendors)")
            raw += 35

    return min(raw, 100.0), factors


# ─── Main scorer ──────────────────────────────────────────────────────────────

def compute_risk(
    forensics: dict | None,
    geo: dict | None,
    classified: dict | None,
    reputation: dict | None,
    weights_path: str = DEFAULT_WEIGHTS_PATH,
) -> dict:
    weights = load_weights(weights_path)

    auth_score, auth_factors = score_auth(forensics)
    geo_score, geo_factors = score_geo(geo)
    nlp_score, nlp_factors = score_nlp(classified)
    rep_score, rep_factors = score_reputation(reputation)

    final = (
        auth_score * weights["auth_weight"]
        + geo_score * weights["geo_weight"]
        + nlp_score * weights["nlp_weight"]
        + rep_score * weights["reputation_weight"]
    )
    final = round(min(max(final, 0.0), 100.0), 2)

    return {
        "risk_score": final,
        "risk_tier": risk_tier(final, weights),
        "contributing_factors": auth_factors + geo_factors + nlp_factors + rep_factors,
        "component_scores": {
            "auth_score": round(auth_score, 2),
            "geo_score": round(geo_score, 2),
            "nlp_score": round(nlp_score, 2),
            "reputation_score": round(rep_score, 2),
        },
    }
