"""
FastAPI backend service for Email Threat Detection Dashboard (Module 7).
Serves risk-scored email alerts with geolocation and threat indicators.
"""
from __future__ import annotations

import glob
import json
import os
from enum import Enum
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field

app = FastAPI(
    title="Email Threat Detection Dashboard API",
    description="Backend API serving risk-scored email alerts for the security dashboard.",
    version="1.0.0",
)

# Enable CORS for local frontend development (Vite: 5173, CRA: 3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DASHBOARD_DATA_DIR = os.environ.get(
    "THREATLENS_DASHBOARD_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "dashboard"))
)


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Geolocation(BaseModel):
    country: str
    city: str
    lat: float
    long: float


class Alert(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    message_id: str
    subject: str
    from_address: str = Field(..., alias="from")
    date: str
    risk_score: float = Field(..., ge=0.0, le=100.0)
    risk_tier: RiskTier
    contributing_factors: List[str]
    geolocation: Optional[Geolocation] = None


def load_alerts(dashboard_dir: Optional[str] = None) -> List[dict]:
    """
    Load alerts from real pipeline outputs in ./data/dashboard/*.json.
    Gracefully returns empty list if directory is empty or missing.
    """
    target_dir = dashboard_dir or DASHBOARD_DATA_DIR
    if not os.path.exists(target_dir):
        return []

    alerts = []
    for filepath in sorted(glob.glob(os.path.join(target_dir, "*.json"))):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                alerts.append(json.load(f))
        except Exception:
            continue
    return alerts


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "email-threat-detector-api"}


@app.get("/api/alerts", response_model=List[Alert], response_model_by_alias=True)
def get_alerts(
    risk_tier: Optional[RiskTier] = Query(None, description="Filter by risk tier (low, medium, high, critical)"),
):
    """
    Returns a list of risk-scored emails sorted by risk_score descending.
    """
    raw_alerts = load_alerts()
    alerts = [Alert.model_validate(item) for item in raw_alerts]

    if risk_tier:
        alerts = [a for a in alerts if a.risk_tier == risk_tier]

    # Return sorted by risk_score descending
    alerts.sort(key=lambda a: a.risk_score, reverse=True)
    return alerts


@app.get("/api/alerts/{message_id}", response_model=Alert, response_model_by_alias=True)
def get_alert_by_id(message_id: str):
    """
    Returns full detail for one email by message_id.
    """
    raw_alerts = load_alerts()
    for item in raw_alerts:
        if item.get("message_id") == message_id:
            return Alert.model_validate(item)
    raise HTTPException(status_code=404, detail=f"Alert with message_id '{message_id}' not found")
