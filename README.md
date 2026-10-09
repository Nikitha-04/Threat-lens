# ThreatLens: AI-Powered Email Threat Detection Platform

ThreatLens is an end-to-end, multi-layered email threat detection, forensic analysis, and security intelligence platform. It ingests emails from real mailboxes (IMAP / Gmail OAuth2) or raw files, performs header authentication forensics, geolocates originating mail relays, predicts phishing probabilities using NLP machine learning models, verifies URL and attachment reputations, computes multi-factor risk scores, and surfaces real-time alerts on an interactive threat intelligence dashboard.

---

## 🌟 Key Features

- **Multi-Source Ingestion**: Ingests raw `.eml` files or live mailboxes via generic IMAP and Gmail API with automatic MIME parsing, attachment hashing, and link extraction.
- **Header Forensics & Authentication**: Evaluates SPF, DKIM, and DMARC verification, domain alignment, suspicious client hops, display name spoofing, and originating client IP extraction.
- **IP Geolocation & Anomaly Detection**: Geolocates public sender IPs using official MaxMind GeoLite2 databases and flags impossible travel anomalies (>900 km/h) based on sender history.
- **NLP Phishing Classification**: Machine learning classifier (TF-IDF + Logistic Regression) scoring phishing probability with keyword factor extraction.
- **Threat Intelligence & Reputation**: Queries Google Safe Browsing and VirusTotal APIs for malicious links and attachment hashes with 24-hour SQLite caching and built-in rate-limiting.
- **Weighted Multi-Factor Risk Scoring**: Computes a normalized risk score (0–100) and assigns actionable risk tiers (`low`, `medium`, `high`, `critical`). Generates automated forensic PDF reports for elevated threats.
- **End-to-End Orchestrator**: `run_pipeline.py` integrates all modules into a seamless pipeline that feeds live alerts into `./data/dashboard/`.
- **Interactive SOC Dashboard**: FastAPI backend serving real-time alerts and a React + TypeScript frontend featuring Leaflet world threat maps, risk filters, and deep-dive forensic inspection.

---

## 🏗️ Architecture & Data Flow

```
   ┌────────────────────────────────────────────────────────┐
   │                  Email Ingestion                       │
   │            (IMAP / Gmail OAuth / .eml)                 │
   └───────────────────────────┬────────────────────────────┘
                               │
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │                  Header Forensics                      │
   │          (SPF, DKIM, DMARC, Domain Align, IP)          │
   └───────────────┬────────────────────────┬───────────────┘
                   │                        │
                   ▼                        ▼
       ┌──────────────────────┐  ┌──────────────────────┐
       │   NLP Phishing ML    │  │    IP Geolocation    │
       │    Classification    │  │ & Impossible Travel  │
       └───────────┬──────────┘  └──────────┬───────────┘
                   │                        │
                   └───────────┬────────────┘
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │            Threat Reputation & Intelligence            │
   │       (Google Safe Browsing + VirusTotal APIs)         │
   └───────────────────────────┬────────────────────────────┘
                               │
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │               Risk Engine & PDF Generator              │
   │         (Weighted 0-100 Score + Risk Tiers)            │
   └───────────────────────────┬────────────────────────────┘
                               │
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │            Dashboard Output (./data/dashboard)         │
   └───────────────────────────┬────────────────────────────┘
                               │
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
       ┌───────────────────┐       ┌───────────────────┐
       │  FastAPI Backend  │ <───> │  React + Leaflet  │
       │  (/api/alerts)    │       │    SOC Dashboard  │
       └───────────────────┘       └───────────────────┘
```

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ and npm
- MaxMind GeoLite2 City database (placed at `data/geoip/GeoLite2-City.mmdb`)

### 2. Environment Configuration
Create a `.env` file in the project root:
```env
# IMAP Configuration (for live email fetch)
IMAP_HOST=imap.gmail.com
IMAP_USER=your_email@gmail.com
IMAP_PASSWORD=your_app_password

# Threat Intelligence API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key

# MaxMind Geolocation
MAXMIND_DB_PATH=./data/geoip/GeoLite2-City.mmdb
```

### 3. Install Python Dependencies
```bash
pip install -r requirements.txt
pip install -r backend/requirements.txt
```

---

## 🔍 Running on Real Data

ThreatLens includes a unified CLI orchestrator (`run_pipeline.py`) that fetches real emails, runs all analytical engines, and outputs production dashboard records.

### Fetch & Process Emails:
```bash
# Fetch and analyze 10 most recent emails from configured IMAP inbox:
python run_pipeline.py --limit 10

# Fetch 20 emails:
python run_pipeline.py --limit 20

# Run against a local .eml file:
python run_pipeline.py --source file --file path/to/sample.eml
```

### Expected Behavior & Rate Limits:
- **VirusTotal Rate Limits**: VirusTotal's public API enforces a strict rate limit of **4 requests/minute**. `run_pipeline.py` features an automatic token-bucket rate limiter that safely throttles outgoing requests without hitting `429 Too Many Requests`.
- **Database Caching**: Evaluated URLs and file hashes are cached for 24 hours in SQLite (`data/db/threat_platform.db`), speeding up recurring runs.
- **Accurate Benign Baseline**: Genuine personal emails (e.g., account notifications, newsletters) typically score `low` (`< 30`). This is expected and confirms correct baseline differentiation.

---

## 🖥️ Running the Web Dashboard

### 1. Start the FastAPI Backend
```bash
uvicorn backend.main:app --reload --port 8000
```
- API Endpoint: `http://localhost:8000/api/alerts`
- Swagger Docs: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/api/health`

### 2. Start the React Frontend
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser to view the interactive threat map, risk filters, and incident breakdown.

---

## 🧪 Testing

Execute test suites for core logic and backend endpoints:
```bash
# Run all unit and integration tests:
pytest -v

# Run backend API tests:
pytest backend/tests -v
```

---

## 📁 Repository Structure

```
Threat-lens/
├── run_pipeline.py          # Unified end-to-end orchestrator CLI
├── ingest.py                # Email ingestion module (IMAP/Gmail/EML)
├── forensics.py             # SPF/DKIM/DMARC and header analysis
├── geolocate.py             # MaxMind GeoLite2 & impossible travel engine
├── classify.py              # NLP phishing ML classifier (TF-IDF + LogReg)
├── reputation.py            # VirusTotal & Safe Browsing reputation module
├── risk_score.py            # Weighted risk scoring & PDF report generator
├── parsers/                 # MIME email and link extraction parsers
├── backend/                 # FastAPI REST API serving dashboard alerts
│   ├── main.py
│   └── tests/
├── frontend/                # React + Vite + Tailwind + Leaflet SOC UI
│   ├── src/components/      # ThreatMap, AlertFeed, ForensicsModal
├── data/
│   ├── dashboard/           # Final merged alert JSONs read by backend
│   ├── geoip/               # GeoLite2-City.mmdb database
│   ├── reports/             # Generated PDF threat forensic reports
│   └── db/                  # SQLite caching & travel database
└── tests/                   # Core platform test suite
```

---

## 🛡️ License
MIT License. Developed for enterprise email threat intelligence and SOC automation.
