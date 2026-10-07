# Email Ingestion Module

AI-powered email threat detection ingestion layer. Connects to email sources (Gmail OAuth2 or generic IMAP), fetches emails, and parses them into a clean JSON structure suitable for downstream modules (threat scoring, header forensics).

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure environment:
   Copy `.env.example` to `.env` and fill in your credentials.

### Gmail Authentication
1. Go to Google Cloud Console.
2. Enable the Gmail API.
3. Create OAuth 2.0 Client ID credentials (Desktop App).
4. Download the JSON and save it as `credentials.json` in the root directory.

## Usage

Run the ingestion CLI:

```bash
# Fetch from IMAP (10 latest emails)
python ingest.py --source imap --limit 10

# Fetch from Gmail (emails since a date)
python ingest.py --source gmail --limit 50 --since 2023/01/01

# Run against a local file (for testing)
python ingest.py --source file --file tests/sample.eml
```

## Output

Parsed emails are saved as JSON files in `data/parsed/`.
Attachments are saved in `data/attachments/<message_id>/`.

## Testing

Run the pytest suite:
```bash
pytest
```


# Geolocation & Anomaly Module (Task 3)

The third module in the AI-powered email threat detection platform. It processes originating IPs extracted during forensics, geolocates them via MaxMind GeoLite2, tracks sender locations in a local SQLite database, and flags impossible travel anomalies (default: >900 km/h).

## Setup & MaxMind DB Configuration

This module requires the MaxMind GeoLite2 City database.

1. Go to MaxMind and sign up for a free account.
2. Generate a License Key.
3. Download the GeoLite2-City.mmdb file and place it in ./data/.
4. Create or update your .env file (see .env.example) with:
   `env
   MAXMIND_LICENSE_KEY=your_key_here
   MAXMIND_DB_PATH=./data/GeoLite2-City.mmdb
   `

*(Note: If the DB is missing, the module gracefully falls back/mocks for demonstration, but production requires the real file).*

## Impossible Travel Anomaly Logic

The system uses the Haversine formula to compute the great-circle distance between a sender's newly observed location (lat/long) and their most recent historical location. It divides this distance by the time elapsed between the emails.

If the implied speed exceeds 900 km/h (faster than a commercial airliner), it raises a red flag in the nomaly.flagged field of the output JSON.

### Known Limitations
- **VPNs and Proxies**: If a sender uses a VPN with endpoints in different countries, it will trigger false positives for impossible travel.
- **Missing Origination IPs**: If an IP cannot be reliably extracted, geolocation is bypassed.

## Usage

```bash
python geolocate.py --input-dir ./data/forensics --output-dir ./data/geo
```

---

# Web Dashboard Module (Task 7)

Module 7 of the AI-powered email threat detection platform: an interactive threat analysis dashboard featuring a global Leaflet map of flagged sender geolocations and a real-time risk alert feed, backed by a FastAPI service.

## Architecture & Data Flow

- **Backend (`/backend`)**: FastAPI service exposing `/api/alerts` and `/api/alerts/{message_id}`, serving risk-scored emails conforming to the Task 6 schema with risk scores on a **0–100 scale**.
- **Frontend (`/frontend`)**: Vite + React application with interactive Leaflet map rendering color-coded pulsing markers, risk tier filter chips, descending risk feed, and a detailed threat forensics inspector.

```
┌────────────────────────┐         HTTP / JSON          ┌─────────────────────────┐
│     React Frontend     │ <──────────────────────────> │     FastAPI Backend     │
│  (Leaflet + AlertFeed) │   GET /api/alerts            │   (Port 8000 + CORS)    │
└────────────────────────┘   GET /api/alerts/{mid}      └───────────┬─────────────┘
                                                                    │
                                                  ┌─────────────────┴─────────────────┐
                                                  │ Current: backend/mock_data.json   │
                                                  │ Future:  data/risk/*.json pipeline│
                                                  └───────────────────────────────────┘
```

## Running the Servers

### 1. Start the FastAPI Backend

From the repository root:

```bash
# Activate virtual environment
.\.venv\Scripts\activate   # Windows
# or source .venv/bin/activate  # Linux/macOS

# Install backend dependencies
pip install -r backend/requirements.txt

# Run backend service
cd backend
uvicorn main:app --reload --port 8000
```

The API will be live at `http://localhost:8000`:
- Alerts list: `http://localhost:8000/api/alerts`
- Single alert: `http://localhost:8000/api/alerts/{message_id}`
- Interactive Swagger docs: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/api/health`

### 2. Start the React Frontend

In a separate terminal window:

```bash
cd frontend
npm install
npm run dev
```

The frontend dashboard will be live at `http://localhost:5173` (or the port Vite provides).

---

## Testing

### Backend Tests
Run the pytest test suite verifying status codes, schema validation, descending sort, tier filtering, and 404 handling:
```bash
# From repository root
pytest backend/tests -v
```

### Frontend Build Verification
Verify TypeScript compilation and Vite bundling:
```bash
cd frontend
npm run build
```

---

## How to Swap `mock_data.json` for Real API / Pipeline Integration

Currently, `backend/main.py` reads data through the `load_alerts()` function:

```python
def load_alerts() -> List[dict]:
    with open(MOCK_DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)
```

To wire this directly to the Task 6 risk pipeline or an upstream database/API service, replace `load_alerts()` with real data ingestion:

### Option A: Read Directly from Task 6 `data/risk/*.json` Files
```python
import glob

def load_alerts() -> List[dict]:
    alerts = []
    risk_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "risk"))
    for file_path in glob.glob(os.path.join(risk_dir, "*.json")):
        with open(file_path, "r", encoding="utf-8") as f:
            alerts.append(json.load(f))
    return alerts
```

### Option B: Call an Upstream REST API or Message Queue
```python
import httpx

def load_alerts() -> List[dict]:
    resp = httpx.get("https://internal-pipeline.company.com/api/v1/risk-scores", timeout=5.0)
    resp.raise_for_status()
    return resp.json()
```

Because the mock data exactly matches Task 6's JSON schema (with `risk_score` on the 0–100 scale, `contributing_factors`, `risk_tier`, `geolocation`), no frontend code changes are needed when switching to production data.

---

## Running on Real Data

ThreatLens includes a unified end-to-end orchestrator (`run_pipeline.py`) that connects to a real email account via IMAP/Gmail, analyzes each email across every security engine in sequence, and outputs unified dashboard alerts.

### 1. Configure Credentials
Ensure your `.env` file contains your IMAP or Gmail credentials:
```env
IMAP_HOST=imap.gmail.com
IMAP_USER=your_email@gmail.com
IMAP_PASSWORD=your_app_password
VIRUSTOTAL_API_KEY=your_vt_key
GOOGLE_SAFE_BROWSING_API_KEY=your_gsb_key
```

### 2. Run the Orchestrator
Fetch and process the latest real emails from your inbox:
```bash
# Fetch and analyze 10 most recent emails via IMAP
python run_pipeline.py --limit 10

# Fetch 20 emails
python run_pipeline.py --limit 20

# Run against a local raw email file
python run_pipeline.py --source file --file path/to/email.eml
```

### Pipeline Flow per Email
1. **Ingest (`ingest.py` / `parsers`)**: Parses headers, multipart bodies, extracts links & attachments.
2. **Forensics (`forensics.py`)**: Analyzes SPF, DKIM, DMARC authentication, domain alignment, red flags, and extracts client originating IP.
3. **Geolocation (`geolocate.py`)**: Geolocates originating IP with MaxMind and checks impossible travel anomalies.
4. **Classification (`classify.py`)**: Predicts phishing probability using the trained TF-IDF + Logistic Regression model.
5. **Reputation (`reputation.py`)**: Queries Google Safe Browsing and VirusTotal for URL/file reputation with SQLite caching.
6. **Risk Scoring (`risk_score.py`)**: Calculates weighted risk score (0-100), determines risk tier (`low`, `medium`, `high`, `critical`), and generates PDF forensic reports for medium+ risks.
7. **Dashboard Integration**: Generates final merged alert JSONs at `./data/dashboard/{message_id}.json`.

### Expected Runtime & Rate Limits
- **VirusTotal Rate Limits**: VirusTotal's public API enforces a strict rate limit of **4 requests per minute**.
- **Rate-Limiter Protection**: `run_pipeline.py` includes a thread-safe token-bucket rate limiter that automatically holds requests until a slot is available, preventing `429 Too Many Requests` errors.
- **SQLite Caching**: All checked URLs and file hashes are cached for 24 hours in SQLite (`data/db/threat_platform.db`). Subsequent runs on identical URLs/attachments execute almost instantaneously.
- **Runtime Estimate**: For 10 emails with new, unseen links, expect 1–3 minutes of execution depending on the number of unique URLs checked.

### What to Expect in Personal Inboxes
- **Most emails will score LOW**: Genuine personal inbox emails (e.g. notifications, account alerts, receipts, personal correspondence) have valid SPF/DKIM/DMARC signatures, clean domains, and low NLP phishing scores.
- **This is accurate behavior, not a bug**: A threat detection platform is designed to flag genuine anomalies and malicious indicators while keeping benign traffic in the green `low` risk tier.

---

## Known Limitations

1. **Proxy & Tor Geolocation**: Flagged senders originating from Tor exit nodes, anonymizing VPNs, or internal corporate mail relays have `geolocation: null`. The dashboard handles this gracefully by displaying an "Anonymized Proxy" badge in the feed and omitting them from the physical map.
2. **Local Mock Polling**: The current scaffold fetches alerts once on initial load, with an on-demand "Reload" button in the navigation header. In production, this can be upgraded to WebSocket streaming (`/ws/alerts`) or Server-Sent Events (SSE) for sub-second threat notifications.
3. **Map Tile Provider**: Default map tiles use CARTO Dark Matter via OpenStreetMap tiles. In isolated/air-gapped enterprise environments, a self-hosted tile server or offline vector tile source should be configured in `ThreatMap.tsx`.

