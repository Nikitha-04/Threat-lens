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

`ash
python geolocate.py --input-dir ./data/forensics --output-dir ./data/geo
`
