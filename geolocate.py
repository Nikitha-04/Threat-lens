import argparse
import json
import os
import glob
from datetime import datetime, timezone
from dateutil import parser as date_parser
from dotenv import load_dotenv

from geo.maxmind_client import MaxMindClient
from geo.sender_history import Database
from geo.anomaly_detection import check_impossible_travel

def parse_date(date_str):
    if not date_str:
        return datetime.now(timezone.utc)
    try:
        dt = date_parser.parse(date_str)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)

def process_email(data, db, maxmind):
    message_id = data.get("message_id", "unknown")
    originating_ip = data.get("originating_ip")
    
    sender_email = data.get("sender_email")
    if not sender_email and "from" in data and isinstance(data["from"], dict):
        sender_email = data["from"].get("email")
    if not sender_email:
        sender_email = "unknown_sender"
        
    date_str = data.get("date")
    seen_at = parse_date(date_str)
    
    history_count = db.get_history_count(sender_email)
    
    if not originating_ip:
        return {
            "message_id": message_id,
            "originating_ip": None,
            "geolocation": None,
            "sender_location_history_count": history_count,
            "anomaly": {
                "flagged": False,
                "reason": None,
                "previous_location": None,
                "implied_speed_kmh": None
            }
        }

    geo_data = maxmind.lookup(originating_ip)
    
    if not geo_data:
        return {
            "message_id": message_id,
            "originating_ip": originating_ip,
            "geolocation": None,
            "sender_location_history_count": history_count,
            "anomaly": {
                "flagged": False,
                "reason": "Geolocation lookup failed",
                "previous_location": None,
                "implied_speed_kmh": None
            }
        }

    prev_loc = db.get_latest_location(sender_email)
    
    flagged = False
    reason = None
    implied_speed = None
    prev_loc_dict = None
    
    if prev_loc:
        prev_seen = prev_loc.seen_at
        if not prev_seen.tzinfo:
            prev_seen = prev_seen.replace(tzinfo=timezone.utc)
            
        flagged, reason, implied_speed = check_impossible_travel(
            new_lat=geo_data["lat"],
            new_long=geo_data["long"],
            new_time=seen_at,
            prev_lat=prev_loc.lat,
            prev_long=prev_loc.long,
            prev_time=prev_seen
        )
        
        prev_loc_dict = {
            "country": prev_loc.country,
            "city": prev_loc.city,
            "seen_at": prev_seen.isoformat()
        }

    db.add_history(
        sender_email=sender_email,
        ip=originating_ip,
        country=geo_data["country"],
        city=geo_data["city"],
        lat=geo_data["lat"],
        long=geo_data["long"],
        seen_at=seen_at.replace(tzinfo=None), # SQLite DateTime doesn't store timezone well in base setup
        message_id=message_id
    )
    
    return {
        "message_id": message_id,
        "originating_ip": originating_ip,
        "geolocation": geo_data,
        "sender_location_history_count": history_count,
        "anomaly": {
            "flagged": flagged,
            "reason": reason,
            "previous_location": prev_loc_dict,
            "implied_speed_kmh": implied_speed
        }
    }

class MockMaxMind:
    def __init__(self):
        self.reader = True
    def lookup(self, ip):
        if ip == "1.1.1.1":
            return {"country": "US", "city": "New York", "lat": 40.7128, "long": -74.0060, "asn": "123", "isp": "Test ISP"}
        elif ip == "2.2.2.2":
            return {"country": "GB", "city": "London", "lat": 51.5074, "long": -0.1278, "asn": "456", "isp": "UK ISP"}
        return None
    def close(self):
        pass

def main():
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="Geolocate originating IPs and flag impossible travel.")
    parser.add_argument("--input-dir", required=True, help="Directory containing forensics JSON files")
    parser.add_argument("--output-dir", required=True, help="Directory to save geo JSON files")
    
    args = parser.parse_args()
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    db = Database()
    maxmind = MaxMindClient()
    if not maxmind.reader:
        print("Using mock MaxMind for demonstration since DB is missing.")
        maxmind = MockMaxMind()
    
    input_files = sorted(glob.glob(os.path.join(args.input_dir, "*.json")))
    
    for filepath in input_files:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        result = process_email(data, db, maxmind)
        
        filename = os.path.basename(filepath)
        out_path = os.path.join(args.output_dir, filename)
        
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2)
            
        print(f"Processed {filename}: Anomaly Flagged = {result['anomaly']['flagged']}")
        
    maxmind.close()

if __name__ == "__main__":
    main()
