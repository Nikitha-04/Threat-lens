import os
import pytest
from datetime import datetime, timezone, timedelta
from geo.anomaly_detection import check_impossible_travel
from geo.sender_history import Database
from geolocate import process_email

class MockMaxMind:
    def __init__(self):
        self.reader = True # just to pass the `if not self.reader` check if needed
    def lookup(self, ip):
        if ip == "1.1.1.1":
            return {"country": "US", "city": "New York", "lat": 40.7128, "long": -74.0060, "asn": "123", "isp": "Test ISP"}
        elif ip == "2.2.2.2":
            return {"country": "GB", "city": "London", "lat": 51.5074, "long": -0.1278, "asn": "456", "isp": "UK ISP"}
        return None
    def close(self):
        pass

@pytest.fixture
def test_db(tmpdir):
    db_path = os.path.join(tmpdir, "test.db")
    db = Database(db_path)
    yield db
    
def test_impossible_travel():
    lat1, lon1 = 40.7128, -74.0060 # NYC
    lat2, lon2 = 51.5074, -0.1278  # London
    
    t1 = datetime.now(timezone.utc)
    t2 = t1 + timedelta(hours=2) # 2 hours diff for 5500km -> impossible
    
    flagged, reason, speed = check_impossible_travel(lat2, lon2, t2, lat1, lon1, t1)
    assert flagged is True
    assert speed > 2000
    
    t3 = t1 + timedelta(hours=10) # 10 hours diff -> plausible
    flagged, reason, speed = check_impossible_travel(lat2, lon2, t3, lat1, lon1, t1)
    assert flagged is False
    assert speed < 900
    
def test_process_email_no_history(test_db):
    maxmind = MockMaxMind()
    data = {
        "message_id": "msg1",
        "originating_ip": "1.1.1.1",
        "sender_email": "alice@example.com",
        "date": datetime.now(timezone.utc).isoformat()
    }
    
    res = process_email(data, test_db, maxmind)
    assert res["geolocation"]["city"] == "New York"
    assert res["sender_location_history_count"] == 0
    assert res["anomaly"]["flagged"] is False
    
def test_process_email_impossible_travel(test_db):
    maxmind = MockMaxMind()
    
    t1 = datetime.now(timezone.utc) - timedelta(hours=2)
    data1 = {
        "message_id": "msg1",
        "originating_ip": "1.1.1.1",
        "sender_email": "bob@example.com",
        "date": t1.isoformat()
    }
    
    process_email(data1, test_db, maxmind)
    
    data2 = {
        "message_id": "msg2",
        "originating_ip": "2.2.2.2",
        "sender_email": "bob@example.com",
        "date": datetime.now(timezone.utc).isoformat()
    }
    
    res = process_email(data2, test_db, maxmind)
    assert res["sender_location_history_count"] == 1
    assert res["anomaly"]["flagged"] is True
    assert "exceeds threshold" in res["anomaly"]["reason"]
    
def test_process_email_null_ip(test_db):
    maxmind = MockMaxMind()
    data = {
        "message_id": "msg1",
        "originating_ip": None,
        "sender_email": "carol@example.com",
        "date": datetime.now(timezone.utc).isoformat()
    }
    
    res = process_email(data, test_db, maxmind)
    assert res["geolocation"] is None
    assert res["anomaly"]["flagged"] is False

def test_missing_db_graceful():
    from geo.maxmind_client import MaxMindClient
    client = MaxMindClient("./does_not_exist.mmdb")
    assert client.reader is None
    assert client.lookup("1.1.1.1") is None
