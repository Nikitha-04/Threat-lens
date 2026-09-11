import math
from datetime import datetime

def haversine_distance(lat1, lon1, lat2, lon2):
    R = 6371.0 # Earth radius in kilometers

    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)

    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad

    a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    distance = R * c
    return distance

def check_impossible_travel(new_lat, new_long, new_time: datetime, prev_lat, prev_long, prev_time: datetime, threshold_kmh=900):
    if any(x is None for x in [new_lat, new_long, new_time, prev_lat, prev_long, prev_time]):
        return False, None, None
        
    distance_km = haversine_distance(prev_lat, prev_long, new_lat, new_long)
    
    time_diff_hours = abs((new_time - prev_time).total_seconds()) / 3600.0
    
    if time_diff_hours <= 0:
        if distance_km > 0:
            return True, "Simultaneous events from different locations", float('inf')
        return False, None, 0.0
        
    speed_kmh = distance_km / time_diff_hours
    
    if speed_kmh > threshold_kmh:
        return True, f"Implied speed {speed_kmh:.2f} km/h exceeds threshold {threshold_kmh} km/h", speed_kmh
        
    return False, None, speed_kmh
