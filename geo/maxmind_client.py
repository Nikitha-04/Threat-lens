import os
import geoip2.database
from geoip2.errors import AddressNotFoundError

class MaxMindClient:
    def __init__(self, db_path=None):
        self.db_path = db_path or os.environ.get("MAXMIND_DB_PATH", "./data/GeoLite2-City.mmdb")
        
        if not os.path.exists(self.db_path):
            print(f"Error: GeoLite2 database not found at {self.db_path}.")
            print("Please sign up at maxmind.com, get a license key, and download the GeoLite2-City.mmdb file.")
            print("Set MAXMIND_LICENSE_KEY and MAXMIND_DB_PATH in your .env file.")
            self.reader = None
        else:
            self.reader = geoip2.database.Reader(self.db_path)
            
    def lookup(self, ip_address):
        if not self.reader:
            return None
            
        try:
            response = self.reader.city(ip_address)
            
            # ASN and ISP are generally in the ASN database, but sometimes
            # traits are populated depending on the exact DB used.
            asn = getattr(response.traits, 'autonomous_system_number', None)
            isp = getattr(response.traits, 'isp', getattr(response.traits, 'autonomous_system_organization', None))
            
            return {
                "country": response.country.iso_code or response.country.name,
                "city": response.city.name,
                "lat": response.location.latitude,
                "long": response.location.longitude,
                "asn": str(asn) if asn else None,
                "isp": str(isp) if isp else None
            }
        except AddressNotFoundError:
            return None
        except Exception as e:
            print(f"GeoIP Lookup Error for {ip_address}: {e}")
            return None

    def close(self):
        if self.reader:
            self.reader.close()
