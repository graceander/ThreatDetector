from src.api_handler import AbuseIPDBHandler

class IPCollector:
    def __init__(self):
        self.ip_addresses = []
        self.api_handler = AbuseIPDBHandler()

    def collect_from_abuseipdb(self, limit=100, confidence_minimum=90):
        """Collect IP addresses from AbuseIPDB blacklist."""
        blacklist_data = self.api_handler.get_blacklist(limit, confidence_minimum)
        if 'data' in blacklist_data:
            self.ip_addresses = [item['ipAddress'] for item in blacklist_data['data']]
        else:
            print("Error fetching blacklist from AbuseIPDB")

    def get_collected_ips(self):
        """Return the list of collected IP addresses."""
        return self.ip_addresses

# Usage example
if __name__ == "__main__":
    collector = IPCollector()
    collector.collect_from_abuseipdb(limit=10)
    print("Collected IPs:", collector.get_collected_ips())
    