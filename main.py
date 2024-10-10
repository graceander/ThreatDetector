from src.ip_collector import IPCollector
from src.api_handler import AbuseIPDBHandler

def main():
    collector = IPCollector()
    api_handler = AbuseIPDBHandler()

    # Collect IPs from AbuseIPDB blacklist
    collector.collect_from_abuseipdb(limit=100)
    
    print(f"Collected {len(collector.get_collected_ips())} IP addresses from AbuseIPDB blacklist.")

    # Check each IP with AbuseIPDB for detailed information
    for ip in collector.get_collected_ips():
        result = api_handler.check_ip(ip)
        print(f"IP: {ip}")
        
        # Safely print data fields
        data = result.get('data', {})
        print(f"Abuse Confidence Score: {data.get('abuseConfidenceScore', 'N/A')}%")
        print(f"Country: {data.get('countryCode', 'N/A')}")
        print(f"Total Reports: {data.get('totalReports', 'N/A')}")
        
        # Print all available fields for debugging
        print("All available data:")
        for key, value in data.items():
            print(f"  {key}: {value}")
        
        print("---")

if __name__ == "__main__":
    main()
    