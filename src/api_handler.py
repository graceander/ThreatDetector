import os
import requests
from dotenv import load_dotenv

load_dotenv()

class AbuseIPDBHandler:
    def __init__(self):
        self.api_key = os.getenv('ABUSEIPDB_API_KEY')
        self.base_url = 'https://api.abuseipdb.com/api/v2'

    def check_ip(self, ip_address):
        url = f"{self.base_url}/check"
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()  # Raises an HTTPError for bad responses
            return response.json()
        except requests.RequestException as e:
            print(f"Error checking IP {ip_address}: {e}")
            return {'error': str(e)}

    def get_blacklist(self, limit=100, confidence_minimum=90):
        url = f"{self.base_url}/blacklist"
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        params = {
            'limit': limit,
            'confidenceMinimum': confidence_minimum
        }
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error fetching blacklist: {e}")
            return {'error': str(e)}

# Usage example
if __name__ == "__main__":
    handler = AbuseIPDBHandler()
    blacklist = handler.get_blacklist(limit=10)
    print(blacklist)
    