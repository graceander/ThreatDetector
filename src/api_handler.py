import os
import requests
from typing import Dict, Optional

class AbuseIPDBHandler:
    def __init__(self):
        self.api_key = os.getenv('ABUSEIPDB_API_KEY')
        self.base_url = 'https://api.abuseipdb.com/api/v2'

    def get_blacklist(self, limit: int = 100, confidence_minimum: int = 90) -> Dict:
        """
        Get blacklisted IP addresses from AbuseIPDB.
        
        Args:
            limit: Maximum number of IPs to retrieve (1-10000)
            confidence_minimum: Minimum confidence score (1-100)
        """
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

    def check_ip(self, ip_address: str, max_age_in_days: int = 30, verbose: bool = True) -> Dict:
        """
        Check details for a single IP address.
        
        Args:
            ip_address: The IP address to check
            max_age_in_days: How far back to check for reports
            verbose: Whether to include detailed report information
        """
        url = f"{self.base_url}/check"
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': max_age_in_days,
            'verbose': verbose
        }
        
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()  # Raises an HTTPError for bad responses
            return response.json()
        except requests.RequestException as e:
            print(f"Error checking IP {ip_address}: {e}")
            return {'error': str(e)}

    def report_ip(self, ip_address: str, categories: list, comment: str) -> Dict:
        """
        Report an abusive IP address.
        
        Args:
            ip_address: The IP address to report
            categories: List of category IDs
            comment: Comment about the abuse
        """
        url = f"{self.base_url}/report"
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        params = {
            'ip': ip_address,
            'categories': ','.join(map(str, categories)),
            'comment': comment
        }
        
        try:
            response = requests.post(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error reporting IP {ip_address}: {e}")
            return {'error': str(e)}

    def bulk_check(self, ip_addresses: list) -> Dict:
        """
        Check multiple IP addresses in one request.
        
        Args:
            ip_addresses: List of IP addresses to check
        """
        url = f"{self.base_url}/check-block"
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        data = {
            'ipAddress': ','.join(ip_addresses)
        }
        
        try:
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error performing bulk check: {e}")
            return {'error': str(e)}
    