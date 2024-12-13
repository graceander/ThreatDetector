import unittest
from unittest.mock import Mock, patch
import sys
import os
from pathlib import Path
from typing import List, Dict, Optional

project_root = str(Path(__file__).parent.parent)
sys.path.append(project_root)

from src.threat_analyzer import ThreatAnalyzer, ThreatType, RiskLevel
from src.ip_collector import IPCollector
from src.api_handler import AbuseIPDBHandler

class TestThreatAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = ThreatAnalyzer()
        
    def create_mock_ip_data(
        self,
        ip_address: str = "192.0.2.1",
        confidence_score: int = 90,
        total_reports: int = 1000,
        categories: List[int] = None
    ) -> Dict:
        """Helper method to create mock IP data"""
        # Ensure categories is always a list
        if categories is None:
            categories = [3, 4, 5]

        return {
            "data": {
                "ipAddress": ip_address,
                "abuseConfidenceScore": confidence_score,
                "totalReports": total_reports,
                "reports": [
                    {
                        "categories": categories,
                        "reporterId": 1,
                        "comment": "Test report",
                        "reportedAt": "2024-12-13T04:16:46+00:00"
                    }
                ],
                "countryCode": "US",
                "usageType": "Data Center",
                "isp": "Example ISP",
                "lastReportedAt": "2024-12-13T04:16:46+00:00"
            }
        }

    def test_determine_risk_level(self):
        """Test risk level determination"""
        test_cases = [
            (95, 1500, RiskLevel.SEVERE),
            (80, 800, RiskLevel.HIGH),
            (60, 200, RiskLevel.MEDIUM),
            (30, 50, RiskLevel.LOW),
        ]
        
        for confidence, attacks, expected in test_cases:
            with self.subTest(confidence=confidence, attacks=attacks):
                risk_level = self.analyzer._determine_risk_level(confidence, attacks)
                self.assertEqual(risk_level, expected)

    def test_determine_threat_type(self):
        test_cases = [
            ([7], ThreatType.PHISHING),                    # Pure phishing
            ([5, 18, 11], ThreatType.PASSWORD_ATTACK),     # Multiple password attack indicators
            ([8, 19, 21], ThreatType.SQL_INJECTION),       # SQL injection
            ([13, 20, 3], ThreatType.MALWARE),            # Malware variants
            ([14], ThreatType.CRYPTOJACKING),             # Port scan/cryptojacking
            ([9, 22], ThreatType.SSH_ABUSE),              # SSH abuse
            ([15], ThreatType.INSIDER_THREAT),            # Hacking/Insider threat
            ([1, 4, 6], ThreatType.DENIAL_OF_SERVICE),    # DoS variants
            ([], ThreatType.UNKNOWN),                     # Empty categories
            ([999], ThreatType.UNKNOWN),                  # Unknown category
        ]
        
        for categories, expected in test_cases:
            with self.subTest(categories=categories):
                threat_type = self.analyzer._determine_threat_type(categories)
                self.assertEqual(
                    threat_type,
                    expected,
                    f"Expected {expected} for categories={categories}, got {threat_type}"
                )
            
    def test_analyze_ip(self):
        """Test complete IP analysis with updated mock data"""
        # Test case for malware detection
        malware_data = self.create_mock_ip_data(
            ip_address="192.0.2.1",
            confidence_score=95,
            total_reports=1500,
            categories=[13, 20, 3]  # Multiple malware indicators
        )
    
        result = self.analyzer.analyze_ip(malware_data)
    
        self.assertEqual(result.ip_address, "192.0.2.1")
        self.assertEqual(result.threat_type, ThreatType.MALWARE)
        self.assertEqual(result.risk_level, RiskLevel.SEVERE)
        self.assertEqual(result.confidence_score, 95)
        self.assertEqual(result.attack_count, 1500)

class TestIPCollector(unittest.TestCase):
    def setUp(self):
        self.collector = IPCollector()

    @patch('src.api_handler.AbuseIPDBHandler')
    def test_collect_from_abuseipdb(self, mock_handler_class):
        """Test IP collection with proper mocking"""
        # Create a mock handler instance
        mock_handler = Mock()
        mock_handler_class.return_value = mock_handler
        
        # Set up the mock response
        mock_handler.get_blacklist.return_value = {
            "data": [
                {"ipAddress": "192.0.2.1"},
                {"ipAddress": "192.0.2.2"}
            ]
        }
        
        # Create collector with mock handler
        collector = IPCollector()
        collector.api_handler = mock_handler
        
        # Test collection
        collector.collect_from_abuseipdb(limit=2)
        collected_ips = collector.get_collected_ips()
        
        self.assertEqual(collected_ips, ["192.0.2.1", "192.0.2.2"])
        mock_handler.get_blacklist.assert_called_once_with(2, 90)

if __name__ == '__main__':
    unittest.main(verbosity=2)
