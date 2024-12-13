from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional

class ThreatType(Enum):
    MALWARE = "Malware"
    PHISHING = "Phishing"
    PASSWORD_ATTACK = "Password Attack"
    MAN_IN_THE_MIDDLE = "Man-in-the-Middle"
    SQL_INJECTION = "SQL Injection"
    DENIAL_OF_SERVICE = "Denial of Service"
    INSIDER_THREAT = "Insider Threat"
    CRYPTOJACKING = "Cryptojacking"
    SOCIAL_ENGINEERING = "Social Engineering"
    SSH_ABUSE = "SSH Abuse"
    UNKNOWN = "Unknown"

class RiskLevel(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    SEVERE = "Severe"

@dataclass
class ThreatInfo:
    ip_address: str
    threat_type: ThreatType
    risk_level: RiskLevel
    confidence_score: int
    description: str
    attack_count: int

class ThreatAnalyzer:
    def __init__(self):
        self.threat_mappings = {
            1: ThreatType.DENIAL_OF_SERVICE,  # DNS Compromise
            2: ThreatType.MALWARE,           # DNS Poisoning
            3: ThreatType.MALWARE,           # Fraud Orders
            4: ThreatType.DENIAL_OF_SERVICE, # DDoS
            5: ThreatType.PASSWORD_ATTACK,   # FTP Brute-Force
            6: ThreatType.DENIAL_OF_SERVICE, # Ping of Death
            7: ThreatType.PHISHING,          # Phishing
            8: ThreatType.SQL_INJECTION,     # SQL Injection
            9: ThreatType.SSH_ABUSE,         # SSH abuse
            10: ThreatType.SOCIAL_ENGINEERING,  # Email Spam
            11: ThreatType.PASSWORD_ATTACK,    # Bad Web Bot
            13: ThreatType.MALWARE,            # Malware
            14: ThreatType.CRYPTOJACKING,      # Port Scan
            15: ThreatType.INSIDER_THREAT,     # Hacking
            16: ThreatType.MAN_IN_THE_MIDDLE,  # Web Spam
            17: ThreatType.MALWARE,            # Email Spam
            18: ThreatType.PASSWORD_ATTACK,    # Brute-Force
            19: ThreatType.SQL_INJECTION,      # Bad Web Bot
            20: ThreatType.MALWARE,            # Exploited Host
            21: ThreatType.SQL_INJECTION,      # Web App Attack
            22: ThreatType.SSH_ABUSE,          # SSH
            23: ThreatType.INSIDER_THREAT      # IoT Targeted
        }

    def _determine_risk_level(self, confidence_score: int, attack_count: int) -> RiskLevel:
        """
        Determine risk level based on confidence score and number of reported attacks
        """
        if confidence_score >= 90 and attack_count >= 1000:
            return RiskLevel.SEVERE
        elif confidence_score >= 70 and attack_count >= 500:
            return RiskLevel.HIGH
        elif confidence_score >= 50 and attack_count >= 100:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _determine_threat_type(self, categories: List[int]) -> ThreatType:
        """
        Determine the primary threat type based on reported categories
        """
        if not categories:
            return ThreatType.UNKNOWN
        
        # Count occurrences of each threat type
        threat_type_counts = {}
        for category in categories:
            threat_type = self.threat_mappings.get(category, ThreatType.UNKNOWN)
            threat_type_counts[threat_type] = threat_type_counts.get(threat_type, 0) + 1
        
        # If we only found unknown threats, return UNKNOWN
        if len(threat_type_counts) == 1 and ThreatType.UNKNOWN in threat_type_counts:
            return ThreatType.UNKNOWN
            
        # Filter out UNKNOWN if we have other threat types
        if len(threat_type_counts) > 1 and ThreatType.UNKNOWN in threat_type_counts:
            del threat_type_counts[ThreatType.UNKNOWN]
            
        # Return the most common threat type
        return max(threat_type_counts.items(), key=lambda x: x[1])[0]

    def analyze_ip(self, ip_data: Dict) -> ThreatInfo:
        """
        Analyze IP data from AbuseIPDB and return threat information
        """
        data = ip_data.get('data', {})
        
        # Extract relevant information
        ip_address = data.get('ipAddress', '')
        confidence_score = data.get('abuseConfidenceScore', 0)
        total_reports = data.get('totalReports', 0)
        
        # Get all reports and their categories
        reports = data.get('reports', [])
        print(f"Number of reports found: {len(reports)}")
        
        all_categories = []
        for report in reports:
            if isinstance(report, dict):
                categories = report.get('categories', [])
                all_categories.extend(categories)
                print(f"Categories found in report: {categories}")
        
        print(f"All categories collected: {all_categories}")
        
        # Determine threat type and risk level
        threat_type = self._determine_threat_type(all_categories)
        print(f"Determined threat type: {threat_type}")
        risk_level = self._determine_risk_level(confidence_score, total_reports)
        
        # Create description
        description = f"IP Address {ip_address} has been reported {total_reports} times "
        description += f"with a confidence score of {confidence_score}%. "
        description += f"Primary threat type: {threat_type.value}"
        
        print(f"Final threat type: {threat_type.value}")

        return ThreatInfo(
            ip_address=ip_address,
            threat_type=threat_type,
            risk_level=risk_level,
            confidence_score=confidence_score,
            description=description,
            attack_count=total_reports
        )

    def analyze_multiple_ips(self, ip_collector: 'IPCollector') -> List[ThreatInfo]:
        """
        Analyze multiple IPs using the IPCollector
        """
        threat_infos = []
        for ip in ip_collector.get_collected_ips():
            ip_data = ip_collector.api_handler.check_ip(ip)
            threat_info = self.analyze_ip(ip_data)
            threat_infos.append(threat_info)
        return threat_infos

    def get_statistics(self, threat_infos: List[ThreatInfo]) -> Dict:
        """
        Generate statistics about analyzed threats
        """
        stats = {
            'total_threats': len(threat_infos),
            'risk_levels': {level.value: 0 for level in RiskLevel},
            'threat_types': {type.value: 0 for type in ThreatType},
            'average_confidence': 0,
            'highest_risk_ips': []
        }

        if not threat_infos:
            return stats

        # Calculate statistics
        total_confidence = 0
        for threat in threat_infos:
            stats['risk_levels'][threat.risk_level.value] += 1
            stats['threat_types'][threat.threat_type.value] += 1
            total_confidence += threat.confidence_score

            if threat.risk_level in [RiskLevel.HIGH, RiskLevel.SEVERE]:
                stats['highest_risk_ips'].append({
                    'ip': threat.ip_address,
                    'risk_level': threat.risk_level.value,
                    'confidence': threat.confidence_score
                })

        stats['average_confidence'] = total_confidence / len(threat_infos)
        stats['highest_risk_ips'].sort(key=lambda x: x['confidence'], reverse=True)

        return stats
    