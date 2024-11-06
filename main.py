from src.ip_collector import IPCollector
from src.api_handler import AbuseIPDBHandler
from src.threat_analyzer import ThreatAnalyzer

def print_ip_details(ip_data: dict):
    """Helper function to print IP details in a formatted way"""
    data = ip_data.get('data', {})
    print(f"IP: {data.get('ipAddress', 'N/A')}")
    print(f"Abuse Confidence Score: {data.get('abuseConfidenceScore', 'N/A')}%")
    print(f"Country: {data.get('countryCode', 'N/A')}")
    print(f"Total Reports: {data.get('totalReports', 'N/A')}")
    
    # Print detailed data fields
    print("Detailed Information:")
    for key, value in data.items():
        if key not in ['ipAddress', 'abuseConfidenceScore', 'countryCode', 'totalReports']:
            print(f"  {key}: {value}")

def print_threat_analysis(threat_info):
    """Helper function to print threat analysis results"""
    print("\nThreat Analysis:")
    print(f"Threat Type: {threat_info.threat_type.value}")
    print(f"Risk Level: {threat_info.risk_level.value}")
    print(f"Confidence Score: {threat_info.confidence_score}%")
    print(f"Description: {threat_info.description}")
    print(f"Attack Count: {threat_info.attack_count}")

def main():
    collector = IPCollector()
    api_handler = AbuseIPDBHandler()
    analyzer = ThreatAnalyzer()

    # Collect IPs from AbuseIPDB blacklist
    collector.collect_from_abuseipdb(limit=100)
    collected_ips = collector.get_collected_ips()
    print(f"\nCollected {len(collected_ips)} IP addresses from AbuseIPDB blacklist.")
    
    # Initialize lists to store results
    all_threat_infos = []
    
    # Check each IP and perform threat analysis
    print("\nAnalyzing IP addresses...")
    for ip in collected_ips:
        print("\n" + "="*50)
        
        # Get IP details from AbuseIPDB
        ip_data = api_handler.check_ip(ip)
        print_ip_details(ip_data)
        
        # Perform threat analysis
        threat_info = analyzer.analyze_ip(ip_data)
        print_threat_analysis(threat_info)
        all_threat_infos.append(threat_info)
        
        print("="*50)

    # Generate and display overall statistics
    stats = analyzer.get_statistics(all_threat_infos)
    
    print("\nOVERALL ANALYSIS SUMMARY")
    print("="*50)
    print(f"Total IPs Analyzed: {stats['total_threats']}")
    
    print("\nRisk Level Distribution:")
    for level, count in stats['risk_levels'].items():
        print(f"- {level}: {count}")
    
    print("\nThreat Type Distribution:")
    for threat_type, count in stats['threat_types'].items():
        if count > 0:
            print(f"- {threat_type}: {count}")
    
    print(f"\nAverage Confidence Score: {stats['average_confidence']:.2f}%")
    
    if stats['highest_risk_ips']:
        print("\nHighest Risk IPs (Top 5):")
        for ip_info in stats['highest_risk_ips'][:5]:
            print(f"- IP: {ip_info['ip']}")
            print(f"  Risk Level: {ip_info['risk_level']}")
            print(f"  Confidence: {ip_info['confidence']}%")

if __name__ == "__main__":
    main()
