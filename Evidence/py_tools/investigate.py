# investigate.py
# This script automates a basic investigation workflow by combining the triage and enrichment tools.

# We will import functions from our other scripts
from triage import load_alerts, triage_alerts
from enrich import load_api_keys, enrich_ip_abuseipdb, enrich_ip_virustotal

def generate_investigation_summary(top_alert, enrichment_data):
    """Generates a final summary and recommended action."""
    
    print("\n" + "="*50)
    print("=== Automated Investigation Summary ===")
    print("="*50)
    
    # --- Print Alert Details ---
    print("\n[+] High-Priority Alert Details:")
    print(f"  Timestamp: {top_alert.get('timestamp', 'N/A')}")
    print(f"  Signature: {top_alert.get('signature', 'N/A')}")
    print(f"  Source IP: {top_alert.get('source_ip', 'N/A')}")
    print(f"  Risk Score: {top_alert.get('risk_score', 'N/A')}")

    # --- Print Enrichment Data ---
    print("\n[+] IOC Enrichment Results:")
    abuse_data = enrichment_data.get('abuseipdb')
    vt_data = enrichment_data.get('virustotal')

    if abuse_data:
        print("  --- AbuseIPDB ---")
        print(f"    Abuse Score: {abuse_data.get('abuseConfidenceScore')}%")
        print(f"    Country: {abuse_data.get('countryCode')}")
        print(f"    ISP: {abuse_data.get('isp')}")
    
    if vt_data:
        vt_stats = vt_data.get('last_analysis_stats', {})
        print("  --- VirusTotal ---")
        print(f"    Malicious Detections: {vt_stats.get('malicious', 0)}")
        print(f"    Suspicious Detections: {vt_stats.get('suspicious', 0)}")
        
    # --- Make a Decision ---
    print("\n[+] Recommended Action:")
    decision = "Monitor" # Default decision
    
    # Simple logic for escalating
    is_malicious_vt = vt_data and vt_data.get('last_analysis_stats', {}).get('malicious', 0) > 0
    is_high_abuse_score = abuse_data and abuse_data.get('abuseConfidenceScore', 0) > 50
    
    if is_malicious_vt or is_high_abuse_score:
        decision = "High Priority - IMMEDIATE INVESTIGATION REQUIRED"
    elif top_alert.get('risk_score', 0) > 60:
        decision = "Medium Priority - Escalate to Tier 2 Analyst"
        
    print(f"  >> {decision} <<")
    print("="*50)


# --- Main Execution ---
if __name__ == "__main__":
    print("Starting automated investigation workflow...")
    
    # 1. Triage alerts to find the most critical one
    all_alerts = load_alerts()
    if not all_alerts:
        print("Workflow stopped: No alerts to process.")
    else:
        triaged_list = triage_alerts(all_alerts)
        top_alert = triaged_list[0] # Get the highest-scored alert
        
        print(f"\nIdentified top priority alert: '{top_alert.get('signature')}' with score {top_alert.get('risk_score')}")
        
        # 2. Extract the IOC for enrichment
        ioc_ip = top_alert.get('source_ip')
        if not ioc_ip:
            print("Workflow stopped: Top alert has no source_ip to investigate.")
        else:
            # 3. Enrich the IOC
            print(f"Enriching IOC: {ioc_ip}...")
            api_keys = load_api_keys()
            
            # We are calling the functions from enrich.py directly
            abuseipdb_results = enrich_ip_abuseipdb(api_keys.get('abuseipdb'), ioc_ip)
            virustotal_results = enrich_ip_virustotal(api_keys.get('virustotal'), ioc_ip)
            
            enrichment_bundle = {
                "abuseipdb": abuseipdb_results,
                "virustotal": virustotal_results
            }
            
            # 4. Generate the final report
            generate_investigation_summary(top_alert, enrichment_bundle)


