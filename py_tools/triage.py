# triage.py
# A script to simulate SOC alert triage by scoring and prioritizing alerts from a JSON file.

import json

def load_alerts(filename="sample_alerts.json"):
    """Loads alerts from a JSON file."""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        print("Please create a 'sample_alerts.json' file.")
        return []
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from '{filename}'.")
        return []

def score_alert(alert):
    """Applies a simple scoring logic to an alert."""
    score = 0
    
    # Rule-based scoring
    # High-severity signatures get a high score
    if "Malware" in alert.get('signature', ''):
        score += 50
    if "SCAN" in alert.get('signature', ''):
        score += 10
    if "Brute Force" in alert.get('signature', ''):
        score += 30
        
    # Source-based scoring
    # Alerts from critical assets could have a higher score
    if alert.get('source_ip', '').startswith('10.0.1.'):
        score += 20 # Assume 10.0.1.0/24 is a critical server subnet
        
    # Honeypot alerts are always interesting
    if alert.get('source_tool') == 'cowrie':
        score += 40
        
    alert['risk_score'] = score
    return alert

def triage_alerts(alerts):
    """Scores and sorts a list of alerts by risk score."""
    scored_alerts = [score_alert(alert) for alert in alerts]
    
    # Sort alerts in descending order based on the new risk_score
    sorted_alerts = sorted(scored_alerts, key=lambda x: x['risk_score'], reverse=True)
    
    return sorted_alerts

def print_triaged_alerts(sorted_alerts):
    """Prints the sorted alerts in a readable format."""
    print("--- Triaged Security Alerts ---")
    print("Priority | Score | Source IP       | Signature")
    print("---------------------------------------------------------")
    for alert in sorted_alerts:
        priority = "HIGH" if alert['risk_score'] >= 50 else "MEDIUM" if alert['risk_score'] >= 30 else "LOW"
        # Using .get() provides a default value if a key is missing
        print(f"{priority:<9}| {alert.get('risk_score'):<6}| {alert.get('source_ip', 'N/A'):<15} | {alert.get('signature', 'N/A')}")


# --- Main Execution ---
if __name__ == "__main__":
    # 1. Load alerts from the file
    alerts = load_alerts()
    
    if alerts:
        # 2. Triage the alerts
        triaged_list = triage_alerts(alerts)
        
        # 3. Print the prioritized list
        print_triaged_alerts(triaged_list)


