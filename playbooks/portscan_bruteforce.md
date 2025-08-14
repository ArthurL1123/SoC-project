Playbook: Port Scan Followed by Brute-Force Attempt
Document Version: 1.0
Last Updated: 2025-07-28
MITRE ATT&CK Tactic(s): Reconnaissance (T1046), Credential Access (T1110)

1. Preparation (Pre-Incident)
Tools: Access to SIEM (Kibana), network sensors (Suricata, Snort), honeypot logs (Cowrie), and IOC enrichment scripts.

Dashboards: The "Network Detection Overview" dashboard should be available and functioning.

Alerting: Rules should be configured to detect a high number of scan alerts or failed logins from a single source IP.

2. Identification & Triage
This phase begins when automated alerts fire for port scan activity or brute-force attempts.

2.1. Ingest Alert: Receive an automated alert from the SIEM (e.g., ">20 Suricata alerts from one IP in 5m").

2.2. Create Ticket: Log a new ticket in the incident tracking system.

2.3. Initial Triage (in Kibana):

Open the Network Detection Overview dashboard and filter by the source IP from the alert.

Correlate Activity: Look for a pattern. Do you see Suricata/Snort scan alerts, immediately followed by Cowrie cowrie.login.failed events from the same source IP?

Decision: If the activity is isolated and stops quickly, it may be low-priority background noise. If the pattern of scan -> login attempts is clear, proceed to analysis.

3. Analysis
This is the deep dive into the attacker's activity using your SIEM.

3.1. Characterize the Scan:

Use your saved KQL query [Hunt] Port Scan (Nmap) to investigate the scan activity.

Identify which ports were targeted. Was it a broad scan or focused on specific ports like 22 (SSH)?

3.2. Analyze the Brute-Force Attempt:

Pivot to the Cowrie logs in Kibana (log_type:"cowrie").

Use your "Top Usernames" and "Top Passwords" visualizations to see what credentials the attacker was trying.

Check if the attacker was successful. Filter for eventid:"cowrie.session.closed" and check the duration field. A session longer than a few seconds indicates a successful login to the honeypot.

3.3. Enrich the Attacker IP:

Take the attacker's source IP address.

Run your enrich.py script to check its reputation on AbuseIPDB and VirusTotal.

Key Question: Is this a known malicious IP, or is it coming from a legitimate cloud provider or residential ISP?

4. Containment
The goal is to block the attacker and prevent further access.

4.1. Block the Attacker IP:

Add the malicious source IP address to a blocklist on your network firewall. This is the most critical containment step.

4.2. Verify No Real Systems Were Compromised:

In Kibana, search for the attacker's IP address across all log sources, not just your security tools.

Crucial Check: Ensure the IP address did not successfully authenticate to any real systems (e.g., Windows Event Logs, legitimate server SSH logs), only to the Cowrie honeypot.

5. Eradication & Recovery
Since the attacker only interacted with the honeypot, this phase is minimal.

5.1. No Action Needed on Production Systems: If you confirmed no other systems were accessed, no remediation is required. The honeypot did its job.

5.2. Monitor: Keep the attacker's IP on a watchlist for a few days to ensure they do not return from a different IP address.

6. Post-Incident Activities
6.1. Document Findings: Complete the incident ticket. Include screenshots from Kibana, the IOC enrichment report, and a summary of the scan -> brute-force attack chain.

6.2. Tune Detections: Was the alert effective? Could the correlation be improved? Consider creating a specific Kibana rule that alerts only when a port scan from an IP is followed by login attempts from the same IP within 10 minutes.
