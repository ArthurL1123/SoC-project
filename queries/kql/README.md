# KQL Threat Hunting Queries

This directory contains a repository of Kibana Query Language (KQL) queries designed for proactive threat hunting within the SIEM. Each query is mapped to a specific tactic or technique from the MITRE ATT&CK framework.

## Query Library

| Filename | Description | MITRE ATT&CK ID |
| :--- | :--- | :--- |
| `T1046_T1110_hunt_attack_chain.kql` | Finds IPs that performed a network scan and then immediately attempted a brute-force attack. | T1046, T1110 |
| `T1059_hunt_cowrie_commands_executed.kql` | Shows the specific commands typed by an attacker after a successful login to the honeypot. | T1059 |
| `T1110_hunt_cowrie_successful_login.kql` | Finds all instances where an attacker successfully logged into the Cowrie honeypot. | T1110 |
| `T1046_hunt_suricata_nmap_scan.kql` | A specific hunt for Nmap scans detected by Suricata. | T1046 |
| `T1027_hunt_win_powershell_encoded.kql` | Detects the use of encoded PowerShell commands, a common obfuscation technique. | T1027 |

