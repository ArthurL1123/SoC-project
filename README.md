# SoC-project
SOC Analyst Project Portfolio: SIEM, Threat Detection & IR
This repository documents a comprehensive, hands-on project designed to simulate the core functions of a Security Operations Center (SOC). The primary goal is to demonstrate practical skills in SIEM implementation, network threat detection, log analysis, and the initial stages of incident response.

This project was built to showcase the foundational knowledge and proactive mindset required for an undergraduate or entry-level SOC Analyst role.

# Key Features
Centralized SIEM: A fully deployed ELK (Elasticsearch, Logstash, Kibana) Stack on Kali Linux to ingest, parse, and visualize security data.

Multi-Source Log Ingestion: Integration of alerts from industry-standard tools:

Suricata (Network Intrusion Detection/Prevention System)

Snort (Network Intrusion Detection System)

Cowrie (Medium-interaction SSH & Telnet Honeypot)

Live Threat Dashboard: A correlated "Network Detection Overview" dashboard in Kibana providing at-a-glance visibility into network and honeypot activity.

Threat Hunting Queries: A repository of KQL queries mapped to the MITRE ATT&CK framework to facilitate proactive threat hunting.

Incident Response Playbooks: Documented response procedures for common security incidents.

# Live SIEM Dashboard: Network Detection Overview
The heart of this project is the central Kibana dashboard, which correlates data from all security tools into a single pane of glass. This provides a unified view for monitoring and detecting potentially malicious activity across the network.

A snapshot of the live dashboard after simulating several attacks, showing alerts from Suricata, Snort, and Cowrie.

# Simulated Detections & Evidence
To validate the effectiveness of the SIEM, several attacks were simulated. The system successfully detected and logged this activity, and the evidence is captured below.

1. Suricata: Port Scan Detection
Suricata identified an Nmap scan targeting the monitored network.

Top alert signatures in Kibana clearly showing the "ET SCAN Nmap" rule trigger.

2. Snort: ICMP & TCP Detection
Snort generated alerts for suspicious ICMP traffic and other network anomalies during the scan.

Top Snort rules triggered, including detections for ICMP traffic.

3. Cowrie Honeypot: Brute-Force Attempts
The Cowrie honeypot successfully logged multiple failed login attempts, capturing the usernames and passwords used by the "attacker."

A breakdown of the most frequently used usernames in SSH brute-force attempts.

A visualization of the most common passwords attempted against the honeypot.

# Repository Structure
This repository is organized to clearly present all project artifacts:

.
├── evidence/              # Screenshots and data exports from detections
├── playbooks/             # Incident Response playbooks in Markdown
├── queries/               # KQL threat hunting queries
├── python_tools/          # Automation scripts for IOC enrichment, etc.
└── README.md              # You are here!

# Technologies Used
SIEM: ELK Stack (Elasticsearch, Kibana, Filebeat) v8.x

Host: Kali Linux

Network Security: Suricata, Snort 3

Honeypot: Cowrie

Scripting: Python, Bash

Version Control: Git & GitHub
