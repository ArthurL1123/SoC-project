# enrich.py
# A tool to enrich IP addresses using the AbuseIPDB and VirusTotal APIs.

import requests
import configparser
import argparse

# --- Configuration ---
def load_api_keys():
    """Loads API keys from config.ini"""
    config = configparser.ConfigParser()
    # Make sure the config.ini file is in the same directory
    config.read('config.ini')
    if 'api_keys' in config:
        return config['api_keys']
    else:
        print("Error: 'api_keys' section not found in config.ini")
        return None

# --- API Functions ---
def enrich_ip_abuseipdb(api_key, ip_address):
    """Enriches an IP address using the AbuseIPDB API."""
    print(f"\n--- Checking AbuseIPDB for {ip_address} ---")
    headers = {'Key': api_key, 'Accept': 'application/json'}
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    
    try:
        response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
        response.raise_for_status() # Raise an exception for bad status codes
        data = response.json().get('data', {})

        if not data:
            print("No data found for this IP.")
            return None

        print(f"IP: {data.get('ipAddress')}")
        print(f"Country: {data.get('countryCode')}")
        print(f"Usage Type: {data.get('usageType')}")
        print(f"ISP: {data.get('isp')}")
        print(f"Domain: {data.get('domain')}")
        print(f"Abuse Confidence Score: {data.get('abuseConfidenceScore')}%")
        print(f"Total Reports: {data.get('totalReports')}")
        return data
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to AbuseIPDB: {e}")
        return None

def enrich_ip_virustotal(api_key, ip_address):
    """Enriches an IP address using the VirusTotal API."""
    print(f"\n--- Checking VirusTotal for {ip_address} ---")
    headers = {'x-apikey': api_key}
    
    try:
        response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}', headers=headers)
        response.raise_for_status()
        data = response.json().get('data', {})
        
        if not data:
            print("No data found for this IP.")
            return None

        attributes = data.get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        print(f"Owner: {attributes.get('as_owner')}")
        print("Last Analysis Stats:")
        print(f"  Harmless: {last_analysis_stats.get('harmless', 0)}")
        print(f"  Malicious: {last_analysis_stats.get('malicious', 0)}")
        print(f"  Suspicious: {last_analysis_stats.get('suspicious', 0)}")
        print(f"  Undetected: {last_analysis_stats.get('undetected', 0)}")
        return attributes
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to VirusTotal: {e}")
        return None

# --- Main Execution ---
if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Enrich an IP address using threat intelligence APIs.")
    parser.add_argument("ip_address", help="The IP address to enrich.")
    args = parser.parse_args()

    # Load keys and run enrichment
    api_keys = load_api_keys()
    if api_keys:
        # Enrich with AbuseIPDB
        enrich_ip_abuseipdb(api_keys.get('abuseipdb'), args.ip_address)
        
        # Enrich with VirusTotal
        enrich_ip_virustotal(api_keys.get('virustotal'), args.ip_address)

