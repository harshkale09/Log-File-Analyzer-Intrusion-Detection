import re
import pandas as pd
import matplotlib.pyplot as plt

# Threat Intelligence Blacklist Feed (Lab Mock Feed)
KNOWN_THREAT_DATABASE = {
    '10.0.0.50': 'Known Brute Force Scanner (AbuseIPDB Threat Score: 85%)',
    '10.0.0.88': 'Known Web Directory Crawler / Recon Host',
    '10.0.0.99': 'High-Volume Traffic Generator / Botnet Node'
}

# 1. Apache Log Parser
def parse_apache_log(file_path):
    log_pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+|-)'
    parsed_records = []
    
    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = re.match(log_pattern, line)
                if match:
                    ip, timestamp, method, endpoint, status, size = match.groups()
                    parsed_records.append({
                        'ip': ip,
                        'timestamp': timestamp,
                        'method': method,
                        'endpoint': endpoint,
                        'status': int(status),
                        'size': int(size) if size != '-' else 0
                    })
        return pd.DataFrame(parsed_records)
    except FileNotFoundError:
        print(f"[ERROR] File not found at path: {file_path}")
        return pd.DataFrame()

# 2. Threat Intelligence Cross-Reference Function
def check_threat_intel(ip_address):
    if ip_address in KNOWN_THREAT_DATABASE:
        return True, KNOWN_THREAT_DATABASE[ip_address]
    return False, "Not flagged in threat feed"

# 3. Threat Detection Logic
def detect_threats(df):
    incidents = []
    if df.empty:
        return pd.DataFrame(incidents)

    # Rule A: Brute Force Detection
    failed_logins = df[(df['status'] == 401) & (df['endpoint'].str.contains('/login', case=False, na=False))]
    bf_counts = failed_logins['ip'].value_counts()
    for ip, count in bf_counts.items():
        if count >= 5:
            is_blacklisted, intel_msg = check_threat_intel(ip)
            incidents.append({
                'IP': ip,
                'Attack_Type': 'Brute Force Attack',
                'Severity': 'HIGH',
                'Reason': f'Detected {count} failed login attempts (HTTP 401)',
                'Endpoint': '/login',
                'Status': 401,
                'Threat_Intel_Matched': is_blacklisted,
                'Threat_Intel_Details': intel_msg
            })

    # Rule B: Scanning Detection
    sensitive_endpoints = ['/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config.php', '/server-status']
    scans = df[df['endpoint'].isin(sensitive_endpoints)]
    scan_counts = scans['ip'].value_counts()
    for ip, count in scan_counts.items():
        if count >= 2:
            scanned_paths = scans[scans['ip'] == ip]['endpoint'].unique()
            is_blacklisted, intel_msg = check_threat_intel(ip)
            incidents.append({
                'IP': ip,
                'Attack_Type': 'Scanning / Reconnaissance',
                'Severity': 'MEDIUM',
                'Reason': f'Accessing sensitive endpoints: {list(scanned_paths)}',
                'Endpoint': ', '.join(scanned_paths),
                'Status': '403/404',
                'Threat_Intel_Matched': is_blacklisted,
                'Threat_Intel_Details': intel_msg
            })

    # Rule C: DoS / High Request Rate
    ip_counts = df['ip'].value_counts()
    for ip, count in ip_counts.items():
        if count >= 10:
            is_blacklisted, intel_msg = check_threat_intel(ip)
            incidents.append({
                'IP': ip,
                'Attack_Type': 'DoS / High Request Rate',
                'Severity': 'HIGH',
                'Reason': f'High volume of requests generated: {count} total requests',
                'Endpoint': 'Multiple',
                'Status': 'Various',
                'Threat_Intel_Matched': is_blacklisted,
                'Threat_Intel_Details': intel_msg
            })

    return pd.DataFrame(incidents)

# 4. Visualization Generator
def generate_graphs(df, incidents_df):
    if df.empty:
        return
    
    # Graph 1: Total Requests by IP
    plt.figure(figsize=(8, 4))
    ip_counts = df['ip'].value_counts()
    ip_counts.plot(kind='bar', color='skyblue')
    plt.title('Total Requests by IP Address')
    plt.xlabel('IP Address')
    plt.ylabel('Request Count')
    plt.tight_layout()
    plt.savefig('graphs/requests_by_ip.png')
    plt.close()

    # Graph 2: HTTP Status Distribution
    plt.figure(figsize=(6, 4))
    status_counts = df['status'].value_counts()
    status_counts.plot(kind='pie', autopct='%1.1f%%', colors=['lightgreen', 'orange', 'crimson'])
    plt.title('HTTP Status Code Distribution')
    plt.ylabel('')
    plt.tight_layout()
    plt.savefig('graphs/status_code_distribution.png')
    plt.close()

    # Graph 3: Attack Types Breakdown
    if not incidents_df.empty:
        plt.figure(figsize=(7, 4))
        attack_counts = incidents_df['Attack_Type'].value_counts()
        attack_counts.plot(kind='barh', color='salmon')
        plt.title('Detected Incidents by Attack Type')
        plt.xlabel('Incident Count')
        plt.tight_layout()
        plt.savefig('graphs/attack_patterns.png')
        plt.close()

# 5. Execution Pipeline
if __name__ == "__main__":
    print("=== Log File Analyzer Started ===")
    
    log_file = "data/sample_access.log"
    df_logs = parse_apache_log(log_file)
    
    if not df_logs.empty:
        print(f"[SUCCESS] Successfully parsed {len(df_logs)} log entries.")
        
        # Threat Detection
        incidents_df = detect_threats(df_logs)
        print(f"[DETECTION] Threat detection complete. Total Incidents: {len(incidents_df)}")
        
        # Export CSV Incident Report
        csv_output_path = "output/incident_report.csv"
        incidents_df.to_csv(csv_output_path, index=False)
        print(f"[REPORT] Incident report saved to: {csv_output_path}")
        
        # Generate Visualizations
        generate_graphs(df_logs, incidents_df)
        print("[GRAPHS] Visualizations saved inside 'graphs/' directory.")
        
        print("\n--- Summary of Incidents with Threat Intel ---")
        print(incidents_df[['IP', 'Attack_Type', 'Severity', 'Threat_Intel_Matched', 'Threat_Intel_Details']])
    else:
        print("[WARNING] No logs parsed or file is empty.")