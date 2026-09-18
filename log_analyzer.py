import re
import pandas as pd
import matplotlib.pyplot as plt

# Threat Intelligence Blacklist Feed
KNOWN_THREAT_DATABASE = {
    '10.0.0.50': 'Known Brute Force Scanner (AbuseIPDB Score: 85%)',
    '10.0.0.88': 'Known Web Directory Crawler / Recon Host',
    '10.0.0.99': 'High-Volume Traffic Generator / Botnet Node',
    '203.0.113.5': 'SSH Brute-Force Botnet Node'
}

# 1. Apache Web Log Parser
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
                        'size': int(size) if size != '-' else 0,
                        'log_type': 'Apache Web'
                    })
        return pd.DataFrame(parsed_records)
    except FileNotFoundError:
        print(f"[ERROR] Web log file not found at: {file_path}")
        return pd.DataFrame()

# 2. SSH Authentication Log Parser
def parse_ssh_log(file_path):
    # Regex to capture SSH Failed/Accepted password events
    ssh_pattern = r'^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+(Failed|Accepted)\s+password\s+for\s+(\S+)\s+from\s+(\S+)'
    parsed_records = []
    
    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = re.search(ssh_pattern, line)
                if match:
                    timestamp, auth_status, user, ip = match.groups()
                    parsed_records.append({
                        'ip': ip,
                        'timestamp': timestamp,
                        'user': user,
                        'status': 401 if auth_status == 'Failed' else 200,
                        'endpoint': 'SSH Service',
                        'log_type': 'SSH Auth'
                    })
        return pd.DataFrame(parsed_records)
    except FileNotFoundError:
        print(f"[ERROR] SSH log file not found at: {file_path}")
        return pd.DataFrame()

# 3. Threat Intelligence Cross-Reference
def check_threat_intel(ip_address):
    if ip_address in KNOWN_THREAT_DATABASE:
        return True, KNOWN_THREAT_DATABASE[ip_address]
    return False, "Not flagged in threat feed"

# 4. Threat Detection Logic (Web + SSH)
def detect_threats(web_df, ssh_df):
    incidents = []
    
    # Web Brute Force Detection
    if not web_df.empty:
        failed_logins = web_df[(web_df['status'] == 401) & (web_df['endpoint'].str.contains('/login', case=False, na=False))]
        bf_counts = failed_logins['ip'].value_counts()
        for ip, count in bf_counts.items():
            if count >= 5:
                is_blacklisted, intel_msg = check_threat_intel(ip)
                incidents.append({
                    'IP': ip,
                    'Attack_Type': 'Web Brute Force Attack',
                    'Severity': 'HIGH',
                    'Reason': f'Detected {count} failed web login attempts',
                    'Endpoint': '/login',
                    'Threat_Intel_Matched': is_blacklisted,
                    'Threat_Intel_Details': intel_msg
                })

        # Web Scanning Detection
        sensitive_endpoints = ['/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config.php']
        scans = web_df[web_df['endpoint'].isin(sensitive_endpoints)]
        scan_counts = scans['ip'].value_counts()
        for ip, count in scan_counts.items():
            if count >= 2:
                scanned_paths = scans[scans['ip'] == ip]['endpoint'].unique()
                is_blacklisted, intel_msg = check_threat_intel(ip)
                incidents.append({
                    'IP': ip,
                    'Attack_Type': 'Scanning / Reconnaissance',
                    'Severity': 'MEDIUM',
                    'Reason': f'Accessing sensitive paths: {list(scanned_paths)}',
                    'Endpoint': ', '.join(scanned_paths),
                    'Threat_Intel_Matched': is_blacklisted,
                    'Threat_Intel_Details': intel_msg
                })

        # Web DoS Detection
        ip_counts = web_df['ip'].value_counts()
        for ip, count in ip_counts.items():
            if count >= 10:
                is_blacklisted, intel_msg = check_threat_intel(ip)
                incidents.append({
                    'IP': ip,
                    'Attack_Type': 'DoS / High Request Rate',
                    'Severity': 'HIGH',
                    'Reason': f'High request volume: {count} total requests',
                    'Endpoint': 'Multiple',
                    'Threat_Intel_Matched': is_blacklisted,
                    'Threat_Intel_Details': intel_msg
                })

    # SSH Brute Force Detection
    if not ssh_df.empty:
        ssh_failed = ssh_df[ssh_df['status'] == 401]
        ssh_bf_counts = ssh_failed['ip'].value_counts()
        for ip, count in ssh_bf_counts.items():
            if count >= 3:
                is_blacklisted, intel_msg = check_threat_intel(ip)
                incidents.append({
                    'IP': ip,
                    'Attack_Type': 'SSH Brute Force Attack',
                    'Severity': 'HIGH',
                    'Reason': f'Detected {count} failed SSH authentication attempts',
                    'Endpoint': 'SSH (Port 22)',
                    'Threat_Intel_Matched': is_blacklisted,
                    'Threat_Intel_Details': intel_msg
                })

    return pd.DataFrame(incidents)

# 5. Visualization Generator
def generate_graphs(df, incidents_df):
    if df.empty:
        return
    
    plt.figure(figsize=(8, 4))
    ip_counts = df['ip'].value_counts()
    ip_counts.plot(kind='bar', color='skyblue')
    plt.title('Total Web Requests by IP Address')
    plt.xlabel('IP Address')
    plt.ylabel('Request Count')
    plt.tight_layout()
    plt.savefig('graphs/requests_by_ip.png')
    plt.close()

    plt.figure(figsize=(6, 4))
    status_counts = df['status'].value_counts()
    status_counts.plot(kind='pie', autopct='%1.1f%%', colors=['lightgreen', 'orange', 'crimson'])
    plt.title('HTTP Status Code Distribution')
    plt.ylabel('')
    plt.tight_layout()
    plt.savefig('graphs/status_code_distribution.png')
    plt.close()

    if not incidents_df.empty:
        plt.figure(figsize=(7, 4))
        attack_counts = incidents_df['Attack_Type'].value_counts()
        attack_counts.plot(kind='barh', color='salmon')
        plt.title('Detected Incidents Breakdown (Web + SSH)')
        plt.xlabel('Incident Count')
        plt.tight_layout()
        plt.savefig('graphs/attack_patterns.png')
        plt.close()

# 6. Execution Pipeline
if __name__ == "__main__":
    print("=== Multi-Log Analyzer Started ===")
    
    # Process Web Logs
    web_log_file = "data/sample_access.log"
    df_web = parse_apache_log(web_log_file)
    print(f"[SUCCESS] Parsed {len(df_web)} Web Log entries.")
    
    # Process SSH Logs
    ssh_log_file = "data/sample_auth.log"
    df_ssh = parse_ssh_log(ssh_log_file)
    print(f"[SUCCESS] Parsed {len(df_ssh)} SSH Log entries.")
    
    # Threat Detection
    incidents_df = detect_threats(df_web, df_ssh)
    print(f"[DETECTION] Detection complete. Total Incidents Detected: {len(incidents_df)}")
    
    # Export CSV Report
    csv_output_path = "output/incident_report.csv"
    incidents_df.to_csv(csv_output_path, index=False)
    print(f"[REPORT] Updated report saved to: {csv_output_path}")
    
    # Generate Visuals
    generate_graphs(df_web, incidents_df)
    print("[GRAPHS] Visualizations updated in 'graphs/' directory.\n")
    
    print("--- Summary of Combined Incidents ---")
    print(incidents_df[['IP', 'Attack_Type', 'Severity', 'Threat_Intel_Matched']])