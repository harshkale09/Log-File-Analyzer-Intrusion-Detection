# Log File Analyzer for Intrusion Detection

A Python-based log analysis and threat detection tool designed to parse web server access logs, detect malicious attack patterns (Brute Force, Scanning, DoS), cross-reference suspicious IPs with threat intelligence feeds, and generate automated CSV incident reports alongside visual analytics.

---

## Executive Summary & Objective

Modern web servers generate massive volumes of log data daily. Manually identifying security incidents within these logs is inefficient and prone to human error. 

**Objective:** Develop a lightweight, automated Python detection system to:
* Parse standard Apache web access log formats using Regular Expressions (Regex).
* Detect malicious activity based on rule-based heuristic logic.
* Cross-reference flagged IP addresses with threat intelligence indicators.
* Export structured CSV incident reports for SOC analysts.
* Generate visual analytics on traffic patterns and HTTP status codes.

---

## Features

* **Log Parsing:** Extracts IP addresses, timestamps, HTTP methods, endpoints, status codes, and response sizes.
* **Brute-Force Detection:** Identifies repeated authentication failures (`HTTP 401` on `/login`).
* **Scanning & Reconnaissance Detection:** Flags unauthorized requests targeting sensitive paths (`/admin`, `/.env`, `/wp-admin`, etc.).
* **DoS / High-Rate Detection:** Detects high-frequency request spikes originating from single IP sources.
* **Threat Intelligence Matching:** Cross-references flagged IPs with known threat indicators.
* **Automated CSV Reporting:** Exports incident data with severity levels and supporting evidence.
* **Data Visualization:** Generates charts for request counts, status code distribution, and attack breakdowns.

---

## Attack Detection Rules

1. **Brute Force Attack:** Triggered when an IP accumulates $\ge 5$ failed login attempts (`HTTP 401`) on authentication endpoints.
2. **Scanning / Reconnaissance:** Triggered when an IP attempts to access $\ge 2$ sensitive system or management endpoints (`HTTP 403` / `HTTP 404`).
3. **DoS / High Request Rate:** Triggered when an IP exceeds a volume threshold of $\ge 10$ requests within the logged timeframe.

---

## Project Directory Structure

```text
Log-File-Analyzer-Intrusion-Detection/
│
├── data/
│   ├── sample_access.log        # Lab-generated synthetic web log dataset
│   └── sample_auth.log          # Lab-generated SSH authentication log
│
├── output/
│   └── incident_report.csv      # Generated CSV incident detection report
│
├── graphs/
│   ├── requests_by_ip.png       # Bar chart: Total requests per IP
│   ├── status_code_distribution.png # Pie chart: HTTP status code breakdown
│   └── attack_patterns.png      # Horizontal bar chart: Detected incidents
│
├── .gitignore                   # Git exclusion configuration
├── log_analyzer.py              # Main Python engine script
├── README.md                    # Project documentation
└── requirements.txt             # Python dependencies