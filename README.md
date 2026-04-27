# mydomainip
This is essentially an automated pipeline: Domain List → DNS Resolution → Port Scan/Score → Gold/Silver Classification → Nmap/SSL/VHost/Metasploit/Export
# DIP v3.2 - Domain IP Pentester

**Domain → IP → cPanel/SMTP → Real-time Nmap → SSL Harvest → VHost → Auto-Exploit**

![Version](https://img.shields.io/badge/version-3.2-brightgreen)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-red)

DIP is an automated reconnaissance and attack-surface mapping tool for authorized penetration testers. It ingests domain lists, resolves to IPs, scores targets by service value, and pipelines high-value targets into aggressive scanning, enumeration, and exploitation workflows.

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **DRAKGRAB Parsing** | Auto-extract domains from DRAKGRAB format logs |
| **Priority Scoring** | Port-based scoring system (GOLD ≥100, SILVER ≥70, BRONZE ≥40) |
| **Banner Grabbing** | Real-time service banner capture during port scanning |
| **SSL Cert Harvesting** | Extract emails, SANs, and CNs from HTTPS certificates |
| **VHost Enumeration** | Gobuster-based virtual host discovery on GOLD IPs |
| **Auto-Exploit Check** | Metasploit cPanel login scanner against GOLD targets |
| **Cloud Detection** | Reverse-DNS cloud provider identification (AWS/GCP/Azure/Cloudflare) |
| **Masscan Integration** | Ultra-fast initial discovery at 10,000 pkts/sec (optional) |
| **Smart Nmap** | Auto-runs fast + full Nmap scans on GOLD IPs |
| **Shodan Enrichment** | Optional Shodan API integration |
| **Excel/CSV Export** | Export results to CSV and Top 100 GOLD to Excel |

---

## 📋 Requirements

```bash
# Core dependencies
pip install dnspython colorama pyfiglet pandas openpyxl

# External tools (must be in $PATH):
# - nmap (https://nmap.org)
# - masscan (https://github.com/robertdavidgraham/masscan) [optional]
# - gobuster (https://github.com/OJ/gobuster) [optional]
# - openssl (for SSL cert harvesting)
# - msfconsole (Metasploit) [optional, for auto-exploit]
# - shodan CLI (pip install shodan) [optional]

# Wordlists (for VHost enumeration):
# - /usr/share/wordlists/dirb/common.txt
# - /usr/share/seclists/Discovery/Web-Content/common.txt
