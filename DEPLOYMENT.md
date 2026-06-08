# 🛠️ DIP v3.2 - Deployment Guide

![DIP Logo](https://via.placeholder.com/1200x300/0A0A0A/00FF9D?text=DIP+v3.2+-+Domain+IP+Pentester)  
**Production-Grade Domain → IP → Gold Target Pipeline**  
*Real-time Nmap • cPanel/SMTP Hunting • 2026 Optimized*

---

> **DIP v3.2** transforms raw DRAKGRAB exports into **actionable GOLD targets** in minutes.  
> This guide covers **full deployment** on Kali Linux / Parrot OS / Ubuntu — from zero to fully armed pentest workstation.

---

## 📋 Table of Contents
- [System Requirements](#-system-requirements)
- [Quick Deploy (5 Minutes)](#-quick-deploy-5-minutes)
- [Detailed Installation](#-detailed-installation)
- [Tool Dependencies](#-tool-dependencies)
- [Configuration](#️-configuration)
- [Workflow Architecture](#-workflow-architecture)
- [Post-Deployment Verification](#-post-deployment-verification)
- [Advanced Deployment Options](#-advanced-deployment-options)
- [Troubleshooting](#-troubleshooting)
- [Security & Legal Notes](#-security--legal-notes)
- [References](#-references)

---

## 📋 System Requirements

| Component              | Minimum                  | Recommended                  | Notes |
|------------------------|--------------------------|------------------------------|-------|
| **OS**                 | Kali Linux 2025+ / Ubuntu 24.04 | Kali Rolling / Parrot OS | Debian-based recommended |
| **Python**             | 3.10+                    | 3.12+                        | Pre-installed on Kali |
| **CPU / Threads**      | 4 cores                  | 8+ cores                     | For 30-thread scans |
| **RAM**                | 8 GB                     | 16 GB+                       | Masscan + Nmap heavy usage |
| **Disk**               | 5 GB free                | 20 GB+                       | Nmap results + wordlists |
| **Internet**           | Required                 | Stable 100 Mbps+             | DNS + tool updates |

**Tested Environments:**
- Kali Linux 2026.1
- Ubuntu 24.04 LTS Server
- Parrot OS 6.1 Security Edition

---

## ⚡ Quick Deploy (5 Minutes)

```bash
# 1. Clone the repository
git clone https://github.com/officialmonsterz/DIP.git
cd DIP

# 2. Install Python dependencies
pip install colorama pyfiglet dnspython pandas openpyxl

# 3. Install system tools (Kali/Parrot/Ubuntu)
sudo apt update && sudo apt install -y \
    nmap masscan gobuster metasploit-framework \
    openssl python3 python3-pip

# 4. Make script executable
chmod +x dip.py

# 5. Run!
python3 dip.py

Done. DIP will auto-detect your DRAKGRAB file and guide you through the rest. Detailed InstallationStep 1: Clone & Preparebash

git clone https://github.com/officialmonsterz/DIP.git
cd DIP

Step 2: Python Environment (Optional but Recommended)bash

# Create virtual environment
python3 -m venv dip-env
source dip-env/bin/activate

# Install requirements
pip install -r requirements.txt   # (create this file if you want)

requirements.txt (create this file):txt

colorama
pyfiglet
dnspython
pandas
openpyxl

Step 3: Install Pentesting Toolsbash

sudo apt install -y nmap masscan gobuster
sudo apt install -y metasploit-framework   # ~2 GB — optional for auto-exploit

Step 4: Wordlist Setup (for vHost Enum)DIP auto-detects these common paths:/usr/share/wordlists/dirb/common.txt
/usr/share/seclists/Discovery/Web-Content/common.txt

Missing wordlist?  bash

sudo apt install seclists

 Tool DependenciesTool
Purpose
Version Tested
Required?
Install Command
nmap
Real-time gold scanning
7.95+
Yes
apt install nmap
masscan
Ultra-fast port discovery
1.3+
Optional
apt install masscan
gobuster
Virtual Host Enumeration
3.5+
Yes
apt install gobuster
metasploit
Auto cPanel exploit check
6.4+
Optional
apt install metasploit-framework
openssl
SSL certificate harvesting
3.x
Yes
apt install openssl
Shodan CLI
Host intelligence
Latest
Optional
pip install shodan

 Configuration1. config.json (Auto-created)json

{
  "shodan_api": "YOUR_SHODAN_API_KEY_HERE"
}

2. resolvers.txt (Highly Recommended)Create this file with fast public resolvers:txt

1.1.1.1
8.8.8.8
9.9.9.9

3. Input FilesPlace your DRAKGRAB export as HIGH_VALUE_TARGETS_*.txt or domains.txt
DIP auto-detects it

4. Output Directory Structure (Auto-created)

DIP/
├── dip_targets.txt
├── gold_ips.txt
├── nmap_results/
│   ├── gold_summary.txt
│   ├── ssl_certs/
│   ├── vhosts/
│   └── msf_autocrack.log
├── DIP_Results.csv
└── GOLD_TARGETS.xlsx

 Workflow Architecturemermaid

graph TD
    A[DRAKGRAB File] --> B[Domain Extraction + Cleaning]
    B --> C[Multi-threaded DNS Resolution]
    C --> D[Ultra-Fast Port Scan + Banner Grab]
    D --> E[Smart Scoring Engine]
    E --> F{Score >= 100?}
    F -->|Yes| G[🔥 GOLD IP Queue]
    F -->|No| H[Continue Scanning]
    G --> I[Real-time Nmap -sV]
    G --> J[SSL Cert Harvesting]
    G --> K[gobuster vHost Enum]
    G --> L[Masscan Cross-Reference]
    I --> M[Organized gold_summary.txt]
    J & K & L --> N[Auto-Export to Excel + CSV]
    M --> O[Metasploit cPanel Auto-Check]
    N --> P[Final Pentest-Ready Report]

Key Optimizations:Gold IPs scanned first (priority queuing)
Only 100+ point targets receive heavy tools
Cloud IPs automatically downgraded

 Post-Deployment VerificationRun this one-liner after first scan:bash

ls -la nmap_results/ && echo "✅ GOLD targets:" && wc -l gold_ips.txt

Expected output:gold_summary.txt with CRACK tags
GOLD_TARGETS.xlsx ready for handover
Console showing live banners and priorities

 Advanced Deployment OptionsDocker (Coming Soon — Community Request)dockerfile

# Dockerfile (add this if you want)
FROM kalilinux/kali-rolling
# ... (full container coming in v3.3)

Run as Background Service (Screen/Tmux)bash

screen -S dip-scan
python3 dip.py
# Detach: Ctrl+A D

CI/CD Integration (GitHub Actions)Add .github/workflows/scan.yml for automated daily runs (advanced users only). TroubleshootingIssue
Cause
Fix
gobuster not found
Missing binary
sudo apt install gobuster
Masscan timeout
Rate too high
Lower --rate=5000 in code
No gold targets
Low-score input
Use better DRAKGRAB export
Metasploit fails
Not installed
apt install metasploit-framework
Slow DNS
Bad resolvers
Use resolvers.txt with 1.1.1.1
Permission denied
Output files
sudo chown $USER .

Still stuck? Open an issue with dip.log (add logging if needed). Security & Legal NotesAuthorized Use Only — This tool is for legal penetration testing and bug bounty programs.
Never scan systems without explicit written permission.
Shodan API usage is rate-limited — use responsibly.
All output files are local-only — no data is sent to third parties.

 ReferencesNmap Official Documentation
Masscan GitHub
Gobuster Documentation
Metasploit Framework
Shodan Developer API
DRAKGRAB Format Reference (internal)
Python DNS Resolver Best Practices

 Deployment Complete!You are now running one of the most advanced domain-to-gold pipelines available in 2026.Next Step:
Run python3 dip.py and watch the GOLD roll in.Made with  for the real hunters.
Author: officialmonsterz
Version: 3.2 (June 2026)

