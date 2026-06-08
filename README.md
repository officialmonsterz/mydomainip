```markdown
# DIP v3.2 - Domain IP Pentester + Real-time Nmap

![DIP Banner](https://via.placeholder.com/800x200/111111/00ff00?text=DIP+v3.2+-+Domain+IP+Pentester)  
**DRAKGRAB → Domain → IP → cPanel/SMTP → INSTANT Nmap Analysis**  
*2026 Production-Grade Pentesting Weapon*

---

**The ultimate domain-to-gold-target pipeline.**  
Turn any DRAKGRAB export into **actionable, high-value targets** with real-time scoring, banner grabbing, live Nmap, SSL harvesting, vHost enumeration, Masscan acceleration, auto-exploit checks, and Excel exports — all in one beautiful, threaded beast.

Whether you're hunting cPanel panels, SMTP relays, WHM masters, or SSH shells, **DIP v3.2** gives you organized, ready-to-crack intelligence faster than any other tool.

---

## ✨ Why Everyone Wants This Tool

- **Smart Scoring Engine** – 2026-optimized port scores (cPanel 2082-2086 = 25 pts each!)
- **Real-time Live Dashboard** – Watch GOLD targets (100+ pts) appear instantly
- **Gold-First Nmap** – Only scans the juiciest IPs with full service detection
- **SSL Cert Harvesting** – Extract emails & extra domains from HTTPS certs
- **Virtual Host Enumeration** – gobuster on every GOLD IP
- **Masscan Ultra-Speed** – Optional 10k+ pps initial discovery
- **Auto-Exploit Check** – Metasploit cPanel login scanner (admin:password)
- **Cloud Detection** – Auto-tags Amazon, Azure, Cloudflare, etc.
- **Beautiful Organized Output** – Single `gold_summary.txt` + folders + Excel
- **Zero Bloat** – Clean, threaded, production-ready Python 3

---

## 🚀 Features

| Feature                    | Status     | Description |
|---------------------------|------------|-----------|
| DRAKGRAB Auto-Parse       | ✅         | Extracts domains from any HIGH_VALUE_TARGETS*.txt |
| Real-time Port Scoring    | ✅         | Banner grab + weighted scoring |
| Gold/Silver/Bronze Tagging| ✅         | Live color-coded console |
| Instant Nmap (Gold only)  | ✅         | -sV + organized summary |
| SSL Certificate Harvest   | ✅         | Emails + SAN domains |
| Virtual Host Enum         | ✅         | gobuster on every GOLD IP |
| Masscan Integration       | ✅         | 10,000+ packets/sec discovery |
| Auto-Exploit (Metasploit) | ✅         | cPanel login scanner |
| Cloud Provider Detection  | ✅         | Reduces score on cloud IPs |
| Excel + CSV Export        | ✅         | Top 100 GOLD in `.xlsx` |
| Shodan CLI Integration    | ✅         | One-click host lookup |
| Multi-threaded (5-30)     | ✅         | Blazing fast |

---

## 📦 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/officialmonsterz/DIP.git
cd DIP
```

### 2. Install Python Dependencies
```bash
pip install colorama pyfiglet dnspython pandas openpyxl
```

### 3. Install Required Tools (Kali / Parrot / Debian-based)
```bash
sudo apt update
sudo apt install nmap masscan gobuster metasploit-framework openssl
```

### 4. (Optional) Shodan CLI
```bash
pip install shodan
shodan init YOUR_API_KEY
```

---

## 🎮 Quick Start

1. Put your DRAKGRAB file in the folder (e.g. `HIGH_VALUE_TARGETS_2026.txt`)
2. Run the script:
```bash
python3 dip.py
```

3. Answer the prompts:
   - DRAKGRAB file (auto-detected)
   - `resolvers.txt` (optional but recommended)
   - Threads (default 12)
   - Real-time Nmap? (y)
   - Shodan API? (optional)
   - Use Masscan? (y/n)

**That’s it.** Watch the magic happen in real time.

---

## 📁 Output Files & Folders

| File / Folder              | Purpose |
|---------------------------|--------|
| `dip_targets.txt`         | Full results: `domain|ip|ports|score` |
| `ip_list.txt`             | Clean list of all resolved IPs |
| `gold_ips.txt`            | Only 100+ point GOLD targets |
| `nmap_results/`           | All Nmap scans + gold_summary.txt |
| `nmap_results/ssl_certs/` | Raw SSL certificates |
| `nmap_results/vhosts/`    | gobuster vHost results per IP |
| `nmap_results/msf_autocrack.log` | Metasploit results |
| `DIP_Results.csv`         | Full export |
| `GOLD_TARGETS.xlsx`       | Top 100 GOLD targets (sorted) |
| `ssl_emails.txt`          | Harvested emails from certs |
| `ssl_domains.txt`         | Extra domains from SANs |

---

## 🧪 Example Live Output

```bash
🔥 GOLD [example.com|185.22.44.11|2082,2083,2086,25|145]
   📋 Banners: Port 2083: cPanel 11.8x...
🎯 2082-2086/cPanel ← ADMIN PANEL (CRACK NOW!)
```

---

## ⚙️ Configuration

- **config.json** – Auto-created when you enter Shodan API
- **resolvers.txt** – One resolver per line (highly recommended for speed)
- **Wordlists** – DIP auto-detects common gobuster wordlists

---

## 🔒 Legal & Responsible Use

> **For authorized penetration testing and bug bounty programs only.**  
> The author is not responsible for any misuse. Always have explicit permission.

---

## ⭐ Show Some Love

If DIP helped you find gold, **star the repo** and drop a screenshot of your biggest score in the issues!

**Author:** [officialmonsterz](https://github.com/officialmonsterz)  
**Email:** willsmith32701@gmail.com

---

**Ready to hunt?**  
Just clone, run, and **watch the GOLD roll in**.

```bash
git clone https://github.com/officialmonsterz/DIP.git && cd DIP && python3 dip.py
```

---

*Made with 🔥 for the real hunters.
