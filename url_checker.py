import re
import whois
import requests
import ssl
import socket
import subprocess
import sqlite3
import os
from datetime import datetime, timedelta
from colorama import Fore, Style, init

# Initialize colorama
init()

# --- Configuration ---
API_KEY = "0864bdc397824db18415143fac2d9fe10bb46c97a3e507136371cde7699173a5"
LEGIT_DOMAINS = ["google.com", "microsoft.com", "github.com", "facebook.com"]
BROWSERS = {
    "Chrome": os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"),
    "Edge": os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History")
}

# --- Core Functions ---
def get_domain(url):
    try:
        return re.search(r"(?:https?://)?(?:www\.)?([^/]+)", url).group(1).lower()
    except (AttributeError, TypeError):
        return None

def is_typosquatting(domain):
    domain_parts = domain.split('.')
    for legit in LEGIT_DOMAINS:
        legit_parts = legit.split('.')
        if domain_parts[-2:] == legit_parts[-2:]:
            diff = sum(1 for a, b in zip(domain_parts[0], legit_parts[0]) if a != b)
            if diff <= 2:
                return True, legit
    return False, None

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        context.timeout = 3
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return True, (valid_to - datetime.now()).days
    except socket.timeout:
        return False, "Connection timeout"
    except ConnectionRefusedError:
        return False, "Connection refused"
    except ssl.SSLError:
        return False, "SSL handshake failed"
    except Exception as e:
        return False, str(e)

def get_domain_age(domain):
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date[0] if isinstance(info.creation_date, list) else info.creation_date
        return (datetime.now() - creation_date).days
    except:
        return None

def check_virustotal(domain):
    if not API_KEY:
        return {"error": "No API key"}
    
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": API_KEY},
            timeout=10
        )
        if response.status_code == 200:
            return response.json().get('data', {}).get('attributes', {})
        return {"error": f"API Error {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Connection failed: {e}"}

# --- Protection Functions ---
def block_with_firewall(domain):
    try:
        # Try to resolve IP first
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            print(f"{Fore.YELLOW}⚠️ Could not resolve IP - blocking by hostname{Style.RESET_ALL}")
            ip = domain
            
        result = subprocess.run(
            f'netsh advfirewall firewall add rule name="Block_{domain[:25]}" '
            f'dir=out action=block remoteip={ip} protocol=any',
            shell=True,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return True
        print(f"{Fore.RED}⚠️ Firewall Error: {result.stderr.strip() or 'Unknown error'}{Style.RESET_ALL}")
        return False
    except Exception as e:
        print(f"{Fore.RED}⚠️ Firewall Exception: {e}{Style.RESET_ALL}")
        return False

def verify_dns(domain):
    try:
        result = subprocess.run(
            f"nslookup -type=mx {domain}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        return "mail exchanger" in result.stdout.lower()
    except Exception:
        return False

def scan_browser_history(domain):
    results = {}
    for browser, path in BROWSERS.items():
        try:
            if not os.path.exists(path):
                continue
                
            temp_db = os.path.join(os.environ['TEMP'], f'temp_history_{browser}')
            with open(temp_db, 'wb') as f, open(path, 'rb') as original:
                f.write(original.read())
            
            conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT url, title, last_visit_time FROM urls WHERE url LIKE ? LIMIT 5",
                (f'%{domain}%',)
            )
            
            if visits := cursor.fetchall():
                results[browser] = [
                    {
                        'url': visit[0],
                        'title': visit[1],
                        'last_visit': datetime(1601, 1, 1) + timedelta(microseconds=visit[2])
                    } for visit in visits
                ]
            conn.close()
            os.remove(temp_db)
        except Exception:
            continue
    return results

def main():
    print(Fore.CYAN + "\n🛡️ URL Security Analyzer" + Style.RESET_ALL)
    url = input("Enter URL to check: ").strip()
    if not (domain := get_domain(url)):
        print(Fore.RED + "❌ Invalid URL format" + Style.RESET_ALL)
        return

    # Analysis
    print(f"\n{Fore.BLUE}🔍 Analysis Results:{Style.RESET_ALL}")
    
    if (typo_match := is_typosquatting(domain))[0]:
        print(f"{Fore.RED}🚨 Typosquatting detected (similar to {typo_match[1]}){Style.RESET_ALL}")
    
    if (age := get_domain_age(domain)) is not None:
        print(f"🕒 Age: {age} days ({'New' if age < 365 else 'Established'})")
    
    ssl_status, ssl_info = check_ssl(domain)
    print(f"🔐 SSL: {Fore.GREEN if ssl_status else Fore.RED}{ssl_info}{Style.RESET_ALL}")

    # VirusTotal
    print(f"\n{Fore.MAGENTA}📊 VirusTotal:{Style.RESET_ALL}")
    if vt_data := check_virustotal(domain):
        if "error" in vt_data:
            print(f"{Fore.YELLOW}⚠️ {vt_data['error']}{Style.RESET_ALL}")
        else:
            stats = vt_data.get('last_analysis_stats', {})
            print(f"✅ Clean: {stats.get('harmless', 0)}")
            print(f"🟡 Suspicious: {stats.get('suspicious', 0)}")
            print(f"🔴 Malicious: {stats.get('malicious', 0)}")

    # Protection
    print(f"\n{Fore.MAGENTA}🛡️ Protection Measures:{Style.RESET_ALL}")
    if block_with_firewall(domain):
        print(f"{Fore.GREEN}✅ Firewall rule added{Style.RESET_ALL}")
    
    print(f"📡 MX Records: {'Found' if verify_dns(domain) else 'None'}")

    if history := scan_browser_history(domain):
        print(f"\n{Fore.RED}⚠️ Browser History Matches:{Style.RESET_ALL}")
        for browser, visits in history.items():
            print(f"{browser}:")
            for visit in visits:
                print(f"- {visit['url']} ({visit['last_visit'].date()})")
    else:
        print(f"{Fore.GREEN}✅ No browser history matches{Style.RESET_ALL}")

if __name__ == "__main__":
    main()