#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import os
import sys
import socket
import threading
import requests
import dns.resolver
import queue
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import random
import time

# ======= CONFIG =======
THREADS = 300
TCP_TIMEOUT = 0.3
UDP_TIMEOUT = 1
COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520]
SENSITIVE_PATHS = ["/.git/HEAD", "/.env", "/wp-admin/", "/wp-login.php",
                   "/readme.html", "/phpinfo.php", "/.DS_Store"]
SUBDOMAIN_THREADS = 50

# ======= COLORS =======
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"
COLOR_LIST = [RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN]

# ======= UTILS =======
def clear_terminal():
    os.system("clear")

def normalize_domain(domain):
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        return urlparse(domain).hostname
    return domain

def full_url(domain):
    return "http://" + domain

# ======= BANNER & INPUT =======
def show_banner_and_input():
    clear_terminal()
    banner_lines = [
        "  ███████╗ ██████╗ ███████╗ ██████╗",
        " ██╔════╝██╔═══██╗██╔════╝██╔═══██╗",
        " ███████╗██║   ██║███████╗██║   ██║",
        " ╚════██║██║   ██║╚════██║██║   ██║",
        " ███████║╚██████╔╝███████║╚██████╔",
        " ╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝",
        "     Recon scanner v1.0"
        "     Made by: Lemonaidd 😊"
    ]
    for line in banner_lines:
        print(random.choice(COLOR_LIST) + line + RESET)
        time.sleep(0.05)
    
    domain = input(f"{CYAN}Enter Target domain (without Http:// OR Https://): {RESET}")
    return normalize_domain(domain)

# ======= SPINNER =======
def spinner_task(stop_event):
    spinner = ['|', '/', '-', '\\']
    idx = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r{YELLOW}Scanning... {spinner[idx % len(spinner)]}{RESET}")
        sys.stdout.flush()
        idx += 1
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * 20 + "\r")

# ======= BANNER GRABBER =======
def grab_banner(host, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((host, port))
        s.send(b'\r\n')
        banner = s.recv(1024).decode().strip()
        if banner:
            print(f"{GREEN}[BANNER]{RESET} Port {port}: {banner}")
        s.close()
    except:
        pass

# ======= SCANS =======
def tcp_scan(host, start_port, end_port):
    print(f"{YELLOW}[*] Starting TCP Scan on {host} ({start_port}-{end_port})...{RESET}")
    q = queue.Queue()
    stop_event = threading.Event()
    t_spinner = threading.Thread(target=spinner_task, args=(stop_event,))
    t_spinner.start()

    def worker():
        while True:
            port = q.get()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(TCP_TIMEOUT)
                if s.connect_ex((host, port)) == 0:
                    print(f"{GREEN}[OPEN]{RESET} TCP {port}")
                    grab_banner(host, port)
                s.close()
            except:
                pass
            q.task_done()

    for _ in range(THREADS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    for p in range(start_port, end_port+1):
        q.put(p)
    q.join()
    stop_event.set()
    t_spinner.join()
    print(f"{GREEN}[*] TCP Scan Complete.{RESET}")

def udp_scan(host):
    print(f"{YELLOW}[*] Starting UDP Scan on {host} (common ports)...{RESET}")
    q = queue.Queue()
    stop_event = threading.Event()
    t_spinner = threading.Thread(target=spinner_task, args=(stop_event,))
    t_spinner.start()

    def worker():
        while True:
            port = q.get()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(UDP_TIMEOUT)
                s.sendto(b"", (host, port))
                s.recvfrom(1024)
                print(f"{GREEN}[OPEN]{RESET} UDP {port}")
                s.close()
            except:
                pass
            q.task_done()

    for _ in range(THREADS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    for port in COMMON_UDP_PORTS:
        q.put(port)
    q.join()
    stop_event.set()
    t_spinner.join()
    print(f"{GREEN}[*] UDP Scan Complete.{RESET}")

# ======= OTHER FUNCTIONS =======
def grab_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"{GREEN}[IP Address]{RESET} {ip}")
        return ip
    except socket.gaierror:
        print(f"{RED}[ERROR]{RESET} Invalid or unreachable domain: {domain}")
        return None

def web_server_banner(domain):
    try:
        r = requests.head(full_url(domain), timeout=5)
        print(f"{GREEN}[Web Server]{RESET} {r.headers.get('Server', 'Unknown')}")
    except:
        print(f"{RED}[Web Server]{RESET} Could not retrieve.")

def cms_detection(domain):
    try:
        r = requests.get(full_url(domain), timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen:
            print(f"{GREEN}[CMS]{RESET} {gen['content']}")
        elif "wp-content" in r.text:
            print(f"{GREEN}[CMS]{RESET} WordPress detected")
        else:
            print(f"{RED}[CMS]{RESET} Unknown")
    except:
        pass

def cloudflare_detect(domain):
    try:
        r = requests.head(full_url(domain), timeout=5)
        if "cloudflare" in r.headers.get("Server", "").lower():
            print(f"{GREEN}[Cloudflare]{RESET} Yes")
        else:
            print(f"{RED}[Cloudflare]{RESET} No")
    except:
        pass

def robots_txt(domain):
    try:
        r = requests.get(urljoin(full_url(domain), "/robots.txt"), timeout=5)
        if r.status_code == 200:
            print(f"{GREEN}[robots.txt]{RESET}\n{r.text}")
        else:
            print(f"{RED}[robots.txt]{RESET} Not found.")
    except:
        pass

def whois_lookup(domain):
    try:
        r = requests.get(f"https://api.api-ninjas.com/v1/whois?domain={domain}",
                         headers={"X-Api-Key": ""}, timeout=8)
        if r.status_code == 200:
            print(f"{GREEN}[WHOIS]{RESET} {r.text}")
        else:
            print(f"{RED}[WHOIS]{RESET} Lookup failed.")
    except:
        pass

def geo_ip_lookup(ip):
    if not ip:
        print(f"{RED}[Geo-IP]{RESET} Cannot lookup, invalid IP")
        return
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        if data["status"] == "success":
            print(f"{GREEN}[Geo-IP Info]{RESET}")
            print(f" IP       : {data.get('query')}")
            print(f" City     : {data.get('city')}")
            print(f" Region   : {data.get('regionName')}")
            print(f" Country  : {data.get('country')}")
            print(f" ASN      : {data.get('as')}")
            print(f" ISP      : {data.get('isp')}")
            print(f" Lat/Long : {data.get('lat')}, {data.get('lon')}")
            print(f" ZIP      : {data.get('zip')}")
            print(f" Timezone : {data.get('timezone')}")
        else:
            print(f"{RED}[Geo-IP]{RESET} Lookup failed.")
    except:
        print(f"{RED}[Geo-IP]{RESET} Error fetching data.")

def dns_lookup(domain):
    try:
        for rtype in ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]:
            ans = dns.resolver.resolve(domain, rtype)
            for a in ans:
                print(f"{GREEN}{rtype}:{RESET} {a.to_text()}")
    except:
        pass

def sensitive_files(domain):
    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(urljoin(full_url(domain), path), timeout=5)
            if r.status_code == 200:
                print(f"{GREEN}[FOUND]{RESET} {path}")
        except:
            pass

def input_field_scanner(domain):
    try:
        r = requests.get(full_url(domain), timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        inputs = soup.find_all("input")
        print(f"{YELLOW}[Input Fields]{RESET} Found {len(inputs)} fields")
        for i in inputs:
            print(f" - {i}")
    except:
        pass

# ======= MULTITHREADED SUBDOMAIN SCANNER =======
COMMON_SUBDOMAINS = [
    "www","mail","ftp","webmail","ns1","ns2","blog","dev","test","cpanel",
    "admin","shop","api","portal","secure","vpn","support","dashboard",
    "staging","web","owa","mysql","smtp","m","docs","wiki","forum","git",
    "backup","img","cdn","cdn1","cdn2","adminpanel","manager","login",
    "account","auth","backend","control","console","siteadmin","panel",
    "adm","adm1","adm2","www1","www2","www3","mail1","mail2","mail3",
    "joomla","wordpress","wp","shopify","magento","drupal","test1","test2",
    "dev1","dev2","staging1","staging2","files","downloads","upload","images",
    "static","api1","api2","mobile","m1","m2","web1","web2","devops","gitlab",
    "jenkins","bitbucket","docker","k8s","grafana","prometheus","monitor"
]

def subdomain_scanner(domain):
    print(f"{YELLOW}[*] Starting Subdomain Scan on {domain}...{RESET}")
    q = queue.Queue()
    found_count = 0
    lock = threading.Lock()

    def worker():
        nonlocal found_count
        while True:
            sub = q.get()
            if sub is None:
                break
            full = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(full)
                with lock:
                    print(f"{GREEN}[FOUND]{RESET} {full} -> {ip}")
                    found_count += 1
            except:
                pass
            q.task_done()

    for _ in range(SUBDOMAIN_THREADS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    for sub in COMMON_SUBDOMAINS:
        q.put(sub)

    q.join()
    print(f"{GREEN}[*] Subdomain Scan Complete. Total found: {found_count}{RESET}")

# ======= MENU =======
def menu():
    print(f"""{CYAN}
[1]  Port Scanner (TCP)
[2]  UDP Scanner
[3]  IP Address
[4]  Web Server Detection
[5]  CMS Detection
[6]  Cloudflare Detection
[7]  robots.txt
[8]  WHOIS Lookup
[9]  Geo-IP Lookup
[10] DNS Lookup
[11] Sensitive Files
[12] Subdomain Scanner
[13] Input Field Scanner
[99] Scan Everything
[0]  Exit
{RESET}""")

# ======= MAIN =======
def main():
    domain = show_banner_and_input()
    menu()
    choice = input("Select option (0 to exit): ")

    if choice == "0":
        print(f"{CYAN}Exiting...{RESET}")
        return

    ip = None
    if choice in ["3", "9", "99"]:
        ip = grab_ip(domain)
        if ip is None:
            return

    if choice == "1":
        tcp_scan(domain, 1, 65535)
    elif choice == "2":
        udp_scan(domain)
    elif choice == "3":
        grab_ip(domain)
    elif choice == "4":
        web_server_banner(domain)
    elif choice == "5":
        cms_detection(domain)
    elif choice == "6":
        cloudflare_detect(domain)
    elif choice == "7":
        robots_txt(domain)
    elif choice == "8":
        whois_lookup(domain)
    elif choice == "9":
        geo_ip_lookup(ip)
    elif choice == "10":
        dns_lookup(domain)
    elif choice == "11":
        sensitive_files(domain)
    elif choice == "12":
        subdomain_scanner(domain)
    elif choice == "13":
        input_field_scanner(domain)
    elif choice == "99":
        ip = grab_ip(domain)
        if ip is None:
            return
        geo_ip_lookup(ip)
        tcp_scan(domain, 1, 65535)
        udp_scan(domain)
        web_server_banner(domain)
        cms_detection(domain)
        cloudflare_detect(domain)
        robots_txt(domain)
        whois_lookup(domain)
        dns_lookup(domain)
        sensitive_files(domain)
        subdomain_scanner(domain)
        input_field_scanner(domain)
    else:
        print(f"{RED}Invalid choice, exiting.{RESET}")
        return

    # Thank you message after scan
    print(f"\n{GREEN}Thanks for using my scanner! Have a nice day 😊{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{GREEN}Thanks for using my scanner! Have a nice day 😊{RESET}")
        sys.exit()
