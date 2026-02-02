#!/usr/bin/env python3
import os
import re
import requests
from urllib.parse import urlparse

# =========================
# Config
# =========================
OUTPUT_DIR = "output"
WAYBACK_URL = "https://web.archive.org/cdx/search/cdx"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (BugBounty-JS-Scanner)",
    "Accept": "application/json"
}

TOKEN_REGEX = re.compile(
    r"(api[_-]?key|secret|token|authorization|bearer|jwt|aws[_-]?access[_-]?key)",
    re.IGNORECASE
)

ENDPOINT_REGEX = re.compile(
    r"(\/api\/[a-zA-Z0-9_\-\/]+|\/v\d+\/[a-zA-Z0-9_\-\/]+)"
)

# =========================
# Helpers
# =========================
def ensure_output():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

def write_file(filename, data):
    with open(os.path.join(OUTPUT_DIR, filename), "a", encoding="utf-8") as f:
        for line in sorted(set(data)):
            f.write(line + "\n")

def get_domains():
    raw = os.getenv("DOMAINS")
    if not raw:
        print("[!] DOMAINS env not set")
        exit(1)

    raw = raw.replace(",", " ")
    domains = [d.strip() for d in raw.split() if d.strip()]
    return sorted(set(domains))

# =========================
# Wayback
# =========================
def fetch_wayback(domain):
    print(f"[+] Wayback: {domain}")

    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey"
    }

    r = requests.get(WAYBACK_URL, headers=HEADERS, params=params, timeout=60)
    r.raise_for_status()

    data = r.json()
    return [row[0] for row in data[1:] if row]

# =========================
# Analysis
# =========================
def analyze(domain, urls):
    js_files = []
    endpoints = []
    tokens = []
    subdomains = []

    for url in urls:
        parsed = urlparse(url)

        if parsed.hostname:
            subdomains.append(parsed.hostname)

        if parsed.path.endswith(".js"):
            js_files.append(f"[{domain}] {url}")

        for ep in ENDPOINT_REGEX.findall(url):
            endpoints.append(f"[{domain}] {ep}")

        for tk in TOKEN_REGEX.findall(url):
            tokens.append(f"[{tk.upper()}] => {url}")

    write_file(f"{domain}_urls.txt", urls)
    write_file(f"{domain}_js_files.txt", js_files)
    write_file(f"{domain}_endpoints.txt", endpoints)
    write_file(f"{domain}_secrets.txt", tokens)
    write_file(f"{domain}_subdomains.txt", subdomains)

# =========================
# Main
# =========================
def main():
    ensure_output()
    domains = get_domains()

    for domain in domains:
        try:
            urls = fetch_wayback(domain)
            analyze(domain, urls)
        except Exception as e:
            print(f"[!] Error with {domain}: {e}")

    print("\n[+] Scan finished for all domains")

if __name__ == "__main__":
    main()
