#!/usr/bin/env python3
import os
import re
import json
import requests
from urllib.parse import urlparse

# =========================
# Config
# =========================
OUTPUT_DIR = "output"
WAYBACK_URL = "https://web.archive.org/cdx/search/cdx"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
    "Accept": "application/json"
}

TOKEN_REGEX = re.compile(
    r"(api[_-]?key|secret|token|authorization|bearer|aws[_-]?access[_-]?key)",
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

def write_file(name, data):
    path = os.path.join(OUTPUT_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        for item in sorted(set(data)):
            f.write(item + "\n")

def get_domain():
    domain = os.getenv("DOMAIN")
    if not domain:
        print("[!] DOMAIN env not set")
        exit(1)
    return domain.strip()

# =========================
# Wayback Fetch
# =========================
def fetch_wayback_urls(domain):
    print(f"[+] Fetching Wayback URLs for: {domain}")

    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey"
    }

    r = requests.get(WAYBACK_URL, params=params, headers=HEADERS, timeout=60)
    r.raise_for_status()

    data = r.json()
    urls = [row[0] for row in data[1:] if row]
    print(f"[+] Collected {len(urls)} URLs")
    return urls

# =========================
# Analysis
# =========================
def analyze_urls(urls):
    js_files = []
    endpoints = []
    tokens = []
    subdomains = []

    for url in urls:
        parsed = urlparse(url)

        # Subdomains
        if parsed.hostname:
            subdomains.append(parsed.hostname)

        # JS files
        if parsed.path.endswith(".js"):
            js_files.append(url)

        # Endpoints
        for ep in ENDPOINT_REGEX.findall(url):
            endpoints.append(ep)

        # Tokens
        for tk in TOKEN_REGEX.findall(url):
            tokens.append(f"{tk} => {url}")

    return js_files, endpoints, tokens, subdomains

# =========================
# Main
# =========================
def main():
    ensure_output()

    domain = get_domain()
    urls = fetch_wayback_urls(domain)

    js_files, endpoints, tokens, subdomains = analyze_urls(urls)

    write_file("collected_urls.txt", urls)
    write_file("js_files.txt", js_files)
    write_file("endpoints.txt", endpoints)
    write_file("tokens.txt", tokens)
    write_file("subdomains.txt", subdomains)

    print("\n[+] Scan completed successfully")
    print(f"    URLs       : {len(urls)}")
    print(f"    JS files   : {len(js_files)}")
    print(f"    Endpoints  : {len(endpoints)}")
    print(f"    Tokens     : {len(tokens)}")
    print(f"    Subdomains : {len(subdomains)}")
    print(f"\n[+] Results saved in ./{OUTPUT_DIR}/")

if __name__ == "__main__":
    main()
