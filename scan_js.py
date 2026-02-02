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
    "Accept": "*/*"
}

# Token patterns (strong but safe)
TOKEN_PATTERNS = [
    r"AIza[0-9A-Za-z\-_]{35}",                     # Google API
    r"ya29\.[0-9A-Za-z\-_]+",                      # Google OAuth
    r"AKIA[0-9A-Z]{16}",                           # AWS Access Key
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}", # JWT
    r"(?i)(api[_-]?key|secret|token|password)[\"'\s:=]+[A-Za-z0-9_\-]{8,}"
]

TOKEN_REGEX = re.compile("|".join(TOKEN_PATTERNS))

# =========================
# Helpers
# =========================
def ensure_output():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

def write_line(filename, line):
    with open(os.path.join(OUTPUT_DIR, filename), "a", encoding="utf-8") as f:
        f.write(line + "\n")

def get_domains():
    raw = os.getenv("DOMAINS")
    if not raw:
        print("[!] DOMAINS env not set")
        exit(1)

    raw = raw.replace(",", " ")
    return sorted(set(d.strip() for d in raw.split() if d.strip()))

# =========================
# Wayback
# =========================
def fetch_wayback(domain):
    print(f"[+] Fetching Wayback URLs for {domain}")

    r = requests.get(
        WAYBACK_URL,
        headers=HEADERS,
        params={
            "url": f"{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey"
        },
        timeout=60
    )

    r.raise_for_status()
    data = r.json()
    return [row[0] for row in data[1:] if row and row[0].endswith(".js")]

# =========================
# JS Downloader + Scanner
# =========================
def scan_js_file(js_url, domain):
    try:
        r = requests.get(js_url, headers=HEADERS, timeout=30)
        if r.status_code != 200 or len(r.text) < 20:
            return

        matches = TOKEN_REGEX.findall(r.text)
        for match in matches:
            token = match if isinstance(match, str) else match[0]
            write_line(
                f"{domain}_tokens.txt",
                f"[{token}] => {js_url}"
            )

    except Exception:
        pass

# =========================
# Main
# =========================
def main():
    ensure_output()
    domains = get_domains()

    for domain in domains:
        print(f"\n=== Scanning domain: {domain} ===")

        try:
            js_files = fetch_wayback(domain)
            print(f"[+] JS files found: {len(js_files)}")

            for js in js_files:
                scan_js_file(js, domain)

        except Exception as e:
            print(f"[!] Error with {domain}: {e}")

    print("\n[✓] Token scanning completed")

if __name__ == "__main__":
    main()
