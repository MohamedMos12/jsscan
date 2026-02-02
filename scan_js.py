import re
import json
import requests
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= USER INPUT =================

print("[*] Enter domain(s) (space or newline separated)")
print("[*] Example: example.com test.com\n")

user_input = []
while True:
    try:
        line = input()
        if not line.strip():
            break
        user_input.extend(line.strip().split())
    except EOFError:
        break

if not user_input:
    print("[-] No domains provided")
    exit(1)

DOMAINS = list(set(user_input))

# ================= OUTPUT =================

os.makedirs("output", exist_ok=True)

tokens_file = open("output/tokens.txt", "a", encoding="utf-8")
subs_file = open("output/subdomains.txt", "a", encoding="utf-8")
endpoints_file = open("output/endpoints.txt", "a", encoding="utf-8")
sensitive_file = open("output/sensitive_data.txt", "a", encoding="utf-8")
urls_file = open("output/collected_urls.txt", "a", encoding="utf-8")

# ================= REGEX =================

TOKEN_REGEX = re.compile(
    r'(api[_-]?key|access[_-]?token|authorization|bearer|secret)'
    r'[\s\'":=]+([A-Za-z0-9_\-\.=]{8,})', re.I
)

SENSITIVE_REGEX = re.compile(
    r'(password|passwd|pwd|private[_-]?key|client[_-]?secret)'
    r'[\s\'":=]+([^\'"\s]+)', re.I
)

ENDPOINT_REGEX = re.compile(
    r'["\'](\/api\/[^"\']+|https?:\/\/[^"\']+)["\']'
)

SUBDOMAIN_REGEX = re.compile(
    r'https?:\/\/([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})'
)

JS_KEYWORDS = ["function", "=>", "var ", "let ", "const ", "window.", "document."]

# ================= HELPERS =================

def detect_type(resp):
    ct = resp.headers.get("Content-Type", "").lower()
    if "javascript" in ct:
        return "JS"
    if "json" in ct:
        return "JSON"
    body = resp.text.lower()
    if any(k in body for k in JS_KEYWORDS):
        return "JS"
    return None

def wayback_urls(domain):
    url = f"https://web.archive.org/cdx/search/cdx?url={domain}*&output=json&fl=original&collapse=urlkey"
    try:
        r = requests.get(url, timeout=30)
        data = json.loads(r.text)
        return {row[0] for row in data[1:]}
    except Exception:
        return set()

def interesting_file(url):
    exts = (
        ".js", ".json", ".env", ".config", ".conf",
        ".bak", ".backup", ".old", ".sql", ".yml", ".yaml"
    )
    return url.lower().endswith(exts)

# ================= MAIN =================

all_urls = set()

for domain in DOMAINS:
    print(f"[+] Collecting from Wayback: {domain}")
    urls = wayback_urls(domain)
    for u in urls:
        if interesting_file(u):
            all_urls.add(u)

print(f"[+] Total collected URLs: {len(all_urls)}")

for url in sorted(all_urls):
    urls_file.write(url + "\n")

    try:
        resp = requests.get(url, timeout=20, verify=False)
    except Exception:
