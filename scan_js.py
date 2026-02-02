import re
import json
import requests
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= USER INPUT =================
domain = input("Enter domain: ").strip()

if not domain:
    print("[-] No domain provided")
    exit(1)

print(f"[+] Target domain: {domain}")

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
    return url.lower().endswith((
        ".js", ".json", ".env", ".config", ".conf",
        ".bak", ".backup", ".old", ".sql", ".yml", ".yaml"
    ))

# ================= MAIN =================
print("[+] Collecting URLs from Wayback...")
all_urls = set()

for u in wayback_urls(domain):
    if interesting_file(u):
        all_urls.add(u)

print(f"[+] Total collected URLs: {len(all_urls)}")

for url in sorted(all_urls):
    urls_file.write(url + "\n")

    try:
        resp = requests.get(url, timeout=20, verify=False)
    except Exception:
        continue

    file_type = detect_type(resp)
    if not file_type:
        continue

    content = resp.text
    src = f"[{file_type}] {url}"

    for m in TOKEN_REGEX.findall(content):
        tokens_file.write(f"{src} => {m[0]} : {m[1]}\n")

    for m in SENSITIVE_REGEX.findall(content):
        sensitive_file.write(f"{src} => {m[0]} : {m[1]}\n")

    for m in ENDPOINT_REGEX.findall(content):
        endpoints_file.write(f"{src} => {m}\n")

    for m in SUBDOMAIN_REGEX.findall(content):
        subs_file.write(f"{src} => {m}\n")

    print(f"[✓] Scanned {file_type}: {url}")

tokens_file.close()
subs_file.close()
endpoints_file.close()
sensitive_file.close()
urls_file.close()

print("\n[✔] Scan completed successfully")
