import re
import sys
import requests

if len(sys.argv) != 2:
    print("Usage: python scan_js.py urls.txt")
    sys.exit(1)

URL_LIST = sys.argv[1]

# Output files
tokens_file = open("output/tokens.txt", "a", encoding="utf-8")
subs_file = open("output/subdomains.txt", "a", encoding="utf-8")
endpoints_file = open("output/endpoints.txt", "a", encoding="utf-8")
sensitive_file = open("output/sensitive_data.txt", "a", encoding="utf-8")

# ================== REGEX ==================

TOKEN_REGEX = re.compile(
    r'(api[_-]?key|access[_-]?token|auth|authorization|secret|bearer)'
    r'[\s\'":=]+([A-Za-z0-9_\-\.=]{8,})',
    re.I
)

SENSITIVE_REGEX = re.compile(
    r'(password|passwd|pwd|private[_-]?key|client[_-]?secret)'
    r'[\s\'":=]+([^\'"\s]+)',
    re.I
)

ENDPOINT_REGEX = re.compile(
    r'["\'](\/api\/[^"\']+|https?:\/\/[^"\']+)["\']'
)

SUBDOMAIN_REGEX = re.compile(
    r'https?:\/\/([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})'
)

JS_KEYWORDS = ["function", "=>", "var ", "let ", "const ", "window.", "document."]

# ================== HELPERS ==================

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

# ================== MAIN ==================

with open(URL_LIST, "r", encoding="utf-8") as f:
    for url in f:
        url = url.strip()
        if not url:
            continue

        try:
            resp = requests.get(url, timeout=15, verify=False)
        except Exception:
            print(f"[!] Failed: {url}")
            continue

        file_type = detect_type(resp)
        if not file_type:
            print(f"[-] Skipped (not JS/JSON): {url}")
            continue

        content = resp.text
        src = f"[{file_type}] {url}"

        # Tokens
        for m in TOKEN_REGEX.findall(content):
            tokens_file.write(f"{src} => {m[0]} : {m[1]}\n")

        # Sensitive data
        for m in SENSITIVE_REGEX.findall(content):
            sensitive_file.write(f"{src} => {m[0]} : {m[1]}\n")

        # Endpoints
        for m in ENDPOINT_REGEX.findall(content):
            endpoints_file.write(f"{src} => {m}\n")

        # Subdomains
        for m in SUBDOMAIN_REGEX.findall(content):
            subs_file.write(f"{src} => {m}\n")

        print(f"[+] Scanned {file_type}: {url}")

tokens_file.close()
subs_file.close()
endpoints_file.close()
sensitive_file.close()

print("\n[✔] Scan completed successfully")
