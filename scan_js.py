import re
import sys
import requests

js_list = sys.argv[1]

tokens_file = open("output/tokens.txt", "a", encoding="utf-8")
subs_file = open("output/subdomains.txt", "a", encoding="utf-8")
endpoints_file = open("output/endpoints.txt", "a", encoding="utf-8")
sensitive_file = open("output/sensitive_data.txt", "a", encoding="utf-8")

# Regex
TOKEN_REGEX = re.compile(
    r'(api[_-]?key|access[_-]?token|auth|authorization|secret)'
    r'[\s\'":=]+([A-Za-z0-9_\-\.=]{8,})', re.I
)

ENDPOINT_REGEX = re.compile(
    r'["\'](\/api\/[^"\']+|https?:\/\/[^"\']+)["\']'
)

SUBDOMAIN_REGEX = re.compile(
    r'https?:\/\/([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})'
)

SENSITIVE_REGEX = re.compile(
    r'(password|passwd|pwd|private[_-]?key|client[_-]?secret)'
    r'[\s\'":=]+([^\'"\s]+)', re.I
)

# JS content indicators
JS_KEYWORDS = ["function", "=>", "var ", "let ", "const ", "window.", "document."]

def is_javascript(resp):
    content_type = resp.headers.get("Content-Type", "").lower()
    if "javascript" in content_type:
        return True

    body = resp.text.lower()
    return any(k in body for k in JS_KEYWORDS)

with open(js_list) as f:
    for url in f:
        url = url.strip()
        if not url:
            continue

        try:
            resp = requests.get(url, timeout=15)
        except Exception:
            print(f"[!] Failed: {url}")
            continue

        # ✅ Bypass .js check
        if not is_javascript(resp):
            print(f"[-] Not JS content: {url}")
            continue

        content = resp.text

        for m in TOKEN_REGEX.findall(content):
            tokens_file.write(f"{url} => {m[0]} : {m[1]}\n")

        for m in SENSITIVE_REGEX.findall(content):
            sensitive_file.write(f"{url} => {m[0]} : {m[1]}\n")

        for m in ENDPOINT_REGEX.findall(content):
            endpoints_file.write(f"{url} => {m}\n")

        for m in SUBDOMAIN_REGEX.findall(content):
            subs_file.write(f"{url} => {m}\n")

tokens_file.close()
subs_file.close()
endpoints_file.close()
sensitive_file.close()

print("[+] Scan completed (JS bypass enabled)")
