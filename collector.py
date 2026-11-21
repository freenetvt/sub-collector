import urllib.request
import base64
import re
import ssl
import subprocess
import os

# نادیده گرفتن خطاهای گواهی SSL برخی سرورها
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# پروتکل‌های پشتیبانی‌شده
PROTOCOLS = (
    "vless://",
    "vmess://",
    "trojan://",
    "hysteria://",
    "hysteria2://",
    "hy2://",
    "ss://",
    "ssr://",
    "tuic://",
    "socks://",
    "socks5://",
    "http://",
    "https://"
)

# الگوی استخراج کانفیگ‌ها از متن و صفحات وب
CONFIG_PATTERN = re.compile(
    r'(?:vless|vmess|trojan|hysteria2?|hy2|ssr?|tuic|socks5?|https?)://[^\s<>"\'`]+',
    re.IGNORECASE
)

# حداکثر تأخیر مجاز (1800 میلی‌ثانیه = 1.8 ثانیه)
MAX_DELAY_MS = 1800

def decode_base64_safe(data):
    try:
        data = data.strip()
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return data

def fetch_url(url):
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=20, context=ctx) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return ""

def is_valid_format(line):
    lower_line = line.lower()
    if lower_line.startswith(("http://", "https://")):
        if "@" not in line and not re.search(r':\d{2,5}$', line.split('#')[0]):
            return False
    return lower_line.startswith(PROTOCOLS)

def main():
    if not os.path.exists("sources.txt"):
        print("sources.txt not found!")
        return

    with open("sources.txt", "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    raw_configs = set()

    for url in urls:
        print(f"Fetching: {url}")
        raw_content = fetch_url(url)
        if not raw_content:
            continue

        decoded_content = decode_base64_safe(raw_content)
        combined_text = raw_content + "\n" + decoded_content

        matches = CONFIG_PATTERN.findall(combined_text)
        for match in matches:
            clean_config = match.strip()
            if is_valid_format(clean_config):
                raw_configs.add(clean_config)

    print(f"Total unique configs extracted: {len(raw_configs)}")

    # تفکیک پروکسی‌های ساده (socks/http) از پروتکل‌های هسته Xray/Sing-box
    proxy_configs = [c for c in raw_configs if c.lower().startswith(("socks://", "socks5://", "http://", "https://"))]
    xray_configs = [c for c in raw_configs if c not in proxy_configs]

    with open("temp_raw.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(xray_configs))

    alive_configs = []

    if os.path.exists("./Xray-knife") and xray_configs:
        print("Running Real Delay test via Xray-knife...")
        cmd = [
            "./Xray-knife", "http",
            "-f", "temp_raw.txt",
            "-o", "valid_xray.txt",
            "-t", "50",
            "-m", str(MAX_DELAY_MS),
            "-u", "http://www.gstatic.com/generate_204",
            "-s"
        ]
        subprocess.run(cmd, check=False)

        if os.path.exists("valid_xray.txt"):
            with open("valid_xray.txt", "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        alive_configs.append(line)
            os.remove("valid_xray.txt")
    else:
        alive_configs.extend(xray_configs)

    if os.path.exists("temp_raw.txt"):
        os.remove("temp_raw.txt")

    final_list = alive_configs + sorted(proxy_configs)
    final_text = "\n".join(final_list)

    # ذخیره نسخه متنی ساده
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(final_text)

    # ذخیره نسخه Base64
    b64_encoded = base64.b64encode(final_text.encode("utf-8")).decode("utf-8")
    with open("sub_b64.txt", "w", encoding="utf-8") as f:
        f.write(b64_encoded)

    print(f"Done! Healthy configs saved: {len(final_list)}")

if __name__ == "__main__":
    main()
