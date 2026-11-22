import urllib.request
import base64
import re
import ssl
import subprocess
import os

# نادیده گرفتن خطاهای گواهی SSL
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# دسته‌بندی پروتکل‌ها و پیشوندهای مربوط به هر فایل
PROTOCOL_GROUPS = {
    "vless": ("vless://",),
    "vmess": ("vmess://",),
    "trojan": ("trojan://",),
    "hysteria": ("hysteria://", "hysteria2://", "hy2://"),
    "shadowsocks": ("ss://", "ssr://"),
    "tuic": ("tuic://",),
    "socks": ("socks://", "socks5://"),
    "http": ("http://", "https://")
}

ALL_PROTOCOLS = tuple(p for group in PROTOCOL_GROUPS.values() for p in group)

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
    return lower_line.startswith(ALL_PROTOCOLS)

def save_sub_files(base_path, configs_list):
    """ذخیره هم‌زمان نسخه متنی ساده و نسخه Base64 برای هر فایل"""
    text_data = "\n".join(configs_list)
    with open(f"{base_path}.txt", "w", encoding="utf-8") as f:
        f.write(text_data)

    b64_data = base64.b64encode(text_data.encode("utf-8")).decode("utf-8")
    with open(f"{base_path}_b64.txt", "w", encoding="utf-8") as f:
        f.write(b64_data)

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

    # تفکیک پروکسی‌های ساده از کانفیگ‌های قابل تست با Xray-knife
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

    # ۱. ذخیره فایل تجمیعی کل سرورها (sub.txt و sub_b64.txt)
    save_sub_files("sub", final_list)

    # ۲. ساخت پوشه protocols و ذخیره فایل جداگانه برای هر پروتکل
    os.makedirs("protocols", exist_ok=True)
    for group_name, prefixes in PROTOCOL_GROUPS.items():
        group_configs = [c for c in final_list if c.lower().startswith(prefixes)]
        save_sub_files(f"protocols/{group_name}", group_configs)
        print(f"Saved {len(group_configs)} configs to protocols/{group_name}.txt")

    print(f"Done! Total healthy configs: {len(final_list)}")

if __name__ == "__main__":
    main()
