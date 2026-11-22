import urllib.request
import base64
import re
import ssl
import subprocess
import os
import json
import socket
from urllib.parse import urlparse, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

TAG_TEXT = "𝑭𝑹𝑬𝑬𝑵𝑬𝑻𝑽𝑻"

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

# تشخیص ایموجی پرچم کشور (Regional Indicator Symbols)
FLAG_REGEX = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

# نگاشت کلمات/کدهای رایج کشور به پرچم در صورت نبود ایموجی مستقیم
COUNTRY_TO_FLAG = {
    "DE": "🇩🇪", "GERMANY": "🇩🇪",
    "US": "🇺🇸", "USA": "🇺🇸", "UNITED STATES": "🇺🇸",
    "NL": "🇳🇱", "NETHERLANDS": "🇳🇱",
    "FR": "🇫🇷", "FRANCE": "🇫🇷",
    "GB": "🇬🇧", "UK": "🇬🇧", "BRITAIN": "🇬🇧", "ENGLAND": "🇬🇧",
    "TR": "🇹🇷", "TURKEY": "🇹🇷",
    "AE": "🇦🇪", "UAE": "🇦🇪", "DUBAI": "🇦🇪",
    "SG": "🇸🇬", "SINGAPORE": "🇸🇬",
    "JP": "🇯🇵", "JAPAN": "🇯🇵",
    "CA": "🇨🇦", "CANADA": "🇨🇦",
    "RU": "🇷🇺", "RUSSIA": "🇷🇺",
    "IR": "🇮🇷", "IRAN": "🇮🇷",
    "FI": "🇫🇮", "FINLAND": "🇫🇮",
    "SE": "🇸🇪", "SWEDEN": "🇸🇪",
    "CH": "🇨🇭", "SWITZERLAND": "🇨🇭",
    "HK": "🇭🇰", "HONG KONG": "🇭🇰",
    "KR": "🇰🇷", "KOREA": "🇰🇷",
    "IN": "🇮🇳", "INDIA": "🇮🇳",
    "AU": "🇦🇺", "AUSTRALIA": "🇦🇺",
    "IT": "🇮🇹", "ITALY": "🇮🇹",
    "ES": "🇪🇸", "SPAIN": "🇪🇸",
    "PL": "🇵🇱", "POLAND": "🇵🇱",
    "AT": "🇦🇹", "AUSTRIA": "🇦🇹",
    "NO": "🇳🇴", "NORWAY": "🇳🇴",
}

MAX_DELAY_MS = 2200


def detect_flag(raw_label: str) -> str:
    """استخراج پرچم موجود یا تشخیص پرچم از نام/کد کشور؛ در صورت نبودن، بازگرداندن 🌐"""
    decoded_label = unquote(raw_label or "")
    flags = FLAG_REGEX.findall(decoded_label)
    if flags:
        return flags[0]

    upper_text = decoded_label.upper()
    for key, emoji in COUNTRY_TO_FLAG.items():
        if re.search(rf'(?<![A-Z0-9]){re.escape(key)}(?![A-Z0-9])', upper_text):
            return emoji

    return "🌐"


def format_tag(flag: str) -> str:
    return f"{flag} {TAG_TEXT}".strip()


def apply_custom_tag(config: str) -> str:
    """اعمال تگ 𝑭𝑹𝑬𝑬𝑵𝑬𝑻𝑽𝑻 با حفظ پرچم/لوکیشن کانفیگ"""
    config = config.strip()
    lower = config.lower()

    # ۱. حالت ویژه VMess (ساختار JSON در بخش بعد از vmess://)
    if lower.startswith("vmess://"):
        try:
            body_and_frag = config[8:]
            parts = body_and_frag.split("#", 1)
            frag = parts[1] if len(parts) > 1 else ""
            raw_b64 = re.sub(r'\s+', '', parts[0])
            missing = len(raw_b64) % 4
            if missing:
                raw_b64 += "=" * (4 - missing)
            decoded_json = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
            data = json.loads(decoded_json)
            if isinstance(data, dict):
                old_ps = str(data.get("ps", "")) or frag
                flag = detect_flag(old_ps)
                data["ps"] = format_tag(flag)
                new_b64 = base64.b64encode(
                    json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                ).decode("utf-8")
                return f"vmess://{new_b64}"
        except Exception:
            pass

    # ۲. سایر لینک‌ها (VLESS, Trojan, SS, SSR, Hysteria2, TUIC, Socks, HTTP و...)
    base_part = config.split("#", 1)[0]
    old_frag = config.split("#", 1)[1] if "#" in config else ""
    flag = detect_flag(old_frag if old_frag else base_part)
    new_tag = quote(format_tag(flag), safe=" ")
    return f"{base_part}#{new_tag}"


def find_knife_binary():
    for root, _, files in os.walk("."):
        for fname in files:
            low = fname.lower()
            if "xray-knife" in low and not low.endswith((".zip", ".txt", ".md", ".json", ".sha256", ".dgst")):
                full_path = os.path.join(root, fname)
                os.chmod(full_path, 0o755)
                return full_path
    return None


def decode_base64_safe(data):
    try:
        cleaned = re.sub(r'\s+', '', data)
        missing_padding = len(cleaned) % 4
        if missing_padding:
            cleaned += '=' * (4 - missing_padding)
        return base64.b64decode(cleaned).decode('utf-8', errors='ignore')
    except Exception:
        return ""


def fetch_url(url):
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
            return url, response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[WARN] Fetch failed for {url}: {e}")
        return url, ""


def is_valid_format(line):
    lower_line = line.lower()
    if lower_line.startswith(("http://", "https://")):
        if "@" not in line and not re.search(r':\d{2,5}$', line.split('#')[0]):
            return False
    return lower_line.startswith(ALL_PROTOCOLS)


def extract_host_port(config):
    try:
        lower = config.lower()
        if lower.startswith("vmess://"):
            b64_part = config[8:].split("#")[0].strip()
            data = json.loads(decode_base64_safe(b64_part))
            return data.get("add"), int(data.get("port", 0))
        if lower.startswith("ss://") and "@" not in config.split("#")[0]:
            decoded = decode_base64_safe(config[5:].split("#")[0].strip())
            if "@" in decoded:
                host, port = decoded.split("@")[-1].rsplit(":", 1)
                return host.strip("[]"), int(port)
        parsed = urlparse(config)
        port = parsed.port or (443 if lower.startswith("https://") else (80 if lower.startswith("http://") else None))
        return parsed.hostname, int(port) if port else None
    except Exception:
        return None, None


def check_tcp_health(config, timeout=2.5):
    lower = config.lower()
    if lower.startswith(("hysteria://", "hysteria2://", "hy2://", "tuic://")):
        return config, True
    host, port = extract_host_port(config)
    if not host or not port:
        return config, False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return config, True
    except Exception:
        return config, False


def save_sub_files(base_path, configs_list):
    text_data = "\n".join(configs_list)
    with open(f"{base_path}.txt", "w", encoding="utf-8") as f:
        f.write(text_data)

    b64_data = base64.b64encode(text_data.encode("utf-8")).decode("utf-8")
    with open(f"{base_path}_b64.txt", "w", encoding="utf-8") as f:
        f.write(b64_data)


def main():
    if not os.path.exists("sources.txt"):
        print("[ERROR] sources.txt not found!")
        return

    with open("sources.txt", "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    urls = list(dict.fromkeys(urls))
    print(f"[INFO] Fetching {len(urls)} unique source URLs in parallel...")

    raw_configs = set()

    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = [executor.submit(fetch_url, u) for u in urls]
        for future in as_completed(futures):
            url, raw_content = future.result()
            if not raw_content:
                continue

            decoded_content = decode_base64_safe(raw_content)
            combined_text = raw_content + "\n" + decoded_content

            before_count = len(raw_configs)
            for line in combined_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                for match in CONFIG_PATTERN.findall(line):
                    clean_config = match.strip()
                    if is_valid_format(clean_config):
                        raw_configs.add(clean_config)
            added = len(raw_configs) - before_count
            if added > 0:
                print(f"[INFO] +{added} from {url}")

    print(f"[INFO] Total unique configs extracted: {len(raw_configs)}")

    proxy_configs = [c for c in raw_configs if c.lower().startswith(("socks://", "socks5://", "http://", "https://"))]
    xray_configs = [c for c in raw_configs if c not in proxy_configs]
    alive_configs = []

    knife_bin = find_knife_binary()
    if knife_bin and xray_configs:
        sample_to_test = xray_configs[:1500]
        print(f"[INFO] Running Real Delay test via {knife_bin} on {len(sample_to_test)} configs...")
        with open("temp_raw.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(sample_to_test))

        cmd = [
            knife_bin, "http",
            "-f", "temp_raw.txt",
            "-o", "valid_xray.txt",
            "-t", "60",
            "-m", str(MAX_DELAY_MS),
            "-u", "http://www.gstatic.com/generate_204",
            "-s"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        print(f"[INFO] xray-knife exit code: {res.returncode}")

        if os.path.exists("valid_xray.txt"):
            with open("valid_xray.txt", "r", encoding="utf-8") as f:
                alive_configs = [line.strip() for line in f if line.strip()]
            os.remove("valid_xray.txt")

        if os.path.exists("temp_raw.txt"):
            os.remove("temp_raw.txt")

    if not alive_configs and xray_configs:
        print("[INFO] Running TCP health check fallback...")
        with ThreadPoolExecutor(max_workers=80) as executor:
            futures = {executor.submit(check_tcp_health, cfg): cfg for cfg in xray_configs[:1500]}
            for future in as_completed(futures):
                cfg, is_alive = future.result()
                if is_alive:
                    alive_configs.append(cfg)

    if not alive_configs and xray_configs:
        print("[WARN] Keeping extracted configs as fallback so files are not empty.")
        alive_configs = xray_configs[:800]

    combined_alive = alive_configs + sorted(proxy_configs)

    # اعمال تگ 𝑭𝑹𝑬𝑬𝑵𝑬𝑻𝑽𝑻 با حفظ پرچم/لوکیشن و حذف موارد تکراری احتمالی پس از تغییر نام
    tagged_configs = list(dict.fromkeys(apply_custom_tag(c) for c in combined_alive))

    save_sub_files("sub", tagged_configs)
    os.makedirs("protocols", exist_ok=True)
    for group_name, prefixes in PROTOCOL_GROUPS.items():
        group_configs = [c for c in tagged_configs if c.lower().startswith(prefixes)]
        save_sub_files(f"protocols/{group_name}", group_configs)
        print(f"[INFO] protocols/{group_name}.txt -> {len(group_configs)} configs")

    print(f"[DONE] Total tagged configs saved in sub.txt: {len(tagged_configs)}")


if __name__ == "__main__":
    main()
