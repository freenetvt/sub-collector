import urllib.request
import urllib.parse
import base64
import re
import ssl
import subprocess
import os
import glob
import json
import socket
from urllib.parse import urlparse, unquote, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

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

MAX_DELAY_MS = 3000
TAG_TEXT = "𝑭𝑹𝑬𝑬𝑵𝑬𝑻𝑽𝑻"
FLAG_PATTERN = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

def extract_flag_or_location(label):
    if not label:
        return ""
    decoded = unquote(label).strip()
    flags = FLAG_PATTERN.findall(decoded)
    if flags:
        return " ".join(flags)
    code_match = re.search(r'\b([A-Z]{2})\b', decoded)
    if code_match:
        return code_match.group(1)
    return ""

def tag_config(config):
    try:
        config = config.strip()
        lower = config.lower()
        if lower.startswith("vmess://"):
            b64_part = config[8:].split("#")[0].strip()
            raw_json = decode_base64_safe(b64_part)
            data = json.loads(raw_json)
            existing_ps = str(data.get("ps", ""))
            loc = extract_flag_or_location(existing_ps)
            data["ps"] = f"{loc} {TAG_TEXT}".strip() if loc else TAG_TEXT
            new_b64 = base64.b64encode(json.dumps(data, ensure_ascii=False).encode("utf-8")).decode("utf-8")
            return f"vmess://{new_b64}"

        base_part, _, frag_part = config.partition("#")
        loc = extract_flag_or_location(frag_part)
        new_label = f"{loc} {TAG_TEXT}".strip() if loc else TAG_TEXT
        return f"{base_part}#{quote(new_label, safe='')}"
    except Exception:
        return config

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
        with urllib.request.urlopen(req, timeout=25, context=ctx) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[WARN] Fetch failed for {url}: {e}")
        return ""

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

def check_tcp_health(config, timeout=3):
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

    print(f"[INFO] Loaded {len(urls)} URLs from sources.txt")
    raw_configs = set()

    for url in urls:
        raw_content = fetch_url(url)
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
        print(f"[INFO] {url} -> +{len(raw_configs) - before_count} configs")

    print(f"[INFO] Total unique configs extracted: {len(raw_configs)}")

    proxy_configs = [c for c in raw_configs if c.lower().startswith(("socks://", "socks5://", "http://", "https://"))]
    xray_configs = [c for c in raw_configs if c not in proxy_configs]
    alive_configs = []

    knife_bins = [f for f in glob.glob("Xray-knife*") if os.path.isfile(f)]
    print(f"[INFO] Found Xray-knife binaries: {knife_bins}")

    if knife_bins and xray_configs:
        knife_bin = f"./{knife_bins[0]}"
        sample_to_test = xray_configs[:1500]
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
        print(f"[INFO] Xray-knife returncode: {res.returncode}")
        if res.stdout:
            print("[Xray-knife stdout]:", res.stdout[-500:])
        if res.stderr:
            print("[Xray-knife stderr]:", res.stderr[-500:])

        if os.path.exists("valid_xray.txt"):
            with open("valid_xray.txt", "r", encoding="utf-8") as f:
                alive_configs = [line.strip() for line in f if line.strip()]
            os.remove("valid_xray.txt")

        if os.path.exists("temp_raw.txt"):
            os.remove("temp_raw.txt")

    print(f"[INFO] Alive configs after Xray-knife: {len(alive_configs)}")

    if not alive_configs and xray_configs:
        print("[INFO] Fallback to TCP check...")
        with ThreadPoolExecutor(max_workers=60) as executor:
            futures = {executor.submit(check_tcp_health, cfg): cfg for cfg in xray_configs[:1500]}
            for future in as_completed(futures):
                cfg, is_alive = future.result()
                if is_alive:
                    alive_configs.append(cfg)
        print(f"[INFO] Alive configs after TCP check: {len(alive_configs)}")

    if not alive_configs and xray_configs:
        print("[WARN] Keeping raw extracted configs as fallback so output is not empty.")
        alive_configs = xray_configs[:500]

    tagged_alive = [tag_config(c) for c in alive_configs]
    tagged_proxies = [tag_config(c) for c in sorted(proxy_configs)]
    final_list = tagged_alive + tagged_proxies

    save_sub_files("sub", final_list)
    os.makedirs("protocols", exist_ok=True)
    for group_name, prefixes in PROTOCOL_GROUPS.items():
        group_configs = [c for c in final_list if c.lower().startswith(prefixes)]
        save_sub_files(f"protocols/{group_name}", group_configs)
        print(f"[INFO] protocols/{group_name}.txt -> {len(group_configs)} configs")

    print(f"[DONE] Total configs in sub.txt: {len(final_list)}")

if __name__ == "__main__":
    main()
