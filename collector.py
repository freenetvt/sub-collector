import base64
import json
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import unquote, urlparse

SUB_URLS = [
    "https://sub.plenix.cyou/",
    "https://shadowmere.xyz/api/b64sub/",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_base64_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub4.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub5.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub6.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub7.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub8.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub9.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub10.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub11.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub12.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub13.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub14.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub15.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub16.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Base64/Sub1_base64.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Base64/Sub2_base64.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Base64/Sub3_base64.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Base64/Sub4_base64.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Base64/Sub5_base64.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Subscribes/sub1.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Subscribes/sub2.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Subscribes/sub3.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Subscribes/sub4.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Subscribes/sub5.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/base64/all_sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub1.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub2.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub3.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub4.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub5.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/main/output/main_top100_checked.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/main/output_iran/iran_top100.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/main/output_iran/mci_top100.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/main/output_iran/irancell_top100.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/main/output_iran/tci_top100.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/sub.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Mix/mix.txt",
    "https://raw.githubusercontent.com/10ium/V2Hub3/main/merged_base64",
    "https://raw.githubusercontent.com/10ium/free-config/main/HighSpeed.txt",
    "https://raw.githubusercontent.com/10ium/base64-encoder/main/encoded/10ium_mixed_iran.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/configtg.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/archives/latest_backup/mixed",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs_base64.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/main/v2ray.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/main/sub/proxies.txt",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/a11",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/static/sub_en",
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/config.txt",
    "https://raw.githubusercontent.com/Freedom-Guard-Builder/Freedom-Finder/main/out/configs/all.txt",
    "https://raw.githubusercontent.com/Freedom-Guard-Builder/Freedom-Finder/main/out/configs/mixed.txt",
    "https://raw.githubusercontent.com/Freedom-Guard-Builder/Freedom-Finder/main/out/channels/v2rayAggregator.txt",
    "https://raw.githubusercontent.com/MahanKenway/Pusheen-V2Ray/main/subscriptions/all.txt",
    "https://raw.githubusercontent.com/MahanKenway/Pusheen-V2Ray/main/subscriptions/reachable-fast.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix_sub.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/AllConfigsSub.txt",
    "https://raw.githubusercontent.com/liketolivefree/kobabi/main/sub.txt",
    "https://raw.githubusercontent.com/liketolivefree/kobabi/main/sub_all.txt",
    "https://raw.githubusercontent.com/DarknessShade/Sub/main/V2mix",
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/all",
    "https://raw.githubusercontent.com/NiREvil/vless/main/sub/SSTime",
    "https://raw.githubusercontent.com/NiREvil/vless/main/sub/v2rayng-wg.txt",
    "https://raw.githubusercontent.com/sinavm/SVM/main/config.txt",
    "https://raw.githubusercontent.com/sinavm/SVM/main/docs/subscriptions/alive-stable",
    "https://raw.githubusercontent.com/sinavm/SVM/main/subscriptions/xray/normal/mix",
    "https://raw.githubusercontent.com/sinavm/SVM/main/subscriptions/xray/base64/mix",
    "https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/all.txt",
    "https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/all-base64.txt",
    "https://raw.githubusercontent.com/AmirrezaFarnamTaheri/HUNTX/main/outputs/all_sources.txt",
    "https://raw.githubusercontent.com/AmirrezaFarnamTaheri/HUNTX/main/outputs/all_sources_sub.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/Original-Configs.txt",
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/conf-week.txt",
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/Config_no_cf.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified_tls.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/curated.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top.txt",
    "https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_full.txt",
    "https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_plain_full.txt",
    "https://raw.githubusercontent.com/TelegaVPN/free-vpn-keys/main/sub/v2raytun/all.txt",
    "https://raw.githubusercontent.com/TelegaVPN/free-vpn-keys/main/sub/base64/all.txt",
    "https://raw.githubusercontent.com/freenetvt/sub-collector/main/protocols/trojan.txt",
    "https://raw.githubusercontent.com/freenetvt/sub-collector/main/protocols/shadowsocks.txt",
]

PROTOCOLS = ("vless", "vmess", "trojan", "ss")
URI_PATTERN = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>]+", re.IGNORECASE)
FLAG_PATTERN = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")


def fetch_url(url: str, timeout: float = 12.0) -> str:
    try:
        import urllib.request

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; V2RayCollector/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def try_decode_base64(text: str) -> str:
    cleaned = "".join(text.strip().split())
    if not cleaned or "://" in cleaned[:200]:
        return ""
    for alphabet_mode in ("standard", "urlsafe"):
        s = cleaned.replace("-", "+").replace("_", "/") if alphabet_mode == "urlsafe" else cleaned
        pad = (-len(s)) % 4
        s_padded = s + ("=" * pad)
        try:
            decoded = base64.b64decode(s_padded, validate=False).decode("utf-8", errors="ignore")
            if "://" in decoded:
                return decoded
        except Exception:
            continue
    return ""


def extract_uris(content: str) -> list[str]:
    text = content.strip()
    if not text:
        return []
    decoded = try_decode_base64(text)
    combined = f"{text}\n{decoded}" if decoded else text
    found = []
    for m in URI_PATTERN.findall(combined):
        uri = unquote(m.strip())
        scheme = uri.split("://", 1)[0].lower()
        if scheme in PROTOCOLS:
            found.append(uri)
    return found


def extract_flag_or_globe(raw_uri: str) -> str:
    """اگر در نام/تگ اصلی کانفیگ پرچم کشور وجود داشته باشد برمی‌گرداند؛ در غیر این صورت 🌐 می‌دهد."""
    if "#" in raw_uri:
        tag_part = unquote(raw_uri.split("#", 1)[1])
        match = FLAG_PATTERN.search(tag_part)
        if match:
            return match.group(0)
    return "🌐"


def strip_location_and_format_name(uri: str, ms: int, scheme: str) -> str:
    """تگ/لوکیشن قبلی را حذف کرده و نام جدید با پرچم یا 🌐 را بدون ستاره اعمال می‌کند."""
    flag = extract_flag_or_globe(uri)
    label = f"تهیه تمام کانفینگ ها را، 𝑭𝒓𝒆𝒆𝒏𝒆𝒕𝒗𝒕👉 𝒕𝒆𝒍𝒆𝒈𝒓𝒂𝒎 | {flag} | {ms}ms | {scheme.upper()}"

    if scheme.lower() == "vmess":
        try:
            b64_part = uri[8:].split("#", 1)[0].split("?", 1)[0].strip()
            b64_part += "=" * ((-len(b64_part)) % 4)
            data = json.loads(base64.b64decode(b64_part).decode("utf-8", errors="ignore"))
            if isinstance(data, dict):
                data["ps"] = label
                encoded = base64.b64encode(json.dumps(data, ensure_ascii=False).encode("utf-8")).decode("ascii")
                return f"vmess://{encoded}"
        except Exception:
            pass

    base_uri = uri.split("#", 1)[0]
    return f"{base_uri}#{label}"


def parse_host_port(uri: str) -> tuple[str, int, str] | None:
    scheme = uri.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            b64_part = uri[8:].split("#", 1)[0].split("?", 1)[0].strip()
            b64_part += "=" * ((-len(b64_part)) % 4)
            data = json.loads(base64.b64decode(b64_part).decode("utf-8", errors="ignore"))
            host = str(data.get("add", "")).strip().strip("[]")
            port = int(data.get("port", 0))
            if host and 1 <= port <= 65535:
                return host, port, scheme
            return None

        if scheme == "ss":
            body = uri[5:].split("#", 1)[0]
            if "@" in body:
                after_at = body.split("@", 1)[1].split("?", 1)[0].split("/", 1)[0]
            else:
                encoded = body.split("?", 1)[0]
                encoded += "=" * ((-len(encoded)) % 4)
                dec = base64.b64decode(encoded).decode("utf-8", errors="ignore")
                after_at = dec.split("@", 1)[1] if "@" in dec else ""
            if ":" in after_at:
                host, port_s = after_at.rsplit(":", 1)
                host = host.strip().strip("[]")
                port = int(re.sub(r"\D.*", "", port_s) or 0)
                if host and 1 <= port <= 65535:
                    return host, port, scheme
            return None

        parsed = urlparse(uri)
        host = (parsed.hostname or "").strip().strip("[]")
        port = parsed.port or 0
        if host and 1 <= port <= 65535:
            return host, port, scheme
        return None
    except Exception:
        return None


def tcp_ping(host: str, port: int, timeout: float = 2.5) -> int | None:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return int((time.perf_counter() - start) * 1000)
    except OSError:
        return None


def main() -> None:
    ping_timeout = float(os.getenv("PING_TIMEOUT", "2.5"))
    max_workers = int(os.getenv("MAX_WORKERS", "120"))
    max_candidates = int(os.getenv("MAX_CANDIDATES", "6000"))

    seen_uris: set[str] = set()
    candidates: list[tuple[str, int, str, str]] = []

    with ThreadPoolExecutor(max_workers=20) as pool:
        futs = {pool.submit(fetch_url, u): u for u in SUB_URLS}
        for fut in as_completed(futs):
            content = fut.result()
            for uri in extract_uris(content):
                if uri in seen_uris:
                    continue
                seen_uris.add(uri)
                hp = parse_host_port(uri)
                if hp:
                    host, port, scheme = hp
                    candidates.append((host, port, scheme, uri))
                    if len(candidates) >= max_candidates:
                        break
            if len(candidates) >= max_candidates:
                break

    print(f"Total unique candidates to TCP-ping: {len(candidates)}")

    alive: list[tuple[int, str, str]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_map = {
            pool.submit(tcp_ping, host, port, ping_timeout): (scheme, uri)
            for host, port, scheme, uri in candidates
        }
        for fut in as_completed(fut_map):
            scheme, uri = fut_map[fut]
            ms = fut.result()
            if ms is not None:
                formatted_uri = strip_location_and_format_name(uri, ms, scheme)
                alive.append((ms, scheme, formatted_uri))

    alive.sort(key=lambda x: x[0])
    print(f"Alive after TCP ping: {len(alive)}")

    all_alive_uris = [item[2] for item in alive]
    Path("sub.txt").write_text("\n".join(all_alive_uris) + ("\n" if all_alive_uris else ""), encoding="utf-8")

    b64_data = base64.b64encode("\n".join(all_alive_uris).encode("utf-8")).decode("ascii")
    Path("sub_b64.txt").write_text(b64_data + "\n", encoding="utf-8")

    proto_dir = Path("protocols")
    proto_dir.mkdir(exist_ok=True)
    for proto in PROTOCOLS:
        p_list = [item[2] for item in alive if item[1] == proto]
        (proto_dir / f"{proto}.txt").write_text(
            "\n".join(p_list) + ("\n" if p_list else ""),
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
