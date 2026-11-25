import base64
import json
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import unquote, urlparse

PROTOCOLS = ("vless", "vmess", "trojan", "ss")
URI_PATTERN = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>]+", re.IGNORECASE)
FLAG_PATTERN = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")


def load_source_urls(source_path: str) -> list[str]:
    p = Path(source_path)
    if not p.exists():
        print(f"ERROR: Source file '{source_path}' not found!")
        return []
    seen: set[str] = set()
    urls: list[str] = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        u = line.strip()
        if not u or u.startswith("#"):
            continue
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


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
    if "#" in raw_uri:
        tag_part = unquote(raw_uri.split("#", 1)[1])
        match = FLAG_PATTERN.search(tag_part)
        if match:
            return match.group(0)
    return "🌐"


def strip_location_and_format_name(uri: str, ms: int, scheme: str) -> str:
    flag = extract_flag_or_globe(uri)
    label = f"تهیه تمام کانفینگ ها را، 𝑭𝒓𝒆𝒆𝒏𝒆𝒕𝒗𝒕👉 تلگرام | {flag} | {ms}ms | {scheme.upper()}"

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
    source_file = os.getenv("SOURCE_FILE", "sources.txt")
    ping_timeout = float(os.getenv("PING_TIMEOUT", "2.5"))
    max_workers = int(os.getenv("MAX_WORKERS", "120"))
    max_candidates = int(os.getenv("MAX_CANDIDATES", "6000"))

    sub_urls = load_source_urls(source_file)
    print(f"Loaded {len(sub_urls)} source URLs from {source_file}")
    if not sub_urls:
        return

    seen_uris: set[str] = set()
    candidates: list[tuple[str, int, str, str]] = []

    with ThreadPoolExecutor(max_workers=20) as pool:
        futs = {pool.submit(fetch_url, u): u for u in sub_urls}
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
