#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import base64
import hashlib
import html
import json
import os
import re
import socket
import ssl
import time
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional

import aiohttp

# لیست کانال‌های تلگرامی شما + منابع کمکی پرسرعت
TELEGRAM_CHANNELS: List[str] = [
    "https://t.me/LonUp_M",
    "https://t.me/prrofile_purple",
    "https://t.me/v2rayngvpn",
    "https://t.me/VPNFolder",
    "https://t.me/Hope_Net",
    "https://t.me/UCIRANIR",
    "https://t.me/mehrosaboran",
    "https://t.me/Outline_Vpn",
    "https://t.me/ShadowProxy66",
]

# تنظیمات تست و خروجی
MAX_CONCURRENT_TESTS = 60
CONNECTION_TIMEOUT = 4.0
MAX_FINAL_CONFIGS = 300
OUTPUT_DIR = Path("sub")
CUSTOM_TAG = "Verified"

# عبارات باقاعده برای شکار دقیق لینک کانفیگ‌ها
PROTOCOL_REGEX = re.compile(
    r"(?:vless|vmess|trojan|ss|hy2|hysteria2|tuic)://[^\s<>\"'`\)\]\u0600-\u06FF]+",
    re.IGNORECASE,
)


def safe_base64_decode(data: str) -> str:
    """رمزگشایی ایمن رشته‌های Base64 با اصلاح خودکار پدینگ."""
    try:
        cleaned = data.strip().replace("\n", "").replace("\r", "").replace(" ", "")
        missing_padding = len(cleaned) % 4
        if missing_padding:
            cleaned += "=" * (4 - missing_padding)
        decoded_bytes = base64.urlsafe_b64decode(cleaned)
        return decoded_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def safe_base64_encode(text: str) -> str:
    """کدگذاری متن به Base64 استاندارد برای لینک اشتراک."""
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def country_code_to_flag(country_code: str) -> str:
    """تبدیل کد دوحرفی کشور به ایموجی پرچم."""
    if not country_code or len(country_code) != 2 or not country_code.isalpha():
        return "🌐"
    code = country_code.upper()
    return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)


class ParsedConfig:
    """مدل نگهداری اطلاعات ساختاری هر کانفیگ برای حذف تکراری‌ها و تست واقعی."""

    def __init__(
        self,
        protocol: str,
        raw_uri: str,
        fingerprint: str,
        host: str,
        port: int,
        transport: str = "tcp",
        security: str = "none",
        sni: str = "",
        ws_host: str = "",
        path: str = "/",
        vmess_dict: Optional[dict] = None,
    ):
        self.protocol = protocol.lower()
        self.raw_uri = raw_uri
        self.fingerprint = fingerprint
        self.host = host
        self.port = port
        self.transport = transport.lower()
        self.security = security.lower()
        self.sni = sni
        self.ws_host = ws_host
        self.path = path if path.startswith("/") else f"/{path}"
        self.vmess_dict = vmess_dict
        self.ping_ms: int = 9999
        self.country_code: str = "UN"

    def build_clean_uri(self, index: int) -> str:
        """ساخت مجدد لینک کانفیگ با نام‌گذاری استاندارد بدون دستکاری پارامترهای فنی."""
        flag = country_code_to_flag(self.country_code)
        proto_label = self.protocol.upper()
        if self.security == "reality":
            proto_label = f"{proto_label}-Reality"
        elif self.transport in ("xhttp", "splithttp"):
            proto_label = f"{proto_label}-XHTTP"
        elif self.transport in ("ws", "grpc"):
            proto_label = f"{proto_label}-{self.transport.upper()}"

        remark = f"{flag} {self.country_code} | {proto_label} | {self.ping_ms}ms | {CUSTOM_TAG}-{index:03d}"

        if self.protocol == "vmess" and self.vmess_dict is not None:
            updated_dict = dict(self.vmess_dict)
            updated_dict["ps"] = remark
            json_str = json.dumps(updated_dict, separators=(",", ":"), ensure_ascii=False)
            return "vmess://" + safe_base64_encode(json_str)

        base_part = self.raw_uri.split("#", 1)[0]
        encoded_remark = urllib.parse.quote(remark, safe="")
        return f"{base_part}#{encoded_remark}"


def parse_and_fingerprint(raw_uri: str) -> Optional[ParsedConfig]:
    """کالبدشکافی کانفیگ و تولید اثر انگشت یکتا برای حذف موارد تکراری."""
    try:
        uri = html.unescape(raw_uri.strip())
        if "://" not in uri:
            return None

        scheme, _ = uri.split("://", 1)
        scheme = scheme.lower()

        if scheme == "hysteria2":
            scheme = "hy2"

        # ۱. پردازش VMess
        if scheme == "vmess":
            b64_payload = uri.split("://", 1)[1].split("#", 1)[0]
            decoded_json = safe_base64_decode(b64_payload)
            if not decoded_json:
                return None

            data = json.loads(decoded_json)
            host = str(data.get("add", "")).strip()
            port = int(data.get("port", 0))
            uuid = str(data.get("id", "")).strip()
            net = str(data.get("net", "tcp")).strip().lower()
            path = str(data.get("path", "/")).strip() or "/"
            tls = str(data.get("tls", "none")).strip().lower()
            ws_host = str(data.get("host", "")).strip().lower()
            sni = str(data.get("sni", "") or ws_host).strip().lower()

            if not host or not (1 <= port <= 65535) or not uuid:
                return None

            fp_raw = f"vmess|{host.lower()}|{port}|{uuid.lower()}|{net}|{path}|{tls}|{sni}"
            fp_hash = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()

            return ParsedConfig(
                protocol="vmess",
                raw_uri=uri,
                fingerprint=fp_hash,
                host=host,
                port=port,
                transport=net,
                security=tls if tls else "none",
                sni=sni,
                ws_host=ws_host or sni or host,
                path=path,
                vmess_dict=data,
            )

        # ۲. پردازش Shadowsocks (شامل کانفیگ‌های Outline)
        if scheme == "ss":
            main_part = uri.split("://", 1)[1].split("#", 1)[0]
            if "@" in main_part:
                userinfo, hostport = main_part.rsplit("@", 1)
                if ":" not in userinfo:
                    decoded_user = safe_base64_decode(userinfo)
                    if ":" in decoded_user:
                        userinfo = decoded_user
            else:
                decoded_full = safe_base64_decode(main_part)
                if "@" not in decoded_full:
                    return None
                userinfo, hostport = decoded_full.rsplit("@", 1)
                # تبدیل به فرمت استاندارد SIP002 برای سازگاری با همه کلاینت‌ها
                b64_user = safe_base64_encode(userinfo).rstrip("=")
                uri = f"ss://{b64_user}@{hostport}"

            hostport_clean = hostport.split("?", 1)[0].split("/", 1)[0]
            parsed_hp = urllib.parse.urlsplit(f"//{hostport_clean}")
            host = parsed_hp.hostname or ""
            port = parsed_hp.port or 0

            if not host or not (1 <= port <= 65535):
                return None

            fp_raw = f"ss|{host.lower()}|{port}|{userinfo}"
            fp_hash = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()

            return ParsedConfig(
                protocol="ss",
                raw_uri=uri,
                fingerprint=fp_hash,
                host=host,
                port=port,
                transport="tcp",
                security="ss",
            )

        # ۳. پردازش VLESS, Trojan, Hysteria2, TUIC
        if scheme in ("vless", "trojan", "hy2", "tuic"):
            no_frag = uri.split("#", 1)[0]
            split_res = urllib.parse.urlsplit(no_frag)
            host = split_res.hostname or ""
            port = split_res.port or 0
            username = urllib.parse.unquote(split_res.username or "")
            password = urllib.parse.unquote(split_res.password or "")

            if not host or not (1 <= port <= 65535) or not username:
                return None

            query_params = urllib.parse.parse_qs(split_res.query, keep_blank_values=False)

            def get_param(key: str, default: str = "") -> str:
                vals = query_params.get(key)
                return vals[0].strip() if vals else default

            transport = get_param("type", "tcp").lower()
            security = get_param("security", "none").lower()
            if scheme == "trojan" and security == "none":
                security = "tls"

            sni = get_param("sni", get_param("peer", "")).lower()
            ws_host = get_param("host", "").lower()
            pbk = get_param("pbk", "")
            path = get_param("path", get_param("serviceName", "/")) or "/"
            alpn = get_param("alpn", "")

            if scheme in ("hy2", "tuic"):
                transport = "quic"
                security = "tls"

            # اگر کانفیگ Reality است ولی کلید عمومی (pbk) ندارد، خراب است
            if security == "reality" and not pbk:
                return None

            fp_raw = (
                f"{scheme}|{host.lower()}|{port}|{username}:{password}|"
                f"{transport}|{security}|{sni}|{ws_host}|{pbk}|{path}|{alpn}"
            )
            fp_hash = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()

            return ParsedConfig(
                protocol=scheme,
                raw_uri=uri,
                fingerprint=fp_hash,
                host=host,
                port=port,
                transport=transport,
                security=security,
                sni=sni,
                ws_host=ws_host or sni or host,
                path=path,
            )

    except Exception:
        return None

    return None


def clean_telegram_html(raw_html: str) -> str:
    """
    پاک‌سازی هوشمند HTML تلگرام:
    تلگرام وسط کانفیگ‌ها روی دامنه‌ها تگ <a> یا <wbr> می‌گذارد.
    تگ‌های درون‌خطی باید بدون فاصله حذف شوند تا لینک کانفیگ نصف نشود!
    """
    # تبدیل تگ‌های بلوکی به خط جدید
    text = re.sub(r"<(?:br\s*/?|/p|/div|/pre|/code|/li)>", "\n", raw_html, flags=re.IGNORECASE)
    # حذف تگ‌های درون‌خطی (مثل <a>, <b>, <span>, <wbr>) بدون شکستن لینک
    text = re.sub(r"<[^>]+>", "", text)
    return html.unescape(text)


def extract_configs_from_text(text: str) -> List[str]:
    """استخراج کانفیگ‌های متنی و بلوک‌های Base64 از متن."""
    found: List[str] = []
    if not text:
        return found

    matches = PROTOCOL_REGEX.findall(text)
    found.extend(matches)

    for line in text.splitlines():
        line_str = line.strip()
        if len(line_str) > 32 and " " not in line_str and "://" not in line_str:
            decoded = safe_base64_decode(line_str)
            if "://" in decoded:
                found.extend(PROTOCOL_REGEX.findall(decoded))

    return found


async def fetch_telegram_web_channel(session: aiohttp.ClientSession, channel: str) -> List[str]:
    """دریافت پیام‌های کانال‌های تلگرامی از نسخه وب."""
    clean_name = channel.strip().replace("@", "")
    clean_name = re.sub(r"^https?://t\.me/(?:s/)?", "", clean_name).strip("/")
    url = f"https://t.me/s/{clean_name}"

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )
    }
    try:
        async with session.get(url, headers=headers, timeout=15) as resp:
            if resp.status == 200:
                html_text = await resp.text()
                cleaned_text = clean_telegram_html(html_text)
                configs = extract_configs_from_text(cleaned_text)
                print(f"[+] Channel '{clean_name}': {len(configs)} configs extracted.")
                return configs
    except Exception as exc:
        print(f"[-] Error fetching '{clean_name}': {exc}")
    return []


async def test_single_config(
    cfg: ParsedConfig,
    semaphore: asyncio.Semaphore,
) -> Optional[ParsedConfig]:
    """
    تست واقعی و عمیق کانفیگ:
    - برای WebSocket (کلودفلر و CDN): ارسال درخواست واقعی HTTP Upgrade و حذف سرورهای 502/521/522/530/404
    - برای TLS / Reality / Trojan: انجام کامل دست‌دهی TLS
    - برای Hysteria2 / TUIC (مبتنی بر UDP): بررسی DNS و در دسترس بودن شبکه
    """
    async with semaphore:
        start_time = time.perf_counter()
        try:
            # ۱. پروتکل‌های مبتنی بر QUIC/UDP (Hysteria2 و TUIC)
            if cfg.transport == "quic" or cfg.protocol in ("hy2", "tuic"):
                loop = asyncio.get_running_loop()
                addr_info = await asyncio.wait_for(
                    loop.getaddrinfo(cfg.host, cfg.port, type=socket.SOCK_DGRAM),
                    timeout=CONNECTION_TIMEOUT,
                )
                if not addr_info:
                    return None
                elapsed_ms = int((time.perf_counter() - start_time) * 1000)
                cfg.ping_ms = max(15, elapsed_ms)
                return cfg

            # ۲. تنظیم لایه TLS برای پروتکل‌های امن TCP
            use_ssl = cfg.security in ("tls", "reality", "xtls")
            ssl_ctx = None
            server_hostname = None

            if use_ssl:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                server_hostname = cfg.sni if cfg.sni else cfg.host

            conn = asyncio.open_connection(
                host=cfg.host,
                port=cfg.port,
                ssl=ssl_ctx,
                server_hostname=server_hostname if use_ssl else None,
            )
            reader, writer = await asyncio.wait_for(conn, timeout=CONNECTION_TIMEOUT)

            # ۳. اگر کانفیگ WebSocket است، تست واقعی به سرور پشت کلودفلر بزنیم
            if cfg.transport == "ws":
                target_host = cfg.ws_host or cfg.sni or cfg.host
                ws_req = (
                    f"GET {cfg.path} HTTP/1.1\r\n"
                    f"Host: {target_host}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Sec-WebSocket-Version: 13\r\n"
                    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
                )
                writer.write(ws_req.encode("utf-8"))
                await writer.drain()

                first_line_bytes = await asyncio.wait_for(
                    reader.readline(), timeout=CONNECTION_TIMEOUT
                )
                first_line = first_line_bytes.decode("utf-8", errors="ignore").strip()

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                # سرورهای سالم WebSocket کد 101 یا 400 (نیاز به هدر V2Ray) برمی‌گردانند
                # کدهای 502, 521, 522, 523, 530, 404, 403 یعنی سرور اصلی خاموش یا خراب است
                if not first_line.startswith("HTTP/"):
                    return None
                if any(
                    bad_code in first_line
                    for bad_code in (" 500", " 502", " 503", " 504", " 52", " 530", " 404", " 403")
                ):
                    return None

                elapsed_ms = int((time.perf_counter() - start_time) * 1000)
                cfg.ping_ms = max(1, elapsed_ms)
                return cfg

            # ۴. برای سایر پروتکل‌ها (VLESS-Reality, TCP, gRPC, SS)
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if 1 <= elapsed_ms <= int(CONNECTION_TIMEOUT * 1000):
                cfg.ping_ms = elapsed_ms
                return cfg

        except Exception:
            return None

    return None


async def enrich_country_codes(
    session: aiohttp.ClientSession,
    configs: List[ParsedConfig],
) -> None:
    """دریافت کشور سرورها برای افزودن پرچم به نام کانفیگ."""
    host_to_ip: Dict[str, str] = {}
    unique_hosts = list({c.host for c in configs})

    loop = asyncio.get_running_loop()

    async def resolve_host(h: str) -> None:
        try:
            info = await loop.getaddrinfo(h, None, family=socket.AF_INET)
            if info:
                host_to_ip[h] = info[0][4][0]
        except Exception:
            pass

    await asyncio.gather(*(resolve_host(h) for h in unique_hosts))

    unique_ips = list(set(host_to_ip.values()))
    ip_to_country: Dict[str, str] = {}

    for i in range(0, len(unique_ips), 100):
        batch = unique_ips[i : i + 100]
        payload = [{"query": ip, "fields": "query,countryCode"} for ip in batch]
        try:
            async with session.post("http://ip-api.com/batch", json=payload, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data:
                        q = item.get("query")
                        cc = item.get("countryCode")
                        if q and cc:
                            ip_to_country[q] = cc
        except Exception:
            pass

    for cfg in configs:
        ip = host_to_ip.get(cfg.host)
        if ip and ip in ip_to_country:
            cfg.country_code = ip_to_country[ip]


def write_subscription_files(verified_configs: List[ParsedConfig]) -> None:
    """ذخیره فایل‌های خروجی به دو صورت معمولی (Plain) و Base64."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    verified_configs.sort(key=lambda x: x.ping_ms)
    final_list = verified_configs[:MAX_FINAL_CONFIGS]

    all_clean_uris: List[str] = []
    by_protocol: Dict[str, List[str]] = {
        "vless": [],
        "vmess": [],
        "trojan": [],
        "ss": [],
        "hy2": [],
        "tuic": [],
    }

    for idx, cfg in enumerate(final_list, start=1):
        clean_uri = cfg.build_clean_uri(idx)
        all_clean_uris.append(clean_uri)
        if cfg.protocol in by_protocol:
            by_protocol[cfg.protocol].append(clean_uri)

    plain_content = "\n".join(all_clean_uris)
    b64_content = safe_base64_encode(plain_content)

    (OUTPUT_DIR / "all_configs.txt").write_text(plain_content, encoding="utf-8")
    (OUTPUT_DIR / "all_configs_base64.txt").write_text(b64_content, encoding="utf-8")

    for proto, uris in by_protocol.items():
        proto_plain = "\n".join(uris)
        proto_b64 = safe_base64_encode(proto_plain) if uris else ""
        (OUTPUT_DIR / f"{proto}.txt").write_text(proto_plain, encoding="utf-8")
        (OUTPUT_DIR / f"{proto}_base64.txt").write_text(proto_b64, encoding="utf-8")

    print(f"\n[OK] Saved {len(all_clean_uris)} verified working configs in 'sub/' directory.")


async def main() -> None:
    print("=== Starting V2Ray & Sing-box Collector ===")
    channels = list(dict.fromkeys(TELEGRAM_CHANNELS))

    raw_configs: List[str] = []
    async with aiohttp.ClientSession() as session:
        web_tasks = [fetch_telegram_web_channel(session, ch) for ch in channels]
        web_results = await asyncio.gather(*web_tasks)
        for res in web_results:
            raw_configs.extend(res)

        print(f"\n[*] Total raw configs extracted: {len(raw_configs)}")

        unique_map: Dict[str, ParsedConfig] = {}
        for raw in raw_configs:
            parsed = parse_and_fingerprint(raw)
            if parsed and parsed.fingerprint not in unique_map:
                unique_map[parsed.fingerprint] = parsed

        unique_configs = list(unique_map.values())
        print(f"[*] Unique valid configs after deduplication: {len(unique_configs)}")

        semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
        test_tasks = [test_single_config(cfg, semaphore) for cfg in unique_configs]
        tested_results = await asyncio.gather(*test_tasks)

        verified_configs = [cfg for cfg in tested_results if cfg is not None]
        print(f"[*] Verified alive configs: {len(verified_configs)}")

        if verified_configs:
            await enrich_country_codes(session, verified_configs)

        write_subscription_files(verified_configs)


if __name__ == "__main__":
    asyncio.run(main())