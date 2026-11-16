#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
سیستم جامع جمع‌آوری، پالایش، حذف موارد مشابه و تست هوشمند کانفیگ‌های V2Ray و Sing-box
پشتیبانی از پروتکل‌های: VLESS (Reality/WS/gRPC/XHTTP), VMess, Trojan, Shadowsocks, Hysteria2, TUIC
قابلیت استخراج از:
  1. کانال‌های عمومی تلگرام (بدون نیاز به اکانت از طریق وب)
  2. گروه‌ها و کانال‌های خصوصی/عمومی تلگرام (از طریق Telethon در صورت تنظیم متغیرهای محیطی)
  3. لینک‌های اشتراک (Subscription) خارجی
"""

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

# ==============================================================================
# ۱. بخش تنظیمات و منابع (لیست کانال‌ها و گروه‌های خود را اینجا قرار دهید)
# ==============================================================================

# لیست کانال‌های تلگرامی (می‌توانید نام کاربری با @، بدون @ یا لینک کامل t.me وارد کنید)
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

# لینک‌های اشتراک (Subscription) خارجی اختیاری برای ادغام
EXTERNAL_SUB_URLS: List[str] = [
    # اگر لینک ساب دیگری دارید می‌توانید اینجا اضافه کنید
]

# تنظیمات تست و بهینه‌سازی
MAX_CONCURRENT_TESTS = 80       # تعداد تست همزمان
CONNECTION_TIMEOUT = 3.5        # حداکثر زمان انتظار برای تست اتصال (ثانیه)
MAX_FINAL_CONFIGS = 500         # حداکثر تعداد بهترین کانفیگ‌ها در فایل نهایی
OUTPUT_DIR = Path("sub")        # پوشه خروجی فایل‌های اشتراک
CUSTOM_TAG = "Verified"         # تگ اختصاصی شما که در انتهای نام کانفیگ‌ها درج می‌شود

# عبارات باقاعده (Regex) برای شکار تمام پروتکل‌های استاندارد و نسل جدید
PROTOCOL_REGEX = re.compile(
    r"(?:vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic)://[^\s<>\"'`\)\]\u0600-\u06FF]+",
    re.IGNORECASE,
)


# ==============================================================================
# ۲. ابزارهای کمکی کدگشایی و نرمال‌سازی
# ==============================================================================

def safe_base64_decode(data: str) -> str:
    """کدگشایی ایمن Base64 حتی در صورت ناقص بودن علامت‌های = در انتهای رشته."""
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
    """تبدیل متن به فرمت استاندارد Base64 بدون خط شکسته."""
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def country_code_to_flag(country_code: str) -> str:
    """تبدیل کد دوحرفی کشور (مثل DE یا NL) به ایموجی پرچم."""
    if not country_code or len(country_code) != 2 or not country_code.isalpha():
        return "🌐"
    code = country_code.upper()
    return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)


# ==============================================================================
# ۳. کالبدشکافی کانفیگ و تولید اثر انگشت یکتا (حذف هوشمند کانفیگ‌های مشابه)
# ==============================================================================

class ParsedConfig:
    """کلاس نگه‌دارنده اطلاعات ساختاریافته هر کانفیگ برای مقایسه، تست و نام‌گذاری مجدد."""

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
        self.vmess_dict = vmess_dict
        self.ping_ms: int = 9999
        self.country_code: str = "UN"

    def build_clean_uri(self, index: int) -> str:
        """بازسازی کانفیگ با نام‌گذاری تمیز، پرچم کشور، نوع پروتکل و پینگ."""
        flag = country_code_to_flag(self.country_code)
        proto_label = self.protocol.upper()
        if self.security == "reality":
            proto_label = f"{proto_label}-Reality"
        elif self.transport in ("xhttp", "splithttp"):
            proto_label = f"{proto_label}-XHTTP"
        elif self.transport in ("ws", "grpc"):
            proto_label = f"{proto_label}-{self.transport.upper()}"

        remark = f"{flag} {self.country_code} | {proto_label} | {self.ping_ms}ms | {CUSTOM_TAG}-{index:03d}"

        # اگر پروتکل VMess است، نام را در JSON داخلی تغییر می‌دهیم و دوباره Base64 می‌کنیم
        if self.protocol == "vmess" and self.vmess_dict is not None:
            updated_dict = dict(self.vmess_dict)
            updated_dict["ps"] = remark
            json_str = json.dumps(updated_dict, separators=(",", ":"), ensure_ascii=False)
            return "vmess://" + safe_base64_encode(json_str)

        # برای سایر پروتکل‌ها (VLESS, Trojan, SS, Hysteria2, TUIC) بخش #fragment را جایگزین می‌کنیم
        base_part = self.raw_uri.split("#", 1)[0]
        encoded_remark = urllib.parse.quote(remark, safe="")
        return f"{base_part}#{encoded_remark}"


def parse_and_fingerprint(raw_uri: str) -> Optional[ParsedConfig]:
    """
    کالبدشکافی لینک کانفیگ و تولید هش یکتا (Fingerprint) بر اساس مشخصات فنی سرور.
    این تابع نام کانال‌ها و تبلیغات انتهای کانفیگ را کاملاً نادیده می‌گیرد تا کانفیگ‌های تکراری حذف شوند.
    """
    try:
        uri = html.unescape(raw_uri.strip())

        if "://" not in uri:
            return None

        scheme, _ = uri.split("://", 1)
        scheme = scheme.lower()

        if scheme == "hysteria2":
            uri = "hy2://" + uri.split("://", 1)[1]
            scheme = "hy2"

        # ---------------- ۱. پردازش اختصاصی پروتکل VMess ----------------
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
            path = str(data.get("path", "")).strip()
            tls = str(data.get("tls", "none")).strip().lower()
            sni = str(data.get("sni", "") or data.get("host", "")).strip().lower()

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
                vmess_dict=data,
            )

        # ---------------- ۲. پردازش اختصاصی پروتکل Shadowsocks ----------------
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

            hostport = hostport.split("?", 1)[0].split("/", 1)[0]
            parsed_hp = urllib.parse.urlsplit(f"//{hostport}")
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

        # ---------------- ۳. پردازش VLESS, Trojan, Hysteria2, TUIC ----------------
        if scheme in ("vless", "trojan", "hy2", "tuic"):
            split_res = urllib.parse.urlsplit(uri)
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
            sni = get_param("sni", get_param("peer", "")).lower()
            pbk = get_param("pbk", "")
            path = get_param("path", get_param("serviceName", ""))
            alpn = get_param("alpn", "")

            if scheme in ("hy2", "tuic"):
                transport = "quic"
                security = "tls"

            fp_raw = (
                f"{scheme}|{host.lower()}|{port}|{username}:{password}|"
                f"{transport}|{security}|{sni}|{pbk}|{path}|{alpn}"
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
            )

    except Exception:
        return None

    return None


# ==============================================================================
# ۴. ماژول استخراج از تلگرام (وب و API) و منابع خارجی
# ==============================================================================

def extract_configs_from_text(text: str) -> List[str]:
    """استخراج تمام لینک‌های کانفیگ از یک متن (شامل متن‌های کدگذاری شده با Base64)."""
    found: List[str] = []
    if not text:
        return found

    cleaned_text = html.unescape(text)
    matches = PROTOCOL_REGEX.findall(cleaned_text)
    found.extend(matches)

    for line in cleaned_text.splitlines():
        line_str = line.strip()
        if len(line_str) > 32 and " " not in line_str and "://" not in line_str:
            decoded = safe_base64_decode(line_str)
            if "://" in decoded:
                found.extend(PROTOCOL_REGEX.findall(decoded))

    return found


async def fetch_telegram_web_channel(session: aiohttp.ClientSession, channel: str) -> List[str]:
    """اسکرپ کردن صفحه وب عمومی کانال تلگرام (t.me/s/channel)."""
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
                text_only = re.sub(r"<[^>]+>", "\n", html_text)
                configs = extract_configs_from_text(text_only)
                print(f"[+] کانال وب '{clean_name}': {len(configs)} کانفیگ استخراج شد.")
                return configs
    except Exception as exc:
        print(f"[-] خطا در دریافت کانال '{clean_name}': {exc}")
    return []


async def fetch_via_telethon_if_configured(channels: List[str]) -> List[str]:
    """
    در صورتی که کاربر بخواهد از «گروه‌های تلگرامی» یا کانال‌های بدون پیش‌نمایش وب هم
    استخراج کند، با قرار دادن TG_API_ID, TG_API_HASH, TG_STRING_SESSION در GitHub Secrets،
    این تابع به صورت خودکار فعال می‌شود.
    """
    api_id = os.getenv("TG_API_ID")
    api_hash = os.getenv("TG_API_HASH")
    string_session = os.getenv("TG_STRING_SESSION")

    if not (api_id and api_hash and string_session):
        return []

    collected: List[str] = []
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession

        print("[*] نشست Telethon شناسایی شد؛ در حال اسکن عمیق گروه‌ها و کانال‌ها...")
        async with TelegramClient(StringSession(string_session), int(api_id), api_hash) as client:
            for ch in channels:
                try:
                    async for message in client.iter_messages(ch, limit=100):
                        if message.text:
                            collected.extend(extract_configs_from_text(message.text))
                except Exception as e:
                    print(f"[-] خطای Telethon در '{ch}': {e}")
    except ImportError:
        print("[!] کتابخانه Telethon نصب نیست؛ فقط از حالت وب استفاده می‌شود.")
    except Exception as e:
        print(f"[-] خطا در اتصال Telethon: {e}")

    return collected


async def fetch_external_subscriptions(session: aiohttp.ClientSession, urls: List[str]) -> List[str]:
    """دریافت کانفیگ از لینک‌های اشتراک خارجی."""
    results: List[str] = []
    for url in urls:
        if not url.strip():
            continue
        try:
            async with session.get(url.strip(), timeout=15) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    results.extend(extract_configs_from_text(content))
        except Exception as e:
            print(f"[-] خطا در دریافت لینک خارجی '{url}': {e}")
    return results


# ==============================================================================
# ۵. موتور تست اتصال، دست‌دهی TLS و موقعیت‌یابی (GeoIP)
# ==============================================================================

async def test_single_config(
    cfg: ParsedConfig,
    semaphore: asyncio.Semaphore,
) -> Optional[ParsedConfig]:
    """
    تست واقعی دست‌دهی شبکه (TCP + TLS Handshake در صورت فعال بودن TLS/Reality)
    و محاسبه دقیق پینگ (Latency) به میلی‌ثانیه.
    """
    async with semaphore:
        start_time = time.perf_counter()
        try:
            use_ssl = cfg.security in ("tls", "reality", "xtls") and cfg.transport != "quic"
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
    """شناسایی کشور سرورها به صورت دسته‌ای (Batch GeoIP) برای درج پرچم دقیق."""
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


# ==============================================================================
# ۶. ذخیره خروجی‌ها (معمولی، Base64 و تفکیک‌شده بر اساس پروتکل)
# ==============================================================================

def write_subscription_files(verified_configs: List[ParsedConfig]) -> None:
    """ذخیره فایل‌های اشتراک به هر دو صورت Plain Text و Base64."""
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

    # ۱. ذخیره فایل جامع (شامل تمام پروتکل‌ها)
    plain_content = "\n".join(all_clean_uris)
    b64_content = safe_base64_encode(plain_content)

    (OUTPUT_DIR / "all_configs.txt").write_text(plain_content, encoding="utf-8")
    (OUTPUT_DIR / "all_configs_base64.txt").write_text(b64_content, encoding="utf-8")

    # ۲. ذخیره فایل‌های تفکیک‌شده برای هر پروتکل (هم معمولی و هم Base64)
    for proto, uris in by_protocol.items():
        proto_plain = "\n".join(uris)
        proto_b64 = safe_base64_encode(proto_plain) if uris else ""
        (OUTPUT_DIR / f"{proto}.txt").write_text(proto_plain, encoding="utf-8")
        (OUTPUT_DIR / f"{proto}_base64.txt").write_text(proto_b64, encoding="utf-8")

    print(f"\n[✓] عملیات با موفقیت کامل شد! {len(all_clean_uris)} کانفیگ سالم و بدون تکرار ذخیره گردید.")


# ==============================================================================
# ۷. تابع اصلی اجرای پایپ‌لاین
# ==============================================================================

async def main() -> None:
    print("=== شروع فرآیند جمع‌آوری و پالایش هوشمند کانفیگ‌ها ===")

    channels_file = Path("channels.txt")
    channels = list(TELEGRAM_CHANNELS)
    if channels_file.exists():
        extra = [
            line.strip()
            for line in channels_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        channels.extend(extra)

    channels = list(dict.fromkeys(channels))

    raw_configs: List[str] = []
    async with aiohttp.ClientSession() as session:
        # ۱. دریافت از پیش‌نمایش وب تلگرام
        web_tasks = [fetch_telegram_web_channel(session, ch) for ch in channels]
        web_results = await asyncio.gather(*web_tasks)
        for res in web_results:
            raw_configs.extend(res)

        # ۲. دریافت از لینک‌های ساب خارجی
        ext_results = await fetch_external_subscriptions(session, EXTERNAL_SUB_URLS)
        raw_configs.extend(ext_results)

        # ۳. دریافت از گروه‌ها و کانال‌ها از طریق Telethon (در صورت تنظیم کلیدها)
        telethon_results = await fetch_via_telethon_if_configured(channels)
        raw_configs.extend(telethon_results)

        print(f"\n[*] مجموع کل کانفیگ‌های خام شکار شده: {len(raw_configs)}")

        # ۴. کالبدشکافی و حذف هوشمند کانفیگ‌های مشابه (Deduplication)
        unique_map: Dict[str, ParsedConfig] = {}
        for raw in raw_configs:
            parsed = parse_and_fingerprint(raw)
            if parsed and parsed.fingerprint not in unique_map:
                unique_map[parsed.fingerprint] = parsed

        unique_configs = list(unique_map.values())
        print(f"[*] تعداد کانفیگ‌های یکتا پس از حذف موارد تکراری: {len(unique_configs)}")

        # ۵. تست همزمان سلامت و پینگ کانفیگ‌ها
        print(f"[*] در حال تست اتصال و دست‌دهی امنیتی ({MAX_CONCURRENT_TESTS} تست همزمان)...")
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
        test_tasks = [test_single_config(cfg, semaphore) for cfg in unique_configs]
        tested_results = await asyncio.gather(*test_tasks)

        verified_configs = [cfg for cfg in tested_results if cfg is not None]
        print(f"[*] تعداد کانفیگ‌های سالم و فعال: {len(verified_configs)}")

        # ۶. شناسایی کشور و افزودن پرچم
        if verified_configs:
            print("[*] در حال شناسایی موقعیت جغرافیایی (GeoIP) سرورها...")
            await enrich_country_codes(session, verified_configs)

        # ۷. ساخت و ذخیره فایل‌های نهایی اشتراک
        write_subscription_files(verified_configs)


if __name__ == "__main__":
    asyncio.run(main())