#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络出口采样检查 (Exit IP / STUN & ICE / IPv6 / DNS resolver)

输出风格：方案 B（极简 4 行对齐看板，逐步实时输出，异常项自动展开详情）
三态：PASS / FAIL / WARN；返回码：0 / 1 / 2（报错优先于警告）。
统一地域规则：US 正常，CN/HK 报错，其他地区或证据不足警告。
DNS 通过 IPLeak 随机域名实际采样解析器，再核验解析器 IP 归属。
STUN 与 DNS 均仅覆盖本次采样，不自动运行浏览器；DoH 只作辅助诊断。
IPv6 同时核验本机与默认/代理路径；可达本身不算错误。
按路由器已关闭 IPv6 的使用设置，本机无路由且未测得 IPv6 出口时视为正常。
"""

from __future__ import annotations

import argparse
import concurrent.futures
import errno
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ============================================================================
# 常量定义
# ============================================================================

UUID_MDNS_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\.local\.?$"
)
GENERIC_MDNS_RE = re.compile(r"^[^\s]+\.local\.?$", re.IGNORECASE)
ICE_CANDIDATE_RE = re.compile(
    r"^(?:a=)?candidate:\S+\s+\d+\s+(udp|tcp)\s+\d+\s+([^\s]+)\s+(\d+)\s+typ\s+(host|srflx|prflx|relay)(?=\s|$)",
    re.IGNORECASE,
)

# RFC 2544 基准测试网段，被 Clash / Surge / Mihomo / Sing-box / Quantumult X 广泛用作 Fake-IP 网段
FAKE_IPV4_NETWORKS = [
    ipaddress.ip_network("198.18.0.0/15"),
]
# IPv6 Fake-IP 常见网段 (Clash / Sing-box 默认 fc00::/18)
FAKE_IPV6_NETWORKS = [
    ipaddress.ip_network("fc00::/18"),
]

STUN_SERVERS: List[Tuple[str, int]] = [
    ("stun.cloudflare.com", 3478),
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.nextcloud.com", 443),
]

# 用于绕过 Fake-IP DNS、直接测试纯 IP UDP 路由是否泄漏的公共 STUN Anycast/公网 IP
DIRECT_IP_STUN_SERVERS: List[Tuple[str, int, str]] = [
    ("74.125.250.129", 19302, "google-direct-ip"),
]

USER_AGENT = "curl/8.7.1 NetCheckCLI/1.0"
PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
STATUS_LABELS = {PASS: "✅ 正常", FAIL: "❌ 报错", WARN: "⚠️ 警告"}
EXIT_CODES = {PASS: 0, FAIL: 1, WARN: 2}
NORMAL_COUNTRY = "US"
BLOCKED_COUNTRIES = frozenset({"CN", "HK"})
REGION_POLICY = "US 正常；CN/HK 报错；其他地区、归属未知或采样不完整警告"
DNS_DEFAULT_SAMPLES = 5
# ISO 3166-1 alpha-2；服务返回未知/占位代码时不能把它算作“其他地区”放行。
COUNTRY_CODES = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN
BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL
GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM
JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME
MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP
NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD
SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO
TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
""".split())


# ============================================================================
# 数据结构定义
# ============================================================================

@dataclass
class ExitInfo:
    success: bool = False
    source: str = ""  # "ipinfo.io" | "cloudflare-trace" | ""
    ip: str = ""
    ip_version: int = 0
    country: str = ""
    region: str = ""
    city: str = ""
    org: str = ""
    asn: str = ""
    colo: str = ""
    warp: str = ""
    via_proxy: bool = False
    latency_ms: float = 0.0
    error: str = ""


@dataclass
class CandidateItem:
    address: str
    port: int = 0
    candidate_type: str = ""  # "host" | "srflx" | "dns-resolved" | "custom"
    source: str = ""          # 来源说明，如 STUN 服务器名或网卡
    category: str = ""        # "PUBLIC" | "FAKE-IP" | "mDNS-UUID" | "mDNS-HOST" | "PRIVATE" | "CGNAT" | "LOOPBACK" | "LINK-LOCAL"
    ip_version: int = 0       # 4 | 6 | 0 (mDNS)
    matches_exit_ip: Optional[bool] = None
    country: str = ""
    org: str = ""
    attribution_source: str = ""
    attribution_error: str = ""


@dataclass
class CheckResult:
    status: str = WARN
    summary: str = ""
    reasons: List[str] = field(default_factory=list)


@dataclass
class StunProbeResult:
    server: str
    candidates: List[CandidateItem] = field(default_factory=list)
    responses: int = 0
    errors: List[str] = field(default_factory=list)


@dataclass
class WebRTCReport:
    status: str = WARN
    summary: str = ""
    scope: str = "仅本次 STUN/外部 ICE 候选采样，不证明浏览器整体无泄漏"
    reasons: List[str] = field(default_factory=list)
    exit_ips_compared: List[str] = field(default_factory=list)
    stun_srflx_ips: List[str] = field(default_factory=list)
    mismatched_ips: List[str] = field(default_factory=list)
    unverified_ips: List[str] = field(default_factory=list)
    browser_ice_supplied: bool = False
    browser_status: str = WARN
    # 仅表示提供的 ICE 样本中出现了 mDNS 名称，不表示所有候选均已隐藏。
    has_mdns_obfuscation: bool = False
    mdns_candidates: List[str] = field(default_factory=list)
    has_fake_ip: bool = False
    fake_ip_candidates: List[str] = field(default_factory=list)
    candidates: List[CandidateItem] = field(default_factory=list)
    probes: List[StunProbeResult] = field(default_factory=list)


@dataclass
class IPv6Report:
    status: str = WARN
    summary: str = ""
    scope: str = "本机 AF_INET6 与默认/代理路径均按地域检查；本机路径仍可能经过 TUN"
    policy: str = "可见出口适用地域规则；按路由器关闭 IPv6 的设置，本机无路由且未测得 IPv6 出口时正常"
    reasons: List[str] = field(default_factory=list)
    local_route_available: Optional[bool] = None
    ipv6_reachable: bool = False
    local_stack_v6_reachable: bool = False
    default_path_v6_reachable: bool = False
    local_probe_error: str = ""
    default_probe_error: str = ""
    local_probe: ExitInfo = field(default_factory=ExitInfo)
    default_probe: ExitInfo = field(default_factory=ExitInfo)
    ipv4_exit_ip: str = ""
    ipv4_country: str = ""
    ipv6_exit_ip: str = ""
    ipv6_country: str = ""
    ipv6_org: str = ""
    ipv6_source: str = ""
    country_match: Optional[bool] = None


@dataclass
class DoHEndpointResult:
    provider: str
    name: str
    url: str
    reachable: bool = False
    status_code: int = 0
    dns_rcode: int = -1
    latency_ms: float = 0.0
    resolved_ips: List[str] = field(default_factory=list)
    has_valid_public_answer: bool = False
    has_fake_ip_answer: bool = False
    has_bogon_answer: bool = False
    ecs_subnet: str = ""
    resolver_ip: str = ""
    error: str = ""


@dataclass
class IPAttribution:
    ip: str
    country: str = ""
    country_name: str = ""
    org: str = ""
    asn: str = ""
    source: str = ""
    error: str = ""


@dataclass
class DNSResolver(IPAttribution):
    query_count: int = 0


@dataclass
class DNSProbeSample:
    hostname: str
    status_code: int = 0
    resolver_ips: List[str] = field(default_factory=list)
    latency_ms: float = 0.0
    error: str = ""


@dataclass
class DNSResolverReport:
    status: str = WARN
    summary: str = ""
    scope: str = "本机默认解析/当前 TUN 路径；未覆盖浏览器独立安全 DNS"
    policy: str = REGION_POLICY
    source: str = "https://ipleak.net/"
    session: str = ""
    requested_samples: int = DNS_DEFAULT_SAMPLES
    successful_samples: int = 0
    blocked_countries: List[str] = field(default_factory=lambda: sorted(BLOCKED_COUNTRIES))
    resolvers: List[DNSResolver] = field(default_factory=list)
    samples: List[DNSProbeSample] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)


@dataclass
class DNSReport:
    status: str = WARN
    summary: str = ""
    scope: str = "实际 DNS 解析器适用统一地域规则；DoH 连通性/一致性仅作辅助诊断"
    doh_status: str = WARN
    doh_summary: str = ""
    doh_reasons: List[str] = field(default_factory=list)
    system_dns_status: str = WARN
    resolver_detection: DNSResolverReport = field(default_factory=DNSResolverReport)
    cloudflare_doh_ok: bool = False
    google_doh_ok: bool = False
    cf_trace_ip: str = ""
    cf_trace_country: str = ""
    cf_egress_aligned: Optional[bool] = None
    cf_trace_error: str = ""
    google_ecs_subnet: str = ""
    google_resolver_ip: str = ""
    google_egress_aligned: Optional[bool] = None
    system_dns_sample_domain: str = "example.com"
    system_dns_ips: List[str] = field(default_factory=list)
    system_dns_is_fake_ip: bool = False
    system_dns_error: str = ""
    reasons: List[str] = field(default_factory=list)
    endpoints: List[DoHEndpointResult] = field(default_factory=list)


# ============================================================================
# 网络与地址分类辅助工具
# ============================================================================

def is_fake_ip(ip_obj: ipaddress._BaseAddress) -> bool:
    """判断 IP 是否属于代理工具常用的 Fake-IP 地址池 (198.18.0.0/15 或 fc00::/18)"""
    if isinstance(ip_obj, ipaddress.IPv4Address):
        return any(ip_obj in net for net in FAKE_IPV4_NETWORKS)
    if isinstance(ip_obj, ipaddress.IPv6Address):
        return any(ip_obj in net for net in FAKE_IPV6_NETWORKS)
    return False


def classify_address(addr: str) -> Tuple[str, int]:
    """识别候选地址类型，返回 (category, ip_version)"""
    cleaned = addr.strip().strip("[]")
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0]

    if UUID_MDNS_RE.match(cleaned):
        return ("mDNS-UUID", 0)
    if GENERIC_MDNS_RE.match(cleaned):
        return ("mDNS-HOST", 0)

    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError:
        return ("HOSTNAME", 0)

    version = ip_obj.version
    if is_fake_ip(ip_obj):
        return ("FAKE-IP", version)
    if ip_obj.is_loopback:
        return ("LOOPBACK", version)
    if ip_obj.is_link_local:
        return ("LINK-LOCAL", version)
    if ip_obj.is_multicast:
        return ("RESERVED", version)
    if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in ipaddress.ip_network("100.64.0.0/10"):
        return ("CGNAT", version)
    if ip_obj.is_private:
        return ("PRIVATE", version)
    if ip_obj.is_global:
        return ("PUBLIC", version)
    return ("RESERVED", version)


def build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def has_local_ipv6_route() -> Optional[bool]:
    """UDP connect 不发包。False 仅表示采样目标无路由；其他错误为 None。"""
    no_route_errors = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EAFNOSUPPORT}
    uncertain = False
    for destination in ("2606:4700:4700::1111", "2001:4860:4860::8888"):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.connect((destination, 443))
            addr = ipaddress.ip_address(sock.getsockname()[0].split("%", 1)[0])
            # ULA 也可能经 NAT66/TUN 到公网，不能仅因不是 global 就跳过。
            if not (addr.is_unspecified or addr.is_loopback or addr.is_link_local):
                return True
            uncertain = True
        except OSError as exc:
            if exc.errno not in no_route_errors:
                uncertain = True
        except Exception:
            uncertain = True
        finally:
            if sock is not None:
                sock.close()
    return None if uncertain else False


def fetch_url_with_family(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 5.0,
    family: int = socket.AF_UNSPEC,
    proxy_url: Optional[str] = None,
    bypass_system_proxy: bool = False,
) -> Tuple[int, str, float, bool]:
    """
    发送 HTTP/HTTPS 请求，支持严格指定 IPv4/IPv6 地址族或代理控制。
    当未走显式 HTTP 代理（例如 TUN 模式或直连模式）且指定了 family (AF_INET / AF_INET6) 时，
    一律通过底层 socket 强制绑定对应地址族，防止双栈环境误走另一协议栈。
    返回: (status_code, body_text, latency_ms, used_proxy)
    """
    req_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        req_headers.update(headers)

    start = time.perf_counter()

    sys_proxies = {} if bypass_system_proxy else urllib.request.getproxies()
    effective_proxy = proxy_url or sys_proxies.get("https") or sys_proxies.get("http") or sys_proxies.get("all")

    # 只要没有使用 HTTP 代理且指定了 AF_INET / AF_INET6，即强制使用对应地址族 socket
    if not effective_proxy and family in (socket.AF_INET, socket.AF_INET6):
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        addr_infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
        if not addr_infos:
            raise OSError(f"无法解析 {host} 的 {'IPv6' if family == socket.AF_INET6 else 'IPv4'} 地址")

        last_err: Optional[Exception] = None
        for af, socktype, proto, _, sockaddr in addr_infos:
            raw_sock: Optional[socket.socket] = None
            try:
                raw_sock = socket.socket(af, socktype, proto)
                raw_sock.settimeout(timeout)
                raw_sock.connect(sockaddr)
                if scheme == "https":
                    ctx = build_ssl_context()
                    conn_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
                else:
                    conn_sock = raw_sock

                host_header = f"[{host}]" if ":" in host else host
                req_lines = [
                    f"GET {path} HTTP/1.1",
                    f"Host: {host_header}",
                    "Connection: close",
                ]
                for k, v in req_headers.items():
                    req_lines.append(f"{k}: {v}")
                raw_request = ("\r\n".join(req_lines) + "\r\n\r\n").encode("utf-8")
                conn_sock.sendall(raw_request)

                chunks: List[bytes] = []
                while True:
                    data = conn_sock.recv(8192)
                    if not data:
                        break
                    chunks.append(data)
                conn_sock.close()

                latency_ms = (time.perf_counter() - start) * 1000.0
                response_bytes = b"".join(chunks)
                header_part, _, body_part = response_bytes.partition(b"\r\n\r\n")
                status_line = header_part.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
                parts = status_line.split(" ", 2)
                if not status_line.startswith("HTTP/") or len(parts) < 2 or not parts[1].isdigit():
                    raise ValueError("无效 HTTP 状态行")
                status_code = int(parts[1])

                if b"transfer-encoding: chunked" in header_part.lower():
                    body_part = decode_chunked(body_part)

                return status_code, body_part.decode("utf-8", errors="replace"), latency_ms, False
            except Exception as exc:
                last_err = exc
                if raw_sock is not None:
                    try:
                        raw_sock.close()
                    except Exception:
                        pass
        raise last_err or OSError("连接失败")

    handlers: List[urllib.request.BaseHandler] = [
        urllib.request.HTTPSHandler(context=build_ssl_context())
    ]
    used_proxy = False
    if bypass_system_proxy and not proxy_url:
        handlers.insert(0, urllib.request.ProxyHandler({}))
    elif proxy_url:
        handlers.insert(0, urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
        used_proxy = True
    elif effective_proxy:
        used_proxy = True

    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        status_code = getattr(resp, "status", 200)
    latency_ms = (time.perf_counter() - start) * 1000.0
    return status_code, body, latency_ms, used_proxy


def decode_chunked(data: bytes) -> bytes:
    out = bytearray()
    idx = 0
    n = len(data)
    while idx < n:
        line_end = data.find(b"\r\n", idx)
        if line_end == -1:
            break
        size_str = data[idx:line_end].split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_str, 16)
        except ValueError:
            break
        if chunk_size == 0:
            break
        chunk_start = line_end + 2
        out.extend(data[chunk_start:chunk_start + chunk_size])
        idx = chunk_start + chunk_size + 2
    return bytes(out)


# ============================================================================
# 模块 1: 出口 IP / 归属 (ipinfo.io 优先，Cloudflare trace 兜底)
# ============================================================================

def normalize_country(value: Any) -> str:
    country = value.strip().upper() if isinstance(value, str) else ""
    return country if len(country) == 2 and country.isascii() and country.isalpha() else ""


def country_status(country: Any) -> str:
    """所有出口、候选与解析器共用此规则；无效国家代码也只能警告。"""
    country = normalize_country(country)
    if country in BLOCKED_COUNTRIES:
        return FAIL
    if country == NORMAL_COUNTRY:
        return PASS
    return WARN


def parse_ipinfo_payload(text: str, latency_ms: float, used_proxy: bool) -> ExitInfo:
    data = json.loads(text)
    ip_str = str(data.get("ip", "")).strip()
    if not ip_str:
        raise ValueError("ipinfo.io 响应缺少 ip 字段")
    ip_obj = ipaddress.ip_address(ip_str)
    if classify_address(ip_str)[0] != "PUBLIC":
        raise ValueError(f"ipinfo.io 返回非公网出口 IP ({ip_str})")

    org_raw = str(data.get("org", "")).strip()
    asn = ""
    org_name = org_raw
    if org_raw.startswith("AS") and " " in org_raw:
        asn, org_name = org_raw.split(" ", 1)

    return ExitInfo(
        success=True,
        source="ipinfo.io",
        ip=ip_str,
        ip_version=ip_obj.version,
        country=normalize_country(data.get("country")),
        region=str(data.get("region", "")).strip(),
        city=str(data.get("city", "")).strip(),
        org=org_name.strip(),
        asn=asn.strip(),
        via_proxy=used_proxy,
        latency_ms=round(latency_ms, 1),
    )


def parse_cf_trace_payload(text: str, latency_ms: float, used_proxy: bool) -> ExitInfo:
    kv: Dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()

    ip_str = kv.get("ip", "")
    if not ip_str:
        raise ValueError("Cloudflare trace 响应缺少 ip 字段")
    ip_obj = ipaddress.ip_address(ip_str)
    if classify_address(ip_str)[0] != "PUBLIC":
        raise ValueError(f"Cloudflare trace 返回非公网出口 IP ({ip_str})")

    return ExitInfo(
        success=True,
        source="cloudflare-trace",
        ip=ip_str,
        ip_version=ip_obj.version,
        country=normalize_country(kv.get("loc")),
        colo=kv.get("colo", ""),
        warp=kv.get("warp", ""),
        via_proxy=used_proxy,
        latency_ms=round(latency_ms, 1),
    )


def detect_exit_ip(
    prefer_v6: bool = False,
    bypass_system_proxy: bool = False,
    proxy_url: Optional[str] = None,
    timeout: float = 5.0,
) -> ExitInfo:
    """
    获取出口 IP 及归属信息：
    1. 优先请求 ipinfo.io (IPv4: ipinfo.io/json, IPv6: v6.ipinfo.io/json)
    2. 失败时使用 Cloudflare trace 兜底 (1.1.1.1 / [2606:4700:4700::1111] / cloudflare.com)
    """
    family = socket.AF_INET6 if prefer_v6 else socket.AF_INET
    if prefer_v6:
        ipinfo_urls = ["https://v6.ipinfo.io/json"]
        cf_urls = [
            "https://[2606:4700:4700::1111]/cdn-cgi/trace",
        ]
    else:
        ipinfo_urls = ["https://ipinfo.io/json"]
        cf_urls = [
            "https://1.1.1.1/cdn-cgi/trace",
            "https://www.cloudflare.com/cdn-cgi/trace",
            "https://1.0.0.1/cdn-cgi/trace",
        ]

    errors: List[str] = []

    # 1. ipinfo.io 优先
    for url in ipinfo_urls:
        try:
            status, body, latency, used_proxy = fetch_url_with_family(
                url,
                headers={"Accept": "application/json"},
                timeout=timeout,
                family=family,
                proxy_url=proxy_url,
                bypass_system_proxy=bypass_system_proxy,
            )
            if 200 <= status < 300:
                info = parse_ipinfo_payload(body, latency, used_proxy)
                if prefer_v6 and info.ip_version != 6:
                    errors.append(f"{url} 返回非 IPv6 地址 ({info.ip})")
                    continue
                if not prefer_v6 and info.ip_version != 4:
                    errors.append(f"{url} 返回非 IPv4 地址 ({info.ip})")
                    continue
                return info
            else:
                errors.append(f"ipinfo HTTP {status}")
        except Exception as exc:
            errors.append(f"ipinfo({url}): {exc}")

    # 2. Cloudflare trace 兜底
    for url in cf_urls:
        try:
            status, body, latency, used_proxy = fetch_url_with_family(
                url,
                timeout=timeout,
                family=family,
                proxy_url=proxy_url,
                bypass_system_proxy=bypass_system_proxy,
            )
            if 200 <= status < 300:
                info = parse_cf_trace_payload(body, latency, used_proxy)
                if prefer_v6 and info.ip_version != 6:
                    errors.append(f"{url} 返回非 IPv6 地址 ({info.ip})")
                    continue
                if not prefer_v6 and info.ip_version != 4:
                    errors.append(f"{url} 返回非 IPv6/v4 匹配地址 ({info.ip})")
                    continue
                return info
            else:
                errors.append(f"cf-trace HTTP {status}")
        except Exception as exc:
            errors.append(f"cf-trace({url}): {exc}")

    return ExitInfo(
        success=False,
        error="; ".join(errors[:3]) if errors else "未知错误",
    )


def lookup_ip_attribution(ip_str: str, timeout: float = 4.0) -> IPAttribution:
    """核验查询 IP 与回传 IP 一致，只使用 country_code，不使用注册地。"""
    result = IPAttribution(ip=ip_str)
    try:
        address = ipaddress.ip_address(ip_str)
        if classify_address(ip_str)[0] != "PUBLIC":
            raise ValueError("归属查询需要有效公网 IP")
        result.ip = str(address)
        result.source = f"https://ipleak.net/json/{urllib.parse.quote(result.ip, safe=':')}"
        status, body, _, _ = fetch_url_with_family(result.source, timeout=timeout)
        if not 200 <= status < 300:
            raise ValueError(f"HTTP {status}")
        data = json.loads(body)
        if not isinstance(data, dict) or ipaddress.ip_address(data.get("ip", "")) != address:
            raise ValueError("归属查询返回了不同的 IP")
        result.country = normalize_country(data.get("country_code"))
        result.country_name = str(data.get("country_name") or "")
        result.org = str(data.get("isp_name") or "")
        as_number = str(data.get("as_number") or "")
        result.asn = f"AS{as_number}" if as_number.isdecimal() else ""
        if result.country not in COUNTRY_CODES:
            result.country = ""
            raise ValueError("国家/地区归属缺失或无效")
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    return result


# ============================================================================
# 模块 2: STUN / 外部 ICE 候选采样
# ============================================================================

def build_stun_binding_request() -> Tuple[bytes, bytes]:
    """构造 RFC 5389 标准 STUN Binding Request 报文 (20 字节)"""
    magic_cookie = 0x2112A442
    tx_id = os.urandom(12)
    packet = struct.pack("!HHI", 0x0001, 0x0000, magic_cookie) + tx_id
    return packet, tx_id


def parse_stun_binding_response(data: bytes, expected_tx_id: bytes) -> Optional[Tuple[str, int]]:
    """严格校验 STUN 头与全部属性边界，再返回映射地址（XOR 优先）。"""
    if len(data) < 20 or len(expected_tx_id) != 12:
        return None
    msg_type, msg_len, magic_cookie = struct.unpack("!HHI", data[:8])
    if (msg_type != 0x0101 or magic_cookie != 0x2112A442
            or data[8:20] != expected_tx_id or msg_len % 4
            or len(data) != 20 + msg_len):
        return None

    offset = 20
    mapped = None
    xor_mapped = None
    while offset < len(data):
        if offset + 4 > len(data):
            return None
        attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
        value_start = offset + 4
        padded_end = value_start + ((attr_len + 3) & ~3)
        if padded_end > len(data):
            return None
        value = data[value_start:value_start + attr_len]
        offset = padded_end
        if attr_type not in (0x0001, 0x0020, 0x8020):
            continue
        if len(value) < 4:
            return None
        family = value[1]
        expected_length = {1: 8, 2: 20}.get(family)
        if expected_length is None or len(value) != expected_length:
            return None
        port = struct.unpack("!H", value[2:4])[0]
        address = value[4:]
        is_xor = attr_type != 0x0001
        if is_xor:
            port ^= magic_cookie >> 16
            mask = struct.pack("!I", magic_cookie) + expected_tx_id
            address = bytes(a ^ b for a, b in zip(address, mask))
        result = (str(ipaddress.ip_address(address)), port)
        if is_xor:
            if xor_mapped is not None and xor_mapped != result:
                return None
            xor_mapped = result
        else:
            if mapped is not None and mapped != result:
                return None
            mapped = result

    return xor_mapped or mapped


def query_single_stun(
    host: str, port: int, timeout: float = 2.0, label: str = "",
) -> StunProbeResult:
    """保留每个探测的响应与错误；无响应不等于 UDP 已被阻断。"""
    result = StunProbeResult(server=label or f"{host}:{port}")
    try:
        addresses = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    except Exception as exc:
        result.errors.append(f"DNS 失败: {exc}")
        return result

    seen = set()
    completed_families = set()
    for af, socktype, proto, _, sockaddr in addresses:
        key = (af, sockaddr)
        if key in seen or af in completed_families:
            continue
        seen.add(key)
        resolved_ip = sockaddr[0]
        category, version = classify_address(resolved_ip)
        if category == "FAKE-IP":
            result.candidates.append(CandidateItem(
                address=resolved_ip, port=port, candidate_type="dns-resolved",
                source=f"DNS({host})", category=category, ip_version=version,
            ))
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            local_ip, local_port = sock.getsockname()[:2]
            local_category, local_version = classify_address(local_ip)
            result.candidates.append(CandidateItem(
                address=local_ip, port=local_port, candidate_type="host",
                source=f"udp-route({result.server})",
                category=local_category, ip_version=local_version,
            ))
            packet, transaction = build_stun_binding_request()
            sock.sendall(packet)
            parsed = parse_stun_binding_response(sock.recv(65535), transaction)
            if parsed is None:
                result.errors.append(f"{resolved_ip}: 无效 STUN 响应")
                continue
            address, mapped_port = parsed
            mapped_category, mapped_version = classify_address(address)
            if mapped_category != "PUBLIC":
                result.errors.append(f"{resolved_ip}: STUN 映射地址不是公网地址 ({address})")
                continue
            result.responses += 1
            completed_families.add(af)
            result.candidates.append(CandidateItem(
                address=address, port=mapped_port, candidate_type="srflx",
                source=f"stun:{result.server}", category=mapped_category,
                ip_version=mapped_version,
            ))
        except Exception as exc:
            result.errors.append(f"{resolved_ip}: {type(exc).__name__}: {exc}")
        finally:
            if sock is not None:
                sock.close()
    if not addresses:
        result.errors.append("DNS 未返回地址")
    return result


def parse_extra_ice_candidates(raw_candidates: List[str]) -> List[CandidateItem]:
    """解析外部传入的 WebRTC ICE 候选字符串或地址"""
    results: List[CandidateItem] = []
    for raw in (line for entry in raw_candidates for line in entry.splitlines()):
        line = raw.strip()
        if not line:
            continue
        m = ICE_CANDIDATE_RE.search(line)
        if m:
            _, addr, port_str, cand_type = m.groups()
            cat, ver = classify_address(addr)
            results.append(
                CandidateItem(
                    address=addr,
                    port=int(port_str),
                    candidate_type=cand_type.lower(),
                    source="ice-sdp-input",
                    category=cat,
                    ip_version=ver,
                )
            )
            # srflx/relay 的 related address 也可能暴露公网地址，不能只看主地址。
            tokens = line[m.end():].split()
            for index, token in enumerate(tokens):
                if token.lower() != "raddr":
                    continue
                related = tokens[index + 1] if index + 1 < len(tokens) else "<missing-raddr>"
                cat, ver = classify_address(related)
                results.append(CandidateItem(
                    address=related, candidate_type="related", source="ice-sdp-input:raddr",
                    category=cat, ip_version=ver,
                ))
            if not 1 <= int(port_str) <= 65535:
                # 记录格式错误，避免其他 US 候选掩盖无法完整解析的输入。
                results.append(CandidateItem(address=line, candidate_type="invalid",
                                             source="ice-sdp-input", category="HOSTNAME"))
        else:
            cat, ver = classify_address(line)
            results.append(
                CandidateItem(
                    address=line,
                    port=0,
                    candidate_type="custom",
                    source="cli-input",
                    category=cat,
                    ip_version=ver,
                )
            )
    return results


def check_webrtc_leak(
    v4_exit: ExitInfo,
    extra_candidates: Optional[List[str]] = None,
    timeout: float = 2.0,
) -> WebRTCReport:
    """核验 STUN/外部 ICE 样本；不从 Bonjour 主机名推断浏览器行为。"""
    probes = []
    targets = [(host, port, f"{host}:{port}") for host, port in STUN_SERVERS]
    targets.extend(DIRECT_IP_STUN_SERVERS)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(targets))) as pool:
        futures = [pool.submit(query_single_stun, h, p, timeout, label)
                   for h, p, label in targets]
        for target, future in zip(targets, futures):
            try:
                probes.append(future.result())
            except Exception as exc:
                probes.append(StunProbeResult(server=target[2], errors=[str(exc)]))

    items = [item for probe in probes for item in probe.candidates]
    extra = parse_extra_ice_candidates(extra_candidates or [])
    items.extend(extra)
    deduped = []
    seen = set()
    for item in items:
        key = (item.source, item.candidate_type, item.address.lower())
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    baseline = None
    if v4_exit.success:
        try:
            baseline = ipaddress.ip_address(v4_exit.ip)
            if not baseline.is_global or is_fake_ip(baseline):
                baseline = None
        except ValueError:
            pass

    mdns = sorted({item.address for item in extra
                   if item.source == "ice-sdp-input" and item.category == "mDNS-UUID"})
    fake_ips = sorted({item.address for item in deduped if item.category == "FAKE-IP"})
    srflx = sorted({item.address for item in deduped
                    if item.category == "PUBLIC" and item.candidate_type == "srflx"})
    mismatched, unverified = set(), set()
    invalid_inputs = []
    for item in extra:
        if item.category in ("HOSTNAME", "RESERVED") or (item.candidate_type == "custom"
                                          and item.category.startswith("mDNS")):
            invalid_inputs.append(item.address)
    public_items: Dict[str, List[CandidateItem]] = {}
    for item in deduped:
        # OS socket 的源地址不代表浏览器向网页暴露了该 host candidate。
        if item.source.startswith("udp-route("):
            continue
        if item.category != "PUBLIC" or item.candidate_type not in (
                "host", "srflx", "prflx", "relay", "related", "custom"):
            continue
        address = ipaddress.ip_address(item.address.split("%", 1)[0].strip("[]"))
        public_items.setdefault(str(address), []).append(item)
        if baseline is not None and address.version == baseline.version:
            item.matches_exit_ip = address == baseline
            if not item.matches_exit_ip:
                mismatched.add(str(address))

    attributions: Dict[str, IPAttribution] = {}
    # 同一地址可复用已取得的出口归属；不同 IP/地址族必须独立查询。
    if baseline is not None and normalize_country(v4_exit.country) in COUNTRY_CODES:
        attributions[str(baseline)] = IPAttribution(
            ip=str(baseline), country=normalize_country(v4_exit.country),
            org=v4_exit.org, source=v4_exit.source,
        )
    missing = sorted(set(public_items) - set(attributions))
    if missing:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(missing))) as pool:
            pending = [(ip, pool.submit(lookup_ip_attribution, ip, timeout)) for ip in missing]
            for ip, future in pending:
                try:
                    attributions[ip] = future.result()
                except Exception as exc:
                    attributions[ip] = IPAttribution(ip=ip, error=str(exc))

    statuses, errors, warnings = [], [], []
    for ip, candidates in sorted(public_items.items()):
        attribution = attributions[ip]
        state = country_status(attribution.country)
        if attribution.error:
            state = WARN
        statuses.append(state)
        for item in candidates:
            item.country, item.org = attribution.country, attribution.org
            item.attribution_source, item.attribution_error = attribution.source, attribution.error
        if attribution.error or attribution.country not in COUNTRY_CODES:
            unverified.add(ip)
        if state != PASS:
            sources = ", ".join(sorted({item.source for item in candidates}))
            reason = f"{sources}: {ip} [{attribution.country or '归属未知'}]"
            if attribution.error:
                reason += f"；{attribution.error}"
            (errors if state == FAIL else warnings).append(reason)

    responders = sum(probe.responses > 0 for probe in probes)
    if not public_items:
        statuses.append(WARN)
        warnings.append("未获得公网候选；无回包不能视为没有异常出口")
    if responders != len(probes):
        statuses.append(WARN)
        warnings.append(f"{len(probes) - responders}/{len(probes)} STUN 探测未获得有效回包，详情见 --json")
    if invalid_inputs:
        statuses.append(WARN)
        warnings.append("无法识别的候选输入: " + ", ".join(invalid_inputs))
    status = aggregate_status(statuses)
    countries = "/".join(sorted({attributions[ip].country or "?" for ip in public_items})) or "未获IP"
    summary = f"{responders}/{len(probes)} STUN | {countries}"
    reasons = errors + warnings

    supplied = any(item.source == "ice-sdp-input" for item in extra)
    summary += " | ICE样本" if supplied else " | 浏览器未测"
    return WebRTCReport(
        status=status, summary=summary, reasons=reasons,
        exit_ips_compared=[str(baseline)] if baseline else [],
        stun_srflx_ips=srflx, mismatched_ips=sorted(mismatched),
        unverified_ips=sorted(unverified), browser_ice_supplied=supplied,
        has_mdns_obfuscation=bool(mdns), mdns_candidates=mdns,
        has_fake_ip=bool(fake_ips), fake_ip_candidates=fake_ips,
        candidates=deduped, probes=probes,
    )


# ============================================================================
# 模块 3: 本机 IPv6 路径与代理远端 IPv6 分开记录
# ============================================================================

def probe_tunnel_v6_endpoint(proxy_url: Optional[str] = None, timeout: float = 2.0) -> ExitInfo:
    """默认路径可能是 HTTP 代理或 TUN；成功不证明本机原生 IPv6 直连。"""
    try:
        status, body, latency, used_proxy = fetch_url_with_family(
            "https://v6.ipinfo.io/json", headers={"Accept": "application/json"},
            timeout=timeout, proxy_url=proxy_url,
        )
        if not 200 <= status < 300:
            return ExitInfo(error=f"HTTP {status}")
        info = parse_ipinfo_payload(body, latency, used_proxy)
        if info.ip_version == 6:
            return info
        return ExitInfo(error=f"端点返回 IPv{info.ip_version}，未确认 IPv6 出口")
    except Exception as exc:
        return ExitInfo(error=f"{type(exc).__name__}: {exc}")


def check_ipv6_exposure(
    v4_exit: ExitInfo,
    proxy_url: Optional[str] = None,
    timeout: float = 2.0,
) -> Tuple[ExitInfo, IPv6Report]:
    """分别检查本机与默认/代理 IPv6 的地域；连通本身不判为错误。"""
    route_available = has_local_ipv6_route()
    local_v6 = ExitInfo()
    if route_available is not False:
        local_v6 = detect_exit_ip(
            prefer_v6=True, bypass_system_proxy=True, timeout=timeout,
        )
    default_v6 = probe_tunnel_v6_endpoint(proxy_url=proxy_url, timeout=timeout)
    chosen = local_v6 if local_v6.success else default_v6
    statuses, errors, warnings, descriptions = [], [], [], []
    for label, info in (("本机", local_v6), ("默认/代理", default_v6)):
        if label == "本机" and route_available is False and not info.success:
            descriptions.append("本机无路由")
            continue
        result = evaluate_exit_country(info)
        if info.success and classify_address(info.ip) != ("PUBLIC", 6):
            result = CheckResult(WARN, "未返回有效公网 IPv6", [info.ip])
        statuses.append(result.status)
        descriptions.append(f"{label} {normalize_country(info.country) or '?'}" if info.success
                            else f"{label}未确认")
        if result.status != PASS:
            reason = f"{label}: {result.summary}"
            if result.reasons:
                reason += "；" + "; ".join(result.reasons)
            (errors if result.status == FAIL else warnings).append(reason)
    status = aggregate_status(statuses)
    summary = " | ".join(descriptions)
    reasons = errors + warnings
    # 用户在路由器关闭了 IPv6：无本机路由且没有观测到 IPv6 出口属于预期。
    # 不把探测失败宣称为全路径关闭证明；原始错误仍保留在 JSON 的 probe 字段。
    if route_available is False and not local_v6.success and not default_v6.success:
        status = PASS
        summary = "本机无路由，未测得 IPv6 出口"
        reasons = []

    country_match = None
    if chosen.success and v4_exit.country and chosen.country:
        country_match = chosen.country.upper() == v4_exit.country.upper()
    report = IPv6Report(
        status=status, summary=summary, reasons=reasons,
        local_route_available=route_available,
        ipv6_reachable=local_v6.success or default_v6.success,
        local_stack_v6_reachable=local_v6.success,
        default_path_v6_reachable=default_v6.success,
        local_probe_error=local_v6.error, default_probe_error=default_v6.error,
        local_probe=local_v6, default_probe=default_v6,
        ipv4_exit_ip=v4_exit.ip, ipv4_country=v4_exit.country,
        ipv6_exit_ip=chosen.ip, ipv6_country=chosen.country,
        ipv6_org=chosen.org, ipv6_source=chosen.source,
        country_match=country_match,
    )
    return chosen, report


# ============================================================================
# 模块 4: DNS 解析器地域采样与 DoH 辅助诊断
# ============================================================================

def test_single_doh_endpoint(
    provider: str,
    name: str,
    url: str,
    proxy_url: Optional[str] = None,
    timeout: float = 3.5,
) -> DoHEndpointResult:
    """
    测试单个 DoH (DNS-over-HTTPS) 端点：
    1. 校验 HTTPS TLS 证书与 HTTP 200 状态码
    2. 校验 DNS RCODE (Status == 0, NOERROR)
    3. 校验问题匹配及 A/AAAA 记录格式；合法公网地址本身并不能证明 DNS 数据正确
    4. 若为 o-o.myaddr.l.google.com TXT 探测，提取 edns0-client-subnet 与递归解析器出口 IP
    """
    try:
        status, body, latency, _ = fetch_url_with_family(
            url,
            headers={"Accept": "application/dns-json"},
            timeout=timeout,
            proxy_url=proxy_url,
        )
        if 200 <= status < 300:
            data = json.loads(body)
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            expected_name = query["name"][0].lower().rstrip(".")
            expected_type = {"A": 1, "AAAA": 28, "TXT": 16}[query["type"][0].upper()]
            questions = data.get("Question") or []
            if not any(q.get("name", "").lower().rstrip(".") == expected_name
                       and q.get("type") == expected_type for q in questions):
                raise ValueError("DoH 响应 Question 与请求不匹配")
            if data.get("TC"):
                raise ValueError("DoH 响应被截断，证据不完整")
            dns_rcode = int(data.get("Status", -1))
            answers = data.get("Answer", []) or []
            ips: List[str] = []
            has_valid_public = False
            has_fake = False
            has_bogon = False
            ecs_subnet = ""
            resolver_ip = ""

            for ans in answers:
                rtype = ans.get("type")
                rdata = str(ans.get("data", "")).strip().strip('"')
                if rtype in (1, 28) and rtype == expected_type:
                    ips.append(rdata)
                    cat, _ = classify_address(rdata)
                    if cat == "PUBLIC":
                        has_valid_public = True
                    elif cat == "FAKE-IP":
                        has_fake = True
                    else:
                        has_bogon = True
                elif rtype == 16 and expected_type == 16:
                    if rdata.lower().startswith("edns0-client-subnet"):
                        parts = rdata.split()
                        if len(parts) >= 2:
                            ecs_subnet = parts[1].strip()
                    else:
                        cat, _ = classify_address(rdata)
                        if cat == "PUBLIC" and not resolver_ip:
                            resolver_ip = rdata

            return DoHEndpointResult(
                provider=provider,
                name=name,
                url=url,
                reachable=(dns_rcode == 0 and len(answers) > 0),
                status_code=status,
                dns_rcode=dns_rcode,
                latency_ms=round(latency, 1),
                resolved_ips=ips,
                has_valid_public_answer=has_valid_public,
                has_fake_ip_answer=has_fake,
                has_bogon_answer=has_bogon,
                ecs_subnet=ecs_subnet,
                resolver_ip=resolver_ip,
                error=(f"DNS RCODE={dns_rcode}" if dns_rcode != 0
                       else ("DNS 未返回答案" if not answers else "")),
            )
        return DoHEndpointResult(
            provider=provider,
            name=name,
            url=url,
            reachable=False,
            status_code=status,
            latency_ms=round(latency, 1),
            error=f"HTTP {status}",
        )
    except Exception as exc:
        return DoHEndpointResult(
            provider=provider,
            name=name,
            url=url,
            reachable=False,
            error=str(exc),
        )


def check_cf_1111_trace(proxy_url: Optional[str] = None, timeout: float = 3.5) -> ExitInfo:
    """1.1.1.1 HTTPS 连接的出口样本，不能代替系统 DNS 的出口测量。"""
    try:
        status, body, latency, used_proxy = fetch_url_with_family(
            "https://1.1.1.1/cdn-cgi/trace", timeout=timeout,
            family=socket.AF_INET, proxy_url=proxy_url,
        )
        if 200 <= status < 300:
            return parse_cf_trace_payload(body, latency, used_proxy)
        return ExitInfo(error=f"HTTP {status}")
    except Exception as exc:
        return ExitInfo(error=f"{type(exc).__name__}: {exc}")


def compare_exit_ip(expected_ip: str, observed_ip: str) -> Optional[bool]:
    """仅比较同地址族的完整公网 IP；未知或跨地址族不判一致/不一致。"""
    try:
        expected = ipaddress.ip_address(expected_ip)
        observed = ipaddress.ip_address(observed_ip)
        if (not expected.is_global or not observed.is_global
                or is_fake_ip(expected) or is_fake_ip(observed)
                or expected.version != observed.version):
            return None
        return expected == observed
    except ValueError:
        return None


def compare_ecs_subnet(ip_str: str, subnet_str: str) -> Optional[bool]:
    """ECS 仅提供网段样本；/0、格式错误及跨地址族都不是出口一致的证据。"""
    try:
        address = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(subnet_str, strict=False)
        if not address.is_global or network.prefixlen == 0 or address.version != network.version:
            return None
        if not network.network_address.is_global or is_fake_ip(network.network_address):
            return None
        return address in network
    except ValueError:
        return None


def parse_dns_observations(body: str, session: str) -> Tuple[Dict[str, int], List[str]]:
    """IPLeak 返回会话累计计数；无效条目保留为错误，不能静默丢弃后放行。"""
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("DNS API 返回格式异常，需要会话对象")
    if data.get("session") != session:
        raise ValueError("DNS API 会话不匹配，不能使用该结果")
    entries = data.get("ip")
    if not isinstance(entries, dict):
        raise ValueError("DNS API 缺少解析器地址表")
    observations, errors = {}, []
    for raw_ip, count in entries.items():
        try:
            address = ipaddress.ip_address(raw_ip)
            if classify_address(raw_ip)[0] != "PUBLIC":
                raise ValueError("非公网地址")
            if type(count) is not int or count <= 0:
                raise ValueError("查询计数无效")
            ip = str(address)
            observations[ip] = max(observations.get(ip, 0), count)
        except ValueError as exc:
            errors.append(f"解析器条目 {raw_ip}: {exc}")
    if not observations:
        errors.append("该轮未返回有效解析器地址")
    return observations, errors


def lookup_dns_resolver(ip: str, query_count: int = 0, timeout: float = 4.0) -> DNSResolver:
    """使用 IPLeak 的 country_code，不用注册国家、服务商名称或 HTTP 出口国家代替。"""
    attribution = lookup_ip_attribution(ip, timeout)
    return DNSResolver(**asdict(attribution), query_count=query_count)


def probe_dns_resolvers(timeout: float = 4.0, sample_count: int = DNS_DEFAULT_SAMPLES) -> DNSResolverReport:
    """经本机系统解析器和当前 TUN 访问随机域名；不使用显式/系统 HTTP 代理。

    必须实际连接：Fake-IP 模式仅 getaddrinfo 可能还没有触发上游查询。
    API: https://ipleak.net/ 的 DNS detection 文档。相同 40 字符会话，每轮换标签。
    """
    if not 1 <= sample_count <= 20:
        raise ValueError("DNS 采样次数必须在 1 到 20 之间")
    session = secrets.token_hex(20)
    report = DNSResolverReport(session=session, requested_samples=sample_count)
    observations: Dict[str, int] = {}
    for index in range(sample_count):
        # IPLeak 对 label 中的额外连字符返回 []；整个域名标签只保留一个分隔符。
        label = f"{index:02x}{secrets.token_hex(4)}"
        hostname = f"{session}-{label}.ipleak.net"
        sample = DNSProbeSample(hostname=hostname)
        try:
            status, body, elapsed, used_proxy = fetch_url_with_family(
                f"https://{hostname}/dnsdetection/", timeout=timeout,
                family=socket.AF_UNSPEC, proxy_url=None, bypass_system_proxy=True,
            )
            sample.status_code = status
            sample.latency_ms = round(elapsed, 1)
            if used_proxy:
                raise ValueError("探测经过 HTTP 代理，无法确认本机解析路径")
            if not 200 <= status < 300:
                raise ValueError(f"HTTP {status}")
            found, errors = parse_dns_observations(body, session)
            sample.resolver_ips = sorted(found)
            for ip, count in found.items():
                # 每轮是累计快照，不能累加；早期出现过的地址也不能被后续快照抹掉。
                observations[ip] = max(observations.get(ip, 0), count)
            if errors:
                sample.error = "; ".join(errors)
            else:
                report.successful_samples += 1
        except Exception as exc:
            sample.error = f"{type(exc).__name__}: {exc}"
        report.samples.append(sample)

    if observations:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(observations))) as pool:
            pending = [(ip, pool.submit(lookup_dns_resolver, ip, count, timeout))
                       for ip, count in sorted(observations.items())]
            for ip, future in pending:
                try:
                    report.resolvers.append(future.result())
                except Exception as exc:
                    report.resolvers.append(DNSResolver(ip=ip, query_count=observations[ip], error=str(exc)))

    blocked = [item for item in report.resolvers if country_status(item.country) == FAIL]
    unknown = [item for item in report.resolvers if item.error or item.country not in COUNTRY_CODES]
    other = [item for item in report.resolvers
             if item.country in COUNTRY_CODES and country_status(item.country) == WARN]
    sample_errors = [f"第 {index + 1} 轮: {sample.error}"
                     for index, sample in enumerate(report.samples) if sample.error]
    if blocked:
        report.status = FAIL
        report.summary = f"检出 CN/HK DNS（{len(blocked)} 个）"
        report.reasons = [f"{item.ip} [{item.country}] {item.org}".rstrip() for item in blocked]
    elif not report.resolvers or unknown or other or report.successful_samples != sample_count:
        report.status = WARN
        report.summary = "DNS 含其他地区或证据不全"
        report.reasons = [f"{item.ip} 归属未确认: {item.error or '缺少国家/地区'}" for item in unknown]
        if not report.resolvers:
            report.reasons.append("未观测到解析器，无法核验地域")
    else:
        report.status = PASS
        report.summary = f"{len(report.resolvers)} 个 DNS / US | {report.successful_samples}/{sample_count} 轮"
    report.reasons.extend(f"{item.ip} [{item.country}]：非 US、CN/HK 地区" for item in other)
    report.reasons.extend(sample_errors)
    # 即使已经命中禁区，JSON 仍保留其他归属缺失，方便复核完整性。
    if blocked:
        report.reasons.extend(f"{item.ip} 归属未确认: {item.error}" for item in unknown)
    return report


def check_dns_reachability(
    v4_exit: ExitInfo,
    proxy_url: Optional[str] = None,
    timeout: float = 3.5,
    sample_count: int = DNS_DEFAULT_SAMPLES,
) -> DNSReport:
    """DNS 使用统一地域规则；DoH 连通性/一致性仅作辅助诊断，不参与地域汇总。"""
    sys_ips, sys_error = [], ""
    try:
        infos = socket.getaddrinfo("example.com", 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        sys_ips = sorted({item[4][0] for item in infos})
        if not sys_ips:
            sys_error = "系统解析未返回地址"
    except Exception as exc:
        sys_error = f"{type(exc).__name__}: {exc}"

    targets = [
        ("cloudflare", "Cloudflare IP DoH", "https://1.1.1.1/dns-query?name=example.com&type=A"),
        ("cloudflare", "Cloudflare 域名 DoH", "https://cloudflare-dns.com/dns-query?name=example.com&type=A"),
        ("google", "Google DoH", "https://dns.google/resolve?name=example.com&type=A"),
        ("google_ecs", "Google ECS", "https://dns.google/resolve?name=o-o.myaddr.l.google.com&type=TXT"),
    ]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets) + 2) as pool:
        futures = [pool.submit(test_single_doh_endpoint, *target, proxy_url, timeout)
                   for target in targets]
        trace_future = pool.submit(check_cf_1111_trace, proxy_url, timeout)
        resolver_future = pool.submit(probe_dns_resolvers, timeout, sample_count)
        for target, future in zip(targets, futures):
            try:
                results.append(future.result())
            except Exception as exc:
                results.append(DoHEndpointResult(*target, error=str(exc)))
        try:
            trace = trace_future.result()
        except Exception as exc:
            trace = ExitInfo(error=str(exc))
        try:
            resolver_detection = resolver_future.result()
        except Exception as exc:
            resolver_detection = DNSResolverReport(
                summary="DNS 采样失败", requested_samples=sample_count,
                reasons=[f"{type(exc).__name__}: {exc}"],
            )

    def valid_answer(result: DoHEndpointResult) -> bool:
        return (result.reachable and result.has_valid_public_answer
                and not result.has_fake_ip_answer and not result.has_bogon_answer)

    cf_ok = any(valid_answer(r) for r in results if r.provider == "cloudflare")
    google_ok = any(valid_answer(r) for r in results if r.provider == "google")
    ecs_result = next(r for r in results if r.provider == "google_ecs")
    ecs = ecs_result.ecs_subnet if ecs_result.reachable else ""
    resolver_ip = ecs_result.resolver_ip if ecs_result.reachable else ""
    cf_aligned = compare_exit_ip(v4_exit.ip, trace.ip) if v4_exit.success and trace.success else None
    google_aligned = compare_ecs_subnet(v4_exit.ip, ecs) if v4_exit.success and ecs else None

    failures, uncertainties = [], []
    for result in results:
        if result.reachable and (result.has_fake_ip_answer or result.has_bogon_answer):
            failures.append(f"{result.name} 返回非公网地址: {', '.join(result.resolved_ips)}")
    if cf_aligned is False:
        failures.append(f"Cloudflare HTTPS 出口 {trace.ip} 与主出口 {v4_exit.ip} 不同，需核对分流")
    elif cf_aligned is None:
        uncertainties.append("Cloudflare 出口未确认" + (f": {trace.error}" if trace.error else ""))
    if google_aligned is False:
        failures.append(f"Google ECS 网段 {ecs} 不包含主出口 {v4_exit.ip}，需核对分流")
    elif google_aligned is None:
        uncertainties.append("Google 未提供可比对的 ECS；解析器地址不能代替客户端出口")
    if not cf_ok:
        uncertainties.append("Cloudflare DoH 查询未成功，不能据此认定泄漏")
    if not google_ok:
        uncertainties.append("Google DoH 查询未成功，不能据此认定泄漏")
    if sys_error:
        uncertainties.append(f"系统 DNS 查询未成功: {sys_error}")

    if failures:
        doh_status = WARN
        doh_summary = "DoH 响应或出口样本有差异（辅助）"
    elif cf_ok and google_ok and cf_aligned is True and google_aligned is True:
        doh_status = PASS
        doh_summary = "DoH 样本一致"
    else:
        doh_status = WARN
        doh_summary = "DoH 待确认"
    return DNSReport(
        status=resolver_detection.status, summary=resolver_detection.summary,
        system_dns_status=resolver_detection.status, resolver_detection=resolver_detection,
        doh_status=doh_status, doh_summary=doh_summary, doh_reasons=failures + uncertainties,
        cloudflare_doh_ok=cf_ok, google_doh_ok=google_ok,
        cf_trace_ip=trace.ip, cf_trace_country=trace.country,
        cf_egress_aligned=cf_aligned, cf_trace_error=trace.error,
        google_ecs_subnet=ecs, google_resolver_ip=resolver_ip,
        google_egress_aligned=google_aligned, system_dns_ips=sys_ips,
        system_dns_is_fake_ip=any(classify_address(ip)[0] == "FAKE-IP" for ip in sys_ips),
        system_dns_error=sys_error, reasons=resolver_detection.reasons, endpoints=results,
    )


# ============================================================================
# 方案 B：终端等宽对齐与逐步实时渲染
# ============================================================================

def char_display_width(ch: str) -> int:
    """计算单个字符在终端中的显示列宽（中文字符/全角符号/Emoji 占 2 列）"""
    if ch in ("✅", "❌", "❔", "⏳"):
        return 2
    eaw = unicodedata.east_asian_width(ch)
    return 2 if eaw in ("W", "F") else 1


def str_display_width(text: str) -> int:
    return sum(char_display_width(c) for c in text)


def pad_right(text: str, width: int) -> str:
    """按终端实际显示宽度右补空格（超长时自动保证至少 2 格间距）"""
    cur = str_display_width(text)
    if cur >= width - 2:
        return text + "  "
    return text + " " * (width - cur)


# 表格各列宽度定义
COL_IDX = 6
COL_NAME = 18
COL_STAT = 12
COL_RES = 48
COL_RULE = 12


def print_table_header() -> None:
    print("规则: " + REGION_POLICY, flush=True)
    h_idx = pad_right("序号", COL_IDX)
    h_name = pad_right("检测项目", COL_NAME)
    h_stat = pad_right("状态", COL_STAT)
    h_res = pad_right("当前检测结果", COL_RES)
    h_rule = "评估标准"
    print(f"{h_idx}{h_name}{h_stat}{h_res}{h_rule}", flush=True)
    print(
        f"{'─' * (COL_IDX - 2)}  "
        f"{'─' * (COL_NAME - 2)}  "
        f"{'─' * (COL_STAT - 2)}  "
        f"{'─' * (COL_RES - 2)}  "
        f"{'─' * COL_RULE}",
        flush=True,
    )


def show_step_running(idx: int, name: str) -> None:
    """在 TTY 下显示当前步骤正在检测的临时状态行"""
    if not sys.stdout.isatty():
        return
    c_idx = pad_right(f"[{idx}]", COL_IDX)
    c_name = pad_right(name, COL_NAME)
    c_stat = pad_right("⏳", COL_STAT)
    sys.stdout.write(f"\r{c_idx}{c_name}{c_stat}正在检测...")
    sys.stdout.flush()


def print_table_row(
    idx: int, name: str, status: str, result_text: str, rule_text: str,
    details: Optional[List[str]] = None,
) -> None:
    """异常/无法确认仅展开至多两条原因；完整证据见 --json。"""
    if sys.stdout.isatty():
        sys.stdout.write("\r\033[K")
    print(pad_right(f"[{idx}]", COL_IDX) + pad_right(name, COL_NAME)
          + pad_right(STATUS_LABELS[status], COL_STAT)
          + pad_right(result_text, COL_RES) + rule_text, flush=True)
    if status != PASS and details:
        visible = list(details[:2])
        if len(details) > 2:
            visible[-1] += f"（另 {len(details) - 2} 条见 --json）"
        for index, detail in enumerate(visible):
            branch = "└─" if index == len(visible) - 1 else "├─"
            print(" " * COL_IDX + f"{branch} {detail}", flush=True)


def aggregate_status(statuses: List[str]) -> str:
    """异常优先；任何未识别状态也不得误放行为通过。"""
    if FAIL in statuses:
        return FAIL
    if not statuses or any(status != PASS for status in statuses):
        return WARN
    return PASS


def evaluate_exit_country(info: ExitInfo) -> CheckResult:
    if not info.success or classify_address(info.ip)[0] != "PUBLIC":
        return CheckResult(WARN, "出口获取失败", [info.error or "没有有效公网出口"])
    country = normalize_country(info.country)
    summary = f"{info.ip} ({country if country in COUNTRY_CODES else '归属未知'})"
    status = country_status(country)
    if country not in COUNTRY_CODES:
        return CheckResult(WARN, summary, ["国家/地区归属缺失或无效"])
    if status == FAIL:
        return CheckResult(FAIL, summary, [f"检出 {country} 公网地址"])
    if status == WARN:
        return CheckResult(WARN, summary, [f"归属 {country}：非 US、CN/HK 地区"])
    return CheckResult(status, summary)


# ============================================================================
# CLI：两种输出共用一套判定，0=正常、1=报错、2=警告
# ============================================================================

def positive_timeout(value: str) -> float:
    result = float(value)
    if not 0 < result < float("inf"):
        raise argparse.ArgumentTypeError("timeout 必须是有限正数")
    return result


def dns_sample_count(value: str) -> int:
    result = int(value)
    if not 1 <= result <= 20:
        raise argparse.ArgumentTypeError("DNS 采样次数必须在 1 到 20 之间")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="出口 IP / STUN 采样 / IPv6 / DNS 解析器统一地域检查",
        epilog=(REGION_POLICY + "。返回码: 0=全部正常, 1=存在报错, 2=存在警告（无报错）。"
                "按路由器关闭 IPv6 的设置，本机无路由且未测得 IPv6 出口时正常。"
                "DNS 使用 IPLeak 采样本机解析/TUN 路径；浏览器独立安全 DNS 未测；"
                "DoH 仅作辅助诊断。JSON schema_version=3，状态为 PASS/FAIL/WARN。"),
    )
    parser.add_argument("--expect-country", type=lambda value: value.strip().upper(),
                        choices=[NORMAL_COUNTRY], default=NORMAL_COUNTRY,
                        help="兼容旧命令，仅接受 US；四项统一使用固定地域规则")
    parser.add_argument("--proxy", help="HTTP/HTTPS 代理地址，例如 http://127.0.0.1:7890")
    parser.add_argument("--candidate", action="append", dest="candidates", default=[],
                        help="附加实际 ICE candidate 或公网地址样本；不表示浏览器候选已采集完整")
    parser.add_argument("--timeout", type=positive_timeout, default=4.0,
                        help="每次 socket 操作超时秒数，默认 4.0；不是整次检测时限")
    parser.add_argument("--dns-samples", type=dns_sample_count, default=DNS_DEFAULT_SAMPLES,
                        help="IPLeak 随机域名采样次数，默认 5，可设 1～20；不走 HTTP 代理，保留 TUN")
    parser.add_argument("--require-no-ipv6", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="输出完整结构化报告")
    args = parser.parse_args()
    if args.require_no_ipv6:
        parser.error("--require-no-ipv6 已停用：IPv6 改按地域判定，请移除此参数")

    def begin(index: int, name: str) -> None:
        if not args.json:
            show_step_running(index, name)

    def emit(index: int, name: str, report: Any, rule: str) -> None:
        if not args.json:
            print_table_row(index, name, report.status, report.summary, rule, report.reasons)

    if not args.json:
        print_table_header()
    begin(1, "出口 IP 与归属")
    exit_info = detect_exit_ip(proxy_url=args.proxy, timeout=args.timeout)
    exit_check = evaluate_exit_country(exit_info)
    emit(1, "出口 IP 与归属", exit_check, "地域规则")

    begin(2, "STUN / ICE 采样")
    webrtc = check_webrtc_leak(exit_info, args.candidates, timeout=args.timeout)
    emit(2, "STUN / ICE 采样", webrtc, "地域规则")

    begin(3, "IPv6 路径检查")
    _, ipv6 = check_ipv6_exposure(exit_info, args.proxy, args.timeout)
    emit(3, "IPv6 路径检查", ipv6, "地域规则")

    begin(4, "DNS 解析器采样")
    dns = check_dns_reachability(exit_info, args.proxy, args.timeout,
                                sample_count=args.dns_samples)
    emit(4, "DNS 解析器采样", dns, "地域规则")

    statuses = [exit_check.status, webrtc.status, ipv6.status, dns.status]
    overall = aggregate_status(statuses)
    return_code = EXIT_CODES[overall]
    if args.json:
        payload: Dict[str, Any] = {
            "schema_version": 3, "status": overall, "region_policy": REGION_POLICY,
            "all_passed": overall == PASS, "return_code": return_code,
            "exit_ip_check": asdict(exit_check),
            "exit_ip": asdict(exit_info), "webrtc_leak": asdict(webrtc),
            "ipv6_exposure": asdict(ipv6), "dns_leak_approx": asdict(dns),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2), flush=True)
    else:
        print("─" * (COL_IDX + COL_NAME + COL_STAT + COL_RES + COL_RULE), flush=True)
        counts = f"{statuses.count(PASS)} 正常 / {statuses.count(FAIL)} 报错 / {statuses.count(WARN)} 警告"
        print(f"结论: {STATUS_LABELS[overall]} ({counts}；返回值: {return_code})", flush=True)
    return return_code


if __name__ == "__main__":
    sys.exit(main())
