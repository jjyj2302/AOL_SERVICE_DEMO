"""AOL 자체 MCP 서버 — 5 위협 인텔리전스 도구를 진짜 MCP 프로토콜로 제공.

목적: 기존 mcp_clients.py 의 live 분기(직접 HTTP/Python lib 호출)를
      MCP 표준 (JSON-RPC over stdio/sse) 으로 감싸서 외부 MCP 클라이언트
      (langchain-mcp-adapters MultiServerMCPClient) 로 호출 가능하게 함.

전송 방식: SSE (Server-Sent Events) — docker compose 내부 네트워크에서
          backend 컨테이너가 sse 로 접근. 디버깅 시 stdio 도 지원.

도구 목록 (5종):
  - virustotal(ioc, ioc_type)  : VT API 평판
  - dnstwist(domain)           : 타이포스쿼트 변형
  - shodan(target)             : 노출 자산 (InternetDB 무료 fallback)
  - osint(target)              : Certificate Transparency (crt.sh)
  - cve(cve_id)                : NVD + EPSS + CISA KEV
"""
from __future__ import annotations

import logging
import os
import re
import time
from typing import Any

import requests
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("aol-mcp")

# 도커 내부 네트워크용 — 신뢰된 호스트만 (DNS rebinding 보호는 유지하되 컨테이너 이름 허용).
# 운영에서 외부 노출 시 ALLOWED_HOSTS / ALLOWED_ORIGINS 환경변수로 좁힌다.
_default_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*", "aol-mcp:*", "aol-mcp:8765"]
_default_origins = ["http://127.0.0.1:*", "http://localhost:*", "http://aol-mcp:*"]
_extra_hosts = [h.strip() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()]
_extra_origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]

mcp = FastMCP(
    name="aol-threat-intel",
    instructions=(
        "AOL 위협 인텔리전스 도구 게이트웨이. "
        "5개 도구 (virustotal, dnstwist, shodan, osint, cve) 제공. "
        "각 도구는 IoC(IP/도메인/해시/URL) 또는 CVE ID 를 받아 위협 정보 JSON 반환."
    ),
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_default_hosts + _extra_hosts,
        allowed_origins=_default_origins + _extra_origins,
    ),
)

_VT_LAST_CALL = 0.0
_VT_MIN_INTERVAL = 15.0  # 무료 티어 분당 4회 = 15초 간격
_CACHE: dict[str, tuple[float, Any]] = {}
_CACHE_TTL = 600


def _cache_get(key: str) -> Any | None:
    if key in _CACHE:
        ts, val = _CACHE[key]
        if time.time() - ts < _CACHE_TTL:
            return val
    return None


def _cache_set(key: str, val: Any) -> None:
    _CACHE[key] = (time.time(), val)


# ============================================================
# 1. VirusTotal
# ============================================================
@mcp.tool()
def virustotal(ioc: str, ioc_type: str = "domain") -> dict[str, Any]:
    """VirusTotal API 평판 조회.

    Args:
        ioc: IP/도메인/해시/URL 값
        ioc_type: 'ip' | 'domain' | 'url' | 'hash' (기본 domain)

    Returns:
        detection_ratio, stats, reputation, categories 등 dict
    """
    cache_key = f"vt:{ioc_type}:{ioc}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return {**cached, "_cached": True}

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {"ioc": ioc, "type": ioc_type, "_error": "VIRUSTOTAL_API_KEY 미설정", "_source": "no_key"}

    global _VT_LAST_CALL
    wait = _VT_MIN_INTERVAL - (time.time() - _VT_LAST_CALL)
    if wait > 0:
        time.sleep(min(wait, 16))

    type_map = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "hash": "files"}
    endpoint = type_map.get(ioc_type, "domains")
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"

    try:
        r = requests.get(url, headers={"x-apikey": api_key}, timeout=15)
        _VT_LAST_CALL = time.time()
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {}) or {}
            total = sum(stats.values()) if stats else 0
            malicious = stats.get("malicious", 0)
            payload = {
                "ioc": ioc,
                "type": ioc_type,
                "detection_ratio": f"{malicious}/{total}" if total else "0/0",
                "stats": stats,
                "reputation": data.get("reputation"),
                "creation_date": data.get("creation_date") or data.get("first_submission_date"),
                "categories": data.get("categories", {}),
                "_source": "virustotal_live",
            }
        elif r.status_code == 429:
            payload = {"ioc": ioc, "type": ioc_type, "_error": "rate_limited", "_source": "virustotal_live"}
        elif r.status_code == 404:
            payload = {"ioc": ioc, "type": ioc_type, "_error": "not_found", "_source": "virustotal_live"}
        else:
            payload = {"ioc": ioc, "type": ioc_type, "_error": f"http_{r.status_code}", "_source": "virustotal_live"}
    except requests.RequestException as e:
        payload = {"ioc": ioc, "type": ioc_type, "_error": str(e), "_source": "virustotal_live"}

    _cache_set(cache_key, payload)
    return payload


# ============================================================
# 2. DNSTwist
# ============================================================
@mcp.tool()
def dnstwist(domain: str, limit: int = 30) -> list[dict[str, Any]]:
    """도메인 타이포스쿼트 변형 생성 (DNS 검증 생략, 상위 N개).

    Args:
        domain: 원본 도메인
        limit: 반환할 최대 변형 수 (기본 30)
    """
    cache_key = f"dnstwist:{domain}:{limit}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        import dnstwist  # type: ignore

        fuzzer = dnstwist.Fuzzer(domain)
        fuzzer.generate()
        permutations = list(fuzzer.permutations())
        result: list[dict[str, Any]] = []
        for p in permutations[:limit]:
            d = p.get("domain") or p.get("domain-name")
            fuzz = p.get("fuzzer") or "unknown"
            if not d or d == domain:
                continue
            result.append({
                "domain": d,
                "technique": fuzz,
                "risk": "HIGH" if fuzz in ("homoglyph", "hyphenation", "addition") else "MEDIUM",
            })
    except Exception as e:  # noqa: BLE001
        logger.warning("dnstwist 호출 실패: %s", e)
        result = [{"_error": str(e), "_source": "dnstwist_lib"}]

    _cache_set(cache_key, result)
    return result


# ============================================================
# 3. Shodan (InternetDB 무료 fallback)
# ============================================================
@mcp.tool()
def shodan(target: str) -> list[dict[str, Any]]:
    """노출 자산 조회. SHODAN_API_KEY 있으면 paid API, 없으면 InternetDB(IP만)."""
    cache_key = f"shodan:{target}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    api_key = os.getenv("SHODAN_API_KEY", "").strip()
    result: list[dict[str, Any]] = []

    try:
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
        if is_ip:
            r = requests.get(f"https://internetdb.shodan.io/{target}", timeout=10)
            if r.status_code == 200:
                d = r.json()
                for port in d.get("ports", [])[:10]:
                    result.append({
                        "target": target,
                        "port": port,
                        "service": "unknown",
                        "cve": None,
                        "severity": "INFO",
                        "_source": "internetdb",
                    })
                for cve in d.get("vulns", [])[:5]:
                    result.append({"target": target, "cve": cve, "severity": "MEDIUM", "_source": "internetdb"})
    except requests.RequestException:
        pass

    if api_key:
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/{target}",
                params={"key": api_key},
                timeout=10,
            )
            if r.status_code == 200:
                d = r.json()
                for svc in d.get("data", [])[:5]:
                    result.append({
                        "target": target,
                        "port": svc.get("port"),
                        "service": svc.get("product") or "unknown",
                        "transport": svc.get("transport"),
                        "_source": "shodan_paid",
                    })
        except requests.RequestException:
            pass

    if not result:
        result = [{"_info": "노출 자산 미발견 또는 도메인 IP 변환 필요", "_source": "shodan_live"}]

    _cache_set(cache_key, result)
    return result


# ============================================================
# 4. OSINT — Certificate Transparency (crt.sh)
# ============================================================
@mcp.tool()
def osint(target: str) -> list[dict[str, Any]]:
    """Certificate Transparency 로그 조회 (crt.sh) — 도메인 관련 인증서 상위 10건."""
    cache_key = f"osint:{target}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    result: list[dict[str, Any]] = []
    try:
        r = requests.get(
            "https://crt.sh/",
            params={"q": target, "output": "json"},
            timeout=15,
        )
        if r.status_code == 200 and r.text.strip():
            certs = r.json()[:10]
            for c in certs:
                result.append({
                    "common_name": c.get("common_name"),
                    "issuer": c.get("issuer_name"),
                    "not_before": c.get("not_before"),
                    "not_after": c.get("not_after"),
                    "_source": "crtsh",
                })
    except (requests.RequestException, ValueError):
        pass

    if not result:
        result = [{"_info": "관련 인증서 없음 또는 조회 실패", "_source": "osint_live"}]

    _cache_set(cache_key, result)
    return result


# ============================================================
# 5. CVE — NVD + EPSS + CISA KEV
# ============================================================
@mcp.tool()
def cve(cve_id: str) -> dict[str, Any]:
    """CVE 상세: NVD CVSS + EPSS 익스플로잇 가능성 + CISA KEV 등재 여부."""
    cache_key = f"cve:{cve_id}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    payload: dict[str, Any] = {"cve_id": cve_id, "_source": "live"}

    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            timeout=15,
        )
        if r.status_code == 200:
            items = r.json().get("vulnerabilities", [])
            if items:
                c = items[0].get("cve", {})
                metrics = c.get("metrics", {})
                cvss = None
                for v in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if v in metrics and metrics[v]:
                        cvss = metrics[v][0].get("cvssData", {})
                        break
                payload.update({
                    "description": (c.get("descriptions", [{}])[0].get("value", ""))[:300],
                    "cvss_score": (cvss or {}).get("baseScore"),
                    "cvss_severity": (cvss or {}).get("baseSeverity"),
                    "published": c.get("published"),
                })
    except requests.RequestException:
        pass

    try:
        r = requests.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": cve_id},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json().get("data", [])
            if data:
                payload["epss"] = float(data[0].get("epss", 0.0))
                payload["epss_percentile"] = float(data[0].get("percentile", 0.0))
    except (requests.RequestException, ValueError):
        pass

    kev_cache_key = "kev_catalog"
    kev_data = _cache_get(kev_cache_key)
    if kev_data is None:
        try:
            r = requests.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=15,
            )
            if r.status_code == 200:
                kev_data = {v["cveID"] for v in r.json().get("vulnerabilities", [])}
                _cache_set(kev_cache_key, kev_data)
        except (requests.RequestException, ValueError, KeyError):
            kev_data = set()
    payload["kev_listed"] = (cve_id in kev_data) if kev_data else False

    _cache_set(cache_key, payload)
    return payload


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "sse").lower()
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        host = os.getenv("MCP_HOST", "0.0.0.0")
        port = int(os.getenv("MCP_PORT", "8765"))
        logger.info("AOL MCP 서버 시작 — sse://%s:%d/sse", host, port)
        mcp.settings.host = host
        mcp.settings.port = port
        mcp.run(transport="sse")
