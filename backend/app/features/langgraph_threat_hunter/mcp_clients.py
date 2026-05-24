"""MCP 도구 게이트웨이 — 시뮬레이션 / 직접 호출 / 진짜 MCP 프로토콜 분기.

modes:
  - simulation    : 시드 데이터 반환 (외부 호출 0회 — 데모/PoC/테스트).
  - live          : 별칭. AOL_LIVE_MCP_MODE 환경변수로 실제 모드 결정 (기본 direct).
  - direct (=live): 백엔드 프로세스가 외부 API/Python lib 를 직접 호출 (기존 동작).
  - self_mcp      : 자체 FastMCP 사이드카(aol-mcp) 에 SSE+JSON-RPC 로 접근.
  - external_mcp  : 외부 MCP 서버(예: dnstwist-mcp) 와 자체 FastMCP 혼합.

self_mcp / external_mcp 는 mcp_live_client.McpLiveClient 를 거쳐
진짜 MCP 프로토콜 (JSON-RPC over SSE) 로 통신한다.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests

from .simulations import get_scenario
from .state import McpCallRecord, ThreatHuntState

logger = logging.getLogger(__name__)

# 캐시 + 레이트리밋 (간단 in-process)
_VT_LAST_CALL = 0.0
_VT_MIN_INTERVAL = 15.0   # 무료티어 분당 4회 = 15초 간격
_CACHE: dict[str, tuple[float, Any]] = {}
_CACHE_TTL = 600  # 10분


def _cache_get(key: str) -> Any | None:
    if key in _CACHE:
        ts, val = _CACHE[key]
        if time.time() - ts < _CACHE_TTL:
            return val
    return None


def _cache_set(key: str, val: Any) -> None:
    _CACHE[key] = (time.time(), val)


_LIVE_MODE_ALIASES = {"live": None}  # 'live' 는 환경변수로 풀림 (아래 _resolve_live_mode)


def _resolve_live_mode(raw: str) -> str:
    """'live' 같은 alias 를 실제 분기 키로 풀어낸다.

    AOL_LIVE_MCP_MODE 환경변수가 ('direct' | 'self_mcp' | 'external_mcp') 중 하나면 그 값.
    미설정이면 'direct' (기존 동작 = 백엔드가 직접 외부 API 호출).
    """
    if raw == "live":
        env = (os.getenv("AOL_LIVE_MCP_MODE", "direct") or "direct").strip().lower()
        if env in ("direct", "self_mcp", "external_mcp"):
            return env
        return "direct"
    return raw


@dataclass
class McpRegistry:
    """5 MCP 도구 호출 추상화. mode 별 분기 + 호출 기록.

    mode 값 (string):
      simulation    : 시드 데이터
      direct        : 백엔드가 외부 API 직접 호출 (기존 'live' 동작)
      self_mcp      : aol-mcp 사이드카 (FastMCP) sse 호출
      external_mcp  : 외부 MCP 서버 (+ fallback self_mcp)
      live          : AOL_LIVE_MCP_MODE 환경변수로 실제 모드 풀이
    """

    mode: str = "simulation"
    _scenario_id: str | None = None
    _live_client: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.mode = _resolve_live_mode(self.mode)
        if self.mode in ("self_mcp", "external_mcp"):
            try:
                from .mcp_live_client import build_client

                self._live_client = build_client(self.mode)
                if self._live_client is None:
                    logger.warning("MCP live client 생성 실패, direct 모드로 fallback (mode=%s)", self.mode)
                    self.mode = "direct"
            except Exception as e:  # noqa: BLE001
                logger.warning("MCP live client 임포트 실패 (%s), direct 로 fallback", e)
                self.mode = "direct"

    def attach_scenario(self, scenario_id: str | None) -> None:
        self._scenario_id = scenario_id

    # ---- 공통 헬퍼 ----
    def _record(self, state: ThreatHuntState, tool: str, key: str, started_ns: int, *, cached: bool = False) -> None:
        elapsed_ms = int((time.perf_counter_ns() - started_ns) / 1_000_000)
        state.mcp_calls.append(
            McpCallRecord(
                tool=tool,
                input_key=key,
                elapsed_ms=elapsed_ms,
                cached=cached,
                simulation=(self.mode == "simulation"),
            )
        )

    def _sim(self) -> dict[str, Any] | None:
        return get_scenario(self._scenario_id) if self._scenario_id else None

    def _via_mcp(self, tool_alias: str, arguments: dict[str, Any]) -> Any:
        """진짜 MCP 프로토콜로 도구 호출. 실패 시 None 반환 (호출부가 폴백 결정)."""
        if self._live_client is None:
            return None
        try:
            return self._live_client.call(tool_alias, arguments)
        except Exception as e:  # noqa: BLE001
            logger.warning("MCP call '%s' 실패: %s", tool_alias, e)
            return None

    # ============================================================
    # 1. VirusTotal — 평판 조회 (실 HTTP)
    # ============================================================
    def virustotal(self, state: ThreatHuntState, ioc: str, ioc_type: str) -> dict[str, Any]:
        t0 = time.perf_counter_ns()
        cache_key = f"vt:{ioc_type}:{ioc}"

        if self.mode == "simulation":
            seed = self._sim() or {}
            triage = seed.get("triage", {})
            payload = {
                "ioc": ioc, "type": ioc_type,
                "detection_ratio": triage.get("detection_ratio", "0/93"),
                "threat_level": triage.get("threat_level", "LOW"),
                "_source": "simulation_seed",
            }
            self._record(state, "virustotal", f"{ioc_type}={ioc}", t0)
            return payload

        if self.mode in ("self_mcp", "external_mcp"):
            payload = self._via_mcp("virustotal", {"ioc": ioc, "ioc_type": ioc_type})
            if payload is not None:
                self._record(state, "virustotal", f"{ioc_type}={ioc}", t0)
                return payload  # type: ignore[return-value]
            # fallback: direct

        # ---- direct 라이브 ----
        cached = _cache_get(cache_key)
        if cached is not None:
            self._record(state, "virustotal", f"{ioc_type}={ioc}", t0, cached=True)
            return cached

        api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        if not api_key:
            payload = {"ioc": ioc, "type": ioc_type, "_error": "VIRUSTOTAL_API_KEY 미설정", "_source": "live_no_key"}
            self._record(state, "virustotal", f"{ioc_type}={ioc}", t0)
            return payload

        # 레이트리밋 자가 준수
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
                    "ioc": ioc, "type": ioc_type,
                    "detection_ratio": f"{malicious}/{total}" if total else "0/0",
                    "stats": stats,
                    "reputation": data.get("reputation"),
                    "creation_date": data.get("creation_date") or data.get("first_submission_date"),
                    "categories": data.get("categories", {}),
                    "_source": "live_virustotal",
                }
            elif r.status_code == 429:
                payload = {"ioc": ioc, "type": ioc_type, "_error": "rate_limited", "_source": "live_virustotal"}
            elif r.status_code == 404:
                payload = {"ioc": ioc, "type": ioc_type, "_error": "not_found_in_vt", "_source": "live_virustotal"}
            else:
                payload = {"ioc": ioc, "type": ioc_type, "_error": f"http_{r.status_code}", "_source": "live_virustotal"}
        except requests.RequestException as e:
            payload = {"ioc": ioc, "type": ioc_type, "_error": str(e), "_source": "live_virustotal"}

        _cache_set(cache_key, payload)
        self._record(state, "virustotal", f"{ioc_type}={ioc}", t0)
        return payload

    # ============================================================
    # 2. DNSTwist — 타이포스쿼트 탐지 (실 Python 라이브러리)
    # ============================================================
    def dnstwist(self, state: ThreatHuntState, domain: str) -> list[dict[str, Any]]:
        t0 = time.perf_counter_ns()
        cache_key = f"dnstwist:{domain}"

        if self.mode == "simulation":
            seed = self._sim() or {}
            result = list(seed.get("infrastructure", {}).get("typosquat_domains", []))
            self._record(state, "dnstwist", f"domain={domain}", t0)
            return result

        if self.mode in ("self_mcp", "external_mcp"):
            result = self._via_mcp("dnstwist", {"domain": domain})
            if result is not None:
                self._record(state, "dnstwist", f"domain={domain}", t0)
                return result if isinstance(result, list) else [result]
            # fallback: direct

        # ---- direct 라이브 ----
        cached = _cache_get(cache_key)
        if cached is not None:
            self._record(state, "dnstwist", f"domain={domain}", t0, cached=True)
            return cached

        try:
            import dnstwist  # type: ignore

            fuzzer = dnstwist.Fuzzer(domain)
            fuzzer.generate()
            permutations = list(fuzzer.permutations())
            # DNS 검증은 시간 오래 걸리니 — 상위 30개 변형만, DNS 미검증 (변형 목록 자체가 유용)
            result = []
            for p in permutations[:30]:
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
        self._record(state, "dnstwist", f"domain={domain}", t0)
        return result

    # ============================================================
    # 3. Shodan — 노출 자산 (paid; InternetDB 무료 fallback)
    # ============================================================
    def shodan(self, state: ThreatHuntState, target: str) -> list[dict[str, Any]]:
        t0 = time.perf_counter_ns()
        cache_key = f"shodan:{target}"

        if self.mode == "simulation":
            seed = self._sim() or {}
            result = list(seed.get("infrastructure", {}).get("exposed_assets", []))
            self._record(state, "shodan", f"target={target}", t0)
            return result

        if self.mode in ("self_mcp", "external_mcp"):
            result = self._via_mcp("shodan", {"target": target})
            if result is not None:
                self._record(state, "shodan", f"target={target}", t0)
                return result if isinstance(result, list) else [result]

        cached = _cache_get(cache_key)
        if cached is not None:
            self._record(state, "shodan", f"target={target}", t0, cached=True)
            return cached

        api_key = os.getenv("SHODAN_API_KEY", "").strip()
        result: list[dict[str, Any]] = []

        # 우선 InternetDB 무료 API (IP만, 도메인이면 DNS 변환 후)
        try:
            # IP 또는 도메인 처리 — 일단 InternetDB 시도 (IP 만 지원)
            import re as _re
            is_ip = bool(_re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
            if is_ip:
                r = requests.get(f"https://internetdb.shodan.io/{target}", timeout=10)
                if r.status_code == 200:
                    d = r.json()
                    for port in d.get("ports", [])[:10]:
                        result.append({
                            "target": target, "port": port,
                            "service": "unknown", "cve": None, "severity": "INFO",
                            "_source": "internetdb",
                        })
                    for cve in d.get("vulns", [])[:5]:
                        result.append({"target": target, "cve": cve, "severity": "MEDIUM", "_source": "internetdb"})
        except requests.RequestException:
            pass

        # 유료 키 있으면 Shodan API 추가
        if api_key:
            try:
                r = requests.get(
                    f"https://api.shodan.io/shodan/host/{target}",
                    params={"key": api_key}, timeout=10,
                )
                if r.status_code == 200:
                    d = r.json()
                    for svc in d.get("data", [])[:5]:
                        result.append({
                            "target": target, "port": svc.get("port"),
                            "service": svc.get("product") or "unknown",
                            "transport": svc.get("transport"),
                            "_source": "shodan_paid",
                        })
            except requests.RequestException:
                pass

        if not result:
            result = [{"_info": "노출 자산 미발견 또는 도메인 IP 변환 필요", "_source": "shodan_live"}]

        _cache_set(cache_key, result)
        self._record(state, "shodan", f"target={target}", t0)
        return result

    # ============================================================
    # 4. OSINT — crt.sh (Certificate Transparency) + DNS
    # ============================================================
    def osint(self, state: ThreatHuntState, target: str) -> list[dict[str, Any]]:
        t0 = time.perf_counter_ns()
        cache_key = f"osint:{target}"

        if self.mode == "simulation":
            seed = self._sim() or {}
            result = list(seed.get("infrastructure", {}).get("related_infra", []))
            self._record(state, "osint", f"target={target}", t0)
            return result

        if self.mode in ("self_mcp", "external_mcp"):
            result = self._via_mcp("osint", {"target": target})
            if result is not None:
                self._record(state, "osint", f"target={target}", t0)
                return result if isinstance(result, list) else [result]

        cached = _cache_get(cache_key)
        if cached is not None:
            self._record(state, "osint", f"target={target}", t0, cached=True)
            return cached

        result: list[dict[str, Any]] = []

        # crt.sh — Certificate Transparency 로그
        try:
            r = requests.get(
                "https://crt.sh/",
                params={"q": target, "output": "json"},
                timeout=15,
            )
            if r.status_code == 200 and r.text.strip():
                certs = r.json()[:10]  # 상위 10건
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
        self._record(state, "osint", f"target={target}", t0)
        return result

    # ============================================================
    # 5. CVE — NVD + EPSS + CISA KEV (모두 공개 무료 API)
    # ============================================================
    def cve(self, state: ThreatHuntState, cve_id: str) -> dict[str, Any]:
        t0 = time.perf_counter_ns()
        cache_key = f"cve:{cve_id}"

        if self.mode == "simulation":
            seed = self._sim() or {}
            triage = seed.get("triage", {})
            campaign = seed.get("campaign", {})
            payload = {
                "cve_id": cve_id,
                "kev_listed": "CISA KEV" in " ".join(triage.get("priority_pivots", [])),
                "epss": 0.97 if cve_id == "CVE-2024-21762" else 0.3,
                "mitre_tactics": triage.get("mitre_tactics", []),
                "threat_groups": [campaign.get("threat_group_hypothesis")] if campaign.get("threat_group_hypothesis") else [],
                "_source": "simulation_seed",
            }
            self._record(state, "cve", f"cve_id={cve_id}", t0)
            return payload

        if self.mode in ("self_mcp", "external_mcp"):
            payload = self._via_mcp("cve", {"cve_id": cve_id})
            if payload is not None:
                self._record(state, "cve", f"cve_id={cve_id}", t0)
                return payload  # type: ignore[return-value]

        cached = _cache_get(cache_key)
        if cached is not None:
            self._record(state, "cve", f"cve_id={cve_id}", t0, cached=True)
            return cached

        payload: dict[str, Any] = {"cve_id": cve_id, "_source": "live"}

        # NVD CVE 정보
        try:
            r = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                timeout=15,
            )
            if r.status_code == 200:
                items = r.json().get("vulnerabilities", [])
                if items:
                    cve = items[0].get("cve", {})
                    metrics = cve.get("metrics", {})
                    cvss = None
                    for v in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if v in metrics and metrics[v]:
                            cvss = metrics[v][0].get("cvssData", {})
                            break
                    payload.update({
                        "description": (cve.get("descriptions", [{}])[0].get("value", ""))[:300],
                        "cvss_score": (cvss or {}).get("baseScore"),
                        "cvss_severity": (cvss or {}).get("baseSeverity"),
                        "published": cve.get("published"),
                    })
        except requests.RequestException:
            pass

        # EPSS
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

        # CISA KEV (단일 JSON, 캐시 1일)
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
        self._record(state, "cve", f"cve_id={cve_id}", t0)
        return payload
