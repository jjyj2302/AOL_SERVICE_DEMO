"""MCP 도구 클라이언트 추상화.

- simulation 모드: 시드 데이터 반환 (외부 호출 0회)
- live 모드: langchain-mcp-adapters 통해 실 MCP 서버 호출

운영 환경 도입 시 MCP 서버 URL 만 환경변수로 주입하면 라이브 동작.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .simulations import get_scenario
from .state import McpCallRecord, ThreatHuntState


@dataclass
class McpRegistry:
    """MCP 도구 5종 호출을 통일하는 게이트웨이.

    simulation 모드면 시드 데이터에서, live 모드면 실 MCP 서버에서 응답한다.
    실제 MCP wire-up 은 향후 Phase 3 라이브 모드 활성화 시점에 추가한다.
    """

    mode: str = "simulation"

    # 시뮬레이션 모드에서는 시나리오 시드를 그대로 반환하기 위해 scenario_id 를 보관
    _scenario_id: str | None = None

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

    # ---- VirusTotal MCP ----
    def virustotal(self, state: ThreatHuntState, ioc: str, ioc_type: str) -> dict[str, Any]:
        t0 = time.perf_counter_ns()
        if self.mode == "simulation":
            seed = self._sim() or {}
            triage = seed.get("triage", {})
            payload = {
                "ioc": ioc,
                "type": ioc_type,
                "detection_ratio": triage.get("detection_ratio", "0/93"),
                "threat_level": triage.get("threat_level", "LOW"),
            }
        else:
            # TODO(live): MultiServerMCPClient 통해 mcp-virustotal 호출
            payload = {"ioc": ioc, "type": ioc_type, "error": "live mode not configured"}
        self._record(state, "virustotal", f"{ioc_type}={ioc}", t0)
        return payload

    # ---- DNSTwist MCP ----
    def dnstwist(self, state: ThreatHuntState, domain: str) -> list[dict[str, Any]]:
        t0 = time.perf_counter_ns()
        if self.mode == "simulation":
            seed = self._sim() or {}
            result = list(seed.get("infrastructure", {}).get("typosquat_domains", []))
        else:
            # TODO(live): mcp-dnstwist 호출
            result = []
        self._record(state, "dnstwist", f"domain={domain}", t0)
        return result

    # ---- Shodan MCP ----
    def shodan(self, state: ThreatHuntState, target: str) -> list[dict[str, Any]]:
        t0 = time.perf_counter_ns()
        if self.mode == "simulation":
            seed = self._sim() or {}
            result = list(seed.get("infrastructure", {}).get("exposed_assets", []))
        else:
            # TODO(live): mcp-shodan 호출
            result = []
        self._record(state, "shodan", f"target={target}", t0)
        return result

    # ---- OSINT MCP (Censys / BGP / cert 등) ----
    def osint(self, state: ThreatHuntState, target: str) -> list[dict[str, Any]]:
        t0 = time.perf_counter_ns()
        if self.mode == "simulation":
            seed = self._sim() or {}
            result = list(seed.get("infrastructure", {}).get("related_infra", []))
        else:
            # TODO(live): osint-mcp-server 호출
            result = []
        self._record(state, "osint", f"target={target}", t0)
        return result

    # ---- CVE MCP (EPSS/KEV/MITRE) ----
    def cve(self, state: ThreatHuntState, cve_id: str) -> dict[str, Any]:
        t0 = time.perf_counter_ns()
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
            }
        else:
            # TODO(live): cve-mcp-server 호출
            payload = {"cve_id": cve_id, "error": "live mode not configured"}
        self._record(state, "cve", f"cve_id={cve_id}", t0)
        return payload
