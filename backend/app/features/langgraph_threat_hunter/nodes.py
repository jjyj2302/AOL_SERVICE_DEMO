"""LangGraph 노드 함수.

LangGraph 패턴: 각 노드는 ThreatHuntState 를 입력받아 갱신할 필드만 담은
dict (또는 부분 상태) 를 반환한다.
- audit_ledger / mcp_calls 는 state.py 에서 Annotated[..., add] 리듀서로 누적된다.
- 그 외 단일 객체 필드(triage 등) 는 그냥 반환한 값이 교체된다.

시뮬레이션 모드: 시드 데이터를 그대로 주입.
라이브 모드: MCP 도구 + LLM 종합 추론으로 결과 생성 (현재는 placeholder).
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from .confidence import apply_gating
from .mcp_clients import McpRegistry
from .simulations import get_scenario
from .state import (
    CampaignFindings,
    InfraFindings,
    LedgerEntry,
    MalwareFindings,
    McpCallRecord,
    ThreatHuntState,
    TriageFindings,
)


def _run_node(
    state: ThreatHuntState,
    node_name: str,
    mcp: McpRegistry,
    body,
) -> dict[str, Any]:
    """공통 실행 래퍼 — 노드 본체를 호출하면서 ledger / mcp_calls delta 를 수집."""
    mcp.attach_scenario(state.scenario_id)
    entry = LedgerEntry(node=node_name)
    t0_ns = time.perf_counter_ns()

    # 노드별 MCP delta 를 격리 수집하기 위해 임시 누적기 사용
    tmp_state = state.model_copy(deep=True)
    # 누적기 초기화 (이 노드 동안 호출된 것만 모음)
    tmp_state.mcp_calls = []

    findings: dict[str, Any] = body(tmp_state, mcp)

    elapsed_ms = int((time.perf_counter_ns() - t0_ns) / 1_000_000)
    entry.finished_at = datetime.utcnow()
    entry.elapsed_ms = elapsed_ms
    entry.summary = findings.pop("_summary", "")
    entry.tools_called = findings.pop("_tools_called", [])

    # delta 만 반환 — Annotated[..., add] 리듀서가 기존 리스트에 concat
    return {
        **findings,
        "audit_ledger": [entry],
        "mcp_calls": list(tmp_state.mcp_calls),
    }


# ---- 노드: Triage ----
def triage_node(state: ThreatHuntState, mcp: McpRegistry) -> dict[str, Any]:
    def body(s: ThreatHuntState, m: McpRegistry) -> dict[str, Any]:
        if s.mode == "simulation":
            seed = get_scenario(s.scenario_id) or {}
            triage = TriageFindings(**seed.get("triage", {})) if seed.get("triage") else TriageFindings()
            m.virustotal(s, s.ioc, s.ioc_type if s.ioc_type != "unknown" else "domain")
        else:
            vt = m.virustotal(s, s.ioc, s.ioc_type if s.ioc_type != "unknown" else "domain")
            triage = TriageFindings(
                threat_level=vt.get("threat_level", "LOW"),
                detection_ratio=vt.get("detection_ratio", ""),
                notes="live mode triage (LLM 추론 미연결)",
            )
        return {
            "triage": triage,
            "_summary": f"threat_level={triage.threat_level}",
            "_tools_called": ["virustotal"],
        }

    return _run_node(state, "triage", mcp, body)


# ---- 노드: Malware ----
def malware_node(state: ThreatHuntState, mcp: McpRegistry) -> dict[str, Any]:
    def body(s: ThreatHuntState, m: McpRegistry) -> dict[str, Any]:
        if s.mode == "simulation":
            seed = get_scenario(s.scenario_id) or {}
            malware = MalwareFindings(**seed.get("malware", {})) if seed.get("malware") else MalwareFindings()
        else:
            malware = MalwareFindings(notes="live mode malware (LLM 추론 미연결)")
        return {
            "malware": malware,
            "_summary": f"family={malware.malware_family or 'N/A'}, c2={len(malware.c2_targets)}",
            "_tools_called": ["virustotal"],
        }

    return _run_node(state, "malware", mcp, body)


# ---- 노드: Infrastructure Hunter ----
def infrastructure_node(state: ThreatHuntState, mcp: McpRegistry) -> dict[str, Any]:
    def body(s: ThreatHuntState, m: McpRegistry) -> dict[str, Any]:
        if s.mode == "simulation":
            seed = get_scenario(s.scenario_id) or {}
            infra = InfraFindings(**seed.get("infrastructure", {})) if seed.get("infrastructure") else InfraFindings()
            m.dnstwist(s, s.ioc)
            m.shodan(s, s.ioc)
            m.osint(s, s.ioc)
        else:
            typosquats = m.dnstwist(s, s.ioc)
            exposed = m.shodan(s, s.ioc)
            related = m.osint(s, s.ioc)
            infra = InfraFindings(
                typosquat_domains=typosquats,
                exposed_assets=exposed,
                related_infra=related,
                notes="live mode infra (LLM 클러스터링 미연결)",
            )
        summary = (
            f"typosquats={len(infra.typosquat_domains)}, "
            f"exposed={len(infra.exposed_assets)}, "
            f"cluster={infra.campaign_cluster_id}"
        )
        return {
            "infrastructure": infra,
            "_summary": summary,
            "_tools_called": ["dnstwist", "shodan", "osint"],
        }

    return _run_node(state, "infrastructure", mcp, body)


# ---- 노드: Campaign Analyst ----
def campaign_node(state: ThreatHuntState, mcp: McpRegistry) -> dict[str, Any]:
    def body(s: ThreatHuntState, m: McpRegistry) -> dict[str, Any]:
        if s.mode == "simulation":
            seed = get_scenario(s.scenario_id) or {}
            campaign = CampaignFindings(**seed.get("campaign", {})) if seed.get("campaign") else CampaignFindings()
            if s.ioc_type == "cve":
                m.cve(s, s.ioc)
        else:
            campaign = CampaignFindings(executive_summary="live mode campaign (LLM 종합 미연결)")
            if s.ioc_type == "cve":
                m.cve(s, s.ioc)
        summary = (
            f"group={campaign.threat_group_hypothesis or 'N/A'}, "
            f"hypotheses={len(campaign.hunt_hypotheses)}, "
            f"fw_rules={len(campaign.firewall_rules)}"
        )
        return {
            "campaign": campaign,
            "_summary": summary,
            "_tools_called": ["cve"] if s.ioc_type == "cve" else [],
        }

    return _run_node(state, "campaign", mcp, body)


# ---- 노드: Confidence Gate ----
def gate_node(state: ThreatHuntState) -> dict[str, Any]:
    entry = LedgerEntry(node="confidence_gate")
    t0_ns = time.perf_counter_ns()

    # Pydantic v2: state 는 이미 채워진 값 (LangGraph 가 합쳐서 넘김)
    apply_gating(state)
    finished_at = datetime.utcnow()
    elapsed_ms = int((finished_at - state.started_at).total_seconds() * 1000)

    entry.finished_at = datetime.utcnow()
    entry.elapsed_ms = int((time.perf_counter_ns() - t0_ns) / 1_000_000)
    entry.summary = (
        f"score={state.confidence_score:.3f}, "
        f"level={state.automation_level}, "
        f"human_approval={state.human_approval_required}"
    )
    entry.tools_called = []

    return {
        "confidence_score": state.confidence_score,
        "automation_level": state.automation_level,
        "human_approval_required": state.human_approval_required,
        "finished_at": finished_at,
        "elapsed_ms": elapsed_ms,
        "audit_ledger": [entry],
    }
