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
from datetime import datetime, timezone
from typing import Any

from .agent_prompts import call_agent, has_anthropic_key, unwrap_findings
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


# IoC 타입별 라우팅 규칙 — Orchestrator 가 사용
ROUTING_RULES: dict[str, tuple[list[str], str]] = {
    "cve": (
        ["triage", "campaign"],
        "CVE 분석은 평판/캠페인 종합만 필요 — Malware/Infrastructure 스킵",
    ),
    "hash": (
        ["triage", "malware", "infrastructure", "campaign"],
        "악성 해시 — 행위 분석 + C2 인프라 + 캠페인 재구성 전 단계 풀체인 실행",
    ),
    "ip": (
        ["triage", "infrastructure", "campaign"],
        "IP 평판/인프라/캠페인 — Malware 분석은 별도 EDR 트리아지 영역",
    ),
    "domain": (
        ["triage", "infrastructure", "campaign"],
        "도메인 평판/인프라/캠페인 — Malware 분석 불필요",
    ),
    "url": (
        ["triage", "infrastructure", "campaign"],
        "URL 평판/인프라/캠페인 — 동적 행위는 별도 샌드박스 영역",
    ),
}
ROUTING_DEFAULT = (
    ["triage", "malware", "infrastructure", "campaign"],
    "타입 불명 — 안전한 전체 분석 (모든 Specialist 호출)",
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
    entry.finished_at = datetime.now(timezone.utc)
    entry.elapsed_ms = elapsed_ms
    entry.summary = findings.pop("_summary", "")
    entry.tools_called = findings.pop("_tools_called", [])

    # delta 만 반환 — Annotated[..., add] 리듀서가 기존 리스트에 concat
    return {
        **findings,
        "audit_ledger": [entry],
        "mcp_calls": list(tmp_state.mcp_calls),
    }


# ---- 노드: Orchestrator (라우팅 결정) ----
def orchestrator_node(state: ThreatHuntState, mcp: McpRegistry) -> dict[str, Any]:
    """IoC 타입을 보고 어떤 Specialist 를 어떤 순서로 호출할지 plan 을 세운다."""
    def body(s: ThreatHuntState, m: McpRegistry) -> dict[str, Any]:
        # 라이브 모드 + Anthropic 키 있으면 LLM 으로 라우팅 결정. 그 외는 결정론적 규칙.
        if s.mode == "live" and has_anthropic_key():
            parsed, _meta = call_agent(
                "orchestrator",
                f"IoC: {s.ioc}\nType: {s.ioc_type}\n위 IoC 에 대한 효율적 route_plan 을 산출하세요.",
                max_tokens=400,
            )
            findings, _ = unwrap_findings(parsed)
            plan = findings.get("route_plan") if isinstance(findings.get("route_plan"), list) else None
            rationale = findings.get("rationale") if findings.get("rationale") else None
            if not plan or not rationale:
                plan, rationale = ROUTING_RULES.get(s.ioc_type, ROUTING_DEFAULT)
        else:
            plan, rationale = ROUTING_RULES.get(s.ioc_type, ROUTING_DEFAULT)
        return {
            "route_plan": list(plan),
            "routing_rationale": rationale,
            "_summary": f"route={'-'.join(plan)} | {rationale}",
            "_tools_called": [],
        }
    return _run_node(state, "orchestrator", mcp, body)


# ---- 라이브 모드 specialist 공통 헬퍼 ----
def _live_user_prompt(state: ThreatHuntState, prior: dict[str, Any]) -> str:
    """specialist 에게 보낼 사용자 메시지 — IoC + 이전 노드 산출물 종합."""
    parts = [f"IoC: {state.ioc}\nType: {state.ioc_type}\n"]
    if prior.get("triage"):
        parts.append(f"이전 Triage 결과: {prior['triage']}")
    if prior.get("malware"):
        parts.append(f"이전 Malware 결과: {prior['malware']}")
    if prior.get("infrastructure"):
        parts.append(f"이전 Infrastructure 결과: {prior['infrastructure']}")
    parts.append("\n위 정보를 종합하여 본 에이전트의 시스템 프롬프트에 정의된 JSON 형식으로 답변하세요.")
    return "\n".join(parts)


def _prior_findings(state: ThreatHuntState) -> dict[str, Any]:
    """현재 state 에 채워진 이전 findings dict 로 dump."""
    return {
        "triage": state.triage.model_dump() if state.triage else None,
        "malware": state.malware.model_dump() if state.malware else None,
        "infrastructure": state.infrastructure.model_dump() if state.infrastructure else None,
    }


# ---- 노드: Triage ----
def triage_node(state: ThreatHuntState, mcp: McpRegistry) -> dict[str, Any]:
    def body(s: ThreatHuntState, m: McpRegistry) -> dict[str, Any]:
        if s.mode == "simulation":
            seed = get_scenario(s.scenario_id) or {}
            triage = TriageFindings(**seed.get("triage", {})) if seed.get("triage") else TriageFindings()
            m.virustotal(s, s.ioc, s.ioc_type if s.ioc_type != "unknown" else "domain")
        elif has_anthropic_key():
            m.virustotal(s, s.ioc, s.ioc_type if s.ioc_type != "unknown" else "domain")
            findings, _meta = call_agent("triage", _live_user_prompt(s, {}), max_tokens=900)
            triage = TriageFindings(**_safe_findings(findings, TriageFindings))
        else:
            m.virustotal(s, s.ioc, s.ioc_type if s.ioc_type != "unknown" else "domain")
            triage = TriageFindings(notes="(API 키 없음 — 추정 분석 불가)", chat_message="ANTHROPIC_API_KEY 미설정 — 라이브 분석 제한됨.")
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
        elif has_anthropic_key():
            findings, _meta = call_agent(
                "malware",
                _live_user_prompt(s, _prior_findings(s)),
                max_tokens=1800,
            )
            malware = MalwareFindings(**_safe_findings(findings, MalwareFindings))
        else:
            malware = MalwareFindings(notes="(API 키 없음)", chat_message="ANTHROPIC_API_KEY 미설정.")
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
            m.dnstwist(s, s.ioc); m.shodan(s, s.ioc); m.osint(s, s.ioc)
        elif has_anthropic_key():
            m.dnstwist(s, s.ioc); m.shodan(s, s.ioc); m.osint(s, s.ioc)
            findings, _meta = call_agent(
                "infrastructure",
                _live_user_prompt(s, _prior_findings(s)),
                max_tokens=1800,
            )
            infra = InfraFindings(**_safe_findings(findings, InfraFindings))
        else:
            m.dnstwist(s, s.ioc); m.shodan(s, s.ioc); m.osint(s, s.ioc)
            infra = InfraFindings(notes="(API 키 없음)", chat_message="ANTHROPIC_API_KEY 미설정.")
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
        elif has_anthropic_key():
            if s.ioc_type == "cve":
                m.cve(s, s.ioc)
            findings, _meta = call_agent(
                "campaign",
                _live_user_prompt(s, _prior_findings(s)),
                max_tokens=2800,
            )
            campaign = CampaignFindings(**_safe_findings(findings, CampaignFindings))
        else:
            campaign = CampaignFindings(
                executive_summary="(API 키 없음 — 종합 분석 불가)",
                chat_message="ANTHROPIC_API_KEY 미설정.",
            )
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


def _safe_findings(parsed: dict[str, Any], model_cls) -> dict[str, Any]:
    """LLM 이 반환한 wrapper {findings, chat_message} 에서 Pydantic 모델에 채택 가능한 필드만 추출."""
    findings, chat_msg = unwrap_findings(parsed)
    valid_fields = set(model_cls.model_fields.keys())
    safe = {k: v for k, v in findings.items() if k in valid_fields}
    if chat_msg and "chat_message" in valid_fields:
        safe["chat_message"] = chat_msg
    return safe


# ---- 노드: Confidence Gate ----
def gate_node(state: ThreatHuntState) -> dict[str, Any]:
    entry = LedgerEntry(node="confidence_gate")
    t0_ns = time.perf_counter_ns()

    # Pydantic v2: state 는 이미 채워진 값 (LangGraph 가 합쳐서 넘김)
    apply_gating(state)
    finished_at = datetime.now(timezone.utc)
    elapsed_ms = int((finished_at - state.started_at).total_seconds() * 1000)

    entry.finished_at = datetime.now(timezone.utc)
    entry.elapsed_ms = int((time.perf_counter_ns() - t0_ns) / 1_000_000)
    entry.summary = (
        f"score={state.confidence_score:.3f}, "
        f"level={state.automation_level}, "
        f"human_approval={state.human_approval_required}"
    )
    entry.tools_called = []

    # 채팅창용 자연어 브리핑 자동 생성
    score_pct = f"{state.confidence_score * 100:.0f}%"
    approval_part = (
        "핵심 자산 키워드가 매칭되어 휴먼 승인 필수입니다."
        if state.human_approval_required
        else "휴먼 승인 없이 자동 처리 가능합니다."
    )
    level_meaning = {
        "L0": "권고만 (분석가 검토 필요)",
        "L1": "분석가 확인 후 처리",
        "L2": "자동 케이스 생성",
        "L3": "자동 SIEM 헌팅 트리거",
        "L4": "자동 FW/IPS 차단",
    }.get(state.automation_level or "L0", "권고만")
    gate_message = (
        f"신뢰도 {score_pct} → {state.automation_level} 등급 ({level_meaning}). "
        f"{approval_part}"
    )

    return {
        "confidence_score": state.confidence_score,
        "automation_level": state.automation_level,
        "human_approval_required": state.human_approval_required,
        "gate_chat_message": gate_message,
        "finished_at": finished_at,
        "elapsed_ms": elapsed_ms,
        "audit_ledger": [entry],
    }
