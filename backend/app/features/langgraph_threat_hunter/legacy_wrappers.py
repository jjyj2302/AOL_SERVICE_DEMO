"""기존 CrewAI 기반 프론트엔드 페이지(Deep Analysis / AI Agents / Bulk Lookup) 호환용 wrapper.

옛 URL 을 유지하되 내부적으로 LangGraph 멀티에이전트를 호출:
- POST /api/crew-solo/{triage,malware,infrastructure,campaign}
- POST /api/threat-hunter/investigate

이로써 frontend 페이지들이 그대로 작동하면서 백엔드는 LangGraph 단일 path.
"""
from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .agent_prompts import call_agent, has_anthropic_key, unwrap_findings
from .graph import build_graph
from .state import ThreatHuntState

legacy_router = APIRouter(tags=["Legacy (LangGraph-backed)"])

# IoC 타입 자동 추론 (router.py 의 _parse_input 와 동일 패턴)
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)


def _detect_type(ioc: str) -> str:
    ioc = ioc.strip()
    if _CVE_RE.match(ioc): return "cve"
    if _HASH_RE.match(ioc): return "hash"
    if _IP_RE.match(ioc): return "ip"
    if _URL_RE.match(ioc): return "url"
    if _DOMAIN_RE.match(ioc): return "domain"
    return "unknown"


class IocRequest(BaseModel):
    ioc: str = Field(..., description="조사할 IoC")
    investigation_type: str | None = Field(None, description="(레거시) comprehensive / quick 등 — 무시됨")


# ============================================================================
# /api/crew-solo/{agent} — 단일 specialist 호출 (Agents.jsx 호환)
# ============================================================================
_AGENT_USER_PROMPTS = {
    "triage": "IoC: {ioc}\n타입: {ioc_type}\n\n위 IoC 에 대한 초기 위협 평가를 수행하세요.",
    "malware": "IoC: {ioc}\n타입: {ioc_type}\n\n위 IoC 와 관련된 악성코드 행위·C2·Attack chain 을 분석하세요.",
    "infrastructure": "IoC: {ioc}\n타입: {ioc_type}\n\n위 IoC 의 공격자 인프라 상관관계·캠페인 클러스터링·타이포스쿼트를 분석하세요.",
    "campaign": "IoC: {ioc}\n타입: {ioc_type}\n\n위 IoC 의 위협 그룹 attribution + 헌팅 가설 + FW 규칙 + 임원 요약을 산출하세요.",
}


@legacy_router.post("/api/crew-solo/{agent_name}")
async def crew_solo_compat(agent_name: str, req: IocRequest) -> dict[str, Any]:
    """단일 specialist 를 LangGraph 에이전트로 직접 호출 (옛 CrewAI 페이지 호환)."""
    if agent_name not in _AGENT_USER_PROMPTS:
        raise HTTPException(status_code=404, detail=f"unknown agent: {agent_name}")

    if not has_anthropic_key():
        return {
            "result": {
                "raw": "ANTHROPIC_API_KEY 미설정 — 라이브 분석 불가. 메인 UI 의 시뮬레이션 모드 사용 권장."
            },
            "agent": agent_name,
            "ioc": req.ioc,
        }

    ioc_type = _detect_type(req.ioc)
    user_prompt = _AGENT_USER_PROMPTS[agent_name].format(ioc=req.ioc, ioc_type=ioc_type)
    parsed, meta = call_agent(agent_name, user_prompt, max_tokens=2000)
    findings, chat_msg = unwrap_findings(parsed)

    return {
        "result": {
            **findings,
            "chat_message": chat_msg,
        },
        "agent": agent_name,
        "ioc": req.ioc,
        "ioc_type": ioc_type,
        "meta": {
            "model": meta.get("model"),
            "input_tokens": meta.get("input_tokens"),
            "output_tokens": meta.get("output_tokens"),
            "elapsed_ms": meta.get("elapsed_ms"),
        },
    }


# ============================================================================
# /api/threat-hunter/investigate — 풀체인 LangGraph (Deep Analysis 페이지 호환)
# ============================================================================
@legacy_router.post("/api/threat-hunter/investigate")
async def threat_hunter_investigate_compat(req: IocRequest) -> dict[str, Any]:
    """전체 LangGraph 풀체인 실행. 옛 deep_analysis/CrewAI 와 동등 기능."""
    ioc_type = _detect_type(req.ioc)
    use_live = has_anthropic_key()

    initial = ThreatHuntState(
        ioc=req.ioc,
        ioc_type=ioc_type,  # type: ignore[arg-type]
        mode="live" if use_live else "simulation",
    )
    graph = build_graph(mode="live" if use_live else "simulation")
    result_state_raw = graph.invoke(initial)
    state = (
        result_state_raw
        if isinstance(result_state_raw, ThreatHuntState)
        else ThreatHuntState.model_validate(result_state_raw)
    )

    return {
        "result": {
            "triage": state.triage.model_dump() if state.triage else None,
            "malware": state.malware.model_dump() if state.malware else None,
            "infrastructure": state.infrastructure.model_dump() if state.infrastructure else None,
            "campaign": state.campaign.model_dump() if state.campaign else None,
            "automation_level": state.automation_level,
            "confidence_score": state.confidence_score,
            "human_approval_required": state.human_approval_required,
        },
        "ioc": req.ioc,
        "ioc_type": ioc_type,
        "mode": state.mode,
        "audit_ledger": [e.model_dump(mode="json") for e in state.audit_ledger],
        "mcp_calls": [c.model_dump(mode="json") for c in state.mcp_calls],
        "elapsed_ms": state.elapsed_ms,
    }
