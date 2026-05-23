"""FastAPI 라우터 — LangGraph 기반 신규 멀티에이전트 위협 헌팅.

엔드포인트:
  GET  /api/lg/health                       — 모듈 가용성 확인
  GET  /api/lg/scenarios                    — 시뮬레이션 시나리오 목록
  POST /api/lg/simulate/{scenario_id}       — 시나리오 1건 실행 (시뮬레이션 모드)
  POST /api/lg/investigate                  — 임의 IoC 라이브 분석 (live 모드, LLM/MCP 미연결 시 placeholder)
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .graph import build_graph, get_simulation_graph
from .simulations import get_scenario, list_scenarios
from .state import IocType, ThreatHuntState

router = APIRouter(prefix="/api/lg", tags=["LangGraph Threat Hunting"])


class InvestigateRequest(BaseModel):
    ioc: str = Field(..., description="조사할 IoC (IP/도메인/URL/해시/CVE)")
    ioc_type: IocType = Field("unknown", description="IoC 타입 — 모르면 unknown")


class SimulationRunResult(BaseModel):
    scenario_id: str
    title: str
    elapsed_ms: int
    confidence_score: float
    automation_level: str | None
    human_approval_required: bool
    audit_ledger: list[dict[str, Any]]
    mcp_calls: list[dict[str, Any]]
    deliverables: dict[str, Any]
    findings: dict[str, Any]


@router.get("/health")
def health() -> dict[str, Any]:
    """모듈 헬스체크 — 그래프 컴파일 정상 여부 포함."""
    try:
        get_simulation_graph()
        return {"status": "ok", "graph": "compiled", "simulation_scenarios": len(list_scenarios())}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"graph build failed: {e}")


@router.get("/scenarios")
def scenarios() -> dict[str, Any]:
    """5대 금융권 시뮬레이션 시나리오 요약 목록."""
    return {"scenarios": list_scenarios()}


@router.post("/simulate/{scenario_id}", response_model=SimulationRunResult)
def simulate(scenario_id: str) -> SimulationRunResult:
    """시뮬레이션 시나리오를 LangGraph 로 실행하고 산출물 반환."""
    seed = get_scenario(scenario_id)
    if not seed:
        raise HTTPException(status_code=404, detail=f"scenario_id={scenario_id} not found")

    initial = ThreatHuntState(
        ioc=seed["ioc"],
        ioc_type=seed["ioc_type"],
        mode="simulation",
        scenario_id=scenario_id,
    )

    graph = get_simulation_graph()
    result_state_raw = graph.invoke(initial)
    # graph.invoke 는 dict 형태로 반환 가능 — Pydantic v2 호환 처리
    result_state: ThreatHuntState = (
        result_state_raw
        if isinstance(result_state_raw, ThreatHuntState)
        else ThreatHuntState.model_validate(result_state_raw)
    )

    findings = {
        "triage": result_state.triage.model_dump() if result_state.triage else None,
        "malware": result_state.malware.model_dump() if result_state.malware else None,
        "infrastructure": result_state.infrastructure.model_dump() if result_state.infrastructure else None,
        "campaign": result_state.campaign.model_dump() if result_state.campaign else None,
    }

    deliverables = {
        "firewall_rules": result_state.campaign.firewall_rules if result_state.campaign else [],
        "hunt_hypotheses": result_state.campaign.hunt_hypotheses if result_state.campaign else [],
        "executive_summary": result_state.campaign.executive_summary if result_state.campaign else "",
        "before_minutes": seed["before_minutes"],
        "estimated_after_seconds": seed["estimated_after_seconds"],
        "actual_elapsed_ms": result_state.elapsed_ms,
    }

    return SimulationRunResult(
        scenario_id=scenario_id,
        title=seed["title"],
        elapsed_ms=result_state.elapsed_ms,
        confidence_score=result_state.confidence_score,
        automation_level=result_state.automation_level,
        human_approval_required=result_state.human_approval_required,
        audit_ledger=[entry.model_dump(mode="json") for entry in result_state.audit_ledger],
        mcp_calls=[call.model_dump(mode="json") for call in result_state.mcp_calls],
        deliverables=deliverables,
        findings=findings,
    )


@router.post("/investigate")
def investigate(req: InvestigateRequest) -> dict[str, Any]:
    """임의 IoC 라이브 모드 분석 — LLM/MCP 미연결 시 placeholder 반환."""
    initial = ThreatHuntState(ioc=req.ioc, ioc_type=req.ioc_type, mode="live")
    graph = build_graph(mode="live")
    result_state_raw = graph.invoke(initial)
    result_state: ThreatHuntState = (
        result_state_raw
        if isinstance(result_state_raw, ThreatHuntState)
        else ThreatHuntState.model_validate(result_state_raw)
    )

    return {
        "mode": "live",
        "ioc": result_state.ioc,
        "ioc_type": result_state.ioc_type,
        "elapsed_ms": result_state.elapsed_ms,
        "confidence_score": result_state.confidence_score,
        "automation_level": result_state.automation_level,
        "human_approval_required": result_state.human_approval_required,
        "audit_ledger": [e.model_dump(mode="json") for e in result_state.audit_ledger],
        "mcp_calls": [c.model_dump(mode="json") for c in result_state.mcp_calls],
        "note": "live mode 는 향후 Phase 3 라이브 MCP/LLM 연결 시점에 활성화됩니다.",
    }
