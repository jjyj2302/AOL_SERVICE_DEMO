"""FastAPI 라우터 — LangGraph 기반 신규 멀티에이전트 위협 헌팅.

엔드포인트:
  GET  /api/lg/health                       — 모듈 가용성 확인
  GET  /api/lg/scenarios                    — 시뮬레이션 시나리오 목록
  POST /api/lg/simulate/{scenario_id}       — 시나리오 1건 실행 (시뮬레이션 모드)
  POST /api/lg/investigate                  — 임의 IoC 라이브 분석 (live 모드, LLM/MCP 미연결 시 placeholder)
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from fastapi import Response

from .conversation import has_anthropic_key, stream_claude_response
from .cost_analysis import compute_strategies
from .graph import build_graph, get_simulation_graph
from .pdf_report import generate_report_pdf
from .simulations import get_scenario, list_scenarios
from .state import IocType, ThreatHuntState

router = APIRouter(prefix="/api/lg", tags=["LangGraph Threat Hunting"])


class InvestigateRequest(BaseModel):
    ioc: str = Field(..., description="조사할 IoC (IP/도메인/URL/해시/CVE)")
    ioc_type: IocType = Field("unknown", description="IoC 타입 — 모르면 unknown")


class ChatRequest(BaseModel):
    """자유 텍스트 입력 → 자동 IoC 감지 + LangGraph 실행."""
    text: str = Field(..., description="사용자 입력 (IoC 그 자체, 또는 S1~S5 등 시나리오 ID)")
    pace: float = Field(0.4, ge=0.0, le=2.0, description="노드 간 인위적 지연 (시연용)")


class DialogueMessage(BaseModel):
    role: str = Field(..., description="user | assistant")
    content: str


class DialogueRequest(BaseModel):
    """진짜 대화 — IoC 분석 OR Claude 자유 대화 + 멀티턴 히스토리."""
    message: str
    history: list[DialogueMessage] = Field(default_factory=list)
    pace: float = Field(0.4, ge=0.0, le=2.0)


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


@router.get("/cost-analysis")
def cost_analysis() -> dict[str, Any]:
    """에이전트별 모델 매핑에 따른 IoC 1건당 비용 분석.

    5가지 전략 비교 (두 baseline):
    - all_opus            : 5 에이전트 모두 Opus (naive — 실무에선 안 함)
    - all_sonnet          : 5 에이전트 모두 Sonnet (★ realistic baseline)
    - all_haiku           : 5 에이전트 모두 Haiku (저비용 하한)
    - mixed               : 복잡도별 분배 (본 시스템 채택)
    - mixed_cached_batch  : Mixed + Prompt Caching + Batch API 50% 할인 (★ 최적)

    headline_savings 에 두 절감률 모두 노출:
    - realistic_vs_sonnet_pct (정직한 비교, ~59%)
    - naive_vs_opus_pct       (옛 91.8% 호환)

    실측 데이터: 2026-05-23 Anthropic API (Haiku 4.5/Sonnet 4.6/Opus 4.7) 실호출.
    benchmarks/results.json 참조.
    """
    return compute_strategies()


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


_HASH_RE = __import__("re").compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_CVE_RE = __import__("re").compile(r"^CVE-\d{4}-\d{4,7}$", __import__("re").IGNORECASE)
_IP_RE = __import__("re").compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_DOMAIN_RE = __import__("re").compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$", __import__("re").IGNORECASE)
_URL_RE = __import__("re").compile(r"^https?://", __import__("re").IGNORECASE)


def _parse_input(text: str) -> tuple[str, str, str | None]:
    """사용자 입력 → (ioc, ioc_type, scenario_id?).

    - "S1"~"S5" → 시나리오 모드
    - 텍스트 내에서 IoC 패턴 추출 (CVE / hash / IP / URL / domain 순서)
    - 매칭 실패 시 그대로 도메인으로 추정
    """
    raw = text.strip()
    upper = raw.upper()
    if upper in {"S1", "S2", "S3", "S4", "S5"}:
        seed = get_scenario(upper) or {}
        return seed.get("ioc", raw), seed.get("ioc_type", "unknown"), upper

    # 텍스트에서 첫 번째 매칭 IoC 토큰 추출 (공백/문장부호로 분리)
    tokens = __import__("re").split(r"[\s,;]+", raw)
    for tok in tokens:
        if not tok:
            continue
        if _CVE_RE.match(tok):
            return tok.upper(), "cve", None
        if _HASH_RE.match(tok):
            return tok.lower(), "hash", None
        if _IP_RE.match(tok):
            return tok, "ip", None
        if _URL_RE.match(tok):
            return tok, "url", None
        if _DOMAIN_RE.match(tok):
            return tok.lower(), "domain", None
    # fallback: 전체를 도메인으로 추정
    return raw, "unknown", None


@router.post("/chat/stream")
async def chat_stream(req: ChatRequest):
    """대화형 입력 → IoC 자동 감지 → LangGraph SSE 스트리밍.

    프론트엔드의 챗봇 UI 가 사용하는 메인 엔드포인트.
    - "S1"~"S5" 입력 시: 시뮬레이션 모드
    - 그 외 IoC 패턴: 시뮬레이션 모드로 매핑 (S1 의 변형) — Phase 8 라이브
      wire-up 시 실 MCP/LLM 호출로 자연스럽게 전환됨.
    """
    ioc, ioc_type, scenario_id = _parse_input(req.text)

    if scenario_id is None:
        # 라이브 모드는 아직 placeholder — 일단 시뮬레이션 그래프로 처리 (S1 시드 사용)
        # 실 라이브 wire-up 시 build_graph(mode="live") 로 교체
        scenario_id = "S1"
        seed = get_scenario(scenario_id) or {}
        title = f"라이브 분석 — {ioc}"
    else:
        seed = get_scenario(scenario_id) or {}
        title = seed.get("title", "Scenario")

    initial = ThreatHuntState(
        ioc=ioc,
        ioc_type=ioc_type,
        mode="simulation",
        scenario_id=scenario_id,
    )

    async def event_gen():
        yield _sse({
            "type": "start",
            "parsed": {"ioc": ioc, "ioc_type": ioc_type, "scenario_id": scenario_id},
            "title": title,
            "before_minutes": seed.get("before_minutes"),
            "estimated_after_seconds": seed.get("estimated_after_seconds"),
        })

        graph = get_simulation_graph()
        for chunk in graph.stream(initial):
            for node_name, delta in chunk.items():
                yield _sse({"type": "node", "node": node_name, "delta": _to_jsonable(delta)})
                if req.pace > 0:
                    await asyncio.sleep(req.pace)

        # 최종 산출물 요약 — 채팅 메시지 종료 시 한 번 전송
        yield _sse({
            "type": "done",
            "deliverables_hint": {
                "executive_summary_available": True,
                "firewall_rules_available": True,
                "hunt_hypotheses_available": True,
                "pdf_report_path": f"/api/lg/simulate/{scenario_id}/report.pdf",
            },
        })

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )


@router.get("/simulate/{scenario_id}/stream")
async def simulate_stream(
    scenario_id: str,
    pace: float = Query(0.0, ge=0.0, le=2.0, description="노드 간 인위적 지연 (초). 시연용 0.4~0.8 권장"),
):
    """SSE 스트리밍 — LangGraph 노드별 실행 진행을 실시간 전달.

    프론트엔드는 EventSource 로 구독하여 노드별로 ledger / mcp_calls /
    findings 부분 상태를 차례로 받아 화면을 점진 갱신할 수 있다.
    """
    seed = get_scenario(scenario_id)
    if not seed:
        raise HTTPException(status_code=404, detail=f"scenario_id={scenario_id} not found")

    initial = ThreatHuntState(
        ioc=seed["ioc"],
        ioc_type=seed["ioc_type"],
        mode="simulation",
        scenario_id=scenario_id,
    )

    async def event_gen():
        # 시작 이벤트 — 시나리오 메타 + 예상 노드 목록
        yield _sse({
            "type": "start",
            "scenario": {
                "id": scenario_id,
                "title": seed["title"],
                "ioc": seed["ioc"],
                "ioc_type": seed["ioc_type"],
                "before_minutes": seed["before_minutes"],
                "estimated_after_seconds": seed["estimated_after_seconds"],
            },
            "expected_nodes": ["triage_step", "malware_step", "infrastructure_step", "campaign_step", "confidence_gate"],
        })

        graph = get_simulation_graph()
        # LangGraph 0.2.x: graph.stream(state) yields {node_name: delta_dict} per super-step
        for chunk in graph.stream(initial):
            for node_name, delta in chunk.items():
                yield _sse({
                    "type": "node",
                    "node": node_name,
                    "delta": _to_jsonable(delta),
                })
                if pace > 0:
                    await asyncio.sleep(pace)

        yield _sse({"type": "done"})

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",   # nginx 버퍼링 비활성화
        },
    )


def _sse(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, default=str, ensure_ascii=False)}\n\n"


def _to_jsonable(obj: Any) -> Any:
    """Pydantic 모델 / datetime / 기타 객체를 직렬화 가능한 형태로 변환."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_jsonable(v) for v in obj]
    return obj


@router.get("/simulate/{scenario_id}/report.pdf")
def simulate_report_pdf(scenario_id: str) -> Response:
    """시뮬레이션 시나리오 분석 결과를 PDF 로 생성하여 반환."""
    seed = get_scenario(scenario_id)
    if not seed:
        raise HTTPException(status_code=404, detail=f"scenario_id={scenario_id} not found")

    # 동기 시뮬레이션 실행 (PDF 생성 시점에 1회) — 결과 페이로드는 simulate() 와 동일 형식
    initial = ThreatHuntState(
        ioc=seed["ioc"],
        ioc_type=seed["ioc_type"],
        mode="simulation",
        scenario_id=scenario_id,
    )
    graph = get_simulation_graph()
    result_state_raw = graph.invoke(initial)
    result_state = (
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
    }
    run_result = {
        "scenario_id": scenario_id,
        "title": seed["title"],
        "automation_level": result_state.automation_level,
        "confidence_score": result_state.confidence_score,
        "human_approval_required": result_state.human_approval_required,
        "elapsed_ms": result_state.elapsed_ms,
        "audit_ledger": [e.model_dump(mode="json") for e in result_state.audit_ledger],
        "findings": findings,
        "deliverables": deliverables,
    }

    pdf_bytes = generate_report_pdf(scenario_id, run_result)
    filename = f"aol-threat-hunter-{scenario_id}-{result_state.ioc_type}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{filename}"'},
    )


@router.post("/chat/dialogue")
async def chat_dialogue(req: DialogueRequest):
    """진짜 대화형 SOC 어시스턴트 — IoC 있으면 LangGraph, 없으면 Claude 자유 대화.

    SSE 이벤트 타입:
    - type=start            : 모드 결정 (analysis / dialogue) + 메타
    - type=chat_chunk       : 자유 대화 모드의 텍스트 chunk 스트림
    - type=node             : 분석 모드의 LangGraph 노드별 delta
    - type=done             : 종료
    """
    ioc, ioc_type, scenario_id = _parse_input(req.message)
    is_analysis = scenario_id is not None or ioc_type not in ("unknown",)

    async def event_gen():
        if is_analysis:
            # ========== Analysis mode: LangGraph 멀티에이전트 ==========
            use_live = has_anthropic_key() and scenario_id is None  # 임의 IoC = 라이브 / 시나리오 ID = 시뮬레이션
            sid = scenario_id or "S1"
            seed = get_scenario(sid) if scenario_id else {}
            title = (seed or {}).get("title") if seed else f"라이브 분석 — {ioc}"
            yield _sse({
                "type": "start",
                "mode": "analysis",
                "submode": "live" if use_live else "simulation",
                "parsed": {"ioc": ioc, "ioc_type": ioc_type, "scenario_id": scenario_id},
                "title": title,
                "before_minutes": (seed or {}).get("before_minutes"),
                "estimated_after_seconds": (seed or {}).get("estimated_after_seconds"),
            })
            initial = ThreatHuntState(
                ioc=ioc,
                ioc_type=ioc_type,
                mode="live" if use_live else "simulation",
                scenario_id=scenario_id,
            )
            graph = build_graph(mode="live") if use_live else get_simulation_graph()
            for chunk in graph.stream(initial):
                for node_name, delta in chunk.items():
                    yield _sse({"type": "node", "node": node_name, "delta": _to_jsonable(delta)})
                    if req.pace > 0:
                        await asyncio.sleep(req.pace)
            yield _sse({
                "type": "done",
                "mode": "analysis",
                "deliverables_hint": {
                    "executive_summary_available": True,
                    "firewall_rules_available": True,
                    "hunt_hypotheses_available": True,
                    "pdf_report_path": f"/api/lg/simulate/{sid}/report.pdf" if scenario_id else None,
                },
            })
        else:
            # ========== Dialogue mode: Claude 자유 대화 + Tool Use 멀티에이전트 ==========
            yield _sse({
                "type": "start",
                "mode": "dialogue",
                "has_anthropic_key": has_anthropic_key(),
            })
            history_dicts = [m.model_dump() for m in req.history]
            async for ev in stream_claude_response(req.message, history_dicts):
                if ev.get("kind") == "text":
                    yield _sse({"type": "chat_chunk", "delta": ev["delta"]})
                elif ev.get("kind") == "tool_use":
                    yield _sse({
                        "type": "tool_use",
                        "tool": ev["tool"],
                        "question": ev["question"],
                    })
                elif ev.get("kind") == "tool_result":
                    yield _sse({
                        "type": "tool_result",
                        "tool": ev["tool"],
                        "summary": ev["summary"],
                        "elapsed_ms": ev.get("elapsed_ms"),
                        "model": ev.get("model"),
                    })
            yield _sse({"type": "done", "mode": "dialogue"})

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
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
