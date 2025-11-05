"""
OSINT Profiler API Routes

Multi-Agent Supervisor를 사용한 OSINT 조사 엔드포인트
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import time

from app.features.osint_profiler.supervisor_cache import get_supervisor
from app.features.osint_profiler.state import create_initial_state


router = APIRouter(prefix="/api/osint", tags=["OSINT Profiler"])


class InvestigationRequest(BaseModel):
    """OSINT 조사 요청"""
    query: str
    query_type: Optional[str] = None  # "cve", "domain", "ip", "hash", "email" (선택)


class InvestigationResponse(BaseModel):
    """OSINT 조사 응답"""
    query: str
    result: str
    execution_time_ms: int
    messages_count: int


class StateSnapshot(BaseModel):
    """State 스냅샷"""
    step: int
    node_name: str
    message_content: Optional[str] = None
    findings_count: int = 0
    confidence_score: float = 0.0


class VerboseInvestigationResponse(BaseModel):
    """상세 OSINT 조사 응답 (State 추적 포함)"""
    query: str
    result: str
    execution_time_ms: int
    messages_count: int
    state_history: List[StateSnapshot]
    final_state: Dict[str, Any]


@router.post("/investigate", response_model=InvestigationResponse)
async def investigate(request: InvestigationRequest):
    """
    OSINT 조사 수행

    Supervisor가 쿼리를 분석하여 적절한 전문 에이전트에게 자동 라우팅:
    - CVE-XXXX-XXXX → vulnerability_expert
    - 도메인/IP → domain_expert
    - 파일 해시 → hash_expert
    - URL → url_expert

    Args:
        request: 조사 요청 (query, query_type)

    Returns:
        조사 결과 및 실행 메타데이터
    """
    try:
        # 캐시된 Supervisor 가져오기 (초고속!)
        supervisor = get_supervisor()

        # 초기 State 생성
        initial_state = create_initial_state(
            query=request.query,
            max_iterations=10  # Evaluator가 10번 반복 후 강제 종료
        )

        # 조사 실행 (recursion_limit 설정으로 무한 루프 방지!)
        start_time = time.time()
        result = await supervisor.ainvoke(
            initial_state,
            config={"recursion_limit": 15}  # 최대 15번 Agent 호출
        )
        execution_time = int((time.time() - start_time) * 1000)

        # 최종 메시지 추출
        final_message = result["messages"][-1]

        return InvestigationResponse(
            query=request.query,
            result=final_message.content,
            execution_time_ms=execution_time,
            messages_count=len(result["messages"])
        )

    except RuntimeError as e:
        # Supervisor 초기화 안 된 경우
        raise HTTPException(
            status_code=503,
            detail=f"OSINT Supervisor not ready: {str(e)}"
        )
    except Exception as e:
        # 기타 에러
        raise HTTPException(
            status_code=500,
            detail=f"Investigation failed: {str(e)}"
        )


@router.post("/investigate/verbose", response_model=VerboseInvestigationResponse)
async def investigate_verbose(request: InvestigationRequest):
    """
    OSINT 조사 수행 (State 추적 포함)

    각 단계별 State 변화를 추적하여 Multi-Agent 실행 순서를 확인할 수 있습니다.

    Args:
        request: 조사 요청 (query, query_type)

    Returns:
        조사 결과 + State 히스토리 + 최종 State
    """
    try:
        supervisor = get_supervisor()

        # 초기 State 생성
        initial_state = create_initial_state(
            query=request.query,
            max_iterations=10  # Evaluator가 10번 반복 후 강제 종료
        )

        # State 히스토리 추적
        state_history: List[StateSnapshot] = []
        step_count = 0

        start_time = time.time()

        # astream으로 각 단계별 State 추적 (recursion_limit 설정!)
        final_state = None
        async for event in supervisor.astream(
            initial_state,
            config={"recursion_limit": 15}  # 최대 15번 Agent 호출
        ):
            step_count += 1

            # 각 노드별 이벤트 처리
            for node_name, node_state in event.items():
                # 메시지 추출
                message_content = None
                if "messages" in node_state and node_state["messages"]:
                    last_msg = node_state["messages"][-1]
                    message_content = last_msg.content if hasattr(last_msg, 'content') else str(last_msg)

                # Snapshot 생성
                snapshot = StateSnapshot(
                    step=step_count,
                    node_name=node_name,
                    message_content=message_content[:500] if message_content else None,  # 500자로 제한
                    findings_count=len(node_state.get("findings", [])),
                    confidence_score=node_state.get("confidence_score", 0.0)
                )

                state_history.append(snapshot)
                final_state = node_state

        execution_time = int((time.time() - start_time) * 1000)

        # 최종 메시지 추출
        final_message = final_state["messages"][-1]

        # 최종 State 직렬화 (메시지는 제외)
        serialized_final_state = {
            "findings_count": len(final_state.get("findings", [])),
            "confidence_score": final_state.get("confidence_score", 0.0),
            "domain_analysis": bool(final_state.get("domain_analysis")),
            "hash_analysis": bool(final_state.get("hash_analysis")),
            "url_analysis": bool(final_state.get("url_analysis")),
            "evaluation": final_state.get("evaluation", {})
        }

        return VerboseInvestigationResponse(
            query=request.query,
            result=final_message.content,
            execution_time_ms=execution_time,
            messages_count=len(final_state["messages"]),
            state_history=state_history,
            final_state=serialized_final_state
        )

    except RuntimeError as e:
        raise HTTPException(
            status_code=503,
            detail=f"OSINT Supervisor not ready: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Investigation failed: {str(e)}"
        )


@router.get("/health")
async def health_check():
    """Supervisor 상태 확인"""
    try:
        supervisor = get_supervisor()
        return {
            "status": "healthy",
            "supervisor": "initialized",
            "agents": [
                "vulnerability_expert",
                "domain_expert",
                "hash_expert",
                "url_expert"
            ]
        }
    except RuntimeError:
        return {
            "status": "not_ready",
            "supervisor": "not_initialized",
            "message": "Server is starting up. Please wait."
        }
