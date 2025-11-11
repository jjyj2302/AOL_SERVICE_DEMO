"""
OSINT 분석 상태 객체 정의

모든 Agent 노드 간 공유되는 상태 스키마
"""

from typing import TypedDict, Annotated, Optional
from langgraph.graph.message import add_messages
import operator


class OsintState(TypedDict):
    """
    OSINT 분석 상태 객체 (Enhanced for Circular Evaluation)

    모든 노드(Agent)가 이 상태를 읽고 수정하며,
    데이터셋이 점진적으로 확장됨

    Evaluator Agent를 통한 순환 평가 패턴 지원:
    - Supervisor → SubAgent → Evaluator → (FAIL시) → Supervisor
    """
    # === 기본 필드 (LangGraph 표준) ===
    messages: Annotated[list, add_messages]
    remaining_steps: int  # ReAct Agent에서 사용하는 남은 추론 단계 수

    # === 원본 쿼리 정보 ===
    original_query: str
    ioc_type: Optional[str]  # domain, ip, cve, hash, url

    # === 축적 데이터셋 (legacy, 호환성 유지) ===
    dataset: dict

    # === Agent별 분석 결과 (새로 추가) ===
    domain_analysis: Optional[dict]      # DomainAgent 결과
    hash_analysis: Optional[dict]        # HashAgent 결과
    url_analysis: Optional[dict]         # URLAgent 결과
    vuln_analysis: Optional[dict]        # VulnerabilityAgent 결과

    # === 평가 필드 (Evaluator Agent 전용) ===
    confidence_score: float              # 0.0-1.0 신뢰도 점수
    data_quality: dict                   # 데이터 품질 메트릭
    evaluation: dict                     # PASS/FAIL 판정 결과

    # === API 호출 추적 (디버깅/분석용) ===
    api_calls: Annotated[list, operator.add]  # API 호출 기록 누적

    # === 발견된 IOC 목록 (순환 분석용) ===
    findings: Annotated[list, operator.add]   # 발견된 IOC 누적

    # === 제어 흐름 필드 ===
    investigation_count: int             # 조사 반복 횟수
    max_iterations: int                  # 최대 반복 횟수
    investigation_complete: bool         # 조사 완료 여부
    next_agent: Optional[str]            # 다음 Agent (Supervisor 결정)
    next_action: Optional[str]           # Evaluator 권장 행동 (finalize/enrich/rewrite)

    # === 데이터 품질 필드 ===
    missing_data: Annotated[list, operator.add]  # 누락된 데이터 목록


def create_initial_state(query: str, max_iterations: int = 5) -> OsintState:
    """
    초기 상태 생성 (Enhanced for Circular Evaluation)

    Args:
        query: 사용자 쿼리 (도메인, IP, CVE 등)
        max_iterations: 최대 반복 횟수 (기본값: 5)

    Returns:
        OsintState: 초기화된 상태 객체
    """
    return {
        # 기본 필드
        "messages": [],
        "remaining_steps": 10,  # ReAct Agent가 사용할 최대 추론 단계 수
        "original_query": query,
        "ioc_type": None,
        "dataset": {},  # legacy 호환성

        # Agent별 결과 (초기값 None)
        "domain_analysis": None,
        "hash_analysis": None,
        "url_analysis": None,
        "vuln_analysis": None,

        # 평가 필드 (초기값)
        "confidence_score": 0.0,
        "data_quality": {},
        "evaluation": {},

        # 추적 필드 (빈 리스트)
        "api_calls": [],
        "findings": [],
        "missing_data": [],

        # 제어 흐름
        "investigation_count": 0,
        "max_iterations": max_iterations,
        "investigation_complete": False,
        "next_agent": None,
        "next_action": None
    }
