"""
OSINT Multi-Agent Supervisor

langgraph-supervisor를 사용한 Multi-Agent 조율 시스템
"""

from langchain_openai import ChatOpenAI
from langgraph_supervisor import create_supervisor

from .agents.vulnerability.agent import create_vulnerability_agent
from .agents.domain.agent import create_domain_agent
from .agents.hash.agent import create_hash_agent
from .agents.url.agent import create_url_agent
from .agents.evaluator.agent import create_evaluator_agent
from .state import OsintState
from app.core.settings.api_keys.cache import APIKeyCache


def create_osint_supervisor(llm_model: str = "gpt-4"):
    """
    OSINT 분석 Multi-Agent Supervisor 생성

    5개 전문 에이전트를 조율:
        - vulnerability_expert: CVE, 취약점 분석
        - domain_expert: IP, 도메인, 네트워크 분석
        - hash_expert: 파일 해시, 멀웨어 분석
        - url_expert: URL, 피싱 분석
        - evaluator_expert: 데이터 품질 평가 및 순환 라우팅

    Args:
        llm_model: 사용할 LLM 모델 (기본값: gpt-4)

    Returns:
        Compiled Supervisor (Pregel)
    """
    print(f"Creating OSINT Supervisor (model: {llm_model})")

    # DB에서 OpenAI API 키 가져오기
    api_cache = APIKeyCache.get_instance()
    openai_key_data = api_cache.get_key("openai")
    openai_key = openai_key_data.get("key", "")

    if not openai_key:
        raise ValueError("OpenAI API key not found in database. Please configure it in settings.")

    # LLM 초기화 (API 키 명시적 전달)
    llm = ChatOpenAI(model=llm_model, temperature=0, api_key=openai_key)

    # 5개 전문 에이전트 생성
    print("  Creating vulnerability_expert...")
    vuln_agent = create_vulnerability_agent(llm_model)

    print("  Creating domain_expert...")
    domain_agent = create_domain_agent(llm_model)

    print("  Creating hash_expert...")
    hash_agent = create_hash_agent(llm_model)

    print("  Creating url_expert...")
    url_agent = create_url_agent(llm_model)

    print("  Creating evaluator_expert...")
    evaluator_agent = create_evaluator_agent(llm_model)

    print("  All agents created")

    # Supervisor 생성 (langgraph-supervisor 사용!)
    print("  Building supervisor workflow...")
    workflow = create_supervisor(
        agents=[vuln_agent, domain_agent, hash_agent, url_agent, evaluator_agent],
        model=llm,
        state_schema=OsintState,
        output_mode="last_message",  # 토큰 절약
        add_handoff_messages=True,   # 디버깅용
        supervisor_name="osint_supervisor",
        prompt="""OSINT supervisor. Route to agents:
        1. CVE-XXXX → vulnerability_expert
        2. domain/IP → domain_expert
        3. hash (32/40/64 hex) → hash_expert
        4. URL (http/https) → url_expert
        5. After specialist analysis → evaluator_expert (quality check & circular routing)
        Evaluator decides: FINALIZE, ENRICH (add more IOCs), or REWRITE query.
        Provide final summary."""
    )

    # Compile with recursion limit (무한 루프 방지!)
    print("  Compiling supervisor...")
    supervisor = workflow.compile(
        checkpointer=None,  # 메모리 없음
        interrupt_before=None,
        interrupt_after=None,
        debug=False
    )

    print("OSINT Supervisor ready\n")
    return supervisor
