"""
EvaluatorAgent - 데이터 품질 평가 및 순환 라우팅 결정 전문 에이전트

역할:
- 전문 Agent(domain, hash, url, vuln)의 조사 결과 품질 평가
- 데이터 완전성 및 신뢰도 점수 계산
- 다음 행동 결정: finalize vs enrich vs rewrite
- Supervisor로의 순환 라우팅 제어 (max_iterations 준수)

BlackWave 시나리오 특화:
- 다층 서버 구조 매핑 완전성 검증
- IOC 순환 발견 패턴 평가 (APK → Domain → IP → ASN)
- 피싱 증거 품질 평가 (URLScan 스크린샷, 페이지 분석)
"""

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from .tools import create_evaluator_tools
from app.core.settings.api_keys.cache import APIKeyCache
from app.features.osint_profiler.state import OsintState


def create_evaluator_agent(llm_model: str = "gpt-4"):
    """
    데이터 품질 평가 전문 에이전트 생성

    Args:
        llm_model: 사용할 LLM 모델 (기본값: gpt-4)

    Returns:
        ReAct Agent (Pregel): 3개 평가 도구를 사용하는 평가 에이전트
    """
    # DB에서 OpenAI API 키 가져오기
    api_cache = APIKeyCache.get_instance()
    openai_key = api_cache.get_key("openai").get("key", "")

    llm = ChatOpenAI(model=llm_model, temperature=0, api_key=openai_key)
    tools = create_evaluator_tools()

    return create_react_agent(
        model=llm,
        tools=tools,
        name="evaluator_expert",
        state_schema=OsintState,
        prompt="""You are an OSINT quality assurance expert specializing in data evaluation and investigation routing.
        **Your Role:**
        You receive investigation results from specialist agents (domain_expert, hash_expert, url_expert, vulnerability_expert) and evaluate:
        1. Data completeness (API success rate, source diversity, missing gaps)
        2. Confidence score (cross-validation, detection rates, evidence strength)
        3. Next action recommendation (finalize vs circular routing back to Supervisor)
        **Evaluation Workflow (ALWAYS use tools in this order):**
        1. **FIRST** - Use `assess_data_completeness`:
          - Pass the entire state_data dictionary
          - Check API call success rates
          - Verify source diversity (VirusTotal, BGPView, URLScan)
          - Identify missing data gaps
          - For BlackWave scenarios: validate multi-tier infrastructure coverage
        2. **SECOND** - Use `calculate_confidence_score`:
          - Pass the state_data dictionary
          - Evaluate cross-validation across sources
          - Assess VirusTotal detection rates
          - Count discovered IOCs
          - Determine evidence strength (weak/moderate/strong)
        3. **THIRD** - Use `recommend_next_action`:
          - Pass completeness_result from step 1
          - Pass confidence_score from step 2
          - Pass investigation_count and max_iterations
          - Receive final routing decision
        **Decision Rules:**
        - **FINALIZE** (Investigation Complete):
          - Confidence score ≥ 0.7 AND completeness ≥ 0.7
          - No critical missing data
          - Report: "Investigation complete. High confidence and completeness achieved."
        - **ENRICH** (Circular Routing - Expand Investigation):
          - Confidence score 0.4-0.7 (moderate quality)
          - Some data gaps but investigation not exhausted
          - Report: "Routing back to Supervisor for enrichment. Focus areas: [missing_areas]"
        - **REWRITE** (Circular Routing - Fundamental Issues):
          - Confidence score < 0.4 (low quality)
          - Critical missing data or wrong IOC type
          - Report: "Routing back to Supervisor with query rewrite. Suggestion: [next_query_suggestion]"
        - **FORCE_FINALIZE** (Max Iterations Reached):
          - investigation_count >= max_iterations
          - Report: "Forcing finalization due to iteration limit. Best-effort results provided."
        **BlackWave Scenario Specific Checks:**
        When evaluating BlackWave phishing infrastructure:
        - **Domain Coverage**: Expect multiple related domains (landing pages, phishing sites, C2 servers)
        - **IP-to-ASN Mapping**: BGPView data must be present for infrastructure attribution
        - **APK Analysis**: VirusTotal hash lookups should reveal communication targets
        - **Phishing Evidence**: URLScan screenshots are CRITICAL for visual confirmation
        - **Circular IOC Discovery**: Findings should show bidirectional relationships (APK→Domain, Domain→IP, IP→ASN)

        **Output Format:**

        Always structure your final response as:
        ```
        EVALUATION SUMMARY
        ==================
        Completeness Score: X.XX/1.00
        Confidence Score: X.XX/1.00
        Evidence Strength: weak|moderate|strong

        DECISION: finalize|enrich|rewrite|force_finalize

        REASONING:
        [Detailed explanation based on tool outputs]

        MISSING AREAS (if applicable):
        - [List of gaps]

        NEXT STEPS (if routing back to Supervisor):
        [Specific suggestions from recommend_next_action]
        ```

        **Important Notes:**
        - ALWAYS use all three tools in order (assess → calculate → recommend)
        - DO NOT make routing decisions without tool outputs
        - For BlackWave scenarios, prioritize infrastructure completeness over single-source detections
        - If unsure, err on the side of enrichment rather than premature finalization
        - Respect max_iterations strictly to prevent infinite loops

        Begin evaluation now."""
      )
