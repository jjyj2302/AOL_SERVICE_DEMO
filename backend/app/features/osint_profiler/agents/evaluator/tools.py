"""
EvaluatorAgent Tools - 데이터 품질 평가 및 다음 행동 추천

3가지 핵심 도구:
1. assess_data_completeness: API 성공률, 소스 다양성 평가
2. calculate_confidence_score: 0.0-1.0 신뢰도 점수 계산
3. recommend_next_action: finalize/enrich/rewrite 결정

BlackWave 시나리오 특화:
- 다층 서버 구조 분석 완전성 검증
- IOC 순환 발견 패턴 평가 (APK → Domain → IP → ASN)
- 피싱 증거 품질 평가 (스크린샷, 페이지 분석)
"""

from typing import List, Dict, Any
from langchain_core.tools import Tool, StructuredTool
from pydantic import BaseModel, Field


# ===== Pydantic Input Schemas =====

class DataCompletenessInput(BaseModel):
    """데이터 완전성 평가 입력"""
    state_data: dict = Field(
        description="현재 OsintState 딕셔너리 (api_calls, agent별 결과 포함)"
    )


class ConfidenceScoreInput(BaseModel):
    """신뢰도 점수 계산 입력"""
    state_data: dict = Field(
        description="현재 OsintState 딕셔너리 (findings, api_calls, agent별 결과 포함)"
    )


class NextActionInput(BaseModel):
    """다음 행동 추천 입력"""
    completeness_result: dict = Field(
        description="assess_data_completeness 결과"
    )
    confidence_score: float = Field(
        description="calculate_confidence_score 결과 (0.0-1.0)"
    )
    investigation_count: int = Field(
        description="현재 조사 반복 횟수"
    )
    max_iterations: int = Field(
        description="최대 반복 횟수"
    )


# ===== Tool Implementation Functions =====

def assess_data_completeness(state_data: dict) -> dict:
    """
    데이터 완전성 평가

    평가 항목:
    1. API 호출 성공률 (api_calls에서 실패 여부 체크)
    2. 소스 다양성 (VirusTotal, BGPView, URLScan 등)
    3. Agent별 결과 존재 여부
    4. BlackWave 특화: 다층 서버 매핑 완전성

    Args:
        state_data: 현재 OsintState 딕셔너리

    Returns:
        dict: {
            "overall_score": float (0.0-1.0),
            "api_success_rate": float,
            "source_diversity": int,
            "agents_responded": list[str],
            "missing_data": list[str],
            "blackwave_coverage": dict
        }
    """
    result = {
        "overall_score": 0.0,
        "api_success_rate": 0.0,
        "source_diversity": 0,
        "agents_responded": [],
        "missing_data": [],
        "blackwave_coverage": {}
    }

    # 1. API 호출 성공률 계산
    api_calls = state_data.get("api_calls", [])
    if api_calls:
        successful_calls = [c for c in api_calls if c.get("success", False)]
        result["api_success_rate"] = len(successful_calls) / len(api_calls)
    else:
        result["api_success_rate"] = 0.0

    # 2. 소스 다양성 (API 종류 카운트)
    unique_sources = set()
    for call in api_calls:
        api_name = call.get("api_name", "")
        if api_name:
            unique_sources.add(api_name)
    result["source_diversity"] = len(unique_sources)

    # 3. Agent별 결과 존재 여부
    agent_fields = ["domain_analysis", "hash_analysis", "url_analysis", "vuln_analysis"]
    for field in agent_fields:
        if state_data.get(field) is not None:
            result["agents_responded"].append(field.replace("_analysis", ""))

    # 4. 누락 데이터 식별
    ioc_type = state_data.get("ioc_type", "")

    # Domain/IP 분석 시 필수 데이터
    if ioc_type in ["domain", "ip"]:
        if not state_data.get("domain_analysis"):
            result["missing_data"].append("domain_analysis required for domain/ip")
        else:
            da = state_data["domain_analysis"]
            if not da.get("virustotal_result"):
                result["missing_data"].append("virustotal_result missing")
            if not da.get("bgp_info") and ioc_type == "ip":
                result["missing_data"].append("bgp_info missing for IP")

    # Hash 분석 시 필수 데이터
    if ioc_type == "hash":
        if not state_data.get("hash_analysis"):
            result["missing_data"].append("hash_analysis required for hash")
        else:
            ha = state_data["hash_analysis"]
            if not ha.get("virustotal_result"):
                result["missing_data"].append("virustotal_result missing for hash")

    # URL 분석 시 필수 데이터
    if ioc_type == "url":
        if not state_data.get("url_analysis"):
            result["missing_data"].append("url_analysis required for url")
        else:
            ua = state_data["url_analysis"]
            if not ua.get("urlscan_result"):
                result["missing_data"].append("urlscan_result missing")
            if not ua.get("screenshot_url"):
                result["missing_data"].append("screenshot evidence missing")

    # 5. BlackWave 특화 평가
    findings = state_data.get("findings", [])
    bw_coverage = {
        "domains_found": 0,
        "ips_found": 0,
        "hashes_found": 0,
        "asn_identified": False,
        "phishing_evidence": False
    }

    for finding in findings:
        finding_type = finding.get("type", "")
        if finding_type == "domain":
            bw_coverage["domains_found"] += 1
        elif finding_type == "ip":
            bw_coverage["ips_found"] += 1
        elif finding_type == "hash":
            bw_coverage["hashes_found"] += 1

    # ASN 정보 확인
    if state_data.get("domain_analysis", {}).get("bgp_info"):
        bw_coverage["asn_identified"] = True

    # 피싱 증거 확인 (URLScan 스크린샷)
    if state_data.get("url_analysis", {}).get("screenshot_url"):
        bw_coverage["phishing_evidence"] = True

    result["blackwave_coverage"] = bw_coverage

    # 6. 종합 점수 계산 (0.0-1.0)
    scores = []
    scores.append(result["api_success_rate"])  # API 성공률 (0-1)
    scores.append(min(result["source_diversity"] / 3.0, 1.0))  # 소스 다양성 (최대 3개 정규화)
    scores.append(len(result["agents_responded"]) / 4.0)  # Agent 응답률 (최대 4개)

    # 누락 데이터 페널티
    if result["missing_data"]:
        scores.append(0.5)  # 누락 시 페널티
    else:
        scores.append(1.0)

    result["overall_score"] = sum(scores) / len(scores)

    return result


def calculate_confidence_score(state_data: dict) -> dict:
    """
    신뢰도 점수 계산

    평가 기준:
    1. 다중 소스 교차 검증 (VirusTotal + BGPView + URLScan)
    2. 탐지 엔진 일치율 (malicious count ≥ 5 = 높은 신뢰도)
    3. 발견된 IOC 수 (많을수록 신뢰도 높음)
    4. 데이터 신선도 (API 호출 시간, last_resolved 등)

    Args:
        state_data: 현재 OsintState 딕셔너리

    Returns:
        dict: {
            "confidence_score": float (0.0-1.0),
            "evidence_strength": str (weak/moderate/strong),
            "cross_validation": bool,
            "detection_rate": float,
            "reasoning": str
        }
    """
    result = {
        "confidence_score": 0.0,
        "evidence_strength": "weak",
        "cross_validation": False,
        "detection_rate": 0.0,
        "reasoning": ""
    }

    scores = []
    reasoning_parts = []

    # 1. 소스 교차 검증
    sources_used = set()
    api_calls = state_data.get("api_calls", [])
    for call in api_calls:
        if call.get("success"):
            sources_used.add(call.get("api_name", ""))

    if len(sources_used) >= 2:
        result["cross_validation"] = True
        scores.append(1.0)
        reasoning_parts.append(f"Cross-validated with {len(sources_used)} sources")
    else:
        scores.append(0.3)
        reasoning_parts.append(f"Only {len(sources_used)} source(s) used")

    # 2. VirusTotal 탐지율 (domain/ip/hash)
    vt_detections = 0
    vt_total = 0

    for agent_field in ["domain_analysis", "hash_analysis", "url_analysis"]:
        analysis = state_data.get(agent_field)
        if analysis and "virustotal_result" in analysis:
            vt_result = analysis["virustotal_result"]
            stats = vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            vt_detections += stats.get("malicious", 0) + stats.get("suspicious", 0)
            vt_total += stats.get("malicious", 0) + stats.get("suspicious", 0) + stats.get("harmless", 0)

    if vt_total > 0:
        detection_rate = vt_detections / vt_total
        result["detection_rate"] = detection_rate

        if detection_rate >= 0.5:
            scores.append(1.0)
            reasoning_parts.append(f"High detection rate: {detection_rate:.2%}")
        elif detection_rate >= 0.1:
            scores.append(0.6)
            reasoning_parts.append(f"Moderate detection rate: {detection_rate:.2%}")
        else:
            scores.append(0.2)
            reasoning_parts.append(f"Low detection rate: {detection_rate:.2%}")
    else:
        scores.append(0.5)
        reasoning_parts.append("No VirusTotal detection data available")

    # 3. 발견된 IOC 수
    findings = state_data.get("findings", [])
    if len(findings) >= 5:
        scores.append(1.0)
        reasoning_parts.append(f"{len(findings)} IOCs discovered")
    elif len(findings) >= 2:
        scores.append(0.7)
        reasoning_parts.append(f"{len(findings)} IOCs discovered")
    elif len(findings) >= 1:
        scores.append(0.4)
        reasoning_parts.append(f"Only {len(findings)} IOC discovered")
    else:
        scores.append(0.0)
        reasoning_parts.append("No IOCs discovered")

    # 4. Agent 응답 다양성
    agents_responded = []
    for field in ["domain_analysis", "hash_analysis", "url_analysis", "vuln_analysis"]:
        if state_data.get(field):
            agents_responded.append(field)

    if len(agents_responded) >= 2:
        scores.append(0.8)
        reasoning_parts.append(f"{len(agents_responded)} agents contributed")
    elif len(agents_responded) == 1:
        scores.append(0.5)
        reasoning_parts.append("Single agent response")
    else:
        scores.append(0.0)
        reasoning_parts.append("No agent responses")

    # 종합 점수
    if scores:
        result["confidence_score"] = sum(scores) / len(scores)

    # 증거 강도 결정
    if result["confidence_score"] >= 0.7:
        result["evidence_strength"] = "strong"
    elif result["confidence_score"] >= 0.4:
        result["evidence_strength"] = "moderate"
    else:
        result["evidence_strength"] = "weak"

    result["reasoning"] = "; ".join(reasoning_parts)

    return result


def recommend_next_action(
    completeness_result: dict,
    confidence_score: float,
    investigation_count: int,
    max_iterations: int
) -> dict:
    """
    다음 행동 추천

    결정 로직:
    1. FINALIZE: 신뢰도 ≥ 0.7 AND 완전성 ≥ 0.7 AND 누락 데이터 없음
    2. ENRICH: 신뢰도 중간(0.4-0.7) AND 반복 횟수 < max_iterations
    3. REWRITE: 신뢰도 낮음(< 0.4) AND 누락 데이터 있음 AND 반복 횟수 < max_iterations
    4. FORCE_FINALIZE: max_iterations 도달

    Args:
        completeness_result: assess_data_completeness 결과
        confidence_score: calculate_confidence_score 결과
        investigation_count: 현재 조사 반복 횟수
        max_iterations: 최대 반복 횟수

    Returns:
        dict: {
            "action": str (finalize/enrich/rewrite/force_finalize),
            "reasoning": str,
            "missing_areas": list[str],
            "next_query_suggestion": str | None
        }
    """
    result = {
        "action": "finalize",
        "reasoning": "",
        "missing_areas": [],
        "next_query_suggestion": None
    }

    completeness_score = completeness_result.get("overall_score", 0.0)
    missing_data = completeness_result.get("missing_data", [])

    # 1. 강제 종료 (max_iterations 도달)
    if investigation_count >= max_iterations:
        result["action"] = "force_finalize"
        result["reasoning"] = f"Max iterations ({max_iterations}) reached. Forcing finalization."
        return result

    # 2. FINALIZE (높은 품질)
    if confidence_score >= 0.7 and completeness_score >= 0.7 and not missing_data:
        result["action"] = "finalize"
        result["reasoning"] = (
            f"High confidence ({confidence_score:.2f}) and completeness ({completeness_score:.2f}). "
            "Investigation complete."
        )
        return result

    # 3. ENRICH (중간 품질, 보강 필요)
    if 0.4 <= confidence_score < 0.7:
        result["action"] = "enrich"
        result["missing_areas"] = missing_data
        result["reasoning"] = (
            f"Moderate confidence ({confidence_score:.2f}). "
            f"Enrichment needed: {', '.join(missing_data) if missing_data else 'general data expansion'}."
        )

        # BlackWave 특화 보강 제안
        bw_coverage = completeness_result.get("blackwave_coverage", {})
        if not bw_coverage.get("asn_identified"):
            result["next_query_suggestion"] = "Investigate IP addresses to identify ASN/hosting provider"
        elif not bw_coverage.get("phishing_evidence"):
            result["next_query_suggestion"] = "Capture URLScan screenshots for phishing evidence"
        elif bw_coverage.get("domains_found", 0) < 3:
            result["next_query_suggestion"] = "Expand domain infrastructure mapping (related domains)"

        return result

    # 4. REWRITE (낮은 품질, 재조사 필요)
    if confidence_score < 0.4:
        result["action"] = "rewrite"
        result["missing_areas"] = missing_data
        result["reasoning"] = (
            f"Low confidence ({confidence_score:.2f}). "
            f"Query rewrite needed. Missing: {', '.join(missing_data) if missing_data else 'critical data'}."
        )

        # 재조사 제안
        if "virustotal_result missing" in missing_data:
            result["next_query_suggestion"] = "Re-query VirusTotal with correct IOC type"
        elif "bgp_info missing" in missing_data:
            result["next_query_suggestion"] = "Query BGPView for IP attribution"
        elif "screenshot evidence missing" in missing_data:
            result["next_query_suggestion"] = "Re-scan URL with URLScan.io for visual evidence"
        else:
            result["next_query_suggestion"] = "Broaden investigation scope or validate IOC type"

        return result

    # 5. 기본값 (보수적 ENRICH)
    result["action"] = "enrich"
    result["reasoning"] = "Default action: enrich investigation with additional sources."
    return result


# ===== Tool Creation Function =====

def create_evaluator_tools() -> List[Tool]:
    """
    Evaluator Agent 도구 생성

    Returns:
        List[Tool]: 3개의 평가 도구
            1. assess_data_completeness
            2. calculate_confidence_score
            3. recommend_next_action
    """
    tools = []

    # 1. 데이터 완전성 평가
    tools.append(StructuredTool.from_function(
        func=assess_data_completeness,
        name="assess_data_completeness",
        description="""Assess OSINT data completeness and quality.

USE WHEN:
- Need to evaluate if specialist agents gathered sufficient data
- Checking API call success rates and source diversity
- Validating BlackWave multi-tier infrastructure coverage

INPUT:
- state_data: Current OsintState dictionary with api_calls, agent results

RETURNS:
{
  "overall_score": float (0.0-1.0),
  "api_success_rate": float,
  "source_diversity": int,
  "agents_responded": ["domain", "hash", "url"],
  "missing_data": ["virustotal_result missing", ...],
  "blackwave_coverage": {
    "domains_found": int,
    "ips_found": int,
    "hashes_found": int,
    "asn_identified": bool,
    "phishing_evidence": bool
  }
}

INTERPRETATION:
- overall_score ≥ 0.7: Good completeness
- overall_score 0.4-0.7: Needs enrichment
- overall_score < 0.4: Critical gaps, rewrite needed

Use this FIRST before calculating confidence score.""",
        args_schema=DataCompletenessInput
    ))

    # 2. 신뢰도 점수 계산
    tools.append(StructuredTool.from_function(
        func=calculate_confidence_score,
        name="calculate_confidence_score",
        description="""Calculate confidence score for OSINT findings.

USE WHEN:
- Need to determine reliability of collected intelligence
- Evaluating cross-validation across multiple sources
- Assessing VirusTotal detection rates and IOC discovery

INPUT:
- state_data: Current OsintState dictionary with findings, api_calls

RETURNS:
{
  "confidence_score": float (0.0-1.0),
  "evidence_strength": "weak|moderate|strong",
  "cross_validation": bool,
  "detection_rate": float,
  "reasoning": "Detailed explanation"
}

INTERPRETATION:
- confidence_score ≥ 0.7: Strong evidence (finalize)
- confidence_score 0.4-0.7: Moderate (enrich)
- confidence_score < 0.4: Weak (rewrite query)

Use this SECOND after assessing completeness.""",
        args_schema=ConfidenceScoreInput
    ))

    # 3. 다음 행동 추천
    tools.append(StructuredTool.from_function(
        func=recommend_next_action,
        name="recommend_next_action",
        description="""Recommend next action based on evaluation results.

USE WHEN:
- Ready to make final decision on investigation status
- Need to determine if circular routing back to Supervisor is required

INPUT:
- completeness_result: Output from assess_data_completeness
- confidence_score: Score from calculate_confidence_score
- investigation_count: Current iteration count
- max_iterations: Maximum allowed iterations

RETURNS:
{
  "action": "finalize|enrich|rewrite|force_finalize",
  "reasoning": "Why this action was chosen",
  "missing_areas": ["list", "of", "gaps"],
  "next_query_suggestion": "Specific suggestion for next investigation"
}

ACTIONS:
- finalize: High quality, complete investigation → END
- enrich: Moderate quality, needs more data → ROUTE BACK to Supervisor
- rewrite: Low quality, fundamental issues → ROUTE BACK with new query
- force_finalize: Max iterations reached → FORCED END

Use this THIRD as final decision tool.""",
        args_schema=NextActionInput
    ))

    return tools
