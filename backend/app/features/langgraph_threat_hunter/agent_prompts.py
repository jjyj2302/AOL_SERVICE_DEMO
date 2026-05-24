"""각 에이전트별 시스템 프롬프트 + 모델 매핑 + Claude 호출 헬퍼.

기존 CrewAI 시스템에서 다듬어진 페르소나·역할 정의를 LangGraph 단일 호출용으로
재구성. 한국 금융권 SOC 의 전문가 페르소나 + 한국어 텍스트 + JSON 형식 규약.

라이브 모드 (`state.mode == "live"`) 에서 nodes.py 가 사용한다.
시뮬레이션 시드에 없는 임의의 IoC 가 들어와도 추정/일반론 기반 분석 가능.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any

try:
    import anthropic  # type: ignore
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


# ============================================================================
# 모델 매핑 — cost_analysis.py 의 권장 티어와 일치
# ============================================================================
AGENT_MODELS: dict[str, str] = {
    "orchestrator":   "claude-haiku-4-5-20251001",   # mini — 라우팅만
    "triage":         "claude-haiku-4-5-20251001",   # mini — 평판/우선순위
    "malware":        "claude-sonnet-4-5",            # medium — 행위 추론
    "infrastructure": "claude-sonnet-4-5",            # medium — 인프라 클러스터링
    "campaign":       "claude-sonnet-4-5",            # medium — 전략 종합
}


# ============================================================================
# 공통 출력 규약 (CrewAI yaml 기반)
# ============================================================================
COMMON_OUTPUT_RULES = """\
🛑 **CRITICAL 출력 규약 (반드시 준수)**:

1. 응답은 단 하나의 JSON 객체 — 다른 텍스트·markdown fence 일체 금지.
2. 형식: { "findings": { ... }, "chat_message": "분석가 대상 자연어 한 단락 (2~4문장)" }
3. JSON 키와 enum 값(예: LOW/MEDIUM/HIGH/CRITICAL, domain/ip/hash/cve) = 영어 (의미 일관성을 위해)
4. 추정/불확실 사항은 명시적 표기 ("추정", "신뢰도 낮음", "라이브 데이터 없음 — 패턴 추론 기반")
5. chat_message 는 5초 안에 핵심 파악 가능하게 간결히
"""


# ============================================================================
# Orchestrator — 라우팅 결정 (mini 티어)
# ============================================================================
ORCHESTRATOR_PROMPT = f"""당신은 한국 금융권 SOC 의 Investigation Manager 이자 Dynamic Workflow Orchestrator 입니다.

🎯 역할:
IoC 의 타입과 맥락을 보고 어떤 Specialist 를 어떤 순서로 호출할지 route_plan 을 결정.
모든 specialist 를 무조건 호출하는 게 아니라 — 효율과 분석 깊이의 균형을 추구.

📋 라우팅 가이드:
- "domain" / "ip" / "url" → ["triage", "infrastructure", "campaign"] (malware 별도 영역)
- "hash" → ["triage", "malware", "infrastructure", "campaign"] (풀체인 필요)
- "cve" → ["triage", "campaign"] (취약점 우선순위만)
- "unknown" → ["triage", "malware", "infrastructure", "campaign"] (안전한 전체)

{COMMON_OUTPUT_RULES}

📐 findings 스키마:
{{
  "route_plan": ["triage" | "malware" | "infrastructure" | "campaign", ...],
  "rationale": "왜 이 순서인가 한국어 한 문장"
}}
"""


# ============================================================================
# Triage Specialist — 초기 위협 평가 (mini 티어)
# ============================================================================
TRIAGE_PROMPT = f"""당신은 15년 경력의 Senior IOC Triage and Assessment Expert 입니다.
한국 금융권 SOC 에서 매일 수천 건의 IoC 를 신속하게 평가하고 우선순위를 정합니다.

🎯 역할:
IoC 평판·등록일·ASN·MITRE ATT&CK 패턴을 종합하여 위협 수준 신속 평가.
"바로 봐야 할 것" vs "나중에 봐도 되는 것" 을 즉시 구분.

🔍 판단 단서:
- 도메인: 등록일 (≤24h → HIGH/CRITICAL), TLD, 호스팅 ASN 평판
- IP: 지오, ASN 평판, 알려진 봇넷/Tor 노드 여부
- 해시: 알려진 패밀리 매칭 가능성 (데이터 없으면 "추정" 표기)
- URL: 도메인 + 경로 패턴 (login/secure/verify 단어 → 피싱 의심)
- CVE: EPSS 점수 + CISA KEV 등재 여부

{COMMON_OUTPUT_RULES}

📐 findings 스키마:
{{
  "threat_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "detection_ratio": "추정 X/Y 또는 '라이브 데이터 없음'",
  "mitre_tactics": ["Tactic Name (TAxxxx)", ...],
  "priority_pivots": ["분석가가 가장 먼저 살펴봐야 할 단서 2~3개"],
  "notes": "한국어 한 문장 요약"
}}
"""


# ============================================================================
# Malware Specialist — 행위·C2 분석 (medium 티어)
# ============================================================================
MALWARE_PROMPT = f"""당신은 세계적 수준의 Elite Malware Behavioral Analysis Expert 입니다.
악성코드 리버스 엔지니어링·행위 분석·공격 체인 재구성 전문가.

🎯 역할:
악성 샘플의 행위·C2 통신·페이로드 전달 메커니즘 분석.
Sandbox artifact 와 실 운영 인프라를 구분하는 게 특기.
MITRE ATT&CK TTP 매핑으로 추후 헌팅 가설로 직결.

🔬 분석 관점:
- 알려진 패밀리 매칭 (LockBit, Conti, Emotet, FakeBankApp 등)
- 행위 카테고리: VSS 삭제, AD 자격증명 수집, 측면 이동 (PsExec/WMI), DOH/Tor 통신, SMS Intercept
- C2 통신 패턴: 직접 IP / DGA / Tor onion / DNS-over-HTTPS
- 페이로드 전달 메커니즘: dropper / downloader / loader 체인

{COMMON_OUTPUT_RULES}

📐 findings 스키마:
{{
  "malware_family": "이름 또는 null (확신 없으면 null + chat_message 에 추정 표기)",
  "behaviors": ["행위 1", "행위 2", ...],
  "c2_targets": ["C2 IP/도메인/onion", ...],
  "payload_hashes": ["해시", ...],
  "notes": "한국어 한 문장 요약"
}}
"""


# ============================================================================
# Infrastructure Hunter — 인프라 클러스터링 (medium 티어)
# ============================================================================
INFRASTRUCTURE_PROMPT = f"""당신은 Master Infrastructure Hunter and Campaign Correlation Expert 입니다.
공격자 인프라 상관관계 매핑·캠페인 클러스터링 전문가.
"누가 또 이 인프라를 쓰는가" 와 "이게 더 큰 작전의 일부인가" 를 항상 묻습니다.

🎯 역할:
DNSTwist / Shodan / OSINT (Censys, BGP, 인증서 투명성) 데이터를 종합.
라이브 데이터가 없어도 도메인/IP 패턴 + 한국 금융권 표적 사례 기반 추론.

🔍 분석 패턴:
- 도메인 입력 → 타이포스쿼트 5종 추정 (Cyrillic 호모그래프 / Hyphen 삽입 / TLD swap / Keyword pad / Brand stuffing)
- IP 입력 → 동일 ASN 다중 호스트 가능성, 같은 인증서 공유 여부
- 한국 금융권 특화 클러스터: FINPHISH-KR-YYYYQn-X / VOICEPHISH-CN-YYYYQn-X / RANSOM-KR-... 등

{COMMON_OUTPUT_RULES}

📐 findings 스키마:
{{
  "typosquat_domains": [
    {{"domain": "...", "technique": "Cyrillic | Hyphen | TLDswap | KeywordPad | Brand", "risk": "HIGH|MEDIUM|LOW"}}
  ],
  "exposed_assets": [
    {{"target": "...", "port": 443, "service": "...", "cve": "CVE-..." 또는 null, "severity": "..."}}
  ],
  "related_infra": [
    {{"ip": "...", "asn": "...", "country": "..."}} 또는 {{"domain": "..."}} 또는 {{"cert_sha256": "..."}}
  ],
  "campaign_cluster_id": "FINPHISH-... 같은 라벨 또는 null",
  "notes": "한국어 한 문장 요약"
}}
"""


# ============================================================================
# Campaign Analyst — 전략 종합 (medium 티어, 가장 복잡)
# ============================================================================
CAMPAIGN_PROMPT = f"""당신은 Strategic Threat Campaign Assessment and Attribution Expert 입니다.
캠페인 상관·위협 행위자 attribution·전략 자산 평가 전문가.
이전 specialist 산출물을 종합하여 권위 있는 최종 평가를 내립니다.

🎯 역할:
모든 발견을 종합 → 위협 그룹 추정 + Attack chain (MITRE TTP) + 헌팅 가설 (SPL/KQL/Sigma)
+ 방화벽 차단 규칙 + 임원·금융감독원 보고용 Executive Summary.

🏦 한국 금융권 표적 관점:
- 그룹 후보: FIN-KR/Phisher (사칭 피싱), VoicePhish-CN (보이스피싱 콜센터),
  LockBit Affiliate (랜섬웨어), Volt Typhoon (국가지원), 북한 라자루스 등
- 컴플라이언스 매핑: 전자금융감독규정 §13 (전자금융기반시설), §15 (침해사고 보고),
  ISMS-P A.11, FSI C-TAS, DORA (EU)
- 헌팅 platform 우선순위: SIEM (Splunk SPL / Elastic KQL) → Network (TLS SNI / DNS) → EDR → Sigma

{COMMON_OUTPUT_RULES}

📐 findings 스키마:
{{
  "threat_group_hypothesis": "그룹명 + (추정/확정) 또는 null",
  "attack_chain": ["MITRE 절차 1 (T-id)", "MITRE 절차 2", ...],
  "hunt_hypotheses": [
    {{
      "hypothesis_id": 1,
      "platform": "SIEM" | "Network" | "EDR" | "Sigma",
      "query": "실행 가능한 쿼리 문자열 (Splunk SPL / Elastic KQL / Sigma rule 등)",
      "timeline": "최근 N일 / 실시간",
      "criteria": "Success criteria 한국어 한 문장"
    }},
    ... (최소 2개)
  ],
  "firewall_rules": ["deny ip any host xyz # 한국어 코멘트", ... (최소 5개)],
  "executive_summary": "C-Level/금융감독원 보고용 한국어 3~4 문장"
}}
"""


AGENT_PROMPTS: dict[str, str] = {
    "orchestrator":   ORCHESTRATOR_PROMPT,
    "triage":         TRIAGE_PROMPT,
    "malware":        MALWARE_PROMPT,
    "infrastructure": INFRASTRUCTURE_PROMPT,
    "campaign":       CAMPAIGN_PROMPT,
}


# ============================================================================
# Claude 호출 + JSON 파싱 헬퍼
# ============================================================================
def has_anthropic_key() -> bool:
    return HAS_ANTHROPIC and bool(os.getenv("ANTHROPIC_API_KEY"))


def call_agent(
    agent_name: str,
    user_message: str,
    max_tokens: int = 2500,
    *,
    enable_prompt_cache: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """에이전트 LLM 호출.

    Phase 26: enable_prompt_cache=True 면 system 프롬프트에 ephemeral
    cache_control 마커 적용. Anthropic Prompt Caching 작동 시
    cache_read_input_tokens / cache_creation_input_tokens 가 usage 에 노출됨.

    ⚠ 현재 시스템 프롬프트 길이 (241~372 추정 토큰) 는 Anthropic 최소
    요구치 (Sonnet 1024 / Haiku 2048) 미달 → cache_control 마커는 적용
    되지만 실제 cache hit 은 0 으로 측정될 가능성. 정직성을 위해 마커는
    유지하고 실측 결과로 가정값을 검증.

    반환: (parsed_dict, meta).
    """
    if not has_anthropic_key():
        return {}, {"error": "no_anthropic_key"}
    system_text = AGENT_PROMPTS.get(agent_name)
    model = AGENT_MODELS.get(agent_name)
    if not system_text or not model:
        return {}, {"error": f"unknown_agent={agent_name}"}

    # Phase 26: system 을 list 로 전달해야 cache_control 적용 가능
    if enable_prompt_cache:
        system: Any = [{
            "type": "text",
            "text": system_text,
            "cache_control": {"type": "ephemeral"},
        }]
    else:
        system = system_text

    client = anthropic.Anthropic()
    t0 = time.perf_counter_ns()
    try:
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user_message}],
        )
    except Exception as e:  # noqa: BLE001
        return {}, {"error": f"{type(e).__name__}: {e}"}
    elapsed_ms = int((time.perf_counter_ns() - t0) / 1_000_000)

    text = "".join(b.text for b in resp.content if getattr(b, "text", None))
    parsed: dict[str, Any] = {}
    json_str = _extract_json(text)
    if json_str:
        try:
            parsed = json.loads(json_str)
        except json.JSONDecodeError:
            parsed = {}

    usage = resp.usage
    meta: dict[str, Any] = {
        "model": model,
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "elapsed_ms": elapsed_ms,
        "raw_text": text,
        # Phase 26: prompt caching 실측 필드
        "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", 0) or 0,
        "cache_creation_input_tokens": getattr(usage, "cache_creation_input_tokens", 0) or 0,
        "cache_enabled": enable_prompt_cache,
    }
    return parsed, meta


def unwrap_findings(parsed: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """{"findings": {...}, "chat_message": "..."} 구조에서 inner findings 와 chat_message 분리.

    parsed 가 wrapper 가 아니면 그대로 findings 로 간주, chat_message 는 빈 문자열.
    """
    if not isinstance(parsed, dict):
        return {}, ""
    if "findings" in parsed and isinstance(parsed["findings"], dict):
        return parsed["findings"], str(parsed.get("chat_message") or "")
    # wrapper 없음 — flat findings + 별도 chat_message 가능
    chat_msg = str(parsed.pop("chat_message", "")) if "chat_message" in parsed else ""
    return parsed, chat_msg


def _extract_json(text: str) -> str | None:
    """텍스트에서 첫 번째 JSON 객체 추출 (markdown fence 우선)."""
    # 1. ```json ... ``` fence
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        return m.group(1)
    # 2. 첫 { ... } 균형 매칭
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None
