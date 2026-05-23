"""대화형 SOC 어시스턴트 — Anthropic Claude 직접 호출 + Tool Use 멀티에이전트.

`/api/lg/chat/dialogue` 엔드포인트가 이 모듈을 사용한다.
- IoC 패턴 입력 시: LangGraph 6-Agent 분석 (router.py 에서 분기)
- 자유 텍스트 시: Claude 가 진행자 역할 → 필요하면 specialist tool 호출
  · consult_triage / consult_malware / consult_infrastructure / consult_campaign
  · 일반 질문 (정책·절차) 은 tool 없이 직접 답변

ANTHROPIC_API_KEY 환경변수 필요. 없으면 fallback 메시지 반환.
"""
from __future__ import annotations

import json
import os
from typing import AsyncIterator

try:
    import anthropic  # type: ignore
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

from .agent_prompts import call_agent


# ---- 보안 분석가 페르소나 시스템 프롬프트 ----
SECURITY_ANALYST_SYSTEM = """당신은 한국 금융권 SOC 의 시니어 보안 분석가이자 멀티에이전트 시스템의 진행자입니다.

사용자(SOC 운영자/의사결정자)와 대화하면서, IoC 값이 확보되면 LangGraph 6-Agent
멀티에이전트 분석으로 자동 전환됩니다. 그 전 단계에서는 **사용자가 IoC 를 찾을 수
있도록 능동적으로 안내**하는 게 핵심 역할.

## 🎯 핵심 행동 원칙

### 1) 상황만 듣고 IoC 없을 때 — IoC 추출 가이드
사용자가 "회사에 의심 트래픽이 있어요" / "직원 PC 가 이상해요" 같은 **상황 설명만**
했다면, 즉시 답하지 말고 **어디서 IoC 를 찾을 수 있는지** 구체적으로 안내:

- **방화벽/프록시 로그**: 차단된 outbound 도메인·IP, 비정상 포트
- **EDR/AV 콘솔**: 격리된 파일 해시, 의심 프로세스
- **SIEM/IDS**: 시그니처 매치 시점, src/dst IP
- **DNS 쿼리 로그**: 신규/짧은 수명 도메인
- **메일 게이트웨이**: 의심 발신자, 첨부 해시
- **사용자가 캡처한 URL/스크린샷**

예시 응답:
> "랜섬웨어 의심 상황이네요. 우선 다음을 확인 부탁드립니다:
>  1. **EDR 콘솔** — 격리된 파일 해시 (MD5/SHA256)
>  2. **방화벽 outbound 로그** — 30분 이내 차단된 도메인/IP
>  3. **vssadmin/PsExec** 같은 LotL 도구가 잡힌 호스트 이름
>  이 중 하나라도 확보하시면 그대로 입력해주세요 → 자동으로 6-Agent 분석이 시작됩니다."

### 2) IoC 가 메시지에 포함되어 들어오면 — 자동 분석 모드
`update-microsoft-soft.net`, `203.0.113.42`, `44d88612fea...`, `CVE-2024-21762` 같은 패턴이
사용자 메시지에 들어 있으면 시스템이 자동으로 LangGraph 6-Agent 분석을 트리거합니다.
당신은 그 결과를 받지 않으니, 사용자에게 "분석 시작합니다" 안내 정도만.

### 3) 일반 IR 절차·정책 질문은 직접 답변
- 격리·증거보존·법적 보고 절차
- Windows/Linux/PowerShell 명령어 (netsh, vssadmin, Get-WinEvent 등)
- 전자금융감독규정 §13/§15, ISMS-P, 개인정보보호법 매핑
- 보안 아키텍처 (Zero Trust, 망분리, EDR 도입)

### 4) 도구 호출 (Tool Use) 가이드 — 깊은 전문 자문이 필요할 때
- 악성코드 행위·랜섬웨어 변종 정밀 → `consult_malware`
- 사칭 도메인·인프라 클러스터링·노출자산 → `consult_infrastructure`
- 위협 그룹 attribution·헌팅 쿼리·FW 룰 → `consult_campaign`
- 알려지지 않은 IoC 의 초기 평가 → `consult_triage`

도구 결과는 사용자에게 자연어로 종합 — raw JSON 노출 금지.

## 응답 스타일
- 한국어, 핵심 명확, 너무 길지 않게
- 번호 단계 또는 우선순위
- 마지막에 후속 질문 1개 또는 다음 액션 제안
- 사용자가 IoC 를 못 찾으면 **다른 후보 (다른 로그/소스)** 를 제안하여 분석 가능성 유지
"""


# ---- Specialist tool 정의 (Anthropic Tool Use spec) ----
SPECIALIST_TOOLS = [
    {
        "name": "consult_triage",
        "description": "초기 위협 평가가 필요할 때 Triage Specialist (Haiku 4.5) 에이전트에 자문 요청. "
                       "위협 수준(LOW~CRITICAL), 우선순위 단서, MITRE ATT&CK 전술 매핑을 받습니다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "Triage 에이전트에게 물어볼 구체적 질문 (한국어). 예: '익명 Tor 노드 IP 의 초기 위협 평가'"
                }
            },
            "required": ["question"],
        },
    },
    {
        "name": "consult_malware",
        "description": "악성코드 행위·C2 통신·페이로드 분석이 필요할 때 Malware Specialist (Sonnet) 자문. "
                       "Attack chain, MITRE TTP, malware family 추정을 받습니다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "Malware 에이전트에게 물어볼 구체적 질문. 예: 'LockBit 4.0 변종의 VSS 무력화 행위'"
                }
            },
            "required": ["question"],
        },
    },
    {
        "name": "consult_infrastructure",
        "description": "공격자 인프라·사칭 도메인·캠페인 클러스터링이 필요할 때 Infrastructure Hunter (Sonnet) 자문. "
                       "타이포스쿼트 후보, 노출 자산, 인프라 상관관계를 받습니다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "Infrastructure 에이전트 질문. 예: '카카오뱅크 사칭 인프라 클러스터 패턴'"
                }
            },
            "required": ["question"],
        },
    },
    {
        "name": "consult_campaign",
        "description": "위협 그룹 attribution·캠페인 종합·헌팅 쿼리·FW 규칙 작성이 필요할 때 "
                       "Campaign Analyst (Sonnet) 자문. 전략 인텔리전스를 받습니다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "Campaign 에이전트 질문. 예: '한국 금융권 랜섬웨어 헌팅 쿼리 작성'"
                }
            },
            "required": ["question"],
        },
    },
]


# ---- Tool 이름 → agent_prompts 의 에이전트 이름 매핑 ----
TOOL_AGENT_MAP = {
    "consult_triage": "triage",
    "consult_malware": "malware",
    "consult_infrastructure": "infrastructure",
    "consult_campaign": "campaign",
}


def has_anthropic_key() -> bool:
    return HAS_ANTHROPIC and bool(os.getenv("ANTHROPIC_API_KEY"))


def _fallback_response(message: str) -> str:
    """API 키 없을 때 placeholder."""
    return (
        f"(⚠️ ANTHROPIC_API_KEY 미설정 상태 — 자유 대화는 제한됩니다.)\n\n"
        f"입력하신 메시지: \"{message[:80]}{'…' if len(message) > 80 else ''}\"\n\n"
        f"운영 환경에서는 Claude Sonnet 4.6 으로 한국 금융권 SOC 보안 분석가가 "
        f"답변하며, 침해사고 대응·컴플라이언스·헌팅 전략 의논이 가능합니다.\n\n"
        f"지금은 좌측 자료실의 샘플 시나리오 (S1~S5) 또는 IoC (도메인/IP/해시/CVE) "
        f"입력으로 LangGraph 멀티에이전트 분석은 정상 동작합니다."
    )


async def stream_claude_response(
    message: str,
    history: list[dict],
    *,
    model: str = "claude-sonnet-4-5",
    max_tokens: int = 1500,
) -> AsyncIterator[dict]:
    """Claude 응답을 이벤트 dict 단위 yield (Tool Use 멀티에이전트 지원).

    yield 이벤트:
    - {"kind": "text", "delta": "..."}         — Claude 텍스트 chunk
    - {"kind": "tool_use", "tool": "consult_malware", "question": "..."} — 자문 요청
    - {"kind": "tool_result", "tool": "consult_malware", "summary": "..."} — 자문 응답
    """
    if not has_anthropic_key():
        yield {"kind": "text", "delta": _fallback_response(message)}
        return

    client = anthropic.Anthropic()

    # 히스토리 정합화
    msgs: list[dict] = []
    last_role = None
    for m in history:
        role = m.get("role")
        content = (m.get("content") or "").strip()
        if not content or role not in ("user", "assistant"):
            continue
        if role == last_role and msgs:
            msgs[-1]["content"] += "\n\n" + content
        else:
            msgs.append({"role": role, "content": content})
            last_role = role
    if not msgs or msgs[-1]["role"] != "user":
        msgs.append({"role": "user", "content": message})
    else:
        msgs[-1]["content"] += "\n\n" + message

    # Tool Use 루프 (최대 3회 — 무한 도구 호출 방지)
    max_tool_rounds = 3
    for round_idx in range(max_tool_rounds + 1):
        try:
            with client.messages.stream(
                model=model,
                max_tokens=max_tokens,
                system=SECURITY_ANALYST_SYSTEM,
                tools=SPECIALIST_TOOLS,
                messages=msgs,
            ) as stream:
                for chunk in stream.text_stream:
                    yield {"kind": "text", "delta": chunk}
                final = stream.get_final_message()
        except Exception as e:  # noqa: BLE001
            yield {"kind": "text", "delta": f"\n\n(⚠️ Claude 호출 실패: {type(e).__name__}: {e})"}
            return

        if final.stop_reason != "tool_use" or round_idx == max_tool_rounds:
            return  # 텍스트로 끝남

        # tool_use 블록들 수집 + specialist 자문 실행
        tool_uses = [c for c in final.content if getattr(c, "type", None) == "tool_use"]
        tool_results: list[dict] = []
        for tu in tool_uses:
            tool_name = tu.name
            tool_input = tu.input or {}
            question = tool_input.get("question") or "분석 요청"
            yield {"kind": "tool_use", "tool": tool_name, "question": question}

            agent_name = TOOL_AGENT_MAP.get(tool_name)
            if not agent_name:
                tool_results.append({
                    "type": "tool_result", "tool_use_id": tu.id,
                    "content": json.dumps({"error": f"unknown tool {tool_name}"}, ensure_ascii=False),
                })
                continue

            parsed, meta = call_agent(agent_name, question, max_tokens=1500)
            findings = parsed.get("findings", parsed) if isinstance(parsed, dict) else {}
            chat_msg = parsed.get("chat_message", "") if isinstance(parsed, dict) else ""
            result_payload = {"findings": findings, "chat_message": chat_msg}
            yield {
                "kind": "tool_result",
                "tool": tool_name,
                "summary": chat_msg or "(no chat_message)",
                "elapsed_ms": meta.get("elapsed_ms"),
                "model": meta.get("model"),
            }
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tu.id,
                "content": json.dumps(result_payload, ensure_ascii=False),
            })

        # 다음 round 위한 메시지 누적
        msgs.append({"role": "assistant", "content": final.content})
        msgs.append({"role": "user", "content": tool_results})
