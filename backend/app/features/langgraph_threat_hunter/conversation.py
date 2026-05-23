"""대화형 SOC 어시스턴트 — Anthropic Claude 직접 호출.

`/api/lg/chat/dialogue` 엔드포인트가 이 모듈을 사용한다.
- IoC 패턴 입력 시: 기존 LangGraph 분석 흐름으로 위임
- 자유 텍스트 시: Claude 가 보안 분석가 페르소나로 멀티턴 대화

ANTHROPIC_API_KEY 환경변수 필요. 없으면 fallback 메시지 반환.
"""
from __future__ import annotations

import os
from typing import AsyncIterator

try:
    import anthropic  # type: ignore
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


# ---- 보안 분석가 페르소나 시스템 프롬프트 ----
SECURITY_ANALYST_SYSTEM = """당신은 한국 금융권 SOC 의 시니어 보안 분석가입니다.

사용자는 SOC 운영자, 보안 담당자, 또는 보안 의사결정자입니다.
침해사고·위협 인텔리전스·대응방안·컴플라이언스에 대해 한국어로 명확하고
실행 가능한 답변을 제공합니다.

도움을 줄 수 있는 영역:
- 침해사고 대응 절차 (IR 플레이북)
- 한국 컴플라이언스 (전자금융감독규정 §13/§15, ISMS-P, FSI C-TAS, 개인정보보호법)
- 위협 인텔리전스 분석 / 위협 그룹 추정
- 보안 솔루션 / 아키텍처 조언 (Zero Trust, 망분리 등)
- 사고 후 복구 · 고객 통지 · 금융감독원 보고 절차
- 랜섬웨어·보이스피싱·피싱·공급망·CVE 우선순위 대응
- MITRE ATT&CK / Sigma · YARA 룰 / SPL · KQL 헌팅 쿼리

응답 스타일:
- 너무 길지 않게 — 핵심만 명확하게
- 가능하면 번호 매긴 단계 (1, 2, 3) 또는 우선순위
- 마지막에 후속 질문 1개 또는 다음 액션 제안

⚠️ IoC (도메인/IP/해시/CVE/URL) 가 포함된 분석 요청은 별도 LangGraph 멀티에이전트
파이프라인이 자동 처리합니다. 사용자가 IoC 자체를 입력하면 우측 Agent Studio 에
실시간 분석 진행이 표시됩니다. 본 대화 응답은 IoC 가 없는 자유 질문 / 사고 대응
의논 / 정책·아키텍처 자문에 집중하세요.

도구 안내가 필요할 때만:
- "좌측 자료실의 S1~S5 카드 또는 IoC 를 직접 입력하시면 LangGraph 가 분석합니다"
"""


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
    max_tokens: int = 1200,
) -> AsyncIterator[str]:
    """Claude 응답을 chunk 단위 yield.

    history: [{"role": "user"|"assistant", "content": "..."}]
    """
    if not has_anthropic_key():
        yield _fallback_response(message)
        return

    client = anthropic.Anthropic()

    # 히스토리 정합화: user/assistant 가 strict 하게 alternate 해야 함.
    # 연속된 assistant 메시지는 하나로 합침, role 누락은 제거.
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
    # 마지막 사용자 메시지 추가
    if not msgs or msgs[-1]["role"] != "user":
        msgs.append({"role": "user", "content": message})
    else:
        # 직전이 user 이면 합치지 말고 별도 turn (드물지만)
        msgs[-1]["content"] += "\n\n" + message

    try:
        with client.messages.stream(
            model=model,
            max_tokens=max_tokens,
            system=SECURITY_ANALYST_SYSTEM,
            messages=msgs,
        ) as stream:
            for chunk in stream.text_stream:
                yield chunk
    except Exception as e:  # noqa: BLE001
        yield f"\n\n(⚠️ Claude 호출 실패: {type(e).__name__}: {e})"
