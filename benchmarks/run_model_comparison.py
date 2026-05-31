#!/usr/bin/env python3
"""Anthropic API 실측 벤치마크 — 에이전트별 모델 티어 토큰/비용 비교.

각 에이전트 역할 (Triage/Malware/Infrastructure/Campaign/Orchestrator) 을
3개 모델 (Haiku 4.5, Sonnet 4.6, Opus 4.7) 로 실제 호출하여
input/output 토큰 사용량·지연시간·비용을 실측한다.

- 예산: 기본 $7 (만원 한도). 80% 도달 시 자동 중단.
- 출력: backend/benchmarks/results.json (gitignore 처리됨)
- API 키: ANTHROPIC_API_KEY 환경변수 (코드에 하드코딩 없음)

사용:
  ANTHROPIC_API_KEY=sk-ant-... python3 benchmarks/run_model_comparison.py
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

try:
    import anthropic
except ImportError:
    print("anthropic SDK 미설치: pip install anthropic", file=sys.stderr)
    sys.exit(1)

# ============================================================================
# 설정
# ============================================================================
BUDGET_USD = float(os.getenv("BENCHMARK_BUDGET_USD", "7.0"))
OUTPUT_PATH = Path(__file__).parent / "results.json"

# 모델 ID + 가격표 (per 1M tokens, 2026 기준)
MODELS = {
    "haiku":  ("claude-haiku-4-5-20251001",  0.25, 1.25),
    "sonnet": ("claude-sonnet-4-6",           3.0,  15.0),
    "opus":   ("claude-opus-4-7",             15.0, 75.0),
}

# ============================================================================
# 에이전트별 실측용 프롬프트 (S1 카카오뱅크 시나리오 기반)
# ============================================================================
COMMON_SYSTEM_PREFIX = (
    "당신은 금융권 SOC 의 멀티에이전트 시스템에 속한 전문가 에이전트입니다. "
    "한국어로 답변하고, 구조화된 JSON 출력 + 한 단락 자연어 브리핑을 함께 제공하세요. "
    "응답은 간결하게 — 핵심만."
)

AGENT_PROMPTS = {
    "orchestrator": {
        "max_tokens": 200,
        "system": COMMON_SYSTEM_PREFIX + (
            " 역할: Investigation Orchestrator. 사용자가 제공한 IoC 의 타입을 보고 "
            "어떤 Specialist (triage / malware / infrastructure / campaign) 를 어떤 "
            "순서로 호출할지 route_plan 만 결정합니다."
        ),
        "user": (
            "IoC: kakaobank-secure-login.com (타입: domain)\n"
            "필요한 specialist 들의 호출 순서를 JSON 으로: "
            '{"route_plan": [...], "rationale": "한 줄 이유"}'
        ),
    },
    "triage": {
        "max_tokens": 700,
        "system": COMMON_SYSTEM_PREFIX + (
            " 역할: Triage Specialist. VirusTotal 평판 데이터를 보고 위협 수준 "
            "(LOW/MEDIUM/HIGH/CRITICAL), 탐지 비율, MITRE ATT&CK 전술을 평가합니다."
        ),
        "user": """다음 도메인의 VirusTotal 결과입니다:

domain: kakaobank-secure-login.com
analysis_stats: {"malicious": 28, "suspicious": 4, "harmless": 51, "undetected": 10}
categories: {"Forcepoint": "Suspicious", "alphaMountain.ai": "Phishing"}
creation_date: 2026-05-22 (등록 1일 차)
resolves_to: 185.x.x.x (AS199524 - 알려진 피싱 호스팅 ASN)

JSON 으로 threat_level, detection_ratio, mitre_tactics, priority_pivots 를 산출하고
chat_message 에 분석가용 한 단락 자연어 브리핑을 작성하세요.""",
    },
    "malware": {
        "max_tokens": 1500,
        "system": COMMON_SYSTEM_PREFIX + (
            " 역할: Malware Specialist. 악성코드의 행위·C2 통신·페이로드 전달 메커니즘을 "
            "분석하여 Attack chain 을 재구성합니다."
        ),
        "user": """다음은 의심 악성코드의 분석 데이터입니다:

file_hash: 44d88612fea8a8f36de82e1278abb02f
vt_detection: 63/93 malicious
ransomware_indicators:
  - vssadmin delete shadows /all /quiet (호출됨)
  - 백업 폴더 우선 암호화
  - Active Directory 자격증명 수집
  - PsExec 측면 이동
c2_targets:
  - lockbit-pay4.onion (Tor)
  - 194.x.x.21 (RU staging)
ransom_note_language: Korean
target_industry: 금융권 (한국)

JSON 으로 malware_family, behaviors, c2_targets, payload_hashes 를 산출하고
chat_message 에 분석가용 한 단락 자연어 브리핑을 작성하세요.""",
    },
    "infrastructure": {
        "max_tokens": 1500,
        "system": COMMON_SYSTEM_PREFIX + (
            " 역할: Infrastructure Hunter. 공격자 인프라 간 상관관계를 매핑하고 "
            "캠페인 클러스터를 식별합니다. DNSTwist + Shodan + URLScan 결과를 종합."
        ),
        "user": """다음은 카카오뱅크 사칭 의심 도메인의 멀티 MCP 결과입니다:

DNSTwist 결과 (타이포스쿼트 변종):
  - kakaobаnk.com  (Cyrillic 'а', 등록: 2026-05-19)
  - kakao-bank.net (Hyphen Insertion, 등록: 2026-05-20)
  - kakaobank-secure.com (Subdomain Pad, 2026-05-21)
  - kakaobank-login.com (Keyword Pad, 2026-05-22)
  - kakaobank-help.kr (TLD Swap, 2026-05-22)

Shodan: 모두 ASN AS199524 (피싱 호스팅, RU)
URLScan: 모두 동일 Let's Encrypt 인증서 (*.kakaobank-secure-login.com)
BGP: 동일 prefix 185.x.x.0/24

JSON 으로 typosquat_domains, related_infra, campaign_cluster_id 를 산출하고
chat_message 에 분석가용 한 단락 자연어 브리핑을 작성하세요.""",
    },
    "campaign": {
        "max_tokens": 2500,
        "system": COMMON_SYSTEM_PREFIX + (
            " 역할: Campaign Analyst. 모든 발견을 종합하여 위협 그룹을 추정하고, "
            "Attack chain · 헌팅 가설 (SPL/KQL) · 방화벽 차단 규칙 · 임원 보고용 요약을 작성합니다."
        ),
        "user": """모든 specialist 의 산출물 종합:

Triage:
  threat_level: HIGH, detection 28/93
  MITRE: Initial Access (TA0001), Resource Development (TA0042)
  priority: 도메인 ≤24h 등록 + 피싱 ASN

Infrastructure:
  5개 타이포스쿼트 도메인 클러스터 FINPHISH-KR-2026Q2-A
  공통 ASN AS199524 / RU 호스팅
  Let's Encrypt 와일드카드 인증서 공유

이를 바탕으로:
1) JSON 으로 threat_group_hypothesis, attack_chain (list), hunt_hypotheses (2건, platform=SIEM/Network, executable query 포함), firewall_rules (5건 이상)
2) executive_summary 에 C-Level/금감원 보고용 3문장 요약
3) chat_message 에 분석가용 한 단락 자연어 브리핑

모두 한국어로.""",
    },
}

# ============================================================================
# 실행
# ============================================================================
def main() -> int:
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("❌ ANTHROPIC_API_KEY 환경변수 필요", file=sys.stderr)
        return 1

    client = anthropic.Anthropic()
    results: list[dict] = []
    cost_so_far = 0.0
    aborted = False

    agents = list(AGENT_PROMPTS.keys())
    tiers = list(MODELS.keys())

    print(f"🧪 Anthropic 벤치마크 시작 — 예산: ${BUDGET_USD}")
    print(f"   에이전트 {len(agents)} × 모델 {len(tiers)} = {len(agents) * len(tiers)} 호출 예정\n")

    for agent in agents:
        for tier in tiers:
            if cost_so_far > BUDGET_USD * 0.85:
                print(f"\n⚠️  예산 85% 초과 (${cost_so_far:.3f} / ${BUDGET_USD}). 중단.")
                aborted = True
                break

            model_id, in_price, out_price = MODELS[tier]
            spec = AGENT_PROMPTS[agent]

            t0 = time.perf_counter()
            try:
                resp = client.messages.create(
                    model=model_id,
                    max_tokens=spec["max_tokens"],
                    system=spec["system"],
                    messages=[{"role": "user", "content": spec["user"]}],
                )
            except Exception as e:
                print(f"  ❌ {agent} @ {tier}: {type(e).__name__}: {e}")
                results.append({"agent": agent, "tier": tier, "model": model_id, "error": str(e)})
                continue

            elapsed = time.perf_counter() - t0
            in_t = resp.usage.input_tokens
            out_t = resp.usage.output_tokens
            cost = (in_t * in_price + out_t * out_price) / 1_000_000
            cost_so_far += cost

            response_text = "".join(
                b.text for b in resp.content if getattr(b, "text", None)
            )

            results.append({
                "agent": agent,
                "tier": tier,
                "model": model_id,
                "input_tokens": in_t,
                "output_tokens": out_t,
                "elapsed_seconds": round(elapsed, 2),
                "cost_usd": round(cost, 6),
                "response_excerpt": response_text[:250],
                "response_length_chars": len(response_text),
            })
            print(
                f"  ✅ {agent:>14s} @ {tier:>6s}: "
                f"in={in_t:>5d}  out={out_t:>5d}  "
                f"{elapsed:>5.2f}s  ${cost:.5f}"
            )
        if aborted:
            break

    print(f"\n💰 총 비용: ${cost_so_far:.4f} / ${BUDGET_USD} (예산 사용률 {cost_so_far/BUDGET_USD*100:.1f}%)")
    print(f"📊 결과 저장: {OUTPUT_PATH}")

    # 비교 표 계산 — All-Opus baseline vs Mixed (권장)
    by_pair = {(r["agent"], r["tier"]): r for r in results if "input_tokens" in r}
    recommended_tier = {
        "orchestrator": "haiku",
        "triage": "haiku",
        "malware": "sonnet",
        "infrastructure": "sonnet",
        "campaign": "sonnet",
    }
    all_opus_cost = sum(by_pair[(a, "opus")]["cost_usd"] for a in agents if (a, "opus") in by_pair)
    mixed_cost = sum(by_pair[(a, recommended_tier[a])]["cost_usd"] for a in agents if (a, recommended_tier[a]) in by_pair)

    print(f"\n📈 실측 비교:")
    print(f"   All-Opus  : ${all_opus_cost:.5f} / IoC")
    print(f"   Mixed 권장 : ${mixed_cost:.5f} / IoC  ({(1-mixed_cost/all_opus_cost)*100 if all_opus_cost else 0:.1f}% 절감)")

    summary = {
        "budget_usd": BUDGET_USD,
        "total_cost_spent_usd": round(cost_so_far, 4),
        "aborted": aborted,
        "measurements": results,
        "summary": {
            "all_opus_cost_per_ioc_usd": round(all_opus_cost, 5),
            "mixed_recommended_cost_per_ioc_usd": round(mixed_cost, 5),
            "savings_pct": round((1 - mixed_cost / all_opus_cost) * 100, 1) if all_opus_cost else 0,
        },
    }
    OUTPUT_PATH.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
