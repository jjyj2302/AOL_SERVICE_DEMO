"""에이전트별 모델 매핑 + 토큰/비용 분석 (Phase 26: 실측 기반 재구성).

각 에이전트의 작업 복잡도가 다르므로 동일 모델(Opus 등)을 모든 에이전트에
적용하는 것은 낭비. 이 모듈은:

1. 에이전트별 권장 모델 티어 (mini / medium / strong) 정의
2. 모델 가격표 (Anthropic / OpenAI 2026년 기준, per 1M tokens)
3. 에이전트별 토큰 사용량 — Phase 26 실측 (benchmarks/caching_measurement.json)
4. 6가지 전략 비용 비교:
   - all_opus            : 모든 에이전트 Opus (naive — 실무에선 안 함)
   - all_sonnet          : 모든 에이전트 Sonnet (현실적 디폴트, 단일 모델 운영)
   - all_haiku           : 모든 에이전트 Haiku (저비용 하한, 품질 trade-off)
   - mixed               : 복잡도별 모델 분배 (본 시스템 채택, caching/batch X)
   - mixed_batch         : Mixed + Batch API 50% off (비실시간 가능, 실현)
   - mixed_cached_batch  : Mixed + Prompt Caching 90% + Batch (★ 옛 헤드라인)
                          ⚠ Phase 26 실측: 현재 system 프롬프트 (967~1491 chars)
                          가 Anthropic minimum cache tokens (Sonnet 1024 /
                          Haiku 2048) 미달로 cache hit 0%. 90% 가정은
                          "프롬프트를 1024+ tokens 로 확장 시" 시나리오.

savings_pct 는 두 baseline 모두에 대해 계산:
  - savings_vs_realistic_pct : all_sonnet 대비 (실무 비교 시 사용 — 정직)
  - savings_vs_naive_pct     : all_opus 대비 (마케팅 헤드라인이었던 91.8% 기준)

★ 정직한 헤드라인 (caching 가정 제거, 실현 가능):
  mixed         vs Sonnet -18%  (모델 매핑만)
  mixed_batch   vs Sonnet -59%  (모델 매핑 + Batch API)
  mixed_cached  vs Sonnet -91%  (모델 매핑 + Batch + Caching 가정 — 옛 헤드라인)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ModelTier = Literal["mini", "medium", "strong"]


# ============================================================================
# 1. 가격표 (per 1M tokens, 2026 기준)
# ============================================================================
@dataclass(frozen=True)
class ModelPricing:
    name: str
    tier: ModelTier
    input_per_1m: float    # USD per 1M input tokens
    output_per_1m: float   # USD per 1M output tokens
    cached_input_per_1m: float | None = None  # Anthropic Prompt Caching 가격


MODELS: dict[str, ModelPricing] = {
    # Anthropic Claude
    "claude-opus-4": ModelPricing("Claude Opus 4", "strong", 15.0, 75.0, 1.50),
    "claude-sonnet-4-6": ModelPricing("Claude Sonnet 4.6", "medium", 3.0, 15.0, 0.30),
    "claude-haiku-4-5": ModelPricing("Claude Haiku 4.5", "mini", 0.25, 1.25, 0.025),
    # OpenAI
    "gpt-4o": ModelPricing("GPT-4o", "strong", 5.0, 20.0, None),
    "gpt-4o-mini": ModelPricing("GPT-4o mini", "mini", 0.15, 0.60, None),
}


# ============================================================================
# 2. 에이전트별 권장 모델 티어
# ============================================================================
@dataclass(frozen=True)
class AgentProfile:
    """에이전트의 작업 복잡도와 예상 토큰 사용량."""
    node_id: str
    label: str
    recommended_tier: ModelTier
    rationale: str
    # 평균 토큰 (실측 시 갱신)
    input_tokens: int
    output_tokens: int
    uses_llm: bool = True


# Phase 26 실측 평균 (benchmarks/caching_measurement.json, 2026-05-24).
# 측정 환경: 각 agent 별 동일 user_message × 3 회 호출, max_tokens=2500.
# input_tokens = system 프롬프트 + user_message 합산 (Anthropic API 측정값).
# output_tokens = 실 응답 토큰 (campaign 만 max_tokens=2500 한도 도달).
#
# 옛 추정값 (system 미포함, user 만) 대비 +75~150% 증가:
#   orchestrator 250 → 627  (+150%)
#   triage       400 → 831  (+108%)
#   malware      440 → 775  (+76%)
#   infrastructure 540 → 944 (+75%)
#   campaign     500 → 1023 (+105%)
AGENTS: list[AgentProfile] = [
    AgentProfile(
        node_id="orchestrator",
        label="🧠 Orchestrator",
        recommended_tier="mini",
        rationale="IoC 타입 보고 route_plan 만 결정 — 라우팅만 필요",
        input_tokens=627,    # Phase 26 실측 (system 967 chars + user)
        output_tokens=377,   # 실측 평균 (max_tokens 미도달)
    ),
    AgentProfile(
        node_id="triage_step",
        label="🔍 Triage",
        recommended_tier="mini",
        rationale="VT JSON 해석 + 위협 수준 분류 — 구조화 데이터 매핑 수준",
        input_tokens=831,    # Phase 26 실측 (system 1022 chars + user)
        output_tokens=473,   # 실측 평균
    ),
    AgentProfile(
        node_id="malware_step",
        label="👾 Malware",
        recommended_tier="medium",
        rationale="악성코드 행위 분석 + Attack chain 재구성 — 추론 필요",
        input_tokens=775,    # Phase 26 실측 (system 1029 chars + user)
        output_tokens=632,   # 실측 평균
    ),
    AgentProfile(
        node_id="infrastructure_step",
        label="🌍 Infrastructure",
        recommended_tier="medium",
        rationale="다중 MCP 출력 클러스터링 + 인프라 상관관계 — 추론 필요",
        input_tokens=944,    # Phase 26 실측 (system 1329 chars + user)
        output_tokens=1000,  # 실측 평균
    ),
    AgentProfile(
        node_id="campaign_step",
        label="📈 Campaign",
        recommended_tier="medium",
        rationale="전략 종합 + 헌팅 쿼리 작성 + FW 룰 산출 — 가장 복잡한 합성",
        input_tokens=1023,   # Phase 26 실측 (system 1491 chars + user)
        output_tokens=2500,  # ★ max_tokens=2500 한도 도달 — 진짜는 더 길 수도
    ),
    AgentProfile(
        node_id="confidence_gate",
        label="🛡️ Gate",
        recommended_tier="mini",  # 의미 없음 — uses_llm=False
        rationale="결정론적 규칙 — LLM 무관, 순수 Python",
        input_tokens=0,
        output_tokens=0,
        uses_llm=False,
    ),
]


# ============================================================================
# 3. 전략 정의
# ============================================================================
TIER_TO_MODEL_ANTHROPIC: dict[ModelTier, str] = {
    "mini": "claude-haiku-4-5",
    "medium": "claude-sonnet-4-6",
    "strong": "claude-opus-4",
}


@dataclass
class StrategyResult:
    name: str
    total_input_tokens: int
    total_output_tokens: int
    total_cost_usd: float
    per_agent_breakdown: list[dict] = field(default_factory=list)
    # 두 baseline 모두 대비 절감률 (정직성 + 호환성)
    savings_vs_realistic_pct: float = 0.0  # vs all_sonnet
    savings_vs_naive_pct: float = 0.0       # vs all_opus (옛 91.8% 헤드라인 호환)
    # @deprecated: 기존 코드 호환을 위한 alias (= savings_vs_naive_pct)
    savings_vs_baseline_pct: float = 0.0


def _compute_for_strategy(
    strategy_name: str,
    tier_to_model: dict[ModelTier, str],
    *,
    force_tier: ModelTier | None = None,
    cached: bool = False,
    batch_discount: float = 0.0,
) -> StrategyResult:
    """force_tier: 모든 에이전트를 같은 tier 로 강제 (baseline 비교용)."""
    total_in = 0
    total_out = 0
    total_cost = 0.0
    breakdown: list[dict] = []

    for agent in AGENTS:
        if not agent.uses_llm:
            breakdown.append({
                "node": agent.node_id,
                "label": agent.label,
                "model": "(no LLM)",
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_usd": 0.0,
            })
            continue

        tier = force_tier or agent.recommended_tier
        model_id = tier_to_model[tier]
        model = MODELS[model_id]

        in_t = agent.input_tokens
        out_t = agent.output_tokens

        # Anthropic Prompt Caching: 시스템 프롬프트(~90%) 가 캐시되어 input 가격이 cached_input_per_1m
        if cached and model.cached_input_per_1m is not None:
            cached_fraction = 0.9
            input_cost = (
                (in_t * cached_fraction) * model.cached_input_per_1m / 1_000_000
                + (in_t * (1 - cached_fraction)) * model.input_per_1m / 1_000_000
            )
        else:
            input_cost = in_t * model.input_per_1m / 1_000_000

        output_cost = out_t * model.output_per_1m / 1_000_000

        # Batch API 할인 (Anthropic Batch API = 50% off)
        if batch_discount > 0:
            input_cost *= 1 - batch_discount
            output_cost *= 1 - batch_discount

        agent_cost = input_cost + output_cost
        total_in += in_t
        total_out += out_t
        total_cost += agent_cost

        breakdown.append({
            "node": agent.node_id,
            "label": agent.label,
            "model": model.name,
            "tier": tier,
            "input_tokens": in_t,
            "output_tokens": out_t,
            "cost_usd": round(agent_cost, 6),
        })

    return StrategyResult(
        name=strategy_name,
        total_input_tokens=total_in,
        total_output_tokens=total_out,
        total_cost_usd=round(total_cost, 6),
        per_agent_breakdown=breakdown,
    )


# ============================================================================
# 4. 공개 API
# ============================================================================
def compute_strategies() -> dict:
    """5가지 비용 전략을 계산하여 비교 가능한 dict 로 반환.

    Returns:
        {
            "strategies": {
                "all_opus":         naive baseline (실무에선 안 씀)
                "all_sonnet":       realistic baseline (실무 디폴트)
                "all_haiku":        저비용 하한
                "mixed":            본 시스템 채택 — 복잡도별 분배
                "mixed_cached_batch": Mixed + Prompt Caching + Batch
            },
            "headline_savings": {
                "realistic_vs_sonnet_pct": float,   # ★ 정직한 헤드라인
                "naive_vs_opus_pct": float,          # 옛 91.8% 호환
                "best_strategy": "mixed_cached_batch"
            },
            "monthly_at_scale": [...],
            "methodology": {...}
        }
    """
    naive_baseline = _compute_for_strategy(
        "all_opus", TIER_TO_MODEL_ANTHROPIC, force_tier="strong",
    )
    realistic_baseline = _compute_for_strategy(
        "all_sonnet", TIER_TO_MODEL_ANTHROPIC, force_tier="medium",
    )
    lower_bound = _compute_for_strategy(
        "all_haiku", TIER_TO_MODEL_ANTHROPIC, force_tier="mini",
    )
    mixed = _compute_for_strategy(
        "mixed", TIER_TO_MODEL_ANTHROPIC,
    )
    # Phase 26: caching 가정 제거 — Batch 만 적용 (실현 가능, 비실시간 워크플로)
    mixed_batch_only = _compute_for_strategy(
        "mixed_batch",
        TIER_TO_MODEL_ANTHROPIC,
        cached=False,
        batch_discount=0.5,
    )
    # 옛 헤드라인 호환 — Caching 가정 + Batch (현재 system 프롬프트 미달로
    # caching 실 작동 0%. 프롬프트 1024+ tokens 확장 시 시나리오)
    cached = _compute_for_strategy(
        "mixed_cached_batch",
        TIER_TO_MODEL_ANTHROPIC,
        cached=True,
        batch_discount=0.5,
    )

    # 두 baseline 모두 대비 절감률 계산
    def _pct(base: float, val: float) -> float:
        return round((base - val) / base * 100, 1) if base > 0 else 0.0

    for s in (realistic_baseline, lower_bound, mixed, mixed_batch_only, cached):
        s.savings_vs_naive_pct = _pct(naive_baseline.total_cost_usd, s.total_cost_usd)
        s.savings_vs_realistic_pct = _pct(realistic_baseline.total_cost_usd, s.total_cost_usd)
        # 호환 alias (옛 코드/문서가 savings_vs_baseline_pct 를 참조)
        s.savings_vs_baseline_pct = s.savings_vs_naive_pct

    # 금융권 SOC 규모별 월간 비용 — 비교는 realistic baseline (all_sonnet) 기준
    daily_volumes = [1_000, 10_000, 50_000]
    monthly_view = []
    for vol in daily_volumes:
        per_day_naive = naive_baseline.total_cost_usd * vol
        per_day_realistic = realistic_baseline.total_cost_usd * vol
        per_day_mixed = mixed.total_cost_usd * vol
        per_day_batch = mixed_batch_only.total_cost_usd * vol
        per_day_cached = cached.total_cost_usd * vol
        monthly_view.append({
            "daily_iocs": vol,
            "monthly_naive_opus_usd": round(per_day_naive * 30, 2),
            "monthly_realistic_sonnet_usd": round(per_day_realistic * 30, 2),
            "monthly_mixed_usd": round(per_day_mixed * 30, 2),
            "monthly_mixed_batch_usd": round(per_day_batch * 30, 2),
            "monthly_cached_usd": round(per_day_cached * 30, 2),
            "monthly_savings_vs_realistic_realized_usd": round(
                (per_day_realistic - per_day_batch) * 30, 2
            ),  # mixed_batch_only 가 실현 가능한 best (caching 가정 X)
            "monthly_savings_vs_realistic_assumed_usd": round(
                (per_day_realistic - per_day_cached) * 30, 2
            ),  # caching 가정 포함 시
            "monthly_savings_vs_naive_usd": round((per_day_naive - per_day_cached) * 30, 2),
        })

    return {
        "strategies": {
            "all_opus": _strategy_to_dict(naive_baseline),
            "all_sonnet": _strategy_to_dict(realistic_baseline),
            "all_haiku": _strategy_to_dict(lower_bound),
            "mixed": _strategy_to_dict(mixed),
            "mixed_batch": _strategy_to_dict(mixed_batch_only),
            "mixed_cached_batch": _strategy_to_dict(cached),
        },
        "headline_savings": {
            # ★ Phase 26 실측 기반 정직 헤드라인
            "realized_vs_sonnet_pct": mixed_batch_only.savings_vs_realistic_pct,
            "realized_best_strategy": "mixed_batch",
            "realized_note": (
                "caching 가정 제거 (Phase 26 실측: 현재 system 프롬프트가 "
                "Anthropic minimum cache tokens 미달로 0% cache hit). Batch API "
                "50% off 만 적용한 실현 가능 best."
            ),
            # 옛 헤드라인 호환 (caching 가정 포함)
            "assumed_vs_sonnet_pct": cached.savings_vs_realistic_pct,
            "assumed_vs_opus_pct": cached.savings_vs_naive_pct,
            "assumed_best_strategy": "mixed_cached_batch",
            "assumed_note": (
                "Anthropic Prompt Caching 90% hit 가정 — 시스템 프롬프트를 "
                "1024+ tokens 로 확장 시 시나리오. 현재는 미달 (Phase 26 실측 0%)."
            ),
            # 옛 필드 (호환 보존)
            "realistic_vs_sonnet_pct": cached.savings_vs_realistic_pct,
            "naive_vs_opus_pct": cached.savings_vs_naive_pct,
            "best_strategy": "mixed_cached_batch",
            "note": (
                "★ Phase 26 갱신: realized_* 가 실측 기반 정직 헤드라인, "
                "assumed_* 는 caching 가정 시 (옛 91.8% / 59.1% 호환). "
                "realistic_vs_sonnet_pct/naive_vs_opus_pct 는 옛 필드 호환."
            ),
        },
        "baselines": {
            "realistic": {
                "name": "all_sonnet",
                "description": "5 에이전트 모두 Sonnet — 실무 디폴트(단일 모델 운영)",
                "cost_usd": realistic_baseline.total_cost_usd,
            },
            "naive": {
                "name": "all_opus",
                "description": "5 에이전트 모두 Opus — 실무에선 안 함 (라우팅에 Opus 쓰는 팀 없음)",
                "cost_usd": naive_baseline.total_cost_usd,
            },
            "lower_bound": {
                "name": "all_haiku",
                "description": "5 에이전트 모두 Haiku — 저비용 하한 (품질 trade-off 큼)",
                "cost_usd": lower_bound.total_cost_usd,
            },
        },
        "monthly_at_scale": monthly_view,
        "methodology": {
            "token_source": (
                "★ Phase 26 실측 (benchmarks/caching_measurement.json) — "
                "각 agent × 3 회 호출 평균 input/output 토큰 (Anthropic API usage 직접)"
            ),
            "pricing_year": 2026,
            "caching": (
                "⚠ cost_analysis 의 cached_fraction=0.9 가정. Phase 26 실측 결과 "
                "현재 system 프롬프트 (chars 967~1491, est tokens 241~372) 가 "
                "Anthropic minimum cache tokens (Sonnet 1024 / Haiku 2048) 미달로 "
                "cache hit 실측 0%. mixed_cached_batch 전략은 '프롬프트 확장 시' 시나리오."
            ),
            "batch_discount": (
                "Anthropic Batch API 50% 할인 (비실시간 워크플로 가정). "
                "실시간 SOC trigger 분석에는 부분 적용. mixed_batch 전략은 batch 만 적용 (실현 가능)."
            ),
            "currency": "USD",
            "baseline_choice": (
                "all_sonnet 을 realistic baseline 으로 사용. "
                "옛 all_opus baseline 은 비현실적이라 naive 라벨로 보존."
            ),
        },
    }


def _strategy_to_dict(s: StrategyResult) -> dict:
    return {
        "name": s.name,
        "total_input_tokens": s.total_input_tokens,
        "total_output_tokens": s.total_output_tokens,
        "total_cost_usd": s.total_cost_usd,
        "savings_vs_realistic_pct": s.savings_vs_realistic_pct,
        "savings_vs_naive_pct": s.savings_vs_naive_pct,
        # 옛 코드 호환
        "savings_vs_baseline_pct": s.savings_vs_baseline_pct,
        "per_agent_breakdown": s.per_agent_breakdown,
    }
