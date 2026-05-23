"""에이전트별 모델 매핑 + 토큰/비용 분석.

각 에이전트의 작업 복잡도가 다르므로 동일 모델(Opus 등)을 모든 에이전트에
적용하는 것은 낭비. 이 모듈은:

1. 에이전트별 권장 모델 티어 (mini / medium / strong) 정의
2. 모델 가격표 (Anthropic / OpenAI 2026년 기준, per 1M tokens)
3. 에이전트별 토큰 사용량 추정
4. 3가지 전략 비용 비교:
   - all_strong   : 모든 에이전트가 strong (Opus)
   - mixed        : 복잡도별 모델 분배 (실제 권장)
   - mixed_cached : Mixed + Prompt Caching + Batch API

운영 단계에서 실측 토큰을 수집하면 ESTIMATES 를 대체 가능.
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


# 토큰 추정치 — 2026-05-23 Anthropic API 실측 평균값으로 갱신.
# 측정 환경: 5 agents × 3 models (Haiku 4.5 / Sonnet 4.6 / Opus 4.7) 단발 호출.
# 결과는 benchmarks/results.json (gitignored) 참조.
AGENTS: list[AgentProfile] = [
    AgentProfile(
        node_id="orchestrator",
        label="🧠 Orchestrator",
        recommended_tier="mini",
        rationale="IoC 타입 보고 route_plan 만 결정 — 라우팅만 필요",
        input_tokens=250,    # 실측 평균
        output_tokens=200,
    ),
    AgentProfile(
        node_id="triage_step",
        label="🔍 Triage",
        recommended_tier="mini",
        rationale="VT JSON 해석 + 위협 수준 분류 — 구조화 데이터 매핑 수준",
        input_tokens=400,    # 실측 평균 (397~466)
        output_tokens=700,
    ),
    AgentProfile(
        node_id="malware_step",
        label="👾 Malware",
        recommended_tier="medium",
        rationale="악성코드 행위 분석 + Attack chain 재구성 — 추론 필요",
        input_tokens=440,    # 실측 평균 (426~473)
        output_tokens=1400,  # Sonnet 1500 / Opus 1124 평균
    ),
    AgentProfile(
        node_id="infrastructure_step",
        label="🌍 Infrastructure",
        recommended_tier="medium",
        rationale="다중 MCP 출력 클러스터링 + 인프라 상관관계 — 추론 필요",
        input_tokens=540,    # 실측 평균 (517~588)
        output_tokens=1300,  # Sonnet 1500 / Opus 1084 평균
    ),
    AgentProfile(
        node_id="campaign_step",
        label="📈 Campaign",
        recommended_tier="medium",
        rationale="전략 종합 + 헌팅 쿼리 작성 + FW 룰 산출 — 가장 복잡한 합성",
        input_tokens=500,    # 실측 평균 (484~556)
        output_tokens=2500,
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
    savings_vs_baseline_pct: float = 0.0


def _compute_for_strategy(
    strategy_name: str,
    tier_to_model: dict[ModelTier, str],
    *,
    force_strong: bool = False,
    cached: bool = False,
    batch_discount: float = 0.0,
) -> StrategyResult:
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

        tier = "strong" if force_strong else agent.recommended_tier
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
    """3가지 비용 전략을 계산하여 비교 가능한 dict 로 반환."""
    baseline = _compute_for_strategy(
        "all_strong",
        TIER_TO_MODEL_ANTHROPIC,
        force_strong=True,
    )
    mixed = _compute_for_strategy(
        "mixed",
        TIER_TO_MODEL_ANTHROPIC,
    )
    cached = _compute_for_strategy(
        "mixed_cached_batch",
        TIER_TO_MODEL_ANTHROPIC,
        cached=True,
        batch_discount=0.5,
    )

    # baseline 대비 절감률
    for s in (mixed, cached):
        if baseline.total_cost_usd > 0:
            s.savings_vs_baseline_pct = round(
                (baseline.total_cost_usd - s.total_cost_usd) / baseline.total_cost_usd * 100,
                1,
            )

    # 금융권 SOC 규모별 월간 비용
    daily_volumes = [1_000, 10_000, 50_000]
    monthly_view = []
    for vol in daily_volumes:
        per_day_baseline = baseline.total_cost_usd * vol
        per_day_mixed = mixed.total_cost_usd * vol
        per_day_cached = cached.total_cost_usd * vol
        monthly_view.append({
            "daily_iocs": vol,
            "monthly_baseline_usd": round(per_day_baseline * 30, 2),
            "monthly_mixed_usd": round(per_day_mixed * 30, 2),
            "monthly_cached_usd": round(per_day_cached * 30, 2),
            "monthly_savings_vs_baseline_usd": round((per_day_baseline - per_day_cached) * 30, 2),
        })

    return {
        "strategies": {
            "all_strong": _strategy_to_dict(baseline),
            "mixed": _strategy_to_dict(mixed),
            "mixed_cached_batch": _strategy_to_dict(cached),
        },
        "monthly_at_scale": monthly_view,
        "methodology": {
            "token_estimates": "각 에이전트의 평균 input/output 토큰 추정치 (실측 시 갱신)",
            "pricing_year": 2026,
            "caching": "Anthropic Prompt Caching — 시스템 프롬프트 90% 캐시 가정",
            "batch_discount": "Anthropic Batch API 50% 할인 적용",
            "currency": "USD",
        },
    }


def _strategy_to_dict(s: StrategyResult) -> dict:
    return {
        "name": s.name,
        "total_input_tokens": s.total_input_tokens,
        "total_output_tokens": s.total_output_tokens,
        "total_cost_usd": s.total_cost_usd,
        "savings_vs_baseline_pct": s.savings_vs_baseline_pct,
        "per_agent_breakdown": s.per_agent_breakdown,
    }
