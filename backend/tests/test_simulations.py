"""시뮬레이션 시드 데이터 정합성 검증."""
from __future__ import annotations

import pytest

from app.features.langgraph_threat_hunter.simulations import (
    SIMULATION_SCENARIOS,
    get_scenario,
    list_scenarios,
)


EXPECTED_IDS = {"S1", "S2", "S3", "S4", "S5"}


def test_5_scenarios_present():
    """5대 금융권 시나리오가 모두 등록되어 있다."""
    assert set(SIMULATION_SCENARIOS.keys()) == EXPECTED_IDS


def test_list_scenarios_summary_shape():
    """list_scenarios 가 프론트엔드 메뉴용 요약 필드만 노출한다."""
    summaries = list_scenarios()
    assert len(summaries) == 5
    required_keys = {"id", "title", "summary", "ioc", "ioc_type", "before_minutes", "estimated_after_seconds"}
    for s in summaries:
        assert required_keys <= set(s.keys()), f"missing keys in {s['id']}"


@pytest.mark.parametrize("sid", sorted(EXPECTED_IDS))
def test_scenario_has_all_four_findings(sid: str):
    """각 시나리오는 4-Agent 산출물 (triage/malware/infrastructure/campaign) 시드를 포함."""
    seed = get_scenario(sid)
    assert seed is not None
    for section in ("triage", "malware", "infrastructure", "campaign"):
        assert section in seed, f"{sid} missing {section}"


def test_get_scenario_unknown_returns_none():
    assert get_scenario("S99") is None


@pytest.mark.parametrize("sid", sorted(EXPECTED_IDS))
def test_before_minutes_positive(sid: str):
    """Before/After 측정값은 양수여야 한다 (정량 효과 표시용)."""
    seed = get_scenario(sid)
    assert seed["before_minutes"] > 0
    assert seed["estimated_after_seconds"] > 0
