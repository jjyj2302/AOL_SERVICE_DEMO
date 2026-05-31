"""신뢰도 게이팅 (L0~L4) 검증."""
from __future__ import annotations

import pytest

from app.features.langgraph_threat_hunter.confidence import apply_gating
from app.features.langgraph_threat_hunter.simulations import get_scenario
from app.features.langgraph_threat_hunter.state import (
    CampaignFindings,
    InfraFindings,
    MalwareFindings,
    ThreatHuntState,
    TriageFindings,
)


def _full_state(scenario_id: str) -> ThreatHuntState:
    seed = get_scenario(scenario_id)
    return ThreatHuntState(
        ioc=seed["ioc"],
        ioc_type=seed["ioc_type"],
        mode="simulation",
        scenario_id=scenario_id,
        triage=TriageFindings(**seed["triage"]),
        malware=MalwareFindings(**seed["malware"]),
        infrastructure=InfraFindings(**seed["infrastructure"]),
        campaign=CampaignFindings(**seed["campaign"]),
    )


def test_empty_state_gives_L0():
    state = ThreatHuntState(ioc="example.com", ioc_type="domain", mode="simulation")
    apply_gating(state)
    assert state.confidence_score == 0.0
    assert state.automation_level == "L0"
    assert state.human_approval_required is False


def test_kakaobank_scenario_triggers_critical_asset_approval():
    """카카오뱅크 사칭 시나리오는 핵심 자산 키워드 매칭으로 휴먼 승인 강제."""
    state = _full_state("S1")
    apply_gating(state)
    assert state.human_approval_required is True, "kakaobank 키워드 매칭 시 휴먼 승인 강제"
    assert state.automation_level in {"L0", "L1", "L2", "L3", "L4"}


def test_ransomware_scenario_high_confidence():
    """랜섬웨어 시나리오는 CRITICAL 위협 + family + c2 + cluster 매칭 → 고신뢰."""
    state = _full_state("S3")
    apply_gating(state)
    assert state.confidence_score >= 0.7
    assert state.automation_level in {"L2", "L3", "L4"}


def test_cve_scenario_does_not_require_approval():
    """CVE 우선순위화 시나리오는 핵심 자산 키워드 없으므로 휴먼 승인 강제 X (L4 아닌 경우)."""
    state = _full_state("S5")
    apply_gating(state)
    if state.automation_level != "L4":
        assert state.human_approval_required is False


@pytest.mark.parametrize("score,expected", [
    (0.0, "L0"),
    (0.49, "L0"),
    (0.5, "L1"),
    (0.69, "L1"),
    (0.7, "L2"),
    (0.84, "L2"),
    (0.85, "L3"),
    (0.94, "L3"),
    (0.95, "L4"),
    (1.0, "L4"),
])
def test_score_to_level_boundaries(score: float, expected: str):
    """등급 경계 (0.5/0.7/0.85/0.95) 매핑 정확성."""
    from app.features.langgraph_threat_hunter.confidence import _to_level
    assert _to_level(score) == expected
