"""LangGraph StateGraph 전체 흐름 통합 검증.

Orchestrator + 동적 라우팅 (IoC 타입별 specialist 스킵) 검증 포함.
"""
from __future__ import annotations

import pytest

from app.features.langgraph_threat_hunter.graph import build_graph
from app.features.langgraph_threat_hunter.simulations import get_scenario
from app.features.langgraph_threat_hunter.state import ThreatHuntState


@pytest.fixture(scope="module")
def sim_graph():
    return build_graph(mode="simulation")


# IoC 타입별 기대 ledger 노드 (Orchestrator + 선택된 Specialist 들 + Gate)
EXPECTED_LEDGER_BY_SCENARIO = {
    "S1": ["orchestrator", "triage", "infrastructure", "campaign", "confidence_gate"],
    "S2": ["orchestrator", "triage", "infrastructure", "campaign", "confidence_gate"],
    "S3": ["orchestrator", "triage", "malware", "infrastructure", "campaign", "confidence_gate"],
    "S4": ["orchestrator", "triage", "infrastructure", "campaign", "confidence_gate"],
    "S5": ["orchestrator", "triage", "campaign", "confidence_gate"],
}

SCENARIO_IDS = list(EXPECTED_LEDGER_BY_SCENARIO.keys())


@pytest.mark.parametrize("sid", SCENARIO_IDS)
def test_full_graph_invoke_per_scenario(sim_graph, sid):
    """각 시나리오가 Orchestrator 라우팅에 따른 정확한 노드만 통과한다."""
    seed = get_scenario(sid)
    init = ThreatHuntState(
        ioc=seed["ioc"],
        ioc_type=seed["ioc_type"],
        mode="simulation",
        scenario_id=sid,
    )
    raw = sim_graph.invoke(init)
    final = raw if isinstance(raw, ThreatHuntState) else ThreatHuntState.model_validate(raw)

    expected = EXPECTED_LEDGER_BY_SCENARIO[sid]
    ledger_nodes = [e.node for e in final.audit_ledger]
    assert ledger_nodes == expected, f"{sid} ledger mismatch: {ledger_nodes} != {expected}"

    # Orchestrator 의 route_plan 이 채워짐
    assert final.route_plan, f"{sid} route_plan empty"
    assert final.routing_rationale, f"{sid} routing_rationale empty"

    # Triage 와 Campaign 은 모든 시나리오에 존재
    assert final.triage is not None
    assert final.campaign is not None

    # 신뢰도 등급 계산됨
    assert final.automation_level in {"L0", "L1", "L2", "L3", "L4"}

    # MCP 호출이 1건 이상
    assert len(final.mcp_calls) >= 1


def test_s5_skips_malware_and_infra(sim_graph):
    """S5 (CVE) 는 malware/infrastructure specialist 스킵."""
    seed = get_scenario("S5")
    init = ThreatHuntState(ioc=seed["ioc"], ioc_type="cve", mode="simulation", scenario_id="S5")
    raw = sim_graph.invoke(init)
    final = raw if isinstance(raw, ThreatHuntState) else ThreatHuntState.model_validate(raw)

    # 스킵된 specialist 의 결과는 None
    assert final.malware is None, "CVE 분석에서 malware 결과가 채워지면 안 됨"
    assert final.infrastructure is None, "CVE 분석에서 infrastructure 결과가 채워지면 안 됨"
    # CVE MCP 는 campaign 단계에서 호출됨
    assert any(c.tool == "cve" for c in final.mcp_calls)


def test_s3_runs_all_specialists(sim_graph):
    """S3 (hash) 는 모든 4 specialist 실행."""
    seed = get_scenario("S3")
    init = ThreatHuntState(ioc=seed["ioc"], ioc_type="hash", mode="simulation", scenario_id="S3")
    raw = sim_graph.invoke(init)
    final = raw if isinstance(raw, ThreatHuntState) else ThreatHuntState.model_validate(raw)

    assert final.triage is not None
    assert final.malware is not None
    assert final.infrastructure is not None
    assert final.campaign is not None


def test_s1_kakaobank_requires_human_approval(sim_graph):
    """S1 카카오뱅크는 핵심 자산 키워드로 휴먼 승인 강제."""
    seed = get_scenario("S1")
    init = ThreatHuntState(
        ioc=seed["ioc"], ioc_type=seed["ioc_type"], mode="simulation", scenario_id="S1"
    )
    raw = sim_graph.invoke(init)
    final = raw if isinstance(raw, ThreatHuntState) else ThreatHuntState.model_validate(raw)
    assert final.human_approval_required is True


def test_simulation_mcp_calls_flagged_as_simulation(sim_graph):
    """simulation 모드에서 발생한 MCP 호출은 simulation=True 플래그."""
    seed = get_scenario("S2")
    init = ThreatHuntState(
        ioc=seed["ioc"], ioc_type=seed["ioc_type"], mode="simulation", scenario_id="S2"
    )
    raw = sim_graph.invoke(init)
    final = raw if isinstance(raw, ThreatHuntState) else ThreatHuntState.model_validate(raw)
    assert all(c.simulation is True for c in final.mcp_calls)
