"""LangGraph StateGraph 전체 흐름 통합 검증."""
from __future__ import annotations

import pytest

from app.features.langgraph_threat_hunter.graph import build_graph
from app.features.langgraph_threat_hunter.simulations import get_scenario
from app.features.langgraph_threat_hunter.state import ThreatHuntState


@pytest.fixture(scope="module")
def sim_graph():
    return build_graph(mode="simulation")


SCENARIO_IDS = ["S1", "S2", "S3", "S4", "S5"]
EXPECTED_LEDGER_NODES = ["triage", "malware", "infrastructure", "campaign", "confidence_gate"]


@pytest.mark.parametrize("sid", SCENARIO_IDS)
def test_full_graph_invoke_per_scenario(sim_graph, sid):
    """각 시나리오가 5개 노드를 모두 통과하고 산출물을 모두 채운다."""
    seed = get_scenario(sid)
    init = ThreatHuntState(
        ioc=seed["ioc"],
        ioc_type=seed["ioc_type"],
        mode="simulation",
        scenario_id=sid,
    )
    raw = sim_graph.invoke(init)
    final = raw if isinstance(raw, ThreatHuntState) else ThreatHuntState.model_validate(raw)

    # 1) Audit Ledger 가 5단계 모두 기록
    ledger_nodes = [e.node for e in final.audit_ledger]
    assert ledger_nodes == EXPECTED_LEDGER_NODES

    # 2) MCP 호출이 1건 이상 발생
    assert len(final.mcp_calls) >= 1

    # 3) 4개 산출물 모두 채워짐
    assert final.triage is not None
    assert final.malware is not None
    assert final.infrastructure is not None
    assert final.campaign is not None

    # 4) 신뢰도 등급 계산됨
    assert final.automation_level in {"L0", "L1", "L2", "L3", "L4"}


def test_s5_includes_cve_mcp_call(sim_graph):
    """S5 (CVE 시나리오) 는 CVE MCP 도구 호출이 포함되어야 한다."""
    seed = get_scenario("S5")
    init = ThreatHuntState(
        ioc=seed["ioc"], ioc_type=seed["ioc_type"], mode="simulation", scenario_id="S5"
    )
    raw = sim_graph.invoke(init)
    final = raw if isinstance(raw, ThreatHuntState) else ThreatHuntState.model_validate(raw)
    called_tools = {c.tool for c in final.mcp_calls}
    assert "cve" in called_tools


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
