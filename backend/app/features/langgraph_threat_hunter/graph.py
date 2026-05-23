"""LangGraph StateGraph 빌더 — Hierarchical Threat Hunting flow.

흐름:
    START → triage → malware → infrastructure → campaign → confidence_gate → END

각 노드는 `nodes.py` 의 함수를 사용하며, MCP 호출은 McpRegistry 를 통해 추상화.
"""
from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from .mcp_clients import McpRegistry
from .nodes import (
    campaign_node,
    gate_node,
    infrastructure_node,
    malware_node,
    triage_node,
)
from .state import ThreatHuntState


def build_graph(mode: str = "simulation") -> Any:
    """ThreatHuntState 그래프를 컴파일하여 반환.

    mode: "simulation" 또는 "live"
    """
    mcp = McpRegistry(mode=mode)

    graph: StateGraph = StateGraph(ThreatHuntState)

    # 주의: LangGraph 0.2.x 는 노드명이 state 필드명과 같으면 충돌.
    # ThreatHuntState 에 triage/malware/infrastructure/campaign 필드가 있어
    # 노드명에는 `_step` 접미사 부여.
    graph.add_node("triage_step", lambda s: triage_node(s, mcp))
    graph.add_node("malware_step", lambda s: malware_node(s, mcp))
    graph.add_node("infrastructure_step", lambda s: infrastructure_node(s, mcp))
    graph.add_node("campaign_step", lambda s: campaign_node(s, mcp))
    graph.add_node("confidence_gate", gate_node)

    graph.add_edge(START, "triage_step")
    graph.add_edge("triage_step", "malware_step")
    graph.add_edge("malware_step", "infrastructure_step")
    graph.add_edge("infrastructure_step", "campaign_step")
    graph.add_edge("campaign_step", "confidence_gate")
    graph.add_edge("confidence_gate", END)

    return graph.compile()


# 모듈 로딩 시점에 미리 컴파일된 시뮬레이션 그래프 (싱글톤 캐시 유사)
_compiled_simulation_graph: Any | None = None


def get_simulation_graph() -> Any:
    global _compiled_simulation_graph
    if _compiled_simulation_graph is None:
        _compiled_simulation_graph = build_graph(mode="simulation")
    return _compiled_simulation_graph
