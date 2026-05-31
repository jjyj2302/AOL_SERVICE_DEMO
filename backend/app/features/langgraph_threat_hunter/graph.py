"""LangGraph StateGraph 빌더 — Orchestrator + Conditional Routing.

흐름:
    START
      └─→ orchestrator (IoC 타입 보고 route_plan 결정)
            └─→ conditional → 첫 specialist (plan[0])
                  └─→ conditional → 다음 specialist or gate
                        ...
                  └─→ confidence_gate → END

각 specialist 노드는 단일 책임을 갖고, 라우팅 결정은 Orchestrator + 조건부
엣지에 위임. CrewAI 의 hierarchical Process 와 동일 구조를 LangGraph 의
state machine 으로 명시적 표현.
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
    orchestrator_node,
    triage_node,
)
from .state import ThreatHuntState

SPECIALIST_NODES = ["triage_step", "malware_step", "infrastructure_step", "campaign_step"]
ALL_BRANCHES = {n: n for n in SPECIALIST_NODES + ["confidence_gate"]}


def _route_after_orchestrator(state: ThreatHuntState) -> str:
    """Orchestrator 가 채운 route_plan 의 첫 노드로 분기."""
    plan = state.route_plan or []
    if not plan:
        return "confidence_gate"
    return f"{plan[0]}_step"


def _route_after(current: str):
    """현 specialist 이후 — plan 에서 다음 step 으로 분기 (없으면 gate)."""
    def router(state: ThreatHuntState) -> str:
        plan = state.route_plan or []
        try:
            idx = plan.index(current)
            if idx + 1 < len(plan):
                return f"{plan[idx + 1]}_step"
        except ValueError:
            pass
        return "confidence_gate"
    return router


def build_graph(mode: str = "simulation") -> Any:
    mcp = McpRegistry(mode=mode)
    g: StateGraph = StateGraph(ThreatHuntState)

    g.add_node("orchestrator", lambda s: orchestrator_node(s, mcp))
    g.add_node("triage_step", lambda s: triage_node(s, mcp))
    g.add_node("malware_step", lambda s: malware_node(s, mcp))
    g.add_node("infrastructure_step", lambda s: infrastructure_node(s, mcp))
    g.add_node("campaign_step", lambda s: campaign_node(s, mcp))
    g.add_node("confidence_gate", gate_node)

    g.add_edge(START, "orchestrator")
    g.add_conditional_edges("orchestrator", _route_after_orchestrator, ALL_BRANCHES)
    g.add_conditional_edges("triage_step", _route_after("triage"), ALL_BRANCHES)
    g.add_conditional_edges("malware_step", _route_after("malware"), ALL_BRANCHES)
    g.add_conditional_edges("infrastructure_step", _route_after("infrastructure"), ALL_BRANCHES)
    g.add_conditional_edges("campaign_step", _route_after("campaign"), ALL_BRANCHES)
    g.add_edge("confidence_gate", END)

    return g.compile()


_compiled_simulation_graph: Any | None = None


def get_simulation_graph() -> Any:
    global _compiled_simulation_graph
    if _compiled_simulation_graph is None:
        _compiled_simulation_graph = build_graph(mode="simulation")
    return _compiled_simulation_graph
