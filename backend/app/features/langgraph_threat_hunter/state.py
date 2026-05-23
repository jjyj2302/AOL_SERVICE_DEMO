"""LangGraph state schema for the financial-sector threat hunting flow.

이 state 는 그래프의 각 노드를 통과하면서 누적되는 조사 컨텍스트를 담는다.
Investigation Ledger 와 Confidence Gating 입력으로 활용된다.
"""
from __future__ import annotations

from datetime import datetime, timezone
from operator import add
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

IocType = Literal["ip", "domain", "url", "hash", "cve", "email", "unknown"]
AutomationLevel = Literal["L0", "L1", "L2", "L3", "L4"]
RunMode = Literal["live", "simulation"]


class LedgerEntry(BaseModel):
    """Audit Ledger 단일 엔트리 — 노드 실행 단위 추적."""
    node: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    elapsed_ms: int | None = None
    summary: str = ""
    tools_called: list[str] = Field(default_factory=list)


class McpCallRecord(BaseModel):
    """단일 MCP 도구 호출 기록."""
    tool: str
    input_key: str  # 호출 인자의 요약 (예: domain="kakaobаnk.com")
    elapsed_ms: int
    cached: bool = False
    simulation: bool = False


class TriageFindings(BaseModel):
    """Triage Specialist 산출물."""
    threat_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    detection_ratio: str = ""           # 예: "21/93"
    mitre_tactics: list[str] = Field(default_factory=list)
    priority_pivots: list[str] = Field(default_factory=list)
    notes: str = ""


class MalwareFindings(BaseModel):
    """Malware Specialist 산출물."""
    malware_family: str | None = None
    behaviors: list[str] = Field(default_factory=list)
    c2_targets: list[str] = Field(default_factory=list)
    payload_hashes: list[str] = Field(default_factory=list)
    notes: str = ""


class InfraFindings(BaseModel):
    """Infrastructure Hunter 산출물 — DNSTwist/Shodan/URLScan 종합."""
    typosquat_domains: list[dict[str, Any]] = Field(default_factory=list)
    exposed_assets: list[dict[str, Any]] = Field(default_factory=list)
    related_infra: list[dict[str, Any]] = Field(default_factory=list)
    campaign_cluster_id: str | None = None
    notes: str = ""


class CampaignFindings(BaseModel):
    """Campaign Analyst 산출물 — 전략 인텔리전스 + 헌팅 가설."""
    threat_group_hypothesis: str | None = None
    attack_chain: list[str] = Field(default_factory=list)
    hunt_hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    firewall_rules: list[str] = Field(default_factory=list)
    executive_summary: str = ""


class ThreatHuntState(BaseModel):
    """LangGraph 전역 상태 — 모든 노드가 누적 갱신."""
    # ---- 입력 ----
    ioc: str
    ioc_type: IocType = "unknown"
    mode: RunMode = "simulation"
    scenario_id: str | None = None     # 시뮬레이션일 때만 세팅

    # ---- 진행 ----
    triage: TriageFindings | None = None
    malware: MalwareFindings | None = None
    infrastructure: InfraFindings | None = None
    campaign: CampaignFindings | None = None

    # ---- 신뢰도 게이팅 ----
    confidence_score: float = 0.0
    automation_level: AutomationLevel | None = None
    human_approval_required: bool = False

    # ---- 감사 / 측정 ----
    # Annotated + add reducer 로 노드 간 누적 (LangGraph 가 노드별 update 를 concat).
    audit_ledger: Annotated[list[LedgerEntry], add] = Field(default_factory=list)
    mcp_calls: Annotated[list[McpCallRecord], add] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    elapsed_ms: int = 0

    # ---- 산출물 경로 ----
    deliverables: dict[str, Any] = Field(default_factory=dict)

    def total_tools(self) -> int:
        return len(self.mcp_calls)
