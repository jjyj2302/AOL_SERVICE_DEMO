"""Confidence-Gated Automation (L0~L4) — 금융권 안전성 보장 모듈.

각 분석 단계의 산출물을 기반으로 신뢰도 점수(0.0~1.0)를 산출하고
L0~L4 등급으로 매핑한다. 핵심 자산 대상 IoC 는 등급과 무관하게
휴먼 승인 플래그를 강제한다.
"""
from __future__ import annotations

from .state import AutomationLevel, ThreatHuntState

# 금융권 핵심 자산 식별 키워드 — 매칭 시 휴먼 승인 강제
CRITICAL_ASSET_PATTERNS = (
    "core-banking",
    "exec-pc",
    "swift",
    "trading-engine",
    "kakaobank",
    "shinhan",
    "kbstar",
    "wooribank",
    "hanafn",
    "ibk",
)


def _signal_score(state: ThreatHuntState) -> float:
    """4개 단계 산출물에서 신뢰도 가산 신호를 합산."""
    score = 0.0

    if state.triage:
        match state.triage.threat_level:
            case "CRITICAL":
                score += 0.35
            case "HIGH":
                score += 0.25
            case "MEDIUM":
                score += 0.10
            case "LOW":
                score += 0.02

    if state.malware:
        if state.malware.malware_family:
            score += 0.15
        if state.malware.c2_targets:
            score += 0.10

    if state.infrastructure:
        if state.infrastructure.typosquat_domains:
            score += 0.15
        if state.infrastructure.campaign_cluster_id:
            score += 0.10
        if state.infrastructure.exposed_assets:
            score += 0.05

    if state.campaign:
        if state.campaign.threat_group_hypothesis:
            score += 0.05
        if state.campaign.hunt_hypotheses:
            score += 0.05

    return min(score, 1.0)


def _to_level(score: float) -> AutomationLevel:
    if score < 0.50:
        return "L0"
    if score < 0.70:
        return "L1"
    if score < 0.85:
        return "L2"
    if score < 0.95:
        return "L3"
    return "L4"


def _is_critical_asset(state: ThreatHuntState) -> bool:
    candidates = [state.ioc.lower()]
    if state.infrastructure:
        candidates.extend(d.get("domain", "").lower() for d in state.infrastructure.typosquat_domains)
        candidates.extend(d.get("target", "").lower() for d in state.infrastructure.exposed_assets)
    return any(pat in c for c in candidates for pat in CRITICAL_ASSET_PATTERNS)


def apply_gating(state: ThreatHuntState) -> ThreatHuntState:
    """state 의 confidence_score / automation_level / human_approval_required 를 채움."""
    score = _signal_score(state)
    state.confidence_score = round(score, 3)
    state.automation_level = _to_level(score)
    state.human_approval_required = _is_critical_asset(state) or state.automation_level == "L4"
    return state
