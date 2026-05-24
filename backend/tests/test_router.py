"""FastAPI 라우터 통합 검증 (TestClient 기반).

main.py 전체를 import 하면 DB 초기화·라이프스팬 등 사이드이펙트가 큼.
여기서는 신규 langgraph_threat_hunter 라우터만 isolated app 으로 마운트.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.features.langgraph_threat_hunter.router import router


@pytest.fixture(scope="module")
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_health_returns_ok(client):
    resp = client.get("/api/lg/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["graph"] == "compiled"
    assert body["simulation_scenarios"] == 5


def test_scenarios_lists_five(client):
    resp = client.get("/api/lg/scenarios")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["scenarios"]) == 5
    ids = {s["id"] for s in body["scenarios"]}
    assert ids == {"S1", "S2", "S3", "S4", "S5"}


# Orchestrator 동적 라우팅 → 시나리오별 노드 수가 다름
EXPECTED_LEDGER_COUNT = {"S1": 5, "S2": 5, "S3": 6, "S4": 5, "S5": 4}


@pytest.mark.parametrize("sid", ["S1", "S2", "S3", "S4", "S5"])
def test_simulate_each_scenario(client, sid):
    resp = client.post(f"/api/lg/simulate/{sid}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scenario_id"] == sid
    assert body["automation_level"] in {"L0", "L1", "L2", "L3", "L4"}
    assert len(body["audit_ledger"]) == EXPECTED_LEDGER_COUNT[sid]
    # before/after 메타 노출 확인 (정량 효과 시연용)
    assert body["deliverables"]["before_minutes"] > 0
    assert body["deliverables"]["estimated_after_seconds"] > 0


def test_simulate_unknown_returns_404(client):
    resp = client.post("/api/lg/simulate/S99")
    assert resp.status_code == 404
    assert "S99" in resp.json()["detail"]


def test_cost_analysis_endpoint(client):
    resp = client.get("/api/lg/cost-analysis")
    assert resp.status_code == 200
    body = resp.json()
    # 5 전략: all_opus(naive), all_sonnet(realistic), all_haiku(lower), mixed, mixed_cached_batch
    assert set(body["strategies"].keys()) == {
        "all_opus", "all_sonnet", "all_haiku", "mixed", "mixed_cached_batch",
    }
    # 가격 순서: opus > sonnet > mixed > cached > haiku
    s = body["strategies"]
    assert s["all_opus"]["total_cost_usd"] > s["all_sonnet"]["total_cost_usd"]
    assert s["all_sonnet"]["total_cost_usd"] > s["mixed"]["total_cost_usd"]
    assert s["mixed"]["total_cost_usd"] > s["mixed_cached_batch"]["total_cost_usd"]

    # 정직한 헤드라인: realistic Sonnet 대비 mixed_cached_batch 가 의미 있는 절감
    headline = body["headline_savings"]
    assert headline["realistic_vs_sonnet_pct"] > 40  # 캐싱+배치로 최소 40%+
    assert headline["realistic_vs_sonnet_pct"] < 80  # 정직성 — 90%+ 는 과대표기 신호
    # 호환: 옛 91.8% (naive vs opus) 헤드라인도 보존
    assert headline["naive_vs_opus_pct"] > 85
    assert headline["best_strategy"] == "mixed_cached_batch"

    # 두 baseline 모두 대비 절감률 노출
    assert "savings_vs_realistic_pct" in s["mixed_cached_batch"]
    assert "savings_vs_naive_pct" in s["mixed_cached_batch"]

    # 월간 데이터 3종 (1k/10k/50k) 노출 + 두 baseline 모두 비용 표시
    assert len(body["monthly_at_scale"]) == 3
    monthly = body["monthly_at_scale"][0]
    assert "monthly_realistic_sonnet_usd" in monthly
    assert "monthly_naive_opus_usd" in monthly
    assert "monthly_savings_vs_realistic_usd" in monthly


@pytest.mark.parametrize("sid", ["S1", "S2", "S3", "S4", "S5"])
def test_pdf_report_endpoint(client, sid):
    """PDF 리포트 생성: 정상 PDF 바이트 반환."""
    resp = client.get(f"/api/lg/simulate/{sid}/report.pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"
    assert len(resp.content) > 1000  # 너무 빈약하지 않은지


def test_pdf_report_unknown_returns_404(client):
    resp = client.get("/api/lg/simulate/S99/report.pdf")
    assert resp.status_code == 404
