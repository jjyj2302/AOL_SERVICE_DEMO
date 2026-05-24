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
    # Phase 26: 6 전략 (mixed_batch 추가 — caching 가정 없는 실현 가능 best)
    assert set(body["strategies"].keys()) == {
        "all_opus", "all_sonnet", "all_haiku",
        "mixed", "mixed_batch", "mixed_cached_batch",
    }
    s = body["strategies"]
    # 가격 순서: opus > sonnet > mixed > mixed_batch > mixed_cached_batch > (haiku 별도)
    assert s["all_opus"]["total_cost_usd"] > s["all_sonnet"]["total_cost_usd"]
    assert s["all_sonnet"]["total_cost_usd"] > s["mixed"]["total_cost_usd"]
    assert s["mixed"]["total_cost_usd"] > s["mixed_batch"]["total_cost_usd"]
    assert s["mixed_batch"]["total_cost_usd"] > s["mixed_cached_batch"]["total_cost_usd"]

    # Phase 26 정직 헤드라인: realized (caching 가정 X) + assumed (caching 가정 O) 둘 다
    headline = body["headline_savings"]
    # realized — caching 없이 실현 가능 (mixed_batch vs sonnet)
    assert 40 <= headline["realized_vs_sonnet_pct"] <= 75  # batch 만으로 50% 부근
    assert headline["realized_best_strategy"] == "mixed_batch"
    # assumed — caching 90% 가정 시 (옛 호환)
    assert headline["assumed_vs_sonnet_pct"] > headline["realized_vs_sonnet_pct"]
    assert headline["assumed_vs_opus_pct"] > 85
    # 호환 alias 보존
    assert "realistic_vs_sonnet_pct" in headline
    assert "naive_vs_opus_pct" in headline
    assert headline["best_strategy"] == "mixed_cached_batch"

    # 두 baseline 모두 대비 절감률 노출
    assert "savings_vs_realistic_pct" in s["mixed_cached_batch"]
    assert "savings_vs_naive_pct" in s["mixed_cached_batch"]
    assert "savings_vs_realistic_pct" in s["mixed_batch"]

    # methodology 에 정직성 표기 (Phase 26 — caching 가정 미작동 명시)
    assert "Phase 26" in body["methodology"]["token_source"]
    assert "minimum cache tokens" in body["methodology"]["caching"]

    # 월간 데이터 3종 (1k/10k/50k) + realized/assumed 둘 다
    assert len(body["monthly_at_scale"]) == 3
    monthly = body["monthly_at_scale"][0]
    assert "monthly_realistic_sonnet_usd" in monthly
    assert "monthly_mixed_batch_usd" in monthly
    assert "monthly_savings_vs_realistic_realized_usd" in monthly
    assert "monthly_savings_vs_realistic_assumed_usd" in monthly


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
