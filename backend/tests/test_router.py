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
