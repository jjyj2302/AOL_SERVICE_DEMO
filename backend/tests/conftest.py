"""Pytest 공통 설정.

본 테스트 슈트는 신규 LangGraph 모듈을 대상으로 한다.
외부 LLM/MCP 호출 없이도 동작하도록 시뮬레이션 모드 기준으로만 검증.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# backend 루트를 sys.path 에 추가 (uvicorn 실행 시와 동일 경로)
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

# 테스트는 SQLite 인메모리/임시 DB 로만 동작 — 운영 PostgreSQL 접근 차단
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
