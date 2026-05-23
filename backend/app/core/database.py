"""SQLAlchemy 엔진/세션 구성.

DATABASE_URL 환경변수가 지정되어 있으면 우선 사용한다 (PostgreSQL 권장).
미지정 시 로컬 개발 편의를 위해 SQLite (data/aol_data.db) 로 폴백한다.

권장 형식:
  PostgreSQL: postgresql+psycopg2://user:pass@host:5432/dbname
  SQLite (fallback): sqlite:///./data/aol_data.db
"""
from __future__ import annotations

import logging
import os

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)

DEFAULT_SQLITE_URL = "sqlite:///./data/aol_data.db"
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL)

# SQLite 인지 여부에 따라 connect_args 가 달라짐
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
    logger.info("Database engine: SQLite (fallback) at %s", SQLALCHEMY_DATABASE_URL)
else:
    # PostgreSQL / MySQL 등 — 운영 환경
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,    # 끊긴 연결 자동 감지
        pool_recycle=3600,     # 1시간 후 커넥션 재활용 (RDS idle timeout 회피)
        future=True,
    )
    # URL 의 비밀번호를 로그에서 마스킹
    safe_url = SQLALCHEMY_DATABASE_URL.split("@")[-1] if "@" in SQLALCHEMY_DATABASE_URL else SQLALCHEMY_DATABASE_URL
    logger.info("Database engine: external (PostgreSQL/MySQL) at %s", safe_url)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
