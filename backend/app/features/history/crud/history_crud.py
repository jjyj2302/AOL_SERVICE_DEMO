"""
History CRUD - 데이터베이스 CRUD 함수
"""

import os
import uuid
import json
from typing import List, Optional, Tuple
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..models.history_models import (
    UploadedFile,
    AnalysisSession,
    IocAnalysis,
    AggregationResult
)

# 파일 저장 디렉토리
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'uploads')


def ensure_upload_dir():
    """업로드 디렉토리 생성"""
    abs_path = os.path.abspath(UPLOAD_DIR)
    if not os.path.exists(abs_path):
        os.makedirs(abs_path)
    return abs_path


# ===== UploadedFile CRUD =====
def create_uploaded_file(
    db: Session,
    filename: str,
    file_content: bytes,
    mime_type: Optional[str] = None
) -> UploadedFile:
    """파일 저장 및 DB 레코드 생성"""
    upload_dir = ensure_upload_dir()

    # UUID로 저장 파일명 생성
    ext = os.path.splitext(filename)[1]
    stored_filename = f"{uuid.uuid4()}{ext}"
    file_path = os.path.join(upload_dir, stored_filename)

    # 파일 저장
    with open(file_path, 'wb') as f:
        f.write(file_content)

    # DB 레코드 생성
    db_file = UploadedFile(
        filename=filename,
        stored_filename=stored_filename,
        file_path=file_path,
        file_size=len(file_content),
        mime_type=mime_type
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)
    return db_file


def get_uploaded_file(db: Session, file_id: int) -> Optional[UploadedFile]:
    """파일 조회"""
    return db.query(UploadedFile).filter(UploadedFile.id == file_id).first()


# ===== AnalysisSession CRUD =====
def create_session(
    db: Session,
    source_type: str,
    session_name: Optional[str] = None,
    uploaded_file_id: Optional[int] = None,
    total_iocs: int = 0
) -> AnalysisSession:
    """분석 세션 생성"""
    db_session = AnalysisSession(
        session_name=session_name,
        source_type=source_type,
        uploaded_file_id=uploaded_file_id,
        total_iocs=total_iocs,
        status='pending'
    )
    db.add(db_session)
    db.commit()
    db.refresh(db_session)
    return db_session


def get_session(db: Session, session_id: int) -> Optional[AnalysisSession]:
    """세션 조회 (IOC 분석 결과 및 Aggregation 포함)"""
    return db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()


def get_sessions(
    db: Session,
    page: int = 1,
    page_size: int = 20,
    status: Optional[str] = None
) -> Tuple[List[AnalysisSession], int]:
    """세션 목록 조회 (페이지네이션)"""
    query = db.query(AnalysisSession)

    if status:
        query = query.filter(AnalysisSession.status == status)

    total = query.count()
    sessions = query.order_by(desc(AnalysisSession.created_at))\
                    .offset((page - 1) * page_size)\
                    .limit(page_size)\
                    .all()

    return sessions, total


def update_session_status(
    db: Session,
    session_id: int,
    status: str,
    total_iocs: Optional[int] = None
) -> Optional[AnalysisSession]:
    """세션 상태 업데이트"""
    db_session = get_session(db, session_id)
    if db_session:
        db_session.status = status
        if total_iocs is not None:
            db_session.total_iocs = total_iocs
        if status == 'completed':
            db_session.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(db_session)
    return db_session


def delete_session(db: Session, session_id: int) -> bool:
    """세션 삭제 (관련 IOC 분석, Aggregation, 파일도 함께 삭제)"""
    db_session = get_session(db, session_id)
    if db_session:
        # 업로드된 파일 삭제
        if db_session.uploaded_file:
            file_path = db_session.uploaded_file.file_path
            if os.path.exists(file_path):
                os.remove(file_path)
            db.delete(db_session.uploaded_file)

        db.delete(db_session)
        db.commit()
        return True
    return False


# ===== IocAnalysis CRUD =====
def create_ioc_analysis(
    db: Session,
    session_id: int,
    ioc_value: str,
    ioc_type: Optional[str] = None,
    triage_result: Optional[dict] = None,
    malware_result: Optional[dict] = None,
    infrastructure_result: Optional[dict] = None,
    campaign_result: Optional[dict] = None,
    overall_threat_level: Optional[str] = None
) -> IocAnalysis:
    """IOC 분석 결과 저장"""
    db_ioc = IocAnalysis(
        session_id=session_id,
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        triage_result=json.dumps(triage_result, ensure_ascii=False) if triage_result else None,
        malware_result=json.dumps(malware_result, ensure_ascii=False) if malware_result else None,
        infrastructure_result=json.dumps(infrastructure_result, ensure_ascii=False) if infrastructure_result else None,
        campaign_result=json.dumps(campaign_result, ensure_ascii=False) if campaign_result else None,
        overall_threat_level=overall_threat_level
    )
    db.add(db_ioc)
    db.commit()
    db.refresh(db_ioc)
    return db_ioc


def get_ioc_analyses_by_session(db: Session, session_id: int) -> List[IocAnalysis]:
    """세션의 모든 IOC 분석 결과 조회"""
    return db.query(IocAnalysis).filter(IocAnalysis.session_id == session_id).all()


# ===== AggregationResult CRUD =====
def create_aggregation(
    db: Session,
    session_id: int,
    aggregated_report: dict
) -> AggregationResult:
    """종합 분석 결과 저장"""
    db_agg = AggregationResult(
        session_id=session_id,
        aggregated_report=json.dumps(aggregated_report, ensure_ascii=False)
    )
    db.add(db_agg)
    db.commit()
    db.refresh(db_agg)
    return db_agg


def get_aggregation_by_session(db: Session, session_id: int) -> Optional[AggregationResult]:
    """세션의 종합 분석 결과 조회"""
    return db.query(AggregationResult).filter(AggregationResult.session_id == session_id).first()


# ===== Search =====
def search_iocs(db: Session, query: str, limit: int = 50) -> List[IocAnalysis]:
    """IOC 값으로 검색"""
    return db.query(IocAnalysis)\
             .filter(IocAnalysis.ioc_value.ilike(f'%{query}%'))\
             .limit(limit)\
             .all()
