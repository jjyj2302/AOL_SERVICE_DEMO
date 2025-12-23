"""
History Routes - 분석 히스토리 API 엔드포인트
"""

import os
import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from ..crud import history_crud
from ..schemas.history_schemas import (
    SessionResponse,
    SessionListResponse,
    IocAnalysisResponse
)

router = APIRouter(prefix="/api/history", tags=["History"])


def get_db():
    """DB 세션 의존성"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/sessions", response_model=SessionListResponse)
async def get_sessions(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    분석 세션 목록 조회 (페이지네이션)

    - **page**: 페이지 번호 (1부터 시작)
    - **page_size**: 페이지당 항목 수 (최대 100)
    - **status**: 상태 필터 (pending, processing, completed, error)
    """
    sessions, total = history_crud.get_sessions(db, page, page_size, status)

    return SessionListResponse(
        sessions=[SessionResponse(
            id=s.id,
            session_name=s.session_name,
            source_type=s.source_type,
            uploaded_file=s.uploaded_file.to_dict() if s.uploaded_file else None,
            total_iocs=s.total_iocs,
            status=s.status,
            created_at=s.created_at,
            completed_at=s.completed_at
        ) for s in sessions],
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/sessions/{session_id}")
async def get_session(
    session_id: int,
    db: Session = Depends(get_db)
):
    """
    특정 세션 상세 조회 (IOC 분석 결과 + Aggregation 포함)
    """
    session = history_crud.get_session(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # IOC 분석 결과들
    ioc_analyses = history_crud.get_ioc_analyses_by_session(db, session_id)

    # JSON 문자열 파싱
    parsed_iocs = []
    for ioc in ioc_analyses:
        parsed_ioc = {
            'id': ioc.id,
            'ioc_value': ioc.ioc_value,
            'ioc_type': ioc.ioc_type,
            'overall_threat_level': ioc.overall_threat_level,
            'created_at': ioc.created_at.isoformat() if ioc.created_at else None,
            'triage_result': json.loads(ioc.triage_result) if ioc.triage_result else None,
            'malware_result': json.loads(ioc.malware_result) if ioc.malware_result else None,
            'infrastructure_result': json.loads(ioc.infrastructure_result) if ioc.infrastructure_result else None,
            'campaign_result': json.loads(ioc.campaign_result) if ioc.campaign_result else None,
        }
        parsed_iocs.append(parsed_ioc)

    # Aggregation 결과
    aggregation = history_crud.get_aggregation_by_session(db, session_id)
    parsed_aggregation = None
    if aggregation:
        parsed_aggregation = {
            'id': aggregation.id,
            'aggregated_report': json.loads(aggregation.aggregated_report) if aggregation.aggregated_report else None,
            'created_at': aggregation.created_at.isoformat() if aggregation.created_at else None
        }

    return {
        'id': session.id,
        'session_name': session.session_name,
        'source_type': session.source_type,
        'uploaded_file': session.uploaded_file.to_dict() if session.uploaded_file else None,
        'total_iocs': session.total_iocs,
        'status': session.status,
        'created_at': session.created_at.isoformat() if session.created_at else None,
        'completed_at': session.completed_at.isoformat() if session.completed_at else None,
        'ioc_analyses': parsed_iocs,
        'aggregation': parsed_aggregation
    }


@router.delete("/sessions/{session_id}")
async def delete_session(
    session_id: int,
    db: Session = Depends(get_db)
):
    """
    세션 삭제 (관련 IOC 분석, Aggregation, 업로드 파일 모두 삭제)
    """
    success = history_crud.delete_session(db, session_id)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found")

    return {"message": "Session deleted successfully", "session_id": session_id}


@router.get("/search")
async def search_iocs(
    q: str = Query(..., min_length=1, description="검색할 IOC 값"),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """
    IOC 값으로 검색
    """
    results = history_crud.search_iocs(db, q, limit)

    return {
        'query': q,
        'count': len(results),
        'results': [
            {
                'id': ioc.id,
                'session_id': ioc.session_id,
                'ioc_value': ioc.ioc_value,
                'ioc_type': ioc.ioc_type,
                'overall_threat_level': ioc.overall_threat_level,
                'created_at': ioc.created_at.isoformat() if ioc.created_at else None
            }
            for ioc in results
        ]
    }


@router.get("/files/{file_id}")
async def get_file(
    file_id: int,
    db: Session = Depends(get_db)
):
    """
    업로드된 파일 다운로드/조회
    """
    uploaded_file = history_crud.get_uploaded_file(db, file_id)
    if not uploaded_file:
        raise HTTPException(status_code=404, detail="File not found")

    if not os.path.exists(uploaded_file.file_path):
        raise HTTPException(status_code=404, detail="File not found on disk")

    return FileResponse(
        path=uploaded_file.file_path,
        filename=uploaded_file.filename,
        media_type=uploaded_file.mime_type or 'application/octet-stream'
    )


@router.get("/files/{file_id}/info")
async def get_file_info(
    file_id: int,
    db: Session = Depends(get_db)
):
    """
    업로드된 파일 정보 조회
    """
    uploaded_file = history_crud.get_uploaded_file(db, file_id)
    if not uploaded_file:
        raise HTTPException(status_code=404, detail="File not found")

    return uploaded_file.to_dict()
