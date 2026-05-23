"""
Bulk Analysis Async Module

Phase 1: 여러 IOC를 병렬로 분석 (4개 Worker Agent, Manager 없음)
Phase 2: 전체 결과 Aggregation (종합 분석)

기존 deep_analysis의 도구와 스키마를 재사용하며,
프롬프트만 독립 실행용으로 수정됨
"""

from .routers import bulk_analysis_router
from .service import BulkAnalysisService, get_bulk_analysis_service
from .crew import BulkAnalysisOrchestrator

__all__ = [
    'bulk_analysis_router',
    'BulkAnalysisService',
    'get_bulk_analysis_service',
    'BulkAnalysisOrchestrator'
]
