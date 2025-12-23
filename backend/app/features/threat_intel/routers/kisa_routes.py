"""
KISA IoC API Routes
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.dependencies import get_db
from ..models.threat_intel_models import KISAIoC
from ..schemas.kisa_schemas import (
    KISAIoCResponse,
    KISAIoCListResponse,
    KISASyncRequest,
    KISASyncResponse,
    KISASelectRequest,
    KISAFirewallRequest,
    KISAFirewallResponse,
    DatasetVersion
)
from ..crud.kisa_crud import KISAIoCCRUD, KISASyncHistoryCRUD
from ..service.kisa_service import KISAIoCService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/kisa-ioc", tags=["KISA IoC"])


@router.get("/health")
async def health_check():
    """KISA IoC 서비스 상태 확인"""
    return {
        "status": "healthy",
        "service": "KISA IoC Integration",
        "available_versions": ["20240531", "20250113"]
    }


@router.post("/sync", response_model=KISASyncResponse)
async def sync_kisa_data(
    request: KISASyncRequest,
    db: Session = Depends(get_db)
):
    """
    KISA IoC 데이터 동기화

    - **dataset_version**: 동기화할 데이터셋 버전 (latest, 20240531, 20250113)
    - **service_key**: KISA OpenAPI 인증키
    - **force_update**: 기존 데이터 덮어쓰기 여부
    """
    try:
        history = KISAIoCService.sync_kisa_data(
            db=db,
            service_key=request.service_key,
            dataset_version=request.dataset_version.value,
            force_update=request.force_update
        )

        return KISASyncResponse(
            sync_id=history.id,
            dataset_version=history.dataset_version,
            sync_status=history.sync_status,
            total_records=history.total_records,
            new_records=history.new_records,
            updated_records=history.updated_records,
            failed_records=history.failed_records,
            error_message=history.error_message,
            started_at=history.started_at.isoformat(),
            completed_at=history.completed_at.isoformat() if history.completed_at else None
        )

    except Exception as e:
        logger.error(f"Sync failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_statistics(
    dataset_version: Optional[str] = Query(None, description="특정 버전의 통계 (없으면 전체)"),
    db: Session = Depends(get_db)
):
    """
    KISA IoC 통계 조회

    - 전체 IoC 수
    - 선택된 IoC 수
    - 방화벽 적용된 IoC 수
    - 최근 동기화 이력
    """
    try:
        stats = KISAIoCService.get_sync_statistics(db, dataset_version)
        return stats
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/iocs", response_model=KISAIoCListResponse)
async def get_iocs(
    page: int = Query(1, ge=1, description="페이지 번호"),
    per_page: int = Query(100, ge=1, le=1000, description="페이지당 레코드 수"),
    dataset_version: Optional[str] = Query(None, description="데이터셋 버전 필터"),
    is_selected: Optional[bool] = Query(None, description="선택된 IoC만 조회"),
    is_blocked: Optional[bool] = Query(None, description="방화벽 적용된 IoC만 조회"),
    country: Optional[str] = Query(None, description="국가로 검색"),
    ip_search: Optional[str] = Query(None, description="IP 주소로 검색"),
    db: Session = Depends(get_db)
):
    """
    KISA IoC 목록 조회

    - 페이지네이션 지원
    - 다양한 필터 옵션
    """
    try:
        skip = (page - 1) * per_page

        iocs = KISAIoCCRUD.get_iocs(
            db=db,
            skip=skip,
            limit=per_page,
            dataset_version=dataset_version,
            is_selected=is_selected,
            is_blocked=is_blocked,
            country=country,
            ip_search=ip_search
        )

        total = KISAIoCCRUD.count_iocs(
            db=db,
            dataset_version=dataset_version,
            is_selected=is_selected,
            is_blocked=is_blocked,
            country=country,
            ip_search=ip_search
        )

        return KISAIoCListResponse(
            total=total,
            page=page,
            per_page=per_page,
            data=[KISAIoCResponse(**ioc.to_dict()) for ioc in iocs]
        )

    except Exception as e:
        logger.error(f"Failed to get IoCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/iocs/{ioc_id}", response_model=KISAIoCResponse)
async def get_ioc(
    ioc_id: int,
    db: Session = Depends(get_db)
):
    """단일 KISA IoC 조회"""
    ioc = KISAIoCCRUD.get_ioc_by_id(db, ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IoC not found")

    return KISAIoCResponse(**ioc.to_dict())


@router.post("/select")
async def select_iocs(
    request: KISASelectRequest,
    db: Session = Depends(get_db)
):
    """
    KISA IoC 선택/선택 해제

    - 방화벽 규칙 적용 전 IoC를 선택합니다.
    """
    try:
        updated_count = KISAIoCCRUD.update_selection(
            db=db,
            ioc_ids=request.ioc_ids,
            is_selected=request.is_selected
        )

        return {
            "success": True,
            "updated_count": updated_count,
            "is_selected": request.is_selected,
            "message": f"{updated_count} IoC(s) {'selected' if request.is_selected else 'unselected'}"
        }

    except Exception as e:
        logger.error(f"Failed to update selection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/firewall/apply", response_model=KISAFirewallResponse)
async def apply_firewall_rules(
    request: KISAFirewallRequest,
    db: Session = Depends(get_db)
):
    """
    방화벽 규칙 적용 (시뮬레이션)

    - 실제 방화벽에는 전송하지 않고, DB에만 기록합니다.
    - 선택된 IoC에 대해 방화벽 규칙을 생성합니다.
    """
    try:
        # IoC 조회
        applied_iocs = []
        failed_iocs = []
        firewall_rules = []
        errors = []

        for ioc_id in request.ioc_ids:
            ioc = KISAIoCCRUD.get_ioc_by_id(db, ioc_id)
            if not ioc:
                failed_iocs.append(ioc_id)
                errors.append(f"IoC ID {ioc_id} not found")
                continue

            # 방화벽 규칙 생성 (시뮬레이션)
            rule_name = f"{request.rule_name_prefix}_{ioc.attack_ip.replace('.', '_')}"

            firewall_rule = {
                "rule_name": rule_name,
                "ioc_id": ioc.id,
                "ip_address": ioc.attack_ip,
                "action": request.action,
                "firewall_type": request.firewall_type,
                "country": ioc.attack_country,
                "attack_date": ioc.attack_date
            }
            firewall_rules.append(firewall_rule)
            applied_iocs.append(ioc_id)

        # DB 업데이트
        if applied_iocs:
            KISAIoCCRUD.update_firewall_status(
                db=db,
                ioc_ids=applied_iocs,
                is_blocked=True,
                firewall_rule_name=f"{request.rule_name_prefix}_*"
            )

        return KISAFirewallResponse(
            total_iocs=len(request.ioc_ids),
            applied_iocs=len(applied_iocs),
            failed_iocs=len(failed_iocs),
            firewall_rules=firewall_rules,
            errors=errors if errors else None
        )

    except Exception as e:
        logger.error(f"Failed to apply firewall rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sync-history")
async def get_sync_history(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """동기화 이력 조회"""
    try:
        skip = (page - 1) * per_page
        histories = KISASyncHistoryCRUD.get_histories(db, skip=skip, limit=per_page)

        return {
            "page": page,
            "per_page": per_page,
            "data": [h.to_dict() for h in histories]
        }

    except Exception as e:
        logger.error(f"Failed to get sync history: {e}")
        raise HTTPException(status_code=500, detail=str(e))
