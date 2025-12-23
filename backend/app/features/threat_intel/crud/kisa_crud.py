"""
KISA IoC CRUD Operations
"""

from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from datetime import datetime

from ..models.threat_intel_models import KISAIoC, KISASyncHistory


class KISAIoCCRUD:
    """KISA IoC 데이터베이스 작업"""

    @staticmethod
    def create_ioc(db: Session, ioc_data: dict) -> KISAIoC:
        """IoC 생성"""
        ioc = KISAIoC(**ioc_data)
        db.add(ioc)
        db.commit()
        db.refresh(ioc)
        return ioc

    @staticmethod
    def bulk_create_iocs(db: Session, iocs_data: List[dict]) -> int:
        """대량 IoC 생성 (중복 무시)"""
        # 배치 내 중복 제거 (attack_ip, attack_date, dataset_version 조합 기준)
        seen = set()
        unique_iocs_data = []

        for ioc_data in iocs_data:
            key = (
                ioc_data.get('attack_ip'),
                ioc_data.get('attack_date'),
                ioc_data.get('dataset_version')
            )

            if key not in seen:
                seen.add(key)
                unique_iocs_data.append(ioc_data)

        created_count = 0
        for ioc_data in unique_iocs_data:
            try:
                # DB 중복 체크
                existing = db.query(KISAIoC).filter(
                    and_(
                        KISAIoC.attack_ip == ioc_data['attack_ip'],
                        KISAIoC.attack_date == ioc_data['attack_date'],
                        KISAIoC.dataset_version == ioc_data.get('dataset_version')
                    )
                ).first()

                if existing:
                    # 업데이트
                    for key, value in ioc_data.items():
                        setattr(existing, key, value)
                else:
                    # 새로 생성
                    ioc = KISAIoC(**ioc_data)
                    db.add(ioc)
                    created_count += 1

            except Exception as e:
                print(f"Failed to create IoC: {e}")
                continue

        db.commit()
        return created_count

    @staticmethod
    def get_ioc_by_id(db: Session, ioc_id: int) -> Optional[KISAIoC]:
        """ID로 IoC 조회"""
        return db.query(KISAIoC).filter(KISAIoC.id == ioc_id).first()

    @staticmethod
    def get_iocs(
        db: Session,
        skip: int = 0,
        limit: int = 100,
        dataset_version: Optional[str] = None,
        is_selected: Optional[bool] = None,
        is_blocked: Optional[bool] = None,
        country: Optional[str] = None,
        ip_search: Optional[str] = None
    ) -> List[KISAIoC]:
        """IoC 목록 조회"""
        query = db.query(KISAIoC)

        if dataset_version:
            query = query.filter(KISAIoC.dataset_version == dataset_version)
        if is_selected is not None:
            query = query.filter(KISAIoC.is_selected == is_selected)
        if is_blocked is not None:
            query = query.filter(KISAIoC.is_blocked == is_blocked)
        if country:
            query = query.filter(KISAIoC.attack_country.ilike(f"%{country}%"))
        if ip_search:
            # Multi-field search
            search_term = f"%{ip_search}%"
            query = query.filter(
                or_(
                    KISAIoC.attack_ip.like(search_term),
                    KISAIoC.attack_country.ilike(search_term),
                    KISAIoC.attack_action.ilike(search_term),
                    KISAIoC.description.ilike(search_term)
                )
            )

        return query.order_by(KISAIoC.created_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def count_iocs(
        db: Session,
        dataset_version: Optional[str] = None,
        is_selected: Optional[bool] = None,
        is_blocked: Optional[bool] = None,
        country: Optional[str] = None,
        ip_search: Optional[str] = None
    ) -> int:
        """IoC 개수 조회"""
        query = db.query(func.count(KISAIoC.id))

        if dataset_version:
            query = query.filter(KISAIoC.dataset_version == dataset_version)
        if is_selected is not None:
            query = query.filter(KISAIoC.is_selected == is_selected)
        if is_blocked is not None:
            query = query.filter(KISAIoC.is_blocked == is_blocked)
        if country:
            query = query.filter(KISAIoC.attack_country.ilike(f"%{country}%"))
        if ip_search:
            query = query.filter(KISAIoC.attack_ip.like(f"%{ip_search}%"))

        return query.scalar()

    @staticmethod
    def get_country_distribution(
        db: Session,
        dataset_version: Optional[str] = None
    ) -> List[dict]:
        """국가별 분포 조회"""
        query = db.query(
            KISAIoC.attack_country.label('name'),
            func.count(KISAIoC.id).label('value')
        )

        if dataset_version:
            query = query.filter(KISAIoC.dataset_version == dataset_version)
        
        # None 국가 필터링 및 이름 변경
        results = query.group_by(KISAIoC.attack_country).order_by(func.count(KISAIoC.id).desc()).limit(5).all()
        
        return [
            {'name': r.name or 'Unknown', 'value': r.value} 
            for r in results
        ]

    @staticmethod
    def get_attack_type_distribution(
        db: Session,
        dataset_version: Optional[str] = None
    ) -> List[dict]:
        """공격 유형별 분포 조회"""
        query = db.query(
            KISAIoC.attack_action.label('name'),
            func.count(KISAIoC.id).label('value')
        )

        if dataset_version:
            query = query.filter(KISAIoC.dataset_version == dataset_version)

        results = query.group_by(KISAIoC.attack_action).order_by(func.count(KISAIoC.id).desc()).limit(5).all()
        
        return [
            {'name': r.name or 'Unknown', 'value': r.value} 
            for r in results
        ]

    @staticmethod
    def update_selection(db: Session, ioc_ids: List[int], is_selected: bool) -> int:
        """IoC 선택 상태 업데이트"""
        updated = db.query(KISAIoC).filter(KISAIoC.id.in_(ioc_ids)).update(
            {
                'is_selected': is_selected,
                'selected_at': datetime.utcnow() if is_selected else None
            },
            synchronize_session=False
        )
        db.commit()
        return updated

    @staticmethod
    def update_firewall_status(
        db: Session,
        ioc_ids: List[int],
        is_blocked: bool,
        firewall_rule_name: Optional[str] = None
    ) -> int:
        """방화벽 적용 상태 업데이트"""
        updated = db.query(KISAIoC).filter(KISAIoC.id.in_(ioc_ids)).update(
            {
                'is_blocked': is_blocked,
                'blocked_at': datetime.utcnow() if is_blocked else None,
                'firewall_rule_name': firewall_rule_name
            },
            synchronize_session=False
        )
        db.commit()
        return updated

    @staticmethod
    def delete_by_version(db: Session, dataset_version: str) -> int:
        """특정 버전의 IoC 삭제"""
        deleted = db.query(KISAIoC).filter(
            KISAIoC.dataset_version == dataset_version
        ).delete()
        db.commit()
        return deleted


class KISASyncHistoryCRUD:
    """KISA 동기화 이력 CRUD"""

    @staticmethod
    def create_history(db: Session, history_data: dict) -> KISASyncHistory:
        """동기화 이력 생성"""
        history = KISASyncHistory(**history_data)
        db.add(history)
        db.commit()
        db.refresh(history)
        return history

    @staticmethod
    def update_history(db: Session, history_id: int, update_data: dict) -> Optional[KISASyncHistory]:
        """동기화 이력 업데이트"""
        history = db.query(KISASyncHistory).filter(KISASyncHistory.id == history_id).first()
        if history:
            for key, value in update_data.items():
                setattr(history, key, value)
            db.commit()
            db.refresh(history)
        return history

    @staticmethod
    def get_latest_history(db: Session, dataset_version: Optional[str] = None) -> Optional[KISASyncHistory]:
        """최신 동기화 이력 조회"""
        query = db.query(KISASyncHistory)
        if dataset_version:
            query = query.filter(KISASyncHistory.dataset_version == dataset_version)
        return query.order_by(KISASyncHistory.started_at.desc()).first()

    @staticmethod
    def get_histories(db: Session, skip: int = 0, limit: int = 20) -> List[KISASyncHistory]:
        """동기화 이력 목록 조회"""
        return db.query(KISASyncHistory).order_by(
            KISASyncHistory.started_at.desc()
        ).offset(skip).limit(limit).all()
