"""
KISA IoC Service - OpenAPI 호출 및 동기화
"""

import requests
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from ..models.threat_intel_models import KISAIoC, KISASyncHistory
from ..crud.kisa_crud import KISAIoCCRUD, KISASyncHistoryCRUD

logger = logging.getLogger(__name__)

# KISA OpenAPI 설정
KISA_BASE_URL = "https://api.odcloud.kr/api"
DATASET_ENDPOINTS = {
    "20240531": "/15128323/v1/uddi:ad42b077-6385-43f4-96b5-beab88f87d87",
    "20250113": "/15128323/v1/uddi:5b097095-4d21-4204-b25c-c1a3181a65ff"
}


class KISAIoCService:
    """KISA IoC OpenAPI 통합 서비스"""

    @staticmethod
    def _fetch_kisa_data(
        service_key: str,
        dataset_version: str,
        page: int = 1,
        per_page: int = 1000
    ) -> Dict[str, Any]:
        """
        KISA OpenAPI에서 데이터 가져오기

        Args:
            service_key: KISA OpenAPI 인증키
            dataset_version: 데이터셋 버전 (20240531, 20250113)
            page: 페이지 번호
            per_page: 페이지당 레코드 수

        Returns:
            API 응답 데이터
        """
        endpoint = DATASET_ENDPOINTS.get(dataset_version)
        if not endpoint:
            raise ValueError(f"Unsupported dataset version: {dataset_version}")

        url = f"{KISA_BASE_URL}{endpoint}"
        params = {
            "serviceKey": service_key,
            "page": page,
            "perPage": per_page,
            "returnType": "JSON"
        }

        try:
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()
            logger.info(f"KISA API Response - Page {page}, Total: {data.get('totalCount', 0)}")
            return data

        except requests.exceptions.RequestException as e:
            logger.error(f"KISA API request failed: {e}")
            raise Exception(f"Failed to fetch KISA data: {str(e)}")

    @staticmethod
    def _parse_ioc_data(raw_data: Dict[str, Any], dataset_version: str) -> Dict[str, Any]:
        """
        API 응답 데이터를 DB 모델 형식으로 변환

        Args:
            raw_data: KISA API 응답 데이터 (단일 레코드)
            dataset_version: 데이터셋 버전

        Returns:
            DB 모델 형식의 딕셔너리
        """
        return {
            'attack_date': raw_data.get('날짜', ''),
            'attack_ip': raw_data.get('공격 IP', ''),
            'attack_country': raw_data.get('공격 IP 국가'),
            'attack_action': raw_data.get('수행 행위'),
            'description': f"Detected {raw_data.get('수행 행위', 'threat')} from {raw_data.get('공격 IP 국가', 'unknown location')}",
            'dataset_version': dataset_version
        }

    @staticmethod
    def sync_kisa_data(
        db: Session,
        service_key: str,
        dataset_version: str = "latest",
        force_update: bool = False
    ) -> KISASyncHistory:
        """
        KISA IoC 데이터 동기화

        Args:
            db: 데이터베이스 세션
            service_key: KISA OpenAPI 인증키
            dataset_version: 데이터셋 버전 ("latest", "20240531", "20250113")
            force_update: 기존 데이터 덮어쓰기 여부

        Returns:
            동기화 이력 객체
        """
        # API 키 디버깅
        logger.info(f"Received service_key (first 20 chars): {service_key[:20] if len(service_key) > 20 else service_key}")
        logger.info(f"Service key length: {len(service_key)}")

        # 최신 버전 자동 선택
        if dataset_version == "latest":
            dataset_version = "20250113"  # 가장 최신 버전

        # 동기화 이력 생성
        history = KISASyncHistoryCRUD.create_history(db, {
            'dataset_version': dataset_version,
            'sync_status': 'started'
        })

        try:
            # 기존 데이터 삭제 (force_update인 경우)
            if force_update:
                deleted = KISAIoCCRUD.delete_by_version(db, dataset_version)
                logger.info(f"Deleted {deleted} existing records for version {dataset_version}")

            total_records = 0
            new_records = 0
            failed_records = 0

            # 첫 페이지 요청으로 총 레코드 수 확인
            first_page = KISAIoCService._fetch_kisa_data(service_key, dataset_version, page=1)
            total_count = first_page.get('totalCount', 0)
            per_page = first_page.get('perPage', 1000)

            logger.info(f"Starting sync for dataset {dataset_version}: {total_count} total records")

            # 모든 페이지 처리
            current_page = 1
            total_pages = (total_count + per_page - 1) // per_page  # 올림 계산

            while current_page <= total_pages:
                try:
                    if current_page == 1:
                        page_data = first_page
                    else:
                        page_data = KISAIoCService._fetch_kisa_data(
                            service_key,
                            dataset_version,
                            page=current_page
                        )

                    # 데이터 파싱 및 저장
                    records = page_data.get('data', [])
                    iocs_data = []

                    for record in records:
                        try:
                            ioc_data = KISAIoCService._parse_ioc_data(record, dataset_version)
                            iocs_data.append(ioc_data)
                        except Exception as e:
                            logger.error(f"Failed to parse record: {e}")
                            failed_records += 1

                    # 대량 삽입
                    if iocs_data:
                        created = KISAIoCCRUD.bulk_create_iocs(db, iocs_data)
                        new_records += created
                        total_records += len(iocs_data)

                    logger.info(f"Processed page {current_page}/{total_pages}")
                    current_page += 1

                except Exception as e:
                    logger.error(f"Failed to process page {current_page}: {e}")
                    failed_records += per_page
                    current_page += 1

            # 동기화 완료 업데이트
            KISASyncHistoryCRUD.update_history(db, history.id, {
                'sync_status': 'completed',
                'total_records': total_records,
                'new_records': new_records,
                'failed_records': failed_records,
                'completed_at': datetime.utcnow()
            })

            logger.info(f"Sync completed: {new_records} new, {failed_records} failed")
            return history

        except Exception as e:
            # 에러 시 이력 업데이트
            logger.error(f"Sync failed: {e}")
            KISASyncHistoryCRUD.update_history(db, history.id, {
                'sync_status': 'failed',
                'error_message': str(e),
                'completed_at': datetime.utcnow()
            })
            raise

    @staticmethod
    def get_sync_statistics(db: Session, dataset_version: Optional[str] = None) -> Dict[str, Any]:
        """
        동기화 통계 조회

        Args:
            db: 데이터베이스 세션
            dataset_version: 특정 버전 (없으면 전체)

        Returns:
            통계 정보
        """
        latest_sync = KISASyncHistoryCRUD.get_latest_history(db, dataset_version)

        total_iocs = KISAIoCCRUD.count_iocs(db, dataset_version=dataset_version)
        selected_iocs = KISAIoCCRUD.count_iocs(db, dataset_version=dataset_version, is_selected=True)
        blocked_iocs = KISAIoCCRUD.count_iocs(db, dataset_version=dataset_version, is_blocked=True)

        # 차트용 데이터 집계
        country_dist = KISAIoCCRUD.get_country_distribution(db, dataset_version)
        attack_type_dist = KISAIoCCRUD.get_attack_type_distribution(db, dataset_version)

        return {
            'total_iocs': total_iocs,
            'selected_iocs': selected_iocs,
            'blocked_iocs': blocked_iocs,
            'latest_sync': latest_sync.to_dict() if latest_sync else None,
            'country_distribution': country_dist,
            'attack_type_distribution': attack_type_dist
        }
