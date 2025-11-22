"""
API Key 캐싱 시스템

서버 시작 시 또는 API 키 변경 시
모든 API 키를 DB에서 로드하여 메모리에 캐싱.
매 요청마다 DB 조회하는 대신 메모리에서 O(1)로 조회.
"""

from typing import Dict, Optional
from sqlalchemy.orm import Session
import os                      # ✅ 추가
import logging                 # ✅ 추가

from .crud.api_keys_settings_crud import get_apikey as db_get_apikey
from .config.service_config import SERVICE_DEFINITIONS

logger = logging.getLogger(__name__)


class APIKeyCache:
    """API 키 메모리 캐시 (싱글톤)"""

    _instance: Optional['APIKeyCache'] = None
    _cache: Dict[str, dict] = {}
    _initialized: bool = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(APIKeyCache, cls).__new__(cls)
        return cls._instance

    @classmethod
    def get_instance(cls) -> 'APIKeyCache':
        """싱글톤 인스턴스 반환"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def load_all_keys(self, db: Session) -> None:
        """
        DB에서 모든 API 키 로드하여 캐시에 저장하고,
        상태 로그 및 주요 ENV(openai 등)를 동기화한다.

        - 서버 시작 시(lifespan/startup) 호출
        - API 키 생성/수정/삭제 시에도 다시 호출 가능
        """
        print("Loading API keys into cache...")

        loaded_count = 0
        active_count = 0

        # ✅ ENV 초기화: 매번 전체 상태 재계산
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ.pop("LITELLM_API_KEY", None)
        # 필요하면 여기서 gemini/claude도 같이 초기화 가능
        # os.environ.pop("GEMINI_API_KEY", None)
        # os.environ.pop("ANTHROPIC_API_KEY", None)

        # 26개 서비스의 모든 required_keys 순회
        for service_key, service_def in SERVICE_DEFINITIONS.items():
            required_keys = (
                service_def.required_keys if service_def.required_keys else [service_key]
            )

            for key_name in required_keys:
                # DB 조회 (dict 형태: {name, key, is_active, bulk_ioc_lookup})
                key_data = db_get_apikey(db, key_name)

                # 캐시 저장
                self._cache[key_name] = key_data
                loaded_count += 1

                key_value = (key_data.get("key") or "").strip()
                is_active = bool(key_value) and key_data.get("is_active", False)

                if is_active:
                    active_count += 1
                    status = "[ACTIVE]"
                else:
                    status = "[INACTIVE]"

                # 상태 로그 (키 값은 마스킹)
                if key_value:
                    masked = (
                        f"{key_value[:4]}...{key_value[-4:]}"
                        if len(key_value) > 8
                        else "***"
                    )
                    print(f"  {status} {key_name}: {masked}")
                else:
                    print(f"  {status} {key_name}: (empty)")

                # ✅ 여기서 openai ENV 동기화까지 같이 처리
                if key_name.lower() == "openai":
                    if is_active and key_value:
                        os.environ["OPENAI_API_KEY"] = key_value
                        os.environ["LITELLM_API_KEY"] = key_value
                        logger.info(
                            "Synced OPENAI_API_KEY / LITELLM_API_KEY from DB (openai)"
                        )
                    else:
                        # 이미 위에서 pop 했지만 상태 로그를 위해 한 번 더 기록
                        logger.info(
                            "OpenAI key inactive or empty; env variables cleared"
                        )

                # (원하면 gemini/claude도 여기서 동일 패턴으로 처리)

        self._initialized = True
        print(f"\nLoaded {loaded_count} keys ({active_count} active)\n")

    def get_key(self, name: str) -> dict:
        """
        캐시에서 API 키 조회

        Returns:
            {name, key, is_active, bulk_ioc_lookup} 딕셔너리
        """
        if not self._initialized:
            raise RuntimeError("APIKeyCache not initialized")

        # 캐시에 없으면 기본값 반환
        return self._cache.get(
            name,
            {
                "name": name,
                "key": "",
                "is_active": False,
                "bulk_ioc_lookup": False,
            },
        )

    def invalidate(self, name: Optional[str] = None) -> None:
        """캐시 무효화 (관리자 키 업데이트 시)"""
        if name:
            self._cache.pop(name, None)
            print(f"Cache invalidated: {name}")
        else:
            self._cache.clear()
            self._initialized = False
            print("Cache cleared")

    def reload_key(self, db: Session, name: str) -> None:
        """특정 키 DB에서 재로드 (부분 갱신이 필요할 때만 사용)"""
        key_data = db_get_apikey(db, name)
        self._cache[name] = key_data
        print(f"Reloaded: {name}")

    def get_cache_stats(self) -> dict:
        """캐시 통계"""
        total = len(self._cache)
        active = sum(1 for k in self._cache.values() if k.get("is_active"))
        configured = sum(1 for k in self._cache.values() if k.get("key"))

        return {
            "initialized": self._initialized,
            "total_keys": total,
            "active_keys": active,
            "configured_keys": configured,
        }


# 애플리케이션 코드에서 사용할 편의 함수

def get_apikey_cached(name: str) -> dict:
    """
    캐시에서 API 키 조회

    기존: get_apikey(db, "virustotal")  # DB 쿼리
    신규: get_apikey_cached("virustotal")  # 메모리 조회
    """
    return APIKeyCache.get_instance().get_key(name)


def invalidate_cache(name: Optional[str] = None) -> None:
    """캐시 무효화"""
    APIKeyCache.get_instance().invalidate(name)


def reload_key_from_db(db: Session, name: str) -> None:
    """DB에서 키 재로드"""
    APIKeyCache.get_instance().reload_key(db, name)
