"""
Redis 캐싱 시스템 for API responses

VirusTotal, URLScan 등의 API 응답을 Redis에 캐싱하여
동일한 IOC 재조회 시 API 호출을 생략하고 즉시 응답
"""

import os
import json
import logging
from typing import Optional, Dict, Any
import redis

logger = logging.getLogger(__name__)


class RedisCache:
    """Redis 캐시 관리 클래스 (싱글톤)"""

    _instance: Optional['RedisCache'] = None
    _client: Optional[redis.Redis] = None
    _connected: bool = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RedisCache, cls).__new__(cls)
        return cls._instance

    @classmethod
    def get_instance(cls) -> 'RedisCache':
        """싱글톤 인스턴스 반환"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def connect(self) -> bool:
        """Redis 연결 (graceful degradation)"""
        if self._connected and self._client:
            return True

        try:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            self._client = redis.from_url(
                redis_url,
                decode_responses=True,  # 자동으로 bytes → str 변환
                socket_connect_timeout=2,
                socket_timeout=2
            )
            # 연결 테스트
            self._client.ping()
            self._connected = True
            logger.info(f"✅ Redis connected: {redis_url}")
            return True

        except Exception as e:
            logger.warning(f"⚠️ Redis connection failed: {e}. Cache disabled.")
            self._connected = False
            self._client = None
            return False

    def _get_ttl(self, ioc_type: str) -> int:
        """IOC 타입별 TTL 반환"""
        ttl_map = {
            'hash': int(os.getenv('REDIS_TTL_HASH', 3600)),
            'domain': int(os.getenv('REDIS_TTL_DOMAIN', 3600)),
            'ip': int(os.getenv('REDIS_TTL_IP', 3600)),
        }
        return ttl_map.get(ioc_type.lower(), int(os.getenv('REDIS_TTL_DEFAULT', 3600)))

    def _make_cache_key(self, service: str, ioc_type: str, ioc: str) -> str:
        """캐시 키 생성: service:ioc_type:ioc"""
        return f"{service}:{ioc_type}:{ioc}"

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """일반 캐시 조회"""
        if not self._connected or not self._client:
            return None

        try:
            data = self._client.get(key)
            if data:
                logger.debug(f"🎯 Cache HIT: {key}")
                return json.loads(data)
            logger.debug(f"❌ Cache MISS: {key}")
            return None

        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None

    def set(self, key: str, value: Dict[str, Any], ttl: int = 3600) -> bool:
        """일반 캐시 저장"""
        if not self._connected or not self._client:
            return False

        try:
            self._client.setex(
                key,
                ttl,
                json.dumps(value, ensure_ascii=False)
            )
            logger.debug(f"💾 Cache SET: {key} (TTL: {ttl}s)")
            return True

        except Exception as e:
            logger.error(f"Redis set error: {e}")
            return False

    def get_ioc_result(self, service: str, ioc_type: str, ioc: str) -> Optional[Dict[str, Any]]:
        """IOC 분석 결과 조회"""
        key = self._make_cache_key(service, ioc_type, ioc)
        return self.get(key)

    def set_ioc_result(self, service: str, ioc_type: str, ioc: str, data: Dict[str, Any]) -> bool:
        """IOC 분석 결과 저장"""
        key = self._make_cache_key(service, ioc_type, ioc)
        ttl = self._get_ttl(ioc_type)
        return self.set(key, data, ttl)

    def delete(self, key: str) -> bool:
        """캐시 삭제"""
        if not self._connected or not self._client:
            return False

        try:
            self._client.delete(key)
            logger.debug(f"🗑️ Cache DELETE: {key}")
            return True

        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False

    def exists(self, key: str) -> bool:
        """캐시 존재 여부 확인"""
        if not self._connected or not self._client:
            return False

        try:
            return bool(self._client.exists(key))
        except Exception as e:
            logger.error(f"Redis exists error: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """캐시 통계 (개발용)"""
        if not self._connected or not self._client:
            return {"connected": False}

        try:
            info = self._client.info('stats')
            return {
                "connected": True,
                "total_commands": info.get('total_commands_processed', 0),
                "keyspace_hits": info.get('keyspace_hits', 0),
                "keyspace_misses": info.get('keyspace_misses', 0),
                "hit_rate": round(
                    info.get('keyspace_hits', 0) /
                    max(info.get('keyspace_hits', 0) + info.get('keyspace_misses', 0), 1) * 100,
                    2
                )
            }
        except Exception as e:
            logger.error(f"Redis stats error: {e}")
            return {"connected": True, "error": str(e)}
