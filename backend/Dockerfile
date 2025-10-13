# syntax=docker/dockerfile:1
# ===== 프로덕션 환경용 Dockerfile =====
# BuildKit 캐싱으로 빌드 속도 최적화
# Hot Reload는 docker-compose.yaml의 volumes + --reload로 구현

FROM python:3.12-slim
WORKDIR /backend

# 시스템 의존성 설치 (BuildKit 캐시 활용)
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y \
    build-essential \
    gcc \
    python3-dev \
    libxml2-dev \
    libxslt-dev \
    liblzma-dev \
    zlib1g-dev

# 데이터 디렉토리 생성
RUN mkdir -p /backend/data

# Python 의존성 설치 (BuildKit pip 캐시 활용)
COPY ./requirements.txt /backend/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && \
    pip install -r /backend/requirements.txt

# ===== HOT RELOAD 관련 주의사항 =====
# 개발 환경:
#   - docker-compose.yaml의 volumes를 통해 로컬 코드를 마운트
#   - command: uvicorn --reload 옵션으로 자동 재시작
#   - 이 Dockerfile의 COPY는 초기 빌드 시에만 사용됨
#
# 프로덕션 환경:
#   - 아래 COPY 명령으로 코드를 이미지에 포함
#   - volumes 마운트 제거
#   - --reload 옵션 제거
# ======================================

# 애플리케이션 코드 복사 (프로덕션 빌드 시 사용)
COPY ./ /backend/

EXPOSE 8000

# 프로덕션 명령 (--reload 없음)
# 개발 환경에서는 docker-compose.yaml의 command로 오버라이드됨
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]