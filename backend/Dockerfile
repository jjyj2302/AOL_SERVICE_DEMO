FROM python:3.12-slim
WORKDIR /backend

# 시스템 의존성 설치 (한 레이어에서 완료 + 캐시 삭제)
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    python3-dev \
    libxml2-dev \
    libxslt-dev \
    liblzma-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 데이터 디렉토리 생성
RUN mkdir -p /backend/data

# pip 업그레이드 (캐싱 최적화)
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# requirements.txt만 먼저 복사 (의존성 캐싱)
COPY ./requirements.txt /backend/requirements.txt

# 의존성 설치 (이 레이어가 가장 오래 걸리지만, requirements.txt 변경 없으면 캐싱됨)
RUN pip install --no-cache-dir --upgrade -r /backend/requirements.txt

# 소스 코드 복사 (마지막에 복사하여 코드 변경 시에만 이 레이어부터 재빌드)
COPY ./ /backend/

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
