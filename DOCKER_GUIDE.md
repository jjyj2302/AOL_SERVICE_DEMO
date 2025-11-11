# 🐳 Docker 완벽 가이드

> 이 문서는 실전 개발에서 Docker를 효율적으로 사용하기 위한 완벽한 가이드입니다.

---

## 📚 목차

1. [Docker 핵심 개념](#1-docker-핵심-개념)
2. [Docker 캐시 시스템](#2-docker-캐시-시스템)
3. [Docker 명령어 완벽 가이드](#3-docker-명령어-완벽-가이드)
4. [빌드 최적화 전략](#4-빌드-최적화-전략)
5. [실전 워크플로우](#5-실전-워크플로우)
6. [트러블슈팅](#6-트러블슈팅)

---

## 1. Docker 핵심 개념

### 1.1 Docker 구조 이해하기

```
┌─────────────────────────────────────────────┐
│          Dockerfile (설계도)                 │
├─────────────────────────────────────────────┤
│ FROM python:3.12-slim           → Layer 1   │
│ WORKDIR /backend               → Layer 2   │
│ RUN apt-get install ...        → Layer 3   │
│ COPY requirements.txt ...      → Layer 4   │
│ RUN pip install ...            → Layer 5   │
│ COPY ./ /backend/              → Layer 6   │
└─────────────────────────────────────────────┘
                 ↓ docker build
┌─────────────────────────────────────────────┐
│          레이어 캐시 (Build Cache)           │
├─────────────────────────────────────────────┤
│ Layer 1: sha256:f35c889e... (119MB)        │
│ Layer 2: sha256:508d53e7... (0B)           │
│ Layer 3: sha256:43280d44... (150MB)        │
│ Layer 4: sha256:9c0d1e2f... (1KB)          │
│ Layer 5: sha256:a1b2c3d4... (800MB) ⭐     │
│ Layer 6: sha256:b2c3d4e5... (15MB)         │
└─────────────────────────────────────────────┘
                 ↓ 레이어 결합
┌─────────────────────────────────────────────┐
│      이미지 (Tagged Image)                   │
├─────────────────────────────────────────────┤
│ aol_service_demo_backend:latest             │
│ = Layer 1 + 2 + 3 + 4 + 5 + 6              │
│ 총 크기: 1.02GB                             │
│ Image ID: 2aa47af1c02e                      │
└─────────────────────────────────────────────┘
                 ↓ docker run
┌─────────────────────────────────────────────┐
│         컨테이너 (Running Container)         │
├─────────────────────────────────────────────┤
│ Container ID: abc123...                     │
│ Name: backend                               │
│ Status: Up 5 minutes                        │
│ = 이미지 + 실행 환경 + 데이터                │
└─────────────────────────────────────────────┘
```

### 1.2 핵심 용어 정리

| 용어 | 설명 | 비유 |
|------|------|------|
| **Dockerfile** | 이미지를 만드는 설계도 | 레시피 |
| **레이어(Layer)** | Dockerfile의 각 명령어 실행 결과 | 재료 |
| **캐시(Cache)** | 재사용 가능한 레이어들의 저장소 | 재료 창고 |
| **이미지(Image)** | 레이어들을 쌓아서 만든 최종 결과물 | 완성된 요리 |
| **컨테이너(Container)** | 이미지를 실행한 인스턴스 | 실제 서빙된 요리 |

**관계:**
```
레이어(재료) → 캐시(재료 창고) → 이미지(완성품) → 컨테이너(실행 중)
```

---

## 2. Docker 캐시 시스템

### 2.1 캐시가 생성되는 시점

Docker 캐시는 **Dockerfile의 각 명령어를 실행할 때마다** 레이어로 저장됩니다.

#### 최초 빌드 시:

```bash
docker-compose build backend
```

```
Step 1/8 : FROM python:3.12-slim
 ---> f35c889e4f8e           ✅ 캐시 생성: Base 이미지 레이어

Step 2/8 : WORKDIR /backend
 ---> 508d53e765f4           ✅ 캐시 생성: WORKDIR 레이어

Step 3/8 : RUN apt-get update && apt-get install ...
 ---> 43280d44e9df           ✅ 캐시 생성: apt-get 레이어 (1분 소요)

Step 4/8 : COPY ./requirements.txt ...
 ---> 9c0d1e2f3g4h           ✅ 캐시 생성: requirements.txt 레이어

Step 5/8 : RUN pip install -r requirements.txt
 ---> a1b2c3d4e5f6           ✅ 캐시 생성: pip install 레이어 (3분 소요)

Step 6/8 : COPY ./ /backend/
 ---> b2c3d4e5f6g7           ✅ 캐시 생성: 소스 코드 레이어

총 소요 시간: 4분 35초
```

### 2.2 캐시 재사용 판단 기준

#### COPY/ADD 명령어
**판단 기준**: 파일 내용의 **체크섬(해시값)**

```dockerfile
COPY ./requirements.txt /backend/requirements.txt
```

**Docker의 판단 로직:**
```python
# 의사 코드
old_hash = sha256(previous_requirements.txt)  # 캐시된 파일
new_hash = sha256(current_requirements.txt)   # 현재 파일

if old_hash == new_hash:
    print("---> Using cache")  # ✅ 캐시 사용
else:
    print("---> Running...")   # ❌ 캐시 무효화, 재실행
```

#### RUN 명령어
**판단 기준**: 명령어 **문자열 자체**

```dockerfile
RUN pip install -r /backend/requirements.txt
```

**Docker의 판단 로직:**
```python
# 의사 코드
old_command = "pip install -r /backend/requirements.txt"
new_command = "pip install -r /backend/requirements.txt"

if old_command == new_command AND previous_layer_cached:
    print("---> Using cache")  # ✅ 캐시 사용
else:
    print("---> Running...")   # ❌ 재실행
```

### 2.3 캐시의 핵심 규칙 4가지

1. **COPY/ADD**: 파일 내용이 바뀌면 → 캐시 무효화
2. **RUN**: 명령어가 바뀌면 → 캐시 무효화
3. **연쇄 반응**: 한 레이어가 무효화되면 → 그 이후 모든 레이어도 재실행
4. **이전 레이어 의존**: 이전 레이어가 캐시되어야 다음 레이어도 캐시됨

### 2.4 실전 시나리오

#### 시나리오 1: 소스 코드만 수정 (main.py)

```bash
# backend/main.py 파일 수정
vim backend/main.py

# 재빌드
docker-compose build backend
```

**빌드 과정:**
```
Step 1-5: Using cache ✅ ✅ ✅ ✅ ✅  # 시스템 설정, pip install 모두 스킵!
Step 6/8 : COPY ./ /backend/
 ---> a9b8c7d6e5f4 ❌                # main.py가 바뀌어서 이 레이어부터 재실행

완료 시간: 5초 (캐시 덕분!)
```

#### 시나리오 2: requirements.txt에 패키지 추가

```bash
# backend/requirements.txt 수정
echo "pandas==2.0.0" >> backend/requirements.txt

# 재빌드
docker-compose build backend
```

**빌드 과정:**
```
Step 1-3: Using cache ✅ ✅ ✅      # 시스템 설정 레이어들

Step 4/8 : COPY ./requirements.txt ...
 ---> b1c2d3e4f5g6 ❌              # requirements.txt 해시 변경됨!

Step 5/8 : RUN pip install -r requirements.txt
 ---> Running in xyz...            # ❌ pip install 재실행 (pandas 추가)
(3분 소요)

Step 6/8: ❌                        # 이후 레이어도 재실행

완료 시간: 3분
```

#### 시나리오 3: Dockerfile 명령어 수정

```bash
# Dockerfile의 RUN 명령어 수정
# AS-IS: RUN pip install --upgrade pip setuptools wheel
# TO-BE: RUN pip install --upgrade pip setuptools wheel poetry

docker-compose build backend
```

**빌드 과정:**
```
Step 1-2: Using cache ✅ ✅

Step 3/8 : RUN pip install --upgrade pip setuptools wheel poetry
 ---> Running in ...               # ❌ 명령어 문자열이 바뀌어서 재실행

Step 4-6: ❌ ❌ ❌                  # 이후 모든 레이어 재실행

완료 시간: 4분
```

### 2.5 캐시의 가치

#### 캐시 없이 (--no-cache):
```
apt-get install (1분) + pip upgrade (30초) + pip install (3분) + COPY (5초)
= 총 4분 35초 ❌
```

#### 캐시 사용 (일반 빌드):

**소스 코드만 수정:**
```
Using cache (0초) + COPY 소스 (5초)
= 총 5초 ✅ (55배 빠름!)
```

**의존성 추가:**
```
Using cache (0초) + pip install (1분) + COPY (5초)
= 총 1분 6초 ✅ (4배 빠름!)
```

---

## 3. Docker 명령어 완벽 가이드

### 3.1 컨테이너 중지/삭제

#### `docker-compose down`
**언제**: 컨테이너를 완전히 중지하고 삭제하고 싶을 때

```bash
docker-compose down
```

**결과:**
- ✅ 컨테이너 중지 및 삭제
- ✅ 네트워크 삭제
- ❌ 이미지는 남음 (재시작 시 빠름)
- ❌ 볼륨은 남음 (데이터 보존)

**사용 예시:**
```bash
# 작업 끝나고 깔끔하게 정리
docker-compose down

# 다음날 다시 시작
docker-compose up -d  # 빠르게 시작됨
```

---

#### `docker-compose down -v`
**언제**: 컨테이너 + 볼륨(데이터)까지 완전히 삭제하고 싶을 때

```bash
docker-compose down -v
```

**결과:**
- ✅ 컨테이너 중지 및 삭제
- ✅ 네트워크 삭제
- ✅ 볼륨 삭제 (⚠️ 모든 데이터 삭제!)
- ❌ 이미지는 남음

**사용 예시:**
```bash
# 데이터베이스가 꼬였거나 완전 초기화 필요
docker-compose down -v

# ⚠️ 주의: ./data 볼륨의 모든 데이터 삭제됨!
```

**차이점:**
| 명령어 | 컨테이너 | 네트워크 | 볼륨(데이터) | 이미지 |
|--------|----------|----------|--------------|--------|
| `down` | 삭제 ✅ | 삭제 ✅ | 보존 ⭐ | 보존 ⭐ |
| `down -v` | 삭제 ✅ | 삭제 ✅ | 삭제 ⚠️ | 보존 ⭐ |

---

### 3.2 이미지 빌드

#### `docker-compose build`
**언제**: 이미지를 새로 빌드하고 싶을 때 (가장 기본, 가장 많이 사용!)

```bash
docker-compose build
```

**결과:**
- ✅ Dockerfile 변경사항만 재빌드 (레이어 캐싱 활용)
- ✅ requirements.txt/package.json 변경 없으면 → 의존성 설치 스킵
- ✅ 소스 코드만 변경되면 → 마지막 COPY 레이어만 재실행
- ⏱️ 시간: 변경 없으면 5-10초, 의존성 변경 시 1-2분

**사용 예시:**
```bash
# main.py 파일만 수정
docker-compose build backend
# 결과: 5초 (COPY 레이어만 재실행)

# requirements.txt에 패키지 추가
docker-compose build backend
# 결과: 1-2분 (pip install 레이어부터 재실행)
```

---

#### `docker-compose build --no-cache`
**언제**: 캐시를 완전히 무시하고 처음부터 빌드하고 싶을 때 (⚠️ 거의 쓰지 마세요!)

```bash
docker-compose build --no-cache
```

**결과:**
- ❌ 모든 레이어를 처음부터 재빌드
- ❌ 의존성 완전 재설치 (pip install, npm install)
- ❌ apt-get update 재실행
- ⏱️ 시간: 항상 4-5분 (변경 여부와 무관)

**사용 예시:**
```bash
# ⚠️ 다음과 같은 문제 발생 시에만 사용:
# - 의존성 설치가 이상하게 꼬였을 때
# - pip/npm 캐시 문제로 에러 발생 시
# - 디버깅 목적으로 완전 초기화 필요 시

docker-compose build --no-cache backend
# 결과: 4-5분 대기 (하지만 문제 해결됨)
```

---

#### `docker-compose build backend` (특정 서비스만)
**언제**: 백엔드만 또는 프론트엔드만 빌드하고 싶을 때

```bash
docker-compose build backend   # backend만 빌드
docker-compose build frontend  # frontend만 빌드
```

**결과:**
- ✅ 지정한 서비스만 빌드
- ✅ 다른 서비스는 그대로 유지
- ⏱️ 시간: 절반으로 단축

**사용 예시:**
```bash
# backend/main.py만 수정했을 때
docker-compose build backend    # frontend는 빌드 안 함 (1분 절약)
docker-compose up -d backend

# frontend/src/App.js만 수정
docker-compose build frontend
docker-compose up -d frontend
```

---

### 3.3 컨테이너 시작

#### `docker-compose up`
**언제**: 컨테이너를 포그라운드로 실행하고 로그를 보고 싶을 때

```bash
docker-compose up
```

**결과:**
- ✅ 컨테이너 시작
- ✅ 터미널에 실시간 로그 출력
- ❌ 터미널 점유 (다른 작업 불가)
- Ctrl+C로 종료 가능

**사용 예시:**
```bash
# 로그를 실시간으로 확인하면서 디버깅
docker-compose up

# 터미널 출력:
# backend  | INFO:     Uvicorn running on http://0.0.0.0:8000
# frontend | /docker-entrypoint.sh: Launching...
```

---

#### `docker-compose up -d`
**언제**: 컨테이너를 백그라운드로 실행하고 싶을 때 (⭐ 가장 많이 사용!)

```bash
docker-compose up -d
```

**결과:**
- ✅ 컨테이너 백그라운드 시작 (detached mode)
- ✅ 터미널 즉시 반환 (다른 작업 가능)
- ✅ 로그는 `docker-compose logs`로 확인 가능

**사용 예시:**
```bash
# 일반적인 개발 시작
docker-compose up -d

# 출력:
# Creating backend  ... done
# Creating frontend ... done

# 바로 터미널 사용 가능!
# 로그 보고 싶으면: docker-compose logs -f
```

---

#### `docker-compose up -d --build`
**언제**: 빌드 + 시작을 한 번에 하고 싶을 때

```bash
docker-compose up -d --build
```

**결과:**
- ✅ 이미지 빌드 (변경사항만)
- ✅ 컨테이너 재시작
- ✅ 백그라운드 실행
- ⏱️ 시간: 빌드 시간 + 시작 시간

**사용 예시:**
```bash
# 코드 수정 후 빠르게 재시작
docker-compose up -d --build

# 이 명령 하나가:
# 1. docker-compose build      (변경사항 빌드)
# 2. docker-compose up -d      (컨테이너 시작)
# 을 동시에 수행!
```

---

#### `docker-compose restart`
**언제**: 빌드 없이 단순히 컨테이너만 재시작하고 싶을 때

```bash
docker-compose restart backend
```

**결과:**
- ✅ 컨테이너 재시작 (1초)
- ❌ 빌드는 하지 않음
- ❌ 코드 변경사항 반영 안 됨 (이미지가 같음)

**사용 예시:**
```bash
# 환경 변수만 변경하고 재시작
docker-compose restart backend

# ⚠️ 주의: 코드를 수정했다면 restart가 아니라 up -d --build 필요!
```

**명령어 비교:**
| 명령어 | 빌드 | 컨테이너 시작 | 용도 | 시간 |
|--------|------|---------------|------|------|
| `build` | ✅ | ❌ | 이미지만 생성 | 5초~4분 |
| `up` | ❌ | ✅ | 이미지로 컨테이너 시작 | 5초 |
| `up --build` | ✅ | ✅ | 빌드 + 시작 (가장 많이 사용) | 10초~4분 |
| `restart` | ❌ | ✅ | 빌드 없이 재시작 | 1초 |

---

### 3.4 정리(Cleanup) 명령어

#### `docker image prune -a`
**언제**: 사용하지 않는 모든 이미지를 삭제하고 싶을 때

```bash
docker image prune -a -f
```

**결과:**
- ✅ `<none>` 태그 이미지 전부 삭제
- ✅ 사용 중이지 않은 모든 이미지 삭제
- ✅ 디스크 공간 대량 확보 (보통 5-10GB)
- ❌ 다음 빌드 시 처음부터 다운로드 필요

**사용 예시:**
```bash
# Before:
docker images
# <none>  <none>  35개 (5GB 낭비)

docker image prune -a -f

# Deleted Images:
# deleted: sha256:b3354d6ee7e0...
# Total reclaimed space: 5.2GB

# After:
docker images
# aol_service_demo_backend   latest  (깔끔!)
# aol_service_demo_frontend  latest  (깔끔!)
```

---

#### `docker builder prune -a`
**언제**: 빌드 캐시를 삭제하고 싶을 때

```bash
docker builder prune -a -f
```

**결과:**
- ✅ BuildKit 빌드 캐시 삭제
- ✅ 디스크 공간 확보 (1-3GB)
- ❌ 다음 빌드가 느려짐 (캐시 없음)

**사용 예시:**
```bash
# 디스크 공간이 부족할 때
docker builder prune -a -f

# Deleted build cache objects:
# Total: 2.5GB

# 다음 빌드 시:
# pip install 다시 실행 (캐시 없어서 느림)
```

---

#### `docker system prune -a --volumes`
**언제**: 완전 초기화 - 모든 것을 삭제하고 싶을 때 (⚠️ 매우 위험!)

```bash
docker system prune -a --volumes -f
```

**결과:**
- ❌ 모든 컨테이너 삭제
- ❌ 모든 이미지 삭제
- ❌ 모든 볼륨 삭제 (데이터 삭제!)
- ❌ 모든 네트워크 삭제
- ❌ 빌드 캐시 삭제
- ✅ Docker를 처음 설치한 상태로 초기화

**사용 예시:**
```bash
# ⚠️⚠️⚠️ 매우 주의! ⚠️⚠️⚠️
# Docker가 완전히 망가졌거나, 디스크 공간 긴급 확보 필요 시만

docker system prune -a --volumes -f

# Total reclaimed space: 15.7GB

# 결과: Docker 완전 초기화
# 다음 빌드는 모든 것을 처음부터 다운로드
```

---

### 3.5 모니터링 명령어

#### `docker-compose logs -f`
**언제**: 실행 중인 컨테이너의 로그를 보고 싶을 때

```bash
docker-compose logs -f          # 모든 서비스 로그
docker-compose logs -f backend  # backend만
```

**결과:**
- ✅ 실시간 로그 출력 (-f: follow)
- ✅ Ctrl+C로 종료 (컨테이너는 계속 실행)

**사용 예시:**
```bash
# API 요청이 왜 실패하는지 확인
docker-compose logs -f backend

# 출력:
# backend | ERROR: Database connection failed
# backend | Traceback (most recent call last):
# ...
```

---

#### `docker-compose ps`
**언제**: 현재 실행 중인 컨테이너 상태를 확인하고 싶을 때

```bash
docker-compose ps
```

**결과:**
```
NAME       COMMAND                STATUS      PORTS
backend    "uvicorn main:app..."  Up 5 min    0.0.0.0:8000->8000/tcp
frontend   "nginx -g 'daemon ..." Up 5 min    0.0.0.0:4000->80/tcp
```

---

## 4. 빌드 최적화 전략

### 4.1 BuildKit 활성화 (필수!)

BuildKit은 Docker의 차세대 빌드 엔진입니다.

**활성화 방법:**
```bash
# 현재 세션에만 적용
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# 영구 적용 (추천)
echo 'export DOCKER_BUILDKIT=1' >> ~/.bashrc
echo 'export COMPOSE_DOCKER_CLI_BUILD=1' >> ~/.bashrc
source ~/.bashrc
```

**효과:**
- ✅ 병렬 빌드 가능 → 2배 빠름
- ✅ 스마트 캐싱 → 캐시 적중률 증가
- ✅ 네트워크 최적화 → 의존성 다운로드 빠름
- ✅ 빌드 컨텍스트 최적화 → 전송 데이터 감소

**BuildKit 없이 빌드**: 2010년대 기술 (느림)
**BuildKit으로 빌드**: 최신 기술 (2-3배 빠름)

---

### 4.2 .dockerignore 최적화

`.dockerignore` 파일은 Docker 빌드 컨텍스트에서 제외할 파일을 지정합니다.

#### Backend `.dockerignore`:
```
# Virtual environments (매우 중요!)
venv/
env/
ENV/
.venv/

# Python cache
__pycache__/
*.pyc
*.pyo
*.pyd
.Python

# Database
*.db
*.sqlite
*.sqlite3
data/

# Testing
.pytest_cache/
.coverage
htmlcov/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Logs
*.log
logs/

# Jupyter
.ipynb_checkpoints/
*.ipynb
```

#### Frontend `.dockerignore`:
```
# Dependencies (매우 중요!)
node_modules/

# Build outputs
build/
dist/
.next/
out/

# Cache
.cache/
.eslintcache

# Environment files
.env
.env*.local

# IDE
.vscode/
.idea/

# Logs
*.log
logs/

# OS
.DS_Store
Thumbs.db
```

**효과:**
- ✅ 빌드 컨텍스트 크기 90% 감소
- ✅ 빌드 속도 2-3배 향상
- ✅ 캐시 효율 증가

---

### 4.3 Dockerfile 레이어 최적화

#### 최적화된 Backend Dockerfile:
```dockerfile
FROM python:3.12-slim
WORKDIR /backend

# 시스템 의존성 (한 레이어에서 완료 + 캐시 삭제)
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# pip 업그레이드
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# requirements.txt만 먼저 복사 (의존성 캐싱) ⭐ 핵심!
COPY ./requirements.txt /backend/requirements.txt

# 의존성 설치 (가장 오래 걸리지만, requirements.txt 변경 없으면 캐싱됨)
RUN pip install --no-cache-dir -r /backend/requirements.txt

# 소스 코드는 마지막에 복사 ⭐ 핵심!
COPY ./ /backend/

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**최적화 포인트:**
1. **자주 변경되지 않는 것을 먼저 배치**
   - Base 이미지 → 시스템 패키지 → Python 패키지 → 소스 코드
2. **requirements.txt를 먼저 COPY**
   - 의존성이 안 바뀌면 pip install 스킵 (3분 절약!)
3. **소스 코드는 마지막에 COPY**
   - 코드만 바뀌면 이 레이어만 재실행 (5초!)
4. **RUN 명령어 체이닝**
   - `&&`로 연결하여 레이어 수 최소화

---

### 4.4 docker-compose.yaml 최적화

```yaml
version: "3.8"
services:
  backend:
    networks:
      - otk-network
    build:
      context: ./backend
      dockerfile: Dockerfile
      # BuildKit 캐시 최적화 ⭐
      cache_from:
        - aol_service_demo_backend:latest
    image: aol_service_demo_backend:latest
    container_name: backend
    volumes:
      - ./data:/backend/data
    restart: unless-stopped

  frontend:
    networks:
      - otk-network
    build:
      context: ./frontend
      dockerfile: Dockerfile
      # BuildKit 캐시 최적화 ⭐
      cache_from:
        - aol_service_demo_frontend:latest
    image: aol_service_demo_frontend:latest
    container_name: frontend
    ports:
      - "4000:80"
    restart: unless-stopped

networks:
  otk-network:
    driver: bridge
```

**최적화 포인트:**
- `cache_from`: 이전 이미지를 캐시로 사용
- `restart: unless-stopped`: 시스템 재시작 시 자동 시작

---

## 5. 실전 워크플로우

### 5.1 일상 개발 워크플로우

#### 아침: 개발 시작
```bash
# 컨테이너 시작 (이미 빌드된 이미지 사용)
docker-compose up -d

# 로그 확인 (선택)
docker-compose logs -f

# 완료 시간: 5초
```

---

#### 코드 수정 후: 빠른 재시작
```bash
# backend/main.py 수정 후
docker-compose up -d --build backend

# 완료 시간: 5-10초 (소스 코드 COPY 레이어만 재실행)
```

---

#### 의존성 추가 후: 재빌드
```bash
# requirements.txt에 패키지 추가 후
docker-compose build backend
docker-compose up -d backend

# 완료 시간: 1-2분 (pip install 레이어부터 재실행)
```

---

#### 저녁: 작업 종료
```bash
# 방법 1: 컨테이너만 정리 (추천)
docker-compose down

# 방법 2: 완전 정리 (디스크 공간 확보)
docker-compose down -v
docker image prune -a -f
```

---

### 5.2 시나리오별 명령어

| 상황 | 명령어 | 시간 |
|------|--------|------|
| **개발 시작** | `docker-compose up -d` | 5초 |
| **코드만 수정** | `docker-compose up -d --build` | 10초 |
| **의존성 추가** | `docker-compose build` → `up -d` | 1-2분 |
| **환경변수 변경** | `docker-compose restart` | 1초 |
| **완전 재빌드** | `docker-compose build --no-cache` | 4-5분 |
| **작업 종료** | `docker-compose down` | 2초 |
| **디스크 정리** | `docker image prune -a -f` | 10초 |

---

### 5.3 Git Merge 후 워크플로우

**중요**: Merge 후에도 `--no-cache`는 **필요 없습니다**!

```bash
# Git merge 완료 후
git checkout integration/backend-frontend
git merge feature/langgraph-multi-agent

# Docker는 파일 변경사항을 자동 감지
docker-compose build  # --no-cache 필요 없음!

# requirements.txt가 바뀌었으면:
# → Docker가 자동으로 pip install 레이어부터 재실행

# 소스 코드만 바뀌었으면:
# → Docker가 자동으로 COPY 레이어만 재실행

docker-compose up -d
```

**왜 `--no-cache`가 필요 없나?**
- Git merge는 **파일만 변경** (Docker 캐시와 무관)
- Docker는 **파일 내용 해시**를 보고 캐시 유효성 판단
- 파일이 바뀌면 → 자동으로 해당 레이어부터 재빌드
- 파일이 안 바뀌면 → 캐시 사용

---

## 6. 트러블슈팅

### 6.1 빌드가 너무 느릴 때

#### 체크리스트:
```bash
# 1. BuildKit이 활성화되어 있는지 확인
echo $DOCKER_BUILDKIT
# 출력이 없거나 0이면 → 비활성화됨!

# 활성화:
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# 2. --no-cache를 사용하고 있는지 확인
# ❌ docker-compose build --no-cache  (느림!)
# ✅ docker-compose build             (빠름!)

# 3. .dockerignore가 제대로 설정되어 있는지 확인
cat backend/.dockerignore
# venv/, node_modules/, __pycache__/ 등이 있어야 함

# 4. 불필요한 이미지 정리
docker image prune -a -f
docker builder prune -a -f
```

---

### 6.2 디스크 공간 부족

```bash
# 1단계: 사용하지 않는 이미지 삭제
docker image prune -a -f

# 2단계: 빌드 캐시 삭제
docker builder prune -a -f

# 3단계: 볼륨 삭제 (⚠️ 데이터 손실)
docker-compose down -v

# 4단계: 완전 초기화 (⚠️⚠️ 모든 것 삭제)
docker system prune -a --volumes -f

# 확인:
docker system df
```

---

### 6.3 이상한 에러 발생 시

```bash
# 1. 컨테이너 로그 확인
docker-compose logs -f backend

# 2. 컨테이너 내부 접속
docker-compose exec backend bash

# 3. 완전 재빌드
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d

# 4. Docker 재시작
sudo systemctl restart docker
```

---

### 6.4 캐시 문제로 변경사항이 반영 안 될 때

```bash
# 특정 서비스만 재빌드 (캐시 무시)
docker-compose build --no-cache backend
docker-compose up -d backend

# 전체 재빌드
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

---

## 7. 성능 비교표

### 7.1 빌드 시간 비교

| 상황 | --no-cache 사용 | 캐시 사용 | 개선율 |
|------|-----------------|-----------|--------|
| **최초 빌드** | 4-5분 | 4-5분 | - |
| **코드만 변경** | 4-5분 | **5초** | **55배 ↑** |
| **의존성 추가** | 4-5분 | **1-2분** | **4배 ↑** |
| **Dockerfile 수정** | 4-5분 | **2-3분** | **2배 ↑** |

### 7.2 최적화 전후 비교

| 항목 | 최적화 전 | 최적화 후 | 개선 |
|------|-----------|-----------|------|
| **빌드 시간** | 4-5분 | 5-10초 | **95% ↓** |
| **디스크 사용량** | 15GB+ | 5GB | **70% ↓** |
| **빌드 컨텍스트** | 80MB | 15MB | **80% ↓** |
| **이미지 개수** | 47개 | 4개 | **91% ↓** |

---

## 8. 명령어 치트시트

### 8.1 자주 쓰는 명령어

```bash
# 개발 시작
docker-compose up -d

# 코드 수정 후 재시작
docker-compose up -d --build

# 로그 확인
docker-compose logs -f backend

# 컨테이너 상태 확인
docker-compose ps

# 작업 종료
docker-compose down

# 디스크 정리
docker image prune -a -f
```

### 8.2 전체 명령어 요약

| 명령어 | 용도 | 시간 | 주의사항 |
|--------|------|------|----------|
| `up -d` | 백그라운드 시작 | 5초 | 가장 많이 사용 |
| `up -d --build` | 빌드 + 시작 | 10초 | 코드 수정 후 |
| `build` | 이미지만 빌드 | 10초 | 캐시 사용 |
| `build --no-cache` | 완전 재빌드 | 4-5분 | 드물게 사용 |
| `restart` | 재시작만 | 1초 | 빌드 안 함 |
| `down` | 중지 + 삭제 | 2초 | 데이터 보존 |
| `down -v` | 볼륨까지 삭제 | 2초 | ⚠️ 데이터 삭제 |
| `logs -f` | 실시간 로그 | 즉시 | Ctrl+C로 종료 |
| `ps` | 상태 확인 | 즉시 | - |
| `image prune -a -f` | 이미지 정리 | 10초 | 5GB+ 확보 |

---

## 9. 핵심 원칙 (꼭 기억하세요!)

### ✅ DO (해야 할 것)
1. **BuildKit 활성화** - 필수!
2. **.dockerignore 최적화** - venv, node_modules 제외
3. **일반 빌드 사용** - `docker-compose build`
4. **레이어 순서 최적화** - 자주 변경되는 것을 뒤로
5. **정기적인 이미지 정리** - `docker image prune -a -f`

### ❌ DON'T (하지 말아야 할 것)
1. **매번 `--no-cache` 사용** - 10배 느려짐
2. **매번 `down -v` 사용** - 데이터 날아감
3. **venv, node_modules 커밋** - .gitignore에 추가
4. **빌드 없이 코드 변경 후 restart** - 변경사항 반영 안 됨
5. **과도한 정리** - 재빌드 시간 증가

---

## 10. 참고 자료

### 공식 문서
- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [BuildKit Documentation](https://docs.docker.com/build/buildkit/)

### 유용한 명령어
```bash
# Docker 버전 확인
docker version
docker-compose version

# 전체 시스템 정보
docker system info
docker system df

# 이미지 히스토리 확인
docker history <image-name>

# 컨테이너 내부 접속
docker-compose exec backend bash
docker-compose exec frontend sh

# 파일 복사
docker cp backend:/backend/data/output.txt ./
```

---

**작성일**: 2025-01-12
**버전**: 1.0
**프로젝트**: AOL Service Demo

---

💡 **Tip**: 이 가이드를 북마크하고 필요할 때마다 참고하세요!
