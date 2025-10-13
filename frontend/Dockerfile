# syntax=docker/dockerfile:1
# ===== 프로덕션 환경용 Dockerfile =====
# BuildKit 캐싱으로 빌드 속도 최적화

# ===== 의존성 설치 스테이지 =====
FROM node:18-alpine AS deps
WORKDIR /app
COPY package*.json ./
# BuildKit 캐시 마운트로 npm 캐시 재사용
RUN --mount=type=cache,target=/root/.npm \
    npm install --prefer-offline

# ===== 빌드 스테이지 =====
FROM node:18-alpine AS build
WORKDIR /app
# 이전 스테이지에서 설치된 node_modules 복사
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# 프로덕션 빌드
RUN npm run build

# ===== HOT RELOAD 관련 주의사항 =====
# 개발 환경 (Hot Reload 필요 시):
#   1. docker-compose.yaml에서 dockerfile: Dockerfile.dev로 변경
#   2. volumes 설정으로 로컬 src를 마운트
#   3. 포트를 3000으로 변경 (React 개발 서버)
#
# 프로덕션 환경:
#   - 현재 Dockerfile 사용 (기본값)
#   - 빌드된 정적 파일을 Nginx로 서빙
#   - Hot Reload 없음, 최적화된 프로덕션 빌드
# ======================================

# 프로덕션 스테이지 (Nginx)
FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80