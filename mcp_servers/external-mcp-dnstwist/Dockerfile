# 외부 Node.js MCP 서버 (dnstwist 전용)
#
# - Node 20 슬림 베이스
# - dnstwist 는 Python 패키지라 pip 로 설치 (Node 가 spawn 으로 호출)
# - sse 로 진짜 MCP 프로토콜 노출 (포트 8766)
FROM node:20-slim

WORKDIR /srv

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip ca-certificates \
    && pip3 install --no-cache-dir --break-system-packages dnstwist>=20240120 \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY server.js ./

ENV MCP_HOST=0.0.0.0 \
    MCP_PORT=8766

EXPOSE 8766

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://localhost:8766/healthz').then(r=>r.ok?process.exit(0):process.exit(1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
