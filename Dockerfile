# Dockerfile — phishing-signal-mcp
# PlayMCP in KC Git 소스 빌드 필수 조건(SPEC §1): 레포 루트에 항상 유지.
# 멀티스테이지: build(TS 컴파일) → runtime(prod 의존성만, non-root 실행).

# ---- Build stage ----
FROM node:22-slim AS build
WORKDIR /app

# 의존성 설치 (재현 가능 빌드: package-lock.json 커밋 필요)
COPY package.json package-lock.json* ./
RUN npm ci

# 소스 컴파일 (src → dist)
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# ---- Runtime stage ----
FROM node:22-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production

# prod 의존성만 설치
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm cache clean --force

# 빌드 산출물 복사
COPY --from=build /app/dist ./dist

# Streamable HTTP / Remote / Stateless (SPEC §3) — 포트는 PORT env로 주입
ENV PORT=3000
EXPOSE 3000

# 최소 권한 실행 (node 이미지 기본 제공 사용자)
USER node

CMD ["node", "dist/server.js"]
