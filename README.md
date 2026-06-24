# 피싱 신호등 (PhishingSignal) — MCP Server

수상한 전화·문자·메신저 내용을 붙여넣으면 **보이스피싱 위험도를 근거와 함께** 설명하고,
**지금 해야 할 행동**과 **공식 신고 루트**를 안내하는 MCP 서버입니다.

> 판정은 LLM 호출이 아니라 **결정적(deterministic) 규칙 엔진**으로 수행합니다(응답 100ms 목표·무과금·일관성).
> 자세한 제품/규정/확정값은 [SPEC.md](SPEC.md)를 참고하세요.

## 툴 (MVP 2종)

| 이름 | 역할 |
|---|---|
| `analyzePhishingRisk` | 입력 텍스트 → 위험 신호 탐지 → 위험도(낮음/주의/높음/매우 높음) + 근거 + 행동 가이드 |
| `getReportChannels` | 상황별(`suspiciousOnly`/`alreadyPaid`/`personalInfoExposed`/`malwareInstalled`) 공식 신고 루트 |

- 전송: **Streamable HTTP / Remote / Stateless(no session)**
- 안전: 입력 미저장, 민감정보 마스킹, 의심 링크 디팽, 모든 분석 출력에 디스클레이머, 응답 24k 가드
- 품질: 공식 시나리오 기반 fixture와 adversarial 합성 샘플 회귀 테스트로 가족/지인 사칭, 기관 사칭, 대출·택배·소액결제·투자/알바·악성앱 유도 유형을 점검

## 요구 사항

- **Node.js 22 LTS** (`engines: ">=22"`)
  - 로컬에 Node 18/22가 혼재한 경우, Homebrew keg-only `node@22` 사용 예:
    ```bash
    export PATH="/opt/homebrew/opt/node@22/bin:$PATH"
    ```

## 설치 / 빌드 / 실행

```bash
npm install          # 의존성 설치(@modelcontextprotocol/sdk, zod)
npm run build        # TypeScript → dist/
npm start            # node dist/server.js (PORT, 기본 3000)

# 개발 모드(컴파일 없이 watch)
npm run dev

# 타입체크 / 테스트
npm run typecheck
npm test
```

서버는 다음 엔드포인트를 제공합니다(기본 포트 3000):

- `POST /mcp` — MCP Streamable HTTP 엔드포인트
- `GET /healthz` — 헬스 체크 (`{"status":"ok",...}`)

```bash
PORT=3000 npm start
curl http://127.0.0.1:3000/healthz
```

## MCP Inspector 점검

[MCP Inspector](https://github.com/modelcontextprotocol/inspector)로 스펙 준수를 확인합니다.

```bash
# 1) 서버 기동
PORT=3000 npm start

# 2-A) UI 모드: 브라우저에서 Transport=Streamable HTTP, URL=http://127.0.0.1:3000/mcp 로 연결
npx @modelcontextprotocol/inspector

# 2-B) CLI 모드(헤드리스)
npx @modelcontextprotocol/inspector --cli http://127.0.0.1:3000/mcp --method tools/list
npx @modelcontextprotocol/inspector --cli http://127.0.0.1:3000/mcp \
  --method tools/call --tool-name getReportChannels \
  --tool-arg situation=suspiciousOnly
```

점검 포인트: 툴 2종 노출, 각 툴의 `name/description/inputSchema/annotations(5종)`,
응답 마크다운(디스클레이머 포함), 응답 크기 24k 이내.

## Docker (PlayMCP in KC — Git 소스 빌드)

레포 루트의 [Dockerfile](Dockerfile)로 빌드합니다(멀티스테이지, Node 22, 비루트 실행).

```bash
docker build -t phishing-signal-mcp .
docker run --rm -p 3000:3000 -e PORT=3000 phishing-signal-mcp
curl http://127.0.0.1:3000/healthz
```

> 재현 빌드를 위해 `npm ci`를 사용하므로 `package-lock.json`이 커밋되어 있어야 합니다.

## 배포 (PlayMCP 콘솔)

1. 공개 Endpoint URL 확보 → 경로는 `https://<host>/mcp`.
2. PlayMCP 개발자 콘솔에 임시 등록 → 도구함 추가 → AI채팅 테스트 → 심사 요청.
3. 심사 통과 후 공개 상태를 "전체 공개"로 전환.

## 레포 포함 기준

- 포함: `src/`, `test/`, `README.md`, `SPEC.md`, `Dockerfile`, `package.json`, `package-lock.json`, `tsconfig.json`
- 제외: 로컬 빌드 산출물(`dist/`), 설치 의존성(`node_modules/`), 로컬 에이전트 지침/QA 핸드오프 문서(`AGENTS.md`, `CLAUDE.md`, `docs/claudeCode*.md`)
