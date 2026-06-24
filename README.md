# 피싱 신호등 (PhishingSignal) — MCP Server

수상한 전화·문자·메신저 내용을 붙여넣으면 **송금·앱설치·인증번호 공유 전에 먼저 멈추게 하고**,
보이스피싱 위험도와 근거, **지금 해야 할 행동**과 **공식 신고 루트**를 안내하는 MCP 서버입니다.

> 판정은 LLM 호출이 아니라 **결정적(deterministic) 규칙 엔진**으로 수행합니다(응답 100ms 목표·무과금·일관성).
> 자세한 제품/규정/확정값은 [SPEC.md](SPEC.md)를 참고하세요.

## 포지셔닝

피싱 신호등은 단순 탐지기가 아니라, 수상한 연락을 받았을 때 피해 행동 직전에 사용자를 멈춰 세우는 **30초 안전 브레이크**를 목표로 합니다.

응답은 다음 순서로 구성됩니다.

1. 30초 안전 브레이크: 링크 클릭, 앱 설치, 송금, 인증번호 공유 중단 안내
2. 위험도: 낮음/주의/높음/매우 높음
3. 지금 하지 말아야 할 행동
4. 지금 해야 할 행동
5. 왜 위험한가요?: 탐지 신호를 심리 압박/위험 행동 관점으로 설명
6. 공식 신고 루트

## 툴 (MVP 2종)

| 이름 | 역할 |
|---|---|
| `analyzePhishingRisk` | 입력 텍스트 → 30초 안전 브레이크 → 위험도(낮음/주의/높음/매우 높음) + 근거 + 행동 가이드 |
| `getReportChannels` | 상황별 공식 신고 루트 (`suspiciousOnly`=의심만 받음, `alreadyPaid`=이미 송금, `personalInfoExposed`=개인정보 노출, `malwareInstalled`=악성앱 설치 의심) |

- 전송: **Streamable HTTP / Remote / Stateless(no session)**
- 안전: 입력 미저장, 민감정보 마스킹, 의심 링크 디팽, 모든 분석 출력에 디스클레이머, 응답 24k 가드
- 품질: 공식 시나리오 기반 fixture와 adversarial 합성 샘플 회귀 테스트로 가족/지인 사칭, 기관 사칭, 대출·택배·소액결제·투자/알바·악성앱 유도 유형을 점검

## 바로 해보기 (합성 데모 샘플)

> 아래는 실제 번호·계좌·URL이 없는 **합성 예시**입니다. `analyzePhishingRisk`의 `text`에 그대로 붙여 넣어 결과를 비교해 보세요.

| 입력 예시 | 기대 위험도 |
|---|---|
| 서울중앙지검 수사관입니다. 지금 안전계좌로 송금하고 인증번호 알려주세요. | 🔴 매우 높음 |
| 엄마 나 폰 깨져서 인증 안돼. 병원비 좀 보내줭 ㅠㅠ | 🟠 높음 |
| 편의점에서 구글기프트 사서 뒷면 코드 긁어 사진 보내. | 🔴 매우 높음 |
| [Web발신] CJ대한통운 주소 불일치 택배 보류. 아래에서 재입력. | 🟡 주의 |
| 고객님 상품이 배송 완료되었습니다. 자세한 내용은 공식 앱에서 확인하세요. | 🟢 낮음 |
| OTP는 누구에게도 알려주면 안 된다고 교육받았어. | 🟢 낮음 |

- **정상 문자(낮음)** 는 과한 경고 없이 한두 줄로 차분히 안내하고, **위험 문자**는 `30초 안전 브레이크 → 위험도 → 왜 위험한지 → 지금 할 행동 → 가족에게 공유할 문구` 순으로 응답합니다.
- 같은 입력에는 항상 같은 근거·결과가 나오는 **결정적(deterministic) 판정**이라 검증·재현이 쉽습니다.

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
