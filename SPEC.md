# 🚦 피싱 신호등 (PhishingSignal) — MCP Server SPEC

> 이 문서는 프로젝트의 <strong>단일 진실 출처(Single Source of Truth)</strong>다. <br>
> 코드 생성/수정 전 항상 이 문서를 먼저 읽는다. 값이 바뀌면 이 문서부터 갱신한다.

---

## 0. 한 줄 정의

수상한 전화·문자·카톡 내용을 붙여넣으면, 송금·앱설치·인증번호 공유 전에 사용자를 먼저 멈춰 세우고 <br>
**보이스피싱 위험도**, **판단 근거**, **지금 해야 할 행동**, **공식 신고 루트**를 안내하는 MCP 서버



- 포지셔닝 : "규칙 기반"이라고 부르지 않는다. **"근거 설명형 위험도 판별 / Explainable Risk Scoring"**
  
- 사용자 경험 포지셔닝 : **"30초 안전 브레이크"** — 분석보다 먼저 피해 행동(송금·앱설치·인증번호 공유)을 멈추게 한다.
  
- 판정은 LLM 호출이 아니라 **결정적(deterministic) 규칙 엔진**으로 한다.
  - 이유 : ① 응답 100ms 충족 ② 무과금 ③ 일관성 ④ 탐지 신호가 그대로 "판단 근거"가 됨
    
- LLM 호스트나 메신저 클라이언트는 자연어 이해를 맡고, 이 MCP는 판정·근거·행동을 반환한다.

---

## 1. 배포 / 심사 컨텍스트 (PlayMCP in KC)

- 배포 방식 : **Git 소스 빌드**. 레포 루트에 `Dockerfile`을 유지한다.
- 공개 Endpoint URL의 MCP 경로는 `https://<host>/mcp`를 기준으로 한다.
- PlayMCP 개발자 콘솔에서 임시 등록 → 도구함 테스트 → 심사 요청 순서로 검증한다.
- 서버는 Streamable HTTP / Remote / Stateless(no session) 구성을 유지한다.

---

## 2. 네이밍 (확정)

| 용도 | 값 | 비고 |
|---|---|---|
| GitHub 레포명 | `phishing-signal-mcp` | 케밥케이스, 영문, `-mcp` 접미사 |
| PlayMCP 등록명(표시) | `피싱 신호등` | 기능을 직관적으로 설명하는 표시명 |
| 영문 식별자/MCP 식별자 | `PhishingSignal` / `phishing-signal` | 콘솔/코드용 |
| MCP server name(영문) | `phishing-signal` | "kakao" 미포함, AI/Bot/Service 키워드 미사용 |

- description(영문+국문 병기, 규정 요구) :
  `Analyzes suspicious calls, SMS, or messenger texts for voice-phishing risk, returning a risk level with evidence and concrete action guides. 피싱 신호등(PhishingSignal)`

---

## 3. 스택 / 런타임 (확정)

- 언어 : **TypeScript**
- 런타임 : **Node.js 22 LTS**
- 패키지 매니저 : **npm**
- MCP SDK : **`@modelcontextprotocol/sdk`** (공식, MIT) — `package-lock.json` 기준으로 재현 설치
- 전송 : **Streamable HTTP**, **Remote(공개 URL)**, **Stateless(no session) 권장**
- MCP 스펙 버전 : 최소 `2025-03-26` ~ 최대 `2025-11-25` 충족
- 사전 점검 : **MCP Inspector**로 스펙 준수 확인

---

## 4. 툴 구성 (MVP = 2개)

> MVP는 수상한 연락 내용을 붙여넣었을 때, 즉시 위험도를 판단하고 행동 가이드와 공식 신고 루트까지 안내하는 흐름에 집중한다.


### 4.1 `analyzePhishingRisk`
- 역할 : 입력 텍스트에서 위험 신호 탐지 → 가중치 점수화 → 30초 안전 브레이크 + 위험도 구간 + 근거 + 행동 가이드 반환
- 입력 스키마 :
  ```ts
  type AnalyzePhishingRiskInput = {
    text: string;                      // 필수: 의심 문자/통화/메시지 내용 붙여넣기
    context?: {                        // 선택: 있으면 행동 가이드 정밀화
      channel?: 'phone' | 'sms' | 'kakao' | 'unknown'; // phone=전화, sms=문자, kakao=카카오톡/메신저, unknown=알 수 없음
      senderKnown?: boolean;           // 기존 연락처/지인으로 확인된 상대인지. 상대 주장만으로 true 금지
      relationship?: 'family' | 'friend' | 'coworker' | 'merchant' | 'unknown'; // 가족/친구·지인/직장동료/거래상대/알 수 없음
      alreadySentMoney?: boolean;      // 이미 송금/이체했는지
      alreadyInstalledApp?: boolean;   // 상대가 안내한 앱을 이미 설치했는지
      alreadySharedPersonalInfo?: boolean; // 개인정보·신분증·계좌·비밀번호 등을 이미 알려줬는지
    };
  };
  ```
- 출력(정제된 마크다운, 24k 미만) :
  - 낮음 응답은 과한 경고를 피하기 위해 위험도와 짧은 주의 안내 중심으로 간소화한다.
  - 주의 이상 응답은 다음 구성을 따른다.
  - 30초 안전 브레이크: 링크 클릭 / 앱 설치 / 송금 / 인증번호 공유 중단 안내
  - 위험도 : `낮음 | 주의 | 높음 | 매우 높음`
  - 지금 하지 말아야 할 행동
  - 지금 해야 할 행동
  - 왜 위험한가요? : 탐지된 위험 신호를 심리 압박/위험 행동 관점으로 설명
  - 가족에게 공유할 문구(높음/매우 높음일 때만 짧게)
  - (상황에 맞는) 공식 신고 루트 요약
  - 디스클레이머(아래 §7)

### 4.2 `getReportChannels`
- 역할 : 상황별 공식 신고/대응 루트를 우선순위와 함께 반환(정적, 초고속)
- 입력 스키마 :
  ```ts
  type GetReportChannelsInput = {
    situation: 'suspiciousOnly' | 'alreadyPaid' | 'personalInfoExposed' | 'malwareInstalled';
    // suspiciousOnly=의심만 받음, alreadyPaid=이미 송금/이체, personalInfoExposed=개인정보 노출, malwareInstalled=악성앱 설치 의심
  };
  ```
- 출력: §6의 확정값 기반 마크다운

### 4.3 공통 규칙 (PlayMCP)
- 각 툴 필수 property : `name, description, inputSchema, annotations`
- `annotations`: `title, readOnlyHint, destructiveHint, openWorldHint, idempotentHint` **모두 값 지정**
  - 두 툴 모두 읽기 전용 판정/조회 → `readOnlyHint: true, destructiveHint: false, idempotentHint: true`
  - 외부 호출 없음(자체 연산/정적 데이터) → `openWorldHint: false`
- 툴 이름 : 영숫자 + `_` + `-`, 1~128자, case-sensitive, 중복 금지
- description : 영문 권장, **서비스명(영문/국문 병기) 포함**, 1,024자 이내
- result 크기 최소화, API 원본 그대로 반환 금지(정제된 마크다운)

---

## 5. 위험 신호 7종 → 점수 → 구간 (Explainable Risk Scoring)

탐지 카테고리(각 신호가 곧 "판단 근거") :

1. 기관 사칭 (검찰·경찰·금감원·은행·택배·정부기관 등 사칭 표현)
2. 요구 행동 — 계좌이체 / 인증번호(OTP) 공유 / 원격제어 앱(AnyDesk·TeamViewer 등) 설치
3. 긴급성 압박 (즉시·지금 당장·기한·구속·범죄 연루 등 시간 압박)
4. 금전 피해 가능성 (송금·이체·대납·안전계좌·보증금·선입금 요구)
5. 개인정보 탈취 (주민번호·계좌·비밀번호·신분증 사진 요구)
6. 악성앱 설치 유도 (apk 링크, 출처불명 앱 설치 유도)
7. 의심 링크 (단축 URL, 비공식 도메인, [Web발신] + 링크 조합 등)

설계 원칙 :
- 각 신호에 가중치 부여 → 합산 점수 → 구간 매핑(낮음/주의/높음/매우 높음)
- 임계값(구간 경계)은 **보수적으로** : 오탐(false positive)보다 **미탐(false negative) 회피 우선**
- 초기 가중치/임계값은 v1에서 하드코딩 후, 실제 피싱 샘플로 캘리브레이션(후속)
- 탐지는 정규식/키워드 사전 기반이되, **카테고리 단위로 구조화**하여 "단순 키워드 매칭"으로 보이지 않게 한다.

---

## 6. 공식 신고 채널 — 확정값 (검증 완료)

> 출처 : 경찰청 통합대응단 1394 개통(2026-02-01, 정책브리핑/언론 복수 확인), <br>
> 금융감독원 보이스피싱지킴이, KISA 118, 금융소비자보호재단 안내 <br>
> **구 대표번호(1566-1688 / 1566-1188 혼재)는 최신성 불안정 → 코드에서 제외. 1394만 사용**

```ts
const REPORT_CHANNELS = {
  // 이미 송금/이체한 경우 — "즉시", 우선순위 순
  alreadyPaid: [
    { name: '경찰청', phone: '112', purpose: '피해 신고 및 사기이용계좌 지급정지 요청', priority: 1 },
    { name: '송금·입금 금융회사 고객센터', phone: '각 금융회사 대표번호', purpose: '계좌 지급정지 요청', priority: 2 },
    { name: '금융감독원', phone: '1332', purpose: '피해 상담 및 지급정지·환급 안내', priority: 3 },
    { name: '전기통신금융사기 통합대응단 신고대응센터', phone: '1394', purpose: '24시간 피해상담·제보·관계기관 연계', priority: 4 },
  ],
  // 의심 문자·전화만 받은 단계 (송금 전)
  suspiciousOnly: [
    { name: '전기통신금융사기 통합대응단 신고대응센터', phone: '1394', purpose: '피싱 여부 확인·제보(24시간)', priority: 1 },
    { name: 'KISA 상담센터', phone: '118', purpose: '스미싱·불법스팸·의심문자 상담/신고', priority: 2 },
  ],
  // 개인정보·신분증 노출
  personalInfoExposed: [
    { name: '금융감독원 개인정보노출자 사고예방시스템', url: 'pd.fss.or.kr', purpose: '노출 등록 → 신규 계좌·카드·대출 개설 차단', priority: 1 },
    { name: '명의도용방지서비스 엠세이퍼', url: 'msafer.or.kr', purpose: '명의도용 휴대전화 개통 여부 확인', priority: 2 },
  ],
  // 악성앱 설치 의심
  malwareInstalled: [
    { name: '휴대전화 초기화 / 통신사 고객센터', purpose: '악성 앱 삭제, 단말 초기화', priority: 1 },
    { name: '공동인증서·OTP 재발급', purpose: '탈취 대비 인증수단 폐기·재발급', priority: 2 },
  ],
};
```

- 송금 상황 문구는 "30분 골든타임"을 공식 문구로 박지 않고 <strong>"즉시"</strong>로 표현 :
  > "송금했다면 시간이 가장 중요합니다. **즉시** 112·거래 금융회사·1332·1394에 연락해 지급정지와 피해상담을 요청하세요."

---

## 7. 개인정보 / 안전 정책 (심사 직결)

- **미저장** : 입력 내용은 판별 목적 외 저장하지 않는다(stateless)
- **마스킹** : 입력에 포함된 계좌번호/주민번호/전화번호 등은 처리 전 마스킹 (정규식 범위는 보수적으로, 리뷰 대상)
- **금지 수집/전송** : 주민등록번호, 운전면허번호, 여권번호, 외국인등록번호, 카드번호, 계좌번호를 요구하거나 응답으로 전송하지 않는다.
- **민감정보 입력 금지 안내**를 출력에 포함(사용자가 OTP·비밀번호 등을 입력하지 않도록)
- **디스클레이머(모든 분석 출력에 고정)** :
  > "이 안내는 위험 신호에 대한 참고용 가이드이며 법적 판단이 아닙니다. 실제 상황에서는 공식 기관과 금융회사의 안내를 우선하세요."

---

## 8. 성능 / 안정성 (심사 정량 기준)

- 응답 : **평균 100ms 이내, p99 3,000ms 필수** → 외부 호출 없는 자체 연산/정적 데이터로 충족
- Tool Response **24k 초과 방지** → 출력 길이 가드(필요 시 일부 생략 안내)
- 인증 불필요(개인정보 OAuth 없음) 필요해질 경우에만 표준 OAuth/커스텀 헤더
- 예외 처리 : 빈 입력/초장문/비정상 입력에 안전한 기본 응답

---

## 9. 디렉터리 구조 (현재)

```
phishing-signal-mcp/
├─ .dockerignore           # Docker 빌드 컨텍스트 제외 규칙
├─ .gitignore              # 로컬 의존성/빌드 산출물/환경 파일 제외 규칙
├─ Dockerfile              # ★ PlayMCP in KC Git 빌드 필수
├─ package.json            # Node 22 / npm, MCP SDK, 테스트/빌드 스크립트
├─ package-lock.json       # npm ci 기반 재현 빌드
├─ tsconfig.json
├─ README.md               # 공개 레포 소개/실행/점검 안내
├─ SPEC.md                 # 본 문서
├─ src/
│  ├─ server.ts            # MCP 서버 부트스트랩(Streamable HTTP, stateless)
│  ├─ tools/
│  │  ├─ analyzePhishingRisk.ts # 위험도 분석 MCP 툴
│  │  └─ getReportChannels.ts   # 상황별 공식 신고 루트 MCP 툴
│  ├─ engine/
│  │  ├─ mask.ts              # 민감정보 마스킹
│  │  ├─ score.ts             # 가중치 합산 → 구간 매핑
│  │  ├─ signalSuppression.ts # 정상 문맥 과탐 억제
│  │  └─ signals.ts           # 위험 신호 7종 탐지기(정규식/사전)
│  ├─ data/
│  │  ├─ reportChannels.ts    # §6 공식 신고 채널 확정값
│  │  ├─ scamPatternLexicon.ts # 공통 피싱 문법/문맥 lexicon
│  │  ├─ scamScenarios.ts     # 공식/대표 시나리오 기반 탐지 데이터
│  │  └─ sourceDiscovery.ts    # 출처 검증 메모/데이터
│  └─ format/
│     └─ markdown.ts       # 출력 포맷터(24k 가드 포함)
└─ test/
   ├─ analyzePhishingRisk.test.ts      # 위험도 분석 툴 단위 테스트
   ├─ compliance.test.ts
   ├─ format.test.ts                  # 마크다운 포맷/24k 가드 테스트
   ├─ getReportChannels.test.ts       # 신고 채널 툴 테스트
   ├─ mask.test.ts                    # 민감정보 마스킹 테스트
   ├─ scamAdversarialQuality.test.ts  # adversarial 합성 샘플 품질/회귀 테스트
   ├─ scamCalibration.test.ts         # 캘리브레이션 샘플 구조/기대값 테스트
   ├─ scamScenarios.test.ts           # 대표 피싱 시나리오 회귀 테스트
   ├─ score.test.ts                   # 점수/위험도 구간 테스트
   ├─ server.test.ts                  # MCP 서버/툴 등록 테스트
   ├─ signals.test.ts                 # 위험 신호 탐지 테스트
   └─ fixtures/
      ├─ scamAdversarialSamples.ts    # adversarial 공격/정상 합성 샘플
      └─ scamCalibrationSamples.ts    # 캘리브레이션 합성 샘플
```

## 10. 구현 / 검증 상태

완료 :
1. `package.json` + `package-lock.json` + `tsconfig.json` + `Dockerfile` 구성
2. `engine` 구현 : 민감정보 마스킹 → 위험 신호 탐지 → 정상 문맥 suppression → 점수/구간 산정
3. `analyzePhishingRisk` : 입력 스키마, context-aware 보정, annotations 5종, 30초 안전 브레이크 중심 마크다운 출력
4. `getReportChannels` : §6 확정값 기반 상황별 공식 신고 채널 안내
5. `server.ts` : Streamable HTTP, Remote, stateless, `/mcp`, `/healthz`
6. 테스트 : compliance/server/tool/engine/scenario/adversarial 회귀 테스트

검증 순서 :
1. `npm run typecheck`
2. `npm test`
3. `npm run build`
4. 서버 기동 후 MCP Inspector에서 `http://127.0.0.1:3000/mcp` 연결 및 `tools/list`, `tools/call` 확인

---

## 11. 후속 고도화

- 마스킹 정밀도 개선 : 정상 숫자와 민감정보를 더 안정적으로 구분하도록 샘플 기반으로 보완한다.
- 위험도 캘리브레이션 : 실제 피싱·정상 샘플을 추가 확보해 임계값과 가중치를 지속적으로 튜닝한다.
- v2 후보 : 번호 평판 조회, URL 평판, 음성 분석, 신고 절차 보조(공식·무상 데이터 출처와 개인정보 처리 범위 검토 후)
