# 🚦 피싱 신호등 (PhishingSignal) — MCP Server


<code> **사기가 도착한 바로 그 대화 안에서, 송금·인증번호·앱설치 직전에 끼어들어 멈춰 세우는 30초 안전 브레이크.**</code>

<br>

수상한 전화·문자·메신저 내용을 붙여넣으면 송금·앱설치·인증번호 공유 전에 먼저 멈추게 하고, <br>
보이스피싱 **위험도와 근거**, **지금 해야 할 행동**, **공식 신고 루트**를 안내합니다. <br>
대화형 AI·메신저(MCP 호스트) 안에서 동작하므로 **별도 앱 설치 없이 사기가 일어나는 그 자리에서** 바로 판단합니다.

<hr>

> 판정은 LLM 호출이 아니라 **결정적(deterministic) 규칙 엔진**으로 수행합니다.  <br>
> (응답 100ms 목표·무과금·일관성) ➪ 자세한 제품/규정/확정값은 [SPEC.md](SPEC.md)를 참고하세요.

<br>

## 🧭 포지셔닝

피싱 신호등은 단순 탐지기가 아니라, <br> 수상한 연락을 받았을 때 피해 행동 직전에 사용자를 멈춰 세우는 **30초 안전 브레이크**를 목표로 합니다.



<ins>위험 신호가 있는 응답</ins>은 다음 순서로 구성됩니다.

1. 30초 안전 브레이크 : 링크 클릭, 앱 설치, 송금, 인증번호 공유 중단 안내
   
2. 위험도 : 낮음/주의/높음/매우 높음
   
3. 지금 하지 말아야 할 행동
   
4. 지금 해야 할 행동
   
5. 왜 위험한가요? : 탐지 신호를 심리 압박/위험 행동 관점으로 설명
    
6. 공식 신고 루트


<br>


## 🖼️ UX 프리뷰

> MCP 응답이 호스트 앱에서 어떻게 보일지 나타낸 디자인 프리뷰입니다(실제 서버는 정제된 Markdown을 반환). <br> **위험 결과는 위험도가 아니라 '멈춤 명령'으로 시작**하고, 정상(낮음)은 겁주지 않고 차분히 안내합니다. 위험도는 신호등 4색(🟢 낮음 · 🟡 주의 · 🟠 높음 · 🔴 매우 높음)으로 구분합니다.

<table>
  <tr>
    <td align="center" width="25%"><img src="docs/ux/01-landing.png" width="200" alt="붙여넣기 화면"><br><b>① 붙여넣기</b><br><sub>그 대화에 붙여넣으면 즉시 마스킹</sub></td>
    <td align="center" width="25%"><img src="docs/ux/02-context.png" width="200" alt="상황 선택 화면"><br><b>② 상황 선택</b><br><sub>신뢰 관계 확인 시에만 위험도 완화</sub></td>
    <td align="center" width="25%"><img src="docs/ux/03-result-high.png" width="200" alt="위험 결과 화면"><br><b>③ 분석 결과 · 위험</b><br><sub>🔴 위험도보다 멈춤 명령 먼저</sub></td>
    <td align="center" width="25%"><img src="docs/ux/03b-result-low.png" width="200" alt="정상 결과 화면"><br><b>③ 분석 결과 · 정상</b><br><sub>🟢 겁주지 않고 차분하게</sub></td>
  </tr>
  <tr>
    <td align="center"><img src="docs/ux/04-actions.png" width="200" alt="행동 가이드 화면"><br><b>④ 행동 가이드</b><br><sub>하지 마세요 / 하세요 분리</sub></td>
    <td align="center"><img src="docs/ux/05-why.png" width="200" alt="왜 위험한가 화면"><br><b>⑤ 왜 위험한가요</b><br><sub>신호→심리압박 번역 + 가족 공유</sub></td>
    <td align="center"><img src="docs/ux/06-report.png" width="200" alt="신고 채널 화면"><br><b>⑥ 신고 채널</b><br><sub>'이미 한 행동'에 따라 루트 분기</sub></td>
    <td align="center"><img src="docs/ux/07-privacy.png" width="200" alt="안전 원칙 화면"><br><b>⑦ 안전 원칙</b><br><sub>미저장·마스킹·외부 호출 없음·결정적</sub></td>
  </tr>
</table>

<br>

## 🛠️ 툴 (MVP 2종)

| 이름 | 역할 |
|---|---|
| `analyzePhishingRisk` | 입력 텍스트 → 30초 안전 브레이크 → 위험도(낮음/주의/높음/매우 높음) + 근거 + 행동 가이드 |
| `getReportChannels` | 상황별 공식 신고 루트  (`suspiciousOnly`=의심만 받음, `alreadyPaid`=이미 송금, <br>  `personalInfoExposed`=개인정보 노출, `malwareInstalled`=악성앱 설치 의심) |

- 전송 : **Streamable HTTP / Remote / Stateless(no session)**
- 안전 : 입력 미저장, 민감정보 마스킹, 의심 링크 디팽, 모든 분석 출력에 디스클레이머, 응답 24k 가드
- 품질 : 공식 시나리오 기반 fixture와 adversarial 합성 샘플 회귀 테스트로 가족/지인 사칭, 기관 사칭, 대출·택배·소액결제·투자/알바·악성앱 유도 유형을 점검

<br>

## 🧪 바로 해보기 (합성 데모 샘플)

> 아래는 실제 번호·계좌·URL이 없는 **합성 예시**입니다. <br>  `analyzePhishingRisk`의 `text`에 그대로 붙여 넣어 결과를 비교해 보세요.

<br>

| 입력 예시 | 기대 위험도 |
|---|---|
| 서울중앙지검 수사관입니다. 지금 안전계좌로 송금하고 인증번호 알려주세요. | 🔴 매우 높음 |
| 엄마 나 폰 깨져서 인증 안돼. 병원비 좀 보내줭 ㅠㅠ | 🟠 높음 |
| 편의점에서 구글기프트 사서 뒷면 코드 긁어 사진 보내. | 🔴 매우 높음 |
| [Web발신] CJ대한통운 주소 불일치 택배 보류. 아래에서 재입력. | 🟡 주의 |
| 고객님 상품이 배송 완료되었습니다. 자세한 내용은 공식 앱에서 확인하세요. | 🟢 낮음 |
| OTP는 누구에게도 알려주면 안 된다고 교육받았어. | 🟢 낮음 |

- **정상 문자(낮음)** 는 과한 경고 없이 한두 줄로 차분히 안내하고,  <br> **위험 문자**는 `30초 안전 브레이크 → 위험도 → 지금 하지 말아야 할 행동 → 지금 해야 할 행동 → 왜 위험한가요? → 공식 신고 루트` 순으로 응답합니다.

- `높음`/`매우 높음`에서는 `왜 위험한가요?` 뒤에 가족에게 공유할 문구가 추가됩니다.
  
- 같은 입력에는 항상 같은 근거·결과가 나오는 **결정적(deterministic) 판정**이라 검증·재현이 쉽습니다.

<br>

## 📊 품질 · 검증

판정 품질을 **CI가 매 커밋 강제하는 불변식**과 **회귀 테스트에 쓰지 않은 held-out 세트로 측정한 일반화 성능**으로 나눠 투명하게 공개합니다. <br> 모든 수치는 외부 호출 없는 결정적 엔진 측정값이며, `npm run report`로 [docs/QUALITY_REPORT.md](docs/QUALITY_REPORT.md)에서 재현됩니다.

| 구분 | 지표 | 값 |
|---|---|---|
| **CI 강제 불변식** <br>(매 커밋 단언) | 정상 문장 과잉경고 | **0건** (0/187) |
| | 공격 문장 경고 임계값 이상 | **100%** (286/286) |
| | 신호 재현율(Recall) | **100%** (89/89) |
| **Held-out 일반화** <br>(엔진이 본 적 없는 신규 샘플, n=40) | 탐지율(Recall) | **86.4%** (19/22) |
| | 정밀도(Precision) | 79.2% (19/24) |
| **측정 지표** | 위험도 정확 일치율 | 76.3% (251/329) |
| **보수적 방향성** | 회귀셋 미탐(under-call) | **0건** — 모든 불일치가 더 위험하게 본 방향 |

- **CI 강제 불변식**의 100% 수치는 *측정된 일반화 성능이 아니라* 회귀 테스트가 매 커밋 강제하는 하드 게이트입니다.
- **Held-out 세트**는 회귀 데이터와 분리해 엔진이 학습·튜닝에 쓰지 않은 신규 샘플이라, 순환논리 없는 일반화 추정입니다(표본 40개라 신뢰구간은 넓습니다).

> **정직한 한계** : held-out 정밀도가 보여주듯 "사기를 *언급*하는 안전한 문장"을 과경고하는 사례가 남아 있고, 새로운 난독화·우회 표현은 미탐될 수 있습니다. 규칙 엔진의 구조적 한계이며 샘플 보강으로 지속 개선합니다.

<br>

## 🔀 동작 흐름

`analyzePhishingRisk`의 내부 처리 흐름입니다. 마스킹 → **탐지용 정규화**(은어·오타·띄어쓰기 표준화, 매칭 사본에만) → 신호별 정상 문맥 억제 → 7종 패턴 매칭 → context 보정 → 점수화 → 정제 Markdown 순으로, 외부 호출 없이 **결정적**으로 동작합니다.

```mermaid
flowchart TD
    A["tool call: analyzePhishingRisk"] --> B["입력 검증"]
    B --> C["text 최대 20,000자 분석"]
    C --> D["maskSensitive"]
    D --> E["PII 숫자 마스킹"]
    E --> F["detectSignals"]
    F --> F2["탐지용 정규화: 은어·오타·띄어쓰기 → 표준어 (매칭 사본, 원문 불변)"]
    F2 --> N["신호별 정상 문맥 억제 검사 (원문 기준)"]
    N --> G["기관·가족/지인 사칭"]
    N --> H["위험 행동 요구"]
    N --> I["긴급성 압박"]
    N --> J["금전 피해 가능성"]
    N --> K["개인정보 탈취"]
    N --> L["악성앱 설치 유도"]
    N --> M["의심 링크/발신"]
    G --> O["context 기반 신호 보정"]
    H --> O
    I --> O
    J --> O
    K --> O
    L --> O
    M --> O
    O --> P{"신뢰 관계 정산성 계좌 요청?"}
    P -->|"예, 고위험 신호 없음"| Q["계좌 단독 personalInfo 신호 제거"]
    P -->|"아니오"| R["신호 유지"]
    Q --> S["scoreSignals 가중치 합산"]
    R --> S
    S --> U{"총점"}
    U -->|"0 이하"| V["낮음"]
    U -->|"1-2"| W["주의"]
    U -->|"3-5"| X["높음"]
    U -->|"6 이상"| Y["매우 높음"]
    V --> Z["formatRiskAnalysis → 정제 Markdown"]
    W --> Z
    X --> Z
    Y --> Z
```

<details>
<summary><b>전체 처리 흐름 더 보기</b> · 요청 라우팅 / 신고 상황 선택 / 출력 분기 / getReportChannels</summary>

<br>

**MCP 요청 라우팅 (stateless)**

```mermaid
flowchart TD
    A["MCP Host 또는 Inspector"] --> B["HTTP 요청 수신"]
    B --> C["CORS 헤더 설정"]
    C --> D{"요청 경로와 메서드"}
    D -->|"OPTIONS"| E["204 응답"]
    D -->|"GET /healthz 또는 /"| F["헬스 체크 JSON"]
    D -->|"POST /mcp"| G["JSON body 읽기"]
    D -->|"GET·DELETE /mcp"| H["405 Method not allowed"]
    D -->|"그 외"| I["404 Not found"]
    G --> J{"본문 파싱 성공?"}
    J -->|"아니오"| K["400 JSON-RPC parse error"]
    J -->|"예"| L["새 McpServer 생성 → 툴 2종 등록"]
    L --> O["StreamableHTTP transport (sessionId undefined)"]
    O --> Q["stateless 요청 처리 → 응답"]
    Q --> S["close 시 transport/server 정리"]
```

**context → 신고 상황(situation) 선택**

```mermaid
flowchart TD
    A["context 입력"] --> B{"alreadySentMoney?"}
    B -->|"true"| C["alreadyPaid → 112·금융회사·1332·1394"]
    B -->|"false/없음"| D{"alreadySharedPersonalInfo?"}
    D -->|"true"| E["personalInfoExposed → pd.fss.or.kr·msafer.or.kr"]
    D -->|"false/없음"| F{"alreadyInstalledApp?"}
    F -->|"true"| G["malwareInstalled → 초기화·인증수단 재발급"]
    F -->|"false/없음"| H["suspiciousOnly → 1394·118"]
```

**출력 Markdown 분기**

```mermaid
flowchart TD
    A["formatRiskAnalysis"] --> B{"위험도 낮음?"}
    B -->|"예"| C["낮음 결과: 위험도 + 짧은 주의 + 민감정보 금지 + 디스클레이머"]
    B -->|"아니오"| H["주의 이상 결과"]
    H --> I["30초 안전 브레이크"]
    I --> K["지금 하지 말 행동 / 할 행동 / 채널별 추가"]
    K --> N["왜 위험한가요?"]
    N --> O{"높음·매우 높음?"}
    O -->|"예"| P["가족 공유 문구"]
    O -->|"아니오"| R["공식 신고 루트"]
    P --> R
    C --> U["24k byte 출력 가드"]
    R --> U
```

**getReportChannels 흐름**

```mermaid
flowchart TD
    A["tool call: getReportChannels"] --> B["situation 입력 검증"]
    B --> C{"situation"}
    C -->|"suspiciousOnly"| D["1394, 118"]
    C -->|"alreadyPaid"| E["즉시 대응 강조 → 112, 금융회사, 1332, 1394"]
    C -->|"personalInfoExposed"| F["pd.fss.or.kr, msafer.or.kr"]
    C -->|"malwareInstalled"| G["초기화, 인증수단 폐기·재발급"]
    D --> L["우선순위 순 Markdown → 디스클레이머 → 24k 가드"]
    E --> L
    F --> L
    G --> L
```

</details>

> 한 페이지 시각본: [PhishingSignal Flowchart (PDF)](docs/PhishingSignal-Flowchart.pdf)

<br>

## ⚙️ 요구 사항

- **Node.js 22 LTS** (`engines: ">=22"`)
- **npm**


<br>    

## 🚀 설치 / 빌드 / 실행

```bash
# 설치 / 빌드 / 서버 실행
node --version       
npm ci               
npm run build        
npm start            

# 개발 모드
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


<br>


## 🔎 MCP Inspector 점검

[MCP Inspector](https://github.com/modelcontextprotocol/inspector)로 스펙 준수를 확인합니다.

```bash
# 1) 서버 기동
PORT=3000 npm start

# 2-A) UI 모드: 브라우저에서 Transport=Streamable HTTP, URL=http://127.0.0.1:3000/mcp 로 연결
npx @modelcontextprotocol/inspector

# 2-B) CLI 모드(헤드리스)
npx @modelcontextprotocol/inspector --cli http://127.0.0.1:3000/mcp \
  --transport http --method tools/list

npx @modelcontextprotocol/inspector --cli http://127.0.0.1:3000/mcp \
  --transport http --method tools/call --tool-name getReportChannels \
  --tool-arg situation=suspiciousOnly
```

점검 포인트 : 툴 2종 노출, 각 툴의 `name/description/inputSchema/annotations(5종)`, 응답 마크다운(디스클레이머 포함), 응답 크기 24k 이내


<br>


## 🐳 Docker (PlayMCP in KC — Git 소스 빌드)

레포 루트의 [Dockerfile](Dockerfile)로 빌드합니다. (멀티스테이지, Node 22, 비루트 실행)

```bash
docker build -t phishing-signal-mcp .
docker run --rm -p 3000:3000 -e PORT=3000 phishing-signal-mcp
curl http://127.0.0.1:3000/healthz
```

> 재현 빌드를 위해 `npm ci`를 사용하므로 `package-lock.json`이 커밋되어 있어야 합니다.

<br>

## 📦 배포 (PlayMCP 콘솔)

1. 공개 Endpoint URL 확보 → 경로는 `https://<host>/mcp`
2. PlayMCP 개발자 콘솔에 임시 등록 → 도구함 추가 → AI채팅 테스트 → 심사 요청
3. 심사 통과 후 공개 상태를 "전체 공개"로 전환






