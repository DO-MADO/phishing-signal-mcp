// 위험 신호 7종 탐지기 (SPEC §5)
// 각 신호가 곧 "판단 근거"다. 카테고리 단위로 정규식 사전을 구조화한다(단순 키워드 매칭처럼 보이지 않게).
// 입력은 보통 마스킹된 텍스트(SPEC §7)지만, 모듈 자체는 임의 문자열을 받는다(조립은 tools/ 단계).

import { getScenarioPatterns } from '../data/scamScenarios.js';

export type SignalId =
  | 'impersonation' // 1. 기관 사칭
  | 'requestedAction' // 2. 요구 행동(OTP 공유 / 원격제어 앱)
  | 'urgency' // 3. 긴급성 압박
  | 'financialLoss' // 4. 금전 피해 가능성
  | 'personalInfo' // 5. 개인정보 탈취
  | 'malwareApp' // 6. 악성앱 설치 유도
  | 'suspiciousLink'; // 7. 의심 링크/발신

export interface SignalDefinition {
  readonly id: SignalId;
  readonly label: string; // 한국어 근거 라벨
  readonly description: string; // 근거 출력용 짧은 설명
  readonly patterns: readonly RegExp[]; // 모두 'g' 플래그 필요
}

export interface DetectedSignal {
  readonly id: SignalId;
  readonly label: string;
  readonly matches: string[]; // 매칭된 표현(중복 제거) = 근거 스니펫
}

export const SIGNAL_DEFINITIONS: readonly SignalDefinition[] = [
  {
    id: 'impersonation',
    label: '기관·가족/지인 사칭',
    description: '공공기관·금융기관 또는 가족/지인 사칭 표현',
    patterns: [
      /(검찰청|대검찰청|지방검찰청|서울중앙지검|검찰|검\s*사|수사관|수\s*사\s*관|경찰청|경찰서|사이버수사|경찰|금융감독원|금감원|금\s*감\s*원|국세청|세무서|건강보험공단|국민연금공단|국민연금|우체국|관세청|법원|등기소|정부24)/g,
      ...getScenarioPatterns('impersonation'),
    ],
  },
  {
    id: 'requestedAction',
    label: '위험 행동 요구',
    description: '인증번호(OTP) 공유 또는 원격제어 앱 설치 유도',
    patterns: [
      /(인증\s*번호|인\s*증\s*번\s*호|승인\s*번호|승\s*인\s*번\s*호|OTP|오\s*티\s*피|ㅇ\s*ㅈ\s*ㅂ\s*ㅎ|보안\s*카드(?:\s*번호)?).{0,25}(불러|알려|말해|입력|전송|제출|공유|보내|캡처|찍어)/gi,
      /(원격제어|원격\s*(?:접속|지원|조종)|원격지원|애니데스크|anydesk|팀뷰어|teamviewer|화면\s*공유|미러링).{0,25}(설치|깔|실행|연결|접속|허용|코드|켜|공유)/gi,
      ...getScenarioPatterns('requestedAction'),
    ],
  },
  {
    id: 'urgency',
    label: '긴급성 압박',
    description: '즉시·기한·구속 등 시간 압박 및 위협 표현',
    patterns: [
      /(즉시|지금\s*당장|당장|긴급|서둘러|빨리|급하게|급해|기한|오늘\s*까지|마감|구속|체포|영장|압류|동결|처벌|연루|불응\s*시|법적\s*조치)/g,
      ...getScenarioPatterns('urgency'),
    ],
  },
  {
    id: 'financialLoss',
    label: '금전 피해 가능성',
    description: '송금·안전계좌·대납·보증금 등 금전 요구',
    patterns: [
      /(안전\s*계좌|대납|보증금|선입금|무통장|공탁금|벌금|예치금)/gi,
      /(핀\s*번호|PIN).{0,20}(보내|알려|전송|사진|캡처|찍어서)/gi,
      /(?:송금|입금|이체|납부)\s*(?:좀|해\s*(?:줘[요용욤여잉ㅇ~!?.ㅠㅜ]*|주라|줄래|주세요|주시|라|야)?|하세요|하라|해야|부탁|요청|바랍니다|필요|진행|처리)/gi,
      ...getScenarioPatterns('financialLoss'),
    ],
  },
  {
    id: 'personalInfo',
    label: '개인정보 탈취',
    description: '주민번호·계좌·비밀번호·신분증 등 민감정보 요구',
    patterns: [
      /(주민\s*등록\s*번호|주민\s*번호|계좌\s*번호|비밀\s*번호|비번|카드\s*번호|보안\s*카드\s*번호|신분증\s*사진|신분증|통장\s*사본|cvc|cvv).{0,25}(불러|알려|말해|입력|전송|제출|공유|보내|촬영|찍어|확인)/gi,
      /(불러|알려|말해|입력|전송|제출|공유|보내|촬영|찍어|확인).{0,25}(주민\s*등록\s*번호|주민\s*번호|계좌\s*번호|비밀\s*번호|비번|카드\s*번호|보안\s*카드\s*번호|신분증\s*사진|신분증|통장\s*사본|cvc|cvv)/gi,
      ...getScenarioPatterns('personalInfo'),
    ],
  },
  {
    id: 'malwareApp',
    label: '악성앱 설치 유도',
    description: 'apk 등 출처불명 앱 설치 유도',
    patterns: [
      /(\.apk|apk\s*파일|apk|어플\s*설치|앱\s*설치|어플리케이션\s*설치|어플\s*깔|앱\s*깔|출처를?\s*알\s*수\s*없는|알\s*수\s*없는\s*출처|설치\s*파일|보안\s*(?:앱|어플|프로그램)\s*(?:설치|깔|실행)|인증\s*(?:앱|어플)\s*설치|접근성\s*허용)/gi,
      ...getScenarioPatterns('malwareApp'),
    ],
  },
  {
    id: 'suspiciousLink',
    label: '의심 링크/발신',
    description: '[Web발신]·단축 URL·비공식 링크 등',
    patterns: [
      /\[\s*(?:web\s*발신|국제\s*발신|국외\s*발신)\s*\]/gi,
      /(bit\.ly|tinyurl\.com|t\.co|goo\.gl|han\.gl|me2\.do|vo\.la|c11\.kr|abr\.ge|is\.gd|buly\.kr|url\.kr)/gi,
      /(https?:\/\/[^\s<>"']+)/gi,
      ...getScenarioPatterns('suspiciousLink'),
    ],
  },
];

const BENIGN_CONTEXT_PATTERNS: Partial<Record<SignalId, readonly RegExp[]>> = {
  impersonation: [
    /(검찰|경찰서?|경찰|수사|법원|등기|은행|대출|건강보험|주민센터|세무서|환급|택배|카드\s*발급|정부지원금).{0,35}(뉴스|기사|드라마|공부|절차|위치|검색|제도|설명|자료|읽|비교|상담\s*예약|전입신고|직접\s*(?:냈|방문|다녀)|문의|물어봤|보냈어|앱에서\s*했)/,
    /(뉴스|기사|드라마|공부|절차|위치|검색|제도|설명|자료|읽|비교|상담\s*예약|전입신고|직접\s*(?:냈|방문|다녀)|문의|물어봤|보냈어|앱에서\s*했).{0,35}(검찰|경찰서?|경찰|수사|법원|등기|은행|대출|건강보험|주민센터|세무서|환급|택배|카드\s*발급|정부지원금)/,
    /(자녀|아이|아들|딸|학생|가족|사고).{0,30}(예방|교육|자료|읽|사례|법교육)/,
    /(예방|교육|자료|읽|사례|법교육).{0,30}(자녀|아이|아들|딸|학생|가족|사고)/,
  ],
  requestedAction: [
    /(OTP|오\s*티\s*피|인증\s*번호|인\s*증\s*번\s*호|승인\s*번호|보안\s*카드|원격\s*지원|원격지원|보안\s*(?:앱|어플|프로그램)|앱\s*설치|어플\s*설치).{0,45}(절대|안\s*된|하지\s*마|알려주지|타인에게|요구하면|피싱일 수|배웠|교육|내부\s*게시판|사내|IT팀|예약|로그인|재발급|하는\s*법|방법|설명서|완료|알림|가입\s*완료)/i,
    /(절대|안\s*된|하지\s*마|알려주지|타인에게|요구하면|피싱일 수|배웠|교육|내부\s*게시판|사내|IT팀|예약|로그인|재발급|하는\s*법|방법|설명서|완료|알림|가입\s*완료).{0,45}(OTP|오\s*티\s*피|인증\s*번호|인\s*증\s*번\s*호|승인\s*번호|보안\s*카드|원격\s*지원|원격지원|보안\s*(?:앱|어플|프로그램)|앱\s*설치|어플\s*설치)/i,
  ],
  financialLoss: [
    /(용돈|병원비\s*급함|안전\s*계좌|계좌\s*대여|계좌\s*빌려|통장|체크카드|돈\s*전달|현금\s*전달|수고비|리딩방|원금\s*보장).{0,45}(물어보|표현|문구|광고|부적절|의심해야|말이\s*나오면|조심해야|교육|강의|사례|계획|가계부|안\s*된|위험|불법|하지\s*말|피해야|주의)/i,
    /(물어보|표현|문구|광고|부적절|의심해야|말이\s*나오면|조심해야|교육|강의|사례|계획|가계부|안\s*된|위험|불법|하지\s*말|피해야|주의).{0,45}(용돈|병원비\s*급함|안전\s*계좌|계좌\s*대여|계좌\s*빌려|통장|체크카드|돈\s*전달|현금\s*전달|수고비|리딩방|원금\s*보장)/i,
  ],
  personalInfo: [
    /(계좌\s*이체).{0,35}(한도|늘리는\s*법|수수료|무료|편하다)/i,
    /(한도|늘리는\s*법|수수료|무료|편하다).{0,35}(계좌\s*이체)/i,
    /(주민\s*번호|계좌\s*번호|비밀\s*번호|비밀번호|보안\s*카드|신분증|통장\s*사본|cvc|cvv).{0,45}(절대|안\s*된|하지\s*마|알려주지|타인에게|요구하면|피싱일 수|배웠|교육|까먹|챙겨|어디|늘리는\s*법|재발급|로그인|확인했|확인했습니다|완료|가입\s*완료)/i,
    /(절대|안\s*된|하지\s*마|알려주지|타인에게|요구하면|피싱일 수|배웠|교육|까먹|챙겨|어디|늘리는\s*법|재발급|로그인|확인했|확인했습니다|완료|가입\s*완료).{0,45}(주민\s*번호|계좌\s*번호|비밀\s*번호|비밀번호|보안\s*카드|신분증|통장\s*사본|cvc|cvv)/i,
    /(계좌|통장|체크카드).{0,45}(대여|빌려주|빌려|맡기|전달).{0,45}(안\s*된|하지\s*마|불법|위험|교육|강의|사례|배웠)/i,
    /(안\s*된|하지\s*마|불법|위험|교육|강의|사례|배웠).{0,45}(계좌|통장|체크카드).{0,45}(대여|빌려주|빌려|맡기|전달)/i,
  ],
  malwareApp: [
    /(회사|사내|내부\s*게시판|IT팀|예약|하는\s*법|방법|설명서|설명해|오류|메뉴|어디|완료|알림).{0,45}(보안\s*(?:앱|어플|프로그램)|원격\s*지원|원격지원|앱\s*설치|어플\s*설치|설치\s*방법|접근성\s*허용|파일\s*실행|권한)/i,
    /(보안\s*(?:앱|어플|프로그램)|원격\s*지원|원격지원|앱\s*설치|어플\s*설치|설치\s*방법|접근성\s*허용|파일\s*실행|권한).{0,45}(회사|사내|내부\s*게시판|IT팀|예약|하는\s*법|방법|설명서|설명해|오류|메뉴|어디|완료|알림)/i,
  ],
};

function shouldSuppressSignal(signalId: SignalId, text: string): boolean {
  return (BENIGN_CONTEXT_PATTERNS[signalId] ?? []).some((pattern) => pattern.test(text));
}

/** 텍스트에서 발화된(매칭된) 위험 신호 목록을 반환한다. */
export function detectSignals(text: string): DetectedSignal[] {
  const detected: DetectedSignal[] = [];
  for (const def of SIGNAL_DEFINITIONS) {
    if (shouldSuppressSignal(def.id, text)) continue;

    const found = new Set<string>();
    for (const pattern of def.patterns) {
      const matches = text.match(pattern); // g 플래그 → 전체 매칭 배열 또는 null
      if (matches) {
        for (const m of matches) {
          const trimmed = m.trim();
          if (trimmed.length > 0) found.add(trimmed);
        }
      }
    }
    if (found.size > 0) {
      detected.push({ id: def.id, label: def.label, matches: [...found] });
    }
  }
  return detected;
}
