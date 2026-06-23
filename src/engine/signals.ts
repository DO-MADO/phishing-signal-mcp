// 위험 신호 7종 탐지기 (SPEC §5)
// 각 신호가 곧 "판단 근거"다. 카테고리 단위로 정규식 사전을 구조화한다(단순 키워드 매칭처럼 보이지 않게).
// 입력은 보통 마스킹된 텍스트(SPEC §7)지만, 모듈 자체는 임의 문자열을 받는다(조립은 tools/ 단계).

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
    label: '기관 사칭',
    description: '검찰·경찰·금융감독원 등 공공기관/금융기관 사칭 표현',
    patterns: [
      /(검찰청|대검찰청|지방검찰청|서울중앙지검|검찰|수사관|경찰청|경찰서|사이버수사|경찰|금융감독원|금감원|국세청|세무서|건강보험공단|국민연금공단|국민연금|우체국|관세청|법원|등기소|정부24)/g,
    ],
  },
  {
    id: 'requestedAction',
    label: '위험 행동 요구',
    description: '인증번호(OTP) 공유 또는 원격제어 앱 설치 유도',
    patterns: [
      /(인증번호|승인번호|OTP|보안카드(?:\s*번호)?|원격제어|원격\s*(?:접속|지원|조종)|원격|애니데스크|anydesk|팀뷰어|teamviewer|화면\s*공유|미러링)/gi,
    ],
  },
  {
    id: 'urgency',
    label: '긴급성 압박',
    description: '즉시·기한·구속 등 시간 압박 및 위협 표현',
    patterns: [
      /(즉시|지금\s*당장|당장|긴급|서둘러|빨리|기한|오늘\s*까지|마감|구속|체포|영장|압류|동결|처벌|연루|불응\s*시|법적\s*조치)/g,
    ],
  },
  {
    id: 'financialLoss',
    label: '금전 피해 가능성',
    description: '송금·안전계좌·대납·보증금 등 금전 요구',
    patterns: [
      /(송금|계좌\s*이체|이체|안전\s*계좌|대납|보증금|선입금|무통장|공탁금|벌금|예치금|납부|입금)/g,
    ],
  },
  {
    id: 'personalInfo',
    label: '개인정보 탈취',
    description: '주민번호·계좌·비밀번호·신분증 등 민감정보 요구',
    patterns: [
      /(주민\s*등록\s*번호|주민\s*번호|계좌\s*번호|비밀\s*번호|비번|카드\s*번호|보안\s*카드\s*번호|신분증\s*사진|신분증|통장\s*사본|cvc|cvv)/gi,
    ],
  },
  {
    id: 'malwareApp',
    label: '악성앱 설치 유도',
    description: 'apk 등 출처불명 앱 설치 유도',
    patterns: [
      /(\.apk|apk\s*파일|apk|어플\s*설치|앱\s*설치|어플리케이션\s*설치|출처를?\s*알\s*수\s*없는|알\s*수\s*없는\s*출처|설치\s*파일|보안\s*앱\s*설치|인증\s*앱\s*설치)/gi,
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
    ],
  },
];

/** 텍스트에서 발화된(매칭된) 위험 신호 목록을 반환한다. */
export function detectSignals(text: string): DetectedSignal[] {
  const detected: DetectedSignal[] = [];
  for (const def of SIGNAL_DEFINITIONS) {
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
