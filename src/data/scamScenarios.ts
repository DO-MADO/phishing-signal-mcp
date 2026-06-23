// 공식 출처 기반 대표 보이스피싱 시나리오 큐레이션.
// 원문 사례/악성 URL/실제 전화번호/계좌번호/개인정보는 저장하지 않고,
// 위험 신호 패턴과 출처 메타데이터만 정적으로 보관한다.

import type { RiskLevel } from '../engine/score.js';
import type { SignalId } from '../engine/signals.js';

export type OfficialSourceId = 'police-phishing-sos' | 'fss-voice-phishing' | 'kisa-boho';

export interface OfficialSourceReference {
  readonly id: OfficialSourceId;
  readonly name: string;
  readonly url: string;
  readonly basis: string;
}

export const OFFICIAL_SOURCE_REFERENCES: readonly OfficialSourceReference[] = [
  {
    id: 'police-phishing-sos',
    name: '경찰청 피싱안심SOS',
    url: 'https://www.counterscam112.go.kr/bbs009/board/boardList.do',
    basis: '피싱안심SOS 피싱 시나리오 목록과 상세의 제목·태그·핵심 위험 신호 기반 큐레이션',
  },
  {
    id: 'fss-voice-phishing',
    name: '금융감독원 보이스피싱지킴이',
    url: 'https://www.fss.or.kr',
    basis: '검찰·경찰·금감원 사칭, 대출 빙자, 안전계좌, 개인정보·인증정보 요구 유형 큐레이션',
  },
  {
    id: 'kisa-boho',
    name: 'KISA 보호나라',
    url: 'https://www.boho.or.kr',
    basis: '스미싱, 큐싱, 택배·지원금 사칭 문자, 악성앱 설치 유도 유형 큐레이션',
  },
];

export interface ScamScenario {
  readonly id: string;
  readonly title: string;
  readonly recommendedLevel: RiskLevel;
  readonly sourceIds: readonly OfficialSourceId[];
  readonly categories: readonly SignalId[];
  readonly reason: string;
  readonly patterns: Partial<Record<SignalId, readonly RegExp[]>>;
}

export interface CounterscamScenarioReference {
  readonly sourceUrl: string;
  readonly sourceTitle: '피싱안심SOS 피싱 시나리오';
  readonly scenarioTitle: string;
  readonly tags: readonly string[];
  readonly riskSignals: readonly SignalId[];
  readonly patternHints: readonly string[];
  readonly recommendedRiskLevel: RiskLevel;
}

export const COUNTERSCAM_SCENARIO_REFERENCES: readonly CounterscamScenarioReference[] = [
  {
    sourceUrl: 'https://www.counterscam112.go.kr/bbs009/board/boardList.do',
    sourceTitle: '피싱안심SOS 피싱 시나리오',
    scenarioTitle: '자녀납치 협박',
    tags: ['자녀납치', '협박', '납치'],
    riskSignals: ['impersonation', 'urgency', 'financialLoss'],
    patternHints: ['자녀·아이 사고/납치/감금 언급', '해치지 않겠다는 협박성 안심', '술값·합의금·대가 명목 금전 요구'],
    recommendedRiskLevel: '매우 높음',
  },
  {
    sourceUrl: 'https://www.counterscam112.go.kr/bbs009/board/boardList.do',
    sourceTitle: '피싱안심SOS 피싱 시나리오',
    scenarioTitle: '성매매(마사지샵) 업소 방문사실 유포 협박',
    tags: ['성매매', '마사지', '협박'],
    riskSignals: ['urgency', 'financialLoss', 'personalInfo'],
    patternHints: ['마사지샵·성매매 방문 사실 언급', '영상 촬영·유포 협박', '가족·지인 연락처 확보 주장', '합의 명목 금전 요구'],
    recommendedRiskLevel: '매우 높음',
  },
  {
    sourceUrl: 'https://www.counterscam112.go.kr/bbs009/board/boardList.do',
    sourceTitle: '피싱안심SOS 피싱 시나리오',
    scenarioTitle: '카드사 사칭',
    tags: ['카드사', '사칭'],
    riskSignals: ['impersonation', 'requestedAction', 'financialLoss', 'personalInfo', 'malwareApp'],
    patternHints: ['카드 배송·카드 발급 확인', '사고예방팀·보안팀 연결', '생년월일·성명 등 확인 요구', '원격앱 설치 유도', '자산보호·범죄수익 검사 명목 이체'],
    recommendedRiskLevel: '매우 높음',
  },
  {
    sourceUrl: 'https://www.counterscam112.go.kr/bbs009/board/boardList.do',
    sourceTitle: '피싱안심SOS 피싱 시나리오',
    scenarioTitle: '대환대출 사기',
    tags: ['대환대출', '사기', '대출'],
    riskSignals: ['impersonation', 'urgency', 'financialLoss', 'malwareApp'],
    patternHints: ['저금리·정부지원 대환대출 미끼', '기존 금융기관 계약위반·전액 상환 압박', '신청서·파일 전송과 악성앱 설치', '현금 인출·전달 또는 이체 요구'],
    recommendedRiskLevel: '매우 높음',
  },
  {
    sourceUrl: 'https://www.counterscam112.go.kr/bbs009/board/boardList.do',
    sourceTitle: '피싱안심SOS 피싱 시나리오',
    scenarioTitle: '관공서 사칭',
    tags: ['관공서', '사칭', '관공서 사칭'],
    riskSignals: ['impersonation', 'suspiciousLink', 'personalInfo'],
    patternHints: ['주민센터·세무서 등 관공서 사칭', '명의도용·사업자등록·위임장 언급', '신분증·도장·생년월일·전화번호 확인', '피싱 사이트 링크 접속 유도'],
    recommendedRiskLevel: '높음',
  },
  {
    sourceUrl: 'https://www.counterscam112.go.kr/bbs009/board/boardList.do',
    sourceTitle: '피싱안심SOS 피싱 시나리오',
    scenarioTitle: '수사기관 사칭',
    tags: ['사칭', '수사기관', '전화피싱'],
    riskSignals: ['impersonation', 'requestedAction', 'urgency', 'personalInfo', 'suspiciousLink'],
    patternHints: ['검찰·경찰·법원 등 수사기관 사칭', '등기 반송·사건 조회 명목', 'URL 접속·모바일/PC 열람 유도', '사건번호·계좌·인증번호 요구'],
    recommendedRiskLevel: '매우 높음',
  },
];

export const SCAM_SCENARIOS: readonly ScamScenario[] = [
  {
    id: 'family_or_friend_impersonation_money_request',
    title: '가족·지인 사칭 금전 요구',
    recommendedLevel: '높음',
    sourceIds: ['police-phishing-sos'],
    categories: ['impersonation', 'urgency', 'financialLoss'],
    reason: '가족 또는 지인을 사칭하면서 급한 사정을 이유로 송금·입금을 요구하는 패턴입니다.',
    patterns: {
      impersonation: [
        /(엄마|아빠|어머니|아버지|아들|딸|자녀|오빠|누나|형|언니|친구|지인).{0,30}(나야|나다|폰\s*고장|휴대폰\s*고장|핸드폰\s*고장|번호\s*(?:바뀜|변경)|카톡\s*안\s*됨)/g,
      ],
      urgency: [/(급해|급하게|지금|바로|빨리|당장).{0,30}(도와줘|처리|보내줘|입금|송금|이체)/g],
      financialLoss: [
        /(돈|비용|수리비|병원비|합의금|상품권|기프트\s*카드|핀번호|PIN).{0,30}(보내줘|빌려줘|입금|송금|이체|사줘|필요)/gi,
        /(보내줘|빌려줘|입금|송금|이체|사줘).{0,30}(돈|비용|수리비|병원비|합의금|상품권|기프트\s*카드|핀번호|PIN)/gi,
      ],
    },
  },
  {
    id: 'phone_broken_or_number_changed',
    title: '휴대폰 고장·번호 변경 사칭',
    recommendedLevel: '주의',
    sourceIds: ['police-phishing-sos'],
    categories: ['impersonation', 'urgency'],
    reason: '휴대폰 고장 또는 번호 변경을 핑계로 본인 확인을 어렵게 만드는 사칭 패턴입니다.',
    patterns: {
      impersonation: [
        /(폰|휴대폰|핸드폰|카톡).{0,12}(고장|분실|안\s*됨|안돼|못\s*써|액정\s*깨짐)/g,
        /(번호|연락처).{0,12}(바뀜|변경|새로|임시)/g,
      ],
    },
  },
  {
    id: 'gift_card_pin_request',
    title: '상품권·기프트카드·PIN 요구',
    recommendedLevel: '매우 높음',
    sourceIds: ['police-phishing-sos'],
    categories: ['requestedAction', 'financialLoss'],
    reason: '상품권 구매 후 PIN·사진 전달을 요구하는 고위험 결제 유도 패턴입니다.',
    patterns: {
      requestedAction: [
        /(상품권|문화\s*상품권|기프트\s*카드|구글\s*기프트|핀번호|PIN|pin|편의점).{0,35}(번호|코드|사진|캡처|찍어서|보내줘|전송)/gi,
      ],
      financialLoss: [
        /(편의점|상품권|문화\s*상품권|기프트\s*카드|구글\s*기프트).{0,35}(사서|구매|결제|충전|보내줘|전송)/g,
      ],
    },
  },
  {
    id: 'child_abduction_accident_settlement_threat',
    title: '자녀 납치·사고·합의금 협박',
    recommendedLevel: '매우 높음',
    sourceIds: ['police-phishing-sos'],
    categories: ['impersonation', 'urgency', 'financialLoss'],
    reason: '자녀 사고·납치·감금 위협으로 즉시 합의금 송금을 압박하는 패턴입니다.',
    patterns: {
      impersonation: [/(자녀|아이|아들|딸|학생|가족).{0,30}(사고|납치|감금|잡혀|다쳤|병원|합의|차에\s*태웠|데리고\s*있)/g],
      urgency: [/(사고|납치|감금|잡혀|다쳤|협박|위험|해치지|대가).{0,30}(지금|즉시|당장|빨리|긴급|합의|돈|술값)/g],
      financialLoss: [/(합의금|치료비|병원비|보상금|술값|대가).{0,30}(필요|입금|송금|이체|보내|요구|내야)/g],
    },
  },
  {
    id: 'investigation_agency_impersonation',
    title: '검찰·경찰·금감원 등 수사기관 사칭',
    recommendedLevel: '매우 높음',
    sourceIds: ['police-phishing-sos', 'fss-voice-phishing'],
    categories: ['impersonation', 'requestedAction', 'urgency', 'personalInfo'],
    reason: '수사·계좌 보호 명목으로 인증번호·계좌·개인정보 제출을 요구하는 패턴입니다.',
    patterns: {
      impersonation: [
        /(검찰|경찰|금감원|금융감독원|수사관|검사|법원|등기).{0,35}(사건|수사|연루|대포통장|범죄|계좌|반송|사건\s*조회)/g,
      ],
      requestedAction: [/(인증번호|OTP|보안카드|승인번호|사건번호).{0,30}(불러|알려|제출|입력|전송|말씀)/gi],
      personalInfo: [/(계좌|통장|신분증|주민번호|비밀번호).{0,30}(확인|제출|촬영|전송|알려)/g],
      suspiciousLink: [/(인터넷\s*창|주소\s*창|url|URL|링크).{0,30}(열어|비워|검색|접속|입력|확인)/gi],
    },
  },
  {
    id: 'refinance_or_low_interest_loan',
    title: '대환대출·저금리 대출 사칭',
    recommendedLevel: '매우 높음',
    sourceIds: ['police-phishing-sos', 'fss-voice-phishing'],
    categories: ['impersonation', 'urgency', 'financialLoss', 'personalInfo', 'malwareApp'],
    reason: '저금리·정부지원 대출을 미끼로 기존 대출 상환, 수수료, 앱 설치, 현금 전달을 요구하는 패턴입니다.',
    patterns: {
      impersonation: [/(은행|캐피탈|저축은행|금융회사|정부지원).{0,30}(대출|대환|저금리|정책자금)/g],
      urgency: [/(계약\s*위반|전액\s*상환|위약금|현금\s*우선\s*변제).{0,35}(협박|알림|내야|안\s*내도|상환|납부)/g],
      financialLoss: [/(대환|저금리|대출|기존\s*대출|위약금).{0,35}(상환|선입금|수수료|보증료|인지세|입금|납부|현금|전달|이체)/g],
      personalInfo: [/(대출|한도|심사).{0,35}(신분증|계좌|비밀번호|인증번호|소득자료)/g],
      malwareApp: [/(대출\s*신청서|파일|악성\s*앱|앱).{0,35}(보냄|전송|설치|깔려|실행)/g],
    },
  },
  {
    id: 'sexual_visit_disclosure_extortion',
    title: '성매매·마사지샵 방문사실 유포 협박',
    recommendedLevel: '매우 높음',
    sourceIds: ['police-phishing-sos'],
    categories: ['urgency', 'financialLoss', 'personalInfo'],
    reason: '성매매·마사지샵 방문 또는 영상 촬영을 빌미로 가족·지인 유포와 합의를 압박하는 패턴입니다.',
    patterns: {
      urgency: [/(성매매|마사지|방문|영상|촬영|유포|흥신소).{0,40}(협박|피해|연락처|가족|지인|합의|보실까요)/g],
      financialLoss: [/(합의|좋게|돈|금액|입금|송금|이체).{0,35}(보시겠|하시겠|필요|요구|처리)/g],
      personalInfo: [/(가족|지인|연락처|생년월일|주소).{0,35}(확보|알고|조회|가지고|유포)/g],
    },
  },
  {
    id: 'card_company_impersonation',
    title: '카드사 사칭',
    recommendedLevel: '매우 높음',
    sourceIds: ['police-phishing-sos'],
    categories: ['impersonation', 'requestedAction', 'financialLoss', 'personalInfo', 'malwareApp'],
    reason: '카드 배송·발급·사고예방팀을 사칭해 개인정보 확인, 원격앱 설치, 자산보호 명목 이체를 유도하는 패턴입니다.',
    patterns: {
      impersonation: [/(카드\s*배송|카드\s*발급|카드사|사고\s*예방팀|보안팀|자산\s*보호).{0,35}(확인|조회|연결|신청|안내)/g],
      requestedAction: [/(인증번호|승인번호|생년월일|성함|원격\s*앱|원격조종|원격제어).{0,35}(말씀|확인|설치|유도|시도|입력)/g],
      financialLoss: [/(자산\s*보호|범죄수익|지정하는\s*계좌|계좌).{0,35}(이체|송금|금액|자금)/g],
      personalInfo: [/(성함|생년월일|명의도용|금융\s*자산|계좌).{0,35}(말씀|확인|조회|질문|신청)/g],
      malwareApp: [/(악성\s*앱|원격\s*앱|휴대폰).{0,35}(점검|설치|원격조종|유도)/g],
    },
  },
  {
    id: 'public_office_impersonation',
    title: '관공서 사칭',
    recommendedLevel: '높음',
    sourceIds: ['police-phishing-sos'],
    categories: ['impersonation', 'suspiciousLink', 'personalInfo'],
    reason: '주민센터·세무서 등 관공서를 사칭해 명의도용, 신분증·위임장 확인, 피싱 사이트 접속을 유도하는 패턴입니다.',
    patterns: {
      impersonation: [/(주민센터|세무서|관공서|사업자\s*등록|대리인|위임장).{0,35}(사칭|신청|신고|확인|접수|대리)/g],
      suspiciousLink: [/(문자|피싱\s*사이트|사이트|링크|URL|url).{0,35}(접속|발송|유도|확인|신청)/gi],
      personalInfo: [/(명의도용|신분증|도장|위임장|생년월일|전화번호).{0,35}(확인|가져|문제|원본|맞으세요)/g],
    },
  },
  {
    id: 'delivery_card_micro_payment_smishing',
    title: '택배·카드배송·소액결제 문자',
    recommendedLevel: '주의',
    sourceIds: ['kisa-boho'],
    categories: ['impersonation', 'suspiciousLink'],
    reason: '배송·카드·소액결제 확인을 핑계로 링크 접속을 유도하는 스미싱 패턴입니다.',
    patterns: {
      impersonation: [/(택배|배송|주소\s*확인|카드\s*배송|카드\s*발급|소액\s*결제|결제\s*승인).{0,35}(확인|조회|취소|반송|URL|링크)/gi],
    },
  },
  {
    id: 'government_grant_or_refund_smishing',
    title: '정부지원금·환급금 사칭',
    recommendedLevel: '주의',
    sourceIds: ['kisa-boho', 'fss-voice-phishing'],
    categories: ['impersonation', 'suspiciousLink', 'personalInfo'],
    reason: '지원금·환급금 신청을 내세워 링크 접속이나 개인정보 입력을 유도하는 패턴입니다.',
    patterns: {
      impersonation: [/(정부지원금|지원금|환급금|보조금|생활지원금|건강보험|국세|세금).{0,35}(신청|대상|확인|조회|환급|지급)/g],
      personalInfo: [/(지원금|환급금|보조금).{0,35}(주민번호|계좌|신분증|인증번호|비밀번호)/g],
    },
  },
  {
    id: 'apk_or_remote_control_install',
    title: 'apk·원격제어 앱 설치 유도',
    recommendedLevel: '매우 높음',
    sourceIds: ['kisa-boho', 'fss-voice-phishing'],
    categories: ['requestedAction', 'malwareApp'],
    reason: '출처불명 앱 또는 원격제어 앱 설치를 요구하는 고위험 악성앱 유도 패턴입니다.',
    patterns: {
      requestedAction: [
        /(apk|앱|어플|원격제어|원격\s*지원|보안\s*앱|인증\s*앱).{0,30}(설치|실행|허용|권한|접속)/gi,
      ],
    },
  },
  {
    id: 'investment_room_high_profit_cash_collector',
    title: '투자리딩·고수익 알바·현금수거책 유도',
    recommendedLevel: '높음',
    sourceIds: ['police-phishing-sos', 'fss-voice-phishing'],
    categories: ['financialLoss', 'personalInfo', 'urgency'],
    reason: '고수익 보장, 리딩방, 현금 수거·전달 알바 등으로 금전 피해나 범죄 가담을 유도하는 패턴입니다.',
    patterns: {
      financialLoss: [
        /(투자\s*리딩|리딩방|고수익|원금\s*보장|단기\s*수익|수익\s*보장).{0,35}(입금|투자|참여|가입|추천)/g,
        /(현금\s*수거|현금\s*전달|통장\s*전달|계좌\s*대여).{0,35}(알바|아르바이트|수당|일당|고수익)/g,
      ],
      personalInfo: [/(통장|계좌|체크카드|OTP).{0,35}(대여|전달|보내|맡겨)/gi],
    },
  },
];

export function getScenarioPatterns(signalId: SignalId): RegExp[] {
  return SCAM_SCENARIOS.flatMap((scenario) => [...(scenario.patterns[signalId] ?? [])]);
}
