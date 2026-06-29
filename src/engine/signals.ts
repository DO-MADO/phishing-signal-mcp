// 위험 신호 7종 탐지기 (SPEC §5)
// 각 신호가 곧 "판단 근거"다. 카테고리 단위로 정규식 사전을 구조화한다(단순 키워드 매칭처럼 보이지 않게).
// 입력은 보통 마스킹된 텍스트(SPEC §7)지만, 모듈 자체는 임의 문자열을 받는다(조립은 tools/ 단계).

import { getScenarioPatterns } from '../data/scamScenarios.js';
import {
  GIFT_CARD_VALUE_CONTEXT,
  VALUE_DISCLOSURE_ACTION,
  VALUE_POINTER,
  VALUE_POINTER_CONTEXT,
} from '../data/scamPatternLexicon.js';
import { normalizeForSignalDetection } from './normalize.js';
import { shouldSuppressSignal } from './signalSuppression.js';

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
      /(인증\s*번호|인\s*증\s*번\s*호|인증\s*코드|인증코드|승인\s*번호|승\s*인\s*번\s*호|OTP|오\s*티\s*피|ㅇ\s*ㅈ\s*ㅂ\s*ㅎ|보안\s*문자|보안문자|보안\s*카드(?:\s*번호)?|보안\s*번호|보안번호|보안\s*코드|보안코드|열람\s*코드|열람코드|확인\s*코드|확인코드|일회용\s*번호|일회용번호|잠금\s*번호|화면\s*잠금\s*번호).{0,25}(불러|알려|말해|말씀|입력|전송|제출|공유|보내|캡처|찍어|읽어|회신|답장)/gi,
      // 코드/상품권/화면값 맥락과 전달 동사가 같이 있을 때만 대명사 우회 요구로 본다.
      new RegExp(String.raw`${VALUE_POINTER_CONTEXT}.{0,45}${VALUE_POINTER}.{0,25}${VALUE_DISCLOSURE_ACTION}`, 'gi'),
      new RegExp(String.raw`${VALUE_POINTER}.{0,25}${VALUE_DISCLOSURE_ACTION}.{0,45}${VALUE_POINTER_CONTEXT}`, 'gi'),
      new RegExp(String.raw`(?:로그인|본인\s*확인|본인확인|결제|인증|승인|보안|은행|카드|페이|계정).{0,45}(?:뜨|뜬|뜨는|나온|오는).{0,20}${VALUE_POINTER}.{0,25}${VALUE_DISCLOSURE_ACTION}`, 'gi'),
      /(원격제어|원격\s*(?:접속|지원|조종)|원격지원|애니데스크|anydesk|팀뷰어|teamviewer|화면\s*공유|미러링).{0,25}(설치|깔|실행|연결|접속|허용|코드|켜|공유)/gi,
      /(화면\s*공유|화면공유).{0,25}(보여|보이|켜|공유|연결)/gi,
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
      /(안전\s*계좌|대납|선입금|무통장|공탁금|벌금|예치금)/gi,
      /(핀\s*번호|PIN).{0,20}(보내|알려|전송|사진|캡처|찍어서)/gi,
      // 상품권/PIN 맥락의 뒤쪽 숫자·코드 전달 요구는 구매 지시가 없어도 금전 피해로 본다.
      new RegExp(String.raw`${GIFT_CARD_VALUE_CONTEXT}.{0,45}${VALUE_POINTER}.{0,25}${VALUE_DISCLOSURE_ACTION}`, 'gi'),
      new RegExp(String.raw`${VALUE_POINTER}.{0,25}${VALUE_DISCLOSURE_ACTION}.{0,45}${GIFT_CARD_VALUE_CONTEXT}`, 'gi'),
      /(?:송금|입금|이체|납부)\s*(?:좀|해\s*(?:줘[요용욤여잉ㅇ~!?.ㅠㅜ]*|주라|줄래|주세요|주시|라|야)?|하세요|하라|해야|부탁|요청|바랍니다|필요|진행|처리)/gi,
      /(보호금|구매자\s*보호금|거래\s*보증금|거래보증금).{0,45}(입금|환불|돌려|받|처리).{0,45}(계좌\s*정보|계좌정보|계좌|은행명|남겨|알려|보내)/gi,
      ...getScenarioPatterns('financialLoss'),
    ],
  },
  {
    id: 'personalInfo',
    label: '개인정보 탈취',
    description: '주민번호·계좌·비밀번호·신분증 등 민감정보 요구',
    patterns: [
      /(주민\s*등록\s*번호|주민\s*번호|계좌\s*번호|계좌\s*정보|계좌정보|은행명|비밀\s*번호|비번|카드\s*번호|보안\s*카드\s*번호|보안\s*문자|보안문자|잠금\s*번호|화면\s*잠금\s*번호|신분증\s*사진|신분증|통장\s*사본|cvc|cvv).{0,25}(불러|알려|말해|말씀|입력|전송|제출|공유|보내|촬영|찍어|확인|남겨)/gi,
      /(불러|알려|말해|말씀|입력|전송|제출|공유|보내|촬영|찍어|확인|남겨).{0,25}(주민\s*등록\s*번호|주민\s*번호|계좌\s*번호|계좌\s*정보|계좌정보|은행명|비밀\s*번호|비번|카드\s*번호|보안\s*카드\s*번호|보안\s*문자|보안문자|잠금\s*번호|화면\s*잠금\s*번호|신분증\s*사진|신분증|통장\s*사본|cvc|cvv)/gi,
      // 신분증·통장 일부를 완곡히 말해도 사진/제출 동사가 있어야만 개인정보 요구로 잡는다.
      /(신분|신분증).{0,18}(앞면|뒷면|앞|뒤).{0,30}(사진|촬영|찍|올려|보내|전송|제출)/gi,
      /(받을|입금\s*받을|환급\s*받을|정산\s*받을).{0,18}(통장|계좌).{0,18}(사진|사본|번호).{0,30}(올려|보내|전송|제출|확인|남겨)/gi,
      /(비밀\s*번호|비밀번호|비번|암호).{0,25}(앞\s*두\s*자리|앞자리|일부|두\s*자리|2\s*자리).{0,25}(확인|말해|알려|불러|보내)/gi,
      ...getScenarioPatterns('personalInfo'),
    ],
  },
  {
    id: 'malwareApp',
    label: '악성앱 설치 유도',
    description: 'apk 등 출처불명 앱 설치 유도',
    patterns: [
      /(\.apk|apk\s*파일|apk|어플\s*설치|앱\s*설치|어플리케이션\s*설치|어플\s*깔|앱\s*깔|출처를?\s*알\s*수\s*없는|알\s*수\s*없는\s*출처|설치\s*파일|보안\s*(?:앱|어플|프로그램)\s*(?:설치|깔|실행)|인증\s*(?:앱|어플)\s*설치|접근성\s*허용)/gi,
      // 파일/앱 설치와 권한 조작이 같이 있는 경우만 잡아 정상 보안교육 문맥은 suppression에 맡긴다.
      /(확인용|상담|검사|검수|보안).{0,18}(파일|앱|어플|프로그램).{0,45}(내려받|다운|받아|설치|실행|열어|권한|허용|접근)/gi,
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

/** 텍스트에서 발화된(매칭된) 위험 신호 목록을 반환한다. */
export function detectSignals(text: string): DetectedSignal[] {
  const detected: DetectedSignal[] = [];
  const matchText = normalizeForSignalDetection(text);
  for (const def of SIGNAL_DEFINITIONS) {
    if (shouldSuppressSignal(def.id, text)) continue;

    const found = new Set<string>();
    for (const pattern of def.patterns) {
      const matches = matchText.match(pattern); // g 플래그 → 전체 매칭 배열 또는 null
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
