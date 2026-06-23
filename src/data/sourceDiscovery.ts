// 개발 단계 source discovery 결과.
// 런타임 MCP에서 외부 호출하지 않으며, 공식 도메인의 URL/제목/유형/요약만 보관한다.
// 원문 사례 전문, 실제 악성 URL, 전화번호, 계좌번호, 개인정보는 저장하지 않는다.

import type { OfficialSourceId } from './scamScenarios.js';

export interface SourceDiscoveryRecord {
  readonly id: string;
  readonly sourceId: OfficialSourceId;
  readonly institution: string;
  readonly title: string;
  readonly url: string;
  readonly domain: 'counterscam112.go.kr' | 'fss.or.kr' | 'boho.or.kr';
  readonly verificationStatus: 'verifiedPage' | 'officialDomainOnly';
  readonly copyrightUrl?: string;
  readonly typeNames: readonly string[];
  readonly scenarioIds: readonly string[];
  readonly evidenceSummary: string;
}

export const SOURCE_DISCOVERY_RECORDS: readonly SourceDiscoveryRecord[] = [
  {
    id: 'police-phishing-sos-scenario-types',
    sourceId: 'police-phishing-sos',
    institution: '경찰청',
    title: '피싱안심SOS 대표 피싱 유형',
    url: 'https://www.counterscam112.go.kr/bbs009/board/boardList.do',
    domain: 'counterscam112.go.kr',
    verificationStatus: 'verifiedPage',
    copyrightUrl: 'https://www.counterscam112.go.kr/guide/copyright.do',
    typeNames: ['자녀납치 협박', '성매매·마사지샵 방문사실 유포 협박', '카드사 사칭', '대환대출 사기', '관공서 사칭', '수사기관 사칭'],
    scenarioIds: [
      'child_abduction_accident_settlement_threat',
      'sexual_visit_disclosure_extortion',
      'card_company_impersonation',
      'refinance_or_low_interest_loan',
      'public_office_impersonation',
      'investigation_agency_impersonation',
    ],
    evidenceSummary: '피싱안심SOS 피싱 시나리오 목록과 상세 페이지의 제목·태그·핵심 위험 신호를 기준으로, 원문 전문 없이 패턴 단위로 큐레이션한다.',
  },
  {
    id: 'fss-voice-phishing-keeper-menu',
    sourceId: 'fss-voice-phishing',
    institution: '금융감독원',
    title: '민원·신고 > 보이스피싱지킴이',
    url: 'https://www.fss.or.kr/fss/main/main.do?menuNo=200000',
    domain: 'fss.or.kr',
    verificationStatus: 'verifiedPage',
    typeNames: ['보이스피싱 한 눈에', '보이스피싱 사전예방', '피해 대응', '피해금 환급 조회'],
    scenarioIds: [
      'investigation_agency_impersonation',
      'refinance_or_low_interest_loan',
      'government_grant_or_refund_smishing',
      'apk_or_remote_control_install',
      'investment_room_high_profit_cash_collector',
    ],
    evidenceSummary: '금융감독원 공식 홈페이지의 보이스피싱지킴이 메뉴와 예방·피해대응 하위 항목을 기준으로 금융기관/수사기관 사칭과 대출빙자 유형을 큐레이션한다.',
  },
  {
    id: 'kisa-smishing-check-service',
    sourceId: 'kisa-boho',
    institution: 'KISA 보호나라',
    title: '스미싱 확인서비스',
    url: 'https://www.boho.or.kr/kr/subPage.do?menuNo=205116',
    domain: 'boho.or.kr',
    verificationStatus: 'verifiedPage',
    typeNames: ['스미싱', '모바일 메신저 악성 메시지', '주의·악성 판정'],
    scenarioIds: [
      'delivery_card_micro_payment_smishing',
      'government_grant_or_refund_smishing',
      'apk_or_remote_control_install',
    ],
    evidenceSummary: 'KISA 보호나라 스미싱 확인서비스의 문자·모바일 메신저 악성 여부 확인과 정상/주의/악성 응답 구조를 기준으로 메시지형 피싱을 큐레이션한다.',
  },
  {
    id: 'kisa-card-news-smishing-quishing',
    sourceId: 'kisa-boho',
    institution: 'KISA 보호나라',
    title: '알림마당 > 카드뉴스',
    url: 'https://www.boho.or.kr/kr/bbs/list.do?bbsId=B0001030&menuNo=205090',
    domain: 'boho.or.kr',
    verificationStatus: 'verifiedPage',
    typeNames: ['지원금 사칭 스미싱', '악성문자', '큐싱'],
    scenarioIds: ['delivery_card_micro_payment_smishing', 'government_grant_or_refund_smishing'],
    evidenceSummary: 'KISA 보호나라 카드뉴스의 지원금 사칭 스미싱, 악성문자, 큐싱 주의 콘텐츠 목록을 기준으로 최신 문자형 유형을 큐레이션한다.',
  },
];
