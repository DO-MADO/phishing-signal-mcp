// 공식 신고 채널 — 확정값 (SPEC §6, 검증 완료)
// 출처: 경찰청 통합대응단 1394(2026-02-01 개통), 금감원 1332, KISA 118 등.
// ★ 구 대표번호(1566-1688 / 1566-1188)는 최신성 불안정 → 코드에서 제외. 1394만 사용.
// 이 값은 사용자 안전 직결 — 임의 변경 금지(변경 시 SPEC §6 먼저 갱신).

export type Situation =
  | 'suspiciousOnly' // 의심 문자·전화만 받은 단계(송금 전)
  | 'alreadyPaid' // 이미 송금/이체한 경우
  | 'personalInfoExposed' // 개인정보·신분증 노출
  | 'malwareInstalled'; // 악성앱 설치 의심

export interface ReportChannel {
  readonly name: string;
  readonly phone?: string;
  readonly url?: string;
  readonly purpose: string;
  readonly priority: number;
}

export const REPORT_CHANNELS: Record<Situation, readonly ReportChannel[]> = {
  // 이미 송금/이체한 경우 — "즉시", 우선순위 순
  alreadyPaid: [
    { name: '경찰청', phone: '112', purpose: '피해 신고 및 사기이용계좌 지급정지 요청', priority: 1 },
    {
      name: '송금·입금 금융회사 고객센터',
      phone: '각 금융회사 대표번호',
      purpose: '계좌 지급정지 요청',
      priority: 2,
    },
    { name: '금융감독원', phone: '1332', purpose: '피해 상담 및 지급정지·환급 안내', priority: 3 },
    {
      name: '전기통신금융사기 통합대응단 신고대응센터',
      phone: '1394',
      purpose: '24시간 피해상담·제보·관계기관 연계',
      priority: 4,
    },
  ],
  // 의심 문자·전화만 받은 단계(송금 전)
  suspiciousOnly: [
    {
      name: '전기통신금융사기 통합대응단 신고대응센터',
      phone: '1394',
      purpose: '피싱 여부 확인·제보(24시간)',
      priority: 1,
    },
    { name: 'KISA 상담센터', phone: '118', purpose: '스미싱·불법스팸·의심문자 상담/신고', priority: 2 },
  ],
  // 개인정보·신분증 노출
  personalInfoExposed: [
    {
      name: '금융감독원 개인정보노출자 사고예방시스템',
      url: 'pd.fss.or.kr',
      purpose: '노출 등록 → 신규 계좌·카드·대출 개설 차단',
      priority: 1,
    },
    {
      name: '명의도용방지서비스 엠세이퍼',
      url: 'msafer.or.kr',
      purpose: '명의도용 휴대전화 개통 여부 확인',
      priority: 2,
    },
  ],
  // 악성앱 설치 의심
  malwareInstalled: [
    {
      name: '휴대전화 초기화 / 통신사 고객센터',
      purpose: '악성 앱 삭제, 단말 초기화',
      priority: 1,
    },
    {
      name: '공동인증서·OTP 재발급',
      purpose: '탈취 대비 인증수단 폐기·재발급',
      priority: 2,
    },
  ],
};

// 송금 상황 강조 문구(SPEC §6): "30분 골든타임" 대신 "즉시".
export const ALREADY_PAID_URGENCY =
  '송금했다면 시간이 가장 중요합니다. 즉시 112·거래 금융회사·1332·1394에 연락해 지급정지와 피해상담을 요청하세요.';
