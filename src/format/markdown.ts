// 출력 포맷터 (SPEC §4.1 출력 구성 / §7 안전 정책 / §8 24k 가드)
// - 정제된 마크다운만 반환(원본 API/입력 그대로 노출 금지).
// - 모든 분석 출력에 디스클레이머 + 민감정보 입력 금지 안내 고정.
// - 의심 링크 등 매칭값은 디팽(defang)하여 클릭 가능한 형태로 재노출하지 않는다.
// - 응답 바이트 길이 24k 가드.

import type { DetectedSignal, SignalId } from '../engine/signals.js';
import type { RiskLevel } from '../engine/score.js';
import {
  ALREADY_PAID_URGENCY,
  REPORT_CHANNELS,
  type ReportChannel,
  type Situation,
} from '../data/reportChannels.js';

// SPEC §8: Tool Response 24k 초과 시 에러 → 여유를 두고 보수적으로 가드.
export const MAX_RESPONSE_BYTES = 24000;

// SPEC §7: 모든 분석 출력에 고정.
export const DISCLAIMER =
  '이 안내는 위험 신호에 대한 참고용 가이드이며 법적 판단이 아닙니다. 실제 상황에서는 공식 기관과 금융회사의 안내를 우선하세요.';

// SPEC §7: 사용자가 OTP·비밀번호 등을 입력하지 않도록 안내.
export const SENSITIVE_INPUT_WARNING =
  'OTP·비밀번호·주민번호·여권번호·계좌번호 등 민감정보는 이 대화에 입력하지 마세요.';

/** UTF-8 바이트 길이. */
export function byteLength(text: string): number {
  return Buffer.byteLength(text, 'utf8');
}

/** 링크/도메인을 클릭 불가 형태로 무력화(재노출 방지). */
export function defang(text: string): string {
  return text.replace(/https?/gi, 'hxxp').replace(/\./g, '[.]');
}

/** 바이트 한도 이하로 자르고, 잘렸으면 안내를 덧붙인다(문자 경계 보존). */
export function clampToByteLimit(text: string, max: number = MAX_RESPONSE_BYTES): string {
  if (byteLength(text) <= max) return text;
  const notice = '\n\n…(출력이 길어 일부를 생략했습니다)';
  const budget = max - byteLength(notice);
  // 코드포인트 단위로 누적하며 예산을 넘지 않게 자른다.
  let out = '';
  for (const ch of text) {
    if (byteLength(out + ch) > budget) break;
    out += ch;
  }
  return out + notice;
}

const RISK_HEADLINE: Record<RiskLevel, string> = {
  낮음: '🟢 위험도: 낮음',
  주의: '🟡 위험도: 주의',
  높음: '🟠 위험도: 높음',
  '매우 높음': '🔴 위험도: 매우 높음',
};

const EMERGENCY_STOP: Record<RiskLevel, string[]> = {
  낮음: [
    '현재 입력만으로는 즉시 멈춤이 필요한 강한 위험 신호는 적습니다.',
    '그래도 링크 클릭, 앱 설치, 송금, 인증번호 공유 요청이 나오면 즉시 중단하고 공식 경로로 확인하세요.',
  ],
  주의: [
    '지금은 잠시 멈추고 확인해야 합니다.',
    '링크 클릭, 앱 설치, 송금, 인증번호 공유를 하기 전에 공식 경로로 다시 확인하세요.',
  ],
  높음: [
    '지금은 멈춰야 합니다.',
    '링크 클릭, 앱 설치, 송금, 인증번호 공유를 하지 마세요.',
  ],
  '매우 높음': [
    '지금은 즉시 멈춰야 합니다.',
    '링크 클릭, 앱 설치, 송금, 인증번호 공유를 하지 마세요.',
  ],
};

const SIGNAL_EXPLANATIONS: Record<SignalId, string> = {
  impersonation: '기관·가족·지인처럼 보이게 만들어 신뢰나 권위로 압박하는 신호입니다.',
  requestedAction: '인증번호, 원격제어, 상품권 코드처럼 피해로 이어질 수 있는 행동을 요구하는 신호입니다.',
  urgency: '즉시 처리하라는 표현으로 사용자의 판단 시간을 줄이는 압박 신호입니다.',
  financialLoss: '송금, 이체, 상품권 구매처럼 금전 피해로 이어질 수 있는 요구 신호입니다.',
  personalInfo: '계좌번호, 비밀번호, 신분증 등 민감정보 탈취로 이어질 수 있는 신호입니다.',
  malwareApp: '악성앱이나 원격제어 앱 설치로 단말 통제권을 빼앗을 수 있는 신호입니다.',
  suspiciousLink: '외부 링크나 비공식 URL로 이동시켜 개인정보 입력 또는 악성앱 설치를 유도할 수 있는 신호입니다.',
};

const FAMILY_SHARE_GUIDE =
  '검찰·경찰·금감원·은행은 전화나 메시지로 앱 설치, 인증번호, 송금을 요구하지 않습니다. 수상한 연락을 받으면 먼저 멈추고 가족 또는 공식 번호로 확인하세요.';

/** 신고 채널 목록을 우선순위 순 마크다운으로 렌더(analyze/getReportChannels 공용). */
export function renderChannels(channels: readonly ReportChannel[]): string {
  return [...channels]
    .sort((a, b) => a.priority - b.priority)
    .map((c) => {
      const contact = c.phone ?? (c.url ? defang(c.url) : '');
      const head = contact ? `**${c.name}** (${contact})` : `**${c.name}**`;
      return `${c.priority}. ${head} — ${c.purpose}`;
    })
    .join('\n');
}

const EVIDENCE_PATTERNS: Record<SignalId, RegExp> = {
  impersonation: /(검찰|경찰|금감원|법원|정부|은행|택배|카드사|엄마|아빠|아들|딸|친구|지인|폰\s*고장|번호\s*변경|카톡\s*안\s*됨)/gi,
  requestedAction: /(인증번호|승인번호|OTP|보안카드|원격제어|화면\s*공유|상품권|PIN|핀번호|사진|캡처)/gi,
  urgency: /(급해|급하게|급함|급한데|급행|즉시|지금|바로|빨리|당장|긴급|구속|체포|압류|동결|협박)/gi,
  financialLoss: /(돈\s*좀|돈|송금|입금\s*좀|입금|이체|납부|보내\s*줘[요용욤여잉ㅇ~!?.ㅠㅜ]*|보내\s*줭|보내\s*죵|보내\s*주라|빌려\s*줘[요용욤여잉ㅇ~!?.ㅠㅜ]*|빌려\s*줄래|수리비|병원비|합의금|상품권|PIN|안전\s*계좌)/gi,
  personalInfo: /(주민번호|계좌번호|비밀번호|비번|카드번호|보안카드|신분증|통장\s*사본|cvc|cvv)/gi,
  malwareApp: /(apk|앱\s*설치|어플\s*설치|설치\s*파일|보안\s*앱|인증\s*앱|출처를?\s*알\s*수\s*없는)/gi,
  suspiciousLink: /(\[?\s*web\s*발신\s*\]?|국제\s*발신|국외\s*발신|https?:\/\/\S+|bit\.ly|tinyurl\.com|t\.co|goo\.gl|링크|URL|url)/gi,
};

function compactEvidence(signalId: SignalId, match: string): string {
  const safe = defang(match).replace(/\s+/g, ' ').trim();
  const tokens = [...safe.matchAll(EVIDENCE_PATTERNS[signalId])]
    .map(([token]) => token.trim())
    .filter(Boolean);
  const unique = [...new Set(tokens)];
  if (unique.length > 0) return unique.slice(0, 4).join(', ');
  return safe.length > 24 ? `${safe.slice(0, 24)}…` : safe;
}

const DONT_DO: Record<Situation, string[]> = {
  suspiciousOnly: [
    '인증번호(OTP)·비밀번호·계좌번호·신분증 정보를 알려주지 마세요.',
    '상대가 보낸 링크를 누르거나 첨부 파일을 열지 마세요.',
    '상대가 안내하는 앱(원격제어·보안앱 등)을 설치하지 마세요.',
    '재촉에 떠밀려 송금/이체하지 마세요.',
  ],
  alreadyPaid: [
    '추가 송금·이체를 절대 하지 마세요.',
    '상대의 추가 지시(앱 설치·인증번호 공유)를 따르지 마세요.',
  ],
  personalInfoExposed: [
    '노출된 정보로 온 추가 연락(추가 인증 요구 등)에 응하지 마세요.',
    '같은 비밀번호를 다른 곳에 재사용하지 마세요.',
  ],
  malwareInstalled: [
    '설치된 앱에서 인증·금융 작업을 하지 마세요.',
    '단말의 인증서·간편결제를 그대로 사용하지 마세요.',
  ],
};

const DO_NOW: Record<Situation, string[]> = {
  suspiciousOnly: [
    '기관·지인 여부는 공식 대표번호 또는 기존 연락처로 직접 확인하세요.',
    '통화기록·문자·대화 내용 등 남아 있는 기록은 삭제하지 말고 보존한 뒤 아래 채널로 신고/상담하세요.',
  ],
  alreadyPaid: [ALREADY_PAID_URGENCY],
  personalInfoExposed: [
    '아래 채널에 노출 사실을 등록해 신규 계좌·대출·개통을 차단하세요.',
    '관련 계정 비밀번호를 즉시 변경하세요.',
  ],
  malwareInstalled: [
    '기기를 비행기모드로 전환하고 통신사/제조사 안내로 악성앱을 삭제하거나 초기화하세요.',
    '공동인증서·OTP 등 인증수단을 폐기하고 재발급하세요.',
  ],
};

export type AnalysisChannel = 'phone' | 'sms' | 'kakao' | 'unknown';

const CHANNEL_DO_NOW: Record<AnalysisChannel, string[]> = {
  phone: ['통화 중이라면 바로 끊고, 상대가 알려준 번호로 다시 걸지 마세요.'],
  sms: ['문자 링크·첨부는 열지 말고, 발신번호와 수신 시간을 함께 보존하세요.'],
  kakao: ['메신저 링크·파일은 열지 말고, 대화방을 나가거나 삭제하기 전에 내용을 보존하세요.'],
  unknown: [],
};

export interface RiskAnalysisView {
  readonly level: RiskLevel;
  readonly total: number;
  readonly signals: readonly DetectedSignal[];
  readonly situation: Situation;
  readonly channels: readonly ReportChannel[];
  readonly channel?: AnalysisChannel;
}

/** analyzePhishingRisk 결과를 정제된 마크다운으로 포맷(24k 가드 포함). */
export function formatRiskAnalysis(view: RiskAnalysisView): string {
  const lines: string[] = [];
  lines.push('## 30초 안전 브레이크');
  for (const item of EMERGENCY_STOP[view.level]) lines.push(`- ${item}`);

  lines.push(`\n### ${RISK_HEADLINE[view.level]}`);

  // 하지 말아야 할 행동을 위험도 직후에 배치해 피해 행동을 먼저 차단한다.
  lines.push('\n### 지금 하지 말아야 할 행동');
  for (const item of DONT_DO[view.situation]) lines.push(`- ${item}`);

  // 지금 해야 할 행동
  lines.push('\n### 지금 해야 할 행동');
  for (const item of DO_NOW[view.situation]) lines.push(`- ${item}`);
  if (view.channel) {
    for (const item of CHANNEL_DO_NOW[view.channel]) lines.push(`- ${item}`);
  }

  // 판단 근거 = 탐지된 위험 신호
  lines.push('\n### 왜 위험한가요?');
  if (view.signals.length === 0) {
    lines.push('- 입력에서 뚜렷한 위험 신호를 찾지 못했습니다.');
  } else {
    for (const s of view.signals) {
      const evidence = s.matches
        .slice(0, 5)
        .map((m) => compactEvidence(s.id, m))
        .join(', ');
      lines.push(`- **${s.label}**: ${SIGNAL_EXPLANATIONS[s.id]} 근거: ${evidence}`);
    }
  }

  if (view.level === '높음' || view.level === '매우 높음') {
    lines.push('\n### 가족에게 공유할 문구');
    lines.push(FAMILY_SHARE_GUIDE);
  }

  // 공식 신고 루트 요약
  lines.push('\n### 공식 신고 루트');
  lines.push(renderChannels(view.channels));

  // 안전 안내 + 디스클레이머(고정)
  lines.push(`\n> ⚠️ ${SENSITIVE_INPUT_WARNING}`);
  lines.push(`\n> ${DISCLAIMER}`);

  return clampToByteLimit(lines.join('\n'));
}

const SITUATION_TITLES: Record<Situation, string> = {
  suspiciousOnly: '의심 문자·전화만 받은 단계 (송금 전)',
  alreadyPaid: '이미 송금/이체한 경우 — 즉시 대응',
  personalInfoExposed: '개인정보·신분증 노출',
  malwareInstalled: '악성앱 설치 의심',
};

/** getReportChannels 결과를 상황별 마크다운으로 포맷(24k 가드 포함). */
export function formatReportChannels(situation: Situation): string {
  const lines: string[] = [];
  lines.push(`## 공식 신고·대응 루트 — ${SITUATION_TITLES[situation]}`);
  if (situation === 'alreadyPaid') {
    lines.push(`\n> ⏱️ ${ALREADY_PAID_URGENCY}`);
  }
  lines.push('');
  lines.push(renderChannels(REPORT_CHANNELS[situation]));
  lines.push(`\n> ${DISCLAIMER}`);
  return clampToByteLimit(lines.join('\n'));
}
