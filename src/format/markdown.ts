// 출력 포맷터 (SPEC §4.1 출력 구성 / §7 안전 정책 / §8 24k 가드)
// - 정제된 마크다운만 반환(원본 API/입력 그대로 노출 금지).
// - 모든 분석 출력에 디스클레이머 + 민감정보 입력 금지 안내 고정.
// - 의심 링크 등 매칭값은 디팽(defang)하여 클릭 가능한 형태로 재노출하지 않는다.
// - 응답 바이트 길이 24k 가드.

import type { DetectedSignal } from '../engine/signals.js';
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

const DONT_DO: Record<Situation, string[]> = {
  suspiciousOnly: [
    '인증번호(OTP)·비밀번호·계좌번호를 알려주지 마세요.',
    '문자·메신저의 링크를 누르거나 첨부 파일을 열지 마세요.',
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
    '통화를 끊고, 해당 기관/지인에게 공식 대표번호로 직접 확인하세요.',
    '의심 문자·번호는 캡처해 두고 아래 채널로 신고/상담하세요.',
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
  phone: ['통화 중이라면 바로 끊고, 상대가 알려준 번호가 아니라 공식 대표번호로 직접 다시 확인하세요.'],
  sms: ['문자 링크·첨부를 열지 말고, 문자 내용을 캡처한 뒤 발신번호와 함께 신고/상담에 활용하세요.'],
  kakao: ['메신저 대화방의 링크·파일을 열지 말고, 기존 연락처나 다른 채널로 본인 여부를 직접 확인하세요.'],
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
  lines.push(`## ${RISK_HEADLINE[view.level]}`);

  // 판단 근거 = 탐지된 위험 신호
  lines.push('\n### 판단 근거');
  if (view.signals.length === 0) {
    lines.push('- 입력에서 뚜렷한 위험 신호를 찾지 못했습니다.');
  } else {
    for (const s of view.signals) {
      const evidence = s.matches
        .slice(0, 5)
        .map((m) => defang(m))
        .join(', ');
      lines.push(`- **${s.label}**: ${evidence}`);
    }
  }

  // 하지 말아야 할 행동
  lines.push('\n### 하지 말아야 할 행동');
  for (const item of DONT_DO[view.situation]) lines.push(`- ${item}`);

  // 지금 해야 할 행동
  lines.push('\n### 지금 해야 할 행동');
  for (const item of DO_NOW[view.situation]) lines.push(`- ${item}`);
  if (view.channel) {
    for (const item of CHANNEL_DO_NOW[view.channel]) lines.push(`- ${item}`);
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
