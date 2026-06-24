// 툴: analyzePhishingRisk (SPEC §4.1 / §4.3)
// 입력 텍스트 → 마스킹(§7) → 신호 탐지(§5) → 점수/구간 → 정제 마크다운(§4.1/§7/§8).
// 판정은 결정적 규칙 엔진(외부 호출 없음) → openWorldHint:false, 평균 100ms 목표(§8).

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { maskSensitive } from '../engine/mask.js';
import { detectSignals, type DetectedSignal } from '../engine/signals.js';
import { scoreSignals } from '../engine/score.js';
import { REPORT_CHANNELS, type Situation } from '../data/reportChannels.js';
import { formatRiskAnalysis } from '../format/markdown.js';
import {
  ACCOUNT_REQUEST_TARGET,
  TRUSTED_ACCOUNT_PURPOSE,
  TRUSTED_ACCOUNT_RELATIONSHIPS,
} from '../data/scamPatternLexicon.js';

export const ANALYZE_TOOL_NAME = 'analyzePhishingRisk';

// SPEC §2: 영문 + 서비스명 영문/국문 병기, 1,024자 이내.
export const ANALYZE_TOOL_DESCRIPTION =
  'Analyzes suspicious calls, SMS, or messenger texts for voice-phishing risk, returning a risk level with evidence and concrete action guides. 피싱 신호등(PhishingSignal).';

// 입력에서 분석에 사용할 최대 길이(초장문 방어, §8). 초과분은 잘라서 처리.
const MAX_INPUT_CHARS = 20000;

// SPEC §4.1 입력 스키마 (registerTool에는 ZodRawShape를 전달).
export const analyzeInputShape = {
  text: z
    .string()
    .max(200000)
    .describe('의심스러운 통화/문자/메신저 내용 원문 (필수). Suspicious call/SMS/messenger text to analyze.'),
  context: z
    .object({
      channel: z.enum(['phone', 'sms', 'kakao', 'unknown']).optional().describe('수신 채널'),
      senderKnown: z.boolean().optional().describe('보낸 사람이 기존 연락처/지인으로 확인됐는지'),
      relationship: z
        .enum(['family', 'friend', 'coworker', 'merchant', 'unknown'])
        .optional()
        .describe('보낸 사람과의 관계(계좌 요청 문맥 보정용)'),
      alreadySentMoney: z.boolean().optional().describe('이미 송금/이체했는지'),
      alreadyInstalledApp: z.boolean().optional().describe('상대가 안내한 앱을 설치했는지'),
      alreadySharedPersonalInfo: z.boolean().optional().describe('개인정보를 알려줬는지'),
    })
    .optional()
    .describe('선택: 있으면 행동 가이드를 정밀화'),
} as const;

export type AnalyzePhishingRiskInput = z.infer<z.ZodObject<typeof analyzeInputShape>>;

// SPEC §4.3: 읽기 전용 판정, 외부 호출 없음, 동일 입력 동일 출력.
export const analyzeAnnotations = {
  title: '피싱 신호등 — 위험도 분석 (PhishingSignal)',
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: false,
  idempotentHint: true,
} as const;

/** 컨텍스트(이미 발생한 피해) 우선순위로 신고 상황을 결정한다. */
function pickSituation(context: AnalyzePhishingRiskInput['context']): Situation {
  if (context?.alreadySentMoney) return 'alreadyPaid';
  if (context?.alreadySharedPersonalInfo) return 'personalInfoExposed';
  if (context?.alreadyInstalledApp) return 'malwareInstalled';
  return 'suspiciousOnly';
}

const TRUSTED_ACCOUNT_RELATIONSHIP_SET = new Set<string>(TRUSTED_ACCOUNT_RELATIONSHIPS);
const ACCOUNT_REQUEST_TARGET_PATTERN = new RegExp(ACCOUNT_REQUEST_TARGET, 'i');
const TRUSTED_ACCOUNT_PURPOSE_PATTERN = new RegExp(TRUSTED_ACCOUNT_PURPOSE, 'i');
const ACCOUNT_REQUEST_ACTION_PATTERN = /(알려|확인|보내|남겨|다시\s*알려|입금할게|송금할게|이체할게)/i;
const HIGH_RISK_CONTEXT_SIGNAL_IDS = new Set(['impersonation', 'urgency', 'requestedAction', 'malwareApp', 'suspiciousLink']);
const NON_ACCOUNT_PERSONAL_INFO_PATTERN =
  /(주민\s*(?:등록\s*)?번호|신분증|통장\s*(?:사본|사진)|카드\s*번호|비밀\s*번호|비밀번호|비번|cvc|cvv|여권|운전\s*면허|외국인\s*등록)/i;

function hasTrustedAccountContext(context: AnalyzePhishingRiskInput['context']): boolean {
  if (!context) return false;
  if (context.relationship && TRUSTED_ACCOUNT_RELATIONSHIP_SET.has(context.relationship)) return true;
  return context.senderKnown === true;
}

function isAccountOnlySignal(signal: DetectedSignal): boolean {
  if (signal.id !== 'personalInfo') return false;
  if (signal.matches.some((match) => NON_ACCOUNT_PERSONAL_INFO_PATTERN.test(match))) return false;
  return signal.matches.some((match) => ACCOUNT_REQUEST_TARGET_PATTERN.test(match));
}

function isTrustedAccountSettlementText(text: string): boolean {
  return (
    ACCOUNT_REQUEST_TARGET_PATTERN.test(text) &&
    ACCOUNT_REQUEST_ACTION_PATTERN.test(text) &&
    TRUSTED_ACCOUNT_PURPOSE_PATTERN.test(text)
  );
}

function applyContextSignalAdjustments(
  signals: readonly DetectedSignal[],
  text: string,
  context: AnalyzePhishingRiskInput['context'],
): DetectedSignal[] {
  if (!hasTrustedAccountContext(context)) return [...signals];
  if (!isTrustedAccountSettlementText(text)) return [...signals];
  if (signals.some((signal) => HIGH_RISK_CONTEXT_SIGNAL_IDS.has(signal.id))) return [...signals];

  return signals.filter((signal) => !isAccountOnlySignal(signal));
}

/** 순수 분석 함수: 입력 → 정제된 마크다운(서버/SDK 비의존, 테스트 용이). */
export function analyzePhishingRisk(input: AnalyzePhishingRiskInput): string {
  const raw = (input.text ?? '').slice(0, MAX_INPUT_CHARS);
  const masked = maskSensitive(raw); // §7: 처리 전 마스킹
  const signals = applyContextSignalAdjustments(detectSignals(masked), masked, input.context);
  const score = scoreSignals(signals);
  const situation = pickSituation(input.context);
  return formatRiskAnalysis({
    level: score.level,
    total: score.total,
    signals: score.signals,
    situation,
    channels: REPORT_CHANNELS[situation],
    channel: input.context?.channel,
  });
}

/** MCP 서버에 analyzePhishingRisk 툴을 등록한다(배선은 server.ts에서 호출). */
export function registerAnalyzePhishingRisk(server: McpServer): void {
  server.registerTool(
    ANALYZE_TOOL_NAME,
    {
      title: analyzeAnnotations.title,
      description: ANALYZE_TOOL_DESCRIPTION,
      inputSchema: analyzeInputShape,
      annotations: analyzeAnnotations,
    },
    (args) => ({
      content: [{ type: 'text' as const, text: analyzePhishingRisk(args) }],
    }),
  );
}
