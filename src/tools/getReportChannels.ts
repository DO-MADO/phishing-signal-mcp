// 툴: getReportChannels (SPEC §4.2 / §4.3)
// 상황별 공식 신고/대응 루트를 우선순위와 함께 반환(정적, 초고속). §6 확정값 기반.
// 외부 호출 없음 → openWorldHint:false, 읽기 전용/멱등.

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { formatReportChannels } from '../format/markdown.js';

export const REPORT_CHANNELS_TOOL_NAME = 'getReportChannels';

// SPEC §2: 영문 + 서비스명 영문/국문 병기, 1,024자 이내.
export const REPORT_CHANNELS_TOOL_DESCRIPTION =
  'Returns official Korean anti-voice-phishing report and response channels for a given situation, prioritized. 피싱 신호등(PhishingSignal).';

// SPEC §4.2 입력 스키마.
export const reportChannelsInputShape = {
  situation: z
    .enum(['suspiciousOnly', 'alreadyPaid', 'personalInfoExposed', 'malwareInstalled'])
    .describe(
      '현재 상황: 의심만 받음(suspiciousOnly) / 이미 송금함(alreadyPaid) / 개인정보 노출(personalInfoExposed) / 악성앱 설치(malwareInstalled).',
    ),
} as const;

export type GetReportChannelsInput = z.infer<z.ZodObject<typeof reportChannelsInputShape>>;

// SPEC §4.3: 읽기 전용 조회, 외부 호출 없음, 동일 입력 동일 출력.
export const reportChannelsAnnotations = {
  title: '피싱 신호등 — 신고 채널 안내 (PhishingSignal)',
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: false,
  idempotentHint: true,
} as const;

/** 순수 조회 함수: 상황 → 정제된 마크다운(서버/SDK 비의존). */
export function getReportChannels(input: GetReportChannelsInput): string {
  return formatReportChannels(input.situation);
}

/** MCP 서버에 getReportChannels 툴을 등록한다(배선은 server.ts에서 호출). */
export function registerGetReportChannels(server: McpServer): void {
  server.registerTool(
    REPORT_CHANNELS_TOOL_NAME,
    {
      title: reportChannelsAnnotations.title,
      description: REPORT_CHANNELS_TOOL_DESCRIPTION,
      inputSchema: reportChannelsInputShape,
      annotations: reportChannelsAnnotations,
    },
    (args) => ({
      content: [{ type: 'text' as const, text: getReportChannels(args) }],
    }),
  );
}
