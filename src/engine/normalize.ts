import { DETECTION_TEXT_REPLACEMENTS } from '../data/textNormalizationLexicon.js';

/** detectSignals 매칭에만 쓰는 보수적 표준화. 원문/마스킹/출력 텍스트는 바꾸지 않는다. */
export function normalizeForSignalDetection(text: string): string {
  let normalized = text
    .normalize('NFC')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/[ \t\r\n]{2,}/g, ' ')
    .trim();

  for (const [pattern, replacement] of DETECTION_TEXT_REPLACEMENTS) {
    normalized = normalized.replace(pattern, replacement);
  }

  return normalized;
}
