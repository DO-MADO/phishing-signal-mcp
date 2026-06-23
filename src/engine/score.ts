// 가중치 합산 → 위험도 구간 매핑 (SPEC §5)
// 설계 원칙: 임계값은 보수적으로 — 오탐(FP)보다 미탐(FN) 회피 우선.
// 초기 가중치/임계값은 v1 하드코딩, 실제 피싱 샘플로 후속 캘리브레이션(SPEC §11).

import type { DetectedSignal, SignalId } from './signals.js';

export type RiskLevel = '낮음' | '주의' | '높음' | '매우 높음';

// 피해를 직접 유발하는 행동(OTP/원격앱, 금전, 개인정보, 악성앱)은 최고 가중치(3).
// 사칭·의심 링크는 보조(2), 긴급성은 단독으로는 약한 신호(1).
export const SIGNAL_WEIGHTS: Record<SignalId, number> = {
  impersonation: 2,
  requestedAction: 3,
  urgency: 1,
  financialLoss: 3,
  personalInfo: 3,
  malwareApp: 3,
  suspiciousLink: 2,
};

export interface RiskScore {
  total: number;
  level: RiskLevel;
  signals: DetectedSignal[]; // 판단 근거
}

// 보수적 구간: 가중치 3짜리 단일 신호(예: OTP 요구)만으로도 '높음'으로 올라간다.
export function toRiskLevel(total: number): RiskLevel {
  if (total <= 0) return '낮음';
  if (total <= 2) return '주의';
  if (total <= 5) return '높음';
  return '매우 높음';
}

/** 탐지된 신호 목록을 가중치 합산해 위험도 점수/구간을 산출한다. */
export function scoreSignals(signals: readonly DetectedSignal[]): RiskScore {
  const total = signals.reduce((sum, s) => sum + (SIGNAL_WEIGHTS[s.id] ?? 0), 0);
  return { total, level: toRiskLevel(total), signals: [...signals] };
}
