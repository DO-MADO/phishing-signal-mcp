import { test } from 'node:test';
import assert from 'node:assert/strict';

import { detectSignals } from '../src/engine/signals.js';
import { scoreSignals, type RiskLevel } from '../src/engine/score.js';
import { SCAM_ADVERSARIAL_SAMPLES } from './fixtures/scamAdversarialSamples.js';

const RANK: Record<RiskLevel, number> = { 낮음: 0, 주의: 1, 높음: 2, '매우 높음': 3 };

test('adversarial 합성 샘플은 최소 공격 50개·정상 30개 이상을 유지한다', () => {
  const attackCount = SCAM_ADVERSARIAL_SAMPLES.filter((sample) => sample.kind === 'attack').length;
  const benignCount = SCAM_ADVERSARIAL_SAMPLES.filter((sample) => sample.kind === 'benign').length;

  assert.ok(attackCount >= 50, `attack samples: ${attackCount}`);
  assert.ok(benignCount >= 30, `benign samples: ${benignCount}`);
});

test('adversarial 합성 샘플은 기대 위험도와 정상문 억제를 만족한다', () => {
  const failures: string[] = [];

  for (const sample of SCAM_ADVERSARIAL_SAMPLES) {
    const signals = detectSignals(sample.text);
    const score = scoreSignals(signals);
    const signalIds = signals.map((signal) => signal.id).join('+') || '-';
    const ok =
      sample.kind === 'benign'
        ? score.level === '낮음'
        : RANK[score.level] >= RANK[sample.expectedLevel];

    if (!ok) {
      failures.push(`${sample.id}: actual=${score.level}, expected=${sample.expectedLevel}, signals=${signalIds}, text=${sample.text}`);
    }
  }

  assert.deepEqual(failures, []);
});
