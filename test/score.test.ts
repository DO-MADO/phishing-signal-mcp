import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreSignals, toRiskLevel, SIGNAL_WEIGHTS } from '../src/engine/score.js';
import { SIGNAL_DEFINITIONS } from '../src/engine/signals.js';
import type { DetectedSignal, SignalId } from '../src/engine/signals.js';

const sig = (id: SignalId): DetectedSignal => ({ id, label: id, matches: ['x'] });

test('신호가 없으면 점수 0, 낮음', () => {
  const r = scoreSignals([]);
  assert.equal(r.total, 0);
  assert.equal(r.level, '낮음');
});

test('가중치를 합산한다', () => {
  const r = scoreSignals([sig('impersonation'), sig('urgency')]); // 2 + 1
  assert.equal(r.total, 3);
});

test('구간 경계 매핑', () => {
  assert.equal(toRiskLevel(0), '낮음');
  assert.equal(toRiskLevel(1), '주의');
  assert.equal(toRiskLevel(2), '주의');
  assert.equal(toRiskLevel(3), '높음');
  assert.equal(toRiskLevel(5), '높음');
  assert.equal(toRiskLevel(6), '매우 높음');
});

test('단일 OTP 요구(가중치 3)는 높음', () => {
  assert.equal(scoreSignals([sig('requestedAction')]).level, '높음');
});

test('전형적 피싱 조합은 매우 높음', () => {
  const r = scoreSignals([
    sig('impersonation'),
    sig('urgency'),
    sig('financialLoss'),
    sig('requestedAction'),
  ]); // 2 + 1 + 3 + 3 = 9
  assert.equal(r.level, '매우 높음');
});

test('모든 신호에 양의 가중치가 정의되어 있다', () => {
  for (const def of SIGNAL_DEFINITIONS) {
    assert.ok(SIGNAL_WEIGHTS[def.id] > 0, `${def.id} 가중치 누락`);
  }
});
