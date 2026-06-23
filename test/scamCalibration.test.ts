import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SOURCE_DISCOVERY_RECORDS } from '../src/data/sourceDiscovery.js';
import {
  OFFICIAL_SOURCE_REFERENCES,
  SCAM_SCENARIOS,
} from '../src/data/scamScenarios.js';
import { detectSignals, type SignalId } from '../src/engine/signals.js';
import { scoreSignals } from '../src/engine/score.js';
import { SCAM_CALIBRATION_SAMPLES } from './fixtures/scamCalibrationSamples.js';

const OFFICIAL_DOMAINS = ['counterscam112.go.kr', 'fss.or.kr', 'boho.or.kr'] as const;

function detectedIds(text: string): SignalId[] {
  return detectSignals(text).map((signal) => signal.id);
}

test('source discovery는 공식 도메인의 요약 메타데이터만 보관한다', () => {
  assert.ok(SOURCE_DISCOVERY_RECORDS.length >= 3);

  for (const record of SOURCE_DISCOVERY_RECORDS) {
    assert.ok(OFFICIAL_DOMAINS.includes(record.domain));
    assert.ok(record.url.startsWith(`https://www.${record.domain}`));
    assert.match(record.verificationStatus, /^(verifiedPage|officialDomainOnly)$/);
    assert.ok(record.institution);
    assert.ok(record.title);
    assert.ok(record.typeNames.length > 0);
    assert.ok(record.scenarioIds.length > 0);
    assert.ok(record.evidenceSummary.length > 0);
    assert.doesNotMatch(record.evidenceSummary, /https?:\/\//i);
  }
});

test('source discovery의 sourceId와 scenarioId는 실제 데이터와 연결된다', () => {
  const sourceIds = new Set(OFFICIAL_SOURCE_REFERENCES.map((source) => source.id));
  const scenarioIds = new Set(SCAM_SCENARIOS.map((scenario) => scenario.id));

  for (const record of SOURCE_DISCOVERY_RECORDS) {
    assert.ok(sourceIds.has(record.sourceId), `${record.id}: sourceId 연결 실패`);
    for (const scenarioId of record.scenarioIds) {
      assert.ok(scenarioIds.has(scenarioId), `${record.id}: ${scenarioId} 시나리오 연결 실패`);
    }
  }
});

test('캘리브레이션 샘플은 30~50개 범위를 유지하고 필수 필드를 갖는다', () => {
  assert.ok(SCAM_CALIBRATION_SAMPLES.length >= 30);
  assert.ok(SCAM_CALIBRATION_SAMPLES.length <= 50);

  const ids = new Set<string>();
  for (const sample of SCAM_CALIBRATION_SAMPLES) {
    assert.ok(sample.id);
    assert.ok(!ids.has(sample.id), `${sample.id}: 중복 id`);
    ids.add(sample.id);
    assert.ok(sample.text);
    assert.match(sample.expectedLevel, /^(낮음|주의|높음|매우 높음)$/);
    assert.ok(sample.scenarioId);
    assert.ok(Array.isArray(sample.sourceIds));
  }
});

test('캘리브레이션 샘플은 원문 URL·전화번호·계좌번호·주민번호를 저장하지 않는다', () => {
  for (const sample of SCAM_CALIBRATION_SAMPLES) {
    assert.doesNotMatch(sample.text, /https?:\/\//i, `${sample.id}: URL 저장 금지`);
    assert.doesNotMatch(sample.text, /\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b/, `${sample.id}: 휴대전화 저장 금지`);
    assert.doesNotMatch(sample.text, /\b\d{6}[-\s]?[1-4]\d{6}\b/, `${sample.id}: 주민번호 저장 금지`);
    assert.doesNotMatch(sample.text, /\b\d{2,6}-\d{2,6}-\d{2,7}(?:-\d{1,6})?\b/, `${sample.id}: 계좌번호 저장 금지`);
  }
});

test('캘리브레이션 샘플의 시나리오와 출처 참조가 유효하다', () => {
  const sourceIds = new Set(OFFICIAL_SOURCE_REFERENCES.map((source) => source.id));
  const scenarioIds = new Set([...SCAM_SCENARIOS.map((scenario) => scenario.id), 'benign_control']);

  for (const sample of SCAM_CALIBRATION_SAMPLES) {
    assert.ok(scenarioIds.has(sample.scenarioId), `${sample.id}: scenarioId 연결 실패`);
    for (const sourceId of sample.sourceIds) {
      assert.ok(sourceIds.has(sourceId), `${sample.id}: sourceId 연결 실패`);
    }
  }
});

test('캘리브레이션 샘플은 기대 위험도와 기대 신호를 만족한다', () => {
  for (const sample of SCAM_CALIBRATION_SAMPLES) {
    const signals = detectSignals(sample.text);
    const score = scoreSignals(signals);
    const ids = new Set(signals.map((signal) => signal.id));

    assert.equal(score.level, sample.expectedLevel, `${sample.id}: 위험도 불일치`);
    assert.deepEqual(detectedIds(sample.text).sort(), [...ids].sort(), `${sample.id}: 신호 중복 정리 실패`);
    for (const expectedSignal of sample.expectedSignals) {
      assert.ok(ids.has(expectedSignal), `${sample.id}: ${expectedSignal} 신호 누락`);
    }
    if (sample.expectedSignals.length === 0) {
      assert.equal(signals.length, 0, `${sample.id}: benign control 과탐`);
    }
  }
});
