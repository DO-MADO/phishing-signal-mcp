import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  OFFICIAL_SOURCE_REFERENCES,
  SCAM_SCENARIOS,
} from '../src/data/scamScenarios.js';
import { detectSignals } from '../src/engine/signals.js';
import { scoreSignals, type RiskLevel } from '../src/engine/score.js';
import { analyzePhishingRisk } from '../src/tools/analyzePhishingRisk.js';

function levelOf(text: string): RiskLevel {
  return scoreSignals(detectSignals(text)).level;
}

function assertAtLeast(level: RiskLevel, min: '주의' | '높음'): void {
  const rank: Record<RiskLevel, number> = { 낮음: 0, 주의: 1, 높음: 2, '매우 높음': 3 };
  assert.ok(rank[level] >= rank[min], `${level} should be at least ${min}`);
}

test('공식 출처 메타데이터와 10개 대표 시나리오를 제공한다', () => {
  assert.equal(SCAM_SCENARIOS.length, 10);
  assert.ok(OFFICIAL_SOURCE_REFERENCES.some((s) => s.name.includes('경찰청')));
  assert.ok(OFFICIAL_SOURCE_REFERENCES.some((s) => s.name.includes('금융감독원')));
  assert.ok(OFFICIAL_SOURCE_REFERENCES.some((s) => s.name.includes('KISA')));
});

test('시나리오 데이터는 원문 사례 대신 패턴/카테고리/권장 위험도/출처만 가진다', () => {
  for (const scenario of SCAM_SCENARIOS) {
    assert.ok(scenario.id);
    assert.ok(scenario.title);
    assert.ok(scenario.reason);
    assert.ok(scenario.categories.length > 0);
    assert.ok(scenario.sourceIds.length > 0);
    assert.match(scenario.recommendedLevel, /^(낮음|주의|높음|매우 높음)$/);
  }
});

test('가족 사칭 후 급전 요구는 높음 이상으로 판단한다', () => {
  const text = '엄마 나 폰 고장났어. 급하게 돈 보내줘.';
  const md = analyzePhishingRisk({ text });

  assertAtLeast(levelOf(text), '높음');
  assert.match(md, /높음|매우 높음/);
  assert.match(md, /가족/);
  assert.match(md, /돈|금전|송금|보내줘/);
});

test('상품권 PIN 요구는 매우 높음으로 판단한다', () => {
  const text = '편의점에서 상품권 사서 PIN 보내줘.';

  assert.equal(levelOf(text), '매우 높음');
});

test('자녀 사고·납치·합의금 협박은 매우 높음으로 판단한다', () => {
  assert.equal(levelOf('자녀가 사고났다. 지금 합의금 필요하니 송금해라.'), '매우 높음');
  assert.equal(levelOf('아이가 납치됐다. 당장 합의금 입금해라.'), '매우 높음');
});

test('검찰/경찰 사칭 + 계좌/OTP/인증번호 요구는 매우 높음으로 판단한다', () => {
  assert.equal(levelOf('검찰 수사관입니다. 계좌 확인이 필요하니 OTP 인증번호를 알려주세요.'), '매우 높음');
  assert.equal(levelOf('경찰입니다. 대포통장 사건에 연루되어 인증번호 제출이 필요합니다.'), '매우 높음');
});

test('택배/카드배송 URL 문자는 주의 이상으로 판단한다', () => {
  assertAtLeast(levelOf('택배 배송 주소 확인 URL http://example.test/track'), '주의');
  assertAtLeast(levelOf('카드배송 확인 링크 https://example.test/card'), '주의');
});

test('apk 설치 또는 원격제어 앱 설치 유도는 매우 높음으로 판단한다', () => {
  assert.equal(levelOf('보안 확인을 위해 apk 설치 후 실행하세요.'), '매우 높음');
  assert.equal(levelOf('원격제어 앱 설치하고 권한 허용하세요.'), '매우 높음');
});
