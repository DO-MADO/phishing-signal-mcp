import { test } from 'node:test';
import assert from 'node:assert/strict';

import { HOLDOUT_SAMPLES } from './fixtures/holdoutSamples.js';
import { HOLDOUT_V2_SAMPLES } from './fixtures/holdoutV2Samples.js';

function assertHoldoutShape(samples: typeof HOLDOUT_SAMPLES, idPattern: RegExp): void {
  const attackCount = samples.filter((sample) => sample.kind === 'attack').length;
  const benignCount = samples.filter((sample) => sample.kind === 'benign').length;
  const ids = new Set(samples.map((sample) => sample.id));

  assert.ok(samples.length >= 35, `holdout samples: ${samples.length}`);
  assert.ok(samples.length <= 45, `holdout samples: ${samples.length}`);
  assert.ok(attackCount >= 20, `attack samples: ${attackCount}`);
  assert.ok(benignCount >= 15, `benign samples: ${benignCount}`);
  assert.equal(ids.size, samples.length, 'id 중복 금지');
  for (const sample of samples) {
    assert.match(sample.id, idPattern);
    assert.ok(sample.text);
    assert.match(sample.expectedLevel, /^(낮음|주의|높음|매우 높음)$/);
  }
}

test('held-out 샘플은 구조만 검증하고 위험도 결과는 단언하지 않는다', () => {
  assertHoldoutShape(HOLDOUT_SAMPLES, /^hold-(?:attack|benign)-\d{3}$/);
  assertHoldoutShape(HOLDOUT_V2_SAMPLES, /^hold2-(?:attack|benign)-\d{3}$/);
});
