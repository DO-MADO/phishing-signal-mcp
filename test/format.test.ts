import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  byteLength,
  clampToByteLimit,
  defang,
  renderChannels,
} from '../src/format/markdown.js';
import { REPORT_CHANNELS } from '../src/data/reportChannels.js';

test('defang은 링크를 클릭 불가 형태로 무력화한다', () => {
  const out = defang('http://bit.ly/abcd');
  assert.ok(!out.includes('http://bit.ly'));
  assert.equal(out, 'hxxp://bit[.]ly/abcd');
});

test('clampToByteLimit은 한도 이하로 자른다', () => {
  const big = '가'.repeat(20000); // 가 = UTF-8 3바이트
  const out = clampToByteLimit(big, 1000);
  assert.ok(byteLength(out) <= 1000);
  assert.ok(out.includes('생략'));
});

test('clampToByteLimit은 한도 이내면 원본을 그대로 반환한다', () => {
  assert.equal(clampToByteLimit('짧은 텍스트', 1000), '짧은 텍스트');
});

test('renderChannels는 우선순위 순으로 렌더하고 url은 디팽한다', () => {
  const out = renderChannels(REPORT_CHANNELS.personalInfoExposed);
  assert.ok(out.startsWith('1.'));
  assert.ok(out.includes('pd[.]fss[.]or[.]kr'));
  assert.ok(!out.includes('pd.fss.or.kr'));
});
