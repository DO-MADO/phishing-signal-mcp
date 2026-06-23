import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getReportChannels } from '../src/tools/getReportChannels.js';
import { DISCLAIMER, MAX_RESPONSE_BYTES } from '../src/format/markdown.js';

test('suspiciousOnly: 1394·118 안내 + 디스클레이머', () => {
  const md = getReportChannels({ situation: 'suspiciousOnly' });
  assert.ok(md.includes('1394') && md.includes('118'));
  assert.ok(md.includes(DISCLAIMER));
});

test('alreadyPaid: 즉시 대응(112·1332·1394) 안내', () => {
  const md = getReportChannels({ situation: 'alreadyPaid' });
  for (const n of ['112', '1332', '1394']) assert.ok(md.includes(n), `${n} 포함`);
  assert.match(md, /즉시/);
});

test('personalInfoExposed: 노출자 사고예방시스템(url 디팽)', () => {
  const md = getReportChannels({ situation: 'personalInfoExposed' });
  assert.ok(md.includes('pd[.]fss[.]or[.]kr'));
  assert.ok(!md.includes('pd.fss.or.kr'), 'url은 디팽되어야 함');
});

test('malwareInstalled: 초기화/재발급 안내', () => {
  const md = getReportChannels({ situation: 'malwareInstalled' });
  assert.ok(md.includes('초기화') && md.includes('재발급'));
});

test('출력은 우선순위 순(1.로 시작)이고 24k 한도 이내', () => {
  const md = getReportChannels({ situation: 'alreadyPaid' });
  assert.match(md, /\n1\. /);
  assert.ok(Buffer.byteLength(md, 'utf8') <= MAX_RESPONSE_BYTES);
});
