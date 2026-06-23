import { test } from 'node:test';
import assert from 'node:assert/strict';
import { maskSensitive } from '../src/engine/mask.js';

test('주민등록번호를 마스킹하고 요청 키워드는 보존한다', () => {
  const out = maskSensitive('제 주민번호는 900101-1234567 입니다');
  assert.ok(!/\d{6}-?\d{7}/.test(out), '원본 주민번호가 남아있으면 안 됨');
  assert.match(out, /\*{6}-\*{7}/);
  assert.ok(out.includes('주민번호'), '요청 키워드(주민번호)는 보존되어야 함');
});

test('휴대전화 번호를 마스킹한다', () => {
  const out = maskSensitive('연락처 010-1234-5678 로 연락주세요');
  assert.ok(!/010-1234-5678/.test(out));
  assert.match(out, /\*{3}-\*{4}-\*{4}/);
});

test('카드번호(16자리)를 마스킹한다', () => {
  const out = maskSensitive('카드 1234-5678-9012-3456 결제');
  assert.ok(!/\d{4}-\d{4}-\d{4}-\d{4}/.test(out));
});

test('계좌번호(연속/하이픈)를 마스킹한다', () => {
  assert.ok(!/\d{10,}/.test(maskSensitive('계좌 12345678901 로 입금')), '연속 계좌번호 누락');
  assert.ok(!/110-234-567890/.test(maskSensitive('농협 110-234-567890')), '하이픈 계좌번호 누락');
});

test('신고 채널 등 짧은 번호는 마스킹하지 않는다', () => {
  const out = maskSensitive('지금 112, 1332, 1394, 118 로 신고하세요');
  for (const n of ['112', '1332', '1394', '118']) {
    assert.ok(out.includes(n), `${n} 은 보존되어야 함`);
  }
});

test('빈 입력/일반 텍스트는 변형하지 않는다', () => {
  assert.equal(maskSensitive(''), '');
  assert.equal(maskSensitive('안녕하세요 반갑습니다'), '안녕하세요 반갑습니다');
});
