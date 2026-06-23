import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzePhishingRisk } from '../src/tools/analyzePhishingRisk.js';
import { DISCLAIMER, MAX_RESPONSE_BYTES } from '../src/format/markdown.js';
import { REPORT_CHANNELS } from '../src/data/reportChannels.js';

test('전형적 피싱 텍스트는 매우 높음 + 디스클레이머 포함', () => {
  const md = analyzePhishingRisk({
    text: '서울중앙지검 수사관입니다. 지금 당장 안전계좌로 송금하고 인증번호를 알려주세요.',
  });
  assert.match(md, /매우 높음/);
  assert.ok(md.includes(DISCLAIMER), '디스클레이머가 포함되어야 함');
});

test('빈 입력은 안전한 기본 응답(낮음) + 디스클레이머', () => {
  const md = analyzePhishingRisk({ text: '' });
  assert.match(md, /낮음/);
  assert.ok(md.includes(DISCLAIMER));
});

test('출력에 원본 민감정보(주민번호/계좌)가 노출되지 않는다', () => {
  const md = analyzePhishingRisk({
    text: '주민번호 900101-1234567, 계좌 110-234-567890 으로 송금하세요',
  });
  assert.ok(!md.includes('900101-1234567'), '주민번호 원본 노출 금지');
  assert.ok(!md.includes('110-234-567890'), '계좌번호 원본 노출 금지');
});

test('의심 링크는 디팽되어 클릭 가능한 형태로 노출되지 않는다', () => {
  const md = analyzePhishingRisk({ text: '[Web발신] http://bit.ly/abcd 확인하세요' });
  assert.ok(!md.includes('http://bit.ly/abcd'), '원본 URL이 그대로 노출되면 안 됨');
});

test('송금 완료 컨텍스트면 즉시 대응 채널(112·1394)을 안내한다', () => {
  const md = analyzePhishingRisk({ text: '송금해 주세요', context: { alreadySentMoney: true } });
  assert.ok(md.includes('112') && md.includes('1394'));
  assert.match(md, /즉시/);
});

test('개인정보 노출 컨텍스트면 노출자 사고예방시스템을 안내한다', () => {
  const md = analyzePhishingRisk({
    text: '신분증 사진 보내주세요',
    context: { alreadySharedPersonalInfo: true },
  });
  assert.ok(md.includes('pd[.]fss[.]or[.]kr') || md.includes('개인정보노출자'));
});

test('수신 채널에 따라 행동 가이드를 정밀화한다', () => {
  const baseText = '인증번호를 알려주세요';
  const phone = analyzePhishingRisk({ text: baseText, context: { channel: 'phone' } });
  const sms = analyzePhishingRisk({ text: baseText, context: { channel: 'sms' } });
  const kakao = analyzePhishingRisk({ text: baseText, context: { channel: 'kakao' } });

  assert.match(phone, /계좌번호·신분증 정보를 알려주지 마세요/);
  assert.match(phone, /상대가 보낸 링크를 누르거나 첨부 파일을 열지 마세요/);
  assert.match(phone, /기관·지인 여부는 공식 대표번호 또는 기존 연락처로 직접 확인하세요/);
  assert.match(phone, /통화기록·문자·대화 내용 등 남아 있는 기록은 삭제하지 말고 보존/);
  assert.match(phone, /통화 중이라면 바로 끊고/);
  assert.match(sms, /문자 링크·첨부는 열지 말고/);
  assert.match(kakao, /메신저 링크·파일은 열지 말고/);
  assert.doesNotMatch(phone, /의심 내용은 삭제하지 말고 캡처/);
  assert.doesNotMatch(phone, /상대가 주장한 기관\/지인/);
  assert.doesNotMatch(phone, /문자·메신저의 링크/);
  assert.doesNotMatch(sms, /통화 중이라면 바로 끊고/);
  assert.doesNotMatch(kakao, /통화 중이라면 바로 끊고/);
  assert.notEqual(phone, sms);
  assert.notEqual(sms, kakao);
});

test('응답은 24k 바이트 한도를 넘지 않는다', () => {
  const md = analyzePhishingRisk({ text: '송금 안전계좌 인증번호 '.repeat(5000) });
  assert.ok(Buffer.byteLength(md, 'utf8') <= MAX_RESPONSE_BYTES);
});

test('신고 채널 데이터는 1394를 포함하고 구 번호(1566)는 없다', () => {
  const all = JSON.stringify(REPORT_CHANNELS);
  assert.ok(all.includes('1394'), '1394 포함되어야 함');
  assert.ok(!all.includes('1566'), '구 대표번호(1566)는 제외되어야 함');
});
