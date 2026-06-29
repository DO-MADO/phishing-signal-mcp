import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzePhishingRisk, scoreText } from '../src/tools/analyzePhishingRisk.js';
import { DISCLAIMER, MAX_RESPONSE_BYTES } from '../src/format/markdown.js';
import { REPORT_CHANNELS } from '../src/data/reportChannels.js';

test('전형적 피싱 텍스트는 매우 높음 + 디스클레이머 포함', () => {
  const md = analyzePhishingRisk({
    text: '서울중앙지검 수사관입니다. 지금 당장 안전계좌로 송금하고 인증번호를 알려주세요.',
  });
  assert.ok(md.startsWith('## 30초 안전 브레이크'));
  assert.match(md, /지금은 즉시 멈춰야 합니다/);
  assert.match(md, /매우 높음/);
  assert.ok(md.includes(DISCLAIMER), '디스클레이머가 포함되어야 함');
});

test('리포트용 scoreText는 텍스트-only 점수 경로를 반환한다', () => {
  const score = scoreText('서울중앙지검 수사관입니다. 지금 당장 안전계좌로 송금하고 인증번호를 알려주세요.');

  assert.equal(score.level, '매우 높음');
  assert.ok(score.signalIds.includes('impersonation'));
  assert.ok(score.signalIds.includes('requestedAction'));
  assert.ok(score.signalIds.includes('financialLoss'));
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

test('판단 근거는 긴 원문 덩어리 대신 핵심 표현으로 요약한다', () => {
  const md = analyzePhishingRisk({ text: '엄마 ㅠㅠ 나 민정이ㅠㅠ 돈 없어 돈 너무 급행 돈 보내줭' });

  assert.ok(!md.includes('돈 없어 돈 너무 급행 돈 보내줭'), '긴 원문 근거가 그대로 노출되면 안 됨');
  assert.match(md, /왜 위험한가요\?/);
  assert.match(md, /긴급성 압박.*판단 시간을 줄이는 압박 신호.*급행/);
  assert.match(md, /금전 피해 가능성.*금전 피해로 이어질 수 있는 요구 신호.*돈.*보내줭/);
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

test('계좌 요청은 신뢰 관계 정산 context가 있을 때만 낮춘다', () => {
  const settlement = '친구야 점심값 보내야 해서 계좌 알려줘';
  const marketplace = '중고거래 구매자인데 계좌 알려주시면 입금하고 주소 드릴게요';
  const smishing = '정부지원금 대상입니다. 링크에서 계좌 확인하세요';

  assert.match(analyzePhishingRisk({ text: settlement }), /위험도: 높음/);
  assert.match(
    analyzePhishingRisk({ text: settlement, context: { senderKnown: true, relationship: 'friend' } }),
    /위험도: 낮음/,
  );
  assert.match(
    analyzePhishingRisk({ text: marketplace, context: { senderKnown: true, relationship: 'merchant' } }),
    /위험도: 높음/,
  );
  assert.match(
    analyzePhishingRisk({ text: smishing, context: { senderKnown: true, relationship: 'friend' } }),
    /위험도: (높음|매우 높음)/,
  );
  assert.match(
    analyzePhishingRisk({
      text: '등록금 보내야 하니까 계좌번호랑 주민번호도 같이 알려줘',
      context: { senderKnown: true, relationship: 'family' },
    }),
    /위험도: (높음|매우 높음)/,
  );
});

test('가족 공유 문구는 높은 위험도에서만 짧게 제공한다', () => {
  const high = analyzePhishingRisk({ text: '엄마 나 폰 고장났어 급해서 수리비 돈좀 보내줘' });
  const low = analyzePhishingRisk({ text: '엄마 오늘 저녁 같이 먹자' });

  assert.match(high, /가족에게 공유할 문구/);
  assert.match(high, /먼저 멈추고 가족 또는 공식 번호로 확인하세요/);
  assert.doesNotMatch(low, /가족에게 공유할 문구/);
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

test('낮음 응답은 과한 경고 없이 차분하게 간소화한다(늑대소년 방지)', () => {
  const md = analyzePhishingRisk({
    text: '고객님 상품이 배송 완료되었습니다. 자세한 내용은 공식 앱에서 확인하세요.',
  });
  assert.match(md, /위험도: 낮음/);
  assert.ok(md.includes(DISCLAIMER));
  // 낮음에는 멈춤 배너·금지 목록·신고 루트를 띄우지 않는다.
  assert.doesNotMatch(md, /30초 안전 브레이크/);
  assert.doesNotMatch(md, /지금 하지 말아야 할 행동/);
  assert.doesNotMatch(md, /공식 신고 루트/);
  assert.doesNotMatch(md, /왜 위험한가요/);
});

test('높음 이상 응답은 멈춤 블록과 가족 공유 문구를 포함한다', () => {
  const md = analyzePhishingRisk({
    text: '금감원 조사라 계좌 비밀번호 확인이 필요합니다 말씀해주세요.',
  });
  assert.ok(md.startsWith('## 30초 안전 브레이크'));
  assert.match(md, /가족에게 공유할 문구/);
});
