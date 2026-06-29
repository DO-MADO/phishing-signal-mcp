import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeForSignalDetection } from '../src/engine/normalize.js';
import { detectSignals } from '../src/engine/signals.js';

const ids = (text: string): string[] => detectSignals(text).map((s) => s.id);

test('기관 사칭 신호를 탐지한다', () => {
  assert.ok(ids('서울중앙지검 수사관입니다').includes('impersonation'));
});

test('위험 행동 요구(OTP/원격앱) 신호를 탐지한다', () => {
  assert.ok(ids('인증번호 불러주세요').includes('requestedAction'));
  assert.ok(ids('애니데스크 설치하세요').includes('requestedAction'));
});

test('긴급성 압박 신호를 탐지한다', () => {
  assert.ok(ids('지금 당장 처리하지 않으면 구속됩니다').includes('urgency'));
});

test('금전 피해 신호를 탐지한다', () => {
  assert.ok(ids('안전계좌로 송금하세요').includes('financialLoss'));
});

test('개인정보 탈취 신호를 탐지한다', () => {
  assert.ok(ids('주민번호와 계좌번호를 알려주세요').includes('personalInfo'));
});

test('악성앱 설치 유도 신호를 탐지한다', () => {
  assert.ok(ids('이 apk 파일을 설치하세요').includes('malwareApp'));
});

test('의심 링크/발신 신호를 탐지한다', () => {
  assert.ok(ids('[Web발신] http://bit.ly/abcd 확인').includes('suspiciousLink'));
});

test('정상 텍스트는 어떤 신호도 탐지하지 않는다', () => {
  assert.equal(detectSignals('오늘 점심 같이 먹을래? 메뉴 추천해줘').length, 0);
});

test('탐지된 신호는 근거(matches)를 포함한다', () => {
  const ra = detectSignals('인증번호 알려주세요').find((s) => s.id === 'requestedAction');
  assert.ok(ra && ra.matches.length > 0);
});

test('탐지 전용 정규화는 상품권·숫자 오타를 표준 표현으로 맞춘다', () => {
  const normalized = normalizeForSignalDetection('구플 깁카 뒤쪽 숫짜만');
  assert.match(normalized, /구글플레이 기프트카드/);
  assert.match(normalized, /뒷면/);
  assert.match(normalized, /숫자/);
});

test('난독화된 상품권 코드 전달 요구를 탐지한다', () => {
  const signalIds = ids('구플 깁카 뒷장 숫짜를 채팅 말고 글자로 보내');
  assert.ok(signalIds.includes('requestedAction'));
  assert.ok(signalIds.includes('financialLoss'));
});

test('대명사로 우회한 인증값 읽기 요구를 탐지한다', () => {
  assert.ok(ids('결제 승인 화면에 나온 그거 지금 읽어줘').includes('requestedAction'));
});

test('서술형 신분증·통장 사진 요구를 탐지한다', () => {
  const signalIds = ids('환급 처리하려면 신분 뒷면과 입금받을 통장 사진을 올려주세요');
  assert.ok(signalIds.includes('personalInfo'));
});

test('교육·후기 문맥의 위험 단어는 억제한다', () => {
  assert.equal(detectSignals('계좌를 잠깐 빌려주면 처벌된다는 예방 포스터를 만들었다').length, 0);
  assert.equal(detectSignals('스토어 밖 파일 설치는 위험하다고 가족에게 안내했다').length, 0);
});
