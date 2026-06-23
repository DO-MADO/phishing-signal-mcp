import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  COUNTERSCAM_SCENARIO_REFERENCES,
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
  assert.ok(SCAM_SCENARIOS.length >= 10);
  assert.ok(OFFICIAL_SOURCE_REFERENCES.some((s) => s.name.includes('경찰청')));
  assert.ok(OFFICIAL_SOURCE_REFERENCES.some((s) => s.name.includes('금융감독원')));
  assert.ok(OFFICIAL_SOURCE_REFERENCES.some((s) => s.name.includes('KISA')));
});

test('피싱안심SOS 큐레이션 항목은 필수 구조화 필드를 가진다', () => {
  assert.equal(COUNTERSCAM_SCENARIO_REFERENCES.length, 6);
  for (const scenario of COUNTERSCAM_SCENARIO_REFERENCES) {
    assert.ok(scenario.sourceUrl.startsWith('https://www.counterscam112.go.kr/bbs009/board/boardList.do'));
    assert.equal(scenario.sourceTitle, '피싱안심SOS 피싱 시나리오');
    assert.ok(scenario.scenarioTitle);
    assert.ok(scenario.tags.length > 0);
    assert.ok(scenario.riskSignals.length > 0);
    assert.ok(scenario.patternHints.length > 0);
    assert.match(scenario.recommendedRiskLevel, /^(낮음|주의|높음|매우 높음)$/);
  }
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

test('구어체·변형 어미의 가족 사칭 금전 요구도 높음 이상으로 판단한다', () => {
  assertAtLeast(levelOf('엄마 ㅠㅠ 나 민정이ㅠㅠ 돈 없어 돈 너무 급행 돈 보내줭'), '높음');
  assertAtLeast(levelOf('엄마 나 폰 고장났어 돈 좀 보내죵'), '높음');
  assertAtLeast(levelOf('아빠 급한데 수리비 보내줘용'), '높음');
  assertAtLeast(levelOf('엄마 나 폰 고장났어 돈 좀 보내주라'), '높음');
  assertAtLeast(levelOf('아빠 급한데 수리비 입금좀'), '높음');
  assertAtLeast(levelOf('엄마ㅠㅠ나야돈좀보내줘'), '높음');
  assertAtLeast(levelOf('ㅇㅁ 나 돈좀 보내줘'), '높음');
  assertAtLeast(levelOf('엄마 나 돈좀'), '높음');
  assertAtLeast(levelOf('아빠 나 수리비 좀 ㅠㅠ'), '높음');
});

test('구어체 금전 표현은 정상 입금·생활비 문맥까지 과탐하지 않는다', () => {
  assert.equal(levelOf('입금 확인했습니다 감사합니다'), '낮음');
  assert.equal(levelOf('친구야 내가 돈 보내줄게'), '낮음');
  assert.equal(levelOf('이번 달 생활비 돈 좀 아껴야겠다'), '낮음');
  assert.equal(levelOf('엄마 나 돈 좀 아껴야겠다'), '낮음');
  assert.equal(levelOf('아빠 나 오늘 급행열차 타고 가'), '낮음');
});

test('우회 표현의 가족 사칭·번호변경·기관 사칭도 미탐하지 않는다', () => {
  assertAtLeast(levelOf('엄마 나 폰 깨짐 돈 부쳐줘'), '높음');
  assertAtLeast(levelOf('엄마 나 휴대폰 안돼 생활비 조금만 부탁'), '높음');
  assertAtLeast(levelOf('엄마 나 지금 큰일났어 돈 가능해?'), '높음');
  assertAtLeast(levelOf('폰 잃어버림 이 번호 저장해줘'), '주의');
  assertAtLeast(levelOf('번호 바꿨어 문자로만 연락해'), '주의');
  assert.equal(levelOf('검 사 입니다 사건 확인하려면 인증 번호 말해주세요'), '매우 높음');
});

test('협박·대출·악성앱·현금수거책 변형 표현을 보수적으로 탐지한다', () => {
  assert.equal(levelOf('아들을 데리고 있다 해치기 싫으면 합의하자'), '매우 높음');
  assert.equal(levelOf('법원 등기 반송 사건조회 링크 접속하세요'), '매우 높음');
  assertAtLeast(levelOf('은행 상담사입니다 수수료 입금하면 한도 열립니다'), '높음');
  assertAtLeast(levelOf('저리 대출 가능 기존 건 먼저 갚아야 해요'), '높음');
  assert.equal(levelOf('보안 어플 깔고 접근성 허용 눌러주세요'), '매우 높음');
  assert.equal(levelOf('원격지원 프로그램 받아서 접속 코드 알려줘'), '매우 높음');
  assertAtLeast(levelOf('단기 부업 현금 전달만 하면 수고비 바로 줍니다'), '높음');
});

test('송금동사·인증정보 난독화·자녀 위급 표현을 추가로 방어한다', () => {
  assertAtLeast(levelOf('아들인데 급한일 생겼어 계좌로 백만원 넣어줘'), '높음');
  assertAtLeast(levelOf('엄마 나 돈 쏴줘'), '높음');
  assertAtLeast(levelOf('형 50만원만 보내줄 수 있어?'), '높음');
  assertAtLeast(levelOf('인 증 번 호 알려줘'), '높음');
  assertAtLeast(levelOf('오티피 불러줘'), '높음');
  assertAtLeast(levelOf('ㅇㅈㅂㅎ 알려줘'), '높음');
  assert.equal(levelOf('아이 데리고 있다 돈 보내'), '매우 높음');
  assertAtLeast(levelOf('따님 교통사고 수술중 병원비 급함'), '높음');
});

test('교육·뉴스·일상 설명 문맥은 단독 키워드만으로 과탐하지 않는다', () => {
  assert.equal(levelOf('계좌이체 수수료가 무료라 편하다'), '낮음');
  assert.equal(levelOf('계좌이체 한도 늘리는 법 알려줘'), '낮음');
  assert.equal(levelOf('생일 선물로 상품권을 받았다'), '낮음');
  assert.equal(levelOf('기프트카드 디자인이 예쁘다'), '낮음');
  assert.equal(levelOf('아이 사고 예방 교육 자료를 읽었다'), '낮음');
  assert.equal(levelOf('검찰 관련 뉴스를 봤다'), '낮음');
  assert.equal(levelOf('회사 보안앱 설치 방법을 내부 게시판에서 봤다'), '낮음');
  assert.equal(levelOf('앱 설치하는 법 좀 알려줘'), '낮음');
  assert.equal(levelOf('비밀번호 까먹었어'), '낮음');
  assert.equal(levelOf('방금 인증번호 입력해서 로그인했어'), '낮음');
  assert.equal(levelOf('나 요즘 원격으로 재택근무'), '낮음');
  assert.equal(levelOf('신분증 챙겨서 와'), '낮음');
  assert.equal(levelOf('보안카드 어디 뒀더라'), '낮음');
  assert.equal(levelOf('OTP 카드 재발급 받아야 해'), '낮음');
  assert.equal(levelOf('OTP는 절대 알려주면 안 된다고 배웠다'), '낮음');
  assert.equal(levelOf('보안카드 번호를 요구하면 피싱일 수 있다'), '낮음');
});

test('상품권 PIN 요구는 매우 높음으로 판단한다', () => {
  const text = '편의점에서 상품권 사서 PIN 보내줘.';

  assert.equal(levelOf(text), '매우 높음');
  assert.equal(levelOf('편의점에서 상품권 사서 PIN 보내줭'), '매우 높음');
});

test('자녀 사고·납치·합의금 협박은 매우 높음으로 판단한다', () => {
  assert.equal(levelOf('자녀가 사고났다. 지금 합의금 필요하니 송금해라.'), '매우 높음');
  assert.equal(levelOf('아이가 납치됐다. 당장 합의금 입금해라.'), '매우 높음');
  assert.equal(levelOf('아이를 차에 태웠다. 해치지 않을 테니 술값을 보내라.'), '매우 높음');
});

test('검찰/경찰 사칭 + 계좌/OTP/인증번호 요구는 매우 높음으로 판단한다', () => {
  assert.equal(levelOf('검찰 수사관입니다. 계좌 확인이 필요하니 OTP 인증번호를 알려주세요.'), '매우 높음');
  assert.equal(levelOf('경찰입니다. 대포통장 사건에 연루되어 인증번호 제출이 필요합니다.'), '매우 높음');
  assert.equal(levelOf('법원 등기가 반송되었습니다. 사건 조회 URL에 접속해서 사건번호를 말씀해주세요.'), '매우 높음');
});

test('택배/카드배송 URL 문자는 주의 이상으로 판단한다', () => {
  assertAtLeast(levelOf('택배 배송 주소 확인 URL http://example.test/track'), '주의');
  assertAtLeast(levelOf('카드배송 확인 링크 https://example.test/card'), '주의');
});

test('apk 설치 또는 원격제어 앱 설치 유도는 매우 높음으로 판단한다', () => {
  assert.equal(levelOf('보안 확인을 위해 apk 설치 후 실행하세요.'), '매우 높음');
  assert.equal(levelOf('원격제어 앱 설치하고 권한 허용하세요.'), '매우 높음');
});

test('성매매/마사지샵 방문사실 유포 협박은 매우 높음으로 판단한다', () => {
  assert.equal(levelOf('마사지 업소 방문 영상이 촬영됐고 가족 지인 연락처 확보했다. 좋게 합의 보자.'), '매우 높음');
});

test('카드사 사칭 + 결제/카드발급/인증번호는 높음 이상으로 판단한다', () => {
  assertAtLeast(levelOf('카드 배송 확인입니다. 발급 조회를 위해 생년월일 말씀해주세요.'), '높음');
  assert.equal(levelOf('카드사 사고예방팀입니다. 원격 앱 설치 후 인증번호 입력하세요.'), '매우 높음');
});

test('대환대출 + 기존 대출 상환/수수료/앱 설치는 매우 높음으로 판단한다', () => {
  assert.equal(levelOf('저금리 대환대출 가능하지만 기존 대출 전액 상환해야 합니다. 신청서 파일 앱 설치 후 수수료 입금하세요.'), '매우 높음');
});

test('관공서 사칭 + 환급/지원금/URL은 주의 이상으로 판단한다', () => {
  assertAtLeast(levelOf('세무서입니다. 환급금 신청 URL 접속해서 신분증 확인하세요.'), '주의');
  assertAtLeast(levelOf('주민센터입니다. 지원금 대상 확인 링크로 접속하세요.'), '주의');
});
