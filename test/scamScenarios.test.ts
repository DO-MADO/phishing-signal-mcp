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
  assert.equal(levelOf('친구한테 빌린 돈 오늘 갚았어 계좌로 보내줬어'), '낮음');
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

test('실서비스형 가족 사칭·상품권·협박 변형을 추가로 방어한다', () => {
  assertAtLeast(levelOf('아빠 폰 맛갔어 급전 좀 부탁'), '높음');
  assertAtLeast(levelOf('엄마 액정 박살나서 송금 가능해?'), '높음');
  assertAtLeast(levelOf('누나 지금 문제 생김 삼십만 쏴줄래?'), '높음');
  assertAtLeast(levelOf('친구야 급한 일 카드값 대신 내줘'), '높음');
  assertAtLeast(levelOf('휴대폰 침수돼서 이 번호로만 톡해'), '주의');
  assert.equal(levelOf('문상 코드만 사진으로 줘'), '매우 높음');
  assert.equal(levelOf('따님을 데리고 있으니 조용히 처리하자'), '매우 높음');
});

test('실서비스형 악성앱·원격권한·현금수거책 변형을 추가로 방어한다', () => {
  assert.equal(levelOf('출처 허용 켜고 내려받은 앱 열어'), '매우 높음');
  assert.equal(levelOf('휴대폰 설정에서 접근성 켠 다음 상담앱 열어'), '매우 높음');
  assert.equal(levelOf('상담원이 보낸 파일 실행하고 권한 다 허용'), '매우 높음');
  assert.equal(levelOf('검찰 보안 메신저 설치하고 알림 접근 권한 허용해야 조사 진행됩니다'), '매우 높음');
  assertAtLeast(levelOf('화면 같이 보게 공유 켜'), '높음');
  assertAtLeast(levelOf('체크카드 잠깐 맡기면 알바비 드려요'), '높음');
  assertAtLeast(levelOf('계좌 빌려주면 수당 바로 지급'), '높음');
});

test('교육·뉴스·일상 설명 문맥은 단독 키워드만으로 과탐하지 않는다', () => {
  assert.equal(levelOf('계좌이체 수수료가 무료라 편하다'), '낮음');
  assert.equal(levelOf('계좌이체 한도 늘리는 법 알려줘'), '낮음');
  assert.equal(levelOf('계좌 잔액은 은행 앱에서 직접 확인했어'), '낮음');
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
  assert.equal(levelOf('앱 설치 후 실행은 설명서대로 하세요'), '낮음');
  assert.equal(levelOf('회사 보안앱 설치 완료 알림입니다'), '낮음');
  assert.equal(levelOf('상품권 번호는 영수증에 있어'), '낮음');
  assert.equal(levelOf('계좌번호 확인했습니다'), '낮음');
  assert.equal(levelOf('인증번호 입력해서 가입 완료'), '낮음');
  assert.equal(levelOf('공동인증서 비밀번호 변경 방법 알려줘'), '낮음');
  assert.equal(levelOf('공인인증서 암호 입력하고 로그인 완료했어'), '낮음');
  assert.equal(levelOf('ARS 인증 받아서 본인확인 완료하고 가입했어'), '낮음');
  assert.equal(levelOf('비밀번호 입력 화면이 진짜인지 확인하는 법을 배웠어'), '낮음');
  assert.equal(levelOf('승인번호 회신하라는 건 금지 문구로 막혀 있어'), '낮음');
  assert.equal(levelOf('인증번호 알려달라는 문자는 무시하고 삭제했어'), '낮음');
  assert.equal(levelOf('비밀번호 변경 방법 좀 알려줘 자꾸 까먹네'), '낮음');
  assert.equal(levelOf('승인번호 입력해서 카드 등록 완료했어'), '낮음');
  assert.equal(levelOf('OTP는 알려주면 안 된다지만 교육 자료로만 읽었어'), '낮음');
  assert.equal(levelOf('보안코드 알려달라는 문구는 피싱 예방 안내에 나와 있어'), '낮음');
  assert.equal(levelOf('인증번호 알려주시겠냐고 묻는 전화는 다 사기야'), '낮음');
  assert.equal(levelOf('계좌 비밀번호 내가 직접 확인했어 문제없더라'), '낮음');
  assert.equal(levelOf('비밀번호 맞는지 확인하려고 한 번 입력해봤어'), '낮음');
  assert.equal(levelOf('보안 문자 인증번호 확인하고 결제 끝냈어'), '낮음');
  assert.equal(levelOf('보안카드 어디 뒀는지 확인해봐야겠다'), '낮음');
  assert.equal(levelOf('인증서 암호 기억나는지 확인해봤어'), '낮음');
  assert.equal(levelOf('잠금 번호 확인하려고 설정 들어갔다 나왔어'), '낮음');
  assert.equal(levelOf('공동인증서 비밀번호 변경하려고 본인확인했어'), '낮음');
  assert.equal(levelOf('비밀번호 변경 절차 어떻게 되는지 확인하고 싶어'), '낮음');
  assert.equal(levelOf('접근성 허용 메뉴가 어디 있는지 설명해줘'), '낮음');
  assert.equal(levelOf('앱 권한 설정 확인했고 알림은 필요한 것만 켰어'), '낮음');
  assert.equal(levelOf('접근성 권한 켜져 있나 확인했더니 꺼져 있더라'), '낮음');
  assert.equal(levelOf('원격 지원 권한은 필요 없어서 해제했어'), '낮음');
  assert.equal(levelOf('알림 접근은 필요한 앱에만 켜라고 보안팀이 안내했어'), '낮음');
  assert.equal(levelOf('접근성 권한 다 끄고 필요한 앱에만 허용했어'), '낮음');
  assert.equal(levelOf('파일 실행 권한 오류가 난다'), '낮음');
  assert.equal(levelOf('병원비 급함이라는 표현은 광고 문구로 부적절하다'), '낮음');
  assert.equal(levelOf('안전계좌라는 말이 나오면 의심해야 한다'), '낮음');
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
  assert.equal(levelOf('경찰 수사 중 ㅇㅈㅂㅎ 알려줘'), '매우 높음');
  assert.equal(levelOf('법원 등기가 반송되었습니다. 사건 조회 URL에 접속해서 사건번호를 말씀해주세요.'), '매우 높음');
  assertAtLeast(levelOf('금융감독 조사 중이라 입출금내역 확인 필요합니다'), '높음');
});

test('완료·방법·안내 같은 정상 앵커가 자격증명 요구를 누르지 않는다', () => {
  assertAtLeast(levelOf('본인 확인 완료를 위해 공동인증서 비밀번호 알려주세요'), '높음');
  assertAtLeast(levelOf('납부 방법 안내드릴게요 계좌 비밀번호 알려주세요'), '높음');
  assertAtLeast(levelOf('가입 완료를 위해 인증서 비밀번호 알려주세요'), '높음');
  assertAtLeast(levelOf('OTP 불러주세요 보안 교육 차원에서 꼭 필요합니다'), '높음');
  assertAtLeast(levelOf('비밀번호 알려주세요 변경 방법은 제가 안내'), '높음');
  assertAtLeast(levelOf('계좌 비밀번호 말씀해주세요 재발급 절차 도와'), '높음');
  assertAtLeast(levelOf('받은 인증번호 회신 바랍니다 보안 교육 차원'), '높음');
  assertAtLeast(levelOf('공동인증서 비밀번호 불러주시면 됩니다 교육받은 절차'), '높음');
  assertAtLeast(levelOf('보안카드 번호 알려주시겠어요 피싱 신고 접수'), '높음');
  assertAtLeast(levelOf('승인번호 확인이 필요합니다 본인 휴대폰 인증이라 말씀해 주실래요'), '높음');
  assertAtLeast(levelOf('비밀번호 변경 방법 알려주세요 그리고 지금 OTP도 불러주세요'), '높음');
  assertAtLeast(levelOf('공동인증서 재발급 방법 설명해주세요 먼저 현재 암호부터 말해주세요'), '높음');
  assertAtLeast(levelOf('문자읽기 권한 허용해주시겠어요 보안 교육 절차'), '높음');
  assertAtLeast(levelOf('경찰 사이버수사대입니다 보안 교육 명목으로 인증번호 회신 바랍니다'), '높음');
  assertAtLeast(levelOf('확인 코드 답장 주셔야 합니다 금지 문구 같지만 정상'), '높음');
  assertAtLeast(levelOf('명의 도용 신고 접수용으로 공인인증서 암호 회신 바랍니다'), '높음');
  assertAtLeast(levelOf('금감원입니다 신고 접수 확인차 계좌 비밀번호 말씀 가능하실까요'), '높음');
  assertAtLeast(levelOf('카드사 보안팀입니다 문구 안내하며 보안카드 번호 알려 주시길 바랍니다'), '높음');
  assertAtLeast(levelOf('국세청입니다 환급 위해 계좌 비밀번호 확인 가능하실까요 신고 접수'), '높음');
  assertAtLeast(levelOf('받은 인증번호 회신 주실 수 있나요 보안 교육 차원'), '높음');
  assertAtLeast(levelOf('보안코드 알려 주면 됩니다 안내 문구대로만'), '높음');
  assertAtLeast(levelOf('일회용 번호 회신 부탁드릴게요 보안 교육상 본인확인'), '높음');
  assertAtLeast(levelOf('OTP는 알려주면 안 된다지만 이번엔 보안코드 회신 주실 수 있나요'), '높음');
  assertAtLeast(levelOf('본인확인 위해 OTP 입력 해야 돼요 문구 안내대로'), '높음');
  assertAtLeast(levelOf('받은 인증번호 회신해 주세욥 보안 교육'), '높음');
  assertAtLeast(levelOf('보안코드 알려 주십시오 신고 접수 확인 절차'), '높음');
  assertAtLeast(levelOf('문자읽기 권한 허용 가능하실까요 보안 교육 절차'), '높음');
  assertAtLeast(levelOf('알림 접근 권한 켜 주실 수 있나요 신고 접수 확인'), '높음');
  assertAtLeast(levelOf('공동인증서 비밀번호 말씀 가능할까요 교육받은 절차'), '높음');
  assertAtLeast(levelOf('카드사입니다 사고 예방 교육 안내하며 카드 비번 회신 주실 수 있나요'), '높음');
  assertAtLeast(levelOf('OTP는 지금 화면에 뜬 그 숫자 그대로 회신 바랍니다'), '높음');
  assertAtLeast(levelOf('검찰입니다 OTP 확인해주세요'), '높음');
  assertAtLeast(levelOf('알림 접근 권한 허용 가능하실까요 신고 접수'), '높음');
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
