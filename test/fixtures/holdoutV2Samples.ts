// 이 세트는 개선에 미사용, 1회 측정 전용 held-out v2 평가셋이다.
// 어떤 테스트도 위험도 결과를 단언하지 않으며, 엔진 튜닝에 사용하지 않는다.
// 라벨은 엔진 실행 전 사람이 본 위험도 기준으로 정했다.

import type { HoldoutSample } from './holdoutSamples.js';

export const HOLDOUT_V2_SAMPLES: readonly HoldoutSample[] = [
  // 가족 사칭과 결제 장애 핑계로 제3자 선결제를 요구한다.
  { id: 'hold2-attack-001', kind: 'attack', text: '엄마 나 액정 나가서 토스 못 켜져 편의점 약 계산 네가 먼저 가능해?', expectedLevel: '높음' },
  // 상품권류 결제수단의 숨겨진 값을 문자로 요구하는 PIN 탈취다.
  { id: 'hold2-attack-002', kind: 'attack', text: '쥐플 기프카 사면 은색 부분 벗기고 끝 글자만 문자로 적어줘', expectedLevel: '매우 높음' },
  // 인증 화면 값을 대명사 없이 서술형으로 요구하는 계정 탈취 시도다.
  { id: 'hold2-attack-003', kind: 'attack', text: '본인 인증 화면 오른쪽에 뜬 그 번호만 조용히 불러주세요', expectedLevel: '높음' },
  // 신용점수·승인을 빌미로 선입금성 비용을 요구한다.
  { id: 'hold2-attack-004', kind: 'attack', text: '신용점수 복구하려면 보증예치 먼저 넣어야 승인 유지됩니다', expectedLevel: '높음' },
  // 법원 등기 열람을 빙자해 링크 접속과 사건 암호 입력을 유도한다.
  { id: 'hold2-attack-005', kind: 'attack', text: '등기 열람 제한이라 링크 열고 사건 암호 입력하세요', expectedLevel: '높음' },
  // 상담 파일 실행과 문자 권한 허용을 결합한 악성앱 설치 유도다.
  { id: 'hold2-attack-006', kind: 'attack', text: '보안상담 파일 실행 후 문자 읽기만 허용하면 조회 끝납니다', expectedLevel: '매우 높음' },
  // 자녀·가족 위해 협박과 현금 지참 요구가 결합됐다.
  { id: 'hold2-attack-007', kind: 'attack', text: '아이하고 같이 있으니 신고 말고 준비한 돈 들고 혼자 나오세요', expectedLevel: '매우 높음' },
  // 입금 후 현금화·전달을 알바로 포장하는 범죄 연루 유도다.
  { id: 'hold2-attack-008', kind: 'attack', text: '입금 확인 알바야 들어온 금액 현금 찾아 봉투에 넣으면 수당 지급', expectedLevel: '높음' },
  // 환급 명목으로 신분증 일부와 계좌 사본을 요구한다.
  { id: 'hold2-attack-009', kind: 'attack', text: '환급 대상이라 신분 뒷쪽이랑 받을 계좌 사본 올리면 끝', expectedLevel: '높음' },
  // 비밀번호 일부만 요구해도 계정 탈취로 이어지는 민감정보 요구다.
  { id: 'hold2-attack-010', kind: 'attack', text: '비번 전체 말고 처음 두 칸만 알려주면 잠금 풀게요', expectedLevel: '높음' },
  // 카드 배송 사칭과 수령코드 회신 요구가 결합됐다.
  { id: 'hold2-attack-011', kind: 'attack', text: '카드 배송 기사 출발 전 화면에 보이는 수령코드 회신 필요', expectedLevel: '높음' },
  // 보안 기능 해제를 설치 오류 해결로 포장하는 악성앱 유도다.
  { id: 'hold2-attack-012', kind: 'attack', text: '앱검사 중 플레이보호 잠깐 꺼야 설치 오류가 사라집니다', expectedLevel: '매우 높음' },
  // 대환대출을 빙자해 선결제성 위약금을 요구한다.
  { id: 'hold2-attack-013', kind: 'attack', text: '대출 갈아타기 위약금만 먼저 정리하면 오늘 금리 확정', expectedLevel: '높음' },
  // 사생활 유포 협박과 합의금 요구다.
  { id: 'hold2-attack-014', kind: 'attack', text: '예약 캡처 가족에게 가기 전에 합의금으로 마무리하자', expectedLevel: '높음' },
  // 인증 문자 값을 끝자리로 우회해 요구한다.
  { id: 'hold2-attack-015', kind: 'attack', text: '네 계정으로 확인 문자가 갔어 맨 끝 숫자 네 개만 남겨', expectedLevel: '높음' },
  // 선불카드 바코드 아래 번호 전달을 요구하는 상품권 편취다.
  { id: 'hold2-attack-016', kind: 'attack', text: '편의점 선불카드 결제하고 바코드 아래 번호를 글자로 보내', expectedLevel: '매우 높음' },
  // 법무팀 사칭과 화면공유, 검증계좌 이체 요구가 결합됐다.
  { id: 'hold2-attack-017', kind: 'attack', text: '법무팀입니다 통장 잔액 화면 공유하고 검증계좌로 옮기세요', expectedLevel: '매우 높음' },
  // 통신 정지를 핑계로 카드값 대납을 요청하는 지인 사칭이다.
  { id: 'hold2-attack-018', kind: 'attack', text: '통신 정지라 카톡 못 봐 카드값 오늘만 대신 내줄래', expectedLevel: '높음' },
  // 지원금 마감 압박과 주소창 입력, 인증 진행 유도다.
  { id: 'hold2-attack-019', kind: 'attack', text: '지원금 마감 전이라 주소창에 안내 주소 넣고 인증 진행하세요', expectedLevel: '주의' },
  // 검수앱 권한 조작과 방금 온 숫자 요구가 결합됐다.
  { id: 'hold2-attack-020', kind: 'attack', text: '검수앱 권한에서 알림 접근 켜고 방금 온 숫자를 불러주세요', expectedLevel: '매우 높음' },
  // 개인 통장 대여를 부업 정산으로 포장하는 범죄 연루 유도다.
  { id: 'hold2-attack-021', kind: 'attack', text: '부업 정산용으로 개인 통장 하루 맡기면 수고비 바로 입금', expectedLevel: '높음' },
  // 가족 위해 협박과 치료비 선송금 요구다.
  { id: 'hold2-attack-022', kind: 'attack', text: '몸 다쳤다는 목소리 듣고 싶으면 치료비부터 보내', expectedLevel: '매우 높음' },

  // 상품권 코드 공유 금지 교육 문장으로 실제 전달 요구가 없다.
  { id: 'hold2-benign-001', kind: 'benign', text: '상품권 뒷면 숫자는 절대 사진으로 보내지 말라는 안내문을 만들었다', expectedLevel: '낮음' },
  // 공식 스토어 업데이트 권고로 악성앱 설치 지시가 아니다.
  { id: 'hold2-benign-002', kind: 'benign', text: '토스 앱은 공식 스토어에서만 업데이트하라고 가족에게 알려줬다', expectedLevel: '낮음' },
  // 인증코드 자기 입력 교육 문장으로 공유 요청이 아니다.
  { id: 'hold2-benign-003', kind: 'benign', text: '인증 화면에 뜬 코드는 본인이 직접 입력해야 한다는 교육을 들었다', expectedLevel: '낮음' },
  // 공식 사이트에서 직접 처리했고 계좌 사본 제출을 하지 않았다.
  { id: 'hold2-benign-004', kind: 'benign', text: '환급금 조회는 홈택스에서 직접 했고 계좌 사본은 제출하지 않았다', expectedLevel: '낮음' },
  // 사고·합의금 키워드가 있지만 뉴스 정리 문맥이다.
  { id: 'hold2-benign-005', kind: 'benign', text: '아이 사고 합의금 요구 사례를 뉴스로 정리했다', expectedLevel: '낮음' },
  // 선불카드 바코드 언급은 보상 규정 확인 문맥이다.
  { id: 'hold2-benign-006', kind: 'benign', text: '선불카드 바코드 훼손 보상 규정을 읽었다', expectedLevel: '낮음' },
  // 회사 IT 승인된 원격지원 안내로 제3자 피싱 요구가 아니다.
  { id: 'hold2-benign-007', kind: 'benign', text: '원격지원은 회사 IT팀 승인된 장비에서만 쓴다고 공지했다', expectedLevel: '낮음' },
  // 계좌 대여 범죄 예방 캠페인 문장이다.
  { id: 'hold2-benign-008', kind: 'benign', text: '계좌를 빌려주면 범죄가 될 수 있다는 캠페인 문구를 검토했다', expectedLevel: '낮음' },
  // 권한 최소화 교육 문장으로 허용 지시가 아니다.
  { id: 'hold2-benign-009', kind: 'benign', text: '문자 접근 권한은 필요한 앱에도 최소로 허용하라고 설명했다', expectedLevel: '낮음' },
  // 대환대출 수수료 비교 문맥으로 선입금 요구가 없다.
  { id: 'hold2-benign-010', kind: 'benign', text: '대출 갈아타기 수수료 비교표를 만들었다', expectedLevel: '낮음' },
  // 택배사 공식 앱에서 직접 확인한 후기다.
  { id: 'hold2-benign-011', kind: 'benign', text: '배송 보류 메시지는 택배사 앱에서 직접 확인했다', expectedLevel: '낮음' },
  // 비밀번호 일부도 공유 금지라는 보안 교육이다.
  { id: 'hold2-benign-012', kind: 'benign', text: '비밀번호 앞 두 자리도 상담원에게 말하면 안 된다고 배웠다', expectedLevel: '낮음' },
  // 현금 전달 알바 위험 후기를 읽고 거절한 문맥이다.
  { id: 'hold2-benign-013', kind: 'benign', text: '현금 전달 알바가 위험하다는 후기를 읽고 지원하지 않았다', expectedLevel: '낮음' },
  // 기프트카드 사기 예방 글 공유 문맥이다.
  { id: 'hold2-benign-014', kind: 'benign', text: '가족 단톡에 구글 기프트카드 사기 예방 글을 올렸다', expectedLevel: '낮음' },
  // 화면공유 요구 거절 안내로 실제 공유 지시가 아니다.
  { id: 'hold2-benign-015', kind: 'benign', text: '계좌 잔액 화면 공유 요구는 피싱일 수 있어 거절하라고 안내했다', expectedLevel: '낮음' },
  // 플레이 보호 해제 요구를 삭제한 안전한 대처 후기다.
  { id: 'hold2-benign-016', kind: 'benign', text: '플레이 보호를 끄라는 문자는 위험하니 삭제했다', expectedLevel: '낮음' },
  // 법원 사건번호는 공식 사이트 직접 조회를 권하는 설명이다.
  { id: 'hold2-benign-017', kind: 'benign', text: '법원 등기 사건번호는 공식 사이트에서 직접 조회하라고 설명했다', expectedLevel: '낮음' },
  // 통신 정지 언급만 있고 금전·인증 요구가 없는 일상 대화다.
  { id: 'hold2-benign-018', kind: 'benign', text: '친구가 통신 정지됐다는 농담을 해서 고객센터 번호를 알려줬다', expectedLevel: '낮음' },
];
