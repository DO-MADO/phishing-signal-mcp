// 이 세트는 어떤 테스트도 단언하지 않는 held-out 평가용이며 엔진 튜닝에 사용하지 않는다.
// 라벨은 엔진 실행 전 사람이 본 위험도 기준으로 정한다.

import type { RiskLevel } from '../../src/engine/score.js';

export interface HoldoutSample {
  readonly id: string;
  readonly text: string;
  readonly expectedLevel: RiskLevel;
  readonly kind: 'attack' | 'benign';
}

export const HOLDOUT_SAMPLES: readonly HoldoutSample[] = [
  // 임시 대화방과 대납 요구가 결합된 지인 사칭 송금 유도다.
  { id: 'hold-attack-001', kind: 'attack', text: '나 폰 매장 맡겼어 여기 답장만 봐줘 접수비는 네가 먼저 처리 가능?', expectedLevel: '높음' },
  // 상품권 코드를 대명사로 우회해 요구하는 금전 편취 시도다.
  { id: 'hold-attack-002', kind: 'attack', text: '편상 뒷장 회색 긁고 그거만 사진 말고 글자로 줘', expectedLevel: '매우 높음' },
  // 기관명 없이 조사팀을 사칭하며 일회용 값을 요구한다.
  { id: 'hold-attack-003', kind: 'attack', text: '민원조사팀인데 본인확인 창에 뜬 여섯 글자 그대로 불러주세요', expectedLevel: '높음' },
  // 링크를 직접 쓰지 않고 주소창 입력을 유도하는 스미싱형 문장이다.
  { id: 'hold-attack-004', kind: 'attack', text: '배송 보류 풀려면 문자 아래 영문주소를 검색창 말고 주소칸에 넣으세요', expectedLevel: '주의' },
  // 가족 사칭과 페이 장애 핑계로 소액 송금을 요구한다.
  { id: 'hold-attack-005', kind: 'attack', text: '엄마 나 페이 잠겨서 편의점 계산 못해 오분만 도와줘', expectedLevel: '높음' },
  // 공포를 이용해 현금 준비를 요구하는 가족 협박이다.
  { id: 'hold-attack-006', kind: 'attack', text: '애가 우리 차에 탔어 어른 한 명만 조용히 나와', expectedLevel: '매우 높음' },
  // 설치 파일과 권한 허용을 요구하는 악성앱 유도다.
  { id: 'hold-attack-007', kind: 'attack', text: '확인용 파일 보냈으니 스토어 말고 내려받아서 알림권한까지 켜세요', expectedLevel: '매우 높음' },
  // 원격 조작을 완곡하게 표현하며 은행앱 화면 노출을 요구한다.
  { id: 'hold-attack-008', kind: 'attack', text: '상담 보면서 같이 할게요 파란 공유 버튼 누르고 은행 화면만 열어두세요', expectedLevel: '높음' },
  // 대출 전환 명목으로 선납 비용을 요구한다.
  { id: 'hold-attack-009', kind: 'attack', text: '갈아타기 승인 직전인데 묶인 비용 먼저 풀어야 한도가 살아납니다', expectedLevel: '높음' },
  // 세금 환급 명목으로 신분 확인 자료 전송을 요구한다.
  { id: 'hold-attack-010', kind: 'attack', text: '환급 심사 마지막이라 신분 앞면이랑 받을 통장 사진만 올리세요', expectedLevel: '높음' },
  // 보안 확인을 빙자해 비밀번호 일부를 요구한다.
  { id: 'hold-attack-011', kind: 'attack', text: '보안점검 중입니다 쓰는 암호 앞 두 자리만 확인하면 끝납니다', expectedLevel: '매우 높음' },
  // 수거책/대포통장성 업무를 알바처럼 포장한다.
  { id: 'hold-attack-012', kind: 'attack', text: '단기 심부름인데 봉투 받아 역 보관함에 넣으면 바로 정산', expectedLevel: '높음' },
  // 계좌 대여를 세금 처리로 포장하는 범죄 연루 유도다.
  { id: 'hold-attack-013', kind: 'attack', text: '정산 계좌 하루만 빌리면 세무 처리 끝나고 수고비 얹어줌', expectedLevel: '높음' },
  // 투자 손실 보전과 입장비를 결합한 투자 사기다.
  { id: 'hold-attack-014', kind: 'attack', text: '체험방 손실은 회사가 메워주니까 자리비만 넣고 시작해요', expectedLevel: '높음' },
  // 협박성 사생활 유포와 정리금 요구다.
  { id: 'hold-attack-015', kind: 'attack', text: '예약 기록 캡처해뒀고 지인 보기 전에 정리금으로 끝내자', expectedLevel: '높음' },
  // 카드 배송 사칭과 수신코드 요구가 결합됐다.
  { id: 'hold-attack-016', kind: 'attack', text: '카드 수령 보류라 방금 뜬 수령값 회신해야 기사님이 출발합니다', expectedLevel: '높음' },
  // 관공서성 보조금 안내를 빙자해 인증 절차로 유도한다.
  { id: 'hold-attack-017', kind: 'attack', text: '생활비 지원 대상자라 본인 절차 안 하면 이번 회차 제외됩니다', expectedLevel: '주의' },
  // 띄어쓰기 파괴와 가족 호칭으로 긴급 송금을 요구한다.
  { id: 'hold-attack-018', kind: 'attack', text: '아빠나지금폰먹통이라카뱅못들어감약값먼저부탁', expectedLevel: '높음' },
  // 오타와 은어로 상품권 번호 전달을 요구한다.
  { id: 'hold-attack-019', kind: 'attack', text: '구플 깊카 까서 뒤에 숫쟈만 톡말고 문자로 남겨', expectedLevel: '매우 높음' },
  // 채무 문제를 빌미로 방문 현금 상환을 요구한다.
  { id: 'hold-attack-020', kind: 'attack', text: '연체 등록 막으려면 담당자가 오늘 들를 때 현금으로 맞추세요', expectedLevel: '높음' },
  // 대명사로 인증정보를 우회 요청하는 지인 사칭이다.
  { id: 'hold-attack-021', kind: 'attack', text: '내 로그인 막혔어 네 폰에 뜨는 그거 잠깐만 읽어줘', expectedLevel: '높음' },
  // 악성앱 권한을 보안검사 예외로 포장한다.
  { id: 'hold-attack-022', kind: 'attack', text: '검사앱이 차단되면 예외 등록하고 문자 접근만 허용하면 됩니다', expectedLevel: '매우 높음' },

  // 보이스피싱 예방 교육 문장으로 실제 요구가 없다.
  { id: 'hold-benign-001', kind: 'benign', text: '엄마에게 OTP는 가족이어도 절대 말하지 말라고 설명했다', expectedLevel: '낮음' },
  // 공식 앱에서 직접 처리했다는 안전한 후기다.
  { id: 'hold-benign-002', kind: 'benign', text: '카드 배송 보류 알림은 은행 앱에서 직접 확인하고 끝냈다', expectedLevel: '낮음' },
  // 위험 단어가 있지만 뉴스 요약 문맥이다.
  { id: 'hold-benign-003', kind: 'benign', text: '안전계좌로 옮기라는 말은 사기라는 뉴스 제목을 봤다', expectedLevel: '낮음' },
  // 상품권 코드 공유 금지 교육 문장이다.
  { id: 'hold-benign-004', kind: 'benign', text: '구글 기프트카드 코드는 선물받은 사람도 남에게 보내면 안 된다', expectedLevel: '낮음' },
  // 회사 보안 문서 작성 문맥이다.
  { id: 'hold-benign-005', kind: 'benign', text: '원격지원 앱 권한 허용 절차를 사내 매뉴얼에서 삭제했다', expectedLevel: '낮음' },
  // 가족 간 일상 연락으로 금전 요구가 없다.
  { id: 'hold-benign-006', kind: 'benign', text: '아빠 나 폰 수리 끝나서 예전 번호 그대로 쓸 수 있어', expectedLevel: '낮음' },
  // 대출 비교 공부 문맥으로 선입금 요구가 없다.
  { id: 'hold-benign-007', kind: 'benign', text: '대환대출 수수료 계산법을 비교표로 정리했다', expectedLevel: '낮음' },
  // 보안 권고 문구로 민감정보 요청이 아니다.
  { id: 'hold-benign-008', kind: 'benign', text: '비밀번호 앞자리도 상담원에게 알려주면 안 된다고 안내했다', expectedLevel: '낮음' },
  // 공공지원 제도 설명 문맥이다.
  { id: 'hold-benign-009', kind: 'benign', text: '생활비 지원 신청은 주민센터 방문으로만 받는다고 공지했다', expectedLevel: '낮음' },
  // 범죄 예방 캠페인 문장이다.
  { id: 'hold-benign-010', kind: 'benign', text: '계좌를 하루만 빌려줘도 처벌될 수 있다는 포스터를 만들었다', expectedLevel: '낮음' },
  // 택배 업무 설명 문맥이며 링크/인증 유도가 없다.
  { id: 'hold-benign-011', kind: 'benign', text: '배송 보류 상태는 택배사 고객센터에서 직접 풀었다', expectedLevel: '낮음' },
  // 투자 사기 예방 교육 문장이다.
  { id: 'hold-benign-012', kind: 'benign', text: '손실 보전과 원금 보장은 투자 사기 단골 문구라고 배웠다', expectedLevel: '낮음' },
  // 아이 사고 예방 캠페인 문장이다.
  { id: 'hold-benign-013', kind: 'benign', text: '아이 사고 합의금 협박 사례를 학교 안전교육에서 다뤘다', expectedLevel: '낮음' },
  // 인증번호 금지 문구 예시다.
  { id: 'hold-benign-014', kind: 'benign', text: '문자에 뜬 여섯 글자는 본인만 입력해야 한다는 배너 문구', expectedLevel: '낮음' },
  // 공식 처리 완료 후기다.
  { id: 'hold-benign-015', kind: 'benign', text: '환급금은 홈택스에서 직접 조회했고 계좌 입력은 하지 않았다', expectedLevel: '낮음' },
  // 파일 설치 위험성 교육 문장이다.
  { id: 'hold-benign-016', kind: 'benign', text: '스토어 밖 파일 설치는 위험하니 가족 단톡에 주의 글을 올렸다', expectedLevel: '낮음' },
  // 물류 알바 후기 탐색 문맥으로 수행 지시가 없다.
  { id: 'hold-benign-017', kind: 'benign', text: '봉투 전달 알바 후기를 보니 위험하다는 댓글이 많았다', expectedLevel: '낮음' },
  // 협박 사례 분석 문장으로 실제 협박이 아니다.
  { id: 'hold-benign-018', kind: 'benign', text: '예약 기록 유포 협박은 신고해야 한다는 상담 사례를 읽었다', expectedLevel: '낮음' },
];
