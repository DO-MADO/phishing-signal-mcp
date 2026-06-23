// 민감정보 마스킹 (SPEC §7)
// 정책: 입력 텍스트의 PII(주민번호/외국인등록번호/운전면허/여권/카드/전화/계좌)를 "처리 전"에 마스킹한다.
//  - 자릿수만 '*'로 치환하고 구분자(-, 공백)는 보존 → 탐지 키워드를 텍스트에 주입하지 않는다.
//  - 보수적 범위(SPEC §11): 과탐(정상 숫자 마스킹)보다 누락 회피를 우선하되,
//    신고 채널 번호(112/1332/1394/118 등 짧은 번호)는 패턴상 매칭되지 않아 보존된다.
//  - 이 모듈은 입력값에만 적용한다(우리가 생성하는 출력은 대상 아님).

/** 매칭된 부분문자열에서 숫자만 '*'로 치환(구분자/문자는 보존). */
function starDigits(s: string): string {
  return s.replace(/\d/g, '*');
}

interface MaskRule {
  readonly name: string;
  readonly pattern: RegExp;
}

// 적용 순서가 중요하다: 구체적·고정 포맷(신분증/카드/휴대전화/지역전화) → 일반 계좌 순.
// 앞 단계에서 숫자가 '*'로 바뀌면 뒤 단계의 숫자 기반 패턴엔 더 이상 매칭되지 않는다.
const MASK_RULES: readonly MaskRule[] = [
  // 주민등록번호: 6자리 + (1~4로 시작하는)7자리
  { name: 'rrn', pattern: /\b\d{6}[-\s]?[1-4]\d{6}\b/g },
  // 외국인등록번호: 6자리 + (5~8로 시작하는)7자리
  { name: 'foreignRegistration', pattern: /\b\d{6}[-\s]?[5-8]\d{6}\b/g },
  // 운전면허번호: 2-2-6-2
  { name: 'driverLicense', pattern: /\b\d{2}[-\s]\d{2}[-\s]\d{6}[-\s]\d{2}\b/g },
  // 여권번호: 영문 1자+숫자 8자리 또는 영문 2자+숫자 7자리
  { name: 'passport', pattern: /\b(?:[A-Z]\d{8}|[A-Z]{2}\d{7})\b/gi },
  // 카드번호: 4-4-4-4 (구분자 선택)
  { name: 'card', pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g },
  // 휴대전화: 010/011/016/017/018/019
  { name: 'mobile', pattern: /\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b/g },
  // 지역 전화: 02 또는 0XX - 3~4 - 4
  { name: 'landline', pattern: /\b0\d{1,2}[-\s]?\d{3,4}[-\s]?\d{4}\b/g },
  // 계좌번호(하이픈 구분 3~4그룹)
  { name: 'accountHyphen', pattern: /\b\d{2,6}-\d{2,6}-\d{2,7}(?:-\d{1,6})?\b/g },
  // 계좌번호(연속 10~16자리)
  { name: 'accountRun', pattern: /\b\d{10,16}\b/g },
];

/** 입력 텍스트의 민감정보를 마스킹한 새 문자열을 반환한다. */
export function maskSensitive(text: string): string {
  let out = text;
  for (const rule of MASK_RULES) {
    out = out.replace(rule.pattern, (m) => starDigits(m));
  }
  return out;
}
