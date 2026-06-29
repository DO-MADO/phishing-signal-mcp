import { mkdirSync, writeFileSync } from 'node:fs';

import { SIGNAL_DEFINITIONS, type SignalId } from '../src/engine/signals.js';
import type { RiskLevel } from '../src/engine/score.js';
import { scoreText } from '../src/tools/analyzePhishingRisk.js';
import { SCAM_ADVERSARIAL_SAMPLES } from '../test/fixtures/scamAdversarialSamples.js';
import { SCAM_CALIBRATION_SAMPLES } from '../test/fixtures/scamCalibrationSamples.js';
import { HOLDOUT_SAMPLES } from '../test/fixtures/holdoutSamples.js';
import { HOLDOUT_V2_SAMPLES } from '../test/fixtures/holdoutV2Samples.js';

const RANK: Record<RiskLevel, number> = { 낮음: 0, 주의: 1, 높음: 2, '매우 높음': 3 };
const REPORT_PATH = 'docs/QUALITY_REPORT.md';

type ScoredSample = {
  readonly id: string;
  readonly text: string;
  readonly expectedLevel: RiskLevel;
  readonly actualLevel: RiskLevel;
  readonly signalIds: readonly SignalId[];
  readonly group: 'attack' | 'benign' | 'calibration';
};

type BinaryMetrics = {
  readonly label: string;
  readonly threshold: RiskLevel;
  readonly tp: number;
  readonly fp: number;
  readonly fn: number;
  readonly tn: number;
  readonly recall: Ratio;
  readonly precision: Ratio;
  readonly benignSafe: Ratio;
};

type Ratio = {
  readonly numerator: number;
  readonly denominator: number;
};

type DirectionMetrics = {
  readonly under: readonly ScoredSample[];
  readonly over: readonly ScoredSample[];
  readonly exact: readonly ScoredSample[];
};

function ratio(numerator: number, denominator: number): Ratio {
  return { numerator, denominator };
}

function percent(r: Ratio): string {
  if (r.denominator === 0) return `해당 없음 (${r.numerator}/${r.denominator})`;
  return `${((r.numerator / r.denominator) * 100).toFixed(1)}% (${r.numerator}/${r.denominator})`;
}

function escapeCell(value: string | number): string {
  return String(value).replace(/\|/g, '\\|').replace(/\n/g, '<br>');
}

function table(headers: readonly string[], rows: readonly (readonly (string | number)[])[]): string {
  const header = `| ${headers.map(escapeCell).join(' | ')} |`;
  const divider = `| ${headers.map(() => '---').join(' | ')} |`;
  const body = rows.map((row) => `| ${row.map(escapeCell).join(' | ')} |`).join('\n');
  return [header, divider, body].filter(Boolean).join('\n');
}

function kstNow(): string {
  return `${new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'Asia/Seoul',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(new Date())} KST`;
}

function preview(text: string): string {
  return text.length <= 80 ? text : `${text.slice(0, 80)}...`;
}

function scoreSample(sample: { id: string; text: string; expectedLevel: RiskLevel }, group: ScoredSample['group']): ScoredSample {
  const scored = scoreText(sample.text);
  return {
    id: sample.id,
    text: sample.text,
    expectedLevel: sample.expectedLevel,
    actualLevel: scored.level,
    signalIds: scored.signalIds,
    group,
  };
}

function binaryMetrics(samples: readonly ScoredSample[], threshold: RiskLevel, label: string): BinaryMetrics {
  const isPositive = (sample: ScoredSample) => sample.group === 'attack';
  const isPredicted = (sample: ScoredSample) => RANK[sample.actualLevel] >= RANK[threshold];

  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;
  for (const sample of samples) {
    if (isPositive(sample) && isPredicted(sample)) tp += 1;
    if (!isPositive(sample) && isPredicted(sample)) fp += 1;
    if (isPositive(sample) && !isPredicted(sample)) fn += 1;
    if (!isPositive(sample) && !isPredicted(sample)) tn += 1;
  }

  const benignCount = samples.filter((sample) => sample.group === 'benign').length;
  const benignLow = samples.filter((sample) => sample.group === 'benign' && sample.actualLevel === '낮음').length;

  return {
    label,
    threshold,
    tp,
    fp,
    fn,
    tn,
    recall: ratio(tp, tp + fn),
    precision: ratio(tp, tp + fp),
    benignSafe: ratio(benignLow, benignCount),
  };
}

function directionMetrics(samples: readonly ScoredSample[]): DirectionMetrics {
  return {
    under: samples.filter((sample) => RANK[sample.actualLevel] < RANK[sample.expectedLevel]),
    over: samples.filter((sample) => RANK[sample.actualLevel] > RANK[sample.expectedLevel]),
    exact: samples.filter((sample) => sample.actualLevel === sample.expectedLevel),
  };
}

function signalMetrics(calibration: readonly ScoredSample[]): {
  readonly tp: number;
  readonly fp: number;
  readonly fn: number;
  readonly precision: Ratio;
  readonly recall: Ratio;
  readonly f1: Ratio;
  readonly bySignal: readonly { id: SignalId; label: string; expected: number; found: number; missed: number; recall: Ratio }[];
} {
  let tp = 0;
  let fp = 0;
  let fn = 0;
  const expectedBySignal = new Map<SignalId, number>();
  const foundBySignal = new Map<SignalId, number>();

  for (const sample of calibration) {
    const expected = new Set(SCAM_CALIBRATION_SAMPLES.find((source) => source.id === sample.id)?.expectedSignals ?? []);
    const actual = new Set(sample.signalIds);

    for (const id of actual) {
      if (expected.has(id)) tp += 1;
      else fp += 1;
    }
    for (const id of expected) {
      expectedBySignal.set(id, (expectedBySignal.get(id) ?? 0) + 1);
      if (actual.has(id)) {
        foundBySignal.set(id, (foundBySignal.get(id) ?? 0) + 1);
      } else {
        fn += 1;
      }
    }
  }

  return {
    tp,
    fp,
    fn,
    precision: ratio(tp, tp + fp),
    recall: ratio(tp, tp + fn),
    f1: ratio(2 * tp, 2 * tp + fp + fn),
    bySignal: SIGNAL_DEFINITIONS.map((signal) => {
      const expected = expectedBySignal.get(signal.id) ?? 0;
      const found = foundBySignal.get(signal.id) ?? 0;
      return {
        id: signal.id,
        label: signal.label,
        expected,
        found,
        missed: expected - found,
        recall: ratio(found, expected),
      };
    }),
  };
}

function evaluateHoldout(
  samples: readonly { id: string; text: string; expectedLevel: RiskLevel; kind: 'attack' | 'benign' }[],
): {
  readonly scored: readonly ScoredSample[];
  readonly attacks: readonly ScoredSample[];
  readonly benign: readonly ScoredSample[];
  readonly warning: BinaryMetrics;
  readonly exact: Ratio;
  readonly atLeast: Ratio;
  readonly direction: DirectionMetrics;
  readonly mismatches: readonly ScoredSample[];
} {
  const scored = samples.map((sample) => scoreSample(sample, sample.kind));
  const attacks = scored.filter((sample) => sample.group === 'attack');
  const benign = scored.filter((sample) => sample.group === 'benign');
  const warning = binaryMetrics(scored, '주의', '경고 임계값(level >= 주의)');

  return {
    scored,
    attacks,
    benign,
    warning,
    exact: ratio(scored.filter((sample) => sample.actualLevel === sample.expectedLevel).length, scored.length),
    atLeast: ratio(
      attacks.filter((sample) => RANK[sample.actualLevel] >= RANK[sample.expectedLevel]).length,
      attacks.length,
    ),
    direction: directionMetrics(attacks),
    mismatches: scored.filter((sample) => sample.actualLevel !== sample.expectedLevel),
  };
}

const generatedAt = kstNow();
const adversarial = SCAM_ADVERSARIAL_SAMPLES.map((sample) => scoreSample(sample, sample.kind));
const calibration = SCAM_CALIBRATION_SAMPLES.map((sample) =>
  scoreSample(sample, sample.expectedLevel === '낮음' ? 'benign' : 'calibration'),
);
const holdoutV1 = evaluateHoldout(HOLDOUT_SAMPLES);
const holdoutV2 = evaluateHoldout(HOLDOUT_V2_SAMPLES);
const adversarialAttacks = adversarial.filter((sample) => sample.group === 'attack');
const adversarialBenign = adversarial.filter((sample) => sample.group === 'benign');
const calibrationRisk = calibration.filter((sample) => sample.group === 'calibration');
const calibrationBenign = calibration.filter((sample) => sample.group === 'benign');
const riskSamples = [...adversarialAttacks, ...calibrationRisk];
const benignSamples = [...adversarialBenign, ...calibrationBenign];
const warning = binaryMetrics(adversarial, '주의', '경고 임계값(level >= 주의)');
const high = binaryMetrics(adversarial, '높음', '고위험 임계값(level >= 높음)');
const riskAtLeast = ratio(
  riskSamples.filter((sample) => RANK[sample.actualLevel] >= RANK[sample.expectedLevel]).length,
  riskSamples.length,
);
const riskExact = ratio(
  riskSamples.filter((sample) => sample.actualLevel === sample.expectedLevel).length,
  riskSamples.length,
);
const benignExact = ratio(
  benignSamples.filter((sample) => sample.actualLevel === '낮음').length,
  benignSamples.length,
);
const signal = signalMetrics(calibration);
const direction = directionMetrics(riskSamples);
const mismatches = [...riskSamples, ...benignSamples].filter((sample) => sample.actualLevel !== sample.expectedLevel);
const sourceIds = [
  ...new Set(SCAM_CALIBRATION_SAMPLES.flatMap((sample) => sample.sourceIds)),
].sort();

const summaryRows = [
  [
    'CI 강제 불변식',
    `정상 과잉경고 ${warning.fp}건 (${warning.fp}/${adversarialBenign.length}) · 공격 전건 경고 이상 (${warning.tp}/${adversarialAttacks.length}) (매 커밋 단언)`,
  ],
  ['측정 정확일치율', percent(riskExact)],
  [
    '미탐(under-call)',
    `회귀셋 ${direction.under.length}건 (${direction.under.length}/${riskSamples.length}) / held-out-v2 ${holdoutV2.direction.under.length}건 (${holdoutV2.direction.under.length}/${holdoutV2.attacks.length})`,
  ],
  ['신호 Precision', percent(signal.precision)],
  ['Held-out-v2 탐지율', percent(holdoutV2.warning.recall)],
];

const invariantRows = [
  [
    `정상 ${adversarialBenign.length}개 과잉경고`,
    `${warning.fp}건 (${warning.fp}/${adversarialBenign.length})`,
    '← 강제 단언: test/scamAdversarialQuality.test.ts',
  ],
  [
    `공격 ${adversarialAttacks.length}개 전부 경고 임계값 이상`,
    percent(warning.recall),
    '← 강제 단언: test/scamAdversarialQuality.test.ts',
  ],
  [
    '신호 Recall',
    percent(signal.recall),
    '← 강제 단언: test/scamCalibration.test.ts',
  ],
];

const measuredRows = [
  ['위험도 정확 일치율', percent(riskExact), '테스트는 actual >= expected만 단언, actual == expected는 비단언'],
  ['신호 Precision', percent(signal.precision), '추가 검출 신호는 회귀 테스트가 실패로 단언하지 않음'],
  ['고위험(level >= 높음) 도달률', percent(high.recall), '경고 임계값(level >= 주의)보다 높은 별도 기준'],
];

const holdoutComparisonRows = [
  ['held-out-v1(dev) 개선 전', '54.5% (12/22)', '개발 참고셋: 약점 진단에 사용한 기준선'],
  ['held-out-v1(dev) 개선 후', percent(holdoutV1.warning.recall), '개선 과정에서 참고한 반-오염 수치'],
  ['held-out-v2(test)', percent(holdoutV2.warning.recall), '개선에 미사용한 검증셋 일반화 추정'],
];

const holdoutBinaryRows = [
  [
    'held-out-v1(dev)',
    holdoutV1.warning.tp,
    holdoutV1.warning.fp,
    holdoutV1.warning.fn,
    holdoutV1.warning.tn,
    percent(holdoutV1.warning.recall),
    percent(holdoutV1.warning.precision),
    `${holdoutV1.warning.fp}건 (${holdoutV1.warning.fp}/${holdoutV1.benign.length})`,
  ],
  [
    'held-out-v2(test)',
    holdoutV2.warning.tp,
    holdoutV2.warning.fp,
    holdoutV2.warning.fn,
    holdoutV2.warning.tn,
    percent(holdoutV2.warning.recall),
    percent(holdoutV2.warning.precision),
    `${holdoutV2.warning.fp}건 (${holdoutV2.warning.fp}/${holdoutV2.benign.length})`,
  ],
];

const holdoutMetricRows = [
  ['held-out-v1(dev) 위험도 정확 일치율', percent(holdoutV1.exact)],
  ['held-out-v1(dev) 공격 샘플 기대이상 비율', percent(holdoutV1.atLeast)],
  ['held-out-v1(dev) under-call(미탐 방향)', `${holdoutV1.direction.under.length}건 (${holdoutV1.direction.under.length}/${holdoutV1.attacks.length})`],
  ['held-out-v2(test) 위험도 정확 일치율', percent(holdoutV2.exact)],
  ['held-out-v2(test) 공격 샘플 기대이상 비율', percent(holdoutV2.atLeast)],
  ['held-out-v2(test) under-call(미탐 방향)', `${holdoutV2.direction.under.length}건 (${holdoutV2.direction.under.length}/${holdoutV2.attacks.length})`],
];

const directionRows = [
  ['미탐 방향 불일치(under)', `${direction.under.length}건 (${direction.under.length}/${riskSamples.length})`],
  ['보수 방향 불일치(over)', `${direction.over.length}건 (${direction.over.length}/${riskSamples.length})`],
  ['정확', `${direction.exact.length}건 (${direction.exact.length}/${riskSamples.length})`],
];

const signalRows = signal.bySignal.map((item) => [
  item.id,
  item.label,
  item.expected,
  item.found,
  item.missed,
  percent(item.recall),
]);

const underCallBlock =
  direction.under.length === 0
    ? "위험을 과소평가한(under-call) 사례 0건 — 모든 불일치가 더 보수적인 방향이며 SPEC §5 '미탐 회피 우선' 원칙과 일치한다."
    : table(
        ['id', 'expected', 'actual', 'text(80자)'],
        direction.under.map((sample) => [sample.id, sample.expectedLevel, sample.actualLevel, preview(sample.text)]),
      );

const overCallTable =
  direction.over.length === 0
    ? '보수 방향 불일치 샘플 없음.'
    : table(
        ['id', 'expected', 'actual', 'text(80자)'],
        direction.over.map((sample) => [sample.id, sample.expectedLevel, sample.actualLevel, preview(sample.text)]),
      );

const holdoutV1MismatchTable =
  holdoutV1.mismatches.length === 0
    ? '틀린 held-out-v1 샘플 없음.'
    : table(
        ['id', 'expected', 'actual', 'text'],
        holdoutV1.mismatches.map((sample) => [sample.id, sample.expectedLevel, sample.actualLevel, sample.text]),
      );

const holdoutV2MismatchTable =
  holdoutV2.mismatches.length === 0
    ? '틀린 held-out-v2 샘플 없음.'
    : table(
        ['id', 'expected', 'actual', 'text'],
        holdoutV2.mismatches.map((sample) => [sample.id, sample.expectedLevel, sample.actualLevel, sample.text]),
      );

const markdown = `# 피싱 신호등 MCP 품질 리포트

## 요약 카드

${table(['항목', '값'], summaryRows)}

측정일자: ${generatedAt}

## [CI 강제 불변식 / Enforced Invariants]

아래는 매 커밋 CI가 강제하는 하드 게이트이며, 측정된 일반화 성능이 아니라 회귀로 보장되는 불변식이다.

${table(['항목', '값', '출처'], invariantRows)}

## [측정 지표 / Measured (비단언)]

아래는 회귀 테스트가 단언하지 않는, 실제로 측정된 값이다.

${table(['항목', '값', '해석'], measuredRows)}

## [Held-out 일반화 추정 / 비단언]

held-out-v1은 개발 참고셋(dev)이다. 개선 과정에서 약점 진단에 참고했으므로 반-오염 수치로만 본다.
held-out-v2는 검증셋(test)이다. 개선에 미사용했으며, 아래 v2 수치가 회귀 테스트에 오염되지 않은 일반화 성능 추정이다.
샘플 v1 ${holdoutV1.scored.length}개, v2 ${holdoutV2.scored.length}개 규모이므로 신뢰구간이 넓다는 점을 감안한다.

### 개선 전후 비교

${table(['셋', '경고 임계값 Recall', '역할'], holdoutComparisonRows)}

### 이진 탐지

${table(['셋', 'TP', 'FP', 'FN', 'TN', 'Recall', 'Precision', '오탐 수'], holdoutBinaryRows)}

### 위험도 지표

${table(['항목', '값'], holdoutMetricRows)}

### held-out-v1(dev) 틀린 샘플

${holdoutV1MismatchTable}

### held-out-v2(test) 틀린 샘플

${holdoutV2MismatchTable}

## 회귀셋 안전 방향성 / Risk Direction

${table(['분류', '개수'], directionRows)}

${underCallBlock}

## 신호 단위 세부 지표 - calibration 셋

### 마이크로 평균

${table(['지표', '값', '프레이밍'], [
  ['Precision', percent(signal.precision), 'Measured (비단언)'],
  ['Recall', percent(signal.recall), 'CI 강제 불변식'],
  ['F1', percent(signal.f1), 'Precision은 비단언, Recall은 강제 단언'],
  ['TP/FP/FN', `TP=${signal.tp}, FP=${signal.fp}, FN=${signal.fn}`, 'calibration expectedSignals 기준'],
])}

### 신호별 Recall

${table(['signalId', '라벨', 'Expected N', 'Found', 'Missed', 'Recall'], signalRows)}

## 보수 방향 불일치 샘플

${overCallTable}

## 방법론 및 한계

- 본 수치는 공개 사례 기반 합성 샘플에 대한 결정적 엔진 측정값이다.
- 측정 경로는 사용자가 컨텍스트 없이 텍스트만 붙여넣었을 때와 동일하게 마스킹, 신호 탐지, 컨텍스트 조정 없음, 점수화를 거친다.
- 본 fixture는 엔진의 회귀 테스트 데이터와 동일하다. 따라서 [CI 강제 불변식] 섹션의 100% 수치는 측정된 일반화 성능이 아니라 회귀로 보장되는 속성이다. 일반화 성능은 별도 held-out 세트로 측정해야 한다.
- adversarial 샘플 출처: \`test/fixtures/scamAdversarialSamples.ts\` (공격 ${adversarialAttacks.length}개, 정상 ${adversarialBenign.length}개).
- calibration 샘플 출처: \`test/fixtures/scamCalibrationSamples.ts\` (위험 ${calibrationRisk.length}개, 정상 ${calibrationBenign.length}개, sourceIds: ${sourceIds.join(', ') || '없음'}).
- held-out-v1 출처: \`test/fixtures/holdoutSamples.ts\` (공격 ${holdoutV1.attacks.length}개, 정상 ${holdoutV1.benign.length}개). 개발 참고셋이라 일반화 성능의 본 지표로 보지 않는다.
- held-out-v2 출처: \`test/fixtures/holdoutV2Samples.ts\` (공격 ${holdoutV2.attacks.length}개, 정상 ${holdoutV2.benign.length}개). 개선에 미사용한 검증셋이다.
- 실제 트래픽 분포, 공격자 문체, 사용자 컨텍스트는 본 합성 샘플과 다를 수 있다.
- 외부 네트워크 호출 없이 로컬 fixture와 규칙 엔진만 사용한다.

## 재현 방법

\`\`\`bash
npm run report
\`\`\`
`;

mkdirSync('docs', { recursive: true });
writeFileSync(REPORT_PATH, `${markdown}\n`);

console.log(`피싱 신호등 MCP 품질 리포트`);
console.log(`생성 시각: ${generatedAt}`);
console.log(`샘플: adversarial 공격 ${adversarialAttacks.length}개 / 정상 ${adversarialBenign.length}개, calibration 위험 ${calibrationRisk.length}개 / 정상 ${calibrationBenign.length}개`);
console.log(`CI 강제 불변식: 정상 과잉경고 ${warning.fp}건 (${warning.fp}/${adversarialBenign.length}), 공격 전건 경고 이상 ${percent(warning.recall)}, 신호 Recall ${percent(signal.recall)}`);
console.log(`측정 지표(비단언): 위험도 정확일치율 ${percent(riskExact)}, 신호 Precision ${percent(signal.precision)}, 고위험 도달률 ${percent(high.recall)}`);
console.log(`Held-out-v1(dev): baseline Recall=54.5% (12/22) -> current Recall=${percent(holdoutV1.warning.recall)}, Precision=${percent(holdoutV1.warning.precision)}, 오탐=${holdoutV1.warning.fp}건 (${holdoutV1.warning.fp}/${holdoutV1.benign.length}), under-call=${holdoutV1.direction.under.length}건 (${holdoutV1.direction.under.length}/${holdoutV1.attacks.length})`);
console.log(`Held-out-v2(test): TP=${holdoutV2.warning.tp}, FP=${holdoutV2.warning.fp}, FN=${holdoutV2.warning.fn}, TN=${holdoutV2.warning.tn}, Recall=${percent(holdoutV2.warning.recall)}, Precision=${percent(holdoutV2.warning.precision)}, 오탐=${holdoutV2.warning.fp}건 (${holdoutV2.warning.fp}/${holdoutV2.benign.length})`);
console.log(`Held-out-v2 위험도: 정확일치율 ${percent(holdoutV2.exact)}, 공격 샘플 기대이상 ${percent(holdoutV2.atLeast)}, under-call=${holdoutV2.direction.under.length}건 (${holdoutV2.direction.under.length}/${holdoutV2.attacks.length})`);
console.log(`안전 방향성: under=${direction.under.length}건 (${direction.under.length}/${riskSamples.length}), over=${direction.over.length}건 (${direction.over.length}/${riskSamples.length}), exact=${direction.exact.length}건 (${direction.exact.length}/${riskSamples.length})`);
if (direction.under.length === 0) {
  console.log("under-call 0건: 모든 불일치가 더 보수적인 방향이며 SPEC §5 '미탐 회피 우선' 원칙과 일치");
}
console.log(`참고: 기대 이상 통과 ${percent(riskAtLeast)}, 정상 낮음 ${percent(benignExact)}, 신호 F1 ${percent(signal.f1)} (TP=${signal.tp}, FP=${signal.fp}, FN=${signal.fn})`);
console.log(`불일치 샘플: ${mismatches.length}개 (${mismatches.length}/${riskSamples.length + benignSamples.length})`);
console.log(`Held-out-v1 틀린 샘플: ${holdoutV1.mismatches.length}개 (${holdoutV1.mismatches.length}/${holdoutV1.scored.length})`);
console.log(`Held-out-v2 틀린 샘플: ${holdoutV2.mismatches.length}개 (${holdoutV2.mismatches.length}/${holdoutV2.scored.length})`);
console.log(`문서 생성: ${REPORT_PATH}`);
