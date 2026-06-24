// PlayMCP / Agentic Player 10 규정 자동 점검 (SPEC §4.3, CLAUDE §11)
// MCP Inspector가 확인하는 항목 중 정적으로 검증 가능한 것들을 회귀 가드로 고정한다.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createMcpServer } from '../src/server.js';

async function listTools() {
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const server = createMcpServer();
  await server.connect(st);
  const client = new Client({ name: 'compliance', version: '0.0.0' });
  await client.connect(ct);
  const { tools } = await client.listTools();
  await client.close();
  return tools;
}

const NAME_RE = /^[A-Za-z0-9_-]{1,128}$/;

test('툴은 정확히 2개이며 이름이 중복되지 않는다', async () => {
  const tools = await listTools();
  assert.equal(tools.length, 2);
  const names = tools.map((t) => t.name);
  assert.equal(new Set(names).size, names.length);
});

test('툴 이름 규칙: 영숫자/_/- 1~128자, "kakao" 미포함', async () => {
  const tools = await listTools();
  for (const t of tools) {
    assert.match(t.name, NAME_RE, `${t.name} 이름 규칙 위반`);
    assert.ok(!/kakao/i.test(t.name), `${t.name} 에 kakao 포함 금지`);
  }
});

test('description: 1,024자 이내 + 서비스명 영문/국문 병기', async () => {
  const tools = await listTools();
  for (const t of tools) {
    const desc = t.description ?? '';
    assert.ok(desc.length > 0 && desc.length <= 1024, `${t.name} description 길이`);
    assert.ok(desc.includes('PhishingSignal'), `${t.name} 영문 서비스명 누락`);
    assert.ok(desc.includes('피싱 신호등'), `${t.name} 국문 서비스명 누락`);
  }
});

test('annotations 5종이 모두 지정되고 읽기전용/비파괴/비외부/멱등이다', async () => {
  const tools = await listTools();
  for (const t of tools) {
    const a = t.annotations ?? {};
    assert.equal(typeof a.title, 'string', `${t.name} title`);
    assert.equal(a.readOnlyHint, true, `${t.name} readOnlyHint`);
    assert.equal(a.destructiveHint, false, `${t.name} destructiveHint`);
    assert.equal(a.openWorldHint, false, `${t.name} openWorldHint`);
    assert.equal(a.idempotentHint, true, `${t.name} idempotentHint`);
  }
});

test('inputSchema가 object 타입으로 노출된다', async () => {
  const tools = await listTools();
  for (const t of tools) {
    assert.equal(t.inputSchema?.type, 'object', `${t.name} inputSchema.type`);
  }
});

test('inputSchema 설명은 enum 값을 한글 의미와 함께 안내한다', async () => {
  const tools = await listTools();
  const analyze = tools.find((t) => t.name === 'analyzePhishingRisk');
  const report = tools.find((t) => t.name === 'getReportChannels');
  assert.ok(analyze, 'analyzePhishingRisk tool');
  assert.ok(report, 'getReportChannels tool');

  const analyzeSchema = analyze.inputSchema as {
    properties?: {
      context?: {
        properties?: Record<string, { description?: string }>;
      };
    };
  };
  const reportSchema = report.inputSchema as {
    properties?: Record<string, { description?: string }>;
  };
  const context = analyzeSchema.properties?.context?.properties ?? {};

  assert.match(context.channel?.description ?? '', /phone=전화/);
  assert.match(context.channel?.description ?? '', /kakao=카카오톡\/메신저/);
  assert.match(context.relationship?.description ?? '', /family=가족/);
  assert.match(context.relationship?.description ?? '', /coworker=직장동료/);
  assert.match(context.senderKnown?.description ?? '', /상대가 주장한 신원만으로는 true로 보지 마세요/);
  assert.match(reportSchema.properties?.situation?.description ?? '', /suspiciousOnly=의심만 받음/);
  assert.match(reportSchema.properties?.situation?.description ?? '', /malwareInstalled=악성앱 설치 의심/);
});
