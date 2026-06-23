import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createMcpServer } from '../src/server.js';

/** 인메모리로 연결된 (client, server) 쌍을 만든다. */
async function connect(): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createMcpServer();
  await server.connect(serverTransport);
  const client = new Client({ name: 'test-client', version: '0.0.0' });
  await client.connect(clientTransport);
  return client;
}

test('두 툴(analyzePhishingRisk, getReportChannels)이 등록되어 있다', async () => {
  const client = await connect();
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name);
  assert.ok(names.includes('analyzePhishingRisk'));
  assert.ok(names.includes('getReportChannels'));
  await client.close();
});

test('모든 툴은 annotations 5종과 description을 갖는다', async () => {
  const client = await connect();
  const { tools } = await client.listTools();
  for (const t of tools) {
    assert.ok(t.description && t.description.length > 0, `${t.name} description 누락`);
    const a = t.annotations ?? {};
    assert.equal(typeof a.title, 'string', `${t.name} annotations.title`);
    assert.equal(typeof a.readOnlyHint, 'boolean', `${t.name} readOnlyHint`);
    assert.equal(typeof a.destructiveHint, 'boolean', `${t.name} destructiveHint`);
    assert.equal(typeof a.openWorldHint, 'boolean', `${t.name} openWorldHint`);
    assert.equal(typeof a.idempotentHint, 'boolean', `${t.name} idempotentHint`);
  }
  await client.close();
});

test('analyzePhishingRisk 호출이 마크다운 위험도를 반환한다', async () => {
  const client = await connect();
  const res = await client.callTool({
    name: 'analyzePhishingRisk',
    arguments: { text: '검찰청입니다. 안전계좌로 즉시 송금하고 인증번호를 알려주세요.' },
  });
  const content = res.content as Array<{ type: string; text?: string }>;
  const text = content.find((c) => c.type === 'text')?.text ?? '';
  assert.match(text, /위험도/);
  assert.ok(text.includes('법적 판단이 아닙니다'), '디스클레이머 포함');
  await client.close();
});

test('getReportChannels 호출이 상황별 채널을 반환한다', async () => {
  const client = await connect();
  const res = await client.callTool({
    name: 'getReportChannels',
    arguments: { situation: 'alreadyPaid' },
  });
  const content = res.content as Array<{ type: string; text?: string }>;
  const text = content.find((c) => c.type === 'text')?.text ?? '';
  assert.ok(text.includes('1394'));
  await client.close();
});

test('잘못된 입력은 검증 오류를 반환한다(자동 검증)', async () => {
  const client = await connect();
  const res = await client.callTool({
    name: 'getReportChannels',
    arguments: { situation: 'invalidSituation' },
  });
  assert.equal(res.isError, true);
  await client.close();
});
